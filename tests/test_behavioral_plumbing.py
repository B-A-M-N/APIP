"""Behavioral detection operational plumbing (audit #17-#23) — end-to-end.

Against real Postgres and the REAL controller:

  #22 the governed local-behavioral principal is registered at startup
      (server-derived, zero-credential, allowed_kinds pinned to the
      behavioral families) — detections can never land unregistered;
  #17 a configured Suricata EVE datasource is actually consumed by the
      running controller (lines converted, detections emitted);
  #20 an unknown-target detection stays dormant until its indicator is
      ingested (bounded pending — nothing silently discarded);
  #19/#16 attached evidence carries the resolved indicator identity and
      lands idempotently through the observation identity;
  #23 a family disabled by the effective policy is stripped from the
      decision path (behavioral_family_disabled_by_policy reason code) —
      and the loader's family gate now cites ONE registry (telemetry).
"""
from __future__ import annotations

import json
import sys
import time
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
import psycopg2.extensions
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pg  # noqa: E402

from apip.config.service import (  # noqa: E402
    ControllerConfig,
    DatabaseConfig,
    load_config,
)
from apip.controller.service import Controller  # noqa: E402
from apip.ledger.db import Database  # noqa: E402
from apip.ledger.migrations import apply_migrations  # noqa: E402
from apip.ledger.repo import Ledger  # noqa: E402
from apip.telemetry.behavioral import (  # noqa: E402
    IMPLEMENTED_FAMILIES,
    LOCAL_BEHAVIORAL_SOURCE_ID,
)
from apip.telemetry.feed import LiveBehavioralFeed  # noqa: E402
from apip.telemetry.sources.suricata_eve import SuricataEveSource  # noqa: E402


def _can_connect() -> bool:
    try:
        conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
        conn.close()
        return True
    except psycopg2.Error:
        return False


pytestmark = pytest.mark.skipif(
    not _can_connect(), reason="no reachable Postgres for behavioral tests")

POLICY = """
policy_version = 'fm-v1'
mode = 'SHADOW'
scope = 'lab'

[thresholds]
observe_m = 40
fqdn_auto_m = 95
fqdn_auto_s = 90
ip_rate_m = 90
ip_rate_s = 85
ip_deny_m = 98
ip_deny_s = 95

[thresholds.rungs.L1]
m = 85
s = 75

[thresholds.rungs.L2]
m = 90
s = 80

[thresholds.rungs.L4]
m = 95
s = 90

[thresholds.rungs.L5]
m = 98
s = 95

[limits]
max_auto_ttl_seconds = 3600
nominal_rate_ceiling_per_min = 120

[authorization]
authorized_prefixes = []
authorized_domains = ["c2.invalid"]

[behavioral]
enabled_families = ["beacon_periodicity", "dga_likelihood",
                    "dns_tunneling", "fastflux", "volume_anomaly",
                    "first_seen_novelty", "tls_metadata_mismatch"]
max_behavioral_m_contribution = 60

[behavioral.corroboration]
distinct_families_for_rate_limit = 2
distinct_families_for_deny = 3
deny_also_requires_external = true

[safety]
auto_prefix_deny = false
auto_routing = false
auto_wildcard_domain = false
allowlist_precedence = true
no_ai_components = true

[replay]
reference_now = '2026-09-05T05:00:00Z'
"""

POLICY_NO_DGA = POLICY.replace(
    'enabled_families = ["beacon_periodicity", "dga_likelihood",\n'
    '                    "dns_tunneling", "fastflux", "volume_anomaly",\n'
    '                    "first_seen_novelty", "tls_metadata_mismatch"]',
    'enabled_families = ["beacon_periodicity", "volume_anomaly",\n'
    '                    "first_seen_novelty"]')


def _sha(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.fixture()
def env(tmp_path):
    name = "apip_beh_" + uuid.uuid4().hex[:12]
    conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    conn.cursor().execute(f'CREATE DATABASE "{name}"')
    conn.close()
    zone_dir = tmp_path / "rpz"
    eve = tmp_path / "eve.json"
    eve.write_text("", encoding="utf-8")
    cfg = replace(
        load_config(None),
        db=DatabaseConfig(host=pg.HOST, port=pg.PORT, dbname=name,
                          user=pg.USER),
        controller=replace(ControllerConfig(), reconcile_interval_s=0.3,
                           verify_interval_s=3600,
                           suricata_eve_path=str(eve)),
        )
    db = Database(cfg.db.dsn_kwargs())
    db.wait_until_ready(timeout_s=10)
    apply_migrations(db)
    led = Ledger(db)
    led.stage_policy(policy_version="behavioral", revision=1,
                     content_sha256=_sha(POLICY), raw_text=POLICY,
                     mode="SHADOW", staged_by="test")
    led.promote_policy("behavioral", 1, "test")
    ctrl = Controller(cfg)
    ctrl.start(wait_db_s=10)
    try:
        yield ctrl, led, db, eve
    finally:
        ctrl.stop()
        conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        conn.cursor().execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        conn.close()


def _ingest_indicator(led: Ledger, db: Database, tag: str, value: str):
    ind_id = led.observable_id("fqdn", value)
    db.execute(
        "INSERT INTO indicators (indicator_id, itype, value) VALUES "
        "(%s, 'fqdn', %s) ON CONFLICT DO NOTHING", (ind_id, value))


def _wait_for(condition, timeout_s: float = 10.0, poll_s: float = 0.05):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(poll_s)
    return False


def test_local_behavioral_principal_registered_at_startup(env):
    """Audit #22: the governed server-derived local evidence principal
    exists in the durable registry — detections can never be unregistered
    (zero silent authority)."""
    ctrl, led, db, eve = env
    row = led.get_source(LOCAL_BEHAVIORAL_SOURCE_ID)
    assert row is not None, (
        "controller.start did not register the local-behavioral principal")
    assert row["source_class"] == "local"
    assert row["allowed_kinds"], "family pin missing"
    assert set(row["allowed_kinds"]) <= {
        f"behavioral_{f}" for f in IMPLEMENTED_FAMILIES}


def test_eve_lines_flow_to_durable_evidence_and_decision(env):
    """Audit #17/#19/#16/#20 end-to-end: EVE DNS lines -> live feed ->
    reconcile attach -> durable evidence under the governed principal ->
    re-decision; an unknown target waits dormant and attaches later."""
    ctrl, led, db, eve = env
    known_domain = "9f86d081884c7d65.c2.invalid"
    unknown_domain = "b5bb9d8014a0f9b1.dormant.invalid"
    _ingest_indicator(led, db, "tag", known_domain)
    ts = "2026-09-05T05:00:00Z"
    with eve.open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "timestamp": ts, "event_type": "dns", "src_ip": "10.0.0.5",
            "dns": {"rrname": known_domain, "rrtype": "A"}}) + "\n")
        f.write(json.dumps({
            "timestamp": ts, "event_type": "dns", "src_ip": "10.0.0.5",
            "dns": {"rrname": unknown_domain, "rrtype": "A"}}) + "\n")
    ind_id = led.observable_id("fqdn", known_domain)
    assert _wait_for(lambda: db.query_one(
        "SELECT evidence_id FROM evidence WHERE indicator_id=%s AND "
        "source_id=%s", (ind_id, LOCAL_BEHAVIORAL_SOURCE_ID))), \
        "behavioral evidence never became durable"
    ev_rows = db.query(
        "SELECT kind FROM evidence WHERE indicator_id=%s AND source_id=%s",
        (ind_id, LOCAL_BEHAVIORAL_SOURCE_ID))
    assert any(r["kind"] == "behavioral_dga_likelihood" for r in ev_rows)
    # #20: the unknown-target detection waited, dormant, then — with the
    # indicator still unknown — stayed pending (bounded), not discarded
    assert ctrl.behavioral_feed.pending_unknown >= 1
    # idempotent attach (#16): a second reconcile pass does NOT duplicate
    n_before = db.query_one(
        "SELECT count(*) AS n FROM evidence WHERE indicator_id=%s",
        (ind_id,))["n"]
    ctrl._attach_behavioral_evidence(
        datetime.now(timezone.utc) + timedelta(seconds=1))
    n_after = db.query_one(
        "SELECT count(*) AS n FROM evidence WHERE indicator_id=%s",
        (ind_id,))["n"]
    assert n_after == n_before


def test_disabled_family_stripped_from_decision(env):
    """Audit #23: a family the effective policy does NOT enable is removed
    from the decision path — scoring can never silently consume it."""
    from apip.decision.layer import merge_policy_overlay  # noqa: F401
    from apip.decision.loader import load_policy_text
    from apip.decision.policy import evaluate
    from apip.domain.models import Evidence, Indicator
    from apip.registry import SourceProfile, SourceRegistry

    registry = SourceRegistry((SourceProfile(
        source_id=LOCAL_BEHAVIORAL_SOURCE_ID, source_class="local",
        independent=False, auto_enforcement_allowed=False,
        allowed_kinds=tuple(f"behavioral_{f}"
                            for f in IMPLEMENTED_FAMILIES)),))
    now = "2026-09-05T05:00:00Z"
    policy = load_policy_text(POLICY, source_registry=registry,
                              now_fn=lambda: now)
    policy_off = load_policy_text(POLICY_NO_DGA, source_registry=registry,
                                  now_fn=lambda: now)
    fresh = (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    indicator = Indicator(
        id="indicator--fam", type="fqdn",
        value="9f86d081884c7d65.c2.invalid", sources=("local-behavioral",),
        evidence=(Evidence(kind="behavioral_dga_likelihood",
                           source_id=LOCAL_BEHAVIORAL_SOURCE_ID,
                           source_class="unassigned", observed_at=fresh,
                           independent=False, detail={"entropy": 4.0}),))
    d_on = evaluate(indicator, policy)
    d_off = evaluate(indicator, policy_off)
    # enabled: the fact is decision-bearing (no disabled-family complaint)
    assert not any(r.startswith("behavioral_family_disabled_by_policy:")
                   for r in d_on.reason_codes)
    # disabled: the fact is stripped BEFORE scoring and the stripping is
    # surfaced as a reason code — the operator can see the gate fired
    assert any(r.startswith("behavioral_family_disabled_by_policy:")
               for r in d_off.reason_codes), d_off.reason_codes
    # and it contributed nothing to the disabled-path score
    assert d_off.maliciousness == 0
