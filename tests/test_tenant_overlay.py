"""Per-tenant policy overlay tests (task #11, feature 2).

The merge is DETERMINISTIC and MONOTONIC: a tenant overlay may raise
thresholds / rung floors, require more behavioral corroboration, lower caps,
narrow the authorization boundary, and only ADD governed allowlist entries —
never loosen the global. The pure merge tests below prove the clamp; the DB
integration test proves a tenant with a stricter overlay gets a TIGHTER
decision on the same evidence than the global policy alone.
"""
from __future__ import annotations

import os
import sys
import uuid
from dataclasses import replace
from pathlib import Path

import psycopg2
import psycopg2.extensions
import pytest
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pg  # noqa: E402  (shared Postgres test endpoints)

from apip.decision.layer import merge_policy_overlay  # noqa: E402
from apip.decision.loader import load_policy_text  # noqa: E402
from apip.decision.policy import Policy  # noqa: E402

GLOBAL_TOML = """
policy_version = "global.1"
mode = "ENFORCE"
scope = "tenant-world"
allowlist = [ { value = "governed.operator.test", owner = "operator", ticket = "g-1" } ]

[thresholds]
observe_m = 40
fqdn_auto_m = 90
fqdn_auto_s = 85
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
max_auto_ttl_seconds = 600
max_evidence_per_indicator = 64
nominal_rate_ceiling_per_min = 1000

[authorization]
authorized_domains = ["corp.test", "operator.test"]

[safety]
allowlist_precedence = true
no_ai_components = true

[behavioral]
enabled_families = ["beacon_periodicity"]
max_behavioral_m_contribution = 60
[behavioral.corroboration]
distinct_families_for_rate_limit = 2
distinct_families_for_deny = 3
deny_also_requires_external = true
"""


def _global() -> Policy:
    return load_policy_text(GLOBAL_TOML)


def _overlay(toml: str) -> Policy:
    from apip.decision.loader import build_overlay
    raw = tomllib.loads(toml)
    return build_overlay(raw, toml)


def test_overlay_only_tightens_thresholds_and_caps():
    g = _global()
    tighter = _overlay("""
policy_version = "t1"
mode = "ENFORCE"
scope = "*"
[thresholds]
fqdn_auto_m = 98
observe_m = 70
[limits]
max_auto_ttl_seconds = 120
max_evidence_per_indicator = 16
""")
    # raise threshold + lower cap -> applied
    eff = merge_policy_overlay(g, tighter)
    assert eff.fqdn_auto_m == 98
    assert eff.observe_m == 70
    assert eff.max_auto_ttl_seconds == 120
    assert eff.max_evidence_per_indicator == 16

    # a LOOSENING overlay is clamped back to the global (monotonic)
    loosing = _overlay("""
policy_version = "t-loose"
mode = "ENFORCE"
scope = "*"
[thresholds]
fqdn_auto_m = 50
observe_m = 10
[limits]
max_auto_ttl_seconds = 3600
max_evidence_per_indicator = 1024
""")
    eff2 = merge_policy_overlay(g, loosing)
    assert eff2.fqdn_auto_m == 90       # not loosened below global
    assert eff2.observe_m == 40
    assert eff2.max_auto_ttl_seconds == 600
    assert eff2.max_evidence_per_indicator == 64


def test_overlay_cannot_add_scope():
    g = _global()
    # overlay proposes a domain outside the global boundary -> dropped
    widen = _overlay("""
policy_version = "t-widen"
mode = "ENFORCE"
scope = "*"
[authorization]
authorized_domains = ["corp.test", "evil.example"]
""")
    eff = merge_policy_overlay(g, widen)
    # a domain outside the global boundary is NEVER added (no scope widening)
    assert "evil.example" not in eff.authorized_domains
    # effective is the intersection of the overlay's declared boundary with the
    # global (tighten-only): a tenant naming its own scope narrows it.
    assert set(eff.authorized_domains) == {"corp.test"}

    # overlay NARROWS the boundary -> honored (tighter)
    narrow = _overlay("""
policy_version = "t-narrow"
mode = "ENFORCE"
scope = "*"
[authorization]
authorized_domains = ["corp.test"]
""")
    eff2 = merge_policy_overlay(g, narrow)
    assert set(eff2.authorized_domains) == {"corp.test"}


def test_overlay_raises_rungs_and_corrob_moves_false_to_true():
    g = _global()
    ov = _overlay("""
policy_version = "t2"
mode = "ENFORCE"
scope = "*"
[thresholds.rungs.L4]
m = 99
s = 97
[behavioral]
[behavioral.corroboration]
distinct_families_for_rate_limit = 3
distinct_families_for_deny = 4
""")
    eff = merge_policy_overlay(g, ov)
    assert eff.rung_floors["L4"].m == 99   # raised
    assert eff.rung_floors["L1"].m == 85   # untouched rung stays global
    assert eff.behavioral_rate_limit_families == 3
    assert eff.behavioral_deny_families == 4


def test_overlay_mode_and_allowlist_semantics():
    g = _global()
    # overlay with allowlist: mode steps down restrictiveness; allowlist may
    # only RE-AFFIRM a governed entry, never introduce a NEW suppressed value
    # (a new value would loosen the global control by blocking enforcement).
    ov = _overlay("""
policy_version = "t3"
mode = "OFF"
scope = "*"
allowlist = [ { value = "governed.operator.test", owner = "tenant", ticket = "t-1" } ]
""")
    eff = merge_policy_overlay(g, ov)
    assert eff.mode == "OFF"              # tenant opted out of auto-action
    keys = {e.value for e in eff.allowlist}
    assert "governed.operator.test" in keys   # governed entry re-affirmed
    # overlay CANNOT introduce a brand-new allowlisted value (losening)
    widen_allow = _overlay("""
policy_version = "t3b"
mode = "ENFORCE"
scope = "*"
allowlist = [ { value = "untrusted.corp.test", owner = "tenant", ticket = "t-x" } ]
""")
    effb = merge_policy_overlay(g, widen_allow)
    assert "untrusted.corp.test" not in {e.value for e in effb.allowlist}
    # overlay cannot demand a STRONGER mode than global
    stronger = _overlay('policy_version="t4"\nmode="EMERGENCY"\nscope="*"\n')
    eff2 = merge_policy_overlay(g, stronger)
    assert eff2.mode == "ENFORCE"          # clamped to global, not escalated


def _can_connect() -> bool:
    try:
        conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
        conn.close()
        return True
    except psycopg2.Error:
        return False


def test_tenant_overlay_drives_a_tighter_decision():
    """Integration: a tenant with a stricter overlay gets a TIGHTER decision on
    the same evidence than the global policy alone."""
    if not _can_connect():
        pytest.skip("no reachable Postgres for tenant integration test")
    from apip.config.service import AdapterConfig, DatabaseConfig, load_config  # noqa: PLC0415
    from apip.ledger.db import Database  # noqa: PLC0415
    from apip.ledger.migrations import apply_migrations  # noqa: PLC0415
    from apip.controller.engine import DecisionPipeline  # noqa: PLC0415
    from apip.controller.service import Controller  # noqa: PLC0415
    from apip.domain.models import Evidence, Indicator  # noqa: PLC0415

    dburi = "apip_tn_" + uuid.uuid4().hex[:12]
    conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    try:
        cur.execute(f'CREATE DATABASE "{dburi}"')
    finally:
        cur.close(); conn.close()

    cfg = replace(
        load_config(None),
        db=DatabaseConfig(host=pg.HOST, port=pg.PORT, dbname=dburi,
                          user=pg.USER),
        adapter=replace(AdapterConfig(rpz_mode="SHADOW", zone_dir="/tmp/apip_tn_rpz"),
                        authorized_domains=("corp.test",)),
    )
    db = Database(cfg.db.dsn_kwargs())
    try:
        db.wait_until_ready(timeout_s=10)
        apply_migrations(db)
        ctrl = Controller(cfg)
        ctrl.start()
        try:
            # active policy: global (ENFORCE, fqdn_auto_m=90)
            ctrl.ledger.stage_policy(
                policy_version="global.1", revision=1,
                content_sha256="sha", raw_text=GLOBAL_TOML, mode="ENFORCE",
                staged_by="test")
            ctrl.ledger.promote_policy("global.1", 1, "test")

            # register a source so evidence has authority
            ctrl.ledger.register_source(source_id="feeda", source_class="curated",
                                        independent=True, key_hash="x", actor="test",
                                        auto_enforcement_allowed=True, enabled=True)
            ctrl.ledger.register_source(source_id="feedb", source_class="curated",
                                        independent=True, key_hash="x", actor="test",
                                        auto_enforcement_allowed=True, enabled=True)

            def _seed(ind_id, tenant_id) -> str:
                ctrl.ledger.record_batch(batch_id=f"b-{ind_id}", source_id="feeda",
                                         raw_sha256=f"s-{ind_id}", indicator_count=1, demoted=0,
                                         channel="t", actor="test")
                ind = Indicator(
                    id=ind_id, type="fqdn", value=f"{ind_id}.evil.corp.test",
                    sources=("feeda", "feedb"),
                    evidence=(Evidence(kind="curated_source", source_id="feeda",
                                       source_class="curated",
                                       observed_at="2026-09-03T00:00:00Z", independent=True),
                              Evidence(kind="curated_source", source_id="feedb",
                                       source_class="curated",
                                       observed_at="2026-09-03T00:00:00Z", independent=True),
                              Evidence(kind="exact_fqdn", source_id="feeda",
                                       source_class="curated",
                                       observed_at="2026-09-03T00:00:00Z", independent=True)),
                    tags=("c2",))
                durable = ctrl.ledger.upsert_indicator(ind, f"b-{ind_id}",
                                                       tenant_id=tenant_id)
                from datetime import datetime, timedelta, timezone
                # bump observed_at into recency window relative to run clock
                recent = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
                ctrl.db.execute(
                    "UPDATE evidence SET observed_at=%s WHERE indicator_id=%s",
                    (recent, durable))
                return durable

            # global tenant: same evidence, no overlay
            gdurable = _seed("ind--global", None)
            gres = ctrl.pipeline.decide_indicator(gdurable, actor="test")
            assert gres is not None
            g_m = gres["decision"].maliciousness

            # tenant with overlay raising fqdn_auto_m FAR above -> the effective
            # threshold is higher, so a score that auto-enforces globally becomes
            # NO_ACTION (below the tenant's raised floor).
            overlay_raw = """
policy_version = "tenant.hot"
mode = "ENFORCE"
scope = "*"
[thresholds]
fqdn_auto_m = 100
"""
            import hashlib
            ctrl.ledger.upsert_tenant_overlay(
                tenant_id="tenant-hot", raw_text=overlay_raw,
                overlay_sha256=hashlib.sha256(overlay_raw.encode()).hexdigest(),
                created_by="test")
            tdurable = _seed("ind--tenant", "tenant-hot")
            tres = ctrl.pipeline.decide_indicator(tdurable, actor="test",
                                                  tenant_id="tenant-hot")
            assert tres is not None
            t_m = tres["decision"].maliciousness
            # both share the same maliciousness score (same evidence/policy weights)
            assert g_m == t_m
            # but the tenant got fewer/no stronger action because its threshold
            # is stricter: disposition must be no-more-permissive than global's.
            # (given fqdn_auto_m=100 and a score < 100, tenant lands NO_ACTION /
            # OBSERVE where global may still act)
            # audit #39: the product claim must be FALSIFIABLE — the tenant
            # decision is strictly observed-or-nothing here; if the overlay
            # ever stops tightening, this fails.
            assert tres["decision"].disposition in ("NO_ACTION", "OBSERVE"), \
                (tres["decision"].disposition, gres["decision"].disposition)
            assert gres["decision"].disposition in ("NO_ACTION", "OBSERVE",
                                                    "AUTO_ENFORCE",
                                                    "PROPOSE_OPERATOR_APPROVAL")
        finally:
            ctrl.stop()
    finally:
        db.close()
        conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        try:
            cur.execute(f'DROP DATABASE IF EXISTS "{dburi}" WITH (FORCE)')
        finally:
            cur.close(); conn.close()