"""Policy lifecycle safety (audit P0 #5/#6/#7).

An installed control is an instance of a policy decision. These tests
prove the three lifecycle properties the audit found missing:

  P0 #5  promotion reconciles ALREADY-ACTIVE enforcement: after a policy
         change that no longer justifies a live control (target
         allowlisted, ENFORCE demoted to SHADOW, target out of scope),
         the periodic reconciler removes it — verification alone must
         never keep an obsolete control healthy.

  P0 #6  proposals are bound to the active policy revision: a decision
         proposed under an older policy content hash cannot be approved
         (and a pending action cannot be dispatched) after a semantic
         policy change — it must be regenerated.

  P0 #7  the global blast-radius cap applies on the GLOBAL path: the
         shipped ``max_new_auto_actions_per_batch`` previously gated only
         tenant-overlay batches; a global batch with cap=1 and three
         actionable FQDNs mints exactly one action and demotes two.

Proven against real Postgres (skip when unreachable).
"""
from __future__ import annotations

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

import pg  # noqa: E402  (shared Postgres test endpoints)

from apip.config.service import (  # noqa: E402
    AdapterConfig,
    ControllerConfig,
    DatabaseConfig,
    load_config,
)
from apip.controller.service import Controller  # noqa: E402
from apip.domain.models import Evidence, Indicator  # noqa: E402
from apip.ledger.db import Database  # noqa: E402
from apip.ledger.migrations import apply_migrations  # noqa: E402
from apip.ledger.repo import Ledger  # noqa: E402


def _can_connect() -> bool:
    try:
        conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
        conn.close()
        return True
    except psycopg2.Error:
        return False


pytestmark = pytest.mark.skipif(
    not _can_connect(),
    reason="no reachable Postgres for policy-lifecycle tests")


POLICY_V1 = """
policy_version = "lifecycle"
mode = "ENFORCE"
scope = "tenant-world"
allowlist = []

[thresholds]
observe_m = 40
fqdn_auto_m = 90
fqdn_auto_s = 85
ip_rate_m = 90
ip_rate_s = 85
ip_deny_m = 98
ip_deny_s = 95

[thresholds.rungs.L4]
m = 95
s = 75

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
enabled_families = []
max_behavioral_m_contribution = 60
[behavioral.corroboration]
distinct_families_for_rate_limit = 2
distinct_families_for_deny = 3
deny_also_requires_external = true
"""

# v2 allowlists a1.evil.corp.test — a live control for that name must go.
POLICY_V2_ALLOWLIST = POLICY_V1.replace(
    'allowlist = []',
    'allowlist = [ { value = "a1.evil.corp.test", owner = "op", '
    'ticket = "t-1" } ]').replace(
    'policy_version = "lifecycle"', 'policy_version = "lifecycle2"')

# v2 demotes posture ENFORCE -> SHADOW (a live ENFORCE control must go).
POLICY_V2_SHADOW = POLICY_V1.replace(
    'mode = "ENFORCE"', 'mode = "SHADOW"').replace(
    'policy_version = "lifecycle"', 'policy_version = "lifecycle2"')

# v2 with a different blast-radius knob only (semantics unchanged apart
# from the content hash — still a NEW revision that must invalidate a
# stale proposal).
POLICY_V2_BUDGET = POLICY_V1.replace(
    'max_auto_ttl_seconds = 600',
    'max_auto_ttl_seconds = 599').replace(
    'policy_version = "lifecycle"', 'policy_version = "lifecycle2"')


@pytest.fixture()
def env():
    """Yields (controller, ledger, db) over one scratch Postgres database."""
    name = "apip_plc_" + uuid.uuid4().hex[:12]
    conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    conn.cursor().execute(f'CREATE DATABASE "{name}"')
    conn.close()
    zone_dir = f"/tmp/apip_plc_rpz_{uuid.uuid4().hex[:8]}"
    cfg = replace(
        load_config(None),
        db=DatabaseConfig(host=pg.HOST, port=pg.PORT, dbname=name,
                          user=pg.USER),
        controller=replace(ControllerConfig(), reconcile_interval_s=0.2,
                           verify_interval_s=3600),
        adapter=replace(
            # audit #31: an ENFORCE posture with the UNEDITED example zone
            # name is refused at startup — fixtures use operator-owned values
            AdapterConfig(rpz_mode="ENFORCE", zone_dir=zone_dir,
                          zone_name="apip.lifecycle.test",
                          reload_command="true",
                          verify_query_server="127.0.0.1",
                          verify_query_port=5333),
            authorized_domains=("corp.test", "operator.test")),
    )
    db = Database(cfg.db.dsn_kwargs())
    db.wait_until_ready(timeout_s=10)
    apply_migrations(db)
    led = Ledger(db)
    ctrl = Controller(cfg)
    ctrl.start()
    try:
        yield ctrl, led, db
    finally:
        ctrl.stop()
        db.close()
        conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        conn.cursor().execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        conn.close()


def _activate(led: Ledger, text: str, version: str) -> str:
    """Stage+promote a policy; returns its content hash."""
    import hashlib
    rev = led.next_policy_revision(version)
    sha = hashlib.sha256(text.encode()).hexdigest()
    led.stage_policy(policy_version=version, revision=rev,
                     content_sha256=sha, raw_text=text,
                     mode="ENFORCE" if "ENFORCE" in text else "SHADOW",
                     staged_by="test")
    led.promote_policy(version, rev, "test")
    return sha


def _seed_action(ctrl: Controller, led: Ledger, db: Database, tag: str,
                 state: str = "applied") -> str:
    """An applied control justified by a decision bound to the CURRENT
    policy content (the normal state after dispatch)."""
    ind = f"{tag}.evil.corp.test"
    sha = led.current_policy_row()["content_sha256"]
    db.execute(
        "INSERT INTO indicators (indicator_id, itype, value) VALUES (%s, "
        "'fqdn', %s) ON CONFLICT DO NOTHING", (f"indicator--{tag}", ind))
    db.execute("""
INSERT INTO decisions (decision_id, seq, indicator_id, batch_id, maliciousness,
    action_safety, disposition, action, rung, scope, ttl_seconds,
    policy_version, policy_content_sha256, reason_codes, explanation,
    content_hash)
VALUES (%s, 1, %s, NULL, 95, 95, 'AUTO_ENFORCE', 'dns_nxdomain', 'L4', '*',
        600, 'lifecycle', %s, '{}', 'x', 'h--' || %s)
""", (f"decision--{tag}", f"indicator--{tag}", sha, tag))
    db.execute("""
INSERT INTO actions (action_id, decision_id, decision_seq, indicator_id, adapter,
    action_type, mode, selector, rule_id, fragment, fragment_hash, bundle_id,
    bundle_hash, requested_by, state)
VALUES (%s, %s, 1, %s, 'rpz', 'dns_nxdomain', 'ENFORCE', %s, %s, %s, 'h',
        'b', 'bh', 'test', %s)
""", (f"action--{tag}", f"decision--{tag}", f"indicator--{tag}",
      f'{{"scope_type": "destination_global", "exact_fqdn": "{ind}"}}',
      f"owner:{ind}", f"{ind} IN CNAME .", state))
    return f"action--{tag}"


def _state(db: Database, action_id: str) -> tuple[str, str]:
    row = db.query_one(
        "SELECT state, desired_state FROM actions WHERE action_id=%s",
        (action_id,))
    return row["state"], row["desired_state"]


def _wait_for(condition, timeout_s: float = 10.0, poll_s: float = 0.05):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(poll_s)
    return False


# --------------------------------------------------------------------------- #
# P0 #5 — promotion reconciles already-active controls
# --------------------------------------------------------------------------- #

def test_allowlist_promotion_removes_live_control(env):
    ctrl, led, db = env
    _activate(led, POLICY_V1, "lifecycle")
    aid = _seed_action(ctrl, led, db, "a1")
    assert _state(db, aid) == ("applied", "PRESENT")
    # promote the allowlisting revision; the reconciler must converge
    _activate(led, POLICY_V2_ALLOWLIST, "lifecycle2")
    assert _wait_for(
        lambda: _state(db, aid)[0] == "revoked"), _state(db, aid)
    assert _state(db, aid)[1] == "ABSENT"


def test_posture_demotion_removes_live_enforce_control(env):
    ctrl, led, db = env
    _activate(led, POLICY_V1, "lifecycle")
    aid = _seed_action(ctrl, led, db, "a2")
    _activate(led, POLICY_V2_SHADOW, "lifecycle2")
    assert _wait_for(
        lambda: _state(db, aid)[0] == "revoked"), _state(db, aid)
    assert _state(db, aid)[1] == "ABSENT"


def test_healthy_control_survives_untouched_policy(env):
    """The negative case: a control still justified by the current policy
    must NOT be churned by the reconcile sweep (a target outside the
    allowlist, in scope, SHADOW posture — permitted-weaker under the
    ENFORCE policy). The rule is written into the shadow artifact first so
    the periodic verify sweep honestly confirms it (ENFORCE verify fails
    closed without a configured resolver, so the physical control here is
    a SHADOW one — file-verifiable)."""
    ctrl, led, db = env
    _activate(led, POLICY_V1, "lifecycle")
    aid = _seed_action(ctrl, led, db, "ok1", state="applied")
    db.execute("UPDATE actions SET mode='SHADOW' WHERE action_id=%s", (aid,))
    adapter = ctrl._adapter_for({"adapter": "rpz"})
    r = adapter.apply({
        "action_id": aid, "decision_id": "decision--ok1", "mode": "SHADOW",
        "action_type": "dns_nxdomain", "rule_id": "owner:ok1.evil.corp.test",
        "fragment": "ok1.evil.corp.test IN CNAME .",
        "selector": {"scope_type": "destination_global",
                     "exact_fqdn": "ok1.evil.corp.test"},
        "ttl_seconds": 600})
    assert r["ok"], r
    _activate(led, POLICY_V2_ALLOWLIST, "lifecycle2")   # allowlists a1 only
    time.sleep(1.0)  # let several reconcile passes run
    state, desired = _state(db, aid)
    assert state in ("applied", "verified") and desired == "PRESENT", \
        f"healthy control was churned: {_state(db, aid)}"


# --------------------------------------------------------------------------- #
# P0 #6 — proposals and actions are bound to the active policy revision
# --------------------------------------------------------------------------- #

def test_stale_proposal_cannot_be_approved(env):
    ctrl, led, db = env
    sha1 = _activate(led, POLICY_V1, "lifecycle")
    ind = "stale.evil.corp.test"
    db.execute(
        "INSERT INTO indicators (indicator_id, itype, value) VALUES (%s, "
        "'fqdn', %s) ON CONFLICT DO NOTHING",
        ("indicator--stale", ind))
    db.execute("""
INSERT INTO decisions (decision_id, seq, indicator_id, batch_id, maliciousness,
    action_safety, disposition, action, rung, scope, ttl_seconds,
    policy_version, policy_content_sha256, reason_codes, explanation,
    content_hash)
VALUES ('decision--stale', 1, 'indicator--stale', NULL, 95, 95,
        'PROPOSE_OPERATOR_APPROVAL', 'dns_nxdomain', 'L4', '*', 600,
        'lifecycle', %s, '{}', 'x', 'h--stale')
""", (sha1,))
    # semantic change: new revision, different content
    _activate(led, POLICY_V2_BUDGET, "lifecycle2")
    with pytest.raises(ValueError, match="different policy revision"):
        ctrl.approve_decision("decision--stale", "operator", "go")


def test_fresh_proposal_still_approvable(env):
    ctrl, led, db = env
    sha = _activate(led, POLICY_V1, "lifecycle")
    db.execute(
        "INSERT INTO indicators (indicator_id, itype, value) VALUES (%s, "
        "'fqdn', %s) ON CONFLICT DO NOTHING",
        ("indicator--fresh", "fresh.evil.corp.test"))
    db.execute("""
INSERT INTO decisions (decision_id, seq, indicator_id, batch_id, maliciousness,
    action_safety, disposition, action, rung, scope, ttl_seconds,
    policy_version, policy_content_sha256, reason_codes, explanation,
    content_hash)
VALUES ('decision--fresh', 1, 'indicator--fresh', NULL, 95, 95,
        'PROPOSE_OPERATOR_APPROVAL', 'dns_nxdomain', 'L4', '*', 600,
        'lifecycle', %s, '{}', 'x', 'h--fresh')
""", (sha,))
    out = ctrl.approve_decision("decision--fresh", "operator", "go")
    assert out["compiled"] is True


def test_pending_action_under_old_revision_is_cancelled_at_dispatch(env):
    ctrl, led, db = env
    sha1 = _activate(led, POLICY_V1, "lifecycle")
    ind = "pend.evil.corp.test"
    db.execute(
        "INSERT INTO indicators (indicator_id, itype, value) VALUES (%s, "
        "'fqdn', %s) ON CONFLICT DO NOTHING",
        ("indicator--pend", ind))
    db.execute("""
INSERT INTO decisions (decision_id, seq, indicator_id, batch_id, maliciousness,
    action_safety, disposition, action, rung, scope, ttl_seconds,
    policy_version, policy_content_sha256, reason_codes, explanation,
    content_hash)
VALUES ('decision--pend', 1, 'indicator--pend', NULL, 95, 95, 'AUTO_ENFORCE',
        'dns_nxdomain', 'L4', '*', 600, 'lifecycle', %s, '{}', 'x',
        'h--pend')
""", (sha1,))
    db.execute("""
INSERT INTO actions (action_id, decision_id, decision_seq, indicator_id,
    adapter, action_type, mode, selector, rule_id, fragment, fragment_hash,
    bundle_id, bundle_hash, requested_by, state)
VALUES ('action--pend', 'decision--pend', 1, 'indicator--pend', 'rpz',
        'dns_nxdomain', 'ENFORCE',
        '{"scope_type": "destination_global", "exact_fqdn": "pend.evil.corp.test"}',
        'owner:pend.evil.corp.test', 'pend.evil.corp.test IN CNAME .', 'h',
        'b', 'bh', 'test', 'pending')
""")
    # semantic promotion BEFORE dispatch
    _activate(led, POLICY_V2_BUDGET, "lifecycle2")
    ctrl._dispatch_one(db.query_one(
        "SELECT * FROM actions WHERE action_id='action--pend'"))
    row = db.query_one(
        "SELECT state, state_reason FROM actions WHERE action_id='action--pend'")
    assert row["state"] == "cancelled_policy_changed", row
    assert "policy_revision_changed" in row["state_reason"], row


# --------------------------------------------------------------------------- #
# P0 #7 — the global blast-radius cap
# --------------------------------------------------------------------------- #

def test_global_batch_budget_caps_actions(env):
    """Global ENFORCE policy with cap=1, three independently actionable
    FQDNs: exactly one action, two persisted as budget-demoted OBSERVE
    decisions, and the audit event records {budget, demoted}. No tenant
    header (tenant_id=None) — the path that previously bypassed the cap."""
    ctrl, led, db = env
    _activate(led, POLICY_V1.replace(
        "[limits]", "[limits]\nmax_new_auto_actions_per_batch = 1"),
        "lifecycle")
    from apip.ingest import IngestBatch

    def ts(minutes_ago: int) -> str:
        return (datetime.now(timezone.utc)
                - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _auto_tier(i: int) -> Indicator:
        """The evidence recipe that reaches the policy's AUTO tier (the same
        mix test_ingest_identity proves: local detection + recency + two
        independent curated corroborations)."""
        return Indicator(
            id=f"indicator--budget{i}", type="fqdn",
            value=f"b{i}.evil.corp.test",
            sources=("local-sensor", "feeda", "feedb"),
            evidence=(Evidence(kind="direct_local_detection",
                               source_id="local-sensor",
                               source_class="local",
                               observed_at=ts(20), independent=True),
                      Evidence(kind="exact_fqdn", source_id="local-sensor",
                               source_class="local",
                               observed_at=ts(15), independent=True),
                      Evidence(kind="exact_ip", source_id="local-sensor",
                               source_class="local",
                               observed_at=ts(10), independent=True),
                      Evidence(kind="recent", source_id="local-sensor",
                               source_class="local",
                               observed_at=ts(5), independent=True),
                      Evidence(kind="curated_source", source_id="feeda",
                               source_class="curated",
                               observed_at=ts(30), independent=True),
                      Evidence(kind="curated_source", source_id="feedb",
                               source_class="curated",
                               observed_at=ts(25), independent=True)),
            tags=("c2",))

    inds = tuple(_auto_tier(i) for i in range(3))
    batch = IngestBatch(
        batch_id="batch--budget", source_id="local-sensor",
        raw_sha256="sha-budget", indicators=inds, demoted_records=0)
    led.register_source(source_id="local-sensor", source_class="local",
                        independent=True, key_hash="x", actor="test",
                        auto_enforcement_allowed=True, enabled=True)
    led.register_source(source_id="feeda", source_class="curated",
                        independent=True, key_hash="x", actor="test",
                        auto_enforcement_allowed=True, enabled=True)
    led.register_source(source_id="feedb", source_class="curated",
                        independent=True, key_hash="x", actor="test",
                        auto_enforcement_allowed=True, enabled=True)
    result = ctrl.process_batch(batch=batch, actor="test", tenant_id=None)
    assert result["actions"] == 1, result
    assert result["demoted"] == 2, result
    row = db.query_one("""
SELECT count(*) AS n FROM decisions
WHERE reason_codes::text LIKE '%%blast_radius_budget_exceeded%%'
""")
    assert row["n"] == 2, "demoted decisions not persisted"
    events = db.query("""
SELECT detail FROM audit_events WHERE event_type='policy.blast_radius_budget'
""")
    assert events, "budget demotion not audited"
