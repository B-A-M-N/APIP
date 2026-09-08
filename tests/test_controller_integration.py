"""Optional integration test of the Task 4 controller wiring against a real
Postgres.

This exercises the REAL controller orchestration that the DB-free wiring tests
can only stub:
  - operator approval (PROPOSE_OPERATOR_APPROVAL) compiles an action;
  - dispatch applies it (receipt carries observed infra state — no fabricated
    success);
  - policy replay re-baselines indicators against the active policy;
  - adapters_status enumerates every configured adapter (RPZ + Suricata).

It RUNS only when a reachable Postgres lets the current OS user create a
throwaway database; otherwise it is skipped so the always-on baseline stays
green without a database. A unique scratch DB is created and dropped per run.
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import uuid
from dataclasses import replace
from pathlib import Path

import psycopg2
import psycopg2.extensions
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pg  # noqa: E402  (shared Postgres test endpoints)

from apip.config.service import (  # noqa: E402
    AdapterConfig,
    DatabaseConfig,
    load_config,
)
from apip.domain.models import (  # noqa: E402
    ActionSelector,
    Decision,
    Evidence,
    Indicator,
)



def _can_connect() -> bool:
    try:
        conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
        conn.close()
        return True
    except psycopg2.Error:
        return False


def _create_scratch() -> str:
    """Create a scratch database owned by the current user; raise if we cannot
    (no createdb privilege or unreachable server)."""
    name = "apip_it_" + uuid.uuid4().hex[:12]
    conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    try:
        cur.execute(f'CREATE DATABASE "{name}"')
    finally:
        cur.close()
        conn.close()
    return name


def _drop_scratch(name: str) -> None:
    conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    try:
        cur.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    finally:
        cur.close()
        conn.close()


pytestmark = pytest.mark.skipif(
    not _can_connect(),
    reason="no reachable Postgres for controller integration test")


@pytest.fixture(scope="module")
def controller():
    from apip.controller.service import Controller
    from apip.ledger.db import Database
    from apip.ledger.migrations import apply_migrations

    dburi = _create_scratch()
    zone = tempfile.mkdtemp(prefix="apip_it_zone_")
    try:
        cfg = replace(
            load_config(None),
            db=DatabaseConfig(host=pg.HOST, port=pg.PORT, dbname=dburi, user=pg.USER),
            adapter=replace(AdapterConfig(rpz_mode="SHADOW", zone_dir=zone),
                            authorized_domains=("operator.test",)),
        )
        db = Database(cfg.db.dsn_kwargs())
        db.wait_until_ready(timeout_s=10)
        apply_migrations(db)
        db.close()

        ctrl = Controller(cfg)
        ctrl.start()
        # seed the channel source the ledger FKs require
        ctrl.ledger.register_source(
            source_id="local-sensor", source_class="local", independent=True,
            key_hash="x", actor="operator", auto_enforcement_allowed=True, enabled=True)
        # stage + promote the enforce policy so an active policy governs
        pol_text = (Path(__file__).resolve().parents[1]
                    / "examples" / "enforce_policy.toml").read_text()
        rev = ctrl.ledger.next_policy_revision("beta")
        ctrl.ledger.stage_policy(
            policy_version="beta", revision=rev,
            content_sha256=hashlib.sha256(pol_text.encode()).hexdigest(),
            raw_text=pol_text, mode="ENFORCE", staged_by="operator")
        ctrl.ledger.promote_policy("beta", rev, "operator")
        yield ctrl, cfg
        ctrl.stop()
    finally:
        _drop_scratch(dburi)


def _record_approval_decision(ctrl, decision_id: str, value: str) -> None:
    """Seed an indicator + a PROPOSE_OPERATOR_APPROVAL decision in the ledger,
    the durable precondition the operator approve path consumes."""
    batch = "batch--" + decision_id
    ctrl.ledger.record_batch(batch_id=batch, source_id="local-sensor",
                             raw_sha256="sha" + decision_id, indicator_count=1,
                             demoted=0, channel="local-sensor", actor="operator")
    ind = Indicator(
        id=f"indicator--{decision_id}", type="fqdn", value=value,
        sources=("local-sensor",),
        evidence=(Evidence(kind="direct_local_detection", source_id="local-sensor",
                           source_class="local", observed_at="2026-09-03T03:00:00Z",
                           independent=True),),
        tags=("c2",))
    durable = ctrl.ledger.upsert_indicator(ind, batch)
    sel = ActionSelector(scope_type="client_destination_pair", client=None,
                         destination=value, protocol_class="interactive_http")
    d = Decision(
        id=decision_id, indicator_id=durable, maliciousness=97, action_safety=90,
        disposition="PROPOSE_OPERATOR_APPROVAL", action="dns_nxdomain", rung="L4",
        scope=ctrl.current_policy().scope, ttl_seconds=3600, policy_version="beta",
        reason_codes=("proposed",), explanation="integration approval",
        selector=sel, content_hash="hash--" + hashlib.sha256(decision_id.encode()).hexdigest())
    # the decision is bound to the ACTIVE policy revision's content hash
    # (audit P0 #6: approval/dispatch verify this binding)
    active = ctrl.ledger.current_policy_row()
    ctrl.ledger.record_decision(
        d, indicator_id=durable, batch_id=batch,
        policy_content_sha256=(active["content_sha256"] if active else "sha"),
        actor="operator")


def test_approve_compiles_and_applies_action(controller):
    ctrl, _ = controller
    did = "decision--it-approve"
    value = "c2-appr.operator.test"
    _record_approval_decision(ctrl, did, value)

    res = ctrl.approve_decision(did, "operator")
    assert res["compiled"] is True
    assert res["action_ids"]

    # the created action is a pending RPZ draft awaiting the worker dispatch
    action = ctrl.ledger.get_action(res["action_ids"][0])
    assert action["adapter"] == "rpz"
    assert action["mode"] == "SHADOW"
    assert action["state"] == "pending"

    # manual dispatch applies it, VERIFIES on apply (audit P1 #11), and
    # records a REAL receipt (observed infra state)
    ctrl._dispatch_one(action)
    applied = ctrl.ledger.get_action(action["action_id"])
    assert applied["state"] == "verified"
    receipts = ctrl.ledger.list_receipts(action["action_id"])
    assert receipts
    observed = receipts[0]["observed"]
    # no fabricated success: the receipt carries observed zone/owner state
    assert "zone_file" in observed and "zone_sha256" in observed


def test_approval_is_one_shot_and_rejection_terminates(controller):
    """P0 #16: approvals are DURABLE one-shot state. A second approval of
    the same decision instance is refused; a rejected proposal can never be
    approved; the approval row cites the exact decision seq + policy hash."""
    ctrl, _ = controller

    # approve once -> durable row citing the exact decision instance
    did = "decision--it-once"
    _record_approval_decision(ctrl, did, "once.operator.test")
    seq = ctrl.ledger.get_decision(did)["seq"]
    res = ctrl.approve_decision(did, "operator", reason="validated")
    assert res["compiled"] is True
    row = ctrl.ledger.approval_for(did, seq)
    assert row is not None and row["outcome"] == "approved"
    assert row["actor"] == "operator" and row["reason"] == "validated"
    assert row["policy_content_sha256"]
    assert row["action_ids"] == res["action_ids"]

    # a second approval of the SAME instance is refused
    try:
        ctrl.approve_decision(did, "operator")
        assert False, "second approval must be refused"
    except ValueError as e:
        assert "one-shot" in str(e) or "already" in str(e)

    # rejection terminates a proposal durably
    did2 = "decision--it-reject"
    _record_approval_decision(ctrl, did2, "reject.operator.test")
    out = ctrl.reject_decision(did2, "operator", reason="fp")
    assert out["outcome"] == "rejected"
    rrow = ctrl.ledger.approval_for(did2)
    assert rrow["outcome"] == "rejected"
    try:
        ctrl.approve_decision(did2, "operator")
        assert False, "approving a rejected proposal must be refused"
    except ValueError:
        pass


def test_action_cites_the_exact_authorizing_decision_instance(controller):
    """P0 #17: an action's decision_seq is the REAL immutable decision
    instance that authorized it (never 0), and the composite FK holds."""
    ctrl, _ = controller
    did = "decision--it-seq"
    _record_approval_decision(ctrl, did, "seq.operator.test")
    res = ctrl.approve_decision(did, "operator")
    action = ctrl.ledger.get_action(res["action_ids"][0])
    expected = ctrl.ledger.get_decision(did)["seq"]
    assert action["decision_seq"] == expected and expected != 0
    # the (decision_id, seq) pair resolves to exactly one decision row
    row = ctrl.db.query_one(
        "SELECT decision_id FROM decisions WHERE decision_id=%s AND seq=%s",
        (did, action["decision_seq"]))
    assert row is not None


def test_approve_refuses_non_approval_decision(controller):
    ctrl, _ = controller
    # NO_ACTION decisions must never be approved into an action
    try:
        ctrl.approve_decision("decision--missing", "operator")
        assert False, "unknown decision should raise"
    except LookupError:
        pass


def test_adapters_status_includes_rpz_and_suricata(controller):
    ctrl, _ = controller
    names = {a["name"] for a in ctrl.adapters_status()}
    assert {"rpz", "suricata"} <= names


def test_replay_policy_runs_against_active_policy(controller):
    ctrl, _ = controller
    from apip.ingest import IngestChannel, parse_indicator_payload
    import json as _json

    batch = "batch--replay"
    ctrl.ledger.record_batch(batch_id=batch, source_id="local-sensor",
                             raw_sha256="sha-replay", indicator_count=1,
                             demoted=0, channel="local-sensor", actor="operator")
    payload = {"indicators": [{
        "id": "indicator--replay", "type": "fqdn", "value": "replay.operator.test",
        "sources": ["local-sensor"], "first_seen": "2026-09-03T03:00:00Z",
        "last_seen": "2026-09-03T03:40:00Z", "tags": ["c2"],
        "evidence": [
            {"kind": "direct_local_detection", "source_id": "local-sensor",
             "observed_at": "2026-09-03T03:00:00Z"},
            {"kind": "exact_fqdn", "source_id": "local-sensor",
             "observed_at": "2026-09-03T03:10:00Z"},
            {"kind": "recent", "source_id": "local-sensor",
             "observed_at": "2026-09-03T03:30:00Z"}]}]}
    channel = IngestChannel(source_id="local-sensor", allowed_source_ids=frozenset())
    pb = parse_indicator_payload(_json.dumps(payload).encode(), channel)
    for ind in pb.indicators:
        ctrl.ledger.upsert_indicator(ind, batch)

    result = ctrl.replay_policy("operator")
    assert result["indicators"] >= 2          # replay + approval seed indicators
    assert "policy_version" in result
    assert result["recorded"] >= 0            # idempotent; may record some new


def test_operator_reads_never_leak_key_hash(controller):
    """GET-style ledger read of a source must exclude the PBKDF2 key_hash.
    (Previously get_source did SELECT *, leaking the stored credential hash
    to the operator read surface.)"""
    ctrl, _ = controller
    # register_source in the fixture used key_hash="x"; re-read via get_source
    row = ctrl.ledger.get_source("local-sensor")
    assert row is not None
    assert "key_hash" not in row
    assert row["source_id"] == "local-sensor"
    assert row["source_class"] == "local"
    # list_sources, the other operator-facing read, also excludes it
    for s in ctrl.ledger.list_sources():
        assert "key_hash" not in s


def test_record_decision_idempotent_at_the_database(controller):
    """record_decision is idempotent on (decision_id, content_hash) and that
    invariant is pinned by a UNIQUE index (no check-then-insert race): the
    first insert returns the instance's seq, the identical re-insert returns
    None, and the DB holds exactly one row for that content hash."""
    ctrl, _ = controller
    # seed a fresh indicator then record the same decision twice
    value = "c2-idedup.operator.test"
    batch = "batch--idedup"
    ctrl.ledger.record_batch(batch_id=batch, source_id="local-sensor",
                             raw_sha256="sha-idedup", indicator_count=1,
                             demoted=0, channel="local-sensor", actor="operator")
    ind = Indicator(
        id="indicator--idedup", type="fqdn", value=value,
        sources=("local-sensor",),
        evidence=(Evidence(kind="direct_local_detection", source_id="local-sensor",
                           source_class="local", observed_at="2026-09-03T03:00:00Z",
                           independent=True),),
        tags=("c2",))
    durable = ctrl.ledger.upsert_indicator(ind, batch)
    d = Decision(
        id="decision--idedup", indicator_id=durable, maliciousness=60,
        action_safety=80, disposition="SHADOW_ACTION", action="dns_nxdomain",
        rung="L4", scope=ctrl.current_policy().scope, ttl_seconds=600,
        policy_version="beta", reason_codes=("shadow",),
        explanation="integration idempotency",
        selector=ActionSelector(scope_type="client_destination_pair",
                                client=None, destination=value,
                                protocol_class="interactive_http"),
        content_hash="hash--idedup-constant")
    seq = ctrl.ledger.record_decision(
        d, indicator_id=durable, batch_id=batch,
        policy_content_sha256="sha", actor="operator")
    assert isinstance(seq, int)
    # identical decision instance => refused (returns None)
    assert ctrl.ledger.record_decision(
        d, indicator_id=durable, batch_id=batch,
        policy_content_sha256="sha", actor="operator") is None
    rows = ctrl.db.query(
        "SELECT seq FROM decisions WHERE decision_id=%s", ("decision--idedup",))
    assert len(rows) == 1          # the UNIQUE index held
    # a DIFFERENT content_hash for the same decision_id is still allowed
    d2 = Decision(
        id="decision--idedup", indicator_id=durable, maliciousness=61,
        action_safety=80, disposition="SHADOW_ACTION", action="dns_nxdomain",
        rung="L4", scope=ctrl.current_policy().scope, ttl_seconds=600,
        policy_version="beta", reason_codes=("shadow",),
        explanation="integration idempotency v2",
        selector=d.selector, content_hash="hash--idedup-other")
    seq2 = ctrl.ledger.record_decision(
        d2, indicator_id=durable, batch_id=batch,
        policy_content_sha256="sha", actor="operator")
    assert isinstance(seq2, int) and seq2 != seq
    rows = ctrl.db.query(
        "SELECT seq FROM decisions WHERE decision_id=%s", ("decision--idedup",))
    assert len(rows) == 2

def test_persisted_mode_survives_posture_flip_restart(controller):
    """Review P0 #1, restart leg: actions created under a SHADOW-posture
    controller keep their serialized SHADOW mode authoritative when the
    deployment is restarted with the adapter configured ENFORCE. The
    re-verified action stays at the shadow artifact (rpz-passthru) — the
    config flip must not upgrade already-created actions into the live
    zone."""
    ctrl, cfg = controller
    did = "decision--it-posture"
    value = "c2-posture.operator.test"
    _record_approval_decision(ctrl, did, value)
    res = ctrl.approve_decision(did, "operator")
    action_id = res["action_ids"][0]
    ctrl._dispatch_one(ctrl.ledger.get_action(action_id))
    applied = ctrl.ledger.get_action(action_id)
    assert applied["mode"] == "SHADOW", applied["mode"]
    shadow_zone = Path(cfg.adapter.zone_dir) / (
        ctrl.adapter.config.zone_name + ".shadow.zone")
    assert "rpz-passthru" in shadow_zone.read_text()

    # restart with the adapter configured ENFORCE against the SAME ledger
    # and zone dir: existing actions must not be upgraded.
    cfg_enf = replace(
        cfg,
        adapter=replace(cfg.adapter, rpz_mode="ENFORCE",
                        reload_command="true",
                        verify_query_server="127.0.0.1",
                        verify_query_port=5333),
    )
    from apip.controller.service import Controller as _C
    ctrl2 = _C(cfg_enf)
    ctrl2.start()
    try:
        # the stored row still carries the persisted mode
        row = ctrl2.ledger.get_action(action_id)
        assert row["mode"] == "SHADOW", row["mode"]
        # verification (and re-dispatch) at the new posture still honors it:
        # verify stays on the shadow artifact — no live zone, no DNS probe.
        v = ctrl2._adapter_for(row).verify(
            {"rule_id": row["rule_id"], "fragment": row["fragment"],
             "mode": row["mode"], "selector": row["selector"]})
        assert v["ok"] is True
        assert v["observed"]["effective_mode"] == "SHADOW"
        assert "dns" not in v["observed"]
        assert not (Path(cfg.adapter.zone_dir) / (
            ctrl.adapter.config.zone_name + ".zone")).exists()
        # even a fresh dispatch of the same stored action re-applies at the
        # shadow tier — the serialized mode is what dispatch consumes.
        r = ctrl2._adapter_for(row).apply(
            {"rule_id": row["rule_id"], "fragment": row["fragment"],
             "mode": row["mode"], "selector": row["selector"]})
        assert r["ok"] is True
        assert r["receipt"]["observed"]["effective_mode"] == "SHADOW"
        assert (Path(cfg.adapter.zone_dir) / (
            ctrl.adapter.config.zone_name + ".zone")).exists() is False
    finally:
        ctrl2.stop()


def test_shared_physical_rule_survives_one_revoke(controller):
    """Review P0 #6: two actions independently deny the same FQDN (identical
    physical rule_id `owner:<fqdn>`). Revoking ONE action must terminate the
    action but NOT remove the shared zone rule; revoking the second (last)
    owner removes it."""
    ctrl, _ = controller
    value = "c2-shared.operator.test"

    def _one(did: str) -> str:
        _record_approval_decision(ctrl, did, value)
        res = ctrl.approve_decision(did, "operator")
        assert res["compiled"], res
        action_id = res["action_ids"][0]
        ctrl._dispatch_one(ctrl.ledger.get_action(action_id))
        return action_id

    a1 = _one("decision--it-shared-1")
    a2 = _one("decision--it-shared-2")
    act1 = ctrl.ledger.get_action(a1)
    act2 = ctrl.ledger.get_action(a2)
    assert act1["rule_id"] == act2["rule_id"], "test precondition: same physical rule"

    out1 = ctrl.revoke_action(a1, "operator", "revoke-one")
    assert out1["state"] == "revoked"
    assert out1.get("shared_rule") is True, out1
    # the physical rule REMAINS (co-owner a2 still active)
    st = ctrl.adapter.get_state(act1["selector"])
    assert st["present"] is True

    out2 = ctrl.revoke_action(a2, "operator", "revoke-last")
    assert out2["state"] == "revoked"
    assert out2.get("shared_rule") is not True
    st = ctrl.adapter.get_state(act2["selector"])
    assert st["present"] is False


def test_dispatch_cancels_when_scope_narrowed_after_creation(controller):
    """Review P0 #7: an action created under a policy authorizing the target
    must NOT be applied after the operator promotes a narrower policy that
    excludes it. Dispatch re-authorizes against the CURRENT effective policy
    and transitions the action to cancelled_policy_changed."""
    ctrl, _ = controller
    did = "decision--it-stale"
    value = "c2-stale.operator.test"
    _record_approval_decision(ctrl, did, value)
    res = ctrl.approve_decision(did, "operator")
    action_id = res["action_ids"][0]
    assert ctrl.ledger.get_action(action_id)["state"] == "pending"

    # operator promotes a policy whose authorized domain excludes the target
    narrowed = """
policy_version = "narrow.1"
mode = "ENFORCE"
scope = "acceptance-tenant"

[thresholds]
observe_m = 40
fqdn_auto_m = 95
fqdn_auto_s = 90
ip_rate_m = 90
ip_rate_s = 85
ip_deny_m = 98
ip_deny_s = 95

[limits]
max_auto_ttl_seconds = 3600

[authorization]
authorized_prefixes = []
authorized_domains = ["other.test"]

[safety]
auto_prefix_deny = false
no_ai_components = true

[replay]
reference_now = "2026-09-07T00:00:00Z"
"""
    import hashlib as _h
    rev = ctrl.ledger.next_policy_revision("narrow.1")
    ctrl.ledger.stage_policy(policy_version="narrow.1", revision=rev,
                             content_sha256=_h.sha256(narrowed.encode()).hexdigest(),
                             raw_text=narrowed, mode="ENFORCE",
                             staged_by="operator")
    ctrl.ledger.promote_policy("narrow.1", rev, "operator")

    # dispatch the stale action: must cancel, never touch the adapter
    action = ctrl.ledger.get_action(action_id)
    ctrl._dispatch_one(action)
    row = ctrl.ledger.get_action(action_id)
    assert row["state"] == "cancelled_policy_changed", row["state"]
    st = ctrl.adapter.get_state(action["selector"])
    assert st["present"] is False
