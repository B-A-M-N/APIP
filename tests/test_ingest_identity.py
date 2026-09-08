"""Integration tests for review P0 #9–13 at the REAL ledger + controller +
HTTP layer, against a scratch Postgres:

  #10  server-derived observable identity — canonical (itype, value) is the
       durable identity; source-submitted ids are provenance only;
  #11  ingest is a resumable unit of work — a crash mid-batch leaves
       'processing' and the retry RESUMES instead of being skipped forever;
  #12  one decision instance authorizes each logical action at most once —
       pinned by uq_actions_per_decision at the DATABASE;
  #13  the policy blast-radius budget (max_new_auto_actions_per_batch) is
       enforced end-to-end: overflow is demoted to OBSERVE with a named
       reason and persisted, never acted on.

These run only when a reachable local Postgres lets the current OS user
create a throwaway database; otherwise skipped.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
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
    Decision,
    Evidence,
    Indicator,
)
from apip.ingest import IngestChannel, parse_indicator_payload  # noqa: E402



def _can_connect() -> bool:
    try:
        conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
        conn.close()
        return True
    except psycopg2.Error:
        return False


pytestmark = pytest.mark.skipif(
    not _can_connect(),
    reason="no reachable Postgres for ingest-identity integration tests")


def _scratch_db():
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


def _drop_db(name: str) -> None:
    conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    try:
        cur.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    finally:
        cur.close()
        conn.close()


def _make_controller(dburi: str, *, zone: str):
    from apip.controller.service import Controller
    from apip.ledger.db import Database
    from apip.ledger.migrations import apply_migrations

    cfg = replace(
        load_config(None),
        db=DatabaseConfig(host=pg.HOST, port=pg.PORT, dbname=dburi,
                          user=pg.USER),
        adapter=replace(AdapterConfig(rpz_mode="SHADOW", zone_dir=zone),
                        authorized_domains=("operator.test",)),
    )
    db = Database(cfg.db.dsn_kwargs())
    db.wait_until_ready(timeout_s=10)
    apply_migrations(db)
    db.close()
    ctrl = Controller(cfg)
    ctrl.start()
    return ctrl, cfg


def _stage_beta(ctrl) -> None:
    pol_text = (Path(__file__).resolve().parents[1]
                / "examples" / "enforce_policy.toml").read_text()
    rev = ctrl.ledger.next_policy_revision("beta")
    ctrl.ledger.stage_policy(
        policy_version="beta", revision=rev,
        content_sha256=hashlib.sha256(pol_text.encode()).hexdigest(),
        raw_text=pol_text, mode="ENFORCE", staged_by="test")
    ctrl.ledger.promote_policy("beta", rev, "test")


def _batch_payload(*indicators: dict) -> bytes:
    return json.dumps({"indicators": list(indicators)}).encode()


def _channel() -> "IngestChannel":
    """The channel the fixture's local-sensor feeds through: the registry
    declares feeda/feedb as its upstreams, so feed-attributed evidence
    survives channel demotion."""
    return IngestChannel(source_id="local-sensor",
                         allowed_source_ids=frozenset({"feeda", "feedb"}))


def _seed_batch(ctrl, batch_id: str) -> None:
    ctrl.ledger.record_batch(batch_id=batch_id, source_id="local-sensor",
                             raw_sha256="sha-" + batch_id, indicator_count=1,
                             demoted=0, channel="local-sensor", actor="test")


def _sensor_ind(**overrides) -> dict:
    """An indicator whose evidence recipe reaches the beta policy's AUTO tier
    (local detection + recency + two independent curated corroborations)."""
    tenant = overrides.pop("tenant", None)
    def ts(minutes_ago: int) -> str:
        from datetime import datetime, timedelta, timezone
        return (datetime.now(timezone.utc) - timedelta(
            minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    base = {
        "tenant_id": tenant,
        "id": "indicator--" + uuid.uuid4().hex[:12],
        "type": "fqdn", "value": "sensor.operator.test",
        "sources": ["local-sensor", "feeda", "feedb"],
        "first_seen": ts(60),
        "last_seen": ts(5), "tags": ["c2"],
        "evidence": [
            {"kind": "direct_local_detection", "source_id": "local-sensor",
             "observed_at": ts(20)},
            {"kind": "exact_fqdn", "source_id": "local-sensor",
             "observed_at": ts(15)},
            {"kind": "exact_ip", "source_id": "local-sensor",
             "observed_at": ts(10)},
            {"kind": "recent", "source_id": "local-sensor",
             "observed_at": ts(5)},
            {"kind": "curated_source", "source_id": "feeda",
             "observed_at": ts(30)},
            {"kind": "exact_fqdn", "source_id": "feeda",
             "observed_at": ts(30)},
            {"kind": "curated_source", "source_id": "feedb",
             "observed_at": ts(30)}],
    }
    base.update(overrides)
    return base


@pytest.fixture(scope="module")
def ing():
    ctrl, cfg = _make_controller(_scratch_db(), zone=__import__("tempfile").mkdtemp(
        prefix="apip_it_ing_"))
    try:
        ctrl.ledger.register_source(
            source_id="local-sensor", source_class="local", independent=True,
            key_hash="x", actor="test", auto_enforcement_allowed=True,
            enabled=True)
        # two independent curated feeds so corroboration can reach AUTO tiers
        ctrl.ledger.register_source(
            source_id="feeda", source_class="curated", independent=True,
            key_hash="x", actor="test", auto_enforcement_allowed=True,
            enabled=True)
        ctrl.ledger.register_source(
            source_id="feedb", source_class="curated", independent=True,
            key_hash="x", actor="test", auto_enforcement_allowed=True,
            enabled=True)
        _stage_beta(ctrl)
        yield ctrl
    finally:
        ctrl.stop()
        _drop_db(cfg.db.dbname)


# --------------------------------------------------------------------------- #
# P0 #10 — server-derived observable identity
# --------------------------------------------------------------------------- #

def test_same_canonical_observable_merges_across_source_ids(ing):
    """Two sources assigning DIFFERENT ids to the SAME canonical observable
    derive the same durable id — evidence and source refs merge onto ONE
    indicator row (corroboration is never split)."""
    ctrl = ing
    a = parse_indicator_payload(_batch_payload(_sensor_ind(
        id="indicator--from-feed-a", value="merge.operator.test")),
        _channel())
    b = parse_indicator_payload(_batch_payload(_sensor_ind(
        id="indicator--from-feed-b", value="merge.operator.test")),
        _channel())
    _seed_batch(ctrl, "b-merge-a")
    _seed_batch(ctrl, "b-merge-b")
    da = ctrl.ledger.upsert_indicator(a.indicators[0], "b-merge-a")
    db_ = ctrl.ledger.upsert_indicator(b.indicators[0], "b-merge-b")
    assert da == db_, "same canonical observable must derive ONE durable id"
    rows = ctrl.db.query(
        "SELECT indicator_id FROM indicators WHERE itype='fqdn' AND value='merge.operator.test'")
    assert len(rows) == 1
    refs = ctrl.db.query(
        "SELECT indicator_id FROM indicator_source_refs WHERE source_id='local-sensor'")
    assert all(r["indicator_id"] == da for r in refs
               if r["indicator_id"].startswith("indicator--")
               and ctrl.db.query_one(
                   "SELECT value FROM indicators WHERE indicator_id=%s",
                   (r["indicator_id"],))["value"] == "merge.operator.test")
    # the submitted ids survive as PROVENANCE only (last writer visible)
    row = ctrl.db.query_one(
        "SELECT source_object_id FROM indicators WHERE indicator_id=%s", (da,))
    assert row["source_object_id"] in ("indicator--from-feed-a",
                                       "indicator--from-feed-b")


def test_reused_id_different_observable_never_merges(ing):
    """A source reusing ANOTHER observable's submitted id for a different
    value derives a different durable id — it can never attach evidence to
    the wrong observable."""
    ctrl = ing
    a = parse_indicator_payload(_batch_payload(_sensor_ind(
        id="indicator--shared-prov", value="one.operator.test")),
        _channel())
    b = parse_indicator_payload(_batch_payload(_sensor_ind(
        id="indicator--shared-prov", value="two.operator.test")),
        _channel())
    _seed_batch(ctrl, "b-prov-a")
    _seed_batch(ctrl, "b-prov-b")
    da = ctrl.ledger.upsert_indicator(a.indicators[0], "b-prov-a")
    db_ = ctrl.ledger.upsert_indicator(b.indicators[0], "b-prov-b")
    assert da != db_
    va = ctrl.db.query_one(
        "SELECT value FROM indicators WHERE indicator_id=%s", (da,))["value"]
    vb = ctrl.db.query_one(
        "SELECT value FROM indicators WHERE indicator_id=%s", (db_,))["value"]
    assert va == "one.operator.test" and vb == "two.operator.test"
    ev = ctrl.db.query(
        "SELECT batch_id FROM evidence WHERE indicator_id=%s", (da,))
    assert {r["batch_id"] for r in ev} == {"b-prov-a"}


def test_fqdn_case_and_trailing_dot_are_one_observable(ing):
    ctrl = ing
    a = parse_indicator_payload(_batch_payload(_sensor_ind(
        id="indicator--case-a", value="Case.Operator.Test.")),
        _channel())
    b = parse_indicator_payload(_batch_payload(_sensor_ind(
        id="indicator--case-b", value="case.operator.test")),
        _channel())
    _seed_batch(ctrl, "b-case-a")
    _seed_batch(ctrl, "b-case-b")
    da = ctrl.ledger.upsert_indicator(a.indicators[0], "b-case-a")
    db_ = ctrl.ledger.upsert_indicator(b.indicators[0], "b-case-b")
    assert da == db_
    rows = ctrl.db.query(
        "SELECT value FROM indicators WHERE itype='fqdn' AND "
        "lower(rtrim(value, '.'))='case.operator.test'")
    assert len(rows) == 1


# --------------------------------------------------------------------------- #
# P0 #11 — ingest is a resumable unit of work
# --------------------------------------------------------------------------- #

def test_crashed_batch_resumes_instead_of_being_skipped(ing):
    """A crash after the batch row is claimed leaves 'processing'; the retry
    RESUMES (records decisions, mints actions) rather than being treated as a
    phantom replay forever."""
    ctrl = ing
    batch = "batch--crash-" + uuid.uuid4().hex[:8]
    ind = parse_indicator_payload(_batch_payload(_sensor_ind(
        value="crash.operator.test")),
        _channel())
    # claim the PARSED batch (its id is derived from source+raw bytes) as if
    # a previous run died right after claiming it
    assert ctrl.ledger.begin_batch(
        batch_id=ind.batch_id, source_id="local-sensor",
        raw_sha256=ind.raw_sha256, indicator_count=1, demoted=0,
        channel="local-sensor", actor="test") is True
    assert ctrl.ledger.batch_status(ind.batch_id) == "processing"

    res = ctrl.process_batch(batch=ind, actor="test")
    assert res["resumed"] is True
    assert res["indicators"] == 1
    assert ctrl.ledger.batch_status(ind.batch_id) == "complete"
    # decisions + actions actually happened on the resume
    assert res["decisions"] >= 1

    # and once complete, the same bytes are a replay no-op
    replay = ctrl.process_batch(batch=ind, actor="test")
    assert replay.get("replay") is True


def test_failed_batch_marks_failed_and_next_retry_resumes(ing):
    ctrl = ing
    batch = "batch--fail-" + uuid.uuid4().hex[:8]
    ind = parse_indicator_payload(_batch_payload(_sensor_ind(
        value="failed-batch.operator.test")),
        _channel())
    assert ctrl.ledger.begin_batch(
        batch_id=ind.batch_id, source_id="local-sensor",
        raw_sha256=ind.raw_sha256, indicator_count=1, demoted=0,
        channel="local-sensor", actor="test") is True
    ctrl.ledger.fail_batch(ind.batch_id, "synthetic failure")
    res = ctrl.process_batch(batch=ind, actor="test")
    assert res["resumed"] is True
    assert ctrl.ledger.batch_status(ind.batch_id) == "complete"


# --------------------------------------------------------------------------- #
# P0 #12 — one decision instance, one action (DB-pinned)
# --------------------------------------------------------------------------- #

def test_reingest_same_bytes_mints_no_second_action(ing):
    """Re-running the identical observable through ingest (fresh batch bytes,
    same decision) can never mint a second action: record_action refuses the
    duplicate at the DATABASE (uq_actions_per_decision)."""
    ctrl = ing
    value = "iddup.operator.test"
    payload1 = _batch_payload(_sensor_ind(value=value))
    pb1 = parse_indicator_payload(
        payload1, _channel())
    r1 = ctrl.process_batch(batch=pb1, actor="test")
    assert r1["actions"] >= 1

    # a DIFFERENT batch (new bytes, new batch id) re-reporting the SAME
    # observable produces the SAME decision content hash -> no new action
    payload2 = _batch_payload(_sensor_ind(value=value))
    assert payload2 != payload1
    pb2 = parse_indicator_payload(
        payload2, _channel())
    r2 = ctrl.process_batch(batch=pb2, actor="test")
    assert r2["actions"] == 0

    rows = ctrl.db.query(
        "SELECT a.action_id FROM actions a JOIN decisions d "
        "ON d.decision_id=a.decision_id AND d.seq=a.decision_seq "
        "JOIN indicators i ON i.indicator_id=d.indicator_id "
        "WHERE i.value=%s", (value,))
    assert len(rows) == 1


# --------------------------------------------------------------------------- #
# P0 #13 — blast-radius budget enforced end-to-end
# --------------------------------------------------------------------------- #

def test_batch_budget_demotes_overflow_to_observe(ing):
    """policy max_new_auto_actions_per_batch=1: the first actionable indicator
    of the batch acts, the rest are DEMOTED to OBSERVE with reason
    blast_radius_budget_exceeded and persisted — never acted on."""
    ctrl = ing
    # tighten-only overlay of the active beta policy with a budget of 1
    overlay_raw = '\n'.join(
        line for line in _beta_budget_toml(1).splitlines())
    import hashlib as _h
    ctrl.ledger.upsert_tenant_overlay(
        tenant_id="budget-tenant", raw_text=overlay_raw,
        overlay_sha256=_h.sha256(overlay_raw.encode()).hexdigest(),
        created_by="test")

    batch = "batch--budget-" + uuid.uuid4().hex[:8]
    payload = _batch_payload(
        *[_sensor_ind(value=f"burst{i}.budget.operator.test",
                      tenant="budget-tenant") for i in range(3)])
    pb = parse_indicator_payload(
        payload, _channel())
    res = ctrl.process_batch(batch=pb, actor="test", tenant_id="budget-tenant")
    assert res["demoted"] == 2, f"expected 2 overflow demotions, got {res}"

    demoted = ctrl.db.query(
        "SELECT d.disposition, d.reason_codes FROM decisions d "
        "JOIN indicators i ON i.indicator_id=d.indicator_id "
        "WHERE d.decision_id LIKE '%%demoted' AND i.value LIKE '%%.budget.operator.test'")
    assert len(demoted) == 2
    for row in demoted:
        assert row["disposition"] == "OBSERVE"
        assert "blast_radius_budget_exceeded" in (row["reason_codes"] or [])
    acted = ctrl.db.query(
        "SELECT COUNT(*) AS n FROM actions a JOIN decisions d "
        "ON d.decision_id=a.decision_id AND d.seq=a.decision_seq "
        "JOIN indicators i ON i.indicator_id=d.indicator_id "
        "WHERE i.value LIKE '%%.budget.operator.test'")
    assert acted[0]["n"] == 1


def _beta_budget_toml(budget: int) -> str:
    """A tighten-only overlay: budget 1 (stricter than unset/infinite)."""
    return f"""
policy_version = "tenant.budget"
mode = "ENFORCE"
scope = "*"
[limits]
max_new_auto_actions_per_batch = {budget}
"""
