"""Desired-state recovery (audit P0 #4).

The durable record must never forget whether the operation in progress was
an APPLY or a REMOVE. Previously both used state='dispatching', so a crash
during a removal claim could be "recovered" by unclaim_action() to 'pending'
— and the dispatch worker would RE-APPLY the control the operator revoked.

The fix: every action carries desired_state PRESENT|ABSENT. Removal commits
the ABSENT intent BEFORE touching infrastructure; recovery converges toward
the durable intent. Proven against real Postgres:

  - a crash mid-removal (action left 'removing') is recovered AS a removal;
  - an intent committed but phase not entered (desired ABSENT, state
    applied) is converged by the reconciler;
  - an APPLY claim still recovers to pending and dispatches normally;
  - the never-again property: no recovery path turns desired-ABSENT into
    'pending'.
"""
from __future__ import annotations

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
import psycopg2.extensions
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pg  # noqa: E402  (shared Postgres test endpoints)

from apip.config.service import DatabaseConfig  # noqa: E402
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
    reason="no reachable Postgres for desired-state recovery tests")


@pytest.fixture()
def store():
    """Yields (ledger, db) over one scratch Postgres database."""
    name = "apip_dsr_" + uuid.uuid4().hex[:12]
    conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    conn.cursor().execute(f'CREATE DATABASE "{name}"')
    conn.close()
    db = Database(DatabaseConfig(host=pg.HOST, port=pg.PORT, dbname=name,
                                 user=pg.USER).dsn_kwargs())
    db.wait_until_ready(timeout_s=10)
    apply_migrations(db)
    try:
        yield Ledger(db), db
    finally:
        db.close()
        conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        conn.cursor().execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        conn.close()


def _seed_applied(led: Ledger, db: Database, tag: str) -> str:
    ind = f"{tag}.recovery.operator.test"
    db.execute(
        "INSERT INTO indicators (indicator_id, itype, value) VALUES (%s, "
        "'fqdn', %s) ON CONFLICT DO NOTHING", (f"indicator--{tag}", ind))
    db.execute("""
INSERT INTO decisions (decision_id, seq, indicator_id, batch_id, maliciousness,
    action_safety, disposition, action, rung, scope, ttl_seconds,
    policy_version, policy_content_sha256, reason_codes, explanation,
    content_hash)
VALUES (%s, 1, %s, NULL, 95, 95, 'AUTO_ENFORCE', 'dns_nxdomain', 'L5', '*',
        600, 'v', 'sha', '{}', 'x', 'h--' || %s)
""", (f"decision--{tag}", f"indicator--{tag}", tag))
    db.execute("""
INSERT INTO actions (action_id, decision_id, decision_seq, indicator_id, adapter,
    action_type, mode, selector, rule_id, fragment, fragment_hash, bundle_id,
    bundle_hash, requested_by, state)
VALUES (%s, %s, 1, %s, 'rpz', 'dns_nxdomain', 'SHADOW', %s, %s, %s, 'h',
        'b', 'bh', 'test', 'applied')
""", (f"action--{tag}", f"decision--{tag}", f"indicator--{tag}",
      f'{{"scope_type": "destination_global", "exact_fqdn": "{ind}"}}',
      f"owner:{ind}", f"{ind} IN CNAME ."))
    return f"action--{tag}"


def _state(db: Database, action_id: str) -> tuple[str, str]:
    row = db.query_one(
        "SELECT state, desired_state FROM actions WHERE action_id=%s",
        (action_id,))
    return row["state"], row["desired_state"]


def test_removal_commit_then_crash_converges_to_removal_not_apply(store):
    led, db = store
    """The audit's exact scenario: revoke commits intent, process dies
    before the adapter call. Recovery must see desired ABSENT."""
    aid = _seed_applied(led, db, "crash1")
    # operator revoke commits the durable intent (the crash happens here)
    assert led.request_removal(aid, ("applied", "verified", "drifted")) is True
    state, desired = _state(db, aid)
    assert state == "removing" and desired == "ABSENT"
    # the crashed process's replacement asks: what does recovery do?
    # unclaim (the old recovery primitive) must NOT produce 'pending'
    led.unclaim_action(aid)
    state, desired = _state(db, aid)
    assert desired == "ABSENT"
    assert state != "pending", \
        "recovery turned a revoked action back into apply-work"


def test_intent_committed_before_phase_converged_by_query(store):
    led, db = store
    """desired ABSENT but state still 'applied' (intent committed, process
    died before the removal phase): the convergence query finds it."""
    aid = _seed_applied(led, db, "crash2")
    db.execute("UPDATE actions SET desired_state='ABSENT' WHERE action_id=%s",
               (aid,))
    pending = led.actions_desired_absent_active()
    assert any(a["action_id"] == aid for a in pending)
    # reconciler path: re-enter removal
    assert led.request_removal(
        aid, ("applied", "verified", "drifted", "removing")) is True
    state, desired = _state(db, aid)
    assert state == "removing" and desired == "ABSENT"


def test_stuck_removing_requeues_as_removal(store):
    led, db = store
    aid = _seed_applied(led, db, "crash3")
    led.request_removal(aid, ("applied",))
    # backdate so it looks wedged past a reconcile window
    db.execute("UPDATE actions SET last_reconciled_at = now() - interval "
               "'1 hour' WHERE action_id=%s", (aid,))
    stuck = led.actions_stuck_removing(datetime.now(timezone.utc) - timedelta(minutes=1))
    assert any(a["action_id"] == aid for a in stuck)
    led.retry_removal(aid)
    state, desired = _state(db, aid)
    assert state == "applied" and desired == "ABSENT", \
        "retry must requeue REMOVAL (applied), never apply-work (pending)"


def test_apply_claim_still_recovers_to_pending(store):
    led, db = store
    """The legitimate apply-crash path is unchanged: 'dispatching' with
    desired PRESENT returns to pending."""
    aid = _seed_applied(led, db, "crash4")
    db.execute("UPDATE actions SET state='pending' WHERE action_id=%s", (aid,))
    assert led.claim_pending_action(aid) is True
    state, desired = _state(db, aid)
    assert state == "dispatching" and desired == "PRESENT"
    led.unclaim_action(aid)
    state, desired = _state(db, aid)
    assert state == "pending" and desired == "PRESENT"


def test_request_removal_from_removing_is_idempotent_exclusion(store):
    led, db = store
    """A second removal path racing an in-flight removal is excluded — the
    first claim still owns it (P0 #21 semantics preserved)."""
    aid = _seed_applied(led, db, "crash5")
    assert led.request_removal(aid, ("applied", "verified", "drifted")) is True
    # the first claimer moved the row to 'removing'; a second path claiming
    # from the same states can no longer grab it
    assert led.request_removal(aid, ("applied", "verified", "drifted")) is False, \
        "second claimer stole an in-flight removal"


def test_expired_via_intent_never_reapplies(store):
    led, db = store
    """End-to-end intent semantics: expiry commits ABSENT, worker removes;
    a crash+recovery at ANY point leaves the action non-dispatchable."""
    aid = _seed_applied(led, db, "crash6")
    led.request_removal(aid, ("applied", "verified", "drifted"))
    # simulate full crash-recovery: stuck-removing requeue, retry, and even
    # a buggy double-unclaim
    led.retry_removal(aid)
    led.unclaim_action(aid)   # must be a no-op: state is 'applied'
    state, desired = _state(db, aid)
    assert desired == "ABSENT"
    # the dispatch worker's claim path is guarded by state='pending' and the
    # row is not pending — prove no claim is possible
    assert led.claim_pending_action(aid) is False
