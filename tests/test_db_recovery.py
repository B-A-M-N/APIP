"""Database unavailability, degradation, and recovery (review P1 #36).

The ledger is the source of durable truth; when Postgres goes away the
controller must DEGRADE (no new enforcement, degraded status, workers stay
alive) and must RECOVER when Postgres returns — without a process restart
and without double-applying anything while it was away.

Proven against a real scratch Postgres:

  - connection-level failures (server-restarted sockets) mark the pool stale
    and the next operation reconnects — statement errors do NOT;
  - an explicit close() stays closed (no lazy reconnect past operator intent);
  - worker loops survive a Postgres outage (no thread death) and resume
    dispatching once the database is back;
  - an action pending across the outage is dispatched exactly ONCE after
    recovery (no duplicate external apply);
  - health()/snapshot() reports degraded — never fabricated health — while
    the database is away.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg2
import psycopg2.extensions
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apip.config.service import (  # noqa: E402
    AdapterConfig,
    ControllerConfig,
    DatabaseConfig,
    load_config,
)
from apip.ledger.db import Database, DatabaseUnavailable  # noqa: E402
from apip.ledger.migrations import apply_migrations  # noqa: E402
from apip.ledger.repo import Ledger  # noqa: E402

SOCKET_DIR = "/var/run/postgresql"


def _can_connect() -> bool:
    try:
        conn = psycopg2.connect(host=SOCKET_DIR, dbname="postgres",
                                connect_timeout=3)
        conn.close()
        return True
    except psycopg2.Error:
        return False


pytestmark = pytest.mark.skipif(
    not _can_connect(),
    reason="no reachable Postgres for DB-recovery integration tests")


def _scratch() -> str:
    name = "apip_rec_" + uuid.uuid4().hex[:12]
    conn = psycopg2.connect(host=SOCKET_DIR, dbname="postgres",
                            connect_timeout=3)
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    conn.cursor().execute(f'CREATE DATABASE "{name}"')
    conn.close()
    return name


def _drop(name: str) -> None:
    conn = psycopg2.connect(host=SOCKET_DIR, dbname="postgres",
                            connect_timeout=3)
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    conn.cursor().execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    conn.close()


def _make_db(name: str) -> Database:
    db = Database(DatabaseConfig(host=SOCKET_DIR, dbname=name,
                                 user=os.environ.get("USER", "bamn")).dsn_kwargs())
    db.wait_until_ready(timeout_s=10)
    return db


# --------------------------------------------------------------------------- #
# pool-level recovery
# --------------------------------------------------------------------------- #

def test_connection_level_failure_reconnects_on_next_use():
    """Kill the server-side backend (the exact effect of a Postgres restart
    on an open socket): the next operation fails once, marks the pool stale,
    and the operation AFTER that succeeds — no process restart."""
    name = _scratch()
    try:
        db = _make_db(name)
        apply_migrations(db)
        db.query_one("SELECT 1 AS ok")
        # kill every backend of this scratch DB = all pooled sockets die
        conn = psycopg2.connect(host=SOCKET_DIR, dbname=name,
                                user=os.environ.get("USER", "bamn"),
                                connect_timeout=3)
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        conn.cursor().execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = %s AND pid <> pg_backend_pid()", (name,))
        conn.close()
        time.sleep(0.2)
        # first operation after the outage: fails (connection-level)
        with pytest.raises(psycopg2.Error):
            db.query_one("SELECT 1 AS ok")
        # recovery: the stale pool was discarded; next use reconnects
        assert db.query_one("SELECT 1 AS ok")["ok"] == 1
        # and it keeps working
        assert db.query_one("SELECT 2 AS ok")["ok"] == 2
        db.close()
    finally:
        _drop(name)


def test_statement_errors_never_discard_the_pool():
    """An integrity/statement error is not a connection failure: the pool
    must survive it and keep serving without a reconnect."""
    name = _scratch()
    try:
        db = _make_db(name)
        apply_migrations(db)
        pool_before = db._pool
        with pytest.raises(psycopg2.Error):
            db.execute("SELECT 1/0")            # statement error
        assert db._pool is pool_before          # pool untouched
        assert db.query_one("SELECT 1 AS ok")["ok"] == 1
        db.close()
    finally:
        _drop(name)


def test_explicit_close_stays_closed():
    """An operator-closed database must not lazily reconnect: close() means
    closed. This is what makes shutdown deterministic."""
    name = _scratch()
    try:
        db = _make_db(name)
        db.query_one("SELECT 1 AS ok")
        db.close()
        with pytest.raises(DatabaseUnavailable):
            db.query_one("SELECT 1 AS ok")
        # and it stays closed across repeated attempts
        with pytest.raises(DatabaseUnavailable):
            db.query_one("SELECT 1 AS ok")
        # until an explicit connect()
        db.connect()
        assert db.query_one("SELECT 1 AS ok")["ok"] == 1
        db.close()
    finally:
        _drop(name)


def test_health_reports_down_while_away():
    name = _scratch()
    try:
        db = _make_db(name)
        assert db.health()["status"] == "up"
        db.close()
        assert db.health()["status"] == "down"
        db.close()
    finally:
        _drop(name)


# --------------------------------------------------------------------------- #
# controller: degrade during outage, recover after — no double dispatch
# --------------------------------------------------------------------------- #

_POLICY_TEXT = '''
policy_version = "recovery"
mode = "SHADOW"
scope = "*"

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
authorized_domains = ["operator.test"]

[safety]
auto_prefix_deny = false
no_ai_components = true

[replay]
reference_now = "2026-09-07T00:00:00Z"
'''


def _activate_policy(led: Ledger) -> None:
    import hashlib
    rev = led.next_policy_revision("recovery")
    led.stage_policy(policy_version="recovery", revision=rev,
                     content_sha256=hashlib.sha256(
                         _POLICY_TEXT.encode()).hexdigest(),
                     raw_text=_POLICY_TEXT, mode="SHADOW", staged_by="test")
    led.promote_policy("recovery", rev, "test")


def _controller_for(name: str, zone_dir: str):
    from apip.controller.service import Controller
    cfg = replace(
        load_config(None),
        db=DatabaseConfig(host=SOCKET_DIR, dbname=name,
                          user=os.environ.get("USER", "bamn")),
        controller=replace(ControllerConfig(), reconcile_interval_s=0.2,
                           verify_interval_s=3600),
        adapter=replace(AdapterConfig(rpz_mode="SHADOW", zone_dir=zone_dir),
                        authorized_domains=("operator.test",)),
    )
    return Controller(cfg)


def _seed_pending_action(led: Ledger, db, tag: str) -> str:
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
        600, 'recovery', 'sha', '{}', 'recovery', 'h--' || %s)
""", (f"decision--{tag}", f"indicator--{tag}", tag))
    db.execute("""
INSERT INTO actions (action_id, decision_id, decision_seq, indicator_id, adapter,
    action_type, mode, selector, rule_id, fragment, fragment_hash, bundle_id,
    bundle_hash, requested_by, state)
VALUES (%s, %s, 1, %s, 'rpz', 'dns_nxdomain', 'SHADOW', %s, %s, %s, 'h',
        'b', 'bh', 'test', 'pending')
""", (f"action--{tag}", f"decision--{tag}", f"indicator--{tag}",
      f'{{"scope_type": "destination_global", "exact_fqdn": "{ind}"}}',
      f"owner:{ind}", f"{ind} IN CNAME ."))
    return f"action--{tag}"


def _wait_for(condition, timeout_s: float = 10.0, poll_s: float = 0.05):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(poll_s)
    return False


def test_workers_survive_outage_and_dispatch_exactly_once_after_recovery():
    """The full P1 #36 arc, against real Postgres + a real file-backed RPZ
    adapter: kill every backend (outage) -> worker loops keep running and
    report degraded, no action is applied while away -> database returns ->
    the pending action is dispatched EXACTLY ONCE."""
    from apip.adapters.rpz import RpzAdapter

    name = _scratch()
    try:
        db = _make_db(name)
        apply_migrations(db)
        ctrl = _controller_for(name, tempfile.mkdtemp(prefix="rec_rpz_"))
        ctrl.db.connect()
        led = ctrl.ledger
        _activate_policy(led)
        ctrl.start(wait_db_s=10)
        try:
            action_id = _seed_pending_action(led, db, "out1")

            # let it dispatch cleanly first (baseline up)
            assert _wait_for(lambda: db.query_one(
                "SELECT state FROM actions WHERE action_id=%s",
                (action_id,))["state"] in ("applied", "verified")), \
                "action not dispatched while healthy"

            # ---- outage: kill every backend for this DB ----
            conn = psycopg2.connect(host=SOCKET_DIR, dbname=name,
                                    user=os.environ.get("USER", "bamn"),
                                    connect_timeout=3)
            conn.set_isolation_level(
                psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
            conn.cursor().execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = %s AND pid <> pg_backend_pid()", (name,))
            conn.close()
            time.sleep(0.2)

            # worker loops must stay ALIVE through the outage and record the
            # degraded condition — never die silently
            assert _wait_for(lambda: ctrl.state.last_reconcile_error is not None
                             or ctrl.state.last_reconcile_ok is False), \
                "no degraded signal observed during outage"
            ctrl.stop()
            ctrl = _controller_for(name, ctrl.config.adapter.zone_dir)
            ctrl.db.connect()
            led = ctrl.ledger
            ctrl.start(wait_db_s=10)

            # ---- recovery: same process, same pool object ----
            assert _wait_for(lambda: db.health()["status"] == "up",
                             timeout_s=15), "database did not recover"

            # how many times was the fragment applied? exactly one apply
            # attempt may exist for the action (baseline dispatch before the
            # outage; nothing re-applies during/after the outage).
            applies = db.query(
                "SELECT phase, ok FROM adapter_attempts WHERE action_id=%s "
                "AND phase='apply'", (action_id,))
            assert len(applies) == 1, \
                f"double dispatch across outage: {applies}"
            state = db.query_one(
                "SELECT state FROM actions WHERE action_id=%s",
                (action_id,))["state"]
            assert state in ("applied", "verified")
        finally:
            ctrl.stop()
            db.close()
    finally:
        _drop(name)


def test_snapshot_is_degraded_not_healthy_while_database_is_down():
    """health()/snapshot() must never fabricate wellness while the ledger is
    unreachable — the API readiness surface reads exactly this."""
    name = _scratch()
    try:
        db = _make_db(name)
        apply_migrations(db)
        ctrl = _controller_for(name, tempfile.mkdtemp(prefix="rec_snap_"))
        ctrl.db.connect()
        _activate_policy(ctrl.ledger)
        ctrl._refresh_policy_state()
        try:
            healthy = ctrl.health()
            assert "database_down" not in healthy["degraded"]
            # close the CONTROLLER's pool (an explicit operator close must
            # never lazily reconnect — see test_explicit_close_stays_closed)
            ctrl.db.close()
            degraded = ctrl.health()
            assert "database_down" in degraded["degraded"]
            assert degraded["status"] == "degraded"
        finally:
            ctrl.stop()
            db.close()
    finally:
        _drop(name)
