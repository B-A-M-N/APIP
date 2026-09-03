"""High-availability leader lease tests (task #11, feature 1).

Two or more controllers pointed at the SAME Postgres ledger must not run the
worker loops (dispatch/expiry/verify) at the same time. This suite proves the
lease compare-and-set is single-winner, that an expired lease is reclaimable
(bounded takeover), and that the controller's lease gate gives the work to one
holder only.

Requires a reachable Postgres (scratch DB, dropped per run) just like the
controller integration test; skipped otherwise so the always-on baseline stays
green.
"""
from __future__ import annotations

import os
import sys
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
from apip.ledger.db import Database  # noqa: E402
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


def _create_scratch() -> str:
    name = "apip_ha_" + uuid.uuid4().hex[:12]
    conn = psycopg2.connect(host=SOCKET_DIR, dbname="postgres", connect_timeout=3)
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    try:
        cur.execute(f'CREATE DATABASE "{name}"')
    finally:
        cur.close()
        conn.close()
    return name


def _drop_scratch(name: str) -> None:
    conn = psycopg2.connect(host=SOCKET_DIR, dbname="postgres", connect_timeout=3)
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    try:
        cur.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    finally:
        cur.close()
        conn.close()


pytestmark = pytest.mark.skipif(
    not _can_connect(),
    reason="no reachable Postgres for HA lease test")


@pytest.fixture()
def two_ledgers():
    """Two Ledger handles over one scratch DB (fresh migrations applied)."""
    dburi = _create_scratch()
    db = Database(DatabaseConfig(host=SOCKET_DIR, dbname=dburi,
                                 user=os.environ.get("USER", "bamn")).dsn_kwargs())
    db.wait_until_ready(timeout_s=10)
    try:
        apply_migrations(db)
        yield Ledger(db), Ledger(db)
    finally:
        db.close()
        _drop_scratch(dburi)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def test_lease_grants_single_winner(two_ledgers):
    a, b = two_ledgers
    # seed: the migration inserts an expired empty row, so first claim wins.
    assert a.claim_leadership("controller--a", 60, _now()) is True
    # B cannot take an unexpired lease B doesn't hold.
    assert b.claim_leadership("controller--b", 60, _now() + timedelta(seconds=1)) is False
    # A renews its own lease while still holding it.
    assert a.claim_leadership("controller--a", 60, _now() + timedelta(seconds=2)) is True
    # The lease still names A.
    st = a.lease_state()
    assert st is not None and st["leader_id"] == "controller--a"


def test_expired_lease_is_reclaimable(two_ledgers):
    a, b = two_ledgers
    # A takes an immediately-expired lease (lease_s=0 => expires now).
    assert a.claim_leadership("controller--a", 0, _now()) is True
    # B can take over an already-expired lease (bounded takeover).
    assert b.claim_leadership("controller--b", 60, _now() + timedelta(seconds=1)) is True
    state = b.lease_state()
    assert state["leader_id"] == "controller--b"
    # A can no longer renew: it lost the lease and it has not expired for A
    # (the row now belongs to B, unexpired for B's 60s window).
    assert a.claim_leadership("controller--a", 60, _now() + timedelta(seconds=5)) is False


def test_release_is_noop_for_non_holder(two_ledgers):
    a, b = two_ledgers
    a.claim_leadership("controller--a", 30, _now())
    # B releasing (not the holder) must not void A's lease.
    b.release_lease("controller--b")
    assert a.claim_leadership("controller--a", 30, _now() + timedelta(seconds=1)) is True


def test_controller_lease_gate_single_worker():
    """Two Controller instances over the same scratch DB: only one reports
    is_leader (and can run the worker loops) at a time, while both stay live
    and the follower can take over once the leader's lease lapses."""
    from apip.controller.service import Controller

    dburi = _create_scratch()
    db = Database(DatabaseConfig(host=SOCKET_DIR, dbname=dburi,
                                 user=os.environ.get("USER", "bamn")).dsn_kwargs())
    db.wait_until_ready(timeout_s=10)
    apply_migrations(db)
    db.close()

    def _make(zone_dir: str, reconcile: float) -> Controller:
        cfg = replace(
            load_config(None),
            db=DatabaseConfig(host=SOCKET_DIR, dbname=dburi,
                              user=os.environ.get("USER", "bamn")),
            controller=replace(ControllerConfig(), reconcile_interval_s=reconcile),
            adapter=replace(AdapterConfig(rpz_mode="SHADOW", zone_dir=zone_dir),
                            authorized_domains=("operator.test",)),
        )
        c = Controller(cfg)
        c._lease_s = 2  # short window so takeover is fast
        return c

    try:
        import tempfile
        a = _make(tempfile.mkdtemp(prefix="ha_a_"), 15.0)
        b = _make(tempfile.mkdtemp(prefix="ha_b_"), 15.0)
        # connect each controller's DB pool (start() would also spawn workers,
        # which we deliberately avoid here so the contention is deterministic)
        a.db.wait_until_ready(timeout_s=10)
        b.db.wait_until_ready(timeout_s=10)
        try:
            # Claim deterministically: A wins first.
            assert a._acquire_or_renew_lease() is True
            assert a.state.is_leader is True
            # B, contesting an unexpired lease it doesn't hold, loses.
            assert b._acquire_or_renew_lease() is False
            assert b.state.is_leader is False
            # A renews (still holding).
            assert a._acquire_or_renew_lease() is True
            # Let A's lease lapse by shaving its expiry and re-contending:
            # A's window is now effectively 0, so B takes over.
            a.ledger.db.execute(
                "UPDATE controller_leases SET expires_at=%s WHERE singleton "
                "AND leader_id=%s",
                (_now() - timedelta(seconds=1), a._leader_id))
            assert b._acquire_or_renew_lease() is True
            assert b.state.is_leader is True
            assert a._acquire_or_renew_lease() is False
        finally:
            a.stop()
            b.stop()
    finally:
        _drop_scratch(dburi)