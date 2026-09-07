"""Database connection handling: bounded pool, fail-closed health, retries.

The ledger is the source of durable truth. When it is unavailable the
controller must DEGRADE (no new enforcement, surface degraded status,
retain state to reconcile later) — never fabricate success.
"""
from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Any

import psycopg2
import psycopg2.extras
import psycopg2.pool


class DatabaseUnavailable(RuntimeError):
    pass


# Connection-LEVEL failures (lost socket, server restart, terminated backend).
# These mean the POOL is stale — as opposed to statement errors (integrity,
# syntax), which must never be retried. psycopg2.pool does not validate pooled
# connections, so without recovery a Postgres restart wedges the controller
# until process restart (review P1 #36).
_CONNECTION_ERRORS = (psycopg2.OperationalError, psycopg2.InterfaceError)


class Database:
    """A small ThreadedConnectionPool wrapper with explicit health state."""

    def __init__(self, dsn_kwargs: dict, pool_min: int = 1, pool_max: int = 8):
        self._dsn_kwargs = dict(dsn_kwargs)
        self._pool_min = pool_min
        self._pool_max = pool_max
        self._pool: psycopg2.pool.ThreadedConnectionPool | None = None
        self._lock = threading.Lock()
        self.last_error: str | None = None
        # set by the first successful connect(); cleared by an explicit
        # close() so a deliberately-closed database stays closed. Worker
        # recovery (P1 #36) reconnects lazily only while this is set.
        self._ever_connected = False

    # -- lifecycle ----------------------------------------------------------

    def connect(self) -> None:
        with self._lock:
            if self._pool is not None:
                return
            try:
                self._pool = psycopg2.pool.ThreadedConnectionPool(
                    self._pool_min, self._pool_max, **self._dsn_kwargs)
                self.last_error = None
                self._ever_connected = True
            except psycopg2.Error as e:
                self.last_error = str(e).strip()
                raise DatabaseUnavailable(
                    f"cannot connect to postgres: {self.last_error}") from e

    def close(self) -> None:
        with self._lock:
            if self._pool is not None:
                try:
                    self._pool.closeall()
                finally:
                    self._pool = None
            self._ever_connected = False

    @property
    def connected(self) -> bool:
        return self._pool is not None

    # -- query surface --------------------------------------------------------

    @contextmanager
    def connection(self):
        """Yield a pooled connection; rollback + re-raise on error. Raises
        DatabaseUnavailable when the pool cannot serve.

        Recovery (review P1 #36): a connection-LEVEL failure
        (OperationalError/InterfaceError — lost socket, server restart) marks
        the whole pool stale and rebuilds it, so the NEXT operation
        reconnects. Statement-level errors (integrity, syntax) are never
        treated as pool failures. Reconnect happens lazily ONLY if this
        Database previously connected — an explicit close() keeps it closed."""
        if self._pool is None:
            if self._ever_connected:
                # stale pool was discarded after a failure — reconnect once
                self.connect()
            else:
                raise DatabaseUnavailable("database not connected")
            if self._pool is None:   # connect() failed and re-raised
                raise DatabaseUnavailable("database not connected")
        conn = None
        try:
            conn = self._pool.getconn()
        except psycopg2.Error as e:
            self.last_error = str(e).strip()
            raise DatabaseUnavailable(f"pool exhausted/error: {self.last_error}") from e
        try:
            yield conn
            conn.commit()
        except _CONNECTION_ERRORS as e:
            # the connection itself died: discard it and drop the stale pool
            # so the next operation reconnects cleanly
            try:
                conn.close()
            except psycopg2.Error:
                pass
            self.last_error = str(e).strip()
            self._discard_pool()
            raise
        except psycopg2.Error as e:
            try:
                conn.rollback()
            except psycopg2.Error:
                pass
            self.last_error = str(e).strip()
            raise
        except Exception:
            try:
                conn.rollback()
            except psycopg2.Error:
                pass
            raise
        finally:
            if conn is not None:
                put = self._pool
                if put is not None and not conn.closed:
                    put.putconn(conn)

    def _discard_pool(self) -> None:
        """Tear down a stale pool so the next connect() rebuilds it. Called
        after a connection-level failure; safe under concurrency (the lock is
        only taken for the swap, never while a query runs)."""
        with self._lock:
            pool = self._pool
            self._pool = None
        if pool is not None:
            try:
                pool.closeall()
            except psycopg2.Error:
                pass

    @contextmanager
    def cursor(self, cursor_factory=psycopg2.extras.RealDictCursor):
        with self.connection() as conn:
            with conn.cursor(cursor_factory=cursor_factory) as cur:
                yield cur

    def execute(self, sql: str, params: tuple | dict = ()) -> None:
        with self.cursor() as cur:
            cur.execute(sql, params)

    def query(self, sql: str, params: tuple | dict = ()) -> list[dict]:
        with self.cursor() as cur:
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]

    def query_one(self, sql: str, params: tuple | dict = ()) -> dict | None:
        with self.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            return dict(row) if row is not None else None

    # -- health ---------------------------------------------------------------

    def health(self) -> dict:
        """Explicit component health: never a bare boolean. A pool discarded
        by connection-level recovery is retried here (lazily) so health
        reflects the SERVER, not a stale teardown — an explicitly closed
        database (never connected / operator close) stays down."""
        if self._pool is None and not self._ever_connected:
            return {"status": "down", "error": self.last_error}
        try:
            row = self.query_one("SELECT 1 AS ok")
            return {"status": "up" if row else "degraded", "error": None}
        except (DatabaseUnavailable, psycopg2.Error) as e:
            self.last_error = str(e).strip()
            return {"status": "down", "error": self.last_error}

    def wait_until_ready(self, timeout_s: float = 30.0, poll_s: float = 1.0) -> None:
        deadline = time.monotonic() + timeout_s
        last: Exception | None = None
        while time.monotonic() < deadline:
            try:
                self.connect()
                self.query_one("SELECT 1")
                return
            except DatabaseUnavailable as e:
                last = e
                self._pool = None
                time.sleep(poll_s)
        raise DatabaseUnavailable(f"database not ready within {timeout_s}s: {last}")
