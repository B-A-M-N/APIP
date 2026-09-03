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


class Database:
    """A small ThreadedConnectionPool wrapper with explicit health state."""

    def __init__(self, dsn_kwargs: dict, pool_min: int = 1, pool_max: int = 8):
        self._dsn_kwargs = dict(dsn_kwargs)
        self._pool_min = pool_min
        self._pool_max = pool_max
        self._pool: psycopg2.pool.ThreadedConnectionPool | None = None
        self._lock = threading.Lock()
        self.last_error: str | None = None

    # -- lifecycle ----------------------------------------------------------

    def connect(self) -> None:
        with self._lock:
            if self._pool is not None:
                return
            try:
                self._pool = psycopg2.pool.ThreadedConnectionPool(
                    self._pool_min, self._pool_max, **self._dsn_kwargs)
                self.last_error = None
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

    @property
    def connected(self) -> bool:
        return self._pool is not None

    # -- query surface --------------------------------------------------------

    @contextmanager
    def connection(self):
        """Yield a pooled connection; rollback + re-raise on error. Raises
        DatabaseUnavailable when the pool cannot serve."""
        if self._pool is None:
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
                if put is not None:
                    put.putconn(conn)

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
        """Explicit component health: never a bare boolean."""
        if self._pool is None:
            return {"status": "down", "error": self.last_error}
        try:
            row = self.query_one("SELECT 1 AS ok")
            return {"status": "up" if row else "degraded", "error": None}
        except Exception as e:
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
