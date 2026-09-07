"""Shared Postgres test endpoints (review P1 #42).

Defaults target the local unix-socket Postgres. CI overrides via env:

  APIP_TEST_PG_HOST  (e.g. 127.0.0.1 for a TCP service container)
  APIP_TEST_PG_PORT  (default 5432)
  APIP_TEST_PG_USER  (default $USER)
  APIP_TEST_PG_PASSWORD (optional)
"""
from __future__ import annotations

import os

HOST = os.environ.get("APIP_TEST_PG_HOST") or "/var/run/postgresql"
PORT = int(os.environ.get("APIP_TEST_PG_PORT", "5432"))
USER = os.environ.get("APIP_TEST_PG_USER") or os.environ.get("USER", "bamn")
PASSWORD = os.environ.get("APIP_TEST_PG_PASSWORD") or None


def dsn_kwargs(dbname: str) -> dict:
    kw = dict(host=HOST, port=PORT, dbname=dbname, user=USER,
              connect_timeout=3)
    if PASSWORD:
        kw["password"] = PASSWORD
    return kw
