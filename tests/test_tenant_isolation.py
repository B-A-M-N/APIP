"""Real tenant isolation (audit P0 #8).

Four properties proven against real Postgres and the real API surface:

  1. distinct durable observables: the SAME FQDN submitted by tenant A
     and tenant B maps to DISTINCT indicator rows — tenant is part of
     the server-derived observable identity, so evidence populations,
     decisions and actions are partitioned (policy layering is not
     isolation).
  2. credential-scoped tenants: a source credential declares the
     tenants it may submit for at registration; tenant is DERIVED from
     the credential, never trusted from a header.
  3. cross-tenant submission is a 403: a credential for A presenting
     x-apip-tenant: B is refused before any durable write.
  4. a global credential (empty allowed_tenants) may NOT claim any
     tenant — the free-form header alone grants nothing.
"""
from __future__ import annotations

import sys
import tempfile
import uuid
from dataclasses import replace
from pathlib import Path

import psycopg2
import psycopg2.extensions
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pg  # noqa: E402  (shared Postgres test endpoints)

from apip.api.app import build_app  # noqa: E402
from apip.config.service import (  # noqa: E402
    AdapterConfig,
    DatabaseConfig,
    load_config,
)
from apip.controller.service import Controller  # noqa: E402
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
    not _can_connect(), reason="no reachable Postgres for tenant tests")


@pytest.fixture()
def api():
    """A real controller + TestClient over one scratch Postgres database."""
    name = "apip_tnt_" + uuid.uuid4().hex[:12]
    conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    conn.cursor().execute(f'CREATE DATABASE "{name}"')
    conn.close()
    cfg = replace(
        load_config(None),
        db=DatabaseConfig(host=pg.HOST, port=pg.PORT, dbname=name,
                          user=pg.USER),
        adapter=replace(AdapterConfig(rpz_mode="SHADOW",
                                      zone_dir=tempfile.mkdtemp()),
                        authorized_domains=("operator.test",)),
        operator_token="apipt_test",
        secret_key="deployment-secret",
    )
    db = Database(cfg.db.dsn_kwargs())
    db.wait_until_ready(timeout_s=10)
    apply_migrations(db)
    db.close()
    ctrl = Controller(cfg)
    ctrl.ledger.db.connect()
    client = TestClient(build_app(cfg, controller=ctrl))
    try:
        yield client, ctrl
    finally:
        client.close()
        ctrl.stop()
        conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        conn.cursor().execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        conn.close()


HDR = {"Authorization": "Bearer apipt_test"}

SHARED_FQDN = "shared.operator.test"

_PAYLOAD = """
{{"indicators": [{{
  "id": "indicator--{tag}", "type": "fqdn", "value": "{value}",
  "sources": ["local-sensor"], "tags": ["c2"],
  "evidence": [{{"kind": "direct_local_detection",
                 "source_id": "local-sensor",
                 "observed_at": "{ts}", "independent": true}}]
}}]}}
"""


def _payload(tag: str, value: str) -> str:
    from datetime import datetime, timedelta, timezone
    ts = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    return _PAYLOAD.format(tag=tag, value=value, ts=ts)


def _register(client, source_id: str, tenants: list[str]) -> str:
    r = client.post("/sources/register", headers=HDR,
                    json={"source_id": source_id, "source_class": "local",
                          "independent": True,
                          "allowed_tenants": tenants})
    assert r.status_code == 200, r.text
    return r.json()["source_key"]


def _ingest(client, token: str, tag: str, value: str,
            tenant: str | None) -> object:
    headers = {"x-apip-source-key": token}
    if tenant:
        headers["x-apip-tenant"] = tenant
    return client.post("/ingest", headers=headers,
                       content=_payload(tag, value).encode())


def test_same_fqdn_two_tenants_distinct_durable_observables(api):
    """Property 1: A and B submit the exact same FQDN; the durable
    indicator rows are DISTINCT, and each row's evidence population is
    its own."""
    client, ctrl = api
    tok_a = _register(client, "src-a", ["tenant-a"])
    tok_b = _register(client, "src-b", ["tenant-b"])
    r = _ingest(client, tok_a, "obs-shared-a", SHARED_FQDN, "tenant-a")
    assert r.status_code == 200, r.text
    r = _ingest(client, tok_b, "obs-shared-b", SHARED_FQDN, "tenant-b")
    assert r.status_code == 200, r.text
    led = ctrl.ledger
    id_a = led.observable_id("fqdn", SHARED_FQDN, "tenant-a")
    id_b = led.observable_id("fqdn", SHARED_FQDN, "tenant-b")
    assert id_a != id_b, "tenant is not part of durable observable identity"
    row_a = led.get_indicator(id_a)
    row_b = led.get_indicator(id_b)
    assert row_a is not None and row_b is not None
    assert row_a["tenant_id"] == "tenant-a"
    assert row_b["tenant_id"] == "tenant-b"
    # partitioned evidence populations: each indicator's evidence rows are
    # exclusively its own (distinct batches; distinct rows entirely)
    ev_a = ctrl.db.query(
        "SELECT evidence_id, batch_id FROM evidence WHERE indicator_id=%s",
        (id_a,))
    ev_b = ctrl.db.query(
        "SELECT evidence_id, batch_id FROM evidence WHERE indicator_id=%s",
        (id_b,))
    assert ev_a and ev_b
    assert {r["evidence_id"] for r in ev_a}.isdisjoint(
        {r["evidence_id"] for r in ev_b})
    assert {r["batch_id"] for r in ev_a}.isdisjoint(
        {r["batch_id"] for r in ev_b})


def test_single_tenant_credential_derives_tenant_without_header(api):
    """Property 2: a credential scoped to exactly one tenant may submit
    WITHOUT x-apip-tenant — the tenant is derived from the credential."""
    client, ctrl = api
    tok = _register(client, "src-single", ["tenant-solo"])
    r = _ingest(client, tok, "obs-solo", SHARED_FQDN, None)
    assert r.status_code == 200, r.text
    led = ctrl.ledger
    row = led.get_indicator(led.observable_id("fqdn", SHARED_FQDN,
                                              "tenant-solo"))
    assert row is not None, "tenant was not derived from the credential"


def test_cross_tenant_submission_is_403(api):
    """Property 3: a credential for tenant-a presenting x-apip-tenant:
    tenant-b gets 403 and NOTHING is written durably."""
    client, ctrl = api
    tok_a = _register(client, "src-x", ["tenant-a"])
    r = _ingest(client, tok_a, "obs-x", SHARED_FQDN, "tenant-b")
    assert r.status_code == 403, r.text
    led = ctrl.ledger
    leaked = led.get_indicator(led.observable_id("fqdn", SHARED_FQDN,
                                                 "tenant-b"))
    assert leaked is None, "cross-tenant submission wrote durable state"


def test_global_credential_cannot_claim_a_tenant(api):
    """Property 4: the header alone grants nothing — a source registered
    without allowed_tenants claiming a tenant is a 403."""
    client, ctrl = api
    tok = _register(client, "src-global", [])
    r = _ingest(client, tok, "obs-g", SHARED_FQDN, "tenant-a")
    assert r.status_code == 403, r.text
    led = ctrl.ledger
    assert led.get_indicator(
        led.observable_id("fqdn", SHARED_FQDN, "tenant-a")) is None


def test_multi_tenant_credential_may_pick_within_scope(api):
    """A credential scoped to several tenants may choose any of them via
    the header — but never one outside the set."""
    client, ctrl = api
    tok = _register(client, "src-multi", ["tenant-a", "tenant-b"])
    assert _ingest(client, tok, "obs-m1", SHARED_FQDN,
                   "tenant-a").status_code == 200
    assert _ingest(client, tok, "obs-m2", SHARED_FQDN,
                   "tenant-c").status_code == 403
