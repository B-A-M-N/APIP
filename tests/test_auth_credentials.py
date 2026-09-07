"""Unit tests for review P0 #14/#15 credential design:

  #14  source keys carry a PUBLIC key_id (apipk_<key_id>.<secret>) so
       channel lookup is one indexed row + one PBKDF2 verification;
  #15  credential hashes are PEPPERED with APIP_SECRET_KEY under a
       versioned scheme (pbkdf2p$), legacy unpeppered hashes still verify,
       and registration fails closed without the deployment secret.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pg  # noqa: E402  (shared Postgres test endpoints)

from apip.auth import (  # noqa: E402
    CredentialError,
    generate_source_key,
    hash_credential,
    parse_source_key,
    verify_credential,
)


# --------------------------------------------------------------------------- #
# P0 #14 — keyed token format
# --------------------------------------------------------------------------- #

def test_generated_key_carries_key_id():
    token, key_id = generate_source_key()
    assert token.startswith("apipk_")
    assert token[len("apipk_"):].startswith(key_id + ".")
    parsed = parse_source_key(token)
    assert parsed is not None
    kid, secret = parsed
    assert kid == key_id
    assert secret and len(secret) >= 32


def test_parse_default_denies_malformed_tokens():
    for bad in ("", "apipk_", "apipk_nodot", "apipk_ZZZZ.abcdef",
                "otherprefix_ab.cd", "apipk_.nosecret", "apipk_abcd."):
        assert parse_source_key(bad) is None, bad


def test_peppered_hash_roundtrip():
    token, key_id = generate_source_key()
    _, secret = parse_source_key(token)
    stored = hash_credential(secret, pepper="deployment-secret")
    assert stored.startswith("pbkdf2p$")      # versioned, peppered scheme
    assert verify_credential(secret, stored, pepper="deployment-secret")
    assert not verify_credential(secret, stored)              # wrong pepper
    assert not verify_credential(secret, stored, pepper="other")
    assert not verify_credential("wrong", stored, pepper="deployment-secret")


def test_legacy_unpeppered_hash_still_verifies_without_pepper():
    # prerelease deployments hashed without the pepper; those hashes must
    # keep verifying (under the legacy scheme) so operators can rotate.
    legacy = hash_credential("legacy-secret")
    assert legacy.startswith("pbkdf2$")
    assert verify_credential("legacy-secret", legacy)
    # the LEGACY scheme is inherently unpeppered: any pepper argument is
    # ignored for pbkdf2$ hashes (they were made without one)
    assert verify_credential("legacy-secret", legacy, pepper="x")


# --------------------------------------------------------------------------- #
# P0 #15 — registration fails closed without the deployment secret
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def api():
    import os
    import tempfile
    import uuid
    from dataclasses import replace

    import psycopg2
    import psycopg2.extensions
    from fastapi.testclient import TestClient

    from apip.api.app import build_app
    from apip.config.service import AdapterConfig, DatabaseConfig, load_config
    from apip.controller.service import Controller
    from apip.ledger.db import Database
    from apip.ledger.migrations import apply_migrations

    try:
        conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
    except psycopg2.Error:
        yield None
        return
    name = "apip_it_" + uuid.uuid4().hex[:12]
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
        yield client
    finally:
        client.close()
        ctrl.stop()
        conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        conn.cursor().execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        conn.close()


HDR = {"Authorization": "Bearer apipt_test"}


def test_registration_requires_the_deployment_secret(api):
    if api is None:
        pytest.skip("no local postgres")
    from dataclasses import replace as _replace
    from apip.config.service import ServiceConfig

    # a config WITHOUT a secret must refuse registration (503), not mint an
    # unpeppered credential
    cfg = api.app.state.controller.config
    import copy
    unpeppered = _replace(cfg, secret_key=None)
    from apip.api.app import build_app
    other = build_app(unpeppered, controller=api.app.state.controller)
    from fastapi.testclient import TestClient as _TC
    c2 = _TC(other)
    try:
        r = c2.post("/sources/register", headers=HDR,
                    json={"source_id": "no-secret-src", "source_class": "local"})
        assert r.status_code == 503
    finally:
        c2.close()


def test_register_and_ingest_through_keyed_credential(api):
    if api is None:
        pytest.skip("no local postgres")
    r = api.post("/sources/register", headers=HDR,
                 json={"source_id": "keyed-src", "source_class": "local",
                       "independent": True})
    assert r.status_code == 200, r.text
    token = r.json()["source_key"]
    parsed = parse_source_key(token)
    assert parsed is not None and parsed[0]
    # the DB row carries key_id (indexed) and a peppered hash
    ctrl = api.app.state.controller
    row = ctrl.db.query_one(
        "SELECT key_id, key_hash FROM sources WHERE source_id='keyed-src'")
    assert row["key_id"] == parsed[0]
    assert row["key_hash"].startswith("pbkdf2p$")
    # ingest authenticates via the keyed token; a forged secret under the
    # same key_id is refused
    ok = ctrl.ledger.source_by_credential(token, pepper="deployment-secret")
    assert ok is not None and ok["source_id"] == "keyed-src"
    kid, secret = parsed
    forged = f"apipk_{kid}." + "A" * 40
    assert ctrl.ledger.source_by_credential(
        forged, pepper="deployment-secret") is None
    # a garbage token default-denies without touching PBKDF2 at all
    assert ctrl.ledger.source_by_credential("junk") is None
