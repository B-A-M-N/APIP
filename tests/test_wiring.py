"""CLI/API wiring for operator approval, policy replay, and multi-adapter
health (Task 4). Two layers:

  1. pure unit tests of the new controller helpers (decision_from_row,
     _adapter_health, ControllerState snapshot multi-adapter degradation) —
     no database required;
  2. API routing tests through build_app with a lightweight FAKE controller,
     so the operator surface (approve / replay / adapters) is exercised
     without a live Postgres. The real controller's orchestration (approve
     compiles -> action, replay appends decisions, adapters_status enumerates
     both adapters) is covered against a scratch database in
     test_controller_integration.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apip.config.service import AdapterConfig, ControllerConfig, ServiceConfig  # noqa: E402
from apip.controller.service import (  # noqa: E402
    ControllerState,
    _adapter_health,
    decision_from_row,
)
from apip.domain.models import ActionSelector, Decision  # noqa: E402


def _cfg() -> ServiceConfig:
    # Operator token is sourced from the INJECTED config (never a re-read of
    # os.environ at request time), so wire it here explicitly.
    return ServiceConfig(operator_token="test-operator-token")


# ---------------------------------------------------------------------------
# decision_from_row (pure)
# ---------------------------------------------------------------------------

def test_decision_from_row_rebuilds_full_decision():
    row = {
        "decision_id": "decision--abc",
        "indicator_id": "indicator--xyz",
        "maliciousness": 42,
        "action_safety": 90,
        "disposition": "PROPOSE_OPERATOR_APPROVAL",
        "action": "dns_nxdomain",
        "rung": "L4",
        "scope": "acceptance-tenant",
        "ttl_seconds": 3600,
        "policy_version": "beta",
        "reason_codes": ["proposed", "ladder"],
        "explanation": "an explanation",
        "selector": {"scope_type": "client_session", "client": "10.0.0.5",
                     "destination": "c2.example.org", "protocol_class": "interactive_http"},
        "randomization": {"mechanism": "ttl_jitter", "draw": {"ttl_seconds": 3400}},
        "content_hash": "hash--deadbeef",
    }
    d = decision_from_row(row)
    assert isinstance(d, Decision)
    assert d.id == row["decision_id"]
    assert d.indicator_id == row["indicator_id"]
    assert d.maliciousness == 42
    assert d.action_safety == 90
    assert d.disposition == "PROPOSE_OPERATOR_APPROVAL"
    assert d.action == "dns_nxdomain"
    assert d.rung == "L4"
    assert d.ttl_seconds == 3600
    assert d.policy_version == "beta"
    assert d.reason_codes == ("proposed", "ladder")
    assert d.explanation == row["explanation"]
    assert d.content_hash == "hash--deadbeef"
    # selector is reconstructed as a typed object, not a raw dict
    assert isinstance(d.selector, ActionSelector)
    assert d.selector.scope_type == "client_session"
    assert d.selector.client == "10.0.0.5"
    assert d.selector.destination == "c2.example.org"
    assert d.selector.protocol_class == "interactive_http"
    # randomization is carried through (draw history is integrity-relevant)
    assert d.randomization is not None
    assert d.randomization["mechanism"] == "ttl_jitter"


def test_decision_from_row_without_selector_is_none():
    row = {
        "decision_id": "decision--noop", "indicator_id": "indicator--a",
        "maliciousness": 10, "action_safety": 10, "disposition": "NO_ACTION",
        "action": "none", "rung": "NONE", "scope": "t", "ttl_seconds": 0,
        "policy_version": "beta", "reason_codes": [], "explanation": "",
        "selector": None, "content_hash": "",
    }
    d = decision_from_row(row)
    assert d.selector is None
    assert d.reason_codes == ()
    assert d.content_hash == ""


# ---------------------------------------------------------------------------
# _adapter_health (pure)
# ---------------------------------------------------------------------------

def test_adapter_health_adds_name_and_max_mode_when_missing():
    from apip.adapters.base import EnforcementAdapter

    class Fake(EnforcementAdapter):
        name = "rn-abc"

        def health(self):
            return {"name": "rn-abc", "mode": "SHADOW", "status": "ok"}

        def max_mode(self):
            return "SHADOW"

        def compile(self, *a, **k):
            raise NotImplementedError

        def validate(self, *a, **k):
            raise NotImplementedError

        def apply(self, *a, **k):
            raise NotImplementedError

        def verify(self, *a, **k):
            raise NotImplementedError

        def revoke(self, *a, **k):
            raise NotImplementedError

        def get_state(self, *a, **k):
            raise NotImplementedError

    h = _adapter_health(Fake())

    assert h["name"] == "rn-abc"
    assert h["mode"] == "SHADOW"
    assert h["status"] == "ok"
    assert h["max_mode"] == "SHADOW"


# ---------------------------------------------------------------------------
# ControllerState snapshot multi-adapter degradation (pure)
# ---------------------------------------------------------------------------

def _snapshot(*adapters_health):
    state = ControllerState()
    state.started_at = None
    db_health = {"status": "up"}
    return state.snapshot(
        db_health=db_health, ledger=None,
        adapter_health=adapters_health[0] if adapters_health else {},
        adapters_health=list(adapters_health),
        registry_rows=[], pipeline_ok=True)


def test_snapshot_surfaces_every_adapter_in_components():
    out = _snapshot({"name": "rpz", "mode": "SHADOW", "status": "ok"},
                    {"name": "suricata", "mode": "OFF", "status": "ok"})
    components = out["components"]
    assert isinstance(components, dict)
    names = [a["name"] for a in components["adapters"]]
    assert names == ["rpz", "suricata"]


def test_snapshot_degrades_when_non_primary_adapter_unhealthy():
    """A degraded Suricata/IPS adapter must degrade the whole status even when
    the primary RPZ is happy (no silent single-adapter gap)."""
    out = _snapshot({"name": "rpz", "mode": "SHADOW", "status": "ok"},
                    {"name": "suricata", "mode": "OFF", "status": "down"})
    assert out["status"] == "degraded"
    assert any(a["status"] != "ok" for a in out["components"]["adapters"])
    assert any(d.startswith("adapter_suricata_") for d in out["degraded"])


# ---------------------------------------------------------------------------
# API routing with a fake controller (no DB)
# ---------------------------------------------------------------------------

class _FakeLedger:
    """Minimal fake the endpoints touch for the routes under test."""


class _FakeController:
    """Stands in for Controller. Routes only call the surface under test."""

    def __init__(self):
        self.ledger = _FakeLedger()
        self.approve_calls = []
        self.replay_calls = 0

    @property
    def adapter(self):
        return _FakeAdapter("rpz")

    def approve_decision(self, decision_id, actor):
        self.approve_calls.append((decision_id, actor))
        if decision_id == "decision--uncompilable":
            return {"decision_id": decision_id, "action_ids": [], "compiled": False}
        return {"decision_id": decision_id, "action_ids": ["action--one"], "compiled": True}

    def replay_policy(self, actor):
        self.replay_calls += 1
        return {"indicators": 3, "recorded": 2, "changed": 1,
                "policy_version": "beta@r2"}

    def adapters_status(self):
        return [_FakeAdapter("rpz").health(), _FakeAdapter("suricata").health()]

    def health(self):
        return {"status": "ok", "components": {"adapters": self.adapters_status()}}


class _FakeAdapter:
    def __init__(self, name):
        self.name = name

    def health(self):
        return {"name": self.name, "mode": "SHADOW", "status": "ok"}


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from apip.api.app import build_app

    faker = _FakeController()
    app = build_app(_cfg(), controller=faker)  # type: ignore[arg-type]  # test double
    app.state._faker = faker
    tc = TestClient(app)
    yield tc, faker


def _auth():
    return {"Authorization": "Bearer test-operator-token"}


def test_approve_endpoint_wires_and_returns_actions(client):
    tc, faker = client
    r = tc.post("/decisions/decision--abc/approve", headers=_auth())
    assert r.status_code == 200
    body = r.json()
    assert body["action_ids"] == ["action--one"]
    assert faker.approve_calls == [("decision--abc", "operator")]


def test_approve_refuses_when_decision_compiles_to_nothing(client):
    tc, _ = client
    r = tc.post("/decisions/decision--uncompilable/approve", headers=_auth())
    assert r.status_code == 409


def test_approve_requires_operator_token(client):
    tc, _ = client
    assert tc.post("/decisions/decision--abc/approve").status_code == 401
    assert tc.post("/decisions/decision--abc/approve",
                   headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_replay_endpoint_wires(client):
    tc, faker = client
    r = tc.post("/policy/replay", headers=_auth())
    assert r.status_code == 200
    assert r.json()["policy_version"] == "beta@r2"
    assert faker.replay_calls == 1


def test_adapters_lists_every_adapter(client):
    tc, _ = client
    r = tc.get("/adapters", headers=_auth())
    assert r.status_code == 200
    names = [a["name"] for a in r.json()["adapters"]]
    assert names == ["rpz", "suricata"]


def test_adapter_status_one_unknown_is_404(client):
    tc, _ = client
    assert tc.get("/adapters/nope", headers=_auth()).status_code == 404