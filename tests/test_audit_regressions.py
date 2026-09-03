"""Regression tests for the adversarial-audit fixes (2026-09-03, B-A-M-N).

Each test pins a specific defect found during the boundary/correctness audit
and now closed:

  - RPZ validate re-refuses a multi-line fragment (zone-file injection),
    and ENFORCE verify fails closed when no resolver is configured (no
    fabricated success on a file write alone);
  - Suricata validate re-refuses a multi-line fragment (ruleset injection),
    re-checks home-net scope at validate time (defense in depth layer 3),
    and — fixing a self-dead-end — accepts the fqdn http.host intent rule
    that compile() legitimately produces;
  - the overlay allowlist clamp: an overlay may only re-affirm a governed
    allowlist entry, never introduce a new suppressed value (monotonic
    tighten-only invariant);
  - OpenC2 export guards: an unknown action is emitted as a no-op rather than
    crashing, and a target is never fabricated from a decision id / CIDR;
  - the operator API returns clean 4xx (not a 500) on unknown-action revoke,
    a non-integer promote revision, and an invalid staged mode, and caps the
    ingest body size.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apip.adapters.base import AdapterError  # noqa: E402
from apip.adapters.rpz import RpzAdapter  # noqa: E402
from apip.adapters.suricata import SuricataAdapter  # noqa: E402
from apip.config.service import AdapterConfig  # noqa: E402
from apip.decision.layer import merge_policy_overlay  # noqa: E402
from apip.decision.loader import build_overlay, load_policy_text  # noqa: E402


# ---------------------------------------------------------------------------
# RPZ: zone-file injection + ENFORCE verify fail-closed
# ---------------------------------------------------------------------------

def _rpz(tmp_path, mode="ENFORCE", authorized=("corp.com",), server="", reload=""):
    return RpzAdapter(AdapterConfig(
        rpz_mode=mode, zone_dir=str(tmp_path), zone_name="corp",
        reload_command=reload, authorized_domains=tuple(authorized),
        verify_query_server=server))


def _rpz_candidate(owner="evil.corp.com", fragment=None):
    return {
        "rule_id": f"owner:{owner}",
        "fragment": fragment or f"{owner}. IN CNAME . ; ok",
        "selector": {"scope_type": "destination_global",
                     "destination": owner, "exact_fqdn": owner},
    }


def test_rpz_validate_rejects_multiline_zone_injection(tmp_path):
    """A fragment carrying a newline must be refused; startswith alone cannot
    see the injected follow-on RR line."""
    ad = _rpz(tmp_path, authorized=("corp.com",), server="127.0.0.1")
    injected = _rpz_candidate(
        "evil.corp.com", fragment="evil.corp.com. IN CNAME . ; ok\nattacker IN A 5.6.7.8")
    with pytest.raises(AdapterError):
        ad.validate(injected)


def test_rpz_enforce_verify_fails_closed_without_resolver(tmp_path):
    """ENFORCE with no verify_query_server must not report a fabricated
    success on a zone-file write alone — it fails closed."""
    ad = _rpz(tmp_path, authorized=("corp.com",), server="")
    # zone-file presence alone must NOT be reported as verified in ENFORCE
    (tmp_path / "corp.zone").write_text("evil.corp.com. IN CNAME . ; ok\n",
                                        encoding="utf-8")
    v = ad.verify(_rpz_candidate("evil.corp.com"))
    assert v["ok"] is False
    assert "verify_query_server" in v["error"]


# ---------------------------------------------------------------------------
# Suricata: ruleset injection + scope re-check + fqdn http.host dead-end
# ---------------------------------------------------------------------------

def _sur(tmp_path, mode="ENFORCE", prefixes=("10.0.0.0/8",), reload=""):
    return SuricataAdapter(AdapterConfig(
        suricata_mode=mode, suricata_rules_dir=str(tmp_path),
        suricata_rules_file="rules", reload_command="",
        suricata_authorized_prefixes=tuple(prefixes)))


def test_suricata_validate_rejects_multiline_ruleset_injection(tmp_path):
    ad = _sur(tmp_path)
    injected = {
        "rule_id": "sid:9100001",
        "fragment": ('drop ip $HOME_NET any -> 10.1.1.1 any '
                     '(msg:"APIP x"; metadata:apip_decision d; sid:9100001; rev:1;)\n'
                     'alert ip any any -> any any (metadata:apip_decision EVIL; '
                     'sid:999999; rev:1;)'),
        "selector": {"scope_type": "destination_global",
                     "destination": "10.1.1.1", "exact_ip": "10.1.1.1"},
    }
    with pytest.raises(AdapterError):
        ad.validate(injected)


def test_suricata_validate_rechecks_home_net_scope(tmp_path):
    """validate re-enforces the adapter's own home-net boundary (defense in
    depth layer 3), not only at compile time."""
    ad = _sur(tmp_path)
    out = {
        "rule_id": "sid:9100002",
        "fragment": 'drop ip $HOME_NET any -> 11.1.1.1 any '
                    '(msg:"APIP x"; metadata:apip_decision d; sid:9100002; rev:1;)',
        "selector": {"scope_type": "destination_global",
                     "destination": "11.1.1.1", "exact_ip": "11.1.1.1"},
    }
    with pytest.raises(AdapterError):
        ad.validate(out)


def test_suricata_validate_catches_exactness_mismatch(tmp_path):
    """A fragment targeting a DIFFERENT ip than the selector is refused."""
    ad = _sur(tmp_path)
    mismatch = {
        "rule_id": "sid:9100003",
        "fragment": 'drop ip $HOME_NET any -> 10.2.2.2 any '
                    '(msg:"APIP x"; metadata:apip_decision d; sid:9100003; rev:1;)',
        "selector": {"scope_type": "destination_global",
                     "destination": "10.1.1.1", "exact_ip": "10.1.1.1"},
    }
    with pytest.raises(AdapterError):
        ad.validate(mismatch)


def test_suricata_fqdn_http_intent_rule_validates(tmp_path):
    """compile() legitimately produces an fqdn http.host rate_limit intent
    selector carrying a pair scope; validate must accept it (bound by the
    host content field), not dead-end a compilable action."""
    ad = _sur(tmp_path)
    intent = {
        "rule_id": "sid:9100004",
        "fragment": ('alert http any any -> any any '
                     '(msg:"APIP SHADOW_ACTION evil.example.com rung=L0"; '
                     'http.host; content:"evil.example.com"; nocase; '
                     'metadata:apip_decision dec-1, apip_ceiling_per_min 10, '
                     'apip_client 10.1.1.1, apip_ttl_seconds 300; '
                     'detection_filter:track by_src, count 10, seconds 60; '
                     'sid:9100004; rev:1;)'),
        "selector": {"scope_type": "client_destination_pair",
                     "destination": "evil.example.com", "exact_ip": None},
    }
    assert ad.validate(intent)["ok"] is True


# ---------------------------------------------------------------------------
# overlay allowlist clamp (monotonic tighten-only invariant)
# ---------------------------------------------------------------------------

GLOBAL_TOML = """
policy_version = "global.1"
mode = "ENFORCE"
scope = "tenant-world"
allowlist = [ { value = "governed.test", owner = "operator", ticket = "g-1" } ]

[thresholds]
observe_m = 40
fqdn_auto_m = 90
fqdn_auto_s = 85
ip_rate_m = 90
ip_rate_s = 85
ip_deny_m = 98
ip_deny_s = 95

[limits]
max_auto_ttl_seconds = 600
max_evidence_per_indicator = 64
nominal_rate_ceiling_per_min = 1000

[authorization]
authorized_domains = ["test"]

[safety]
allowlist_precedence = true
no_ai_components = true
"""


def _overlay_text(text: str):
    return build_overlay(tomllib.loads(text), text)


def test_overlay_narrows_open_global_domains_not_to_nothing():
    """A tenant narrowing an OPEN (unrestricted-over-domains) global via
    authorized_domains keeps its declared boundary as the effective scope —
    it must NOT be emptied to nothing (which would deny the tenant all
    protection)."""
    open_global = load_policy_text("""
policy_version = "open.1"
mode = "SHADOW"
scope = "*"
[thresholds]
observe_m = 40
fqdn_auto_m = 90
fqdn_auto_s = 85
ip_rate_m = 90
ip_rate_s = 85
ip_deny_m = 98
ip_deny_s = 95
[limits]
max_auto_ttl_seconds = 600
max_evidence_per_indicator = 64
nominal_rate_ceiling_per_min = 1000
[safety]
allowlist_precedence = true
no_ai_components = true
""")
    assert open_global.authorized_domains == ()
    narrow = _overlay_text('policy_version="n"\nmode="ENFORCE"\nscope="*"\n'
                           '[authorization]\nauthorized_domains = ["tenant.test"]')
    eff = merge_policy_overlay(open_global, narrow)
    assert set(eff.authorized_domains) == {"tenant.test"}


def test_overlay_may_not_introduce_new_allowlist_value():
    """An overlay cannot add a NEW suppressed value (that would loosen the
    global control — the tenant whitelisting its own C2 surface); it may only
    re-affirm a governed entry."""
    g = load_policy_text(GLOBAL_TOML)
    # new ungoverned value -> dropped
    widening = _overlay_text('policy_version="o1"\nmode="ENFORCE"\nscope="*"\n'
                             'allowlist = [ { value = "evil.test", owner = "tenant", ticket = "t" } ]')
    eff = merge_policy_overlay(g, widening)
    assert "evil.test" not in {e.value for e in eff.allowlist}
    # governed value -> re-affirmed
    reaffirm = _overlay_text('policy_version="o2"\nmode="ENFORCE"\nscope="*"\n'
                             'allowlist = [ { value = "governed.test", owner = "tenant", ticket = "t" } ]')
    eff2 = merge_policy_overlay(g, reaffirm)
    assert "governed.test" in {e.value for e in eff2.allowlist}


# ---------------------------------------------------------------------------
# OpenC2 export: unknown action + no fabricated target
# ---------------------------------------------------------------------------

def _decision(action, scope_type=None, destination=None, host=None):
    from apip.domain.models import ActionSelector, Decision  # noqa: PLC0415
    sel = None
    if scope_type is not None:
        sel = ActionSelector(scope_type=scope_type, destination=destination,
                             host=host)
    return Decision(id="d-1", indicator_id="i-1", maliciousness=60,
                    action_safety=80, disposition="AUTO_ENFORCE",
                    action=action, rung="L1", scope="scope", ttl_seconds=300,
                    policy_version="p", reason_codes=(), explanation="e",
                    selector=sel)


def test_openc2_unknown_action_is_guarded():
    from apip.interop.openc2 import decision_to_openc2  # noqa: PLC0415
    out = decision_to_openc2(_decision("some_new_action"))
    assert out["action"] == "query"
    assert out["actuator"]["type"] == "openc2:actuator:unknown:1.0"
    assert out["target"] == {}


def test_openc2_does_not_fabricate_target_from_decision_id():
    """A firewall_deny with no selector must not invent a device named after
    the decision id."""
    from apip.interop.openc2 import decision_to_openc2  # noqa: PLC0415
    out = decision_to_openc2(_decision("firewall_deny"))
    assert out["target"] == {}


def test_openc2_cidr_has_no_fabricated_source():
    """A CIDR/port destination must not claim a fabricated 0.0.0.0/0 source."""
    from apip.interop.openc2 import decision_to_openc2  # noqa: PLC0415
    out = decision_to_openc2(_decision("firewall_deny",
                                       scope_type="destination_global",
                                       destination="10.0.0.0/8"))
    tgt = out["target"]["ipv4_connection"]
    assert tgt["dst_addr"] == "10.0.0.0/8"
    assert "src_addr" not in tgt


# ---------------------------------------------------------------------------
# operator API input hardening
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def api_harness():
    from fastapi.testclient import TestClient  # noqa: PLC0415
    from apip.api.app import build_app  # noqa: PLC0415
    from apip.config.service import ServiceConfig  # noqa: PLC0415
    cfg = ServiceConfig(operator_token="test-token")
    faker = _FakeController()
    app = build_app(cfg, controller=faker)  # type: ignore[arg-type]
    return TestClient(app), faker


class _FakeController:
    """Minimal controller double: everything the app routes touch."""

    def __init__(self):
        self.ledger = _FakeLedger()

    def approve_decision(self, decision_id, actor):
        if decision_id.endswith("uncompilable"):
            raise ValueError("compiles to nothing")
        return {"action_ids": ["action--one"], "compiled": True}

    def revoke_action(self, action_id, actor):
        if action_id == "missing":
            raise LookupError("unknown action missing")
        return {"action_id": action_id, "state": "revoked", "verified": True}

    def replay_policy(self, actor):
        return {"policy_version": "beta@r2", "decisions": []}

    def health(self):
        return {"status": "ok", "degraded": [], "components": {}}

    def adapters_status(self):
        return [{"name": "rpz", "mode": "SHADOW", "status": "ok"}]


class _FakeLedger:
    def source_by_credential(self, key):
        return None

    def list_sources(self):
        return []

    def next_policy_revision(self, version):
        return 1

    def stage_policy(self, **kwargs):
        return None

    def promote_policy(self, version, revision, actor):
        if revision != 1:
            raise ValueError("not staged")
        return None


def test_api_revoke_unknown_action_is_404(api_harness):
    tc, _ = api_harness
    h = {"Authorization": "Bearer test-token"}
    assert tc.post("/actions/missing/revoke", headers=h).status_code == 404
    assert tc.post("/actions/missing/revoke").status_code == 401


def test_api_promote_bad_revision_is_400(api_harness):
    tc, _ = api_harness
    h = {"Authorization": "Bearer test-token"}
    # non-integer revision -> 400, not 500
    r = tc.post("/policy/promote", json={"version": "p", "revision": "abc"},
                headers=h)
    assert r.status_code == 400


def test_api_policy_stage_invalid_mode_is_400(api_harness):
    tc, _ = api_harness
    h = {"Authorization": "Bearer test-token"}
    r = tc.post("/policy/stage", json={"text": "", "mode": "BOGUS"}, headers=h)
    assert r.status_code == 400


def test_api_health_does_not_disclose_topology(api_harness):
    tc, _ = api_harness
    body = tc.get("/health").json()
    # liveness only: no adapter modes / zones / scope leaked unauthenticated
    assert set(body) <= {"status", "degraded", "api_version"}
    assert "components" not in body
    assert "mode" not in body