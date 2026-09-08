"""Capability registry + materialization honesty (audit #24-#29).

  #29 adapters ADVERTISE capabilities (action types, indicator types,
      selector shapes, max posture, independent verification); the
      controller exposes the truthful matrix and reports `decision valid /
      materialization unavailable` when an approval compiles to zero
      fragments;
  #28 CIDR is a dead product branch: the decision records OBSERVE with
      materialization_unavailable, never a proposal inviting approval;
  #24 observation context: evidence detail carrying client/protocol_class
      reaches the evaluator server-derived, so the L1/L2 gates are
      reachable from real ingestion (deterministically derived, ties
      broken deterministically, unknown protocol classes fail closed);
  knobs implement-or-reject: the L1 challenge-budget knobs are REJECTED
      at load (no proxy_challenge actuator exists, audit #25).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apip.adapters.base import MODE_RANK  # noqa: E402
from apip.controller.engine import DecisionPipeline  # noqa: E402
from apip.controller.service import decision_from_row  # noqa: E402
from apip.decision.loader import PolicyValidationError, validate_policy  # noqa: E402
from apip.decision.policy import evaluate  # noqa: E402
from apip.domain.models import Evidence, Indicator  # noqa: E402
from apip.registry import SourceProfile, SourceRegistry  # noqa: E402


# -- #29 capability advertisement ----------------------------------------------

def test_rpz_capabilities_are_exact_fqdn_only(tmp_path):
    from apip.adapters.rpz import RpzAdapter
    from apip.config.service import AdapterConfig
    ad = RpzAdapter(AdapterConfig(
        rpz_mode="ENFORCE", zone_dir=str(tmp_path),
        zone_name="apip.test", reload_command="true",
        verify_query_server="127.0.0.1",
        authorized_domains=("operator.test",)))
    cap = ad.capabilities()
    assert cap["action_types"] == ["dns_nxdomain"]
    assert cap["indicator_types"] == ["fqdn"]
    assert cap["selector_shapes"] == ["destination_global"]
    assert cap["max_posture"] == "ENFORCE"
    assert cap["independent_verify"] is True   # resolver configured
    # below ENFORCE, or ENFORCE with no resolver: file-state only
    ad_sh = RpzAdapter(AdapterConfig(
        rpz_mode="SHADOW", zone_dir=str(tmp_path),
        zone_name="apip.test", authorized_domains=("operator.test",)))
    assert ad_sh.capabilities()["independent_verify"] is False


def test_suricata_capabilities_admit_no_enforcement(tmp_path):
    from apip.adapters.suricata import SuricataAdapter
    from apip.config.service import AdapterConfig
    ad = SuricataAdapter(AdapterConfig(
        suricata_mode="SHADOW", suricata_rules_dir=str(tmp_path)))
    cap = ad.capabilities()
    # IDS/EXPORT surface: independent verification of ENFORCEMENT is false
    # no matter the mode (audit #26/#27 honesty)
    assert cap["independent_verify"] is False
    assert "none" in cap["enforcement"]
    assert cap["max_posture"] == "SHADOW"


# -- #29 materialization unavailable on approve --------------------------------

def test_approve_of_unmaterializable_decision_reports_honestly():
    """A rate_limit decision (no enforcing actuator) approved through a
    deployment whose adapters cannot execute it reports `compiled: False`
    WITH the capability gap — never a bare silent zero-action approval."""
    from apip.controller.service import Controller
    from types import SimpleNamespace

    # a minimal stand-in with the real (unbound) methods: no adapters
    ctrl = SimpleNamespace(_adapters={}, capability_matrix=lambda: [])
    assert Controller.capability_matrix(ctrl) == []
    dec = decision_from_row({
        "decision_id": "decision--rl", "seq": 1,
        "indicator_id": "indicator--x", "maliciousness": 90,
        "action_safety": 80, "disposition": "PROPOSE_OPERATOR_APPROVAL",
        "action": "rate_limit", "rung": "L2", "scope": "lab",
        "ttl_seconds": 600, "policy_version": "p",
        "policy_content_sha256": "sha", "reason_codes": [],
        "explanation": "x", "content_hash": "h",
    })
    def _variant(base, **overrides):
        row = {("decision_id" if k == "id" else k): v
               for k, v in base.__dict__.items()}
        row.update(overrides)
        return decision_from_row(row)

    mat = Controller.materialization_for(ctrl, dec, "10.0.0.8", "ipv4")
    assert mat["available"] is False
    assert any("rate-limit actuator" in g for g in mat["gaps"])

    # proxy_challenge: the L1 gap is named
    dec_l1 = _variant(dec, action="proxy_challenge", rung="L1")
    mat_l1 = Controller.materialization_for(ctrl, dec_l1, "10.0.0.8", "ipv4")
    assert any("proxy/WAF" in g for g in mat_l1["gaps"])

    # firewall_deny: the L5 gap is named
    dec_l5 = _variant(dec, action="firewall_deny", rung="L5")
    mat_l5 = Controller.materialization_for(ctrl, dec_l5, "10.0.0.8", "ipv4")
    assert any("firewall actuator" in g for g in mat_l5["gaps"])
    assert mat_l5["adapters"] == []


# -- #28 CIDR dead branch --------------------------------------------------------

NOW = "2026-09-06T05:00:00Z"

POLICY = """
policy_version = 'cap-v1'
mode = 'ENFORCE'
scope = 'lab'
[thresholds]
observe_m = 40
fqdn_auto_m = 95
fqdn_auto_s = 90
ip_rate_m = 90
ip_rate_s = 85
ip_deny_m = 98
ip_deny_s = 95
[thresholds.rungs.L4]
m = 95
s = 90
[limits]
max_auto_ttl_seconds = 3600
[authorization]
authorized_prefixes = ['198.51.100.0/24']
authorized_domains = ['operator.test']
[safety]
no_ai_components = true
[replay]
reference_now = '2026-09-06T05:00:00Z'
"""


def _policy():
    from apip.decision.loader import load_policy_text
    reg = SourceRegistry((SourceProfile(
        source_id="feed-a", source_class="curated", independent=True),
        SourceProfile(source_id="feed-b", source_class="curated",
                      independent=True),
        SourceProfile(source_id="sensor-a", source_class="local",
                      independent=True)))
    return load_policy_text(POLICY, source_registry=reg, now_fn=lambda: NOW)


def test_cidr_decision_never_reaches_proposal_path():
    """Audit #28: a CIDR indicator records OBSERVE with the gap named —
    the decision never invites an approval that would compile to zero
    actions."""
    from apip.decision.policy import evaluate
    policy = _policy()
    strong = Indicator(
        id="indicator--cidr", type="cidr", value="198.51.100.0/24",
        sources=("feed-a", "feed-b", "sensor-a"),
        evidence=(
            Evidence(kind="curated_source", source_id="feed-a",
                     source_class="curated", observed_at=NOW,
                     independent=True, detail={}),
            Evidence(kind="curated_source", source_id="feed-b",
                     source_class="curated", observed_at=NOW,
                     independent=True, detail={}),
            Evidence(kind="direct_local_detection", source_id="sensor-a",
                     source_class="local", observed_at=NOW,
                     independent=True, detail={}),
        ))
    d = evaluate(strong, policy)
    assert d.disposition == "OBSERVE"
    assert any(r == "materialization_unavailable:no_supported_adapter"
               for r in d.reason_codes)


# -- #24 observation context -----------------------------------------------------

def test_observation_context_derived_deterministically():
    votes = [
        {"detail": {"client": "ws-a", "protocol_class": "interactive_http"}},
        {"detail": {"client": "ws-a", "protocol_class": "interactive_http"}},
        {"detail": {"client": "ws-b", "protocol_class": "dns"}},
    ]
    ctx = DecisionPipeline._observation_context(votes)
    assert ctx["client"] == "ws-a"          # 2 votes beat 1
    assert ctx["protocol_class"] == "interactive_http"

    # unknown protocol classes fail closed (not carried)
    ctx2 = DecisionPipeline._observation_context(
        [{"detail": {"protocol_class": "mystery"}}])
    assert "protocol_class" not in ctx2

    # empty detail: no context at all
    assert DecisionPipeline._observation_context([]) == {}
    assert DecisionPipeline._observation_context([{"detail": None}]) == {}


def test_l1_gates_reachable_with_derived_context():
    """The audit's core #24 claim: with client+interactive context derived
    server-side, the L1 rung gate is actually reachable (previously the
    pipeline called evaluate() with no context, so L1 could never fire)."""
    from apip.decision.policy import select_rung
    policy = _policy()
    policy = policy.__class__(**{
        **{f.name: getattr(policy, f.name)
           for f in policy.__dataclass_fields__.values()},
        "rung_floors": {**policy.rung_floors, "L1": policy.rung_floors[
            "L4"].__class__(m=50, s=40)},
    })
    ind = Indicator(id="i", type="ipv4", value="198.51.100.7",
                    sources=("feed-a",), evidence=())
    rung, action, reasons, sel, _ = select_rung(
        ind, policy, m=80, s_ctx=70, s_ip=70, behavioral_families=set(),
        external_qualified=True, infra_state="dedicated",
        dedicated_use=True,
        protocol_class="interactive_http", client="ws-a")
    assert rung == "L1" and action == "proxy_challenge"
    assert sel is not None and sel.client == "ws-a"
    assert sel.scope_type == "client_session"


# -- knobs: implement-or-reject ---------------------------------------------------

def test_l1_challenge_budget_knobs_are_rejected_at_load():
    """The challenge-fraction limit paces an actuator that does not exist
    (audit #25); measurement.* feeds the same unimplemented budget. Inert
    security configuration is rejected, not carried."""
    base = {
        "policy_version": "k",
        "mode": "SHADOW",
        "scope": "lab",
        "thresholds": {"observe_m": 40},
        "safety": {"no_ai_components": True},
    }
    bad_limits = dict(base, limits={
        "max_challenged_transaction_fraction_per_hour": 0.5})
    problems = validate_policy(bad_limits)
    assert any("max_challenged_transaction_fraction_per_hour" in p
               for p in problems), problems

    bad_measurement = dict(base, measurement={
        "interactive_transactions_per_hour": 100})
    problems2 = validate_policy(bad_measurement)
    assert any("measurement" in p and "challenge" in p
               for p in problems2), problems2

    # the clean policy still validates
    assert validate_policy(base) == []


def test_legacy_threshold_fields_documented_as_superseded():
    """The legacy fqdn_auto/ip_rate/ip_deny fields remain REQUIRED only for
    reference parity with the differential oracle; the rung floors are the
    product authority. The loader documents this — a policy relying on
    fqdn_auto_m alone (no rung floors) simply gets observe decisions, which
    is the honest behavior (floors absent = nothing above observe)."""
    from apip.decision.loader import load_policy_text
    reg = SourceRegistry((SourceProfile(
        source_id="feed-a", source_class="curated", independent=True),
        SourceProfile(source_id="feed-b", source_class="curated",
                      independent=True),))
    legacy_only = """
policy_version = 'legacy'
mode = 'ENFORCE'
scope = 'lab'
[thresholds]
observe_m = 40
fqdn_auto_m = 10
fqdn_auto_s = 10
ip_rate_m = 10
ip_rate_s = 10
ip_deny_m = 10
ip_deny_s = 10
[limits]
max_auto_ttl_seconds = 3600
[authorization]
authorized_prefixes = ['198.51.100.0/24']
authorized_domains = ['operator.test']
[safety]
no_ai_components = true
[replay]
reference_now = '2026-09-06T05:00:00Z'
"""
    policy = load_policy_text(legacy_only, source_registry=reg,
                              now_fn=lambda: NOW)
    # fqdn_auto_m=10 does NOT promote anything — action selection is the
    # rung floors' job, and none are configured. The indicator is scored
    # high enough to clear observe_m (two independent curated feeds) but
    # no rung floor is configured, so the ceiling is OBSERVE.
    ind = Indicator(id="i", type="fqdn", value="bad.operator.test",
                    sources=("feed-a", "feed-b"),
                    evidence=(Evidence(
                        kind="curated_source", source_id="feed-a",
                        source_class="curated", observed_at=NOW,
                        independent=True, detail={}),
                        Evidence(
                        kind="curated_source", source_id="feed-b",
                        source_class="curated", observed_at=NOW,
                        independent=True, detail={}),))
    d = evaluate(ind, policy)
    assert d.disposition == "OBSERVE" and d.rung == "L0"
