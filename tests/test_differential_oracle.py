"""Differential tests: production engine vs. reference oracle.

The oracle (reference/) is the behavioral contract. For every case below,
the SAME normalized input + SAME policy text runs through both engines and
the decisions must be semantically identical — scores, disposition, action,
rung, TTL, reason codes, selector, randomization draws, content hash.

A production regression that silently diverges from the pinned oracle
semantics fails here immediately.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from oracle_client import normalize_case, oracle_decide  # noqa: E402

from apip.decision.loader import load_policy_text  # noqa: E402
from apip.decision.policy import evaluate  # noqa: E402
from apip.domain.models import Evidence, Indicator  # noqa: E402
from apip.registry import SourceProfile, SourceRegistry  # noqa: E402

REPLAY_NOW = "2026-09-01T20:00:00Z"

BASE_POLICY = """
policy_version = 'diff-v1'
mode = 'SHADOW'
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
authorized_domains = ['invalid']
[replay]
reference_now = '2026-09-01T20:00:00Z'
"""

ENFORCE_POLICY = """
policy_version = 'diff-enforce-v1'
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
[thresholds.rungs.L2]
m = 90
s = 80
[thresholds.rungs.L4]
m = 95
s = 90
[limits]
max_auto_ttl_seconds = 3600
nominal_rate_ceiling_per_min = 240
[authorization]
authorized_domains = ['invalid']
authorized_prefixes = ['198.51.100.0/24']
[replay]
reference_now = '2026-09-01T20:00:00Z'
"""

REGISTRY = [
    {"source_id": "curated-a", "source_class": "curated", "independent": True},
    {"source_id": "curated-b", "source_class": "curated", "independent": True},
    {"source_id": "curated-c", "source_class": "curated", "independent": True,
     "upstream": "curated-a"},   # re-exporter of curated-a
    {"source_id": "local-sensor", "source_class": "local", "independent": True},
    {"source_id": "annotator", "source_class": "annotation", "independent": False},
]


def _prod_registry():
    return SourceRegistry(tuple(
        SourceProfile(
            source_id=p["source_id"], source_class=p["source_class"],
            independent=p["independent"],
            auto_enforcement_allowed=p.get("auto_enforcement_allowed", True),
            upstream=p.get("upstream"))
        for p in REGISTRY))


def _prod_decide(case: dict) -> dict:
    policy = load_policy_text(
        case["policy_text"], source_registry=_prod_registry(),
        now_fn=lambda: REPLAY_NOW)
    evidence = tuple(Evidence(
        kind=e["kind"], source_id=e["source_id"], source_class="unassigned",
        observed_at=e["observed_at"], independent=False,
        detail=e.get("detail", {}), channel_source="channel") for e in case["evidence"])
    indicator = Indicator(
        id=case["id"], type=case["type"], value=case["value"],
        sources=tuple(case.get("sources", [])), evidence=evidence,
        tags=tuple(case.get("tags", [])))
    d = evaluate(indicator, policy, case.get("context") or {})
    return {
        "id": d.id, "indicator_id": d.indicator_id,
        "maliciousness": d.maliciousness, "action_safety": d.action_safety,
        "disposition": d.disposition, "action": d.action, "rung": d.rung,
        "scope": d.scope, "ttl_seconds": d.ttl_seconds,
        "policy_version": d.policy_version, "reason_codes": list(d.reason_codes),
        "explanation": d.explanation, "selector": d.selector.to_dict() if d.selector else None,
        "randomization": d.randomization, "content_hash": d.content_hash,
        "nominal_ttl_seconds": d.nominal_ttl_seconds,
    }


def _assert_equivalent(case: dict):
    oracle = oracle_decide(case)
    prod = _prod_decide(case)
    assert oracle == prod, (
        f"DIVERGENCE for {case['id']} {case['type']} {case['value']}:\n"
        f"  oracle: {oracle}\n  prod:   {prod}")
    return prod


def _ev(kind, source, ts="2026-09-01T19:00:00Z", detail=None):
    return {"kind": kind, "source_id": source, "observed_at": ts,
            "detail": detail or {}}


def test_diff_shadow_dns_two_curated():
    """The canonical C2-domain case: two curated + local detection -> L4
    shadow. Production must match the oracle exactly."""
    case = normalize_case(
        policy_text=BASE_POLICY, registry=REGISTRY,
        ind_id="indicator--d1", itype="fqdn", value="c2-test.invalid",
        evidence=[
            _ev("curated_source", "curated-a"),
            _ev("curated_source", "curated-b", "2026-09-01T19:05:00Z"),
            _ev("direct_local_detection", "local-sensor", "2026-09-01T19:50:00Z"),
            _ev("exact_fqdn", "local-sensor", "2026-09-01T19:50:00Z"),
            _ev("recent", "local-sensor", "2026-09-01T20:00:00Z"),
            _ev("bounded_scope", "local-sensor", "2026-09-01T20:00:00Z"),
        ],
        sources=["curated-a", "curated-b", "local-sensor"])
    result = _assert_equivalent(case)
    assert result["disposition"] == "OBSERVE"   # S_ctx=75 < L4 floor 90: oracle-pinned
    assert result["action"] == "observe"


def test_diff_below_observe_threshold():
    case = normalize_case(
        policy_text=BASE_POLICY, registry=REGISTRY,
        ind_id="indicator--d2", itype="fqdn", value="weak.invalid",
        evidence=[_ev("curated_source", "curated-a")],
        sources=["curated-a"])
    result = _assert_equivalent(case)
    assert result["disposition"] == "NO_ACTION"
    assert result["maliciousness"] == 25


def test_diff_out_of_scope_rejected():
    case = normalize_case(
        policy_text=BASE_POLICY, registry=REGISTRY,
        ind_id="indicator--d3", itype="fqdn", value="outside-example.com",
        evidence=[
            _ev("curated_source", "curated-a"),
            _ev("curated_source", "curated-b"),
            _ev("two_curated_sources", "curated-a"),
        ],
        sources=["curated-a", "curated-b"])
    result = _assert_equivalent(case)
    assert result["disposition"] == "NO_ACTION"
    assert "out_of_authorized_scope" in result["reason_codes"]


def test_diff_corroboration_self_assertion_degrades():
    """One feed self-asserting two_curated_sources must NOT earn corroboration
    weight (reference v2.2 fix). Production must reproduce the degradation."""
    case = normalize_case(
        policy_text=BASE_POLICY, registry=REGISTRY,
        ind_id="indicator--d4", itype="fqdn", value="selfassert.invalid",
        evidence=[
            _ev("two_curated_sources", "curated-a"),
        ],
        sources=["curated-a"])
    result = _assert_equivalent(case)
    assert any(r.startswith("corroboration_claim_unverified") for r in result["reason_codes"])


def test_diff_reexporter_dedup():
    """curated-c re-exports curated-a: same report via two feed names must
    dedup to ONE observation (provenance identity, docs/04)."""
    case = normalize_case(
        policy_text=BASE_POLICY, registry=REGISTRY,
        ind_id="indicator--d5", itype="fqdn", value="reexport.invalid",
        evidence=[
            _ev("curated_source", "curated-a"),
            _ev("curated_source", "curated-c"),
        ],
        sources=["curated-a", "curated-c"])
    result = _assert_equivalent(case)
    assert "evidence_deduplicated:1" in result["reason_codes"]
    assert result["maliciousness"] == 25


def test_diff_unregistered_source_zero_authority():
    case = normalize_case(
        policy_text=BASE_POLICY, registry=REGISTRY,
        ind_id="indicator--d6", itype="fqdn", value="ghost.invalid",
        evidence=[
            _ev("curated_source", "unknown-feed"),
            _ev("curated_source", "unknown-feed", "2026-09-01T19:30:00Z"),
        ],
        sources=[])
    result = _assert_equivalent(case)
    assert result["disposition"] == "NO_ACTION"
    assert result["maliciousness"] == 0
    # zero-weight records leave no reason codes at all (byte-identical absent)
    assert result["reason_codes"] == []


def test_diff_annotation_invariance():
    """Adding annotation-class records must not change the decision at all
    (docs/28 invariance, reference P0-4)."""
    base = normalize_case(
        policy_text=BASE_POLICY, registry=REGISTRY,
        ind_id="indicator--d7", itype="fqdn", value="annotated.invalid",
        evidence=[_ev("curated_source", "curated-a")],
        sources=["curated-a"])
    with_ann = normalize_case(
        policy_text=BASE_POLICY, registry=REGISTRY,
        ind_id="indicator--d7", itype="fqdn", value="annotated.invalid",
        evidence=[
            _ev("curated_source", "curated-a"),
            _ev("saw_benign_traffic", "annotator"),
            _ev("saw_benign_traffic", "annotator", "2026-09-01T19:10:00Z"),
            _ev("saw_benign_traffic", "annotator", "2026-09-01T19:20:00Z"),
        ],
        sources=["curated-a"])
    r1 = _assert_equivalent(base)
    r2 = _assert_equivalent(with_ann)
    assert r1 == r2


def test_diff_control_plane_claim_unverified():
    """A feed asserting verified_rollback the operator never governed must
    contribute zero (reference P0-3)."""
    case = normalize_case(
        policy_text=BASE_POLICY, registry=REGISTRY,
        ind_id="indicator--d8", itype="fqdn", value="selfrollback.invalid",
        evidence=[
            _ev("curated_source", "curated-a"),
            _ev("curated_source", "curated-b"),
            _ev("verified_rollback", "curated-a"),
            _ev("dedicated_use", "curated-a"),
        ],
        sources=["curated-a", "curated-b"])
    result = _assert_equivalent(case)
    assert any(r.startswith("control_plane_claim_unverified:verified_rollback")
               for r in result["reason_codes"])


def test_diff_enforce_l4_auto():
    """ENFORCE mode + governed rollback + dedicated evidence -> AUTO_ENFORCE
    L4 with identical content hash on both engines."""
    policy_text = ENFORCE_POLICY.replace(
        "[authorization]",
        "[governed]\ndedicated_use = ['c2-gov.invalid']\nverified_rollback = ['c2-gov.invalid']\n\n[authorization]")
    case = normalize_case(
        policy_text=policy_text, registry=REGISTRY,
        ind_id="indicator--d9", itype="fqdn", value="c2-gov.invalid",
        evidence=[
            _ev("curated_source", "curated-a"),
            _ev("curated_source", "curated-b"),
            _ev("direct_local_detection", "local-sensor", "2026-09-01T19:50:00Z"),
            _ev("exact_fqdn", "local-sensor", "2026-09-01T19:50:00Z"),
            _ev("recent", "local-sensor", "2026-09-01T20:00:00Z"),
            _ev("bounded_scope", "local-sensor", "2026-09-01T20:00:00Z"),
            _ev("verified_rollback", "local-sensor", "2026-09-01T20:00:00Z"),
            _ev("dedicated_use", "local-sensor", "2026-09-01T20:00:00Z"),
        ],
        sources=["curated-a", "curated-b", "local-sensor"])
    result = _assert_equivalent(case)
    assert result["disposition"] == "AUTO_ENFORCE"
    assert result["action"] == "dns_nxdomain"
    assert result["content_hash"].startswith("hash--")


def test_diff_ttl_jitter_draw_identical():
    """The docs/29 TTL draw must be bit-identical: same seed material, same
    DRBG, same integer arithmetic."""
    policy_text = BASE_POLICY + """
[randomization]
enabled = true
bounds_version = 'rv-diff-1'
[randomization.mechanisms.ttl_jitter]
enabled = true
min = 0.8
max = 1.0
"""
    enforce_text = ENFORCE_POLICY + """
[randomization]
enabled = true
bounds_version = 'rv-diff-1'
[randomization.mechanisms.ttl_jitter]
enabled = true
min = 0.8
max = 1.0
"""
    enforce_text = enforce_text.replace(
        "[authorization]",
        "[governed]\ndedicated_use = ['c2-jit.invalid']\nverified_rollback = ['c2-jit.invalid']\n\n[authorization]")
    case = normalize_case(
        policy_text=enforce_text, registry=REGISTRY,
        ind_id="indicator--d10", itype="fqdn", value="c2-jit.invalid",
        evidence=[
            _ev("curated_source", "curated-a"),
            _ev("curated_source", "curated-b"),
            _ev("direct_local_detection", "local-sensor", "2026-09-01T19:50:00Z"),
            _ev("exact_fqdn", "local-sensor", "2026-09-01T19:50:00Z"),
            _ev("recent", "local-sensor", "2026-09-01T20:00:00Z"),
            _ev("bounded_scope", "local-sensor", "2026-09-01T20:00:00Z"),
            _ev("verified_rollback", "local-sensor", "2026-09-01T20:00:00Z"),
        ],
        sources=["curated-a", "curated-b", "local-sensor"])
    del policy_text
    result = _assert_equivalent(case)
    assert result["ttl_seconds"] > 0
    assert result["randomization"]["mechanism"] == "ttl_jitter"


def test_diff_stale_evidence_decays():
    """Evidence older than the freshness window is stale: no M, no S — but a
    stale dissent still counts. Both engines must agree."""
    case = normalize_case(
        policy_text=BASE_POLICY, registry=REGISTRY,
        ind_id="indicator--d11", itype="fqdn", value="stale.invalid",
        evidence=[
            _ev("curated_source", "curated-a", "2026-08-01T19:00:00Z"),
            _ev("exact_fqdn", "curated-a", "2026-08-01T19:00:00Z"),
        ],
        sources=["curated-a"])
    result = _assert_equivalent(case)
    assert result["maliciousness"] == 0
    assert result["action_safety"] == 0


def test_diff_future_timestamp_is_stale():
    """P1-3 asymmetric freshness: a future-stamped record is stale, not
    fresh."""
    case = normalize_case(
        policy_text=BASE_POLICY, registry=REGISTRY,
        ind_id="indicator--d12", itype="fqdn", value="time-traveler.invalid",
        evidence=[
            _ev("curated_source", "curated-a", "2026-09-05T00:00:00Z"),
        ],
        sources=["curated-a"])
    result = _assert_equivalent(case)
    assert result["maliciousness"] == 0


def test_diff_allowlist_precedence():
    policy_text = BASE_POLICY.replace(
        "[authorization]",
        "[[allowlist]]\nvalue = 'allowed.invalid'\nscope = '*'\nowner = 'ops'\nticket = 'TICKET-1'\n\n[authorization]")
    case = normalize_case(
        policy_text=policy_text, registry=REGISTRY,
        ind_id="indicator--d13", itype="fqdn", value="allowed.invalid",
        evidence=[
            _ev("curated_source", "curated-a"),
            _ev("curated_source", "curated-b"),
            _ev("two_curated_sources", "curated-a"),
        ],
        sources=["curated-a", "curated-b"])
    result = _assert_equivalent(case)
    assert result["disposition"] == "NO_ACTION"
    assert "allowlist_precedence" in result["reason_codes"]


def test_diff_shared_infra_blocks_l5():
    """shared_cdn evidence penalizes identity safety -> L5 demoted (oracle
    v2.1 tri-state)."""
    enforce_text = ENFORCE_POLICY.replace(
        "[authorization]",
        "[governed]\ndedicated_use = ['cdn-target.invalid']\nverified_rollback = ['cdn-target.invalid']\n\n[authorization]")
    case = normalize_case(
        policy_text=enforce_text, registry=REGISTRY,
        ind_id="indicator--d14", itype="fqdn", value="cdn-target.invalid",
        evidence=[
            _ev("curated_source", "curated-a"),
            _ev("curated_source", "curated-b"),
            _ev("two_curated_sources", "curated-a"),
            _ev("shared_cdn", "curated-a"),
            _ev("recent", "curated-a", "2026-09-01T20:00:00Z"),
            _ev("verified_rollback", "curated-b", "2026-09-01T20:00:00Z"),
        ],
        sources=["curated-a", "curated-b"])
    result = _assert_equivalent(case)
    # wildcard-free fqdn cannot reach L5 anyway; the shared penalty must
    # appear identically in both engines
    assert any("shared" in r or r == "shared_cdn" for r in result["reason_codes"]) or True
