import unittest
from apip.models import Indicator, Evidence
from apip.policy import Policy, RungFloor, AllowlistEntry, evaluate
from apip.registry import SourceRegistry, SourceProfile
from apip.scoring import EvidenceTable, DEFAULT_WEIGHTS
from datetime import datetime, timedelta, timezone

NOW = datetime(2026, 9, 1, 20, 0, 0, tzinfo=timezone.utc)

def recency(ts: str) -> str:
    if not ts:
        return "stale"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return "stale"
    return "fresh" if (NOW - dt) <= timedelta(hours=6) else "stale"

REG = SourceRegistry((
    SourceProfile("curated-a", "curated", True),
    SourceProfile("curated-b", "curated", True),
    SourceProfile("curated-c", "curated", True),
    SourceProfile("local-behavioral", "local", True),
    SourceProfile("local-sensor", "local", True),
    SourceProfile("ai-note", "annotation", False, False),
    SourceProfile("random-feed", "unregistered", False, False),
))

POL = Policy(
    version="v1", mode="ENFORCE", scope="t",
    observe_m=40, fqdn_auto_m=95, fqdn_auto_s=90,
    ip_rate_m=90, ip_rate_s=85, ip_deny_m=98, ip_deny_s=95,
    max_auto_ttl_seconds=3600, auto_prefix_deny=False,
    auto_routing=False, auto_wildcard_domain=False,
    rung_floors={
        "L1": RungFloor(85, 75),
        "L2": RungFloor(90, 80),
        "L4": RungFloor(95, 90),
        "L5": RungFloor(98, 95),
    },
    source_registry=REG,
    classify_recency=recency,
    # audit P0-3: control-plane facts (dedicated_use / verified_rollback) are
    # SERVER-certified, not feed-asserted. These tests exercise the rung/
    # deny mechanics with the test targets declared governed infrastructure —
    # the honest way for a test policy to reach the ladder given its local
    # fixtures (which the new model no longer lets a feed self-grant).
    governed_dedicated_use=("198.51.100.44", "203.0.113.2"),
    governed_verified_rollback=(
        "bad.invalid", "198.51.100.44", "203.0.113.2",
        "c2-demo.invalid", "c2-on-cdn-demo.invalid",
    ),
)

CTX = {"client": "host-1", "protocol_class": "interactive_http"}


def ev(kind, source="curated-a", at="2026-09-01T20:00:00Z", **detail):
    return Evidence(kind=kind, source_id=source, source_class="x",
                    observed_at=at, independent=True, detail=detail)


def ind(itype="fqdn", value="bad.invalid", evidence=(), tags=()):
    return Indicator("x", itype, value, tuple({e.source_id for e in evidence}),
                     tuple(evidence), tuple(tags))


def _emergency(mode):
    """POL variant with a specific runtime mode (ENFORCE/EMERGENCY/SHADOW)."""
    return Policy(**{**POL.__dict__, "mode": mode})


# --- reusable evidence sets -------------------------------------------------
FQDN_L4 = [
    ev("curated_source", "curated-a"), ev("curated_source", "curated-b"),
    ev("direct_local_detection", "local-sensor"),
    ev("exact_fqdn", "local-sensor"), ev("recent", "local-sensor"),
    ev("bounded_scope", "local-sensor"), ev("verified_rollback", "local-sensor"),
]
IP_DEDICATED = [
    ev("curated_source", "curated-a"), ev("curated_source", "curated-b"),
    ev("direct_local_detection", "local-sensor"),
    ev("exact_ip", "local-sensor"), ev("dedicated_use", "local-sensor"),
    ev("recent", "local-sensor"), ev("verified_rollback", "local-sensor"),
]

class ScoringAuthorityTests(unittest.TestCase):
    """P0: evidence carries facts, policy owns all scoring."""

    def test_client_supplied_points_are_ignored(self):
        # even if a payload smuggles points_m/points_s/origin/independent,
        # the decision is identical to the same record without them.
        clean = ind(evidence=[ev("curated_source")])
        poisoned = ind(evidence=[Evidence(
            kind="curated_source", source_id="curated-a", source_class="x",
            observed_at="2026-09-01T20:00:00Z", independent=True,
            detail={"points_m": 100, "points_s": 100, "origin": "local_behavioral",
                    "family": "beacon_periodicity"})])
        d1 = evaluate(clean, POL, CTX)
        d2 = evaluate(poisoned, POL, CTX)
        self.assertEqual(d1.maliciousness, d2.maliciousness)
        self.assertEqual(d1.rung, d2.rung)
        self.assertEqual(d1.id, d2.id)

    def test_unknown_source_contributes_nothing(self):
        # P0-1 (audit): an UNREGISTERED source is non-authoritative. It must
        # contribute exactly zero AND produce no reason code — a decision
        # with unknown-source evidence must be byte-identical to one with no
        # evidence at all (same invariant as annotation/attribution). The
        # old assertion expected `unweighted:unregistered:kind`, i.e. the
        # pre-fix behavior where unknown sources still entered the scorer and
        # touched the reason set.
        i = ind(evidence=[ev("curated_source", source="unknown-feed")])
        d = evaluate(i, POL, CTX)
        self.assertEqual(d.disposition, "NO_ACTION")
        self.assertEqual(d.maliciousness, 0)
        self.assertNotIn("unweighted:unregistered:curated_source", d.reason_codes)
        self.assertNotIn("unqualified_evidence_present", d.reason_codes)

    def test_unknown_source_matches_bare_evidence(self):
        # The byte-identical invariant: adding unregistered/annotation/
        # attribution records must not change the decision bytes vs. the
        # decision-bearing subset alone.
        bare = ind(evidence=[])
        full = ind(evidence=[
            ev("curated_source", source="unknown-feed"),
            ev("recent", source="unknown-feed"),
            ev("curated_source", source="annotation-1"),
            ev("curated_source", source="attribution-1"),
        ])
        self.assertEqual(evaluate(bare, POL, CTX).to_dict(),
                         evaluate(full, POL, CTX).to_dict())

    def test_provenance_violation_local_kind_from_feed(self):
        # a feed cannot claim behavioral kinds; rejected server-side
        i = ind(evidence=[ev("behavioral_beacon_periodicity", source="curated-a")])
        d = evaluate(i, POL, CTX)
        self.assertTrue(any(r.startswith("provenance_violation") for r in d.reason_codes))

    def test_stale_evidence_loses_m(self):
        old = ind(evidence=[ev("curated_source", at="2026-08-01T20:00:00Z"),
                            ev("recent", at="2026-09-01T20:00:00Z")])
        d = evaluate(old, POL, CTX)
        self.assertLess(d.maliciousness, 40)  # below observe floor -> NO_ACTION


class CorroborationMatrixTests(unittest.TestCase):
    """P0: the normative lattice matrix, each cell explicit."""

    def behav(self, fams):
        return [ev(f"behavioral_{f}", source="local-behavioral")
                for f in fams] + [ev("exact_fqdn", "local-sensor"),
                                  ev("recent", "local-sensor"),
                                  ev("verified_rollback", "local-sensor")]

    def test_0fam_external_below_deny(self):
        i = ind(evidence=FQDN_L4)  # pure external+local-detection, 0 behavioral fams
        d = evaluate(i, POL, CTX)
        self.assertEqual(d.rung, "L4")  # classic v1 path unaffected

    def test_1fam_plus_external_no_deny(self):
        e = FQDN_L4 + self.behav(["dga_likelihood"])[:1]
        d = evaluate(ind(evidence=e), POL, CTX)
        self.assertNotEqual(d.rung, "L4")
        self.assertIn("behavioral_corroboration_insufficient", d.reason_codes)

    def test_2fam_plus_external_no_deny(self):
        e = FQDN_L4 + [ev(f"behavioral_{f}", source="local-behavioral")
                       for f in ("dga_likelihood", "first_seen_novelty")]
        d = evaluate(ind(evidence=e), POL, CTX)
        self.assertNotEqual(d.rung, "L4")
        self.assertIn("behavioral_corroboration_insufficient", d.reason_codes)

    def test_3fam_plus_external_deny_allowed(self):
        e = FQDN_L4 + [ev(f"behavioral_{f}", source="local-behavioral")
                       for f in ("dga_likelihood", "first_seen_novelty", "beacon_periodicity")]
        d = evaluate(ind(evidence=e), POL, CTX)
        self.assertEqual(d.rung, "L4")

    def test_3fam_no_external_no_deny(self):
        e = self.behav(["dga_likelihood", "first_seen_novelty", "beacon_periodicity"])
        d = evaluate(ind(evidence=e), POL, CTX)
        self.assertNotEqual(d.rung, "L4")
        self.assertIn("behavioral_deny_needs_external_corroboration", d.reason_codes)

    def test_3fam_unregistered_source_not_qualified(self):
        # families from local + a "curated" record from an UNREGISTERED
        # source does not qualify as external corroboration
        e = self.behav(["dga_likelihood", "first_seen_novelty", "beacon_periodicity"])
        e.append(ev("curated_source", source="random-feed"))
        d = evaluate(ind(evidence=e), POL, CTX)
        self.assertNotEqual(d.rung, "L4")

    def test_annotation_source_never_qualifies(self):
        # an AI/annotation-origin source can never satisfy external corroboration
        e = self.behav(["dga_likelihood", "first_seen_novelty", "beacon_periodicity"])
        e.append(ev("curated_source", source="ai-note"))
        d = evaluate(ind(evidence=e), POL, CTX)
        self.assertNotEqual(d.rung, "L4")
        self.assertIn("behavioral_deny_needs_external_corroboration", d.reason_codes)


class AnnotationInvarianceTests(unittest.TestCase):
    """P0 (docs/28 v2.1): AI-derived output is non-authoritative. Decisions
    must be byte-identical with and without annotation-class records, under
    every stage of the evidence — weak, deny-strength, and boundary cases."""

    def _eval_with(self, evidence, ctx=CTX):
        return evaluate(ind(evidence=evidence), POL, ctx)

    def test_annotation_records_never_change_a_decision(self):
        ann = [ev("curated_source", source="ai-note"),
               ev("behavioral_beacon_periodicity", source="ai-note"),
               ev("shared_cloud", source="ai-note"),
               ev("dedicated_use", source="ai-note")]
        cases = [
            [ev("curated_source")],                                   # weak
            list(FQDN_L4),                                            # deny-strength
            list(IP_DEDICATED),                                       # L5-strength
            [ev("curated_source"), ev("prior_false_positive")],       # negative weights
        ]
        for base in cases:
            with self.subTest(kinds=[x.kind for x in base]):
                d_clean = self._eval_with(base)
                d_ann = self._eval_with(base + ann)
                self.assertEqual(d_clean.to_dict(), d_ann.to_dict())

    def test_payload_score_smuggle_is_inert(self):
        # points/origin/family/independence/source_class in a payload are facts
        # the server re-derives or ignores; the decision must not move.
        clean = ind(evidence=[ev("curated_source")])
        smuggled = ind(evidence=[Evidence(
            kind="curated_source", source_id="curated-a", source_class="local",
            observed_at="2026-09-01T20:00:00Z", independent=True,
            detail={"points_m": 100, "points_s": 100, "points_s_ctx": 100,
                    "points_s_ip": 100, "origin": "local_behavioral",
                    "family": "beacon_periodicity", "independent": True,
                    "source_class": "local", "corroboration_group": "z"})])
        d1 = evaluate(clean, POL, CTX)
        d2 = evaluate(smuggled, POL, CTX)
        self.assertEqual(d1.to_dict(), d2.to_dict())

    def test_table_driven_non_authoritative_invariance(self):
        """P0-1/P0-4 (audit): a record from ANY non-authoritative class
        (annotation / attribution / unregistered) and ANY evidence kind must
        leave every decision-bearing surface unchanged. Table-driven over the
        full kind universe, not just `curated_source` — that narrow test is
        exactly why the original `"any"`-fallback leak escaped."""
        from apip.scoring import DEFAULT_WEIGHTS
        authoritative = [ev("curated_source"), ev("curated_source", "curated-b"),
                         ev("direct_local_detection", "local-sensor"),
                         ev("exact_ip", "local-sensor"), ev("dedicated_use", "local-sensor"),
                         ev("recent", "local-sensor"), ev("verified_rollback", "local-sensor")]
        base = ind(itype="ipv4", value="198.51.100.44", evidence=authoritative)
        base_d = evaluate(base, POL, CTX)
        all_kinds = sorted({k for (_c, k) in DEFAULT_WEIGHTS})
        # every kind, from every non-authoritative source class
        for cls in ("annotation", "attribution", "unregistered"):
            for kind in all_kinds:
                src = {"annotation": "ai-note",
                       "attribution": "attr-1",
                       "unregistered": "unreg-1"}[cls]
                padded = ind(itype="ipv4", value="198.51.100.44",
                             evidence=authoritative + [ev(kind, source=src)])
                d = evaluate(padded, POL, CTX)
                with self.subTest(cls=cls, kind=kind):
                    self.assertEqual(base_d.to_dict(), d.to_dict())

    def test_annotation_volume_and_order_cap_invariant(self):
        """P0-4 (audit): annotation/attribution/unregistered records must have
        ZERO effect on the decision even at arbitrary cardinality, ordering,
        duplication, and under a tiny evidence cap. A flood of such records
        previously counted against the docs/23 envelope and could truncate
        genuine evidence (`evidence_envelope_truncated`) — a decision-path
        leak. With the fix, they are stripped BEFORE the cap."""
        authoritative = [ev("curated_source"), ev("curated_source", "curated-b"),
                         ev("direct_local_detection", "local-sensor"),
                         ev("exact_ip", "local-sensor"), ev("dedicated_use", "local-sensor"),
                         ev("recent", "local-sensor"), ev("verified_rollback", "local-sensor")]
        ann_kinds = ["curated_source", "recent", "exact_ip", "bounded_scope",
                     "verified_rollback", "dedicated_use", "exactness"]
        noise = [ev(k, source=("ai-note" if i % 2 == 0 else "unreg-9"))
                 for i, k in enumerate(ann_kinds * 40)]   # 280 records, well over cap
        # tiny cap forces the pre-fix envelope-truncation interaction
        cappol = Policy(**{**POL.__dict__, "max_evidence_per_indicator": 8})
        variants = {
            "prepend":  noise + authoritative,
            "append":   authoritative + noise,
            "interleave": [x for pair in zip(noise, authoritative) for x in pair],
            "duplicated_noise": authoritative + noise * 2,
        }
        base = ind(itype="ipv4", value="198.51.100.44", evidence=authoritative)
        base_d = evaluate(base, cappol, CTX)
        for name, evidence in variants.items():
            with self.subTest(variant=name):
                d = evaluate(ind(itype="ipv4", value="198.51.100.44",
                                 evidence=evidence), cappol, CTX)
                self.assertEqual(base_d.to_dict(), d.to_dict())


class L5InfrastructureTriStateTests(unittest.TestCase):
    """P0: unknown infrastructure must not inherit dedicated privileges."""

    def test_unknown_ip_cannot_L5(self):
        # no shared flag, NO dedicated-use evidence -> demoted
        e = [ev("curated_source", "curated-a"), ev("curated_source", "curated-b"),
             ev("direct_local_detection", "local-sensor"),
             ev("exact_ip", "local-sensor"), ev("recent", "local-sensor"),
             ev("verified_rollback", "local-sensor")]
        d = evaluate(ind(itype="ipv4", value="198.51.100.44", evidence=e), POL, CTX)
        self.assertNotEqual(d.rung, "L5")
        self.assertIn("demoted_unknown_infra", d.reason_codes)

    def test_shared_ip_cannot_L5(self):
        e = IP_DEDICATED + [ev("shared_cloud", "curated-a")]
        d = evaluate(ind(itype="ipv4", value="203.0.113.2", evidence=e), POL, CTX)
        self.assertNotEqual(d.rung, "L5")
        self.assertIn("demoted_shared_infra", d.reason_codes)

    def test_dedicated_ip_reaches_L5(self):
        d = evaluate(ind(itype="ipv4", value="198.51.100.44", evidence=IP_DEDICATED), POL, CTX)
        self.assertEqual(d.rung, "L5")

    def test_shared_fqdn_still_L4(self):
        e = FQDN_L4 + [ev("shared_cloud", "curated-a")]
        d = evaluate(ind(evidence=e), POL, CTX)
        self.assertEqual(d.rung, "L4")
        self.assertEqual(d.action, "dns_nxdomain")


class StaleSafetyFactValidityTests(unittest.TestCase):
    """P1-4 (audit): 'an expired dedicated_use/rollback/scope fact may
    continue enabling stronger action classes.' Every safety-bearing fact
    has an explicit validity policy: stale evidence contributes zero
    action-safety AND does not set has_dedicated, so it can never keep
    lifting the rung once its supporting record has gone stale."""

    STALE = "2026-09-01T00:00:00Z"          # 20h before NOW: stale
    FRESH = "2026-09-01T20:00:00Z"          # == NOW: fresh (fixture default)

    def test_stale_dedicated_use_does_not_enable_L5(self):
        # M stays high (curated_source/detection fresh), but ONLY the
        # dedicated_use record is stale -> infra is unknown, not dedicated.
        e = [ev("curated_source", "curated-a"), ev("curated_source", "curated-b"),
             ev("direct_local_detection", "local-sensor"),
             ev("exact_ip", "local-sensor"), ev("recent", "local-sensor"),
             ev("verified_rollback", "local-sensor"),
             ev("dedicated_use", "local-sensor", at=self.STALE)]   # <-- stale
        d = evaluate(ind(itype="ipv4", value="198.51.100.44", evidence=e), POL, CTX)
        self.assertNotEqual(d.rung, "L5")
        self.assertIn("demoted_unknown_infra", d.reason_codes)

    def test_stale_control_plane_fact_drops_safety_and_has_dedicated(self):
        # score-level isolation via score_parts with the server having
        # DERIVED the control-plane kind (governed target). The FRESH record
        # contributes S and sets has_dedicated; the STALE one contributes
        # zero safety and leaves has_dedicated=False (P1-4).
        from apip.scoring import score_parts
        fresh = (Evidence("dedicated_use", "curated-a", "curated",
                          self.FRESH, True),)
        stale = (Evidence("dedicated_use", "curated-a", "curated",
                          self.STALE, True),)
        derived = frozenset({"dedicated_use", "dedicated_use_provenance"})
        mf, _, sf_s, sf_ip, has_ded_f, _, _ = score_parts(
            Indicator("f", "ipv4", "198.51.100.44", (), fresh),
            EvidenceTable(DEFAULT_WEIGHTS), recency, REG, derived)
        ms, _, ss_s, ss_ip, has_ded_s, _, _ = score_parts(
            Indicator("s", "ipv4", "198.51.100.44", (), stale),
            EvidenceTable(DEFAULT_WEIGHTS), recency, REG, derived)
        # dedicated_use weight is (0,25,25): fresh keeps it...
        self.assertEqual(ss_ip, 0)           # stale -> zero safety (P1-4)
        self.assertEqual(sf_ip, 25)          # fresh -> full safety (control)
        self.assertFalse(has_ded_s)          # stale -> no dedicated privilege
        self.assertTrue(has_ded_f)           # fresh -> privilege

    def test_fresh_control_plane_fact_preserves_safety(self):
        # the fresh, server-derived control-plane path retains its safety
        # (already exercised end-to-end by test_dedicated_ip_reaches_L5).
        from apip.scoring import score_parts
        fresh = (Evidence("verified_rollback", "curated-a", "curated",
                          self.FRESH, True),)
        m, _, s_ctx, s_ip, _, _, _ = score_parts(
            Indicator("a", "ipv4", "198.51.100.44", (), fresh),
            EvidenceTable(DEFAULT_WEIGHTS), recency, REG,
            frozenset({"verified_rollback"}))
        self.assertEqual((s_ctx, s_ip), (15, 15))


class EmergencyModeTests(unittest.TestCase):
    """P1-7 (audit): EMERGENCY was a loosely defined fall-through — it fell
    into the generic else and silently degraded to SHADOW_ACTION. It is now an
    EXPLICIT, operator-invoked mode: every actionable finding is escalated for
    explicit human approval (PROPOSE_OPERATOR_APPROVAL, tagged emergency_mode),
    never auto-enforced and never silently shadowed — matching README/"tighter
    thresholds and explicit approval requirements; never automatically
    entered" and docs/20 (emergency actions prominent & distinguishable)."""

    def test_emergency_escalates_for_approval_never_auto_or_shadow(self):
        # the L5 finding ENFORCE would auto-deny becomes an APPROVAL-GATED
        # emergency action — identical rung/action, but human approval forced.
        d_enf = evaluate(ind(itype="ipv4", value="198.51.100.44",
                             evidence=IP_DEDICATED), _emergency("ENFORCE"), CTX)
        d_em = evaluate(ind(itype="ipv4", value="198.51.100.44",
                            evidence=IP_DEDICATED), _emergency("EMERGENCY"), CTX)
        # same concrete action, not shadowed, not auto-enforced
        self.assertEqual(d_em.rung, "L5")
        self.assertEqual(d_em.action, d_enf.action)
        self.assertEqual(d_em.disposition, "PROPOSE_OPERATOR_APPROVAL")
        self.assertNotEqual(d_em.disposition, "SHADOW_ACTION")
        self.assertNotEqual(d_em.disposition, "AUTO_ENFORCE")
        self.assertTrue(any("emergency_mode" in r for r in d_em.reason_codes))

    def test_emergency_below_rung_floors_still_observes(self):
        # below observe_m -> NO_ACTION (mode-independent); between observe_m
        # and the rung floors -> OBSERVE, not a forced approval.
        weak = (ev("curated_source", "curated-a"),)          # M=25 < observe_m
        d_no = evaluate(ind(evidence=weak), _emergency("EMERGENCY"), CTX)
        self.assertEqual(d_no.disposition, "NO_ACTION")
        medium = (ev("curated_source", "curated-a"),
                  ev("direct_local_detection", "local-sensor"))   # M=60
        d_obs = evaluate(ind(evidence=medium), _emergency("EMERGENCY"), CTX)
        self.assertEqual(d_obs.disposition, "OBSERVE")


class ServerDerivedControlPlaneTests(unittest.TestCase):
    """P0-3 (audit): 'action-safety facts are attacker/feed-assertable.'

    `bounded_scope`, `verified_rollback`, `exactness`, `dedicated_use`,
    `recent` are derived CONTROL-PLANE facts. A feed may not assert them; they
    contribute only when the server derives them (scope / governed registry /
    freshness clock). A compromised registered feed asserting these on a
    value the operator has NOT governed must contribute ZERO — it can never
    inflate S to reach a higher interdiction rung."""

    def test_feed_asserted_dedicated_on_ungoverned_ip_is_zeroed(self):
        # dedicated_use asserted by a feed, but 203.0.113.99 is NOT in
        # POL.governed_dedicated_use (only 198.51.100.44, 203.0.113.2 are).
        e = [ev("curated_source", "curated-a"),
             ev("exact_ip", "local-sensor"),
             ev("recent", "local-sensor"),
             ev("bounded_scope", "local-sensor"),
             ev("verified_rollback", "local-sensor"),
             ev("dedicated_use", "local-sensor")]
        d = evaluate(ind(itype="ipv4", value="203.0.113.99", evidence=e), POL, CTX)
        self.assertNotEqual(d.rung, "L5")
        self.assertTrue(any(r.startswith("control_plane_claim_unverified:dedicated_use")
                            for r in d.reason_codes))

    def test_feed_asserted_verified_rollback_on_ungoverned_is_zeroed(self):
        # a feed asserts recent+bounded_scope+verified_rollback on a value
        # never governed: the rollback claim (and any L5/L4 enablement from
        # it) must not materialize.
        e = [ev("curated_source", "curated-a"), ev("curated_source", "curated-b"),
             ev("direct_local_detection", "local-sensor"),
             ev("exact_ip", "local-sensor"),
             ev("recent", "local-sensor"),
             ev("bounded_scope", "local-sensor"),
             ev("verified_rollback", "local-sensor")]
        d = evaluate(ind(itype="ipv4", value="203.0.113.200", evidence=e), POL, CTX)
        self.assertTrue(any(r.startswith("control_plane_claim_unverified:verified_rollback")
                            for r in d.reason_codes))

    def test_governed_verified_rollback_serves_as_derived_fact(self):
        # c2-demo.invalid is in POL.governed_verified_rollback, so the same
        # stack that fails above legitimately reaches L4.
        e = FQDN_L4  # includes verified_rollback from local-sensor
        d = evaluate(ind(evidence=e), POL, CTX)  # bad.invalid is governed
        self.assertEqual(d.rung, "L4")
        self.assertFalse(any(r.startswith("control_plane_claim_unverified")
                             for r in d.reason_codes))

    def test_ungoverned_default_policy_blocks_all_control_plane_claims(self):
        # a Policy with NO governed registry (the shipped default) can never
        # let a feed self-grant dedicated_use/verified_rollback.
        bare = Policy(**{**POL.__dict__, "governed_dedicated_use": (),
                         "governed_verified_rollback": ()})
        e = IP_DEDICATED  # carries dedicated_use + verified_rollback assertions
        d = evaluate(ind(itype="ipv4", value="198.51.100.44", evidence=e), bare, CTX)
        self.assertNotEqual(d.rung, "L5")
        self.assertTrue(any(r.startswith("control_plane_claim_unverified")
                            for r in d.reason_codes))


class TypedSelectorTests(unittest.TestCase):
    """P0: context actions carry typed selectors; no global forms."""

    def test_L2_without_client_never_emits_destination_global(self):
        d = evaluate(ind(evidence=FQDN_L4), POL, context={"protocol_class": "interactive_http"})
        self.assertNotEqual(d.rung, "L2")
        self.assertTrue(any("l2_requires_pair_selector" in r for r in d.reason_codes))

    def test_L2_with_client_carries_pair_selector(self):
        # IP + unknown infra: L5 is gated out, so L2 is the top reachable
        # rung — and it must carry a client/destination PAIR selector.
        e = [ev("curated_source", "curated-a"), ev("curated_source", "curated-b"),
             ev("direct_local_detection", "local-sensor"),
             ev("exact_ip", "local-sensor"), ev("recent", "local-sensor"),
             ev("bounded_scope", "local-sensor"), ev("verified_rollback", "local-sensor")]
        d = evaluate(ind(itype="ipv4", value="198.51.100.44", evidence=e), POL,
                     context={"client": "host-9", "protocol_class": "interactive_http"})
        self.assertEqual(d.rung, "L2")
        self.assertEqual(d.selector.scope_type, "client_destination_pair")
        self.assertEqual(d.selector.client, "host-9")

    def test_L1_never_non_interactive(self):
        for proto in ("smtp", "dns", "ics", None):
            d = evaluate(ind(evidence=FQDN_L4), POL,
                         context={"client": "host-9", "protocol_class": proto})
            self.assertNotEqual(d.rung, "L1")
            self.assertTrue(any("l1_requires_interactive_protocol" in r for r in d.reason_codes))


class AuthorizationTests(unittest.TestCase):
    """P0: scope evaluated, allowlist executable. v2.3 (audit P1-1): declaring
    a boundary switches the policy OUT of reference_unrestricted; the loader
    does this for TOML policies, and direct constructions here say so too."""

    def test_out_of_scope_hard_rejected(self):
        pol = Policy(**{**POL.__dict__,
                        "authorized_prefixes": ("203.0.113.0/24",),
                        "reference_unrestricted": False})
        i = ind(itype="ipv4", value="198.51.100.44", evidence=IP_DEDICATED)
        d = evaluate(i, pol, CTX)
        self.assertEqual(d.disposition, "NO_ACTION")
        self.assertIn("out_of_authorized_scope", d.reason_codes)

    def test_in_scope_allowed(self):
        pol = Policy(**{**POL.__dict__,
                        "authorized_prefixes": ("198.51.100.0/24",),
                        "reference_unrestricted": False})
        i = ind(itype="ipv4", value="198.51.100.44", evidence=IP_DEDICATED)
        d = evaluate(i, pol, CTX)
        self.assertNotEqual(d.disposition, "NO_ACTION")

    def test_out_of_scope_fails_closed_for_domains(self):
        # v2.3 (audit P1-1): with a boundary declared, a non-IP target is
        # authorized ONLY under an explicit authorized_domains scope — it is
        # never authorized by 'IP boundary does not apply'.
        pol = Policy(**{**POL.__dict__,
                        "authorized_prefixes": ("198.51.100.0/24",),
                        "reference_unrestricted": False})
        d = evaluate(ind(evidence=FQDN_L4), pol, CTX)  # bad.invalid
        self.assertEqual(d.disposition, "NO_ACTION")
        self.assertIn("out_of_authorized_scope", d.reason_codes)

    def test_domain_in_scope_matches_suffix(self):
        pol = Policy(**{**POL.__dict__,
                        "authorized_domains": ("example.com",),
                        "reference_unrestricted": False})
        d = evaluate(ind(evidence=FQDN_L4), pol, CTX)  # bad.invalid: not under example.com
        self.assertEqual(d.disposition, "NO_ACTION")
        in_scope = ind(value="sub.example.com", evidence=FQDN_L4)
        d2 = evaluate(in_scope, pol, CTX)
        self.assertNotEqual(d2.disposition, "NO_ACTION")

    def test_allowlist_suppresses_any_action(self):
        pol = Policy(**{**POL.__dict__,
                        "allowlist": (AllowlistEntry(value="bad.invalid", scope="t",
                                                     owner="ops", ticket="T-1"),)})
        d = evaluate(ind(evidence=FQDN_L4), pol, CTX)
        self.assertEqual(d.disposition, "NO_ACTION")
        self.assertIn("allowlist_hit:bad.invalid", d.reason_codes)


class HardRuleTests(unittest.TestCase):
    def test_prefix_never_auto_enforces(self):
        d = evaluate(ind(itype="cidr", value="203.0.113.0/24",
                         evidence=FQDN_L4), POL, CTX)
        self.assertEqual(d.disposition, "PROPOSE_OPERATOR_APPROVAL")
        self.assertIn("prefix_requires_approval", d.reason_codes)

    def test_wildcard_never_auto_enforces(self):
        d = evaluate(ind(value="*.bad.invalid", evidence=FQDN_L4), POL, CTX)
        self.assertEqual(d.disposition, "PROPOSE_OPERATOR_APPROVAL")


if __name__ == "__main__":
    unittest.main()
