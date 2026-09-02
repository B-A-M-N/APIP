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
)

CTX = {"client": "host-1", "protocol_class": "interactive_http"}


def ev(kind, source="curated-a", at="2026-09-01T20:00:00Z", **detail):
    return Evidence(kind=kind, source_id=source, source_class="x",
                    observed_at=at, independent=True, detail=detail)


def ind(itype="fqdn", value="bad.invalid", evidence=(), tags=()):
    return Indicator("x", itype, value, tuple({e.source_id for e in evidence}),
                     tuple(evidence), tuple(tags))


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
        i = ind(evidence=[ev("curated_source", source="unknown-feed")])
        d = evaluate(i, POL, CTX)
        self.assertEqual(d.disposition, "NO_ACTION")
        self.assertIn("unweighted:unregistered:curated_source", d.reason_codes)

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
    """P0: scope evaluated, allowlist executable."""

    def test_out_of_scope_hard_rejected(self):
        pol = Policy(**{**POL.__dict__,
                        "authorized_prefixes": ("203.0.113.0/24",)})
        i = ind(itype="ipv4", value="198.51.100.44", evidence=IP_DEDICATED)
        d = evaluate(i, pol, CTX)
        self.assertEqual(d.disposition, "NO_ACTION")
        self.assertIn("out_of_authorized_scope", d.reason_codes)

    def test_in_scope_allowed(self):
        pol = Policy(**{**POL.__dict__,
                        "authorized_prefixes": ("198.51.100.0/24",)})
        i = ind(itype="ipv4", value="198.51.100.44", evidence=IP_DEDICATED)
        d = evaluate(i, pol, CTX)
        self.assertNotEqual(d.disposition, "NO_ACTION")

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
