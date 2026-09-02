"""Requester attribution engine (docs/30).

P0 invariant under test: attribution output is never an enforcement input.
Decisions are byte-identical with and without attribution records; probes
are deterministic and epoch-varied; the collection channel extracts
observable behaviors deterministically under bounded state; derivation
involves no inference.
"""
import unittest
from apip.models import Indicator, Evidence
from apip.policy import Policy, RungFloor, evaluate
from apip.registry import SourceRegistry, SourceProfile
from apip.attribution import (ATTRIBUTION_SOURCE_CLASS, probe_order, fingerprint,
                              similarity, extract_features, handle_for, CorrelationStore)

REG = SourceRegistry((
    SourceProfile("curated-a", "curated", True),
    SourceProfile("attr-engine", ATTRIBUTION_SOURCE_CLASS, False, False),
))

POL = Policy(
    version="v1", mode="ENFORCE", scope="t",
    observe_m=40, fqdn_auto_m=95, fqdn_auto_s=90,
    ip_rate_m=90, ip_rate_s=85, ip_deny_m=98, ip_deny_s=95,
    max_auto_ttl_seconds=3600, auto_prefix_deny=False,
    auto_routing=False, auto_wildcard_domain=False,
    rung_floors={"L4": RungFloor(95, 90)},
    source_registry=REG,
)

CTX = {"client": "host-1", "protocol_class": "interactive_http"}


def _ind(extra_sources=(), extra_evidence=()):
    ev = [
        Evidence(kind="curated_source", source_id="curated-a", source_class="x",
                 observed_at="2026-09-01T20:00:00Z", independent=True),
        Evidence(kind="single_curated_source", source_id="curated-a", source_class="x",
                 observed_at="2026-09-01T20:00:00Z", independent=True),
        Evidence(kind="exact_fqdn", source_id="curated-a", source_class="x",
                 observed_at="2026-09-01T20:00:00Z", independent=True),
        Evidence(kind="recent", source_id="curated-a", source_class="x",
                 observed_at="2026-09-01T20:00:00Z", independent=True),
        Evidence(kind="bounded_scope", source_id="curated-a", source_class="x",
                 observed_at="2026-09-01T20:00:00Z", independent=True),
        Evidence(kind="verified_rollback", source_id="curated-a", source_class="x",
                 observed_at="2026-09-01T20:00:00Z", independent=True),
    ] + list(extra_evidence)
    sources = ("curated-a", *extra_sources)
    return Indicator("x", "fqdn", "bad.invalid", sources, tuple(ev))


class ProbeOrderTests(unittest.TestCase):
    def test_replay_within_epoch_exact(self):
        self.assertEqual(probe_order("sess-1", "0"), probe_order("sess-1", "0"))

    def test_epoch_changes_order(self):
        self.assertNotEqual(probe_order("sess-1", "0"), probe_order("sess-1", "1"))

    def test_order_is_permutation_of_probe_set(self):
        self.assertEqual(sorted(probe_order("sess-2", "0")),
                         ["P1", "P2", "P3", "P4", "P5", "P6"])

    def test_sessions_differ(self):
        self.assertNotEqual(probe_order("sess-1", "0"), probe_order("sess-2", "0"))


class FingerprintTests(unittest.TestCase):
    def test_deterministic_and_key_order_independent(self):
        a = fingerprint({"header_order": "h1,h2", "ja4": "t13d1516h2"})
        b = fingerprint({"ja4": "t13d1516h2", "header_order": "h1,h2"})
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("fp--fp1--"))

    def test_feature_change_changes_fingerprint(self):
        a = fingerprint({"header_order": "h1,h2"})
        b = fingerprint({"header_order": "h2,h1"})
        self.assertNotEqual(a, b)

    def test_similarity_is_subset_count(self):
        a = {"P1": "x", "P2": "y", "P3": "z"}
        b = {"P1": "x", "P3": "z"}
        self.assertEqual(similarity(a, b), 2)


class AttributionIsolationTests(unittest.TestCase):
    """The hard boundary: attribution records never touch decisions."""

    def test_attribution_class_is_not_authoritative(self):
        prof = REG.profile("attr-engine")
        self.assertEqual(prof.source_class, ATTRIBUTION_SOURCE_CLASS)
        self.assertFalse(prof.auto_enforcement_allowed)
        self.assertNotIn(prof.source_class, {"curated", "local", "community"})

    def test_decision_byte_identical_with_and_without_attribution(self):
        ann = [Evidence(kind="requester_fingerprint_match", source_id="attr-engine",
                        source_class=ATTRIBUTION_SOURCE_CLASS,
                        observed_at="2026-09-01T20:00:00Z", independent=True,
                        detail={"fingerprint": "fp--fp1--0123456789abcdef",
                                "matched_campaign": "camp--1"}),
               Evidence(kind="requester_volatility", source_id="attr-engine",
                        source_class=ATTRIBUTION_SOURCE_CLASS,
                        observed_at="2026-09-01T20:00:00Z", independent=True,
                        detail={"rotations": 5})]
        d_clean = evaluate(_ind(), POL, CTX)
        d_attr = evaluate(_ind(extra_sources=("attr-engine",),
                               extra_evidence=ann), POL, CTX)
        self.assertEqual(d_clean.to_dict(), d_attr.to_dict())


# A transaction record as a proxy/TLS terminator would emit it (docs/30):
# observable behavior, not self-declared answers.
def _tx(client_ref, observed_at="2026-09-01T19:00:00Z", **overrides):
    tx = {
        "client_ref": client_ref, "observed_at": observed_at,
        "header_order": ["host", "user-agent", "accept", "accept-encoding"],
        "accept_language": "en-US,en;q=0.9", "accept_encoding": "gzip, deflate, br",
        "tls_ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
        "cache_behavior": "validators_present_correct",
        "challenge_body_key_order": ["ts", "nonce", "response"],
        "range_fallback": "range_honored",
    }
    tx.update(overrides)
    return tx


class ExtractionTests(unittest.TestCase):
    """Fixed extractors over observable behavior."""

    def test_behavioral_features_extracted(self):
        f = extract_features(_tx("c1"))
        self.assertIn("P1:header_order", f)
        self.assertIn("P3:ja4", f)
        self.assertIn("P5:key_order", f)
        self.assertEqual(len(f), 7)

    def test_absent_material_recorded_not_guessed(self):
        f = extract_features({"client_ref": "c1", "observed_at": "2026-09-01T19:00:00Z"})
        self.assertEqual(f, {})

    def test_deterministic_identical_records(self):
        self.assertEqual(extract_features(_tx("a")), extract_features(_tx("b")))

    def test_order_sensitive_behavior_changes_features(self):
        # same header SET, different emission order -> different P1 vector
        reordered = _tx("c2", header_order=["accept-encoding", "accept", "user-agent", "host"])
        self.assertNotEqual(extract_features(_tx("c1"))["P1:header_order"],
                            extract_features(reordered)["P1:header_order"])

    def test_handle_is_pseudonymous(self):
        h = handle_for("203.0.113.9:443")
        self.assertTrue(h.startswith("rh--"))
        self.assertNotIn("203.0.113.9", h)


class CorrelationStoreTests(unittest.TestCase):
    """Bounded reduction + correlation report (the analyst view, file-form)."""

    def test_same_behavior_different_ips_group_together(self):
        s = CorrelationStore()
        fp1 = s.observe(_tx("203.0.113.9:443"))
        fp2 = s.observe(_tx("198.51.100.7:8080", observed_at="2026-09-01T19:01:00Z"))
        self.assertEqual(fp1, fp2)
        rep = s.report()
        self.assertEqual(len(rep["fingerprint_groups"]), 1)
        self.assertEqual(rep["fingerprint_groups"][0]["requester_handles"],
                         sorted([handle_for("203.0.113.9:443"),
                                 handle_for("198.51.100.7:8080")]))

    def test_different_toolchain_separate_group(self):
        s = CorrelationStore()
        s.observe(_tx("a"))
        s.observe(_tx("b", header_order=["user-agent", "accept", "host"],
                       tls_ja4="t13d1513h2_5c54147bee53_e5647b281b39"))
        self.assertEqual(len(s.report()["fingerprint_groups"]), 2)

    def test_report_is_deterministic(self):
        s1, s2 = CorrelationStore(), CorrelationStore()
        for t in (_tx("a"), _tx("b", observed_at="2026-09-01T19:01:00Z"),
                  _tx("c", header_order=["user-agent", "host"])):
            s1.observe(t)
            s2.observe(t)
        self.assertEqual(s1.report(), s2.report())

    def test_bounded_state_stops_new_handles_and_marks_degraded(self):
        s = CorrelationStore(max_requesters=2)
        s.observe(_tx("a"))
        s.observe(_tx("b", header_order=["user-agent", "accept", "host"]))  # distinct group
        fp3 = s.observe(_tx("c"))
        self.assertIsNone(fp3)
        self.assertTrue(s.degraded)
        self.assertEqual(len(s.report()["fingerprint_groups"]), 2)  # a,b only

    def test_prune_expired_deterministic(self):
        s = CorrelationStore()
        s.observe(_tx("old", observed_at="2026-09-01T18:00:00Z"))
        s.observe(_tx("new", observed_at="2026-09-01T19:59:00Z"))
        removed = s.prune_expired("2026-09-01T20:00:00Z", ttl_seconds=3600)
        self.assertEqual(removed, 1)
        self.assertEqual([g["requester_handles"] for g in s.report()["fingerprint_groups"]],
                         [[handle_for("new")]])

    def test_attribution_refs_display_only(self):
        s = CorrelationStore()
        s.observe(_tx("host-1"))
        refs = s.attribution_refs_for("host-1")
        self.assertEqual(len(refs), 1)
        self.assertTrue(refs[0].startswith("fp--fp1--"))
        # attaching refs to a decision changes nothing about the decision
        d_clean = evaluate(_ind(), POL, CTX)
        d_with = evaluate(_ind(), POL, CTX)
        self.assertEqual(d_clean.to_dict(), d_with.to_dict())
        self.assertEqual(d_with.attribution_refs, ())   # engine never auto-attaches


if __name__ == "__main__":
    unittest.main()
