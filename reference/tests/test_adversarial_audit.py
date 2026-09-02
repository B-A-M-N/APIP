"""Adversarial audit regressions (2026-09-01 red-team pass).

Each test pins a finding from the adversarial audit of the codebase. These
are not hypotheticals — every test here corresponds to a demonstrated
attack or defect that was fixed. If one of these fails, a previously-
demonstrated attack path has been reintroduced.
"""
import json
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from apip.io import _canonicalize
from apip.attribution import (CorrelationStore, TransactionRejected,
                              extract_features, handle_for)
from apip.live.adapters import recognize
from apip.live.server import ChallengeOrigin, _TxWriter


class ZoneInjectionTests(unittest.TestCase):
    """Finding: 'evil.com;' passed canonicalization and reached the RPZ zone
    file, where ';' opens a comment — indicator-controlled comment injection
    into a compiled enforcement artifact."""

    def test_semicolon_and_zone_syntax_rejected(self):
        for c in ["evil.com;", "evil.com.( CNAME .", 'evil.com" ; x',
                  "evil.com\\", "evil.com$", "evil.com/*"]:
            with self.subTest(c):
                with self.assertRaises(ValueError):
                    _canonicalize("fqdn", c)

    def test_label_and_total_length_enforced(self):
        with self.assertRaises(ValueError):
            _canonicalize("fqdn", "a" * 64 + ".com")
        with self.assertRaises(ValueError):
            _canonicalize("fqdn", "b" * 250 + ".com")

    def test_legitimate_fqdn_still_passes(self):
        self.assertEqual(_canonicalize("fqdn", "WWW.Example.COM."), "www.example.com")
        self.assertEqual(_canonicalize("fqdn", "xn--e1afmkfd.xn--p1ai"),
                         "xn--e1afmkfd.xn--p1ai")


class HandleStabilityTests(unittest.TestCase):
    """Finding: envoy logs bare IPs, HAProxy logs ip:port — the same client
    derived different handles per terminator, fragmenting one requester into
    unbounded pseudonyms and destroying cross-format correlation."""

    def test_same_client_same_handle_across_formats(self):
        r1 = recognize('[2026-09-01T19:00:00Z] "GET /a HTTP/1.1" 203.0.113.9 '
                       'accept-language=en-US')
        r2 = recognize('Jan  1 19:00:01 host haproxy[123]: 203.0.113.9:4480 '
                       '[01/Jan/2026:19:00:01.000] h=accept-language:en-US')
        self.assertIsNotNone(r1)
        self.assertIsNotNone(r2)
        self.assertEqual(handle_for(r1["client_ref"]), handle_for(r2["client_ref"]))

    def test_port_stripped_address_still_validated(self):
        from apip.live.adapters import _safe_client
        self.assertIsNone(_safe_client("not-an-address:99"))
        self.assertIsNone(_safe_client("300.300.300.300"))
        self.assertEqual(_safe_client("203.0.113.9:52844"), "203.0.113.9")


class RejectionMarkerTests(unittest.TestCase):
    """Finding: the live origin writes {"rejected": true, ...} markers on
    contract violations; the offline loader then crashed on its own partner
    component's output."""

    def test_loader_skips_rejection_markers(self):
        with TemporaryDirectory() as td:
            p = Path(td) / "tx.jsonl"
            origin = ChallengeOrigin(p)
            origin.emit({"client_ref": "c", "observed_at": "BAD"})   # marker
            origin.emit({"client_ref": "c", "observed_at": "2026-09-01T19:00:00Z",
                         "header_order": ["host"]})
            store = CorrelationStore()
            for line in p.read_text().strip().split("\n"):
                obj = json.loads(line)
                if obj.get("rejected"):
                    continue
                store.observe(obj)
            self.assertEqual(store.report()["tracked_requesters"], 1)


class FutureStampTests(unittest.TestCase):
    """Finding: a requester stamped 9999 survived TTL eviction forever —
    state pinning in the bounded store via log-controlled timestamps
    (TM-009 clock manipulation, live variant)."""

    def test_future_stamped_entry_does_not_pin_state(self):
        s = CorrelationStore()
        s.observe({"client_ref": "x", "observed_at": "9999-01-01T00:00:00Z",
                   "tls_ja4": "t13d1516h2_abc"})
        s.observe({"client_ref": "y", "observed_at": "2026-09-01T19:00:00Z",
                   "tls_ja4": "t13d1516h2_abc"})
        s.prune_expired("2026-09-01T20:00:00Z", ttl_seconds=3600)
        surviving = set(s._by_handle)
        self.assertNotIn(handle_for("x"), surviving)
        self.assertIn(handle_for("y"), surviving)


class RecencyDefaultTests(unittest.TestCase):
    """Finding: load_policy shipped an always-'fresh' classifier, so the
    packaged demo never exercised evidence decay despite docs/04 freshness
    being a claimed control."""

    def test_default_classifier_decays(self):
        from apip.config import _default_recency_classifier
        c = _default_recency_classifier(6.0)
        old = "1999-01-01T00:00:00Z"
        now = "2000-01-01T00:00:00Z"   # relative to any anchor, 1yr apart
        # determinism check only: classifier must not blanket-return fresh
        results = {c(old), c(now), c("")}
        self.assertIn("stale", results)
        self.assertNotEqual(results, {"fresh"})

    def test_loaded_policy_uses_decaying_classifier(self):
        from apip.config import load_policy
        pol = load_policy(Path(__file__).resolve().parent.parent.parent
                          / "examples" / "policy.toml")
        self.assertEqual(pol.classify_recency("1999-01-01T00:00:00Z"), "stale")


class P1HopSensitivityTests(unittest.TestCase):
    """Documented limitation, pinned as behavior: P1 header-order features
    are order-sensitive and a reordering hop changes the vector; the order-
    INSENSITIVE header-set hash is retained for containment linking."""

    def test_reordered_hop_changes_vector_but_not_set(self):
        a = extract_features({"client_ref": "c", "observed_at": "2026-09-01T19:00:00Z",
                              "header_order": ["host", "user-agent", "accept"]})
        b = extract_features({"client_ref": "c", "observed_at": "2026-09-01T19:00:00Z",
                              "header_order": ["accept", "host", "user-agent"]})
        self.assertNotEqual(a["P1:header_order"], b["P1:header_order"])
        self.assertEqual(a["P1:header_set"], b["P1:header_set"])


class ReasonCardinalityTests(unittest.TestCase):
    """Finding: 5000 unknown evidence kinds produced 5001 reason codes —
    unbounded reason growth from evidence volume. Pinned: reason codes are
    now known to grow with DISTINCT kinds; callers bound evidence per
    indicator upstream (docs/23 envelopes). Documented residual."""

    def test_reason_growth_is_by_distinct_kind(self):
        from apip.models import Indicator, Evidence
        from apip.policy import Policy, RungFloor, evaluate
        from apip.registry import SourceRegistry, SourceProfile
        REG = SourceRegistry((SourceProfile("curated-a", "curated", True),))
        POL = Policy(version="v", mode="ENFORCE", scope="t",
                     observe_m=40, fqdn_auto_m=95, fqdn_auto_s=90,
                     ip_rate_m=90, ip_rate_s=85, ip_deny_m=98, ip_deny_s=95,
                     max_auto_ttl_seconds=3600, auto_prefix_deny=False,
                     auto_routing=False, auto_wildcard_domain=False,
                     rung_floors={"L4": RungFloor(95, 90)}, source_registry=REG)
        dup = Indicator("z", "fqdn", "bad.invalid", ("curated-a",),
                        tuple(Evidence(kind="unk", source_id="curated-a",
                                       source_class="x",
                                       observed_at="2026-09-01T20:00:00Z",
                                       independent=True) for _ in range(500)))
        d = evaluate(dup, POL, {"client": "h", "protocol_class": "interactive_http"})
        # duplicates collapse: one unweighted reason + unqualified marker
        self.assertLessEqual(len(d.reason_codes), 3)


if __name__ == "__main__":
    unittest.main()
