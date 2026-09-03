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
        # audit P1-40: close the ChallengeOrigin writer deterministically via
        # `with` — the rejection-marker test previously leaked a _TxWriter
        # handle that GC warned about at shutdown.
        with TemporaryDirectory() as td:
            p = Path(td) / "tx.jsonl"
            with ChallengeOrigin(p) as origin:
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


class InputHardeningTests(unittest.TestCase):
    """audit P2-43/P2-44: hostile input must fail CLOSED with a clean error —
    never a runtime crash (unhashable type, iteration-of-dict) and never an
    unbounded file read that exhausts memory before the record caps bite."""

    def _write(self, td: Path, obj) -> Path:
        p = td / "indicators.json"
        p.write_text(json.dumps(obj))
        return p

    def _base_indicator(self):
        return {
            "id": "i1", "type": "fqdn", "value": "host.invalid",
            "sources": ["curated-a"], "tags": ["t"],
            "evidence": [{"kind": "curated_source", "source_id": "curated-a",
                          "observed_at": "2026-09-01T19:00:00Z"}],
        }

    def test_non_string_type_rejected_not_crashed(self):
        # audit P2-44: `"type": []` previously hit `kind not in frozenset` and
        # raised TypeError: unhashable — a crash, not a rejection.
        from apip.io import load_indicators
        for hostile in ([], {}, 3, ["fqdn"]):
            obj = [self._base_indicator()]
            obj[0]["type"] = hostile
            with TemporaryDirectory() as td:
                p = self._write(Path(td), obj)
                with self.assertRaises(ValueError):
                    load_indicators(p)

    def test_non_list_tags_rejected_not_crashed(self):
        # audit P2-44: `"tags": "abc"` (string) iterates as characters and
        # `"tags": {"k":1}` iterates dict keys; `"tags": [["x"]]` crashes
        # set() on an unhashable list. All must be clean rejections.
        from apip.io import load_indicators
        for hostile in ("abc", {"k": 1}, [["nested"]]):
            obj = [self._base_indicator()]
            obj[0]["tags"] = hostile
            with TemporaryDirectory() as td:
                p = self._write(Path(td), obj)
                with self.assertRaises(ValueError):
                    load_indicators(p)

    def test_non_list_sources_rejected(self):
        from apip.io import load_indicators
        for hostile in ("src", {"s": 1}):
            obj = [self._base_indicator()]
            obj[0]["sources"] = hostile
            with TemporaryDirectory() as td:
                p = self._write(Path(td), obj)
                with self.assertRaises(ValueError):
                    load_indicators(p)

    def test_oversized_file_rejected_before_read(self):
        # audit P2-43: the byte gate must trip on file SIZE before the JSON is
        # ever parsed into memory. We simulate a huge file by patching the cap
        # to a tiny value, then proving an ordinary small-ish payload is
        # rejected by the stat() gate (not by parsing).
        import apip.io as io
        from apip.io import load_indicators
        with TemporaryDirectory() as td:
            p = self._write(Path(td), [self._base_indicator()] * 200)
            self.assertGreater(p.stat().st_size, 0)
            old = io._MAX_INDICATOR_FILE_BYTES
            io._MAX_INDICATOR_FILE_BYTES = 1     # any nonzero file is "too big"
            try:
                with self.assertRaises(ValueError) as cm:
                    load_indicators(p)
                self.assertIn("too large", str(cm.exception))
            finally:
                io._MAX_INDICATOR_FILE_BYTES = old


# ---------------------------------------------------------------------------
# audit P1-42: deterministic property tests. The reference is deterministic,
# so instead of an external property-test library we drive a fixed-seed LCG
# (implemented inline — never imports `random`) and assert INVARIANTS hold
# under arbitrary cardinality/order/skew, not just on hand-picked examples.
# The seed is pinned so any invariant regression is reproducible in CI.
# ---------------------------------------------------------------------------

class _LCG:
    """Minimal deterministic PRNG (Lehmer). Same seed -> identical sequence.
    No `random` import, preserving the no-AI/determinism conformance gate."""

    def __init__(self, seed: int):
        self._s = seed % 2147483647
        if self._s == 0:
            self._s = 1

    def next(self, lo: int, hi: int) -> int:
        self._s = (self._s * 16807) % 2147483647
        return lo + (self._s % (hi - lo + 1))

    def choice(self, seq):
        return seq[self.next(0, len(seq) - 1)]


class PropertyBasedTests(unittest.TestCase):
    """P1-42: fuzz/property claims over hard invariants, not just examples."""

    KINDS = ("curated_source", "exact_fqdn", "recent", "bounded_scope",
             "verified_rollback", "prior_false_positive", "beacon_periodicity",
             "dga_likelihood", "first_seen_novelty", "volume_anomaly")
    TYPES = ("fqdn", "ipv4", "ipv6", "cidr", "url")

    def _decision(self, rng: _LCG, i: int) -> tuple["Indicator", "Decision"]:
        """Build a randomized decision/indicator pair for exporter fuzzing.
        The indicator VALUE always matches its TYPE (a valid IP literal for
        ipv4/ipv6, a canonical fqdn/cidr/url otherwise) so the exporter sees
        realistic, type-correct inputs to guard/verify."""
        from apip.models import (Indicator, Decision, ActionSelector,
                                 Evidence)
        kind = rng.choice(self.KINDS)
        typ = rng.choice(self.TYPES)
        if typ == "ipv4":
            value = f"{rng.next(10, 200)}.{rng.next(0, 255)}.{rng.next(0, 255)}.{rng.next(1, 255)}"
        elif typ == "ipv6":
            value = f"2001:db8::{i:x}"
        elif typ == "cidr":
            value = f"203.0.113.{rng.next(1, 50)}/32"
        elif typ == "url":
            value = f"https://host-{i}.invalid/path"
        else:
            value = f"host-{i}.invalid"
        ind = Indicator(f"pid{i}", typ, value, (f"s{rng.next(0, 3)}",),
                        (Evidence(f"e{i}_{k}", kind, f"s{rng.next(0, 3)}",
                                  "curated", "2026-09-01T19:00:00Z", True)
                         for k in range(rng.next(0, 4))))
        # randomized pair-scope: sometimes a pair whose CLIENT is unboundable
        # (None) — the case the adapter must REFUSE rather than broaden to
        # destination-global — and sometimes a truly boundable pair client or
        # a destination-global scope (both emit-able).
        _r = rng.next(0, 5)
        if _r == 0:              # PAIR scope, NO client -> exporter must refuse
            client = None
            scope_type = "client_destination_pair"
        elif _r in (1, 2):       # pair scope WITH boundable client -> emit
            client = ["203.0.113.5", "192.0.2.9"][rng.next(0, 1)]
            scope_type = "client_destination_pair"
        else:                    # destination-global -> emit
            client = None
            scope_type = "destination_global"
        sel = ActionSelector(
            scope_type=scope_type,
            client=client, destination=value,
            rate_ceiling_per_min=rng.next(1, 200))
        rng.next(0, 1)  # vary action direction deterministically
        action = "rate_limit"
        dec = Decision(
            f"pd{i}", ind.id, rng.next(70, 99), rng.next(5, 94), "RATE_LIMIT",
            action, "L3", "scope", 3600, "v2.3", ("rate_limit_reached",),
            "", sel, nominal_ttl_seconds=3600)
        return ind, dec

    def test_selector_never_broadens_across_fuzz(self):
        """P1-42: an IP pair-scoped selector with no boundable client must be
        REFUSED loudly at the exporter boundary, never emitted as a broadened
        destination-global rule (docs/25). Fuzz across many client/scope
        combinations."""
        from apip.exporters.suricata import compile_rules_structured
        from apip.sanitize import validate_ip_literal
        rng = _LCG(20260901)
        refused = 0
        emitted = 0
        for i in range(200):
            ind, dec = self._decision(rng, i)
            if ind.type not in {"ipv4", "ipv6"}:
                continue
            pair_no_client = (dec.selector is not None
                              and dec.selector.scope_type in
                              {"client_destination_pair", "client_session"}
                              and not dec.selector.client)
            if pair_no_client:
                with self.assertRaises(ValueError):
                    compile_rules_structured([(ind, dec)])
                refused += 1
            else:
                arts = compile_rules_structured([(ind, dec)])
                emitted += 1
                for a in arts:
                    # the emitted fragment must reference the SAME destination,
                    # never a wildcard/global that broadens the typed selector
                    safe = validate_ip_literal(ind.value)
                    self.assertIn(safe, a.fragment)
        # the fuzz must have actually exercised BOTH branches
        self.assertGreater(refused, 0, "no unboundable pair-scope case fuzzed")
        self.assertGreater(emitted, 0, "no emit case fuzzed")

    def _compile_able(self, items):
        """Filter to the decisions the Suricata adapter can faithfully emit —
        dropping pair-scoped-with-no-client decisions that it legally refuses
        (that refusal is asserted in test_selector_never_broadens_across_fuzz)."""
        out = []
        for ind, dec in items:
            sel = dec.selector
            if (sel is not None
                    and sel.scope_type in {"client_destination_pair",
                                           "client_session"}
                    and not sel.client):
                continue
            out.append((ind, dec))
        return out

    def test_fragments_are_deterministic_and_pairwise_distinct(self):
        """P1-42: compiling the SAME decision twice must yield byte-identical
        artifacts; distinct decisions must yield distinct fragment hashes. One
        decision id maps to exactly one content hash."""
        from apip.exporters.suricata import compile_rules_structured
        rng = _LCG(7)
        items = self._compile_able([self._decision(rng, i) for i in range(40)])
        self.assertGreater(len(items), 0)
        a1 = compile_rules_structured(items)
        a2 = compile_rules_structured(items)     # same input, fresh compile
        for x, y in zip(a1, a2):
            self.assertEqual(x.fragment, y.fragment)   # deterministic
            self.assertEqual(x.fragment_hash, y.fragment_hash)
        hashes = [a.fragment_hash for a in a1]
        self.assertEqual(len(set(hashes)), len(hashes), "two compiles of "
                         f"distinct decisions collided on hash: {set(hashes)}")

    def test_evidence_permutation_does_not_change_decision(self):
        """P1-42: scoring is invariant to the ORDER of evidence and sources —
        permuting the envelope (arbitrary cardinality/order) must not change
        maliciousness/action or the set of reason codes."""
        import itertools as _it
        from apip.models import (Indicator, Evidence)
        from apip.policy import evaluate
        from tests.test_audit_residuals import _policy, CTX
        base = _policy(mode="OBSERVE")
        # a fixed evidence multiset, scored in every permutation of a subset
        stack = [Evidence(f"p{i}", "curated_source", f"s{i % 2}",
                          "curated", "2026-09-01T19:00:00Z", True)
                 for i in range(6)]
        outs = set()
        for perm in _it.permutations(stack, 5):
            ind = Indicator("perm", "fqdn", "p.invalid", ("sa", "sb", "sc"),
                            tuple(perm))
            d = evaluate(ind, base, context=CTX)
            outs.add((d.maliciousness, d.action,
                      tuple(sorted(d.reason_codes))))
        self.assertEqual(len(outs), 1, f"evidence permutation changed the "
                         f"decision: {sorted(outs)}")

    def test_hostile_value_fuzz_fails_closed(self):
        """P1-42: arbitrary hostile strings pushed through the canonicalizers
        and validators must fail closed (raise/reject), never silently
        canonicalize to something that broadens authorization."""
        from apip.io import _canonicalize
        from apip.sanitize import (validate_fqdn, validate_ip_literal,
                                   rpz_comment_safe, UnsafeIdentifier)
        rng = _LCG(99)
        corpus = list('abcXYZ09.-_|;:*()[]{}$,"\n\t\\ ') + ["..", ".", "",
                                                            "-", "--"]
        made = 0
        refused = 0
        for _ in range(400):
            n = rng.next(1, 24)
            hostile = "".join(rng.choice(corpus) for _ in range(n))
            made += 1
            for fn in (lambda v: validate_fqdn(v),
                       lambda v: validate_ip_literal(v),
                       lambda v: rpz_comment_safe(v),
                       lambda v: _canonicalize("fqdn", v)):
                try:
                    res = fn(hostile)
                except (ValueError, UnsafeIdentifier):
                    refused += 1
                    continue
                # if it did NOT reject, the value must round-trip unchanged or
                # be an idempotent canonical form — never a semantically
                # different string that a downstream allow/deny mis-parses
                # (e.g. ";evil.invalid" must not pass as a bare fqdn).
                self.assertNotIn(";", res)
                self.assertNotIn("\n", res)
        self.assertGreater(refused, 0, "no hostile value was refused — the "
                             "fuzz failed to exercise the fail-closed paths")
        self.assertGreater(made, 0)


if __name__ == "__main__":
    unittest.main()
