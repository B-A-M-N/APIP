"""Adversarial-audit residual regressions (v2.1.1).

Each test pins one residual named in AUDIT_ADVERSARIAL_2026_09_01.md or the
follow-up verdict. These were the accepted/documented gaps: rate_limit with
no ceiling, unexercised resource envelopes, best-effort P5 extraction,
unsalted handles, wall-clock-only replay, asserted (not derived)
independence, unbounded per-indicator evidence, and a lab adversary that
never rotated behavior. If one fails, a named residual has regressed.
"""
import json
import os
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from apip.models import Indicator, Evidence
from apip.policy import Policy, RungFloor, evaluate, RandomizationMechanism
from apip.registry import SourceRegistry, SourceProfile
from apip.scoring import EvidenceTable, DEFAULT_WEIGHTS


def _pinned_classifier():
    """Decaying classifier pinned to a fixed instant so tests are
    replay-stable (matches shipped policy semantics: 6h freshness window)."""
    from datetime import datetime, timedelta, timezone

    def classify(ts: str) -> str:
        if not ts:
            return "stale"
        try:
            t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return "stale"
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        now = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        return "fresh" if abs(now - t) <= timedelta(hours=6.0) else "stale"

    return classify


def _policy(**over) -> Policy:
    kw = dict(
        version="v", mode="ENFORCE", scope="t", observe_m=1,
        fqdn_auto_m=95, fqdn_auto_s=90, ip_rate_m=90, ip_rate_s=85,
        ip_deny_m=98, ip_deny_s=95, max_auto_ttl_seconds=3600,
        auto_prefix_deny=False, auto_routing=False, auto_wildcard_domain=False,
        rung_floors={"L1": RungFloor(85, 75), "L2": RungFloor(90, 80),
                     "L4": RungFloor(95, 90), "L5": RungFloor(98, 95)},
        source_registry=SourceRegistry((
            SourceProfile("curated-a", "curated", True),
            SourceProfile("local-b", "local", True, True),
            SourceProfile("local-behavioral", "local", True, True))),
        evidence_table=EvidenceTable(DEFAULT_WEIGHTS),
        nominal_rate_ceiling_per_min=240,
        # decaying classifier (audit finding #2: never ship always-fresh)
        classify_recency=_pinned_classifier(),
    )
    kw.update(over)
    return Policy(**kw)


CTX = {"client": "h1", "protocol_class": "interactive_http"}

# M=130, S_ctx=85 under DEFAULT_WEIGHTS: clears the L2 floor (90/80) without
# dedicated-use evidence (which would flip infra state toward L5 selection)
STRONG_EVIDENCE = (
    Evidence("single_curated_source", "curated-a", "curated", "2026-09-01T11:00:00Z", True),
    Evidence("curated_source", "curated-a", "curated", "2026-09-01T11:00:00Z", True),
    Evidence("exact_ip", "curated-a", "curated", "2026-09-01T11:00:00Z", True),
    Evidence("recent", "curated-a", "curated", "2026-09-01T11:00:00Z", True),
    Evidence("direct_local_detection", "local-b", "local", "2026-09-01T11:00:00Z", True),
    Evidence("bounded_scope", "curated-a", "curated", "2026-09-01T11:00:00Z", True),
    Evidence("verified_rollback", "curated-a", "curated", "2026-09-01T11:00:00Z", True),
)


class RateCeilingTests(unittest.TestCase):
    """Residual: 'L2 rate_limit has no rate parameter — the scaffold would
    emit a rule with no ceiling semantics.'"""

    def test_l2_selector_carries_ceiling(self):
        pol = _policy()
        ind = Indicator("i1", "ipv4", "203.0.113.5", ("curated-a",), STRONG_EVIDENCE)
        d = evaluate(ind, pol, CTX)
        self.assertEqual(d.rung, "L2")
        self.assertIsNotNone(d.selector)
        self.assertEqual(d.selector.scope_type, "client_destination_pair")
        self.assertEqual(d.selector.rate_ceiling_per_min, 240)   # nominal

    def test_ceiling_draw_within_bounds_and_recorded(self):
        pol = _policy(randomization_enabled=True,
                      randomization_bounds_version="rv1",
                      randomization_epoch="e1",
                      rate_ceiling_jitter=RandomizationMechanism(True, 0.5, 1.0))
        ind = Indicator("i2", "ipv4", "203.0.113.6", ("curated-a",), STRONG_EVIDENCE)
        d = evaluate(ind, pol, CTX)
        self.assertEqual(d.rung, "L2")
        ceiling = d.selector.rate_ceiling_per_min
        self.assertTrue(120 <= ceiling <= 240)      # inside [0.5, 1.0] x 240
        rec = d.randomization
        mechs = rec if isinstance(rec, list) else [rec]
        rc = [m for m in mechs if m["mechanism"] == "rate_ceiling"]
        self.assertEqual(len(rc), 1)
        self.assertEqual(rc[0]["draw"]["ceiling_per_min"], ceiling)
        # deterministic replay from the same policy state
        d2 = evaluate(ind, pol, CTX)
        self.assertEqual(d2.selector.rate_ceiling_per_min, ceiling)

    def test_exporter_refuses_ceilingless_rate_limit(self):
        from apip.exporters.suricata import compile_rules
        pol = _policy(nominal_rate_ceiling_per_min=0)   # misconfiguration
        ind = Indicator("i3", "ipv4", "203.0.113.7", ("curated-a",), STRONG_EVIDENCE)
        d = evaluate(ind, pol, CTX)
        if d.action == "rate_limit":
            # zero/nominal-less ceiling is carried as falsy, and the
            # exporter refuses to compile a ceilingless rate_limit
            self.assertFalse(d.selector.rate_ceiling_per_min)
            with self.assertRaises(ValueError):
                compile_rules([(ind, d)])

    def test_compiled_rule_carries_ceiling_and_ttl(self):
        from apip.exporters.suricata import compile_rules
        pol = _policy()
        ind = Indicator("i4", "ipv4", "203.0.113.8", ("curated-a",), STRONG_EVIDENCE)
        d = evaluate(ind, pol, CTX)
        rules = compile_rules([(ind, d)])
        self.assertIn(f"count {d.selector.rate_ceiling_per_min}", rules)
        self.assertIn(f"apip_ttl_seconds", rules)
        self.assertIn(d.id, rules)


class ProvenanceIndependenceTests(unittest.TestCase):
    """Residual: independence was asserted per feed; docs/04 says two records
    are not independent merely because they came through two feeds."""

    def test_resellers_of_one_upstream_corroborate_once(self):
        reg = SourceRegistry((
            SourceProfile("upstream-U", "curated", True),
            SourceProfile("reseller-1", "curated", True, upstream="upstream-U"),
            SourceProfile("reseller-2", "curated", True, upstream="upstream-U"),
            SourceProfile("truly-other", "curated", True, upstream="U2"),
        ))
        from apip.policy import _external_corroboration
        from apip.models import Indicator
        # three feed names, ONE provenance identity
        ind = Indicator("i", "ipv4", "203.0.113.9", (), (
            Evidence("curated_source", "upstream-U", "curated", "2026-09-01T11:00:00Z", True),
            Evidence("curated_source", "reseller-1", "curated", "2026-09-01T11:00:00Z", True),
            Evidence("curated_source", "reseller-2", "curated", "2026-09-01T11:00:00Z", True),
        ))
        qualified, count = _external_corroboration(ind, reg)
        self.assertTrue(qualified)
        self.assertEqual(count, 1)      # not 3
        ind2 = Indicator("j", "ipv4", "203.0.113.9", (), (
            Evidence("curated_source", "upstream-U", "curated", "2026-09-01T11:00:00Z", True),
            Evidence("curated_source", "truly-other", "curated", "2026-09-01T11:00:00Z", True),
        ))
        _, count2 = _external_corroboration(ind2, reg)
        self.assertEqual(count2, 2)


class EvidenceEnvelopeTests(unittest.TestCase):
    """Residual: reason growth by distinct kind — callers needed an upstream
    per-indicator evidence bound; now the policy owns one (docs/23)."""

    def test_overflow_truncated_with_reason(self):
        pol = _policy(max_evidence_per_indicator=4, mode="OBSERVE")
        evs = tuple(Evidence(f"kind{i}", "curated-a", "curated",
                             "2026-09-01T11:00:00Z", True) for i in range(50))
        ind = Indicator("i", "ipv4", "203.0.113.10", ("curated-a",), evs)
        d = evaluate(ind, pol, CTX)
        self.assertTrue(any(r.startswith("evidence_envelope_truncated:") for r in d.reason_codes))
        # scorer saw at most 4 records
        self.assertLessEqual(len([r for r in d.reason_codes if not r.startswith("evidence_envelope_truncated")]), 6)

    def test_under_cap_is_untouched(self):
        pol = _policy(max_evidence_per_indicator=64, mode="OBSERVE")
        evs = tuple(Evidence("recent", "curated-a", "curated",
                             "2026-09-01T11:00:00Z", True) for _ in range(10))
        ind = Indicator("i", "ipv4", "203.0.113.11", ("curated-a",), evs)
        d = evaluate(ind, pol, CTX)
        self.assertFalse(any(r.startswith("evidence_envelope_truncated") for r in d.reason_codes))


class ReplayClockTests(unittest.TestCase):
    """Residual: recency was wall-clock anchored, so byte-replay was only
    exact within a freshness window."""

    def test_pinned_reference_now_exact_replay(self):
        ts_old = "1999-01-01T00:00:00Z"
        ev = (Evidence("recent", "curated-a", "curated", ts_old, True),)
        pol_fresh = _policy(mode="OBSERVE", reference_now="1999-01-01T01:00:00Z")
        pol_stale = _policy(mode="OBSERVE", reference_now="2026-09-01T00:00:00Z")
        ind = Indicator("i", "ipv4", "203.0.113.12", ("curated-a",), ev)
        d1 = evaluate(ind, pol_fresh, CTX)
        d2 = evaluate(ind, pol_fresh, CTX)
        # the SAME evidence is fresh at one pin and stale at another — and
        # identical across runs at the same pin (no wall clock in the path)
        self.assertEqual(d1.maliciousness, 25)      # fresh 'recent' weight
        self.assertEqual(d2.maliciousness, d1.maliciousness)
        d3 = evaluate(ind, pol_stale, CTX)
        self.assertEqual(d3.maliciousness, 0)       # stale: no positive M

    def test_unpinned_policy_still_decays(self):
        pol = _policy(mode="OBSERVE")    # no reference_now: wall clock
        ind = Indicator("i", "ipv4", "203.0.113.13", ("curated-a",),
                        (Evidence("recent", "curated-a", "curated", "1999-01-01T00:00:00Z", True),))
        d = evaluate(ind, pol, CTX)
        self.assertEqual(d.maliciousness, 0)

    def test_config_loads_reference_now(self):
        from apip.config import load_policy
        with TemporaryDirectory() as td:
            p = Path(td) / "pol.toml"
            p.write_text(
                'policy_version = "t"\nmode = "OBSERVE"\nscope = "s"\n'
                '[thresholds]\nobserve_m = 40\nfqdn_auto_m = 95\nfqdn_auto_s = 90\n'
                'ip_rate_m = 90\nip_rate_s = 85\nip_deny_m = 98\nip_deny_s = 95\n'
                '[thresholds.rungs.L2]\nm = 90\ns = 80\n'
                '[limits]\nmax_auto_ttl_seconds = 3600\n'
                'nominal_rate_ceiling_per_min = 240\n'
                '[replay]\nreference_now = "2026-09-01T12:00:00Z"\n')
            pol = load_policy(p)
            self.assertEqual(pol.reference_now, "2026-09-01T12:00:00Z")


class KeyedHandleTests(unittest.TestCase):
    """Residual: handles were unsalted SHA-256 prefixes — invertible by
    anyone who could guess the client IP space."""

    def test_handles_differ_per_deployment_key(self):
        from apip.attribution import handle_for, reset_key_cache
        old = {k: os.environ.pop(k, None)
               for k in ("APIP_DEPLOYMENT_KEY", "APIP_DEPLOYMENT_KEY_FILE")}
        try:
            reset_key_cache()
            h_dev = handle_for("203.0.113.20")
            os.environ["APIP_DEPLOYMENT_KEY"] = "deployment-one"
            reset_key_cache()
            h_one = handle_for("203.0.113.20")
            os.environ["APIP_DEPLOYMENT_KEY"] = "deployment-two"
            reset_key_cache()
            h_two = handle_for("203.0.113.20")
            self.assertEqual(len({h_dev, h_one, h_two}), 3)
            # stability within a deployment (env still carries key two)
            reset_key_cache()
            self.assertEqual(handle_for("203.0.113.20"), h_two)
            # cross-deployment joinability is dead: same client, different keys
            self.assertNotEqual(h_one, h_two)
        finally:
            for k, v in old.items():
                if v is not None:
                    os.environ[k] = v
                else:
                    os.environ.pop(k, None)
            reset_key_cache()

    def test_report_marks_unkeyed_handles(self):
        from apip.attribution import CorrelationStore, reset_key_cache
        old = os.environ.pop("APIP_DEPLOYMENT_KEY", None)
        try:
            reset_key_cache()
            s = CorrelationStore()
            s.observe({"client_ref": "203.0.113.21",
                       "observed_at": "2026-09-01T19:00:00Z",
                       "tls_ja4": "t13d1516h2_abc"})
            rep = s.report()
            self.assertEqual(rep["handle_keying"], "dev-fallback")
            html = __import__("apip.uireport", fromlist=["render_correlation_report"]) \
                .render_correlation_report(rep)
            self.assertIn("UNKEYED HANDLES", html)
        finally:
            if old is not None:
                os.environ["APIP_DEPLOYMENT_KEY"] = old
            reset_key_cache()


class BeaconDetectorTests(unittest.TestCase):
    """Residual: docs/23 envelopes were specified but no reference detector
    existed to bound. BD-1 beacon periodicity is the reference."""

    def _beacon(self, detector, src="10.0.0.5", dst="203.0.113.30",
                period=60, count=8, start=1_000_000):
        ts = start
        first = None
        for _ in range(count):
            r = detector.observe(src, dst, "2026-09-01T00:00:00Z", ts)
            if r and first is None:
                first = r
            ts += period
        return first

    def test_clean_beacon_detected_as_local_behavioral_evidence(self):
        from apip.behavioral import BeaconDetector, BEACON_KIND
        d = BeaconDetector(min_events=6)
        det = self._beacon(d)
        self.assertIsNotNone(det)
        fields = det.as_evidence_fields()
        self.assertEqual(fields["kind"], BEACON_KIND)
        self.assertEqual(fields["source_id"], "local-behavioral")
        # and it feeds the existing lattice as single-family evidence
        pol = _policy()
        ind = Indicator("ib", "ipv4", "203.0.113.30", ("local-behavioral",), (
            Evidence(fields["kind"], fields["source_id"], "local",
                     "2026-09-01T11:00:00Z", True, fields["detail"]),))
        dec = evaluate(ind, pol, CTX)
        self.assertEqual(dec.rung, "L0")       # capped: one family, no external

    def test_erratic_traffic_not_detected(self):
        from apip.behavioral import BeaconDetector
        d = BeaconDetector(min_events=6)
        ts = 1_000_000
        hits = 0
        for gap in (3, 250, 17, 900, 44, 12, 777, 31, 5, 220, 61, 58):
            ts += gap
            if d.observe("a", "z", "2026-09-01T00:00:00Z", ts):
                hits += 1
        self.assertEqual(hits, 0)

    def test_bounded_emission_one_per_completed_block(self):
        from apip.behavioral import BeaconDetector
        d = BeaconDetector(min_events=6)
        ts = 1_000_000
        emissions = 0
        for _ in range(31):                    # 30 gaps -> 5 complete blocks
            if d.observe("a", "b2", "2026-09-01T00:00:00Z", ts):
                emissions += 1
            ts += 60
        self.assertEqual(emissions, 5)

    def test_event_envelope_degrades_stop_and_mark(self):
        from apip.behavioral import BeaconDetector
        d = BeaconDetector(max_events=12, min_events=3)
        ts = 1_000_000
        for _ in range(40):
            d.observe("x", "y", "2026-09-01T00:00:00Z", ts)
            ts += 60
        self.assertTrue(d.degraded)
        self.assertIsNone(d.observe("x", "y", "2026-09-01T00:00:00Z", ts))
        self.assertEqual(d.tracked_windows, 0)   # state frozen

    def test_window_envelope_sheds_deterministically(self):
        from apip.behavioral import BeaconDetector
        d = BeaconDetector(max_windows=3, min_events=3)
        for i, pair in enumerate((("a", "1"), ("b", "2"), ("c", "3"))):
            d.observe(pair[0], pair[1], "2026-09-01T00:00:00Z", 1000)
        self.assertIsNone(d.observe("d", "4", "2026-09-01T00:00:00Z", 1000))
        self.assertEqual(d.suppressed_new_windows, 1)
        self.assertEqual(d.tracked_windows, 3)

    def test_detection_is_deterministic(self):
        from apip.behavioral import BeaconDetector
        def run():
            d = BeaconDetector(min_events=6)
            det = self._beacon(d, period=30, count=8, start=7_000_000)
            return None if det is None else (det.src, det.dst,
                                             det.median_gap_s, det.events)
        self.assertIsNotNone(run())
        self.assertEqual(run(), run())


class P5HardeningTests(unittest.TestCase):
    """Residual: P5 key-order extraction was a best-effort lexical scan that
    hostile bodies could steer into quoting arbitrary text as 'keys'."""

    def test_hostile_bodies_fail_closed(self):
        from apip.live.server import _key_order
        self.assertEqual(_key_order(b'{"' + b"A" * 10_000 + b'":1}'), [])
        self.assertEqual(_key_order(b"not json at all"), [])
        self.assertEqual(_key_order(b'{"unterminated'), [])
        self.assertEqual(_key_order(b""), [])

    def test_valid_json_with_escapes_extracted(self):
        import json as _json
        from apip.live.server import _key_order
        body = _json.dumps({"k1": 'val with ":\" inside', "k2": 2}).encode()
        self.assertEqual(_key_order(body), ["k1", "k2"])
        # escaped quote inside a key name: the scan cannot safely continue,
        # so it fails closed for that key rather than guessing
        body2 = b'{"key\\"with\\"quotes":1,"plain":2}'
        self.assertEqual(_key_order(body2), ["plain"])

    def test_keys_are_bounded(self):
        from apip.live.server import _key_order
        body = b"{" + b",".join(b'"k%d":1' % i for i in range(100)) + b"}"
        self.assertLessEqual(len(_key_order(body)), 32)


class ConfigValidationTests(unittest.TestCase):
    """New knobs are semantically validated at load."""

    def test_l2_without_ceiling_rejected(self):
        from apip.config import validate_policy
        raw = {
            "policy_version": "t", "mode": "ENFORCE", "scope": "s",
            "thresholds": {"observe_m": 40, "fqdn_auto_m": 95, "fqdn_auto_s": 90,
                           "ip_rate_m": 90, "ip_rate_s": 85, "ip_deny_m": 98,
                           "ip_deny_s": 95,
                           "rungs": {"L2": {"m": 90, "s": 80}}},
            "limits": {"max_auto_ttl_seconds": 3600},     # NO ceiling
            "safety": {},
        }
        problems = validate_policy(raw)
        self.assertTrue(any("nominal_rate_ceiling_per_min" in p for p in problems))

    def test_bad_reference_now_rejected(self):
        from apip.config import validate_policy
        raw = {
            "policy_version": "t", "mode": "ENFORCE", "scope": "s",
            "thresholds": {"observe_m": 40},
            "limits": {"max_auto_ttl_seconds": 3600},
            "replay": {"reference_now": "yesterday"},
        }
        problems = validate_policy(raw)
        self.assertTrue(any("reference_now" in p for p in problems))


if __name__ == "__main__":
    unittest.main()
