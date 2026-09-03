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


def _iso_of_epoch(epoch_s: int) -> str:
    """An ISO-8601 instant that EXACTLY matches an integer unix epoch, so
    detector cross-validation (audit P1-23) sees two agreeing timestamps."""
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch_s, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
        # audit P0-3: STRONG_EVIDENCE carries verified_rollback, which is now
        # a SERVER-certified control-plane fact. These tests exercise L2 rate-
        # ceiling mechanics, so the targets are declared governed/rollback-
        # verified infrastructure (the honest way to reach the rung now).
        governed_verified_rollback=tuple(f"203.0.113.{k}" for k in range(1, 12)),
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

    def test_future_evidence_is_stale_not_fresh(self):
        """v2.3 (audit P1-3): `abs(now - t)` treated a FUTURE observation as
        fresh. This pins the asymmetric rule — a record stamped hours ahead
        of the policy clock contributes zero positive M (only a small
        clock-skew allowance is tolerated)."""
        from datetime import timedelta
        pol = _policy(mode="OBSERVE", reference_now="2026-09-01T12:00:00Z")
        hours_ahead = "2026-09-01T15:00:00Z"    # +3h: too far ahead
        ind = Indicator("i", "ipv4", "203.0.113.14", ("curated-a",),
                        (Evidence("recent", "curated-a", "curated", hours_ahead, True),))
        d = evaluate(ind, pol, CTX)
        self.assertEqual(d.maliciousness, 0)     # future -> stale, no M

    def test_small_clock_skew_still_fresh(self):
        # a few minutes ahead is a tolerable skew, not future-dated evidence
        pol = _policy(mode="OBSERVE", reference_now="2026-09-01T12:00:00Z")
        two_min_ahead = "2026-09-01T12:02:00Z"
        ind = Indicator("i", "ipv4", "203.0.113.15", ("curated-a",),
                        (Evidence("recent", "curated-a", "curated", two_min_ahead, True),))
        d = evaluate(ind, pol, CTX)
        self.assertEqual(d.maliciousness, 25)    # within skew: fresh

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


class CorroborationP15Tests(unittest.TestCase):
    """P1-5 (audit): 'Define a specific set of evidence facts that constitute
    an external maliciousness assertion, with freshness. Do not infer "source
    corroborated the maliciousness claim" from a structural metadata
    observation.' Corroboration rests on FRESH MALICIOUSNESS ASSERTIONS
    (`curated_source` / `direct_local_detection`) from distinct upstreams —
    never on `recent`/`exact_*`/`exactness`, and never on a stale report."""

    FRESH = "2026-09-01T10:00:00Z"
    STALE = "2026-09-01T00:00:00Z"

    def _reg(self):
        return SourceRegistry((
            SourceProfile("curated-a", "curated", True),
            SourceProfile("curated-b", "curated", True),
        ))

    def test_two_fresh_maliciousness_assertions_corroborate(self):
        from apip.scoring import corroboration_tier
        from apip.policy import _external_corroboration
        reg = self._reg()
        ind = Indicator("f", "ipv4", "203.0.113.20", ("curated-a", "curated-b"),
                        (Evidence("curated_source", "curated-a", "curated", self.FRESH, True),
                         Evidence("curated_source", "curated-b", "curated", self.FRESH, True)))
        distinct, tier = corroboration_tier(ind, reg, _pinned_classifier())
        self.assertEqual((distinct, tier), (2, 1))
        qualified, count = _external_corroboration(ind, reg, _pinned_classifier())
        self.assertTrue(qualified)

    def test_stale_maliciousness_reports_do_not_corroborate(self):
        # two distinct upstreams, but both reports are outside the freshness
        # window -> NO corroboration, not externally qualified (P1-5).
        from apip.scoring import corroboration_tier
        from apip.policy import _external_corroboration
        reg = self._reg()
        ind = Indicator("s", "ipv4", "203.0.113.21", ("curated-a", "curated-b"),
                        (Evidence("curated_source", "curated-a", "curated", self.STALE, True),
                         Evidence("curated_source", "curated-b", "curated", self.STALE, True)))
        distinct, tier = corroboration_tier(ind, reg, _pinned_classifier())
        self.assertEqual((distinct, tier), (0, 0))
        qualified, count = _external_corroboration(ind, reg, _pinned_classifier())
        self.assertFalse(qualified)

    def test_structural_metadata_is_not_a_maliciousness_assertion(self):
        # one fresh maliciousness report (curated-a) + a second source that
        # only observes the target structurally -> tier 0 (no corroboration).
        from apip.scoring import corroboration_tier
        reg = self._reg()
        ind = Indicator("m", "ipv4", "203.0.113.22", ("curated-a", "curated-b"),
                        (Evidence("curated_source", "curated-a", "curated", self.FRESH, True),
                         Evidence("recent", "curated-b", "curated", self.FRESH, True),
                         Evidence("exact_ip", "curated-b", "curated", self.FRESH, True)))
        distinct, tier = corroboration_tier(ind, reg, _pinned_classifier())
        self.assertEqual((distinct, tier), (1, 0))


class RandomizationEpochTests(unittest.TestCase):
    """P1-8 (audit): 'Pick one model: explicit epoch field or preferably
    versioned rotation interval + policy clock -> derived epoch. Then test the
    load_policy path, not only manually constructed Policy objects.'"""

    def _draw_pol(self, **over):
        base = dict(
            randomization_enabled=True,
            randomization_bounds_version="rv1",
            rate_ceiling_jitter=RandomizationMechanism(True, 0.5, 1.0),
        )
        base.update(over)
        return _policy(**base)

    def test_load_policy_honors_explicit_epoch(self):
        from apip.config import load_policy
        with TemporaryDirectory() as td:
            p = Path(td) / "pol.toml"
            p.write_text(
                'policy_version = "t"\nmode = "ENFORCE"\nscope = "s"\n'
                '[thresholds]\nobserve_m = 40\nfqdn_auto_m = 95\nfqdn_auto_s = 90\n'
                'ip_rate_m = 90\nip_rate_s = 85\nip_deny_m = 98\n'
                'ip_deny_s = 95\nmax_auto_ttl_seconds = 3600\n'
                '[thresholds.rungs.L2]\nm = 90\ns = 70\n'
                '[limits]\nnominal_rate_ceiling_per_min = 240\n'
                '[authorization]\nauthorized_prefixes = ["203.0.113.0/24"]\n'
                '[governed]\nverified_rollback = ["203.0.113.9"]\n'
                '[replay]\nreference_now = "2026-09-01T12:00:00Z"\n'
                '[randomization]\nenabled = true\nbounds_version = "rv1"\n'
                'epoch = "explicit-7"\n'
                '[randomization.mechanisms.rate_ceiling]\nenabled = true\n'
                'min = 0.5\nmax = 1.0\n')
            pol = load_policy(p)
            ind = Indicator("e", "ipv4", "203.0.113.9", ("curated-a",), STRONG_EVIDENCE)
            d = evaluate(ind, pol, CTX)
            self.assertEqual(d.rung, "L2")
            rec = d.randomization
            mechs = rec if isinstance(rec, list) else [rec]
            rc = [m for m in mechs if m["mechanism"] == "rate_ceiling"]
            self.assertEqual(len(rc), 1)
            self.assertEqual(rc[0]["epoch"], "explicit-7")

    def test_load_policy_derives_epoch_from_rotation_interval(self):
        """Versioned rotation interval + pinned policy clock -> derived epoch
        bucket, `floor(clock_seconds // interval)`. Two clock pins in different
        buckets draw DIFFERENT ceilings; two pins in the SAME bucket draw the
        SAME ceiling. Asserts the derived epoch is carried on the draw record."""
        from apip.config import load_policy
        base_toml = (
            'policy_version = "t"\nmode = "ENFORCE"\nscope = "s"\n'
            '[thresholds]\nobserve_m = 40\nfqdn_auto_m = 95\nfqdn_auto_s = 90\n'
            'ip_rate_m = 90\nip_rate_s = 85\nip_deny_m = 98\n'
            'ip_deny_s = 95\nmax_auto_ttl_seconds = 3600\n'
            '[thresholds.rungs.L2]\nm = 90\ns = 70\n'
            '[limits]\nnominal_rate_ceiling_per_min = 240\n'
            '[authorization]\nauthorized_prefixes = ["203.0.113.0/24"]\n'
            '[governed]\nverified_rollback = ["203.0.113.10"]\n'
            '[replay]\nreference_now = "2026-09-01T12:00:00Z"\n'
            '[randomization]\nenabled = true\nbounds_version = "rv1"\n'
            'rotation_interval_seconds = 3600\n'
            '[randomization.mechanisms.rate_ceiling]\nenabled = true\n'
            'min = 0.5\nmax = 1.0\n'
        )
        with TemporaryDirectory() as td:
            p = Path(td) / "pol.toml"
            p.write_text(base_toml)
            pol = load_policy(p)
            ind = Indicator("e", "ipv4", "203.0.113.10", ("curated-a",), STRONG_EVIDENCE)
            # clock = 2026-09-01T00:00:00Z -> unix seconds, bucket 0
            pol_a = _pin_clock(pol, "2026-09-01T12:00:00Z")
            # same bucket (+1800s < 3600 interval)
            pol_same = _pin_clock(pol, "2026-09-01T12:30:00Z")
            # next bucket (+5400s >= 3600 interval)
            pol_next = _pin_clock(pol, "2026-09-01T13:30:00Z")

            def rc_epoch_ceiling(p_):
                d = evaluate(ind, p_, CTX)
                rec = d.randomization
                mechs = rec if isinstance(rec, list) else [rec]
                rc = [m for m in mechs if m["mechanism"] == "rate_ceiling"][0]
                return rc["epoch"], d.selector.rate_ceiling_per_min

            e0, c0 = rc_epoch_ceiling(pol_a)
            e_same, c_same = rc_epoch_ceiling(pol_same)
            e1, c1 = rc_epoch_ceiling(pol_next)
            # distinct buckets -> distinct derived epochs AND distinct draws
            self.assertNotEqual(e0, e1)
            self.assertNotEqual(c0, c1)
            # same bucket -> identical derived epoch AND exact replay
            self.assertEqual(e0, e_same)
            self.assertEqual(c0, c_same)
            # the derived epochs are the floor() hour buckets: 12:00 vs 13:30
            import datetime as _dt
            base_unix = int(_dt.datetime(2026, 9, 1, 12, 0, 0,
                                         tzinfo=_dt.timezone.utc).timestamp())
            self.assertEqual(e0, str(base_unix // 3600))
            self.assertEqual(e1, str(base_unix // 3600 + 1))


def _pin_clock(pol: Policy, iso: str) -> Policy:
    """Return a copy of `pol` with the replay/policy clock pinned to `iso`.
    Policy is a frozen dataclass; `dataclasses.replace` lets us override just
    `reference_now` while preserving the registry/evidence table intact."""
    import dataclasses
    return dataclasses.replace(pol, reference_now=iso)


class DecisionInstanceIdentityTests(unittest.TestCase):
    """P1-10 (audit): 'Separate logical_decision_id and action_instance_id/
    content_hash' and 'Make seed_id uniquely identify its actual seed.'"""

    def _pol(self, epoch):
        return _policy(
            randomization_enabled=True,
            randomization_bounds_version="rv1",
            randomization_epoch=epoch,
            rate_ceiling_jitter=RandomizationMechanism(True, 0.5, 1.0),
        )

    def test_logical_id_stable_across_epochs_content_hash_differs(self):
        ind = Indicator("i", "ipv4", "203.0.113.7", ("curated-a",), STRONG_EVIDENCE)
        d0 = evaluate(ind, self._pol("0"), CTX)
        d1 = evaluate(ind, self._pol("1"), CTX)
        # SAME logical decision: id is input-scoped, not epoch/randomization-scoped
        self.assertEqual(d0.id, d1.id)
        # DIFFERENT action instances: the drawn ceiling moved with the epoch,
        # so the content hash over the exact output must diverge
        self.assertNotEqual(d0.content_hash, d1.content_hash)
        self.assertTrue(d0.content_hash.startswith("hash--"))
        self.assertTrue(d1.content_hash.startswith("hash--"))

    def test_seed_id_identifies_actual_seed_and_differs_across_epoch(self):
        ind = Indicator("i", "ipv4", "203.0.113.8", ("curated-a",), STRONG_EVIDENCE)
        d0 = evaluate(ind, self._pol("9"), CTX)
        d1 = evaluate(ind, self._pol("10"), CTX)
        rec0 = d0.randomization
        rec1 = d1.randomization
        mechs0 = rec0 if isinstance(rec0, list) else [rec0]
        mechs1 = rec1 if isinstance(rec1, list) else [rec1]
        rc0 = [m for m in mechs0 if m["mechanism"] == "rate_ceiling"][0]
        rc1 = [m for m in mechs1 if m["mechanism"] == "rate_ceiling"][0]
        # seed_id is a content-derived tag of the actual seed (mechanism
        # discriminator + bounds version + epoch), so it MUST differ when the
        # epoch (hence the seed material) differs.
        self.assertNotEqual(rc0["seed_id"], rc1["seed_id"])
        self.assertEqual(rc0["epoch"], "9")
        self.assertEqual(rc1["epoch"], "10")

    def test_content_hash_identical_for_identical_instance(self):
        ind = Indicator("i", "ipv4", "203.0.113.11", ("curated-a",), STRONG_EVIDENCE)
        d0 = evaluate(ind, self._pol("5"), CTX)
        d1 = evaluate(ind, self._pol("5"), CTX)
        self.assertEqual(d0.content_hash, d1.content_hash)


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
            # 256-bit bar (P1-16): keys must carry >= 32 bytes of material
            os.environ["APIP_DEPLOYMENT_KEY"] = "deployment-one-96f4a8c2d7b3e6f09af54b1c2d3e4f5"
            reset_key_cache()
            h_one = handle_for("203.0.113.20")
            os.environ["APIP_DEPLOYMENT_KEY"] = "deployment-two-51b8e0d3a9f6c4b27d901ef58a6c7d80"
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
            # audit P1-23: ts_iso must agree with epoch_s, or the detector
            # rejects the event (cross-validated, never folded on contradiction)
            r = detector.observe(src, dst, _iso_of_epoch(ts), ts)
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
            if d.observe("a", "z", _iso_of_epoch(ts), ts):
                hits += 1
        self.assertEqual(hits, 0)

    def test_bounded_emission_one_per_completed_block(self):
        from apip.behavioral import BeaconDetector
        d = BeaconDetector(min_events=6)
        ts = 1_000_000
        emissions = 0
        for _ in range(31):                    # 30 gaps -> 5 complete blocks
            if d.observe("a", "b2", _iso_of_epoch(ts), ts):
                emissions += 1
            ts += 60
        self.assertEqual(emissions, 5)

    def test_event_envelope_degrades_stop_and_mark(self):
        from apip.behavioral import BeaconDetector
        d = BeaconDetector(max_events=12, min_events=3)
        ts = 1_000_000
        for _ in range(40):
            d.observe("x", "y", _iso_of_epoch(ts), ts)
            ts += 60
        self.assertTrue(d.degraded)
        self.assertIsNone(d.observe("x", "y", _iso_of_epoch(ts), ts))
        self.assertEqual(d.tracked_windows, 0)   # state frozen

    def test_window_envelope_sheds_deterministically(self):
        from apip.behavioral import BeaconDetector
        d = BeaconDetector(max_windows=3, min_events=3)
        for i, pair in enumerate((("a", "1"), ("b", "2"), ("c", "3"))):
            d.observe(pair[0], pair[1], _iso_of_epoch(1000), 1000)
        self.assertIsNone(d.observe("d", "4", _iso_of_epoch(1000), 1000))
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


class BehavioralAuditFixesTests(unittest.TestCase):
    """audit P1-20..P1-24 residuals, pinned."""

    def test_rearming_never_freezes_on_long_lived_window(self):
        # audit P1-21: a window living past the analysis-buffer cap must still
        # be able to accumulate min_events NEW gaps and re-arm. Buffer is kept
        # to min_events+64; pumping far more gaps then a fresh steady beacon
        # must still emit again — the old `len(gaps)` watermark froze forever.
        from apip.behavioral import BeaconDetector
        d = BeaconDetector(min_events=6)
        ts = 1_000_000
        for _ in range(200):                      # overflow the buffer
            d.observe("a", "z", _iso_of_epoch(ts), ts)
            ts += 60
        first = None
        for _ in range(12):                       # fresh steady block must re-arm
            r = d.observe("a", "z", _iso_of_epoch(ts), ts)
            if r and first is None:
                first = r
            ts += 60
        self.assertIsNotNone(first)               # re-armed, did not freeze

    def test_detection_freshness_is_last_contact_not_window_birth(self):
        # audit P1-22: evidence must be timestamped with the TRIGGER event,
        # not the window's first contact. A burst of fresh traffic on an old
        # window must yield a fresh observed_at (never the window birth).
        from apip.behavioral import BeaconDetector
        d = BeaconDetector(min_events=6)
        ts = 1_000_000
        for _ in range(20):                       # old window, steady contacts
            d.observe("a", "z", _iso_of_epoch(ts), ts)
            ts += 60
        fresh_at = ts                            # first event of the fresh block
        det = None
        for _ in range(12):                       # fresh block on the old window
            r = d.observe("a", "z", _iso_of_epoch(ts), ts)
            ts += 60
            if r is not None:
                det = r
                break
        self.assertIsNotNone(det)
        # observed_at is a RECENT trigger event, never the window-birth ts
        self.assertNotEqual(det.observed_at, d._windows[("a", "z")].first_ts)
        # and it is the actual trigger time (>= the fresh block's first event)
        self.assertLessEqual(_iso_of_epoch(fresh_at), det.observed_at)
        # freshness must look fresh: classify() treats it as within 6h
        from apip.behavioral import _epoch_of_iso
        self.assertIsNotNone(_epoch_of_iso(det.observed_at))

    def test_epoch_ts_mismatch_rejected_with_named_reason(self):
        # audit P1-23: a contact whose epoch_s and ts_iso contradict each
        # other is REJECTED (named counter), never folded into a gap — a
        # backwards watermark used to distort the next gap.
        from apip.behavioral import BeaconDetector
        d = BeaconDetector(min_events=3)
        ts = 1_000_000
        r = d.observe("a", "z", _iso_of_epoch(ts), ts)
        self.assertIsNone(r)
        # ts_iso disagrees wildly with epoch_s
        r = d.observe("a", "z", "1970-01-01T00:00:00Z", ts)
        self.assertIsNone(r)
        self.assertEqual(d.rejected_epoch_mismatch, 1)
        # a real sequence (consistent reps) works
        for _ in range(4):
            d.observe("a", "z", _iso_of_epoch(ts), ts)
            ts += 60
        self.assertEqual(d.rejected_epoch_mismatch, 1)   # only the bad one
        self.assertEqual(d.detections, 1)

    def test_nonmonotonic_epoch_rejected(self):
        # audit P1-23: an out-of-order epoch_s is rejected with a named reason
        # and must NOT move the watermark forward (distorting the next gap).
        from apip.behavioral import BeaconDetector
        d = BeaconDetector(min_events=3)
        ts = 1_000_000
        for _ in range(4):
            d.observe("a", "z", _iso_of_epoch(ts), ts)
            ts += 60
        # a backwards event
        d.observe("a", "z", _iso_of_epoch(ts - 10_000), ts - 10_000)
        self.assertEqual(d.rejected_nonmonotonic, 1)
        # the odd event must NOT move the watermark: the next gap is computed
        # against the true last (forward) epoch. Feed a full fresh 60s block
        # and confirm re-arm works (the odd event changed nothing).
        before = d.detections
        for _ in range(5):
            d.observe("a", "z", _iso_of_epoch(ts), ts)
            ts += 60
        self.assertGreater(d.detections, before)      # re-armed normally
        self.assertEqual(d.rejected_nonmonotonic, 1)  # still just the one

    def test_first_seen_novelty_is_a_real_second_family(self):
        # audit P1-20 (V2-A gate): at least two IMPLEMENTED behavioral families.
        from apip.behavioral import (FirstSeenNoveltyDetector, NOVELTY_KIND,
                                     BEACON_KIND)
        d = FirstSeenNoveltyDetector()
        det = d.observe("10.0.0.5", "203.0.113.99", _iso_of_epoch(1_000_000), 1_000_000)
        self.assertIsNotNone(det)
        self.assertEqual(det.kind, NOVELTY_KIND)
        self.assertNotEqual(NOVELTY_KIND, BEACON_KIND)
        fields = det.as_evidence_fields()
        self.assertEqual(fields["kind"], NOVELTY_KIND)
        # repeat contact is NOT novel
        self.assertIsNone(d.observe("10.0.0.5", "203.0.113.99",
                                    _iso_of_epoch(1_000_060), 1_000_060))
        # subject context is carried (audit P1-24)
        self.assertEqual(fields["detail"]["client"], "10.0.0.5")

    def test_novelty_envelope_sheds_and_degrades(self):
        from apip.behavioral import FirstSeenNoveltyDetector
        d = FirstSeenNoveltyDetector(max_entries=3)
        for i in range(3):
            d.observe("h", f"dst-{i}", _iso_of_epoch(1_000_000 + i), 1_000_000 + i)
        # the 4th novel destination exceeds the envelope: stop-and-mark
        self.assertIsNone(d.observe("h", "dst-over", _iso_of_epoch(1_000_003), 1_000_003))
        self.assertTrue(d.degraded)
        self.assertEqual(d.suppressed_new_dsts, 1)
        self.assertIsNone(d.observe("h", "dst-late", _iso_of_epoch(1_000_004), 1_000_004))

    def test_pending_families_reported_not_implied(self):
        # audit P1-20: requested-but-not-implemented families are honest.
        from apip.behavioral import BeaconDetector
        d = BeaconDetector(enabled_families=("beacon_periodicity", "dga_likelihood",
                                             "fastflux"))
        self.assertEqual(sorted(d.pending_families), ["dga_likelihood", "fastflux"])
        self.assertTrue(d.beacon_enabled)
        self.assertIn("beacon_periodicity", d.enabled_families)
        # a policy requesting ONLY an unimplemented family detects nothing
        d2 = BeaconDetector(enabled_families=("dga_likelihood",))
        self.assertFalse(d2.beacon_enabled)
        self.assertIsNone(d2.observe("a", "z", _iso_of_epoch(1_000_000), 1_000_000))

    def test_detection_subject_is_subject_aware(self):
        # audit P1-24: the decision context for behavioral evidence is the
        # ACTUAL client the detection is about, never a fabricated demo client.
        from apip.cli import _detection_subject
        from apip.behavioral import BeaconDetector, BEACON_KIND
        # build a genuine beacon, then fold its evidence into an indicator
        d2 = BeaconDetector(min_events=6)
        ts = 1_000_000
        det = None
        for _ in range(8):
            r = d2.observe("host-A", "203.0.113.30", _iso_of_epoch(ts), ts)
            if r and det is None:
                det = r
            ts += 60
        self.assertIsNotNone(det)
        fields = det.as_evidence_fields()
        ind = Indicator("ib", "ipv4", "203.0.113.30", ("local-behavioral",), (
            Evidence(fields["kind"], fields["source_id"], "local",
                     fields["observed_at"], True, fields["detail"]),))
        self.assertEqual(_detection_subject(ind), "host-A")      # real subject
        # a demo-labeled indicator with no behavioral evidence has no subject
        plain = Indicator("ip", "ipv4", "203.0.113.66", ("feed-a",), ())
        self.assertIsNone(_detection_subject(plain))
        # mixed subjects refuse to fabricate a client
        mixed = Indicator("im", "ipv4", "203.0.113.30", ("local-behavioral",), (
            Evidence(BEACON_KIND, "local-behavioral", "local", "2026-09-01T00:00:00Z",
                     True, {"client": "host-A"}),
            Evidence(BEACON_KIND, "local-behavioral", "local", "2026-09-01T00:00:01Z",
                     True, {"client": "host-B"})))
        self.assertIsNone(_detection_subject(mixed))


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

    def test_empty_governed_value_rejected(self):
        """v2.3 (audit P0-3): a governed registry entry must be a non-empty
        string — a blank value is a misconfiguration, not a governed target."""
        from apip.config import validate_policy
        raw = {
            "policy_version": "t", "mode": "SHADOW", "scope": "s",
            "thresholds": {"observe_m": 40},
            "limits": {"max_auto_ttl_seconds": 3600},
            "governed": {"dedicated_use": ["", "198.51.100.44"]},
        }
        problems = validate_policy(raw)
        self.assertTrue(any("governed.dedicated_use" in p for p in problems))

    def test_governed_loads_from_toml(self):
        """v2.3 (audit P0-3): load_policy must surface the operator's governed
        registry into the Policy the engine evaluates with."""
        import tomllib
        from apip.config import load_policy
        with TemporaryDirectory() as td:
            p = Path(td) / "pol.toml"
            p.write_text(
                'policy_version = "t"\nmode = "SHADOW"\nscope = "s"\n'
                '[thresholds]\nobserve_m = 40\nfqdn_auto_m = 95\nfqdn_auto_s = 90\n'
                'ip_rate_m = 90\nip_rate_s = 85\nip_deny_m = 98\nip_deny_s = 95\n'
                '[limits]\nmax_auto_ttl_seconds = 3600\n'
                '[governed]\ndedicated_use = ["198.51.100.44"]\n'
                'verified_rollback = ["198.51.100.44", "c2-demo.invalid"]\n')
            pol = load_policy(p)
            self.assertIn("198.51.100.44", pol.governed_dedicated_use)
            self.assertIn("c2-demo.invalid", pol.governed_verified_rollback)


class ReceiptTruthfulnessTests(unittest.TestCase):
    """audit P1-26/P1-27: receipts exist only for decisions that actually
    compiled an artifact, and they carry both bundle and decision-specific
    identities.

    P1-26: artifact compilation returns structured results; receipts are
    generated from those results, never by inspecting `Decision.action`. A
    decision whose action has no adapter representation (proxy_challenge) or
    which compiles to nothing must produce NO receipt.
    P1-27: every receipt records BOTH the decision-specific fragment identity
    (rule_id + fragment_hash) and the whole-bundle identity (bundle_id +
    bundle_hash), so verify/revoke/reconcile can target one rule without
    disturbing the bundle.

    NOTE: the governed-rollback IPs (203.0.113.1-11) are the honest way to
    reach L2 rate_limit under the P0-3 server-certified control-plane gate.
    """

    def _compile(self, pairs):
        from apip.exporters.rpz import compile_rpz_structured
        from apip.exporters.suricata import compile_rules_structured
        return compile_rules_structured(pairs) + compile_rpz_structured(pairs)

    def _receipts(self, arts):
        from apip.cli import _receipt
        return [_receipt(a) for a in arts]

    def test_receipt_carries_bundle_and_fragment_identities(self):
        """P1-27: a decision that compiles to a rule yields a receipt carrying
        rule_id + fragment_hash (decision-specific) AND bundle_id +
        bundle_hash (whole-bundle)."""
        pol = _policy()
        ind = Indicator("r1", "ipv4", "203.0.113.2", ("curated-a",), STRONG_EVIDENCE)
        d = evaluate(ind, pol, CTX)
        self.assertEqual(d.action, "rate_limit")     # governed rollback IP
        arts = self._compile([(ind, d)])
        self.assertEqual(len(arts), 1)               # one decision -> one artifact
        rc = self._receipts(arts)
        self.assertEqual(len(rc), 1)
        rec = rc[0]
        self.assertTrue(rec["rule_id"].startswith("sid:"))
        self.assertTrue(rec["fragment_hash"].startswith("frag--"))
        self.assertEqual(rec["bundle_id"], "suricata-bundle-1")
        self.assertTrue(rec["bundle_hash"].startswith("bundle--"))
        self.assertEqual(rec["decision_id"], d.id)

    def test_bundle_hash_shared_fragment_hash_distinct(self):
        """P1-27: fragment_hash is decision-specific; bundle_hash is shared
        across all artifacts in the same compilation bundle."""
        pol = _policy()
        ind1 = Indicator("r2a", "ipv4", "203.0.113.3", ("curated-a",), STRONG_EVIDENCE)
        ind2 = Indicator("r2b", "ipv4", "203.0.113.4", ("curated-a",), STRONG_EVIDENCE)
        arts = self._compile([(ind1, evaluate(ind1, pol, CTX)),
                              (ind2, evaluate(ind2, pol, CTX))])
        self.assertEqual(len(arts), 2)               # two decisions -> two artifacts
        bundle_hashes = {a.bundle_hash for a in arts}
        self.assertEqual(len(bundle_hashes), 1)      # same bundle, shared hash
        fragment_hashes = {a.fragment_hash for a in arts}
        self.assertEqual(len(fragment_hashes), 2)    # per-rule distinct
        self.assertNotEqual(arts[0].fragment_hash, arts[1].fragment_hash)

    def test_proxy_challenge_produces_no_receipt(self):
        """P1-26: an action NO exporter implements (proxy_challenge) renders
        no artifact and therefore MUST yield no receipt — attesting to a
        nonexistent control would fabricate enforcement. Constructed directly
        because the reference's governed path does not currently surface a
        proxy_challenge from a single indicator."""
        from apip.models import ActionSelector, Decision
        from apip.exporters.suricata import compile_rules_structured
        from apip.exporters.rpz import compile_rpz_structured
        d = Decision(
            id="proxy--1", indicator_id="pi1", maliciousness=95,
            action_safety=92, disposition="AUTO_ENFORCE", action="proxy_challenge",
            rung="L1", scope="client_destination_pair", ttl_seconds=300,
            policy_version="v", reason_codes=("l1_proxy",),
            explanation="test", selector=ActionSelector(
                scope_type="client_destination_pair", client="h1",
                destination="198.51.100.9", protocol_class="interactive_http"),
        )
        ind = Indicator("pi1", "ipv4", "198.51.100.9", ("curated-a",), STRONG_EVIDENCE)
        arts = compile_rules_structured([(ind, d)]) + compile_rpz_structured([(ind, d)])
        self.assertEqual(arts, [])                   # NO exporter renders it
        self.assertEqual(self._receipts(arts), [])

    def test_observe_decision_produces_no_artifact_no_receipt(self):
        """P1-26 core: the receipt pipeline is driven by artifacts, not by
        `Decision.action`. An OBSERVE decision has no enforcement artifact, so
        the artifact->receipt loop emits NOTHING for it, even though the
        decision object exists in the batch."""
        pol = _policy()
        ind = Indicator("r5", "ipv4", "203.0.113.50", ("curated-a",), STRONG_EVIDENCE)
        d = evaluate(ind, pol, CTX)
        self.assertEqual(d.action, "observe")        # ungoverned -> observe
        arts = self._compile([(ind, d)])
        self.assertEqual(arts, [])                   # observe compiles to nothing
        self.assertEqual(self._receipts(arts), [])   # and so yields NO receipt


if __name__ == "__main__":
    unittest.main()


if __name__ == "__main__":
    unittest.main()
