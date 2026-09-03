import unittest
from apip.models import Indicator, Evidence
from apip.policy import Policy, RungFloor, RandomizationMechanism, evaluate
from apip.registry import SourceRegistry, SourceProfile
from apip.randomize import ApipRng, draw_ttl_jitter

REG = SourceRegistry((SourceProfile("curated-a", "curated", True),))

def _pol(epoch="0", rz=True):
    return Policy(
        version="v1", mode="ENFORCE", scope="t",
        observe_m=40, fqdn_auto_m=95, fqdn_auto_s=90,
        ip_rate_m=90, ip_rate_s=85, ip_deny_m=98, ip_deny_s=95,
        max_auto_ttl_seconds=3600, auto_prefix_deny=False,
        auto_routing=False, auto_wildcard_domain=False,
        rung_floors={"L4": RungFloor(95, 90)},
        source_registry=REG,
        randomization_enabled=rz,
        randomization_bounds_version="rv-test.1",
        randomization_epoch=epoch,
        ttl_jitter=RandomizationMechanism(enabled=True, lo=0.8, hi=1.0),
        # audit P0-3: `_ind()` asserts verified_rollback/dedicated_use on the
        # test target; the policy must declare it governed to reach the rung
        # (the TTL jitter these tests exercise is an L4 action).
        governed_dedicated_use=("bad.invalid",),
        governed_verified_rollback=("bad.invalid",),
    )

def _ind():
    return Indicator("x", "fqdn", "bad.invalid", ("curated-a",), (
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
        Evidence(kind="dedicated_use", source_id="curated-a", source_class="x",
                 observed_at="2026-09-01T20:00:00Z", independent=True),
    ))

CTX = {"client": "host-1", "protocol_class": "interactive_http"}

class RngTests(unittest.TestCase):
    def test_replay_reproduces_exact_draw(self):
        a = ApipRng("seed-material-1|epoch-42")
        b = ApipRng("seed-material-1|epoch-42")
        c = ApipRng("seed-material-1|epoch-43")
        da = [a.next_uniform_micros(800_000, 1_000_000) for _ in range(100)]
        db = [b.next_uniform_micros(800_000, 1_000_000) for _ in range(100)]
        dc = [c.next_uniform_micros(800_000, 1_000_000) for _ in range(100)]
        self.assertEqual(da, db)            # replay within epoch: exact
        self.assertNotEqual(da, dc)         # epoch changes the stream

    def test_draws_within_bounds_and_integer(self):
        rng = ApipRng("bounds")
        for _ in range(1000):
            v = rng.next_uniform_micros(500_000, 1_000_000)
            self.assertIsInstance(v, int)
            self.assertGreaterEqual(v, 500_000)
            self.assertLessEqual(v, 1_000_000)

    def test_ttl_jitter_always_in_bounds(self):
        rng = ApipRng("ttl")
        for _ in range(500):
            ttl, frac = draw_ttl_jitter(rng, 3600, 0.8, 1.0)
            self.assertGreaterEqual(frac, 800_000)
            self.assertLessEqual(frac, 1_000_000)
            self.assertGreaterEqual(ttl, 1)
            self.assertLessEqual(ttl, 3600)

class StatisticalPropertyTests(unittest.TestCase):
    """docs/29 CR6: over a large sample, draws are uniform within bounds,
    cross-mechanism streams are independent (correlated draws would let one
    observed parameter predict another), and the integer counter mode shows
    no short cycle within the operational horizon."""

    N = 20_000

    def test_uniformity_within_bounds(self):
        from apip.randomize import ApipRng
        rng = ApipRng("uniformity")
        lo, hi = 0, 999
        draws = [rng.next_uniform_micros(lo, hi) for _ in range(self.N)]
        in_bounds = all(lo <= v <= hi for v in draws)
        self.assertTrue(in_bounds)
        mean = sum(draws) / len(draws)
        # uniform over [0,999] -> expected mean 499.5; allow a wide band.
        self.assertTrue(470 <= mean <= 530, f"mean {mean:.1f} off-uniform")
        # no quarter is empty or starved (crude uniformity cell check)
        for quarter in range(4):
            cell = sum(1 for v in draws if v // 250 == quarter)
            self.assertGreater(cell, self.N // 8)

    def test_independent_streams(self):
        # two mechanisms draw from their OWN streams (seed + mechanism tag);
        # a large interleaved sample must not show pairwise predictability
        # (Pearson |r| far below a correlated-echo signature).
        from apip.randomize import ApipRng
        a = ApipRng("mech-a|s")
        b = ApipRng("mech-b|s")
        xa = [a.next_uniform_micros(0, 99) for _ in range(10_000)]
        xb = [b.next_uniform_micros(0, 99) for _ in range(10_000)]
        ma, mb = sum(xa) / len(xa), sum(xb) / len(xb)
        cov = sum((xa[i] - ma) * (xb[i] - mb) for i in range(len(xa)))
        va = sum((v - ma) ** 2 for v in xa)
        vb = sum((v - mb) ** 2 for v in xb)
        r = cov / (va * vb) ** 0.5 if va and vb else 0.0
        self.assertLess(abs(r), 0.05, f"cross-mechanism correlation r={r:.3f}")

    def test_no_short_cycle(self):
        from apip.randomize import ApipRng
        rng = ApipRng("cycle")
        seen = set()
        # 50k draws from the counter-mode word stream must be collision-free
        # in the low word (a 64-bit counter feed would repeat at 2^64, far
        # beyond the operational horizon) — a short cycle would replay.
        for _ in range(50_000):
            w = rng.next_uniform_micros(0, 2**32 - 1)
            self.assertNotIn(w, seen)
            seen.add(w)


class EpochMovingTargetTests(unittest.TestCase):
    def test_same_indicator_differs_across_epochs(self):
        # docs/29 v2.1: the moving-target property. Draw #1 (epoch 0) must
        # not deterministically equal draw #2 (epoch 1).
        d0 = evaluate(_ind(), _pol(epoch="0"), CTX)
        d1 = evaluate(_ind(), _pol(epoch="1"), CTX)
        self.assertIsNotNone(d0.randomization)
        self.assertIsNotNone(d1.randomization)
        self.assertNotEqual(
            d0.randomization["draw"]["ttl_fraction_micros"],
            d1.randomization["draw"]["ttl_fraction_micros"])

    def test_replay_within_epoch_is_exact(self):
        d0a = evaluate(_ind(), _pol(epoch="7"), CTX)
        d0b = evaluate(_ind(), _pol(epoch="7"), CTX)
        self.assertEqual(d0a.randomization, d0b.randomization)
        self.assertEqual(d0a.id, d0b.id)

    def test_draw_record_carries_epoch(self):
        d = evaluate(_ind(), _pol(epoch="9"), CTX)
        self.assertEqual(d.randomization["epoch"], "9")

    def test_no_randomization_when_disabled(self):
        d = evaluate(_ind(), _pol(rz=False), CTX)
        self.assertIsNone(d.randomization)
        self.assertEqual(d.ttl_seconds, d.nominal_ttl_seconds)

if __name__ == "__main__":
    unittest.main()
