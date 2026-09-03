from __future__ import annotations
"""
Seeded deterministic randomization (docs/29, v2.1).

A dependency-free deterministic DRBG built on SHA-256 counter mode.
Seed material includes the policy epoch bucket, so the same indicator +
policy draws differently across time windows (moving-target property)
while replay within an epoch reproduces the exact draw. Bounds are
enforced DOWNSTREAM of the draw; all arithmetic is integer fixed-point
so cross-language replay cannot diverge on float rounding.
"""
import hashlib

class ApipRng:
    """Deterministic SHA-256 counter-mode DRBG (docs/29, audit P1-11).

    Drawn values are REPRODUCIBLE deterministic parameter diversity, NOT
    cryptographic unpredictability: every seed input (indicator identity,
    policy version, scores, scope, bounds version, epoch) is recorded in the
    decision, so an observer holding a past decision can reconstruct the seed
    and predict draws that share it. For observer-unpredictable windows the
    operator must add a per-window secret at the edge (see docs/29 "Security
    model"); this class never claims secret-key CSPRNG strength."""

    def __init__(self, seed_material: str):
        self._key = hashlib.sha256(("apip-drbg-v1|" + seed_material).encode()).digest()
        self._counter = 0
        self._buf = b""

    def _refill(self) -> None:
        self._buf = hashlib.sha256(self._key + self._counter.to_bytes(8, "big")).digest()
        self._counter += 1

    def next_uniform_micros(self, lo_micros: int, hi_micros: int) -> int:
        """Uniform draw in [lo_micros, hi_micros] as INTEGER microseconds.

        Fixed-point: a value x in [0, 2^64) is scaled to the range with
        integer arithmetic only. Cross-language replay is exact.
        """
        if hi_micros < lo_micros:
            lo_micros, hi_micros = hi_micros, lo_micros
        if hi_micros == lo_micros:
            return lo_micros
        while len(self._buf) < 8:
            self._refill()
        word = int.from_bytes(self._buf[:8], "big")
        self._buf = self._buf[8:]
        span = hi_micros - lo_micros
        return lo_micros + (word % (span + 1))


def draw_ttl_jitter(rng: ApipRng, nominal_ttl: int, lo: float, hi: float) -> tuple[int, int]:
    """Draw a jittered TTL as a fraction of nominal, bounds-clamped.

    Bounds are converted to integer microseconds once; the draw is integer.
    Returns (actual_ttl, ttl_fraction_micros). Downstream clamp guarantees
    no draw exceeds policy bounds regardless of RNG behavior.
    """
    if nominal_ttl <= 0:
        return 0, 1_000_000
    lo_m = int(round(max(0.0, min(lo, hi)) * 1_000_000))
    hi_m = int(round(max(lo, hi) * 1_000_000))
    frac_micros = rng.next_uniform_micros(lo_m, hi_m)
    actual = (nominal_ttl * frac_micros) // 1_000_000
    actual = max(1, min(actual, nominal_ttl))  # hard downstream clamp
    return actual, frac_micros


def draw_scaled_integer(rng: ApipRng, nominal: int, lo: float, hi: float,
                        minimum: int = 1) -> tuple[int, int]:
    """Draw a value in [lo, hi] × nominal as a bounded integer.

    Generic bounded-fraction draw (docs/29): used for the L2 rate ceiling
    (fraction of the nominal per-minute ceiling) and any future mechanism
    that scales a policy nominal. Integer fixed-point throughout; the
    downstream clamp guarantees no draw escapes the bounds regardless of
    RNG behavior. Returns (value, fraction_micros).
    """
    if nominal <= 0:
        return 0, 1_000_000
    lo_m = int(round(max(0.0, min(lo, hi)) * 1_000_000))
    hi_m = int(round(max(lo, hi) * 1_000_000))
    frac_micros = rng.next_uniform_micros(lo_m, hi_m)
    value = max(minimum, min(nominal, (nominal * frac_micros) // 1_000_000))
    return value, frac_micros
