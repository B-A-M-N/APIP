"""Seeded deterministic randomization — byte-compatible port of
``reference/src/apip/randomize.py`` (docs/29).

Same SHA-256 counter-mode DRBG, same integer fixed-point arithmetic, so a
seed reproduced in the production engine draws exactly what the oracle draws
(differential tests pin this). Drawn values are reproducible parameter
diversity, NOT cryptographic unpredictability.
"""
from __future__ import annotations

import hashlib


class ApipRng:
    """Deterministic SHA-256 counter-mode DRBG (docs/29, audit P1-11)."""

    def __init__(self, seed_material: str):
        self._key = hashlib.sha256(("apip-drbg-v1|" + seed_material).encode()).digest()
        self._counter = 0
        self._buf = b""

    def _refill(self) -> None:
        self._buf = hashlib.sha256(self._key + self._counter.to_bytes(8, "big")).digest()
        self._counter += 1

    def next_uniform_micros(self, lo_micros: int, hi_micros: int) -> int:
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
    if nominal <= 0:
        return 0, 1_000_000
    lo_m = int(round(max(0.0, min(lo, hi)) * 1_000_000))
    hi_m = int(round(max(lo, hi) * 1_000_000))
    frac_micros = rng.next_uniform_micros(lo_m, hi_m)
    value = max(minimum, min(nominal, (nominal * frac_micros) // 1_000_000))
    return value, frac_micros
