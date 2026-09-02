"""Bounded streaming behavioral detector — reference implementation (docs/23).

The audit's largest stated gap: resource envelopes for the behavioral suite
were specified but no reference detector existed to bound, so nothing
exercised the docs/23 discipline in code. This module is that reference:
a deterministic beacon-periodicity detector (BD-1) over (source,destination)
contact windows with the full envelope contract enforced in code:

  - bounded state: at most `max_windows` tracked pairs; overflow sheds new
    windows (counted), never evicts silently;
  - bounded work: at most `max_events` events total; exceeding the envelope
    freezes detection state and marks the detector degraded
    (stop-and-mark). Degradation can only REDUCE detections, never inflate
    them — the failure direction is inert;
  - deterministic arithmetic: periodicity over integer-second gaps with
    fixed-point ratio math (no floats in the verdict path);
  - evidence, not authority: a detection is a fact with kind
    `behavioral_beacon_periodicity`, class `local` — it enters the same
    weight table and corroboration lattice as any local evidence and can
    never exceed the behavioral caps.

Beacon logic (deliberately simple, deliberately mechanical): a window with
>= min_events contacts whose consecutive gaps are all within tolerance of
the window's median gap — i.e. low jitter ratio — and whose median gap
falls in the plausible beacon band, emits one detection. No training, no
inference: median and ratio, integers only.
"""
from __future__ import annotations
from dataclasses import dataclass, field

BEACON_KIND = "behavioral_beacon_periodicity"

# Plausible beacon intervals (integer seconds): between 10s and 1h.
MIN_MEDIAN_GAP_S = 10
MAX_MEDIAN_GAP_S = 3600
# Jitter band as fixed-point micros of the median: |gap - median|/median
# must fall within [0, tolerance] for every gap in the window.
DEFAULT_TOLERANCE_MICROS = 250_000   # 0.25


def _median(sorted_vals: list[int]) -> int:
    n = len(sorted_vals)
    mid = n // 2
    if n % 2:
        return sorted_vals[mid]
    return (sorted_vals[mid - 1] + sorted_vals[mid]) // 2


@dataclass
class _Window:
    src: str
    dst: str
    first_ts: str          # window birth (eviction order key)
    last_epoch_s: int
    gaps: list[int] = field(default_factory=list)
    # emission watermark (docs/23 bounded emission): a window emits at most
    # one Detection per completed block of min_events gaps — re-arming
    # requires min_events NEW gaps. Bounded emission per window, forever.
    emitted_at_count: int = 0


@dataclass(frozen=True)
class Detection:
    """One emitted behavioral fact — an evidence record in the making."""
    src: str
    dst: str
    median_gap_s: int
    events: int
    observed_at: str

    def as_evidence_fields(self) -> dict:
        """Fields for an apip.models.Evidence record (kind/source fixed)."""
        return {
            "kind": BEACON_KIND,
            "source_id": "local-behavioral",
            "observed_at": self.observed_at,
            "detail": {"median_gap_s": self.median_gap_s, "events": self.events},
        }


class BeaconDetector:
    """Bounded, deterministic beacon-periodicity detector (docs/23 BD-1)."""

    KIND = "beacon_periodicity"

    def __init__(self, max_windows: int = 50_000, max_events: int = 1_000_000,
                 min_events: int = 6,
                 tolerance_micros: int = DEFAULT_TOLERANCE_MICROS):
        if min_events < 3:
            raise ValueError("min_events must be >= 3 (periodicity needs a gap sequence)")
        self._max_windows = max_windows
        self._max_events = max_events
        self._min_events = min_events
        self._tol = tolerance_micros
        self._windows: dict[tuple[str, str], _Window] = {}
        self._events = 0
        self.degraded = False            # stop-and-mark flag (docs/23)
        self.detections = 0
        self.suppressed_new_windows = 0  # telemetry for the degraded state

    # -- envelope introspection -------------------------------------------

    @property
    def tracked_windows(self) -> int:
        return len(self._windows)

    # -- ingestion ----------------------------------------------------------

    def observe(self, src: str, dst: str, ts_iso: str, epoch_s: int) -> Detection | None:
        """Fold one contact event into its window; emit a Detection when the
        window first crosses the periodicity bar.

        Degradation semantics (stop-and-mark): once the event envelope is
        exhausted, NEW windows are not tracked and NEW detection stops.
        Existing windows continue only until they too would emit — no, they
        stop emitting as well: degradation freezes detection state so the
        detector can only ever under-detect, never over-detect, while
        overloaded. Envelope overflow of a single window's gap list is
        bounded implicitly by max_events per window accounting.
        """
        if self.degraded:
            return None
        key = (src, dst)
        w = self._windows.get(key)
        if w is None:
            if len(self._windows) >= self._max_windows:
                # window-count envelope reached: shed this event
                self.suppressed_new_windows += 1
                if self._events >= self._max_events:
                    self._mark_degraded()
                return None
            if self._events >= self._max_events:
                self._mark_degraded()
                return None
            w = _Window(src=src, dst=dst, first_ts=ts_iso, last_epoch_s=epoch_s)
            self._windows[key] = w
        if self._events >= self._max_events:
            self._mark_degraded()
            return None
        self._events += 1
        gap = epoch_s - w.last_epoch_s
        w.last_epoch_s = epoch_s
        if gap > 0:
            w.gaps.append(gap)
            if len(w.gaps) > self._min_events + 64:
                # per-window bound: keep the most recent gaps (stable order)
                w.gaps = w.gaps[-(self._min_events + 64):]
        if len(w.gaps) < self._min_events:
            return None
        # bounded emission: only when a NEW complete block of min_events
        # gaps has accumulated since the last emission
        if len(w.gaps) - w.emitted_at_count < self._min_events:
            return None
        det = self._evaluate(w)
        if det is not None:
            w.emitted_at_count = len(w.gaps)
            self.detections += 1
        return det

    def _mark_degraded(self) -> None:
        # stop-and-mark: freeze all state; degraded detectors detect nothing
        self.degraded = True
        self._windows.clear()

    # -- deterministic verdict ------------------------------------------------

    def _evaluate(self, w: _Window) -> Detection | None:
        """Median-gap periodicity over integers; fixed-point ratio:
        |gap-median|*1e6 // median <= tol for every gap in the window."""
        ordered = sorted(w.gaps)
        median = _median(ordered)
        if not (MIN_MEDIAN_GAP_S <= median <= MAX_MEDIAN_GAP_S):
            return None
        for g in ordered:
            if median == 0:
                return None
            dev_micros = abs(g - median) * 1_000_000 // median
            if dev_micros > self._tol:
                return None
        # every gap inside the band: deterministic detection
        return Detection(src=w.src, dst=w.dst, median_gap_s=median,
                         events=len(w.gaps), observed_at=w.first_ts)

    # -- eviction (deterministic) ---------------------------------------------

    def evict_oldest(self, count: int = 1) -> int:
        """Oldest-window-start-first eviction with (src,dst) tiebreak —
        the same discipline as the correlation store, deterministic."""
        removed = 0
        for _ in range(min(count, len(self._windows))):
            oldest = min(self._windows.values(),
                         key=lambda w: (w.first_ts, w.src, w.dst))
            del self._windows[(oldest.src, oldest.dst)]
            removed += 1
        return removed

    def as_evidence(self, det: Detection) -> dict:
        return det.as_evidence_fields()
