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
NOVELTY_KIND = "behavioral_first_seen_novelty"

# Plausible beacon intervals (integer seconds): between 10s and 1h.
MIN_MEDIAN_GAP_S = 10
MAX_MEDIAN_GAP_S = 3600
# Jitter band as fixed-point micros of the median: |gap - median|/median
# must fall within [0, tolerance] for every gap in the window.
DEFAULT_TOLERANCE_MICROS = 250_000   # 0.25

# audit P1-20: schema/policy enums advertise many families; only these are
# IMPLEMENTED in the reference. The rest are explicitly PENDING — beta
# honesty requires not letting enum presence look like detector existence.
# `enabled_families` in policy gates the runtime to the implemented subset.
IMPLEMENTED_FAMILIES = frozenset({"beacon_periodicity", "first_seen_novelty"})
PENDING_FAMILIES = frozenset({"dga_likelihood", "dns_tunneling", "fastflux",
                              "volume_anomaly", "tls_metadata_mismatch",
                              "sync_first_contact"})

# audit P1-23: epoch (unix int) and ts_iso must agree within this wallclock
# tolerance (seconds). Beyond it they are two timestamps of the same moment
# that contradict one another — the event is rejected, never folded.
EPOCH_TS_TOLERANCE_S = 120


def _median(sorted_vals: list[int]) -> int:
    n = len(sorted_vals)
    mid = n // 2
    if n % 2:
        return sorted_vals[mid]
    return (sorted_vals[mid - 1] + sorted_vals[mid]) // 2


def _epoch_of_iso(ts_iso: str) -> int | None:
    """Parse an ISO-8601 instant to a unix epoch (seconds), or None on any
    malformed shape. Used for the P1-23 cross-check — a single canonical
    instant behind both representations."""
    from datetime import datetime, timezone
    try:
        normalized = ts_iso.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except (ValueError, TypeError, OverflowError):
        return None


@dataclass
class _Window:
    src: str
    dst: str
    first_ts: str          # window birth (eviction order key)
    last_ts: str           # most recent contact instant (evidence freshness)
    last_epoch_s: int
    gaps: list[int] = field(default_factory=list)
    # audit P1-21: the analysis BUFFER (gaps, bounded) and the LIFETIME
    # emission counter (never truncated) are separate. Re-arming requires a
    # brand-new complete block of min_events POSITIVE gaps since the last
    # emission; a monotonic lifetime count keeps that reachable past the
    # buffer cap (previously `len(gaps)` froze, so a long-lived window
    # could never re-arm — P1-21).
    total_gaps: int = 0
    emitted_total: int = 0


@dataclass(frozen=True)
class Detection:
    """One emitted behavioral fact — an evidence record in the making.

    audit P1-22: `observed_at` is the ACTUAL trigger event's instant (the
    last contact), never the window-birth timestamp — fresh activity must
    not look stale. audit P1-24: `src` (the subject/client) is carried
    through so corroboration can be subject-aware instead of losing the
    client to a destination-global merge.
    """
    src: str
    dst: str
    median_gap_s: int
    events: int
    observed_at: str
    first_seen: str
    kind: str = BEACON_KIND            # evidence kind discriminates the family

    def as_evidence_fields(self) -> dict:
        """Fields for an apip.models.Evidence record (kind/source fixed)."""
        detail: dict = {"client": self.src, "first_seen": self.first_seen}
        if self.kind == BEACON_KIND:
            detail.update({"median_gap_s": self.median_gap_s,
                           "events": self.events})
        return {
            "kind": self.kind,
            "source_id": "local-behavioral",
            "observed_at": self.observed_at,
            # the subject/client is retained as decision context (P1-24);
            # detail carries only named facts, never authority.
            "detail": detail,
        }


class BeaconDetector:
    """Bounded, deterministic beacon-periodicity detector (docs/23 BD-1)."""

    KIND = "beacon_periodicity"

    def __init__(self, max_windows: int = 50_000, max_events: int = 1_000_000,
                 min_events: int = 6,
                 tolerance_micros: int = DEFAULT_TOLERANCE_MICROS,
                 enabled_families: tuple[str, ...] | None = None):
        """A beacon-periodicity detector. `enabled_families` (audit P1-20) is
        the operator's policy gate: families requested but not IMPLEMENTED are
        recorded on `pending_families` (so the run can say so honestly), and
        only the implemented+enabled ones actually detect."""
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
        self.rejected_nonmonotonic = 0   # audit P1-23: out-of-order events
        self.rejected_epoch_mismatch = 0 # audit P1-23: epoch/ts disagreement
        # -- audit P1-20: family gating ---
        enabled = set(enabled_families) if enabled_families is not None else set(IMPLEMENTED_FAMILIES)
        requested_pending = sorted(enabled & PENDING_FAMILIES)
        self.pending_families: tuple[str, ...] = tuple(requested_pending)
        self.enabled_families: frozenset[str] = frozenset(
            enabled & IMPLEMENTED_FAMILIES)
        self.beacon_enabled = "beacon_periodicity" in self.enabled_families

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
        if self.degraded or not self.beacon_enabled:
            return None
        # audit P1-23: one canonical instant behind BOTH representations. If
        # the epoch and the ISO string are two timestamps of the same moment
        # that disagree beyond tolerance, reject the event with a named reason
        # — never fold a contradictory pair. Also reject non-monotonic epochs
        # (a backwards epoch_s previously overwrote last_epoch_s and distorted
        # the next gap even though the negative gap was ignored).
        iso_epoch = _epoch_of_iso(ts_iso)
        if iso_epoch is not None and abs(iso_epoch - epoch_s) > EPOCH_TS_TOLERANCE_S:
            self.rejected_epoch_mismatch += 1
            return None
        key = (src, dst)
        w = self._windows.get(key)
        created = w is None
        if created:
            if len(self._windows) >= self._max_windows:
                # window-count envelope reached: shed this event
                self.suppressed_new_windows += 1
                if self._events >= self._max_events:
                    self._mark_degraded()
                return None
            if self._events >= self._max_events:
                self._mark_degraded()
                return None
            w = _Window(src=src, dst=dst, first_ts=ts_iso, last_ts=ts_iso,
                        last_epoch_s=epoch_s)
            self._windows[key] = w
        if self._events >= self._max_events:
            self._mark_degraded()
            return None
        self._events += 1
        if created:
            # the window's first contact ESTABLISHES the epoch baseline; it is
            # not a gap (gap==0 against its own start must not read as a
            # non-monotonic rejection — audit P1-23).
            return None
        gap = epoch_s - w.last_epoch_s
        # audit P1-23: a non-monotonic (or zero/duplicate-instant) epoch is
        # rejected with a named reason AND the watermark is left UNCHANGED —
        # moving last_epoch_s backward (or forward) would corrupt the baseline
        # the next gap is computed against. Only a genuinely forward epoch
        # advances the watermark.
        if gap <= 0:
            self.rejected_nonmonotonic += 1
            return None
        w.last_epoch_s = epoch_s
        w.last_ts = ts_iso              # audit P1-22: freshness = last contact
        # gap > 0 is guaranteed here (<= 0 returned above)
        w.gaps.append(gap)
        w.total_gaps += 1               # audit P1-21: lifetime counter, never truncated
        if len(w.gaps) > self._min_events + 64:
            # per-window analysis buffer bound: keep the most recent gaps
            w.gaps = w.gaps[-(self._min_events + 64):]
        if w.total_gaps < self._min_events:
            return None
        # audit P1-21: bounded emission is on the LIFETIME counter, not the
        # truncated buffer — re-arming always needs min_events NEW positive
        # gaps, reachable no matter how long the window has lived.
        if w.total_gaps - w.emitted_total < self._min_events:
            return None
        det = self._evaluate(w)
        if det is not None:
            w.emitted_total = w.total_gaps
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
        # every gap inside the band: deterministic detection. audit P1-22:
        # freshness is the ACTUAL trigger event (last contact), not the
        # window-birth first_ts — active beacons must not look stale.
        return Detection(src=w.src, dst=w.dst, median_gap_s=median,
                         events=len(w.gaps), observed_at=w.last_ts,
                         first_seen=w.first_ts)

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


class FirstSeenNoveltyDetector:
    """BD-6 first-seen/novelty detector (docs/23) — the reference's second
    IMPLEMENTED behavioral family (audit P1-20: at least two to satisfy Gate
    V2-A).

    Signal (docs/23 BD-6): a destination contacted by an internal host for
    the first time (within retention). Emits one detection per first contact
    of a novel destination, carrying the subject (src) as decision context
    (audit P1-24). Resource envelope (docs/23 B-6): a population first-seen
    table bounded by `max_entries` and aged by `ttl_s`; overflow sheds new
    entries (counted) and stop-and-marks the detector — detection can only
    shrink, never grow, under load. Deterministic integer epoch math only.
    """

    KIND = "first_seen_novelty"

    def __init__(self, max_entries: int = 500_000, ttl_s: int = 86_400):
        """max_entries bounds the table; ttl_s is the retention window (the
        "within retention" qualifier in BD-6)."""
        self._max_entries = max_entries
        self._ttl_s = ttl_s
        self._table: dict[str, tuple[int, str]] = {}   # dst -> (epoch, first_ts)
        self._events = 0
        self.degraded = False
        self.detections = 0
        self.suppressed_new_dsts = 0

    @property
    def tracked_destinations(self) -> int:
        return len(self._table)

    def observe(self, src: str, dst: str, ts_iso: str, epoch_s: int) -> Detection | None:
        """Emit a Detection the first time this destination is contacted
        within retention. Returns None for repeat contacts and expired rows
        (deterministic; never guesses)."""
        if self.degraded:
            return None
        cur = self._table.get(dst)
        is_novel = False
        if cur is None:
            is_novel = True
        else:
            seen_epoch, _ = cur
            if epoch_s - seen_epoch > self._ttl_s:
                is_novel = True   # expired out of retention -> re-novel
        if is_novel:
            if len(self._table) >= self._max_entries:
                self.suppressed_new_dsts += 1
                self.degraded = True          # envelope exhausted: stop-and-mark
                return None
            self._table[dst] = (epoch_s, ts_iso)
            self.detections += 1
            return Detection(src=src, dst=dst, median_gap_s=0, events=1,
                             observed_at=ts_iso, first_seen=ts_iso,
                             kind=NOVELTY_KIND)
        return None

    def as_evidence(self, det: Detection) -> dict:
        return det.as_evidence_fields()
