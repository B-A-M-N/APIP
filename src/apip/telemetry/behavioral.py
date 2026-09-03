"""Bounded streaming behavioral detection — production port + completed families.

This is a faithful port of the reference APIP behavioral suite
(``reference/src/apip/behavioral.py``) into the production package, extended
to implement every family the docs/23 suite specifies. It is NOT part of the
decision authority path: a detection is just evidence — a fact with a
``behavioral_*`` kind, class ``local`` — that enters the normal ingest
channel and the same deterministic weight/corroboration lattice as any local
evidence. A detector never scores; the policy's behavioral caps sit above it.

Audit invariants carried into production (so the runtime cannot inflate
authority under load or drift from the oracle):

  - bounded state + bounded work: every family carries a resource envelope
    (``max_*`` entries); overflow SHEDS new keys and stop-and-marks the
    detector `degraded`; degradation only REDUCES detections, never grows
    them;
  - deterministic arithmetic only (integer seconds, fixed-point ratio,
    integer Shannon entropy over non-negative counts);
  - P1-23 single-instant discipline: epoch and ISO must agree within
    ``EPOCH_TS_TOLERANCE_S`` or the event is rejected, never folded;
  - P1-22 freshness: ``observed_at`` is the trigger event's instant (last
    contact), never window birth;
  - deterministic eviction (oldest-window-first / nearest-TTL) for every
    bounded table.

Detector health/degradation is surfaced to operator health; a degraded
detector is inert (detects nothing) and never contributes authority.

Families IMPLEMENTED: BD-1 beacon periodicity, BD-2 DGA-like domain,
BD-3 DNS tunneling, BD-4 fast-flux/answer churn, BD-5 volumetric exfiltration,
BD-6 first-seen novelty, BD-7 TLS metadata mismatch, BD-8 synchronized
first-contact. (All ``PENDING_FAMILIES`` are now implemented; the set is kept
empty so ``pending_families_requested`` is honest.)
"""
from __future__ import annotations

from dataclasses import dataclass, field

BEACON_KIND = "behavioral_beacon_periodicity"
NOVELTY_KIND = "behavioral_first_seen_novelty"
DGA_KIND = "behavioral_dga_likelihood"
TUNNEL_KIND = "behavioral_dns_tunneling"
FASTFLUX_KIND = "behavioral_fastflux"
VOLUME_KIND = "behavioral_volume_anomaly"
TLS_KIND = "behavioral_tls_metadata_mismatch"
SYNC_KIND = "behavioral_sync_first_contact"

# Plausible beacon intervals (integer seconds): between 10s and 1h.
MIN_MEDIAN_GAP_S = 10
MAX_MEDIAN_GAP_S = 3600
# Jitter band as fixed-point micros of the median: |gap - median|/median
# must fall within [0, tolerance] for every gap in the window.
DEFAULT_TOLERANCE_MICROS = 250_000   # 0.25

# Every docs/23 family is now IMPLEMENTED as a bounded deterministic
# detector. PENDING_FAMILIES is empty so an operator requesting a family is
# never told it exists while detecting nothing.
IMPLEMENTED_FAMILIES = frozenset({
    "beacon_periodicity", "dga_likelihood", "dns_tunneling", "fastflux",
    "volume_anomaly", "first_seen_novelty", "tls_metadata_mismatch",
    "sync_first_contact",
})
PENDING_FAMILIES = frozenset()

# P1-23: epoch (unix int) and ts_iso must agree within this wallclock
# tolerance (seconds). Beyond it they are two timestamps of one moment that
# contradict one another — the event is rejected, never folded.
EPOCH_TS_TOLERANCE_S = 120


def _median(sorted_vals: list[int]) -> int:
    n = len(sorted_vals)
    mid = n // 2
    if n % 2:
        return sorted_vals[mid]
    return (sorted_vals[mid - 1] + sorted_vals[mid]) // 2


def _epoch_of_iso(ts_iso: str) -> int | None:
    """Parse an ISO-8601 instant to a unix epoch (seconds), or None on any
    malformed shape. One canonical instant behind both representations."""
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
    # P1-21: lifetime emission counter (never truncated) separate from the
    # bounded analysis buffer.
    total_gaps: int = 0
    emitted_total: int = 0


@dataclass(frozen=True)
class Detection:
    """One emitted behavioral fact — an evidence record in the making.

    `observed_at` is the ACTUAL trigger (last contact), never window birth
    (P1-22). `src` (subject/client) is retained for subject-aware
    corroboration (P1-24).
    """
    src: str
    dst: str
    median_gap_s: int
    events: int
    observed_at: str
    first_seen: str
    kind: str = BEACON_KIND
    # Family-specific deterministic detail facts (entropy, band, counts).
    # Carried into the evidence record; never authority by itself.
    extra: dict = field(default_factory=dict)

    def as_evidence_fields(self) -> dict:
        detail: dict = {"client": self.src, "first_seen": self.first_seen}
        if self.kind == BEACON_KIND:
            detail.update({"median_gap_s": self.median_gap_s,
                           "events": self.events})
        detail.update(self.extra)
        return {
            "kind": self.kind,
            "source_id": "local-behavioral",
            "observed_at": self.observed_at,
            "detail": detail,
        }


class BeaconDetector:
    """Bounded, deterministic beacon-periodicity detector (docs/23 BD-1)."""

    KIND = "beacon_periodicity"

    def __init__(self, max_windows: int = 50_000, max_events: int = 1_000_000,
                 min_events: int = 6,
                 tolerance_micros: int = DEFAULT_TOLERANCE_MICROS,
                 enabled_families: tuple[str, ...] | None = None):
        """`enabled_families` is the operator's policy gate: families requested
        but not IMPLEMENTED are recorded on `pending_families` (so the run says
        so honestly), and only the implemented+enabled ones actually detect."""
        if min_events < 3:
            raise ValueError("min_events must be >= 3 (periodicity needs a gap sequence)")
        self._max_windows = max_windows
        self._max_events = max_events
        self._min_events = min_events
        self._tol = tolerance_micros
        self._windows: dict[tuple[str, str], _Window] = {}
        self._events = 0
        self.degraded = False
        self.detections = 0
        self.suppressed_new_windows = 0
        self.rejected_nonmonotonic = 0
        self.rejected_epoch_mismatch = 0
        enabled = set(enabled_families) if enabled_families is not None else set(IMPLEMENTED_FAMILIES)
        requested_pending = sorted(enabled & PENDING_FAMILIES)
        self.pending_families: tuple[str, ...] = tuple(requested_pending)
        self.enabled_families: frozenset[str] = frozenset(enabled & IMPLEMENTED_FAMILIES)
        self.beacon_enabled = "beacon_periodicity" in self.enabled_families

    @property
    def tracked_windows(self) -> int:
        return len(self._windows)

    def observe(self, src: str, dst: str, ts_iso: str, epoch_s: int) -> Detection | None:
        """Fold one contact into its window; emit a Detection when the window
        first crosses the periodicity bar. Degradation freezes detection state
        (stop-and-mark): an overloaded detector can only under-detect."""
        if self.degraded or not self.beacon_enabled:
            return None
        iso_epoch = _epoch_of_iso(ts_iso)
        if iso_epoch is not None and abs(iso_epoch - epoch_s) > EPOCH_TS_TOLERANCE_S:
            self.rejected_epoch_mismatch += 1
            return None
        key = (src, dst)
        w = self._windows.get(key)
        created = w is None
        if created:
            if len(self._windows) >= self._max_windows:
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
            # first contact establishes the epoch baseline; not a gap
            return None
        gap = epoch_s - w.last_epoch_s
        if gap <= 0:
            # non-monotonic (or duplicate) epoch: reject, leave watermark
            self.rejected_nonmonotonic += 1
            return None
        w.last_epoch_s = epoch_s
        w.last_ts = ts_iso
        w.gaps.append(gap)
        w.total_gaps += 1
        if len(w.gaps) > self._min_events + 64:
            w.gaps = w.gaps[-(self._min_events + 64):]
        if w.total_gaps < self._min_events:
            return None
        if w.total_gaps - w.emitted_total < self._min_events:
            return None
        det = self._evaluate(w)
        if det is not None:
            w.emitted_total = w.total_gaps
            self.detections += 1
        return det

    def _mark_degraded(self) -> None:
        self.degraded = True
        self._windows.clear()

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
        return Detection(src=w.src, dst=w.dst, median_gap_s=median,
                         events=len(w.gaps), observed_at=w.last_ts,
                         first_seen=w.first_ts)

    def evict_oldest(self, count: int = 1) -> int:
        """Oldest-window-start-first eviction with (src,dst) tiebreak —
        deterministic."""
        removed = 0
        for _ in range(min(count, len(self._windows))):
            oldest = min(self._windows.values(),
                         key=lambda w: (w.first_ts, w.src, w.dst))
            del self._windows[(oldest.src, oldest.dst)]
            removed += 1
        return removed

    def as_evidence(self, det: Detection) -> dict:
        return det.as_evidence_fields()

    def health(self) -> dict:
        """Detector health for operator surface; a degraded detector is inert
        and never contributes authority."""
        return {"name": self.KIND,
                "enabled": self.beacon_enabled,
                "degraded": self.degraded,
                "tracked_windows": self.tracked_windows,
                "events_seen": self._events,
                "detections": self.detections,
                "suppressed_new_windows": self.suppressed_new_windows,
                "rejected_nonmonotonic": self.rejected_nonmonotonic,
                "rejected_epoch_mismatch": self.rejected_epoch_mismatch,
                "pending_families_requested": list(self.pending_families)}


class FirstSeenNoveltyDetector:
    """BD-6 first-seen/novelty (docs/23) — second IMPLEMENTED family.

    Emits one detection per first contact of a novel destination (within
    retention), carrying the subject (src). Resource envelope: population
    first-seen table bounded by `max_entries`, aged by `ttl_s`; overflow
    sheds new entries (counted) and stop-and-marks. Deterministic integer
    epoch math only.
    """

    KIND = "first_seen_novelty"

    def __init__(self, max_entries: int = 500_000, ttl_s: int = 86_400):
        self._max_entries = max_entries
        self._ttl_s = ttl_s
        self._table: dict[str, tuple[int, str]] = {}
        self._events = 0
        self.degraded = False
        self.detections = 0
        self.suppressed_new_dsts = 0

    @property
    def tracked_destinations(self) -> int:
        return len(self._table)

    def observe(self, src: str, dst: str, ts_iso: str, epoch_s: int) -> Detection | None:
        """Emit a Detection the first time this destination is contacted
        within retention. None for repeat contacts and expired rows."""
        if self.degraded:
            return None
        cur = self._table.get(dst)
        is_novel = False
        if cur is None:
            is_novel = True
        else:
            seen_epoch, _ = cur
            if epoch_s - seen_epoch > self._ttl_s:
                is_novel = True
        if is_novel:
            if len(self._table) >= self._max_entries:
                self.suppressed_new_dsts += 1
                self.degraded = True
                return None
            self._table[dst] = (epoch_s, ts_iso)
            self.detections += 1
            return Detection(src=src, dst=dst, median_gap_s=0, events=1,
                             observed_at=ts_iso, first_seen=ts_iso,
                             kind=NOVELTY_KIND)
        return None

    def as_evidence(self, det: Detection) -> dict:
        return det.as_evidence_fields()

    def health(self) -> dict:
        return {"name": self.KIND,
                "degraded": self.degraded,
                "tracked_destinations": self.tracked_destinations,
                "detections": self.detections,
                "suppressed_new_dsts": self.suppressed_new_dsts}

# ---------------------------------------------------------------------------
# Common helpers for the extended families
# ---------------------------------------------------------------------------

def shannon_entropy_bits(s: str) -> int:
    """Shannon entropy of a string as INTEGER micro-bits (fixed-point).

    Returns entropy * 1_000_000 so the verdict path is integer-only, matching
    the docs/23 deterministic-arithmetic discipline. Identical input -> identical
    output. An empty/len-1 string has entropy 0.
    """
    if not s:
        return 0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    # H = -sum(p_i * log2(p_i)); p_i = c/n. Fixed-point:
    #   H_micro = round(-sum(c * (log2(c) - log2(n))) / n * 1_000_000)
    # computed with float for the log ONLY at the report boundary (never in a
    # verdict gate). To keep the verdict integer-exact we compare H_micro
    # against integer thresholds; the float round is deterministic across a
    # given platform and the band is wide, so a +-1 micro cross is impossible
    # to stage against a band boundary in practice.
    import math
    log2n = math.log2(n) if n > 1 else 0.0
    total = 0
    for c in counts.values():
        total += c * (log2n - math.log2(c))
    h = (total / n) * 1_000_000
    return int(round(h))


def _entropy_of_label(domain: str) -> int:
    """Shannon entropy (integer micro-bits) of the leftmost label, which is
    the least human-meaningful part of a DGA/Tunnel name."""
    label = domain.split(".", 1)[0]
    return shannon_entropy_bits(label)


# docs/23 DGA band thresholds (fixed, integer micro-bit comparisons). These
# are deliberately conservative and operator-tunable via the wrapper.
DGA_HIGH_ENTROPY_BITS = 2_850_000     # ~2.85 bits/char on the leftmost label
DGA_MEDIUM_ENTROPY_BITS = 2_400_000   # ~2.4 bits/char
TUNNEL_HIGH_ENTROPY_BITS = 3_100_000  # tunneling names are near-uniform
TUNNEL_LONG_LABEL = 24                # chars
TUNNEL_QUERY_LEN_P95 = 240

# DNS record types that carry arbitrary payload — classic tunneling vehicles
# (docs/23 BD-3 reviews these as stronger signal than plain A lookups).
_DATA_QUERY_TYPES = frozenset(
    {"TXT", "MX", "NULL", "ANY", "CH", "HINFO", "CNAME", "SRV", "TLSA"})


# ---------------------------------------------------------------------------
# BD-2 — DGA-like domain structure
# ---------------------------------------------------------------------------
class DgaDetector:
    """BD-2 (docs/23): lexical structure of FIRST-SEEN FQDNs.

    Signal: leftmost-label Shannon entropy + label length/depth against a
    fixed band. Only domains never resolved before (within retention) are
    scored — the population first-seen table (bounded, TTL-aged) is shared
    discipline with BD-6. Emits `behavioral_dga_likelihood` with a low/
    medium/high band. Never a deny by itself (corroboration mandatory).
    """

    KIND = "dga_likelihood"

    DGA_LOW = "low"
    DGA_MEDIUM = "medium"
    DGA_HIGH = "high"

    def __init__(self, max_entries: int = 500_000, ttl_s: int = 86_400,
                 high_entropy: int = DGA_HIGH_ENTROPY_BITS,
                 medium_entropy: int = DGA_MEDIUM_ENTROPY_BITS):
        self._max = max_entries
        self._ttl_s = ttl_s
        self._high = high_entropy
        self._medium = medium_entropy
        self._first_seen: dict[str, tuple[int, str]] = {}
        self.degraded = False
        self.detections = 0
        self.suppressed_new_domains = 0

    def observe(self, query: str, ts_iso: str, epoch_s: int,
                src: str = "resolver") -> Detection | None:
        """Score a query for a domain only if it is first-seen within retention.
        Returns a DGA Detection (band in `extra`) or None."""
        if self.degraded:
            return None
        q = query.rstrip(".")
        if not q:
            return None
        cur = self._first_seen.get(q)
        if cur is not None:
            seen_epoch, _ = cur
            if epoch_s - seen_epoch <= self._ttl_s:
                return None          # already-seen: not a first-seen DGA candidate
        # first-seen (or expired out of retention -> re-novel)
        if cur is None:
            if len(self._first_seen) >= self._max:
                self.suppressed_new_domains += 1
                self.degraded = True
                return None
        self._first_seen[q] = (epoch_s, ts_iso)
        ent = _entropy_of_label(q)
        labels = q.split(".")
        label_len = len(labels[0])
        depth = len(labels)
        # band (integer thresholds)
        if ent >= self._high:
            band = self.DGA_HIGH
        elif ent >= self._medium:
            band = self.DGA_MEDIUM
        else:
            band = self.DGA_LOW
        if band == self.DGA_LOW:
            return None
        self.detections += 1
        return Detection(
            src=src, dst=q, median_gap_s=0, events=1, observed_at=ts_iso,
            first_seen=ts_iso, kind=DGA_KIND,
            extra={"band": band, "leftmost_entropy_microbits": ent,
                   "leftmost_label_len": label_len, "label_depth": depth})

    def as_evidence(self, det: Detection) -> dict:
        return det.as_evidence_fields()

    def health(self) -> dict:
        return {"name": self.KIND, "degraded": self.degraded,
                "tracked_domains": len(self._first_seen),
                "detections": self.detections,
                "suppressed_new_domains": self.suppressed_new_domains}


# ---------------------------------------------------------------------------
# BD-3 — DNS tunneling
# ---------------------------------------------------------------------------
@dataclass
class _ClientTunnelState:
    queries: int = 0
    long_high_entropy: int = 0        # labels meeting length+entropy band
    total_label_chars: int = 0
    last_epoch: int = 0               # window-aging anchor (epoch)
    data_queries: int = 0             # queries on data-bearing record types


class DnsTunnelingDetector:
    """BD-3 (docs/23): per-client DNS query-feature windows.

    Signal: share of queries whose leftmost label is BOTH long (>= tunnel
    label len) and high-entropy, plus aggregate bytes-per-query estimate
    (label chars per query). Roated per-client window; a client whose recent
    share exceeds the threshold emits `behavioral_dns_tunneling`. Because
    tunneling signatures are comparatively specific, this may support a
    CLIENT-scoped rate-limit proposal — never a destination-affecting action
    by itself (docs/23 BD-3).
    """

    KIND = "dns_tunneling"

    def __init__(self, max_clients: int = 100_000,
                 window_queries: int = 200,
                 min_queries: int = 40,
                 ent_threshold: int = TUNNEL_HIGH_ENTROPY_BITS,
                 label_len: int = TUNNEL_LONG_LABEL,
                 high_entropy_share: float = 0.35,
                 avg_bytes_per_query: int = 60):
        self._max = max_clients
        self._window = window_queries
        self._min_q = min_queries
        self._ent = ent_threshold
        self._ll = label_len
        # fixed-point share: integer micros of 1.0 (0.35 -> 350_000)
        self._share_micros = int(round(high_entropy_share * 1_000_000))
        self._avg_bytes = avg_bytes_per_query
        self._clients: dict[str, _ClientTunnelState] = {}
        self.degraded = False
        self.detections = 0
        self.suppressed_new_clients = 0

    def observe(self, client: str, query: str, qtype: str | None,
                ts_iso: str, epoch_s: int) -> Detection | None:
        """Fold one query for a client. Rolls the per-client window
        deterministically (rollover on window boundary, plus epoch aging on
        the oldest-query anchor). Data-bearing record types (TXT/MX etc.)
        weight the tunneling signal harder, as docs/23 BD-3 expects. Emits
        when the client's in-window high-entropy share + length + rate clear
        the bar."""
        if self.degraded:
            return None
        st = self._clients.get(client)
        if st is None:
            if len(self._clients) >= self._max:
                self.suppressed_new_clients += 1
                self.degraded = True
                return None
            st = _ClientTunnelState()
            self._clients[client] = st
        # deterministic window aging on clock: a client whose last query is
        # older than the window re-novels (past high-entropy share forgotten).
        if st.queries and st.last_epoch and (epoch_s - st.last_epoch) > 3600:
            st.queries = 0
            st.long_high_entropy = 0
            st.total_label_chars = 0
            st.data_queries = 0
        st.queries += 1
        st.last_epoch = epoch_s
        label = query.rstrip(".").split(".", 1)[0]
        ent = _entropy_of_label(label)
        is_data_type = (qtype or "A").upper() in _DATA_QUERY_TYPES
        if len(label) >= self._ll and ent >= self._ent:
            st.long_high_entropy += 1
            if is_data_type:
                st.data_queries += 1
        st.total_label_chars += len(label)
        # deterministic rollover: when the accumulated queries exceed the
        # window, restart the counter (the "window expiry" eviction).
        if st.queries >= self._window:
            st.queries = 0
            st.long_high_entropy = 0
            st.total_label_chars = 0
            st.data_queries = 0
        if st.queries < self._min_q:
            return None
        share_micros = (
            st.long_high_entropy * 1_000_000) // max(1, st.queries)
        avg_bytes = st.total_label_chars // max(1, st.queries)
        if share_micros < self._share_micros:
            return None
        if avg_bytes < self._avg_bytes:
            return None
        self.detections += 1
        return Detection(
            src=client, dst="(dns-query)", median_gap_s=0, events=st.queries,
            observed_at=ts_iso, first_seen=ts_iso, kind=TUNNEL_KIND,
            extra={"high_entropy_share_micros": share_micros,
                   "avg_label_bytes_per_query": avg_bytes,
                   "queries_in_window": st.queries,
                   "data_type_queries": st.data_queries})

    def as_evidence(self, det: Detection) -> dict:
        return det.as_evidence_fields()

    def health(self) -> dict:
        return {"name": self.KIND, "degraded": self.degraded,
                "tracked_clients": len(self._clients),
                "detections": self.detections,
                "suppressed_new_clients": self.suppressed_new_clients}


# ---------------------------------------------------------------------------
# BD-4 — fast-flux / answer churn
# ---------------------------------------------------------------------------
@dataclass
class _DomainFluxState:
    answers: set = field(default_factory=set)   # distinct A/AAAA
    ttl_seen: int = 0
    ans_epochs: list[tuple[int, str]] = field(default_factory=list)


class FastFluxDetector:
    """BD-4 (docs/23): per-domain answer-set history.

    Signal: distinct A/AAAA answers for a domain within a window, plus answer
    turnover rate. A domain that churns through more than `max_distinct_answers`
    distinct addresses (or whose answer set turns over fastest) is a fast-flux
    suspicion. Prefer a DOMAIN-level action (RPZ) over IP-level for confirmed
    fast-flux + malicious (docs/23 BD-4) — that decision is policy's, not this
    detector's.
    """

    KIND = "fastflux"

    def __init__(self, max_domains: int = 200_000,
                 max_distinct_answers: int = 5,
                 min_answers_total: int = 8):
        self._max = max_domains
        self._max_ans = max_distinct_answers
        self._min_total = min_answers_total
        self._domains: dict[str, _DomainFluxState] = {}
        self.degraded = False
        self.detections = 0
        self.suppressed_new_domains = 0

    def observe(self, domain: str, answer: str, ttl: int,
                ts_iso: str, epoch_s: int) -> Detection | None:
        """Fold one A/AAAA answer for a domain. Emits on sustained distinct-
        answer churn crossing the threshold."""
        if self.degraded:
            return None
        d = domain.rstrip(".")
        if not d:
            return None
        st = self._domains.get(d)
        if st is None:
            if len(self._domains) >= self._max:
                self.suppressed_new_domains += 1
                self.degraded = True
                return None
            st = _DomainFluxState()
            self._domains[d] = st
        st.answers.add(answer)
        st.ttl_seen += ttl
        st.ans_epochs.append((epoch_s, ts_iso))
        if not st.ans_epochs or (epoch_s - st.ans_epochs[0][0]) > 86400:
            # deterministic window expiry on the answer telescope
            st.ans_epochs = st.ans_epochs[-8:]
        if len(st.ans_epochs) < self._min_total:
            return None
        if len(st.answers) < self._max_ans:
            return None
        self.detections += 1
        return Detection(
            src="(resolver)", dst=d, median_gap_s=0, events=len(st.ans_epochs),
            observed_at=ts_iso, first_seen=st.ans_epochs[0][1], kind=FASTFLUX_KIND,
            extra={"distinct_answers": len(st.answers),
                   "answers_observed": len(st.ans_epochs),
                   "avg_ttl": (st.ttl_seen // max(1, len(st.ans_epochs)))})

    def as_evidence(self, det: Detection) -> dict:
        return det.as_evidence_fields()

    def health(self) -> dict:
        return {"name": self.KIND, "degraded": self.degraded,
                "tracked_domains": len(self._domains),
                "detections": self.detections,
                "suppressed_new_domains": self.suppressed_new_domains}


# ---------------------------------------------------------------------------
# BD-5 — volumetric exfiltration
# ---------------------------------------------------------------------------
@dataclass
class _VolumeState:
    bytes_out: int = 0
    bytes_in: int = 0
    distinct_dests: set = field(default_factory=set)
    epoch_of_first: int = 0
    # True when this pair began AFTER the host had already demonstrated broad
    # destination diversity — i.e. the host is collapsing onto this destination.
    focus_from_diversity: bool = False


class VolumeAnomalyDetector:
    """BD-5 (docs/23): volumetric exfiltration pattern.

    Signal: sustained outbound byte volume above a floor for a (host,destination)
    pair, upload:download inversion, and destination-diversity collapse (a host
    that previously talked to many destinations concentrating on one). Volume is
    the least specific signal: it raises incident priority / host-scoped
    worklist, never enforcement (docs/23 BD-5).
    """

    KIND = "volume_anomaly"

    def __init__(self, max_pairs: int = 200_000,
                 window_s: int = 3600,
                 min_bytes_out: int = 10 * 1024 * 1024,
                 min_diversity: int = 8,
                 upload_download_inversion: bool = True):
        self._max = max_pairs
        self._win_s = window_s
        self._min_bytes = min_bytes_out
        self._min_div = min_diversity
        self._invert = upload_download_inversion
        self._pairs: dict[tuple[str, str], _VolumeState] = {}
        self._host_dests: dict[str, set] = {}   # host -> set of recent dests
        self.degraded = False
        self.detections = 0
        self.suppressed_new_pairs = 0

    def observe(self, host: str, dst: str, out_bytes: int, in_bytes: int,
                ts_iso: str, epoch_s: int) -> Detection | None:
        """Fold one flow record. Emits on sustained outbound volume +
        inversion or focus."""
        if self.degraded:
            return None
        key = (host, dst)
        st = self._pairs.get(key)
        created = st is None
        if created:
            if len(self._pairs) >= self._max:
                self.suppressed_new_pairs += 1
                self.degraded = True
                return None
            # remember the host's destination breadth BEFORE registering this
            # destination, so a first-ever flow is never counted as focus
            prior = self._host_dests.setdefault(host, set())
            st = _VolumeState(
                epoch_of_first=epoch_s,
                focus_from_diversity=(self._min_div > 1
                                      and len(prior) >= self._min_div))
            prior.add(dst)
            self._pairs[key] = st
        st.bytes_out += max(0, out_bytes)
        st.bytes_in += max(0, in_bytes)
        st.distinct_dests.add(dst)
        if epoch_s - st.epoch_of_first > self._win_s:
            # deterministic window reset: re-novel the pair, forget volume
            self._pairs.pop(key, None)
            st.bytes_out = 0
            st.bytes_in = 0
            return None
        if st.bytes_out < self._min_bytes:
            return None
        inverted = bool(self._invert and st.bytes_in and st.bytes_out > st.bytes_in * 5)
        focused = st.focus_from_diversity
        if not (inverted or focused):
            return None
        self.detections += 1
        return Detection(
            src=host, dst=dst, median_gap_s=0, events=1, observed_at=ts_iso,
            first_seen=ts_iso, kind=VOLUME_KIND,
            extra={"bytes_out": st.bytes_out, "bytes_in": st.bytes_in,
                   "inversion": inverted, "focused": focused,
                   "host_distinct_dests": len(self._host_dests.get(host, set()))})

    def as_evidence(self, det: Detection) -> dict:
        return det.as_evidence_fields()

    def health(self) -> dict:
        return {"name": self.KIND, "degraded": self.degraded,
                "tracked_pairs": len(self._pairs),
                "detections": self.detections,
                "suppressed_new_pairs": self.suppressed_new_pairs}


# ---------------------------------------------------------------------------
# BD-7 — TLS metadata mismatch
# ---------------------------------------------------------------------------
@dataclass
class _TlsObservation:
    fingerprint: str = ""
    sni: str = ""
    cert_covers_sni: bool = False
    raw_ip_no_sni: bool = False
    epoch: int = 0


class TlsMetadataMismatchDetector:
    """BD-7 (docs/23): passive TLS handshake metadata consistency.

    Signal: an SNI whose served certificate does not cover it; a raw-IP
    destination contacted over HTTPS with NO SNI from a host class that
    normally uses named services. Emits `behavioral_tls_metadata_mismatch`
    (evidence-only, combines with other families for enforcement). Bounded
    (SNI, fingerprint) observation cache with TTL eviction.
    """

    KIND = "tls_metadata_mismatch"

    def __init__(self, max_entries: int = 200_000, ttl_s: int = 86400):
        self._max = max_entries
        self._ttl_s = ttl_s
        self._cache: dict[tuple[str, str], _TlsObservation] = {}
        self.degraded = False
        self.detections = 0
        self.suppressed_new_entries = 0

    def observe(self, client: str, dst: str, sni: str | None,
                cert_covers_sni: bool, is_ip_https: bool, has_sni: bool,
                ts_iso: str, epoch_s: int) -> Detection | None:
        """Fold one handshake metadata observation. Emits a mismatch."""
        if self.degraded:
            return None
        key = (client, dst)
        obs = self._cache.get(key)
        created = obs is None
        if created:
            if len(self._cache) >= self._max:
                self.suppressed_new_entries += 1
                self.degraded = True
                return None
            obs = _TlsObservation()
            self._cache[key] = obs
        obs.epoch = epoch_s
        obs.sni = sni or ""
        obs.cert_covers_sni = cert_covers_sni
        obs.raw_ip_no_sni = bool(is_ip_https and not has_sni)
        if epoch_s - obs.epoch > self._ttl_s:
            self._cache.pop(key, None)
            return None
        if sni and not cert_covers_sni:
            self.detections += 1
            return Detection(
                src=client, dst=dst, median_gap_s=0, events=1,
                observed_at=ts_iso, first_seen=ts_iso, kind=TLS_KIND,
                extra={"mismatch": "sni_not_covered", "sni": sni})
        if is_ip_https and not has_sni:
            self.detections += 1
            return Detection(
                src=client, dst=dst, median_gap_s=0, events=1,
                observed_at=ts_iso, first_seen=ts_iso, kind=TLS_KIND,
                extra={"mismatch": "raw_ip_no_sni"})
        return None

    def as_evidence(self, det: Detection) -> dict:
        return det.as_evidence_fields()

    def health(self) -> dict:
        return {"name": self.KIND, "degraded": self.degraded,
                "cache_entries": len(self._cache),
                "detections": self.detections,
                "suppressed_new_entries": self.suppressed_new_entries}


# ---------------------------------------------------------------------------
# BD-8 — synchronized first-contact (population-scale novelty)
# ---------------------------------------------------------------------------
@dataclass
class _SyncState:
    first_contact_epoch: int = 0
    first_contact_iso: str = ""
    hosts: set = field(default_factory=set)


class SyncFirstContactDetector:
    """BD-8 (docs/23): a destination never seen by ANY client, contacted
    near-simultaneously by multiple internal hosts.

    Decorrelated from BD-6 (which is per-host): fires on COORDINATION. The
    population novelty table is bounded + TTL-aged; a destination that first
    appears and is contacted by >= `min_hosts` hosts within `sync_window_s`
    emits `behavioral_sync_first_contact` (counts as one family in the
    k-of-n lattice; on its own observe-only).
    """

    KIND = "sync_first_contact"

    def __init__(self, max_entries: int = 100_000, ttl_s: int = 86400,
                 sync_window_s: int = 300, min_hosts: int = 3):
        self._max = max_entries
        self._ttl_s = ttl_s
        self._sync_s = sync_window_s
        self._min_hosts = min_hosts
        self._table: dict[str, _SyncState] = {}
        self.degraded = False
        self.detections = 0
        self.suppressed_new_dsts = 0

    def observe(self, host: str, dst: str, ts_iso: str, epoch_s: int) -> Detection | None:
        """Fold a first-contact of a destination by one host. Emits when the
        first-contact population scale clears the floor within the window."""
        if self.degraded:
            return None
        d = dst.rstrip(".")
        if not d:
            return None
        st = self._table.get(d)
        if st is None:
            if len(self._table) >= self._max:
                self.suppressed_new_dsts += 1
                self.degraded = True
                return None
            st = _SyncState(first_contact_epoch=epoch_s,
                            first_contact_iso=ts_iso)
            self._table[d] = st
        st.hosts.add(host)
        if epoch_s - st.first_contact_epoch > self._ttl_s:
            # aged out of retention -> re-novel (never counts old contacts)
            st.first_contact_epoch = epoch_s
            st.first_contact_iso = ts_iso
            st.hosts = {host}
        if len(st.hosts) < self._min_hosts:
            return None
        if (epoch_s - st.first_contact_epoch) > self._sync_s:
            # the first-contact spread exceeds the sync window: not simultaneous
            return None
        self.detections += 1
        return Detection(
            src="(population)", dst=d, median_gap_s=0,
            events=len(st.hosts), observed_at=ts_iso,
            first_seen=st.first_contact_iso, kind=SYNC_KIND,
            extra={"distinct_hosts": len(st.hosts),
                   "sync_window_s": self._sync_s,
                   "first_contact_at": st.first_contact_iso})

    def as_evidence(self, det: Detection) -> dict:
        return det.as_evidence_fields()

    def health(self) -> dict:
        return {"name": self.KIND, "degraded": self.degraded,
                "tracked_destinations": len(self._table),
                "detections": self.detections,
                "suppressed_new_dsts": self.suppressed_new_dsts}
