from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from .randomize import ApipRng

# Source class for attribution records (docs/30). Distinct from every
# authoritative class in the registry; the evidence weight table carries no
# entries for it and must never gain any.
ATTRIBUTION_SOURCE_CLASS = "attribution"

# Versioned probe set (docs/30). Fixed material; the presented subset/order is
# drawn per (session, epoch) by the recorded ApipRng.
PROBE_IDS = ("P1", "P2", "P3", "P4", "P5", "P6")

# Fingerprint schema version. Bumping re-baselines all stored fingerprints;
# cross-version comparison is prohibited (docs/30).
FP_SCHEMA_VERSION = "fp1"


def probe_order(session_id: str, epoch: str) -> tuple[str, ...]:
    """Deterministic, epoch-varied probe presentation order (docs/29/30).

    Same (session, epoch) -> exact same order; epoch change -> different
    order. Recorded through ApipRng so any historical draw replays exactly.
    """
    rng = ApipRng(f"attribution|{session_id}|{epoch}")
    probes = list(PROBE_IDS)
    for i in range(len(probes) - 1, 0, -1):
        j = rng.next_uniform_micros(0, i)
        probes[i], probes[j] = probes[j], probes[i]
    return tuple(probes)


def fingerprint(features: dict[str, str]) -> str:
    """Versioned deterministic fingerprint derivation (docs/30).

    Canonical serialization (sorted keys) then SHA-256 — exact arithmetic,
    reproducible from the stored features, no inference anywhere.
    """
    canonical = "|".join(f"{k}={features[k]}" for k in sorted(features))
    return f"fp--{FP_SCHEMA_VERSION}--{hashlib.sha256(canonical.encode()).hexdigest()[:16]}"


def similarity(a: dict[str, str], b: dict[str, str]) -> int:
    """Shared-probe subset count (docs/30). Deterministic; used for
    correlation *display* only — never a score, never an enforcement input."""
    return len(set(a) & set(b))


# ---------------------------------------------------------------------------
# Collection channel (docs/30 "Feature extraction and collection channel").
#
# The engine harvests OBSERVABLE BEHAVIOR, not self-declared answers: what a
# requester claims (User-Agent text, declared locale) is spoofable raw material;
# how it constructs a response (header order, conditional-request semantics,
# serialization key order, TLS extension surface) is the signature. Extraction
# is a fixed, versioned function over already-captured transaction records —
# in this offline scaffold, a JSONL log of observations the proxy/TLS
# terminator would emit anyway. The scaffold never terminates traffic itself.


def handle_for(client_ref: str) -> str:
    """Pseudonymous requester handle (docs/30): keyed hash of the client
    identity at the chokepoint, never the raw identifier."""
    return "rh--" + hashlib.sha256(client_ref.encode()).hexdigest()[:16]


def extract_features(tx: dict) -> dict[str, str]:
    """Fixed per-probe extractors over one observed transaction record.

    A probe whose material is absent from the record contributes nothing —
    absence is recorded as missing, never guessed. Deterministic: identical
    records yield identical feature vectors.
    """
    feats: dict[str, str] = {}

    # P1 — header-order vector + header-set hash (behavioral: emission order)
    headers = tx.get("header_order")
    if isinstance(headers, list) and headers:
        feats["P1:header_order"] = ",".join(str(h) for h in headers)
        feats["P1:header_set"] = hashlib.sha256(
            ",".join(sorted(str(h) for h in headers)).encode()).hexdigest()[:12]

    # P2 — locale/encoding coherence (behavioral: declared-vs-structural fit)
    al, ae = tx.get("accept_language"), tx.get("accept_encoding")
    if al and ae:
        langs = sorted(x.strip().split(";")[0] for x in str(al).split(",") if x.strip())
        codings = sorted(x.strip() for x in str(ae).split(",") if x.strip())
        feats["P2:coherence"] = hashlib.sha256(
            f"{langs}|{codings}".encode()).hexdigest()[:12]

    # P3 — passive TLS client-hello digest captured at the terminator
    ja4 = tx.get("tls_ja4")
    if ja4:
        feats["P3:ja4"] = str(ja4)

    # P4 — conditional-request correctness on a versioned asset
    p4 = tx.get("cache_behavior")
    if p4 in {"validators_absent", "validators_present_correct",
              "validators_present_incorrect", "revalidation_ignored"}:
        feats["P4:cache_behavior"] = p4

    # P5 — serialization-order signature from the canonical-JSON challenge
    body = tx.get("challenge_body_key_order")
    if isinstance(body, list) and body:
        feats["P5:key_order"] = ",".join(str(k) for k in body)

    # P6 — range/encoding fallback behavior class
    p6 = tx.get("range_fallback")
    if p6 in {"range_honored", "range_ignored", "identity_fallback", "malformed_retry"}:
        feats["P6:range_fallback"] = p6

    return feats


@dataclass
class _RequesterState:
    handle: str
    features: dict[str, str] = field(default_factory=dict)
    transactions: int = 0
    last_seen: str = ""


class CorrelationStore:
    """Bounded per-requester reduction with deterministic eviction (docs/30).

    Same resource-envelope discipline as the behavioral suite (docs/23):
    max tracked requesters, oldest-last_seen-first eviction. Overflow stops
    reduction for NEW handles and marks the store degraded — it can only
    reduce what attribution records exist (i.e. fewer), never add authority
    anywhere.
    """

    SCHEMA_VERSION = "corr-1"

    def __init__(self, max_requesters: int = 10_000):
        self._max = max_requesters
        self._by_handle: dict[str, _RequesterState] = {}
        self.degraded: bool = False

    def observe(self, tx: dict) -> dict[str, str] | None:
        """Fold one observed transaction into the requester's feature vector.
        Returns the derived fingerprint when the vector is non-empty."""
        feats = extract_features(tx)
        if not feats:
            return None
        handle = handle_for(str(tx.get("client_ref", "")))
        state = self._by_handle.get(handle)
        if state is None:
            if len(self._by_handle) >= self._max:
                # deterministic degradation: stop tracking new handles
                self.degraded = True
                return None
            state = _RequesterState(handle=handle)
            self._by_handle[handle] = state
        state.features.update(feats)
        state.transactions += 1
        state.last_seen = str(tx.get("observed_at", state.last_seen))
        return fingerprint(state.features)

    def _evict_oldest(self) -> None:
        if not self._by_handle:
            return
        oldest = min(self._by_handle.values(),
                     key=lambda s: (s.last_seen, s.handle))
        del self._by_handle[oldest.handle]

    def prune_expired(self, now_iso: str, ttl_seconds: int) -> int:
        """TTL eviction, deterministic on (now, last_seen, handle)."""
        from datetime import datetime, timedelta
        try:
            now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
        except ValueError:
            return 0
        expired = []
        for s in self._by_handle.values():
            try:
                seen = datetime.fromisoformat(s.last_seen.replace("Z", "+00:00"))
            except ValueError:
                expired.append(s.handle)
                continue
            if seen + timedelta(seconds=ttl_seconds) < now:
                expired.append(s.handle)
        for h in expired:
            del self._by_handle[h]
        return len(expired)

    def report(self, min_similarity: int = 3) -> dict:
        """Campaign-correlation report — the analyst worklist (docs/30).

        Groups requesters by identical fingerprint, then links groups whose
        feature vectors share >= min_similarity probes (deterministic subset
        count, display-only). This structure IS the file-form of the operator
        UI view; rendering it is presentation, not analysis.
        """
        groups: dict[str, list[str]] = {}
        for s in self._by_handle.values():
            groups.setdefault(fingerprint(s.features), []).append(s.handle)
        fps = list(groups)
        links = []
        for i in range(len(fps)):
            for j in range(i + 1, len(fps)):
                a = next(s.features for s in self._by_handle.values()
                         if fingerprint(s.features) == fps[i])
                b = next(s.features for s in self._by_handle.values()
                         if fingerprint(s.features) == fps[j])
                sim = similarity(a, b)
                if sim >= min_similarity:
                    links.append({"a": fps[i], "b": fps[j], "shared_probes": sim})
        return {
            "schema_version": self.SCHEMA_VERSION,
            "degraded": self.degraded,
            "tracked_requesters": len(self._by_handle),
            "fingerprint_groups": [
                {"fingerprint": fp, "requester_handles": sorted(handles),
                 "probe_count": len(next(s.features for s in self._by_handle.values()
                                         if fingerprint(s.features) == fp))}
                for fp, handles in sorted(groups.items())
            ],
            "cross_fingerprint_links": sorted(
                links, key=lambda l: (l["a"], l["b"])),
        }

    def attribution_refs_for(self, client_ref: str) -> tuple[str, ...]:
        """Display-only refs to attach to decisions/indicators (docs/30).
        These never enter scoring; tests enforce decisions are byte-identical
        with and without them."""
        handle = handle_for(client_ref)
        s = self._by_handle.get(handle)
        if s is None:
            return ()
        return (fingerprint(s.features),)
