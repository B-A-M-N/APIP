from __future__ import annotations
import hashlib
import hmac as _hmac
import os
from dataclasses import dataclass, field
from .randomize import ApipRng

# Source class for attribution records (docs/30). Distinct from every
# authoritative class in the registry; the evidence weight table carries no
# entries for it and must never gain any.
ATTRIBUTION_SOURCE_CLASS = "attribution"

# ---------------------------------------------------------------------------
# Deployment pseudonymization key (v2.1.1 audit-residual fix).
#
# Handles were previously unsalted SHA-256 prefixes of the client address.
# Within one deployment the input space is low-entropy: anyone who can
# guess the client IP space could invert every handle by brute force. The
# fix is a keyed HMAC-SHA-256 with a per-deployment key, so handles are
# unverifiable outside the deployment that holds the key while remaining
# perfectly deterministic within it (replay/audit unchanged).
#
# Key sourcing, in order:
#   1. APIP_DEPLOYMENT_KEY environment variable (hex or any string);
#   2. the deployment key file named by APIP_DEPLOYMENT_KEY_FILE;
#   3. a deterministic development fallback derived from nothing secret —
#      allowed ONLY for the offline scaffold/tests, and marked in the
#      report so an operator can never mistake it for protection.
# Storage stays pseudonymous per deployment: keys must NOT be shared
# across deployments (docs/30: handles must not be cross-deployment
# joinable), and rotation re-baselines all handles.
# ---------------------------------------------------------------------------

_DEV_FALLBACK_KEY = "apip-reference-dev-key-do-not-use-in-production"
_KEY_ENV = "APIP_DEPLOYMENT_KEY"
_KEY_FILE_ENV = "APIP_DEPLOYMENT_KEY_FILE"


def _load_deployment_key() -> tuple[bytes, str]:
    """Returns (key_bytes, provenance_tag). Never raises: scaffold degrades
    to the marked development key rather than crashing an offline pipeline."""
    env = os.environ.get(_KEY_ENV)
    if env:
        return (env.encode("utf-8"), "env")
    path = os.environ.get(_KEY_FILE_ENV)
    if path:
        try:
            with open(path, "rb") as f:
                data = f.read().strip()
            if data:
                return (data, "file")
        except OSError:
            pass
    return (_DEV_FALLBACK_KEY.encode("utf-8"), "dev-fallback")


_KEY_CACHE: tuple[bytes, str] | None = None


def _key() -> tuple[bytes, str]:
    global _KEY_CACHE
    if _KEY_CACHE is None:
        _KEY_CACHE = _load_deployment_key()
    return _KEY_CACHE


def reset_key_cache() -> None:
    """Test/rotation hook: forget the cached deployment key."""
    global _KEY_CACHE
    _KEY_CACHE = None


def deployment_key_provenance() -> str:
    """'env' | 'file' | 'dev-fallback' — surfaced in reports so an operator
    can see when handles are NOT keyed."""
    return _key()[1]

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
    """Pseudonymous requester handle (docs/30): keyed HMAC-SHA-256 of the
    client identity at the chokepoint, never the raw identifier.

    v2.1.1: keyed with the per-deployment key — an actor outside the
    deployment (or a stolen report) can no longer brute-force the small
    client-address space to invert handles. Deterministic within a
    deployment for correlation; keys are per-deployment and rotatable.
    """
    key, _ = _key()
    return "rh--" + _hmac.new(key, client_ref.encode("utf-8"),
                              hashlib.sha256).hexdigest()[:16]


# --- adapter contract validation (schemas/observed_transaction.schema.json) --
# Structural validation mirroring the schema, stdlib-only (docs/28 allowlist).
# Production adapters must emit records this validator accepts; malformed
# records are REJECTED (never coerced), so a broken log shipper cannot
# silently distort the feature vectors.

_TX_ENUMS = {
    "cache_behavior": {"validators_absent", "validators_present_correct",
                       "validators_present_incorrect", "revalidation_ignored"},
    "range_fallback": {"range_honored", "range_ignored",
                       "identity_fallback", "malformed_retry"},
}
_TX_STRING_FIELDS = {"client_ref", "observed_at", "session_epoch",
                     "accept_language", "accept_encoding", "tls_ja4"}
_TX_LIST_FIELDS = {"header_order", "challenge_body_key_order"}

# ISO-8601 UTC shape enforced structurally: YYYY-MM-DDTHH:MM:SS(.ffffff)?Z
import re as _re
_ISO_UTC = _re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")


class TransactionRejected(ValueError):
    """A transaction record violated the observed-transaction contract."""


def validate_transaction(tx: dict) -> None:
    """Validate one observed-transaction record against the docs/30 contract.

    Raises TransactionRejected with a named reason on any violation. The
    reference pipeline refuses (not coerces) malformed records.
    """
    if not isinstance(tx, dict):
        raise TransactionRejected("record must be an object")
    unknown = set(tx) - set(_TX_STRING_FIELDS) - set(_TX_ENUMS) - set(_TX_LIST_FIELDS)
    if unknown:
        raise TransactionRejected(f"unknown fields: {sorted(unknown)}")
    for f in ("client_ref", "observed_at"):
        v = tx.get(f)
        if not isinstance(v, str) or not (1 <= len(v) <= 128):
            raise TransactionRejected(f"{f} must be a 1..128 char string")
    if not _ISO_UTC.match(tx["observed_at"]):
        raise TransactionRejected(
            "observed_at must be ISO-8601 UTC (YYYY-MM-DDTHH:MM:SS[.ffffff]Z); "
            "adapters must normalize before emitting")
    for f, allowed in _TX_ENUMS.items():
        if f in tx and tx[f] not in allowed:
            raise TransactionRejected(f"{f} must be one of {sorted(allowed)}")
    for f in _TX_LIST_FIELDS:
        if f in tx:
            v = tx[f]
            if (not isinstance(v, list) or len(v) > 64
                    or not all(isinstance(x, str) and 0 < len(x) <= 64 for x in v)
                    or len(set(v)) != len(v)):
                raise TransactionRejected(
                    f"{f} must be a list of unique short strings (max 64)")


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
        # v2.2: the store is folded from handler threads (ChallengeOrigin.emit)
        # as well as offline; observe() mutates shared state and must be
        # atomic. Read paths (report/prune) are invoked from the pipeline
        # thread and take the same lock, keeping the bounded-store contract
        # exact under contention.
        import threading as _threading
        self._lock = _threading.RLock()

    def observe(self, tx: dict) -> dict[str, str] | None:
        """Fold one observed transaction into the requester's feature vector.
        Returns the derived fingerprint when the vector is non-empty.
        Contract-violating records are rejected (never coerced)."""
        validate_transaction(tx)
        feats = extract_features(tx)
        if not feats:
            return None
        handle = handle_for(str(tx.get("client_ref", "")))
        with self._lock:
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
        """TTL eviction, deterministic on (now, last_seen, handle).

        Adversarial-audit fix: records stamped far in the FUTURE previously
        survived eviction forever (a requester able to influence its own
        logged timestamps could pin state in the bounded store). Future-
        stamped entries beyond the TTL horizon are now treated as expired —
        bad clocks lose their records, per TM-009 (clock manipulation).
        """
        from datetime import datetime, timedelta
        try:
            now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
        except ValueError:
            return 0
        horizon = timedelta(seconds=ttl_seconds)
        expired = []
        with self._lock:
            for s in self._by_handle.values():
                try:
                    seen = datetime.fromisoformat(s.last_seen.replace("Z", "+00:00"))
                except ValueError:
                    expired.append(s.handle)
                    continue
                if seen > now + horizon:
                    expired.append(s.handle)          # future-stamped: treat as stale
                elif seen + horizon < now:
                    expired.append(s.handle)          # genuinely aged out
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
        feats_by_fp = {fingerprint(s.features): s.features
                       for s in self._by_handle.values()}
        links = []
        for i in range(len(fps)):
            for j in range(i + 1, len(fps)):
                a, b = feats_by_fp[fps[i]], feats_by_fp[fps[j]]
                sim = similarity(a, b)
                matching = sum(1 for k in set(a) & set(b) if a[k] == b[k])
                # Link when matching-value probes clear the policy floor, OR
                # one vector is fully contained in the other with all shared
                # values identical (>= 2 probes). The containment clause
                # handles heterogeneous terminators: different loggers
                # capture different probe subsets of the same client. Shared
                # keys with CONFLICTING values never link — behavioral
                # disagreement is evidence of difference.
                contained = (matching == min(len(a), len(b)) and matching >= 2
                             and matching == sim)
                if matching >= min_similarity or contained:
                    links.append({"a": fps[i], "b": fps[j], "shared_probes": matching})
        return {
            "schema_version": self.SCHEMA_VERSION,
            "degraded": self.degraded,
            "handle_keying": deployment_key_provenance(),
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
