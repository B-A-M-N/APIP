"""Requester attribution correlation runtime (docs/30).

Byte-compatible port of ``reference/src/apip/attribution.py`` — the P0
invariant holds in this product exactly as in the reference:

  attribution output is NEVER an enforcement input.

The correlation store reduces observable requester behavior into
pseudonymous handles and fingerprint groups that feed the ANALYST WORKLIST
only. Nothing in the decision path reads it (decisions are byte-identical
with or without attribution records — a test pins this).

The whole corridor is deterministic and stdlib-only (docs/28 allowlist):

  - keyed HMAC-SHA-256 handles (per-deployment key, never a raw identity);
  - versioned canonical feature fingerprints (no inference);
  - a bounded per-requester store with deterministic TTL + oldest-first
    eviction and stop-and-mark degradation (docs/23 envelope discipline);
  - a structural transaction validator that REFUSES malformed records
    (never coerces, so a broken log shipper cannot distort the vector).

The collection channel harvests OBSERVABLE BEHAVIOR (emission order,
conditional-request semantics, TLS client-hello digest), not trivially
spoofable self-declared answers. This module never terminates traffic
itself; it consumes already-captured JSONL observations.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import os
import re as _re
from dataclasses import dataclass, field

from apip.decision.rng import ApipRng

# Source class for attribution records (docs/30). Distinct from every
# authoritative class in the registry; the evidence weight table carries no
# entries for it and must never gain any.
ATTRIBUTION_SOURCE_CLASS = "attribution"


# --- deployment pseudonymization key (P1-16 keyed-HMAC fix) -----------------

_DEV_FALLBACK_KEY = "apip-reference-dev-key-do-not-use-in-production"
_KEY_ENV = "APIP_DEPLOYMENT_KEY"
_KEY_FILE_ENV = "APIP_DEPLOYMENT_KEY_FILE"
_MIN_KEY_BYTES = 32


class DeploymentKeyError(RuntimeError):
    """An explicitly-configured deployment key was empty, unreadable, or
    below the 256-bit entropy bar. Fail closed: never silently fall back to
    the public development key when a privacy control was requested."""


def _load_deployment_key() -> tuple[bytes, str]:
    env = os.environ.get(_KEY_ENV)
    if env is not None:
        if len(env.encode("utf-8")) < _MIN_KEY_BYTES:
            raise DeploymentKeyError(
                "APIP_DEPLOYMENT_KEY is shorter than 256 bits of key material; "
                "refusing to key the deployment (fail closed)")
        return (env.encode("utf-8"), "env")
    path = os.environ.get(_KEY_FILE_ENV)
    if path:
        try:
            with open(path, "rb") as f:
                data = f.read().strip()
        except OSError as e:
            raise DeploymentKeyError(
                f"APIP_DEPLOYMENT_KEY_FILE configured but unreadable: {e}") from e
        if not data:
            raise DeploymentKeyError(
                "APIP_DEPLOYMENT_KEY_FILE configured but empty; refusing to "
                "silently fall back to the dev key")
        if len(data) < _MIN_KEY_BYTES:
            raise DeploymentKeyError(
                "APIP_DEPLOYMENT_KEY_FILE holds fewer than 256 bits of key "
                "material; refusing to key the deployment (fail closed)")
        return (data, "file")
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


# Versioned probe set + fingerprint schema (docs/30).
PROBE_IDS = ("P1", "P2", "P3", "P4", "P5", "P6")
FP_SCHEMA_VERSION = "fp1"


def probe_order(session_id: str, epoch: str) -> tuple[str, ...]:
    """Deterministic, epoch-varied probe presentation order (docs/29/30)."""
    rng = ApipRng(f"attribution|{session_id}|{epoch}")
    probes = list(PROBE_IDS)
    for i in range(len(probes) - 1, 0, -1):
        j = rng.next_uniform_micros(0, i)
        probes[i], probes[j] = probes[j], probes[i]
    return tuple(probes)


def fingerprint(features: dict[str, str]) -> str:
    """Versioned deterministic fingerprint derivation (docs/30)."""
    canonical = "|".join(f"{k}={features[k]}" for k in sorted(features))
    return f"fp--{FP_SCHEMA_VERSION}--{hashlib.sha256(canonical.encode()).hexdigest()[:16]}"


def similarity(a: dict[str, str], b: dict[str, str]) -> int:
    """Shared-probe subset count (docs/30). Display-only."""
    return len(set(a) & set(b))


def handle_for(client_ref: str) -> str:
    """Pseudonymous requester handle: keyed HMAC-SHA-256, never the raw id."""
    key, _ = _key()
    return "rh--" + _hmac.new(key, client_ref.encode("utf-8"),
                              hashlib.sha256).hexdigest()[:16]


# --- observed-transaction contract validation --------------------------------

_TX_ENUMS = {
    "cache_behavior": {"validators_absent", "validators_present_correct",
                       "validators_present_incorrect", "revalidation_ignored"},
    "range_fallback": {"range_honored", "range_ignored",
                       "identity_fallback", "malformed_retry"},
}
_TX_STRING_FIELDS = {"client_ref", "observed_at", "session_epoch",
                     "accept_language", "accept_encoding", "tls_ja4"}
_TX_LIST_FIELDS = {"header_order", "challenge_body_key_order"}
_TX_STRING_MAXLEN = {
    "client_ref": 128,
    "observed_at": 64,
    "session_epoch": 64,
    "accept_language": 256,
    "accept_encoding": 256,
    "tls_ja4": 128,
}

_ISO_UTC = _re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")
_TX_NON_CONTROL = _re.compile(r"^[^\x00-\x1f\x7f-\x9f]*$")


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
        if f not in tx:
            raise TransactionRejected(f"missing required field: {f}")

    for f in _TX_STRING_FIELDS:
        if f not in tx:
            continue
        v = tx[f]
        if not isinstance(v, str):
            raise TransactionRejected(f"{f} must be a string, got {type(v).__name__}")
        maxlen = _TX_STRING_MAXLEN.get(f, 64)
        if not (1 <= len(v) <= maxlen):
            raise TransactionRejected(f"{f} must be 1..{maxlen} chars")
        if not _TX_NON_CONTROL.match(v):
            raise TransactionRejected(f"{f} contains control characters")
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
    """Fixed per-probe extractors over one observed transaction record."""
    feats: dict[str, str] = {}

    # P1 — header-order vector + header-set hash
    headers = tx.get("header_order")
    if isinstance(headers, list) and headers:
        feats["P1:header_order"] = ",".join(str(h) for h in headers)
        feats["P1:header_set"] = hashlib.sha256(
            ",".join(sorted(str(h) for h in headers)).encode()).hexdigest()[:12]

    # P2 — locale/encoding coherence
    al, ae = tx.get("accept_language"), tx.get("accept_encoding")
    if al and ae:
        langs = sorted(x.strip().split(";")[0] for x in str(al).split(",") if x.strip())
        codings = sorted(x.strip() for x in str(ae).split(",") if x.strip())
        feats["P2:coherence"] = hashlib.sha256(
            f"{langs}|{codings}".encode()).hexdigest()[:12]

    # P3 — passive TLS client-hello digest
    ja4 = tx.get("tls_ja4")
    if ja4:
        feats["P3:ja4"] = str(ja4)

    # P4 — conditional-request correctness
    p4 = tx.get("cache_behavior")
    if p4 in {"validators_absent", "validators_present_correct",
              "validators_present_incorrect", "revalidation_ignored"}:
        feats["P4:cache_behavior"] = p4

    # P5 — serialization-order signature
    body = tx.get("challenge_body_key_order")
    if isinstance(body, list) and body:
        feats["P5:key_order"] = ",".join(str(k) for k in body)

    # P6 — range/encoding fallback behavior class
    p6 = tx.get("range_fallback")
    if p6 in {"range_honored", "range_ignored", "identity_fallback", "malformed_retry"}:
        feats["P6:range_fallback"] = p6

    return feats


def _parse_instant(iso: str) -> tuple[int, int]:
    """Deterministic parse of an ISO-8601 UTC instant to (micros, frac-digits)."""
    if not isinstance(iso, str) or not iso:
        return (0, 0)
    s = iso[:-1] if iso.endswith("Z") else iso
    s = s.replace("+00:00", "").replace("-00:00", "").replace("Z", "")
    base, _, frac = s.partition(".")
    try:
        import datetime as _dt
        dt = _dt.datetime.fromisoformat(base)
    except ValueError:
        return (0, 0)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    micros = int((frac or "")[:6].ljust(6, "0")) if frac else 0
    micros += int(dt.timestamp() * 1_000_000) % 1_000_000
    ts = int(dt.timestamp())
    return (ts, micros)


@dataclass
class _RequesterState:
    handle: str
    features: dict[str, str] = field(default_factory=dict)
    transactions: int = 0
    last_seen: str = ""
    _rev: dict[str, str] = field(default_factory=dict)


class CorrelationStore:
    """Bounded per-requester reduction with deterministic eviction (docs/30)."""

    SCHEMA_VERSION = "corr-1"

    def __init__(self, max_requesters: int = 10_000):
        self._max = max_requesters
        self._by_handle: dict[str, _RequesterState] = {}
        self.degraded: bool = False
        import threading as _threading
        self._lock = _threading.RLock()

    def observe(self, tx: dict) -> str | None:
        """Fold a record whose `client_ref` is the RAW client identity
        (offline/adapter ingestion). The handle is derived ONCE via
        `handle_for`."""
        validate_transaction(tx)
        return self._fold(handle_for(str(tx.get("client_ref", ""))), tx)

    def observe_pseudonymous_handle(self, tx: dict,
                                    requester_handle: str | None = None
                                    ) -> str | None:
        """Fold a record whose identity is ALREADY a pseudonymous requester
        handle (live capture). No second HMAC (P1-14)."""
        validate_transaction(tx)
        handle = requester_handle if requester_handle is not None else tx.get("client_ref")
        if not isinstance(handle, str) or not handle:
            return None
        return self._fold(handle, tx)

    def _fold(self, handle: str, tx: dict) -> str | None:
        """Deterministic, order-invariant merge (P1-18)."""
        feats = extract_features(tx)
        if not feats:
            return None
        inst = _parse_instant(str(tx.get("observed_at", "")))
        last_seen_iso = tx.get("observed_at", "")
        with self._lock:
            state = self._by_handle.get(handle)
            if state is None:
                if len(self._by_handle) >= self._max:
                    self.degraded = True
                    return None
                state = _RequesterState(handle=handle)
                self._by_handle[handle] = state
            state.transactions += 1
            if state.last_seen:
                if inst > _parse_instant(state.last_seen):
                    state.last_seen = last_seen_iso
            else:
                state.last_seen = last_seen_iso
            for k, v in feats.items():
                prev_rev = state._rev.get(k)
                if prev_rev is None:
                    state._rev[k] = last_seen_iso
                    state.features[k] = v
                elif inst > _parse_instant(prev_rev):
                    state._rev[k] = last_seen_iso
                    state.features[k] = v
            return fingerprint(state.features)

    def prune_expired(self, now_iso: str, ttl_seconds: int) -> int:
        """TTL eviction, deterministic on (now, last_seen, handle)."""
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
                    expired.append(s.handle)
                elif seen + horizon < now:
                    expired.append(s.handle)
            for h in expired:
                del self._by_handle[h]
        return len(expired)

    def _snapshot(self) -> list[_RequesterState]:
        with self._lock:
            return sorted(self._by_handle.values(), key=lambda s: s.handle)

    def report(self, min_similarity: int = 3) -> dict:
        """Campaign-correlation report — the analyst worklist (docs/30)."""
        states = self._snapshot()
        groups: dict[str, list[str]] = {}
        feats_by_fp: dict[str, dict[str, str]] = {}
        for s in states:
            fp = fingerprint(s.features)
            groups.setdefault(fp, []).append(s.handle)
            feats_by_fp[fp] = s.features
        fps = sorted(groups)
        links = []
        for i in range(len(fps)):
            for j in range(i + 1, len(fps)):
                a, b = feats_by_fp[fps[i]], feats_by_fp[fps[j]]
                sim = similarity(a, b)
                matching = sum(1 for k in set(a) & set(b) if a[k] == b[k])
                contained = (matching == min(len(a), len(b)) and matching >= 2
                             and matching == sim)
                if matching >= min_similarity or contained:
                    links.append({"a": fps[i], "b": fps[j], "shared_probes": matching})
        return {
            "schema_version": self.SCHEMA_VERSION,
            "degraded": self.degraded,
            "handle_keying": deployment_key_provenance(),
            "tracked_requesters": len(states),
            "fingerprint_groups": [
                {"fingerprint": fp, "requester_handles": sorted(groups[fp]),
                 "probe_count": len(feats_by_fp[fp])}
                for fp in fps
            ],
            "cross_fingerprint_links": sorted(
                links, key=lambda l: (l["a"], l["b"])),
        }

    def attribution_refs_for(self, client_ref: str) -> tuple[str, ...]:
        """Display-only refs keyed by RAW client identity (offline)."""
        return self.attribution_refs_for_handle(handle_for(client_ref))

    def attribution_refs_for_handle(self, requester_handle: str) -> tuple[str, ...]:
        """Display-only refs keyed by an ALREADY-derived requester handle."""
        for s in self._snapshot():
            if s.handle == requester_handle:
                return (fingerprint(s.features),)
        return ()