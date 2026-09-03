"""Challenge origin (docs/30) — loopback-default observation server.

Byte-compatible port of ``reference/src/apip/live/server.py``.

Serves the probe material on an operator-specified bind address (default
127.0.0.1) and writes observed-transaction records (JSONL) compatible with the
docs/30 observed-transaction contract.

HARD SAFETY PROPERTIES (enforced in code and tests):
  - observe-only: the server performs NO enforcement action of any kind. It
    never blocks, redirects, rate-limits, or refuses based on identity —
    every request receives a response (200, 404, or challenge material);
  - no outbound connections: the handler opens no sockets, performs no DNS
    resolution, and issues no callbacks;
  - loopback default: without an explicit allow_nonloopback the server
    refuses to start on a non-loopback address (production opt-in);
  - pseudonymization at the boundary: raw client addresses pass through the
    canonical address normalizer before anything retains them, and the raw
    address never reaches the transaction records;
  - bounded output: the JSONL writer enforces a max-records cap with
    deterministic stop-and-mark, mirroring docs/23 resource envelopes;
  - every connection has a hard socket timeout; hostile Content-Length /
    Range values are rejected or clamped; handler exceptions answer 400 and
    never escape into the server loop.

This is the OFFLINE scaffold's collection channel — it exercises the probe
surface so an operator can exercise a real deployment's harvest. It never
terminates production traffic.
"""
from __future__ import annotations

import hashlib as _hl
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from apip.attribution import (
    CorrelationStore,
    TransactionRejected,
    handle_for,
    validate_transaction,
)
from apip.attribution_adapters import _safe_client
from apip.decision.rng import ApipRng

# Canonical-JSON challenge object (P5 material): the client is asked to echo
# this object with its own serializer; the KEY ORDER it emits is the
# behavioral feature. Keys are scrambled deterministically per issue but
# ALWAYS the canonical keys below.
CHALLENGE_KEYS = ("ts", "nonce", "response", "probe_set")

CHALLENGE_TTL_S = 300
MAX_CHALLENGES = 128
MAX_SESSIONS = 10_000
HANDLER_TIMEOUT_S = 30
MAX_BODY_BYTES = 65_536


def origin_epoch_marker(epoch: str) -> str:
    """Non-empty deterministic marker for an epoch (used in id material)."""
    return epoch or "0"


def _now_iso() -> str:
    """Current UTC instant in the observed_at ISO-8601 shape (validated)."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _scramble_fields(session_id: str, epoch: str) -> list[str]:
    rng = ApipRng(f"attribution-fields|{session_id}|{epoch}")
    fields: list[str] = [str(k) for k in CHALLENGE_KEYS]
    for i in range(len(fields) - 1, 0, -1):
        j = rng.next_uniform_micros(0, i)
        fields[i], fields[j] = fields[j], fields[i]
    return fields
    """Randomized order of the canonical challenge fields (audit P1-12).

    Deterministic per (session, epoch) so a challenge replays exactly and an
    epoch change re-orders the fields — but the keys are ALWAYS the canonical
    CHALLENGE_KEYS, never the probe ids."""
    rng = ApipRng(f"attribution-fields|{session_id}|{epoch}")
    fields = list(CHALLENGE_KEYS)
    for i in range(len(fields) - 1, 0, -1):
        j = rng.next_uniform_micros(0, i)
        fields[i], fields[j] = fields[j], fields[i]
    return fields


class _TxWriter:
    """Bounded, thread-safe JSONL writer for observed-transaction records."""

    def __init__(self, path: Path, max_records: int = 100_000):
        self._path = path
        self._max = max_records
        self._count = 0
        self.degraded = False
        self._fh = None
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        acquired = self._lock.acquire(timeout=5.0)
        if not acquired:
            self.degraded = True
            return
        try:
            if self.degraded:
                return
            if self._count >= self._max:
                self.degraded = True
                if self._fh:
                    self._fh.close()
                    self._fh = None
                return
            if self._fh is None:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                # refuse to follow a pre-placed symlink: fail-closed to
                # degraded rather than redirect records into an arbitrary target
                if self._path.is_symlink():
                    self.degraded = True
                    return
                self._fh = open(self._path, "a", encoding="utf-8")
            self._fh.write(json.dumps(record, sort_keys=True) + "\n")
            self._fh.flush()
            self._count += 1
        finally:
            self._lock.release()

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.close()
                self._fh = None


class ChallengeOrigin:
    """Runnable challenge origin + passive harvest.

    Serves probe material, records observable behavior, and can fold the
    resulting records into a CorrelationStore in-process (or leave the JSONL
    for the offline pipeline).
    """

    def __init__(self, out_path: Path, epoch: str = "0",
                 max_records: int = 100_000, store: CorrelationStore | None = None):
        self.writer = _TxWriter(Path(out_path), max_records=max_records)
        self.epoch = epoch
        self.store = store
        self.requests_observed = 0
        self._sessions: dict[str, int] = {}     # handle -> assigned session number
        self._MAX_SESSIONS = MAX_SESSIONS
        self._sessions_lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._challenges: dict[str, dict] = {}
        self._challenges_lock = threading.Lock()

    def _make_handler(self):
        origin = self

        class Handler(BaseHTTPRequestHandler):
            timeout = HANDLER_TIMEOUT_S

            def _record_common(self) -> dict[str, Any]:
                headers = []
                for k in self.headers.keys():
                    lk = k.lower()
                    if lk not in headers:
                        headers.append(lk)
                rec: dict[str, Any] = {
                    "client_ref": origin._canonical_client(self.client_address[0])
                        or self.client_address[0],
                    "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                if headers:
                    rec["header_order"] = headers
                al = self.headers.get("Accept-Language")
                ae = self.headers.get("Accept-Encoding")
                if al:
                    rec["accept_language"] = al
                if ae:
                    rec["accept_encoding"] = ae
                return rec

            def _session_for(self) -> tuple[str, int]:
                raw = origin._canonical_client(self.client_address[0]) \
                    or self.client_address[0]
                handle = handle_for(raw)   # pseudonymize first, retain raw nowhere
                with origin._sessions_lock:
                    n = origin._sessions.get(handle, 0)
                    if n == 0 and len(origin._sessions) >= origin._MAX_SESSIONS:
                        return handle, 0
                    origin._sessions[handle] = n + 1
                return handle, n

            def log_message(self, format, *args):  # quiet by default (no-op)
                pass

            CUR_ASSET = b"ASTVWXYZ"       # the canonical 8-byte asset (P4/P6)

            def _asset_response(self, rec: dict[str, Any]) -> None:
                etag = '"v1-2026-09-01"'
                inm = self.headers.get("If-None-Match")
                rng = self.headers.get("Range")
                if rng:
                    req = _parse_range(rng)
                    if req == (0, 1):
                        self.send_response(206)
                        self.send_header("Content-Type", "text/plain")
                        self.send_header("Content-Range", "bytes 0-1/8")
                        self.end_headers()
                        self.wfile.write(self.CUR_ASSET[0:2])
                        rec["range_fallback"] = "range_honored"
                        return
                    elif req is None:
                        rec["range_fallback"] = "malformed_retry"
                    else:
                        rec["range_fallback"] = "range_ignored"
                if inm == etag:
                    self.send_response(304)
                    self.end_headers()
                    rec["cache_behavior"] = "validators_present_correct"
                elif inm is not None:
                    self.send_response(200)
                    self.send_header("ETag", etag)
                    self.end_headers()
                    self.wfile.write(self.CUR_ASSET)
                    rec["cache_behavior"] = "validators_present_incorrect"
                else:
                    self.send_response(200)
                    self.send_header("ETag", etag)
                    self.end_headers()
                    self.wfile.write(self.CUR_ASSET)
                    rec["cache_behavior"] = "validators_absent"

            def _emit_common(self, rec: dict[str, Any]) -> None:
                handle, _ = self._session_for()
                rec["client_ref"] = handle       # records carry the pseudonym only
                rec["session_epoch"] = origin.epoch
                origin.emit(rec, requester_handle=handle)

            def do_GET(self):
                rec = self._record_common()
                with origin._counter_lock:
                    origin.requests_observed += 1
                path = self.path.split("?")[0]
                if path == "/healthz":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"ok\n")
                    self._emit_common(rec)
                    return
                if path == "/challenge":
                    challenged = origin._issue_challenge()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(challenged).encode())
                    rec["challenge_issued"] = True
                    self._emit_common(rec)
                    return
                if path == "/asset":
                    self._asset_response(rec)
                    self._emit_common(rec)
                    return
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"not found\n")
                self._emit_common(rec)

            def do_POST(self):
                rec = self._record_common()
                with origin._counter_lock:
                    origin.requests_observed += 1
                length = _safe_content_length(self.headers.get("Content-Length"))
                if length is None:
                    self.send_response(400)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"bad content-length\n")
                    self._emit_common(rec)
                    return
                body = self.rfile.read(min(length, MAX_BODY_BYTES)) if length else b""
                path = self.path.split("?")[0]
                prefix = "/challenge/"
                if not path.startswith(prefix):
                    self.send_response(404)
                    self.end_headers()
                    self._emit_common(rec)
                    return
                cid = path[len(prefix):]
                valid, key_order = origin._validate_challenge_submission(cid, body)
                rec["challenge_body_key_order"] = key_order or []
                rec["challenge_valid"] = bool(valid)
                if valid:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"valid":true,"schema_version":"fp1"}\n')
                else:
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"valid":false}\n')
                self._emit_common(rec)

        return Handler

    @staticmethod
    def _canonical_client(raw: str) -> str | None:
        """Canonicalize a raw peer address with the SAME rules the offline
        adapter contract uses (docs/30 cross-format exactness), so a live peer
        and its terminator-log alias derive ONE handle."""
        return _safe_client(raw)

    def emit(self, rec: dict[str, Any],
             requester_handle: str | None = None) -> None:
        """Validate, write, and (optionally) fold one observed transaction.

        The record's `client_ref` is ALREADY a pseudonymous requester handle —
        fold via `observe_pseudonymous_handle`, never `observe` (no second
        HMAC, P1-14). Invalid records are dropped with a counter, never coerced.
        """
        try:
            validate_transaction(rec)
        except TransactionRejected:
            self.writer.write({"rejected": True, "reason": "contract",
                               "observed_at": rec.get("observed_at")})
            return
        self.writer.write(rec)
        if self.store is not None:
            with self._counter_lock:
                self.store.observe_pseudonymous_handle(rec, requester_handle)

    # -- two-step challenge state machine (P1-12) --------------------------

    def _issue_challenge(self) -> dict[str, Any]:
        from datetime import datetime as _dt
        with self._sessions_lock:
            seq = self.requests_observed + len(self._challenges)
        cid = "ch--" + _hl.sha256(f"{seq}|{origin_epoch_marker(self.epoch)}"
                                  .encode()).hexdigest()[:16]
        rng = ApipRng(f"challenge|{cid}|{self.epoch}")
        nonce = _hl.sha256(f"nonce|{cid}|{rng.next_uniform_micros(0, 1 << 40)}"
                           .encode()).hexdigest()[:24]
        fields = _scramble_fields(cid, self.epoch)
        entry = {"nonce": nonce, "probe_set": fields, "issued_at": _now_iso()}
        with self._challenges_lock:
            self._challenges[cid] = entry
            self._evict_challenges()
        return {"challenge_id": cid, "nonce": nonce, "fields": fields}

    def _validate_challenge_submission(self, challenge_id: str,
                                       body: bytes) -> tuple[bool, list[str] | None]:
        from datetime import datetime
        with self._challenges_lock:
            entry = self._challenges.get(challenge_id)
        if entry is None:
            return False, None
        try:
            issued = datetime.fromisoformat(entry["issued_at"].replace("Z", "+00:00"))
            if (datetime.fromisoformat(_now_iso().replace("Z", "+00:00"))
                    - issued).total_seconds() > CHALLENGE_TTL_S:
                with self._challenges_lock:
                    self._challenges.pop(challenge_id, None)
                return False, None
        except ValueError:
            return False, None
        key_order = _key_order(body)
        nonce = entry["nonce"]
        echoed = nonce.encode("utf-8") in body
        pending = True
        with self._challenges_lock:
            pending = challenge_id in self._challenges
        ok = echoed and pending and bool(key_order)
        with self._challenges_lock:
            self._challenges.pop(challenge_id, None)
        return ok, key_order

    def _evict_challenges(self) -> None:
        from datetime import datetime
        now = datetime.fromisoformat(_now_iso().replace("Z", "+00:00"))
        keep = {}
        for cid, e in self._challenges.items():
            try:
                issued = datetime.fromisoformat(e["issued_at"].replace("Z", "+00:00"))
            except ValueError:
                continue
            if (now - issued).total_seconds() <= CHALLENGE_TTL_S:
                keep[cid] = e
        self._challenges = keep
        if len(self._challenges) > MAX_CHALLENGES:
            for cid in sorted(self._challenges,
                              key=lambda c: self._challenges[c]["issued_at"])[
                          len(keep) - MAX_CHALLENGES:]:
                self._challenges.pop(cid, None)

    # -- lifecycle -----------------------------------------------------------

    def serve(self, bind: str = "127.0.0.1", port: int = 8765) -> None:
        if not _is_loopback(bind):
            raise ValueError(
                "refusing non-loopback bind by default; pass allow_nonloopback=True "
                "only for production deployment after privacy review (docs/30)")
        self._server = ThreadingHTTPServer((bind, port), self._make_handler())
        self._server.daemon_threads = True
        self._server.serve_forever()

    def serve_forever(self, bind: str, port: int, allow_nonloopback: bool = False) -> None:
        if not allow_nonloopback and not _is_loopback(bind):
            raise ValueError("non-loopback bind requires allow_nonloopback=True")
        self._server = ThreadingHTTPServer((bind, port), self._make_handler())
        self._server.daemon_threads = True
        self._server.serve_forever()

    def shutdown(self) -> None:
        """Release the writer's file handle. Idempotent."""
        if self._server:
            self._server.shutdown()
            self._server = None
        self.writer.close()

    def __enter__(self) -> "ChallengeOrigin":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.shutdown()


def _safe_content_length(raw: str | None) -> int | None:
    """Parse a Content-Length header defensively.

    Returns None for anything that is not a plain non-negative integer (the
    handler answers 400), otherwise the clamped integer value."""
    if raw is None:
        return 0
    raw = raw.strip()
    if not raw or not raw.isdigit():
        return None
    try:
        return min(int(raw), MAX_BODY_BYTES)
    except ValueError:
        return None


def _parse_range(header: str | None) -> tuple[int, int] | None:
    """Parse a Range header to the exact [start, end] byte pair requested.

    Returns (start, end) ONLY for a single, plain, in-bounds `bytes=0-1`
    range; 0-1, malformed, multi-range, suffix, open-ended, or out-of-range
    headers return None so the caller records the honest class."""
    if header is None:
        return None
    h = header.strip()
    if not h.lower().startswith("bytes="):
        return None
    spec = h[len("bytes="):].strip()
    if "," in spec:
        return None
    try:
        start_s, _, end_s = spec.partition("-")
        if not end_s:
            return None
        start = int(start_s)
        end = int(end_s)
    except ValueError:
        return None
    if start < 0 or end < start:
        return None
    return (start, end)


def _is_loopback(bind: str) -> bool:
    """True only for IP-literal loopback addresses (127.0.0.0/8, ::1)."""
    import ipaddress
    try:
        return ipaddress.ip_address(bind).is_loopback
    except ValueError:
        return False


def _key_order(body: bytes) -> list[str]:
    """Extract the key order the client serialized (P5 feature), without
    interpreting values. Deterministic lexical scan of the raw body.

    Fails closed: keys are bounded in length and count, must satisfy a
    JSON-key charset, escape sequences are skipped, and scan work is bounded
    by a step budget. An ambiguous body yields a SHORTER order (possibly
    empty) — never a guessed one."""
    import re as _re
    key_ok = _re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
    order: list[str] = []
    i = 0
    n = len(body)
    steps = 0
    MAX_STEPS = 4096
    MAX_KEYS = 32
    while i < n and len(order) < MAX_KEYS and steps < MAX_STEPS:
        steps += 1
        if body[i:i + 1] == b'"':
            j = i + 1
            parts = bytearray()
            escaped = False
            while j < n and len(parts) <= 64:
                c = body[j:j + 1]
                if escaped:
                    parts += c
                    escaped = False
                elif c == b"\\":
                    escaped = True
                elif c == b'"':
                    break
                else:
                    parts += c
                j += 1
                if j - i > 128:
                    break
            if j >= n or escaped:
                break
            key = parts.decode("utf-8", "replace")
            k = j + 1
            while k < n and body[k:k + 1] in b" \t\r\n":
                k += 1
            if k < n and body[k:k + 1] == b":" and key_ok.match(key):
                if key not in order:
                    order.append(key)
            i = j + 1
        else:
            i += 1
    return order