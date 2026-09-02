"""Challenge origin (docs/30) — loopback-default observation server.

Serves the probe material on an operator-specified bind address (default
127.0.0.1) and writes observed-transaction records (JSONL) compatible with
`schema/observed_transaction.schema.json`.

HARD SAFETY PROPERTIES (enforced in code and tests):
  - observe-only: the server performs NO enforcement action of any kind.
    It never blocks, redirects, rate-limits, or refuses based on identity —
    every request receives a response (200, 404, or challenge material);
  - no outbound connections: the handler opens no sockets, performs no
    DNS resolution, and issues no callbacks;
  - loopback default: without an explicit --bind flag the server refuses
    to start on a non-loopback address (production deployments must opt in);
  - pseudonymization at the boundary: raw client addresses are passed
    through `handle_for()` before anything else retains them, and the raw
    address never reaches the transaction records;
  - bounded output: the JSONL writer enforces a max-records cap with
    deterministic stop-and-mark, mirroring docs/23 resource envelopes.

v2.2 robustness (independent-audit findings 7–9):
  - the writer is thread-safe: ThreadingHTTPServer runs one handler thread
    per request, and the writer previously raced on its cap counter and
    file handle (demonstrated cap overshoot + closed-file exceptions);
  - hostile Content-Length values are rejected or clamped: a non-numeric
    header crashed the handler and a negative one turned the bounded body
    read into an unbounded read-until-EOF (thread pinned per connection);
  - every connection has a hard socket timeout, so a stalled client can
    pin a thread for seconds, not forever;
  - handler exceptions answer 400 and never escape into the server loop.
"""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ..attribution import (
    CorrelationStore,
    TransactionRejected,
    handle_for,
    probe_order,
    validate_transaction,
)

# Canonical-JSON challenge object (P5 material): the client is asked to
# echo this object with its own serializer; the KEY ORDER it emits is the
# behavioral feature. Key order is scrambled deterministically per session
# by probe_order so replayed/frozen responses are detectable.
CHALLENGE_KEYS = ("ts", "nonce", "response", "probe_set")

# Per-connection socket timeout (seconds): bounds how long one slow client
# can pin one handler thread.
HANDLER_TIMEOUT_S = 30
# Hard body cap (bytes) regardless of the claimed Content-Length.
MAX_BODY_BYTES = 65_536


class _TxWriter:
    """Bounded, thread-safe JSONL writer for observed-transaction records.

    v2.2: every mutation of (_count, _fh, degraded) happens under a lock.
    The cap is now exact under contention (previously overshot) and a
    thread can never flush a handle another thread just closed.
    """

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
            # lock starvation is itself degradation: stop-and-mark rather
            # than block the handler thread indefinitely
            self.degraded = True
            return
        try:
            if self.degraded:
                return
            if self._count >= self._max:
                self.degraded = True   # stop-and-mark (docs/23 discipline)
                if self._fh:
                    self._fh.close()
                    self._fh = None
                return
            if self._fh is None:
                self._path.parent.mkdir(parents=True, exist_ok=True)
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
    resulting records into a CorrelationStore in-process (or leave the
    JSONL for the offline pipeline).
    """

    def __init__(self, out_path: Path, epoch: str = "0",
                 max_records: int = 100_000, store: CorrelationStore | None = None):
        self.writer = _TxWriter(Path(out_path), max_records=max_records)
        self.epoch = epoch
        self.store = store
        self.requests_observed = 0
        self._sessions: dict[str, int] = {}     # handle -> assigned session number
        self._sessions_lock = threading.Lock()  # handler threads race here too
        self._counter_lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None

    # -- handler factory ---------------------------------------------------

    def _make_handler(self):
        origin = self

        class Handler(BaseHTTPRequestHandler):
            # observable behaviors captured per request:
            #   P1: header emission order (as received, before any parsing)
            #   P2: locale/encoding coherence inputs
            #   P4: conditional-request correctness on the versioned asset
            #   P6: Range/Accept-Encoding fallback behavior
            timeout = HANDLER_TIMEOUT_S   # bounds stalled-client thread pinning

            def _record_common(self) -> dict[str, Any]:
                headers = []
                for k in self.headers.keys():
                    lk = k.lower()
                    if lk not in headers:
                        headers.append(lk)
                rec: dict[str, Any] = {
                    "client_ref": self.client_address[0],
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
                raw = self.client_address[0]
                handle = handle_for(raw)   # pseudonymize first, retain raw nowhere
                with origin._sessions_lock:
                    n = origin._sessions.get(handle, 0)
                    origin._sessions[handle] = n + 1
                return handle, n

            def log_message(self, fmt, *args):  # quiet by default
                pass

            # P4/P6 material: a versioned asset with known validators.
            def do_GET(self):
                rec = self._record_common()
                with origin._counter_lock:
                    origin.requests_observed += 1
                etag = '"v1-2026-09-01"'
                path = self.path.split("?")[0]
                if path == "/healthz":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"ok\n")
                    return
                if path == "/asset":
                    inm = self.headers.get("If-None-Match")
                    rng = self.headers.get("Range")
                    if rng:
                        # P6: does the client honor a 206 with the requested slice?
                        self.send_response(206)
                        self.send_header("Content-Type", "text/plain")
                        self.send_header("Content-Range", "bytes 0-1/8")
                        self.end_headers()
                        self.wfile.write(b"AB")
                        rec["range_fallback"] = "range_honored"
                    elif inm == etag:
                        self.send_response(304)
                        self.end_headers()
                        rec["cache_behavior"] = "validators_present_correct"
                    elif inm is not None:
                        self.send_response(200)
                        self.send_header("ETag", etag)
                        self.end_headers()
                        self.wfile.write(b"ASTVWXYZ")
                        rec["cache_behavior"] = "validators_present_incorrect"
                    else:
                        self.send_response(200)
                        self.send_header("ETag", etag)
                        self.end_headers()
                        self.wfile.write(b"ASTVWXYZ")
                        rec["cache_behavior"] = "validators_absent"
                else:
                    # P1 surface on a synthetic 404: header-order vector.
                    self.send_response(404)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"not found\n")
                handle, n = self._session_for()
                rec["client_ref"] = handle          # records carry the pseudonym only
                rec["session_epoch"] = origin.epoch
                origin.emit(rec)

            # P5 material: the canonical-JSON challenge object.
            def do_POST(self):
                rec = self._record_common()
                with origin._counter_lock:
                    origin.requests_observed += 1
                length = _safe_content_length(self.headers.get("Content-Length"))
                if length is None:
                    # hostile or malformed framing: answer 400, never crash
                    self.send_response(400)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"bad content-length\n")
                    return
                # bounded read: hard cap regardless of the claimed length
                body = self.rfile.read(min(length, MAX_BODY_BYTES)) if length else b""
                _, n = self._session_for()
                probes = probe_order(f"post-{n}", origin.epoch)
                if self.path == "/challenge":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    # deterministic key scramble for this session interaction
                    obj = {k: "..." for k in probes[:len(CHALLENGE_KEYS)]}
                    self.wfile.write(json.dumps(obj).encode())
                    rec["challenge_body_key_order"] = _key_order(body)
                else:
                    self.send_response(404)
                    self.end_headers()
                handle, _ = self._session_for()
                rec["client_ref"] = handle
                rec["session_epoch"] = origin.epoch
                origin.emit(rec)

        return Handler

    # -- emit + fold --------------------------------------------------------

    def emit(self, rec: dict[str, Any]) -> None:
        """Validate, write, and (optionally) fold one observed transaction.
        Invalid records are dropped with a counter, never coerced."""
        try:
            validate_transaction(rec)
        except TransactionRejected:
            self.writer.write({"rejected": True, "reason": "contract",
                               "observed_at": rec.get("observed_at")})
            return
        self.writer.write(rec)
        if self.store is not None:
            with self._counter_lock:
                self.store.observe(rec)

    # -- lifecycle -----------------------------------------------------------

    def serve(self, bind: str = "127.0.0.1", port: int = 8765) -> None:
        """Start serving. Refuses non-loopback binds unless explicitly opted in
        via allow_nonloopback=True on serve_forever (production opt-in)."""
        if not bind.startswith("127.") and bind not in ("localhost", "::1"):
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
        if self._server:
            self._server.shutdown()
            self._server = None
        self.writer.close()


def _safe_content_length(raw: str | None) -> int | None:
    """Parse a Content-Length header defensively.

    Returns None for anything that is not a plain non-negative integer
    (the handler answers 400), otherwise the clamped integer value. The
    previous inline `int(header or 0)` crashed on non-numeric input and
    turned negative values into read-until-EOF body reads.
    """
    if raw is None:
        return 0
    raw = raw.strip()
    if not raw or not raw.isdigit():
        return None
    try:
        return min(int(raw), MAX_BODY_BYTES)
    except ValueError:
        return None


def _is_loopback(bind: str) -> bool:
    return bind.startswith("127.") or bind in ("localhost", "::1")


def _key_order(body: bytes) -> list[str]:
    """Extract the key order the client serialized (P5 feature), without
    interpreting values. Deterministic scan of the raw body.

    v2.1.1 hardening (audit residual): the extractor is a lexical scan, not
    a JSON parser — a hostile body could previously steer it into quoting a
    long run of body text as "keys" (e.g. `"` + 10k chars + `"`), yielding
    polluted features. Fails closed now: keys are bounded in length and
    count, must satisfy a JSON-key charset, escape sequences are skipped
    rather than scanned, and scan work is bounded by a step budget. An
    ambiguous body yields a SHORTER order (possibly empty) — never a
    guessed one.
    """
    import re as _re
    key_ok = _re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
    order: list[str] = []
    i = 0
    n = len(body)
    steps = 0
    MAX_STEPS = 4096        # bound total scan work regardless of body shape
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
                    # skip escaped char wholesale: an escaped quote or
                    # backslash is content, never structure
                    parts += c
                    escaped = False
                elif c == b"\\":
                    escaped = True
                elif c == b'"':
                    break
                else:
                    parts += c
                j += 1
                if j - i > 128:   # bound per-key scan window
                    break
            if j >= n or escaped:
                break               # unterminated key: fail closed
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
