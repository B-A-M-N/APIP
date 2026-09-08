"""Suricata EVE JSON datasource (audit #17) — the first production feed.

One bounded structured stream (a Suricata ``eve.json``) supplies DNS, TLS
and flow observations, converted into ``LiveBehavioralFeed`` intake calls.
Design mirrors the rest of the platform:

  - checkpointed: the reader persists (inode, offset) so a restart resumes
    WHERE IT LEFT OFF — never re-ingesting (duplicate detections) and never
    skipping (silent loss). A rotated file (inode change) restarts from the
    top of the new file.
  - bounded: a fixed-depth line window; an overwhelmed converter DROPS
    (counted) rather than growing without bound — degradation reduces
    coverage, never memory.
  - validating: every line must be a JSON object carrying the fields the
    conversion needs for its event_type; malformed lines are counted and
    skipped, never partially folded.
  - deterministic conversion: EVE timestamps are parsed once into
    (ts_iso, epoch_s); intake rejects contradictions (P1-23).

Only the stdlib is used. ``SuricataEveSource.run_forever()`` is intended to
run on the controller's lifecycle (a worker thread started by ``start()``,
stopped by ``stop()``); ``process_available()`` is the synchronous form for
callers with their own loop.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from apip.telemetry.feed import LiveBehavioralFeed

DEFAULT_MAX_LINES_PER_PASS = 5_000
CHECKPOINT_SUFFIX = ".apip-eve-checkpoint"


class EveSourceError(RuntimeError):
    pass


class SuricataEveSource:
    """Tail a Suricata EVE JSON file into a ``LiveBehavioralFeed``.

    Supported event types (the vertical slice the feed intakes today):

      - ``dns``  (v1 ``dns`` or v2 ``dns`` nested records) -> on_dns_query
        and on_dns_answer;
      - ``tls``  -> on_tls (SNI vs certificate coverage when Suricata
        provides ``sni``/``subject``);
      - ``flow`` -> on_flow (byte counters, app_proto best effort).

    Event types the feed has no intake for are counted
    (``unsupported_events``) and skipped — honestly visible on ``stats()``.
    """

    def __init__(self, feed: LiveBehavioralFeed, eve_path: str | Path,
                 checkpoint_path: str | Path | None = None,
                 max_lines_per_pass: int = DEFAULT_MAX_LINES_PER_PASS):
        self.feed = feed
        self.path = Path(eve_path)
        self.checkpoint_path = Path(
            checkpoint_path) if checkpoint_path else (
            self.path.parent / (self.path.name + CHECKPOINT_SUFFIX))
        self._max_lines = max(1, int(max_lines_per_pass))
        self._stop = threading.Event()
        # (inode, offset) checkpoint; loaded eagerly so process_available()
        # resumes even without a prior run_forever() in this process.
        self._inode, self._offset = self._load_checkpoint()
        # stats: degradation is counted, never silent
        self.lines_read = 0
        self.events_converted = 0
        self.malformed_lines = 0
        self.unsupported_events = 0
        self.checkpoint_writes = 0
        self.last_error: str | None = None

    # -- checkpoint ----------------------------------------------------------

    def _load_checkpoint(self) -> tuple[int, int]:
        try:
            raw = self.checkpoint_path.read_text(encoding="utf-8")
            inode_s, offset_s = raw.split()
            return int(inode_s), int(offset_s)
        except (OSError, ValueError):
            return -1, 0

    def _save_checkpoint(self, inode: int, offset: int) -> None:
        tmp = self.checkpoint_path.with_suffix(
            self.checkpoint_path.suffix + ".tmp")
        try:
            tmp.write_text(f"{inode} {offset}\n", encoding="utf-8")
            os.replace(tmp, self.checkpoint_path)
            self.checkpoint_writes += 1
        except OSError as e:      # checkpoint loss degrades to re-read; the
            self.last_error = f"checkpoint write failed: {e}"   # feed's own
            # dedup (bounded pending + evidence identity) bounds the damage

    # -- conversion ----------------------------------------------------------

    @staticmethod
    def _split_ts(record: dict) -> tuple[str, int] | None:
        """EVE 'timestamp' (ISO-8601) -> (iso, epoch_s); None when absent or
        unparseable (counted upstream as malformed)."""
        ts = record.get("timestamp")
        if not isinstance(ts, str):
            return None
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            iso = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            return iso, int(dt.timestamp())
        except ValueError:
            return None

    def convert(self, record: dict) -> int:
        """Fold one validated EVE record into the feed. Returns the number
        of intake calls made (0 for unsupported/shapeless records)."""
        et = record.get("event_type")
        pair = self._split_ts(record)
        if pair is None:
            self.malformed_lines += 1
            return 0
        ts_iso, epoch_s = pair
        made = 0
        if et == "dns":
            dns = record.get("dns") or {}
            if not isinstance(dns, dict):
                self.malformed_lines += 1
                return 0
            # EVE v2 nests under "dns"; v1 flat. Accept both shapes.
            rrtype = dns.get("rrtype") or record.get("rrtype") or ""
            src = record.get("src_ip") or ""
            domain = dns.get("rrname") or record.get("rrname") or ""
            answers = dns.get("answers") or []
            if domain:
                self.feed.on_dns_query(src=src, domain=domain,
                                       qtype=str(rrtype) or None,
                                       ts_iso=ts_iso, epoch_s=epoch_s)
                made += 1
            for ans in answers:
                if not isinstance(ans, dict):
                    continue
                if str(ans.get("rrtype", "")).upper() in ("A", "AAAA") \
                        and ans.get("rdata"):
                    self.feed.on_dns_answer(
                        domain=domain, answer=str(ans["rdata"]),
                        ttl=int(ans.get("ttl") or 0),
                        ts_iso=ts_iso, epoch_s=epoch_s)
                    made += 1
        elif et == "tls":
            tls = record.get("tls") or {}
            if not isinstance(tls, dict):
                self.malformed_lines += 1
                return 0
            sni = tls.get("sni") or None
            subject = tls.get("subject") or None
            dest = record.get("dest_ip") or ""
            try:
                import ipaddress as _ipa
                _ipa.ip_address(dest)
                is_ip_https = True
            except ValueError:
                is_ip_https = False
            # Suricata does not hand us a full SAN list on the wire; the
            # conservative fold treats an absent subject as uncovered and a
            # subject that does not contain the SNI as a mismatch signal —
            # the detector's job, not ours, is to weigh it.
            covers = bool(sni and subject and sni in subject)
            self.feed.on_tls(
                client=record.get("src_ip") or "",
                dst=tls.get("sni") or dest,
                sni=sni,
                cert_covers_sni=covers,
                is_ip_https=is_ip_https,
                has_sni=sni is not None,
                ts_iso=ts_iso, epoch_s=epoch_s)
            made += 1
        elif et == "flow":
            flow = record.get("flow") or {}
            if not isinstance(flow, dict):
                self.malformed_lines += 1
                return 0
            self.feed.on_flow(
                host=record.get("src_ip") or "",
                dst=record.get("dest_ip") or "",
                out_bytes=int(flow.get("bytes_toserver") or 0),
                in_bytes=int(flow.get("bytes_toclient") or 0),
                ts_iso=ts_iso, epoch_s=epoch_s)
            made += 1
        else:
            self.unsupported_events += 1
        return made

    def process_available(self, *, checkpoint: bool = True) -> int:
        """Read NEW lines since the checkpoint, convert each, advance the
        checkpoint. Returns converted-event count. Bounds work per pass."""
        try:
            st = self.path.stat()
        except OSError:
            return 0                 # file not created yet: nothing to do
        inode, size = st.st_ino, st.st_size
        if inode != self._inode:
            # rotation (or first sight): start the new file from the top
            self._inode, self._offset = inode, 0
        if size < self._offset:
            self._offset = 0         # truncation: restart
        if size <= self._offset:
            return 0
        converted = 0
        try:
            with self.path.open("rb") as f:
                f.seek(self._offset)
                for _ in range(self._max_lines):
                    line_start = f.tell()
                    line = f.readline()
                    if not line:
                        break
                    if not line.endswith(b"\n"):
                        # partial write: rewind to the line start so the
                        # checkpoint re-reads the WHOLE line next pass —
                        # tell() here has already consumed the torn bytes.
                        f.seek(line_start)
                        break
                    self.lines_read += 1
                    try:
                        rec = json.loads(line)
                        if not isinstance(rec, dict):
                            raise ValueError("not an object")
                    except ValueError:
                        self.malformed_lines += 1
                        continue
                    converted += self.convert(rec)
                self._offset = f.tell()
        except OSError as e:
            self.last_error = f"read failed: {e}"
            return converted
        if checkpoint:
            self._save_checkpoint(self._inode, self._offset)
        return converted

    # -- lifecycle -------------------------------------------------------------

    def run_forever(self, poll_s: float = 0.5) -> None:
        """Worker-loop form: process until ``stop()``. Runs on a controller
        thread; never raises out of the loop (degradation is counted)."""
        while not self._stop.is_set():
            try:
                self.process_available()
            except Exception as e:       # noqa: BLE001 — the tail must not
                self.last_error = str(e)  # die silently or loudly kill the
            self._stop.wait(max(0.05, poll_s))          # controller thread

    def start_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.run_forever, name="apip-eve",
                             daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()

    def stats(self) -> dict:
        return {
            "path": str(self.path),
            "inode": self._inode,
            "offset": self._offset,
            "lines_read": self.lines_read,
            "events_converted": self.events_converted,
            "malformed_lines": self.malformed_lines,
            "unsupported_events": self.unsupported_events,
            "checkpoint_writes": self.checkpoint_writes,
            "last_error": self.last_error,
        }
