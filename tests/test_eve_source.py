"""Suricata EVE JSON datasource (audit #17) — the production feed proof.

Properties:

  - real EVE lines convert into the right LiveBehavioralFeed intake calls
    (dns v1 flat + v2 nested, tls, flow) and unsupported types are counted;
  - checkpointed resume: a restart never re-reads consumed lines (no
    duplicate detections) and a mid-line partial write is left for later;
  - file rotation (inode change) restarts from the top of the new file;
  - malformed lines are counted and skipped, never partially folded;
  - the bounded pass limit caps work (backpressure without unbounded
    growth), and degradation is visible on stats().
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apip.telemetry.behavioral import (  # noqa: E402
    BEACON_KIND, DGA_KIND, FASTFLUX_KIND, TLS_KIND, VOLUME_KIND,
)
from apip.telemetry.feed import LiveBehavioralFeed  # noqa: E402
from apip.telemetry.sources.suricata_eve import SuricataEveSource  # noqa: E402


def _line(obj: dict) -> str:
    return json.dumps(obj) + "\n"


def _dns_v2(domain: str, ts="2026-09-04T05:00:00Z", answers=None) -> dict:
    return {"timestamp": ts, "event_type": "dns", "src_ip": "10.0.0.5",
            "dns": {"type": "query", "rrname": domain, "rrtype": "A",
                    "answers": answers or []}}


def test_eve_lines_drive_feed_detections(tmp_path):
    eve = tmp_path / "eve.json"
    high_entropy = "9f86d081884c7d65"
    lines = [
        _line(_dns_v2(f"{high_entropy}.c2.invalid")),
        _line({"timestamp": "2026-09-04T05:00:01Z", "event_type": "alert",
               "alert": {"signature": "x"}}),          # unsupported type
        _line({"timestamp": "2026-09-04T05:00:02Z", "event_type": "flow",
               "src_ip": "10.0.0.5", "dest_ip": "198.51.100.9",
               "flow": {"bytes_toserver": 999_999_999,
                        "bytes_toclient": 10}}),
        _line({"timestamp": "2026-09-04T05:00:03Z", "event_type": "tls",
               "src_ip": "10.0.0.5", "dest_ip": "203.0.113.7",
               "tls": {"sni": "evil.invalid", "subject": "CN=other.invalid"}}),
        "not json at all\n",
    ]
    eve.write_text("".join(lines), encoding="utf-8")
    feed = LiveBehavioralFeed()
    src = SuricataEveSource(feed, eve, checkpoint_path=tmp_path / "ck")
    converted = src.process_available()
    assert converted == 3                    # dns + flow + tls
    assert src.unsupported_events == 1
    assert src.malformed_lines == 1
    st = src.stats()
    assert st["lines_read"] == 5
    # every converted observation landed in the feed's bounded retention
    # (the DNS line drives TWO detections: dga_likelihood + novelty)
    assert feed.detections_emitted == 4
    # and the detections resolve against known indicators as evidence
    ev = feed.attach_to_indicators({
        f"{high_entropy}.c2.invalid": "ind--c2",
        "198.51.100.9": "ind--exfil",
        "evil.invalid": "ind--tls"})
    kinds = {e["kind"] for e in ev}
    assert DGA_KIND in kinds and VOLUME_KIND in kinds and TLS_KIND in kinds
    assert all(e["indicator_id"].startswith("ind--") for e in ev)


def test_checkpoint_resume_never_repeats(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text(_line(_dns_v2("one.invalid")), encoding="utf-8")
    feed = LiveBehavioralFeed()
    src = SuricataEveSource(feed, eve, checkpoint_path=tmp_path / "ck")
    src.process_available()
    first = feed.detections_emitted
    # second pass with nothing new: no re-read, no duplicates
    assert src.process_available() == 0
    assert feed.detections_emitted == first
    # new appended lines are consumed exactly once
    with eve.open("a", encoding="utf-8") as f:
        f.write(_line(_dns_v2("two.invalid")))
    assert src.process_available() == 1
    assert feed.detections_emitted == first + 1


def test_partial_line_left_for_next_pass(tmp_path):
    eve = tmp_path / "eve.json"
    full = _line(_dns_v2("a.invalid"))
    torn = json.dumps(_dns_v2("b.invalid"))
    head, tail = torn[:20], torn[20:]
    eve.write_text(full + head, encoding="utf-8")   # torn write
    feed = LiveBehavioralFeed()
    src = SuricataEveSource(feed, eve, checkpoint_path=tmp_path / "ck")
    assert src.process_available() == 1
    # complete the torn line
    with eve.open("a", encoding="utf-8") as f:
        f.write(tail + "\n")
    assert src.process_available() == 1
    assert src.malformed_lines == 0


def test_rotation_restarts_new_file_from_top(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text(_line(_dns_v2("old.invalid")), encoding="utf-8")
    feed = LiveBehavioralFeed()
    src = SuricataEveSource(feed, eve, checkpoint_path=tmp_path / "ck")
    src.process_available()
    old_inode = src.stats()["inode"]
    # rotate: rename + recreate
    eve.rename(tmp_path / "eve.json.1")
    eve.write_text(_line(_dns_v2("new.invalid")), encoding="utf-8")
    assert src.process_available() == 1
    assert src.stats()["inode"] != old_inode
    assert src.stats()["offset"] == eve.stat().st_size


def test_pass_bound_caps_work(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text("".join(_line(_dns_v2(f"d{i}.invalid"))
                           for i in range(50)), encoding="utf-8")
    feed = LiveBehavioralFeed()
    src = SuricataEveSource(feed, eve, checkpoint_path=tmp_path / "ck",
                            max_lines_per_pass=10)
    assert src.process_available() == 10
    assert src.process_available() == 10     # resumes where it stopped
    assert src.stats()["lines_read"] == 20


def test_worker_thread_stops_cleanly(tmp_path):
    eve = tmp_path / "eve.json"
    feed = LiveBehavioralFeed()
    src = SuricataEveSource(feed, eve, checkpoint_path=tmp_path / "ck")
    t = src.start_thread()
    src.stop()
    t.join(timeout=5)
    assert not t.is_alive()
