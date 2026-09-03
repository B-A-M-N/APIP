"""Terminator-log adapters + challenge-origin tests (docs/30, WP-30).

Proof goals:
  1. adapters parse the three supported formats into contract-valid records;
  2. canned address refs normalize to ONE canonical handle (cross-format
     exactness) and log-injection / zone-id refs are rejected, never coerced;
  3. malformed log lines count as rejected/unparsed and never stop a batch;
  4. BYTE-IDENTICAL to the reference oracle for recognize / _safe_client /
     _norm_ts (differential, subprocess-isolated);
  5. origin safety: loopback default refuses non-loopback binds; raw peer
     addresses never reach records (pseudonymized); hostile Content-Length /
     Range / challenge handling fails closed without crashing the server.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from oracle_client import oracle_adapters  # noqa: E402

from apip.attribution_adapters import (  # noqa: E402
    _norm_ts,
    _safe_client,
    apply_stream,
    parse_envoy,
    parse_haproxy,
    parse_nginx,
    recognize,
)
from apip.attribution_origin import (  # noqa: E402
    _is_loopback,
    _key_order,
    _parse_range,
    _safe_content_length,
)
from apip.attribution import validate_transaction  # noqa: E402


# ---------------------------------------------------------------------------
# Address canonicalization (cross-format exactness)
# ---------------------------------------------------------------------------

def test_safe_client_ipv4_port_strips_port():
    assert _safe_client("203.0.113.7:443") == "203.0.113.7"
    assert _safe_client("203.0.113.7") == "203.0.113.7"


def test_safe_client_ipv6_canonical():
    # expanded + compressed + bracketed forms derive ONE handle
    assert _safe_client("2001:0db8:0000::0001") == "2001:db8::1"
    assert _safe_client("[2001:db8::1]:443") == "2001:db8::1"


def test_safe_client_rejects_zone_id_and_garbage():
    assert _safe_client("fe80::1%eth0") is None
    assert _safe_client("not-an-ip") is None
    assert _safe_client("") is None


# ---------------------------------------------------------------------------
# Format adapters
# ---------------------------------------------------------------------------

def test_parse_nginx_json():
    rec = parse_nginx(
        '{"time":"2026-09-01T20:00:00Z","remote_addr":"203.0.113.7",'
        '"http_accept_language":"en-US","ja4":"t13d1517h2",'
        '"header_order":"Host|User-Agent"}')
    assert rec is not None
    assert rec["client_ref"] == "203.0.113.7"
    assert rec["accept_language"] == "en-US"
    assert rec["tls_ja4"] == "t13d1517h2"
    assert rec["header_order"] == ["Host", "User-Agent"]
    # the produced record must be contract-valid
    validate_transaction(rec)


def test_parse_envoy_annotated():
    line = ('[2026-09-01T19:00:00Z] "GET /asset HTTP/1.1" 203.0.113.9 '
            'accept-language=en-US accept-encoding=gzip ja4=t13d1516h2_abc')
    rec = parse_envoy(line)
    assert rec is not None
    assert rec["client_ref"] == "203.0.113.9"
    assert rec["observed_at"] == "2026-09-01T19:00:00Z"
    assert rec["accept_language"] == "en-US"
    assert rec["tls_ja4"] == "t13d1516h2_abc"


def test_parse_haproxy():
    line = ("Sep  1 20:00:00 proxy haproxy[123]: "
            "203.0.113.7:54321 [01/Sep/2026:20:00:00.123] frontend http-in "
            'h=accept-language:en-US')
    rec = parse_haproxy(line)
    assert rec is not None
    assert rec["client_ref"] == "203.0.113.7"
    assert rec["accept_language"] == "en-US"


def test_recognize_returns_first_match_and_validates():
    # an nginx JSON line is recognized (contract-valid at the boundary)
    rec = recognize(
        '{"time":"2026-09-01T20:00:00Z","remote_addr":"10.0.0.5",'
        '"http_accept_language":"fr-FR"}')
    assert rec is not None
    assert rec["client_ref"] == "10.0.0.5"
    # a non-line is None (never a guessed record)
    assert recognize("random log junk that matches nothing") is None


def test_apply_stream_counts_and_never_stops_on_bad_lines():
    class Sink:
        rows = []
        def write(self, r):
            self.rows.append(r)

    lines = [
        '{"time":"2026-09-01T20:00:00Z","remote_addr":"10.0.0.1"}',   # parse
        "garbage not a format",                                        # unparsed
        '{"time":"not-a-timestamp","remote_addr":"10.0.0.2"}',         # rejected
        "",                                                              # skipped
        '{"time":"2026-09-01T20:00:01Z","remote_addr":"10.0.0.3"}',   # parse
    ]
    sink = Sink()
    parsed, rejected, unparsed = apply_stream(lines, sink)
    assert parsed == 2
    assert rejected == 1   # bad timestamp violates the contract
    assert unparsed == 1
    assert len(sink.rows) == 2


# ---------------------------------------------------------------------------
# Differential: adapters == reference oracle
# ---------------------------------------------------------------------------

def test_adapter_normalization_byte_identical_to_reference():
    refs = ["203.0.113.7:443", "203.0.113.7", "[2001:db8::1]:443",
            "2001:0db8:0000::0001", "fe80::1%eth0", "not-an-ip", ""]
    ts = ["2026-09-01T20:00:00Z", "01/Sep/2026:20:00:00.123",
          "03/Jan/2026:19:00:00.001", "not-a-time"]
    lines = [
        '{"time":"2026-09-01T20:00:00Z","remote_addr":"203.0.113.7",'
        '"http_accept_language":"en-US"}',
        "random log junk that matches nothing",
    ]
    script = (
        [{"op": "safe_client", "ref": r} for r in refs]
        + [{"op": "norm_ts", "ts": t} for t in ts]
        + [{"op": "recognize", "tag": str(i), "line": l} for i, l in enumerate(lines)]
    )
    oracle = oracle_adapters(script)

    mine = {}
    for r in refs:
        mine[f"sc|{r}"] = _safe_client(r)
    for t in ts:
        mine[f"ts|{t}"] = _norm_ts(t)
    for i, l in enumerate(lines):
        mine[f"rec|{i}"] = recognize(l)

    assert mine == oracle


# ---------------------------------------------------------------------------
# Origin safety properties
# ---------------------------------------------------------------------------

def test_is_loopback_only_ip_literals():
    assert _is_loopback("127.0.0.1") is True
    assert _is_loopback("::1") is True
    assert _is_loopback("203.0.113.7") is False
    assert _is_loopback("127.attacker.example") is False   # not an IP literal


def test_safe_content_length_defensive():
    assert _safe_content_length(None) == 0
    assert _safe_content_length("123") == 123
    assert _safe_content_length("1e9") is None            # non-numeric -> 400
    clamped = _safe_content_length("99999999")
    assert clamped is not None and clamped <= 65_536      # clamped
    assert _safe_content_length("-5") is None


def test_parse_range_exact_only():
    assert _parse_range("bytes=0-1") == (0, 1)
    assert _parse_range("bytes=0-") is None    # open-ended
    assert _parse_range("bytes=0-1,2-3") is None  # multi-range
    assert _parse_range("bytes=5-2") is None      # reversed
    assert _parse_range("garbage") is None


def test_key_order_lexical_scan():
    body = b'{"nonce":"abc","response":"def","probe_set":["ts"]}'
    order = _key_order(body)
    assert order == ["nonce", "response", "probe_set"]
    # bounded: no suffix pollution from a hostile long key
    hostile = b'{"' + b"x" * 5000 + b'":1}'
    assert _key_order(hostile) == []   # key longer than 64 -> fail closed


def test_challenge_origin_rejects_nonloopback_bind(tmp_path):
    from apip.attribution_origin import ChallengeOrigin
    with ChallengeOrigin(out_path=tmp_path / "tx.jsonl") as origin:
        with pytest.raises(ValueError, match="non-loopback"):
            origin.serve(bind="203.0.113.7", port=0)