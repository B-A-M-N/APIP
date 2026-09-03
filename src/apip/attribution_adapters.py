"""Terminator log adapters (docs/30, WP-30).

Byte-compatible port of ``reference/src/apip/live/adapters.py`` — the
collection channel that turns production proxy/TLS-terminator access logs
into observed-transaction records conforming to the docs/30 contract.

Each adapter is a pure line->record function plus a line-format recognizer.
Only observable-behavior fields are mapped; anything outside the contract is
dropped, and records that would violate the contract are rejected (never
coerced) via ``validate_transaction`` at emit time.

Supported formats (operators extend by registering an adapter):
  - envoy      : default Envoy access-log format
  - haproxy    : HAProxy default HTTP log format (format %b)
  - nginx      : NGINX `log_format` with the JSON escape (common fields)

This is OBSERVE-ONLY: parsing a log never triggers or influences any
enforcement action, and a malformed line never stops a batch (counted,
not raised).
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Callable

from apip.attribution import TransactionRejected, validate_transaction

Adapter = Callable[[str], dict | None]

_ADAPTERS: dict[str, Adapter] = {}


def adapter(name: str):
    def register(fn: Adapter) -> Adapter:
        _ADAPTERS[name] = fn
        return fn
    return register


def _safe_client(ref: str) -> str | None:
    """Accept well-formed address refs in ALL common terminator spellings;
    log injection attempts are rejected rather than sanitized into something
    plausible.

    Normalization rules (the handle is derived from the RETURNED string, so
    every spelling of one address must return the same string):
      - ip:port (IPv4)      -> bare address;
      - [v6]:port           -> bare v6 address;
      - bare v6             -> canonical RFC 5952 form, so '2001:db8::1' and
                               '2001:0db8:0000::1' derive ONE handle;
      - zone ids ('%eth0')  -> rejected (link-local scope is not a stable
                               requester identity).
    Returns the CANONICAL ipaddress rendering, which is what the attribution
    HMAC hashes.
    """
    ref = (ref or "").strip()
    if not ref:
        return None
    if ref.startswith("[") and "]" in ref:
        host, _, port = ref[1:].partition("]")
        if port.startswith(":"):
            addr = host
        else:
            return None
    else:
        if ref.count(":") == 1:
            addr = ref.rsplit(":", 1)[0]
        else:
            addr = ref
    if "%" in addr:            # zone id: not a stable identity
        return None
    try:
        return str(ipaddress.ip_address(addr))
    except ValueError:
        return None


@adapter("envoy")
def parse_envoy(line: str) -> dict | None:
    m = re.match(r'^\[(?P<ts>[^\]]+)\]\s+"(?P<req>[^"]*)"\s+(?P<rest>.*)$', line)
    if not m:
        return None
    req = m.group("req").split()
    if len(req) < 2:
        return None
    rest = (m.group("rest") or "").strip()
    first = rest.split('"', 1)[0].split()
    if not first:
        return None
    client = _safe_client(first[0])
    if client is None:
        return None
    rec: dict = {"client_ref": client, "observed_at": _norm_ts(m.group("ts"))}
    for tok in re.findall(r'(\w[\w.-]*)=([^\s"]+)', m.group("rest")):
        k, v = tok
        lk = k.lower()
        if lk == "accept-language":
            rec["accept_language"] = v[:256]
        elif lk == "accept-encoding":
            rec["accept_encoding"] = v[:256]
        elif lk == "x-envoy-external-ja4" or lk == "ja4":
            rec["tls_ja4"] = v[:128]
    return rec


@adapter("haproxy")
def parse_haproxy(line: str) -> dict | None:
    m = re.match(r'^\S+\s+\d+\s+\S+\s+\S+\s+haproxy\[\d+\]:\s+(?P<client>\S+)\s+'
                 r'\[(?P<ts>[^\]]+)\]', line)
    if not m:
        return None
    client = _safe_client(m.group("client"))
    if client is None:
        return None
    rec: dict = {"client_ref": client, "observed_at": _norm_ts(m.group("ts"))}
    for tok in re.findall(r'h=([\w-]+):([^\s]+)', line):
        lk = tok[0].lower()
        if lk == "accept-language":
            rec["accept_language"] = tok[1][:256]
        elif lk == "accept-encoding":
            rec["accept_encoding"] = tok[1][:256]
    return rec


@adapter("nginx")
def parse_nginx(line: str) -> dict | None:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    client = _safe_client(str(obj.get("remote_addr", "")))
    ts = obj.get("time") or obj.get("time_iso8601")
    if client is None or not isinstance(ts, str):
        return None
    rec: dict = {"client_ref": client, "observed_at": _norm_ts(ts)}
    al = obj.get("http_accept_language")
    ae = obj.get("http_accept_encoding")
    ja4 = obj.get("ja4") or obj.get("ssl_ja4")
    if isinstance(al, str):
        rec["accept_language"] = al[:256]
    if isinstance(ae, str):
        rec["accept_encoding"] = ae[:256]
    if isinstance(ja4, str):
        rec["tls_ja4"] = ja4[:128]
    ho = obj.get("header_order")
    if isinstance(ho, str) and ho:
        names = [h for h in ho.split("|") if h][:64]
        if len(set(names)) == len(names):
            rec["header_order"] = names
    return rec


from datetime import datetime as _dt, timezone as _tz  # noqa: E402

_CLF_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def _norm_ts(ts: str) -> str:
    """Normalize the three common terminator timestamp shapes to the
    contract's ISO-8601 UTC form. Unparseable input is passed through and
    will be rejected at the contract boundary (never silently accepted)."""
    ts = ts.strip()
    try:
        if ts[4] == "-" and ts[7] == "-" and "T" in ts:
            d = _dt.fromisoformat(ts.replace("Z", "+00:00"))
            if d.tzinfo is None:
                d = d.replace(tzinfo=_tz.utc)
            return d.astimezone(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, IndexError):
        pass
    m = re.match(r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$", ts)
    if m:
        day, mon, year, hh, mm, ss, frac = m.groups()
        month = _CLF_MONTHS.get(mon.title())
        if month:
            try:
                micro = int((frac or "0").ljust(6, "0")[:6])
                d = _dt(year=int(year), month=month, day=int(day),
                        hour=int(hh), minute=int(mm), second=int(ss),
                        microsecond=micro, tzinfo=_tz.utc)
            except ValueError:
                return ts
            return d.strftime("%Y-%m-%dT%H:%M:%SZ")
    return ts


def recognize(line: str) -> dict | None:
    """Try each registered adapter; returns the first accepted record.
    Unrecognized lines yield None (logged-and-dropped upstream), never a
    guessed record."""
    for fn in _ADAPTERS.values():
        rec = fn(line)
        if rec is not None:
            validate_transaction(rec)   # contract enforcement at the boundary
            return rec
    return None


def apply_stream(lines, out) -> tuple[int, int, int]:
    """Convert a log stream to contract records. Returns
    (parsed, rejected, unparsed). Rejected records raise nothing here —
    they are counted, because one malformed line must not stop a batch."""
    parsed = rejected = unparsed = 0
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        try:
            rec = recognize(line)
        except TransactionRejected:
            rejected += 1
            continue
        if rec is None:
            unparsed += 1
            continue
        out.write(rec)
        parsed += 1
    return parsed, rejected, unparsed