#!/usr/bin/env python3
"""APIP acceptance-lab DNS resolver.

A minimal stdlib UDP DNS server that serves APIP's RPZ zone semantics on a
loopback high port for the acceptance test. It answers:

  - A/ANY queries for an owner name present in the APIP RPZ zone  -> NXDOMAIN
    (rcode 3), the expected enforcement response for `IN CNAME .`;
  - NXDOMAIN for the reserved `.invalid` TLD (these names never resolve
    publicly), so `invalid` names are unambiguously blocked regardless of
    APIP state;
  - NXDOMAIN for any owner name present in the APIP RPZ zone, and a real
    synthetic A record (10.99.0.5) for `baseline-test.operator.test` so the
    acceptance test can prove "baseline behavior restored" after revoke.

This is a LAB resolver for the acceptance test only — NOT part of the APIP
product. APIP supports operator-managed resolvers (see IMPLEMENTATION_STATUS).
"""
from __future__ import annotations

import argparse
import socket
import struct

MALFORMED = 1
NXDOMAIN = 3
NOERROR = 0


def _parse_question(data: bytes) -> tuple[list[str], int, int] | None:
    if len(data) < 12:
        return None
    offset = 12
    labels: list[str] = []
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            return None  # no compression in the query path
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if len(data) < offset + 4:
        return None
    qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
    return labels, qtype, qclass


def _encode_name(labels: list[str]) -> bytes:
    return b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\x00"


MONITOR_ONLY_MARKER = "APIP MONITOR-ONLY RPZ (OBSERVE)"


def _owned(zone_text: str, qname: str) -> bool:
    """True when the APIP RPZ zone contains an `IN CNAME .` rule for qname."""
    needle = qname.rstrip(".")
    for line in zone_text.splitlines():
        stripped = line.split(";", 1)[0].strip()
        owner = stripped.split()[0] if stripped else ""
        body = " ".join(stripped.split()[1:])
        if owner.rstrip(".") == needle \
                and "CNAME" in body and body.rstrip().endswith("."):
            return True
    return False


def _is_monitor_only(zone_text: str) -> bool:
    """A zone is monitor-only (SHADOW/OBSERVE) when its header carries the
    APIP monitor-only marker — a real enforcement resolver would NOT load it."""
    return MONITOR_ONLY_MARKER in zone_text


def _respond(packet: bytes, zone_text: str, baseline_a: str | None,
             honor_zone: bool = True) -> bytes:
    tid = packet[:2]
    parsed = _parse_question(packet)
    if parsed is None:
        return tid + struct.pack(">HHHHH", 0x8000 | MALFORMED, 0, 0, 0, 0)
    labels, qtype, _qclass = parsed
    qname = ".".join(labels)
    flags = 0x8000 | 0x0080  # QR + RA
    if qtype not in (1, 255):   # A or ANY; treat all as resolvable-0
        return tid + struct.pack(">HHHHH", flags, 1, 0, 0, 0) + _encode_name(labels) \
            + struct.pack(">HH", qtype, 1)
    answer = b""
    rcode = NOERROR
    ancount = 0
    # A monitor-only (SHADOW/OBSERVE) zone is NOT consumed for policy answers
    # by a real enforcement resolver (no live change), so the owned rule is
    # skipped and the name resolves to its normal baseline. An ENFORCE zone IS
    # consumed (NXDOMAIN for the exact owner); honor_zone decides whether we
    # even read the zone for policy answers (the acceptance's lab resolver sets
    # it False so only ENFORCE zones bite).
    owned = _owned(zone_text, qname) and not (
        _is_monitor_only(zone_text) and not honor_zone)
    if owned:
        rcode = NXDOMAIN
    elif qname.endswith(".invalid"):
        rcode = NXDOMAIN   # reserved TLD: blocked regardless of APIP state
    elif baseline_a and qname.rstrip(".") == baseline_a.rstrip("."):
        rcode = NOERROR
        answer = _encode_name(labels) + struct.pack(">HHIH", 1, 1, 60, 4) \
            + socket.inet_aton("10.99.0.5")
        ancount = 1
    elif qname.rstrip(".") == "c2-test.operator.test":
        rcode = NOERROR
        answer = _encode_name(labels) + struct.pack(">HHIH", 1, 1, 60, 4) \
            + socket.inet_aton("10.99.0.9")
        ancount = 1
    # header: byte 3 low nibble carries the rcode.
    return tid + bytes([
        (flags >> 8) & 0xFF,
        (flags & 0xFF) | rcode,
        (1 >> 8) & 0xFF, 1 & 0xFF,           # qdcount = 1
        (ancount >> 8) & 0xFF, ancount & 0xFF,
        0, 0, 0, 0,                             # nscount, arcount = 0
    ]) + _encode_name(labels) + struct.pack(">HH", qtype, 1) + answer


def serve(bind: str, port: int, zone_path: str, baseline_a: str | None,
          honor_zone: bool = True) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
    print(f"lab resolver listening on {bind}:{port} (zone={zone_path}, "
          f"baseline_a={baseline_a}, honor_zone={honor_zone})", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            zone = open(zone_path, "r", encoding="utf-8", errors="replace").read()
        except OSError:
            zone = ""
        try:
            resp = _respond(data, zone, baseline_a, honor_zone=honor_zone)
        except Exception:  # never crash the lab server on a malformed query
            resp = data[:2] + struct.pack(">HHHHH", 0x8000 | MALFORMED, 0, 0, 0, 0)
        sock.sendto(resp, addr)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5353)
    ap.add_argument("--zone", default="/tmp/apip/rpz/apip.shadow.invalid.zone")
    ap.add_argument("--baseline", default="baseline-test.operator.test")
    ap.add_argument("--honor-zone", action="store_true")
    args = ap.parse_args()
    serve(args.bind, args.port, args.zone, args.baseline,
          honor_zone=args.honor_zone)


if __name__ == "__main__":
    main()