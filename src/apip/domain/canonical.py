"""Canonical value normalization — production port of the reference
ingest canonicalizer (``reference/src/apip/io.py`` ``_canonicalize``).

Every indicator value stored in the ledger is canonical: FQDNs are IDNA-
encoded lowercase with trailing dots stripped and a closed charset (this is
the artifact-injection defense — 'evil.com;' never reaches a zone file);
IPs/CIDRs are their ``ipaddress`` canonical renderings. Timestamps accept
only ISO-8601 UTC.

Byte-identical with the oracle so a value normalized here and a value
normalized by the reference ingest produce the same decision input.
"""
from __future__ import annotations

import ipaddress
import re

# Zone-file/rule-safe FQDN form: LDH + dots only, after IDNA (reference
# adversarial-audit fix: ';' starts a zone-file comment).
_FQDN_SAFE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*$")

# ISO-8601 UTC timestamp shape (same contract as the reference ingest).
_ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")

INDICATOR_TYPES = frozenset({"fqdn", "ipv4", "ipv6", "cidr", "url"})


def is_iso_utc(ts: str) -> bool:
    return bool(ts) and bool(_ISO_UTC.match(ts))


def canonicalize(kind: str, value: str) -> str:
    """Canonical form for an indicator value; raises ValueError on anything
    that cannot be represented safely."""
    value = value.strip()
    if kind == "fqdn":
        v = value.rstrip(".").lower()
        if not v or " " in v or "/" in v:
            raise ValueError(f"invalid fqdn: {value!r}")
        v = v.encode("idna").decode("ascii")
        if not _FQDN_SAFE.match(v):
            raise ValueError(f"invalid fqdn (unsafe characters): {value!r}")
        if any(len(label) > 63 for label in v.split(".")) or len(v) > 253:
            raise ValueError(f"invalid fqdn (label/length): {value!r}")
        return v
    if kind == "ipv4":
        return str(ipaddress.IPv4Address(value))
    if kind == "ipv6":
        return str(ipaddress.IPv6Address(value))
    if kind == "cidr":
        return str(ipaddress.ip_network(value, strict=False))
    if kind == "url":
        if any(c in value for c in ' \t\r\n;"\\'):
            raise ValueError(f"invalid url (unsafe characters): {value!r}")
        if len(value) > 2048:
            raise ValueError("invalid url (length)")
        return value
    raise ValueError(f"unsupported indicator type: {kind!r}")
