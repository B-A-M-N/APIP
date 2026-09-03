"""Input/output integrity layer — production port of ``reference/src/apip/sanitize.py``.

One module, one job: nothing crosses a trust boundary without passing a
closed validator here. Same two boundaries as the oracle:

  1. INGEST — external data enters the decision path; every field is
     charset- and length-bounded at load time.
  2. EMIT — internal data is compiled into third-party artifact languages
     (RPZ zone files); the adapter validates/escapes at compile time as
     defense in depth.

Design rules (docs/09): fail closed; closed charsets; artifact escaping is a
last resort that renders a value inert, never a transformation to reason
about. Kept byte-identical with the oracle so differential tests can rely on
identical accept/reject behavior.
"""
from __future__ import annotations

import re

_ID_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9_.\-/:]{1,128}$")
_CLIENT_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")
_FQDN_RE = re.compile(r"^[a-z0-9_\-]+(\.[a-z0-9_\-]+)*\.?$")


class UnsafeIdentifier(ValueError):
    """A string crossed a trust boundary carrying characters that are
    meaningful in some downstream artifact language."""


def validate_id(value: str, what: str = "id") -> str:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise UnsafeIdentifier(
            f"unsafe {what}: must match [A-Za-z0-9_.:-] and be 1..128 chars, "
            f"got {value!r}")
    return value


def validate_label(value: str, what: str = "label") -> str:
    if not isinstance(value, str) or not _LABEL_RE.match(value):
        raise UnsafeIdentifier(
            f"unsafe {what}: must match [A-Za-z0-9_.-/:] and be 1..128 chars, "
            f"got {value!r}")
    return value


def validate_client(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _CLIENT_RE.match(value):
        raise UnsafeIdentifier(
            f"unsafe client reference: must match [A-Za-z0-9_.:-] and be "
            f"1..128 chars, got {value!r}")
    return value


def validate_fqdn(value: str) -> str:
    v = value.rstrip(".")
    if not v or not _FQDN_RE.match(value):
        raise UnsafeIdentifier(f"unsafe fqdn for artifact: {value!r}")
    if any(len(label) > 63 for label in v.split(".")) or len(v) > 253:
        raise UnsafeIdentifier(f"unsafe fqdn length: {value!r}")
    return v


def validate_ip_literal(value: str) -> str:
    import ipaddress
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        raise UnsafeIdentifier(f"unsafe ip literal for artifact: {value!r}")
    if str(addr) != value:
        raise UnsafeIdentifier(
            f"non-canonical ip literal for artifact: {value!r} "
            f"(canonical form is {str(addr)!r})")
    return value


def rpz_comment_safe(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:\-= ]", "_", str(value))
    if ";" in cleaned or "\n" in cleaned or "(" in cleaned or ")" in cleaned:
        raise UnsafeIdentifier(f"value for rpz comment still unsafe: {value!r}")
    return cleaned or "_"


def suricata_safe(value: str, field: str) -> str:
    """Render a value safe for interpolation into Suricata rule metadata.

    Suricata rule option values are terminated by ``;`` and comment-terminated
    by ``#``. This is the compile-time backstop behind the ingest boundary
    (mirror of the reference exporter's ``suricata_safe``): any character that
    can alter rule structure is rendered inert, and the value is rejected
    outright if it still carries rule syntax (fail closed).
    """
    cleaned = re.sub(r"[^A-Za-z0-9_.:\-= ]", "_", str(value))
    if ";" in cleaned or '"' in cleaned or "\\" in cleaned or "\n" in cleaned:
        raise UnsafeIdentifier(
            f"value for suricata {field} still contains rule syntax after "
            f"sanitization: {value!r}")
    if not cleaned:
        raise UnsafeIdentifier(f"empty suricata {field}")
    return cleaned
