"""Input/output integrity layer (v2.2 hardening).

One module, one job: nothing crosses a trust boundary without passing a
closed validator here. Two boundaries exist:

  1. INGEST — external data (indicator ids, source ids, evidence kinds,
     allowlist entries, client selectors) enters the decision path. Every
     field is charset- and length-bounded here, at load time, so no
     downstream code ever has to "be careful" with a raw string.
  2. EMIT — internal data is compiled into third-party artifact languages
     (RPZ zone files, Suricata rule syntax). The exporters validate/escape
     at compile time as well (defense in depth): even if a future loader
     forgets to sanitize, a hostile value cannot reach an artifact.

Design rules (docs/09, adversarial-audit discipline):
  - fail closed: a value that fails validation raises, it is never coerced
    into something plausible;
  - closed charsets: every accepted character is explicitly listed — no
    blocklists, no "escape the bad ones" reasoning;
  - the artifact-language escaping here is a LAST resort that renders a
    value inert, not a transformation an attacker can reason about. The
    primary defense is that hostile values never get in at all.
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Closed charsets (ingest boundary)
# ---------------------------------------------------------------------------

# Indicator/source identifiers: STIX-like ids are `name--hex`; the scaffold
# accepts a strict superset that can never carry artifact syntax (`;`, `"`,
# whitespace, parens, backslash, `#`, `$`), quote characters, or control
# bytes. Anything an operator can read aloud survives; nothing that can
# terminate a rule, a comment, a zone line, a JSON string, or a shell does.
_ID_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")

# Evidence kinds and policy-scope labels: lowercase-conventional, but accept
# mixed case; no whitespace, no separators beyond `. - _ / :`.
_LABEL_RE = re.compile(r"^[A-Za-z0-9_.\-/:]{1,128}$")

# Client/selector references (host-1, session ids): bounded, no artifact
# syntax. This is what the exporters interpolate into `apip_client` — it
# must be inert by construction.
_CLIENT_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")

# Domain names (post-IDNA canonical form produced by io._canonicalize).
_FQDN_RE = re.compile(r"^[a-z0-9_\-]+(\.[a-z0-9_\-]+)*\.?$")


class UnsafeIdentifier(ValueError):
    """A string crossed a trust boundary carrying characters that are
    meaningful in some downstream artifact language."""


def validate_id(value: str, what: str = "id") -> str:
    """Validate an identifier for the decision path (ingest boundary)."""
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise UnsafeIdentifier(
            f"unsafe {what}: must match [A-Za-z0-9_.:-] and be 1..128 chars, "
            f"got {value!r}")
    return value


def validate_label(value: str, what: str = "label") -> str:
    """Validate an evidence kind / scope / family label."""
    if not isinstance(value, str) or not _LABEL_RE.match(value):
        raise UnsafeIdentifier(
            f"unsafe {what}: must match [A-Za-z0-9_.-/:] and be 1..128 chars, "
            f"got {value!r}")
    return value


def validate_client(value: str | None) -> str | None:
    """Validate a client/selector reference destined for artifacts."""
    if value is None:
        return None
    if not isinstance(value, str) or not _CLIENT_RE.match(value):
        raise UnsafeIdentifier(
            f"unsafe client reference: must match [A-Za-z0-9_.:-] and be "
            f"1..128 chars, got {value!r}")
    return value


def validate_fqdn(value: str) -> str:
    """Validate an already-canonicalized FQDN (defense in depth behind
    io._canonicalize; exporters call this at compile time)."""
    v = value.rstrip(".")
    if not v or not _FQDN_RE.match(value):
        raise UnsafeIdentifier(f"unsafe fqdn for artifact: {value!r}")
    if any(len(label) > 63 for label in v.split(".")) or len(v) > 253:
        raise UnsafeIdentifier(f"unsafe fqdn length: {value!r}")
    return value


def validate_ip_literal(value: str) -> str:
    """Validate a bare IPv4/IPv6 literal for artifact interpolation.

    Refuses anything that is not the canonical `ipaddress` rendering —
    zone files and rule syntax both treat some of the rejected characters
    (`/`, `:`, whitespace, `%` zone ids) as structure.
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        raise UnsafeIdentifier(f"unsafe ip literal for artifact: {value!r}")
    if str(addr) != value:
        # non-canonical spellings (leading zeros, compressed variants,
        # v4-mapped shorthand) are normalised before artifacts are compiled
        raise UnsafeIdentifier(
            f"non-canonical ip literal for artifact: {value!r} "
            f"(canonical form is {str(addr)!r})")
    return value


# ---------------------------------------------------------------------------
# Artifact-language escaping (emit boundary, LAST resort)
# ---------------------------------------------------------------------------

def suricata_safe(value: str, field: str) -> str:
    """Render a value safe for interpolation into Suricata rule metadata.

    Suricata rule option values are terminated by `;` and rule text is
    comment-terminated by `#`. The ingest boundary should already have
    rejected hostile values; this is the compile-time backstop. Any
    character that can alter rule structure is rendered as a hex escape
    placeholder — inert in metadata — and the value is rejected outright
    if it still contains rule syntax after that (it cannot, by
    construction, but fail closed anyway).
    """
    cleaned = re.sub(r"[^A-Za-z0-9_.:\-= ]", "_", str(value))
    if ";" in cleaned or '"' in cleaned or "\\" in cleaned or "\n" in cleaned:
        raise UnsafeIdentifier(
            f"value for suricata {field} still contains rule syntax after "
            f"sanitization: {value!r}")
    if not cleaned:
        raise UnsafeIdentifier(f"empty suricata {field}")
    return cleaned


def rpz_comment_safe(value: str) -> str:
    """Render a value safe for an RPZ zone-file comment (`;` and newline
    open/close comments)."""
    cleaned = re.sub(r"[^A-Za-z0-9_.:\-= ]", "_", str(value))
    if ";" in cleaned or "\n" in cleaned or "(" in cleaned or ")" in cleaned:
        raise UnsafeIdentifier(f"value for rpz comment still unsafe: {value!r}")
    return cleaned or "_"


def html_escape(value: str) -> str:
    """Escape for HTML text/attribute interpolation (uireport)."""
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;")
            .replace("'", "&#39;"))
