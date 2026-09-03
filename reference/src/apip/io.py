from __future__ import annotations
import json, re, ipaddress
from pathlib import Path
from .models import Indicator, Evidence
from .sanitize import validate_id, validate_label, UnsafeIdentifier

# Zone-file/rule-safe FQDN form: LDH + dots only, after IDNA. Adversarial
# audit fix: 'evil.com;' previously passed canonicalization and reached the
# RPZ zone file, where ';' begins a comment — indicator-controlled comment
# injection into a compiled enforcement artifact. The charset is now closed.
_FQDN_SAFE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*$")

# v2.3 (audit P0-2): the identity a payload source_id is demoted to when the
# ingest channel has not certified it. The source registry has no profile for
# this id, so it always resolves to class "unregistered" (zero authority).
_UNREGISTERED = "unregistered"
# The operator-certified set for channels that carry only the reference
# scaffold's synthetic feeds. Used ONLY by the explicit --demo-trust-fixture
# opt-in; the default (trusted_sources=None) is fail-closed.
_DEMO_TRUSTED_SOURCES = frozenset({"curated-a", "curated-b", "local-sensor",
                                   "local-behavioral"})

# v2.2: the decision path is only defined for indicator types the schema and
# engine agree on. Anything else is rejected at load, not silently scored as
# an opaque string (the old behavior let `type: "bogus_type"` load and reach
# rung selection with no candidates — defined, but never what the operator
# meant).
_INDICATOR_TYPES = frozenset({"fqdn", "ipv4", "ipv6", "cidr", "url"})

# v2.2: structural caps mirroring schemas/indicator.schema.json intent —
# an input file is untrusted; its size in every dimension is bounded here.
_MAX_INDICATORS = 100_000
_MAX_EVIDENCE_PER_INDICATOR = 1_024
_MAX_SOURCES_PER_INDICATOR = 64
_MAX_TAGS_PER_INDICATOR = 64
_MAX_EVIDENCE_KIND_LEN = 128

# audit P2-43: hard BYTE gate enforced BEFORE the file is read into memory.
# The per-record caps bound the logical size, but a hostile multi-GB file is
# read fully by `json.loads(Path(...).read_text())` before those caps can
# bite — 512 MiB is well past any realistic 100k-indicator feed yet stops an
# unbounded input from exhausting memory at the very first read.
_MAX_INDICATOR_FILE_BYTES = 512 * 1024 * 1024

# ISO-8601 UTC timestamp shape (same contract the attribution channel uses).
_ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")


def _canonicalize(kind: str, value: str) -> str:
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
    return value


def load_indicators(path: str | Path, *, trusted_sources=None) -> list[Indicator]:
    """Load indicators as FACTS (docs/04 v2.1), with the ingest boundary
    enforced (v2.2, v2.3).

    Authority rules:
      - Any client-supplied score fields (points_m, points_s, ...) are
        IGNORED — scoring authority belongs to the policy weight table.
      - Source class and independence are assigned server-side by the
        source registry, never from the payload.
      - v2.3 (audit P0-2): SOURCE IDENTITY is bound to the ingest channel,
        not trusted from the payload. A hostile file can otherwise name any
        registered source_id (curated-a, local-sensor, ...) and inherit that
        source's authority — the input could simply impersonate the known
        default sources. `trusted_sources` is the operator-certified set of
        source ids this channel may assert. A payload source_id OUTSIDE that
        set is demoted to 'unregistered' (zero authority) at the boundary.
        With `trusted_sources=None` (the default, fail-closed) NO payload
        source_id is granted authority: every evidence record resolves to
        'unregistered'. The offline demo opts in explicitly via
        --demo-trust-fixture (see cli.py).

    Integrity rules (v2.2, closes the artifact-injection class at ingest):
      - indicator ids, source ids, evidence kinds, and tags pass closed
        charset/length validation; a hostile id previously rode the CLI's
        id-derived client selector into Suricata rule metadata;
      - indicator types are restricted to the set the engine defines;
      - evidence timestamps must be ISO-8601 UTC (recency is only defined
        for parseable instants; unparseable input previously loaded as ""
        and silently scored stale);
      - every list dimension is bounded (files are untrusted input).

    Violations raise (never coerced): a record the operator did not mean
    must fail the batch loudly, not shrink into something plausible.
    """
    src = Path(path)
    # audit P2-43: reject oversized files BEFORE reading them into memory, so
    # a gigantic hostile feed cannot exhaust resources prior to the logical
    # record caps taking effect. stat() (not read) is the resource gate.
    if src.stat().st_size > _MAX_INDICATOR_FILE_BYTES:
        raise ValueError(
            f"indicator file too large: {src.stat().st_size} bytes exceeds "
            f"{_MAX_INDICATOR_FILE_BYTES}")
    raw = json.loads(src.read_text())
    if not isinstance(raw, list):
        raise ValueError("indicator file must be a JSON array")
    if len(raw) > _MAX_INDICATORS:
        raise ValueError(f"indicator file exceeds {_MAX_INDICATORS} entries")
    out: list[Indicator] = []
    for pos, obj in enumerate(raw):
        if not isinstance(obj, dict):
            raise ValueError(f"indicator #{pos} must be an object")
        ind_id = validate_id(str(obj["id"]), "indicator id")
        # audit P2-44: `type` must be a scalar string BEFORE any membership
        # test. A hostile `"type": []` or `"type": {"k":1}` previously fell
        # into `kind not in _INDICATOR_TYPES` and raised an unhashable-type
        # crash instead of a clean rejection — refuse it as an invalid type.
        if not isinstance(obj["type"], str):
            raise ValueError(f"indicator {ind_id}: type must be a string, "
                             f"got {type(obj['type']).__name__}")
        kind = obj["type"]
        if kind not in _INDICATOR_TYPES:
            raise ValueError(f"indicator {ind_id}: unsupported type {kind!r} "
                             f"(expected one of {sorted(_INDICATOR_TYPES)})")
        value = _canonicalize(kind, obj["value"])

        # v2.3: a file-less source list is a claim, not a binding. The
        # authoritative provenance comes from the EVIDENCE source_ids the
        # channel certifies (see trusted_sources). The payload's redundant
        # `sources` array is IGNORED as an authority assertion — it only
        # constrains the id shape so a garbage field fails loudly, and the
        # derived `sources` below is built from accepted evidence.
        declared_sources = obj.get("sources", [])
        if not isinstance(declared_sources, list):
            raise ValueError(f"indicator {ind_id}: sources must be a list")
        if len(declared_sources) > _MAX_SOURCES_PER_INDICATOR:
            raise ValueError(f"indicator {ind_id}: too many sources")
        for s in declared_sources:
            validate_id(str(s), "source id")

        raw_tags = obj.get("tags", [])
        # audit P2-44: reject non-list `tags` BEFORE iterating — a hostile
        # `"tags": "abc"` (string) or `"tags": {"k":1}` (dict) would otherwise
        # be silently iterated as characters/keys or crash set() on
        # unhashable elements. A list of JSON scalars is the only shape we
        # accept.
        if not isinstance(raw_tags, list) or not all(
                isinstance(t, (str, int, float, bool)) for t in raw_tags):
            raise ValueError(f"indicator {ind_id}: tags must be a JSON array "
                             f"of scalars")
        tags = tuple(sorted(set(str(t) for t in raw_tags)))
        if len(tags) > _MAX_TAGS_PER_INDICATOR:
            raise ValueError(f"indicator {ind_id}: too many tags")
        for t in tags:
            validate_label(t, "tag")

        raw_evidence = obj.get("evidence", [])
        if not isinstance(raw_evidence, list) or len(raw_evidence) > _MAX_EVIDENCE_PER_INDICATOR:
            raise ValueError(
                f"indicator {ind_id}: evidence must be a list of at most "
                f"{_MAX_EVIDENCE_PER_INDICATOR} records")
        evidence: list[Evidence] = []
        for ev in raw_evidence:
            if not isinstance(ev, dict):
                raise ValueError(f"indicator {ind_id}: evidence record must be an object")
            ev_kind = str(ev.get("kind", "evidence"))
            if len(ev_kind) > _MAX_EVIDENCE_KIND_LEN:
                raise ValueError(f"indicator {ind_id}: evidence kind too long")
            validate_label(ev_kind, "evidence kind")
            ev_source = str(ev.get("source_id", _UNREGISTERED))
            validate_id(ev_source, "evidence source_id")
            # v2.3 (audit P0-2): source identity is BOUND to the ingest
            # channel. trusted_sources=None is the FAIL-CLOSED default: the
            # channel certified no source, so EVERY payload source_id is
            # demoted to 'unregistered' — a bare file grants no authority.
            # When a set IS provided, only those certified ids keep
            # identity; any other payload source_id is demoted.
            if trusted_sources is None or ev_source not in trusted_sources:
                ev_source = _UNREGISTERED
            observed_at = str(ev.get("observed_at", obj.get("last_seen", "")) or "")
            if observed_at and not _ISO_UTC.match(observed_at):
                raise ValueError(
                    f"indicator {ind_id}: evidence observed_at must be ISO-8601 UTC "
                    f"(YYYY-MM-DDTHH:MM:SS[.ffffff]Z), got {observed_at!r}; "
                    "adapters must normalize before ingest")
            evidence.append(Evidence(
                kind=ev_kind,
                source_id=ev_source,
                source_class="unassigned",   # replaced by registry at policy time
                observed_at=observed_at,
                independent=False,           # replaced by registry at policy time
                detail={k: v for k, v in ev.items()
                        if k not in {"kind", "source_id", "observed_at",
                                     "points_m", "points_s", "points_s_ctx",
                                     "points_s_ip", "independent", "origin",
                                     "family", "corroboration_group"}},
            ))
        # v2.3: Indicator.sources is DERIVED from the accepted (channel-
        # certified) evidence, not trusted from a second redundant payload
        # field.
        authoritative = sorted({
            ev_.source_id for ev_ in evidence
            if ev_.source_id != _UNREGISTERED
        })
        out.append(Indicator(
            id=ind_id,
            type=kind,
            value=value,
            sources=tuple(authoritative),
            evidence=tuple(evidence),
            tags=tags,
        ))
    return out
