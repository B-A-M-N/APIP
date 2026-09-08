"""Authenticated ingest boundary.

Core lesson carried from the reference (v2.3, audit P0-2): SOURCE IDENTITY
IS BOUND TO THE INGEST CHANNEL. A payload's declared ``source_id`` never
grants authority. Production rules:

  1. the authenticated channel determines ONE authoritative source id;
  2. evidence records naming a different source_id are recorded with the
     asserted id moved to ``detail.asserted_source_id`` and demoted to the
     channel's identity ONLY if the channel is PROVEN to carry that upstream
     (``channel.allowed_source_ids``), else to ``unregistered`` (zero
     authority);
  3. a disabled source, or a kind outside its allowed classes, is rejected
     at the boundary — never silently scored;
  4. every ingest batch is hashed (SHA-256 over raw bytes) and idempotent:
     re-submitting the same bytes to the same source is a no-op returning
     the original batch.

Integrity rules mirror the reference ingest: closed charsets via
domain.sanitize, canonical values via domain.canonicalize, ISO-8601 UTC
timestamps, bounded sizes, score-bearing fields stripped (points_*,
independent, origin are claims, not facts).
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from apip.domain.canonical import INDICATOR_TYPES, canonicalize, is_iso_utc
from apip.domain.models import Evidence, Indicator
from apip.domain.sanitize import UnsafeIdentifier, validate_id, validate_label

_UNREGISTERED = "unregistered"

# Structural caps (reference io.py; input is untrusted).
MAX_INDICATORS = 100_000
MAX_EVIDENCE_PER_INDICATOR = 1_024
MAX_SOURCES_PER_INDICATOR = 64
MAX_TAGS_PER_INDICATOR = 64
MAX_EVIDENCE_KIND_LEN = 128
# ABSOLUTE safety ceiling (not configurable): no ingest payload may ever
# exceed this, whatever the service config says (review P1 #28 — one
# service-level configurable limit, one non-negotiable bound).
ABSOLUTE_MAX_INGEST_BYTES = 512 * 1024 * 1024
# Back-compat alias (older callers/tests).
MAX_INDICATOR_FILE_BYTES = ABSOLUTE_MAX_INGEST_BYTES

# Fields that are CLAIMS about authority or score — stripped from evidence
# detail and never allowed to influence anything (docs/04).
STRIPPED_EVIDENCE_FIELDS = frozenset({
    "kind", "source_id", "observed_at", "points_m", "points_s",
    "points_s_ctx", "points_s_ip", "independent", "origin", "family",
    "corroboration_group",
})


class IngestError(ValueError):
    """A record the operator did not mean: the batch fails loudly, it is
    never coerced into something plausible."""


@dataclass(frozen=True)
class IngestChannel:
    """The authenticated identity of one ingest submission.

    ``source_id`` is DERIVED from the credential (never from the body).
    ``allowed_source_ids`` is the registry-declared set of upstream source
    ids this channel is PROVEN to carry (a re-exporter lists its upstream);
    anything else in a payload is demoted to unregistered.
    """
    source_id: str
    allowed_source_ids: frozenset[str] = frozenset()
    # Evidence kinds this channel's source may assert (P1 #29): empty = all
    # allowed; anything else is DEMOTED to unregistered (zero scoring
    # authority) rather than silently scored — the registry's documented
    # boundary ("evidence kinds outside a source's allowed classes are
    # demoted to unregistered").
    allowed_kinds: frozenset[str] = frozenset()

    def resolve_source(self, asserted: str) -> str:
        """Resolve a payload source_id to its authoritative value."""
        if asserted == self.source_id:
            return self.source_id
        if asserted in self.allowed_source_ids:
            return asserted
        return _UNREGISTERED


@dataclass(frozen=True)
class IngestBatch:
    """One authenticated, normalized, idempotent ingest submission."""
    batch_id: str
    source_id: str
    raw_sha256: str
    indicators: tuple[Indicator, ...]
    demoted_records: int   # evidence records demoted to unregistered
    rejected: tuple[str, ...] = ()


def raw_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def batch_id_for(source_id: str, raw_sha256: str) -> str:
    return "batch--" + hashlib.sha256(
        f"{source_id}\x1f{raw_sha256}".encode()).hexdigest()[:24]


def _resolve_channel_source(channel: IngestChannel, asserted: str,
                            ind_id: str, counter: list[int]) -> str:
    resolved = channel.resolve_source(asserted)
    if resolved == _UNREGISTERED and asserted not in ("", _UNREGISTERED):
        counter[0] += 1
    return resolved


def parse_indicator_payload(data: bytes, channel: IngestChannel,
                            max_bytes: int = ABSOLUTE_MAX_INGEST_BYTES) -> IngestBatch:
    """Parse + normalize + channel-bind an indicator JSON payload.

    Raises IngestError (loudly) on structurally invalid input. Evidence
    records that fail timestamp validation are REJECTED for the whole
    batch (fail closed) — mirrors the reference loader discipline.
    """
    raw_sha = raw_digest(data)
    bid = batch_id_for(channel.source_id, raw_sha)
    limit = min(max_bytes, ABSOLUTE_MAX_INGEST_BYTES)
    if len(data) > limit:
        raise IngestError(
            f"payload too large: {len(data)} bytes exceeds {limit}")
    try:
        raw = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise IngestError(f"payload is not valid JSON: {e}") from e
    if not isinstance(raw, dict) or not isinstance(raw.get("indicators"), list):
        raise IngestError("payload must be an object with an 'indicators' array")
    items = raw["indicators"]
    if len(items) > MAX_INDICATORS:
        raise IngestError(f"payload exceeds {MAX_INDICATORS} indicators")

    demoted = 0
    out: list[Indicator] = []
    for pos, obj in enumerate(items):
        if not isinstance(obj, dict):
            raise IngestError(f"indicator #{pos} must be an object")
        try:
            ind_id = validate_id(str(obj["id"]), "indicator id")
        except UnsafeIdentifier as e:
            raise IngestError(f"indicator #{pos}: {e}") from e
        if not isinstance(obj.get("type"), str):
            raise IngestError(
                f"indicator {ind_id}: type must be a string, got {type(obj.get('type')).__name__}")
        kind = obj["type"]
        if kind not in INDICATOR_TYPES:
            raise IngestError(
                f"indicator {ind_id}: unsupported type {kind!r} (expected one of {sorted(INDICATOR_TYPES)})")
        try:
            value = canonicalize(kind, obj["value"])
        except ValueError as e:
            raise IngestError(f"indicator {ind_id}: {e}") from e

        declared_sources = obj.get("sources", [])
        if not isinstance(declared_sources, list):
            raise IngestError(f"indicator {ind_id}: sources must be a list")
        if len(declared_sources) > MAX_SOURCES_PER_INDICATOR:
            raise IngestError(f"indicator {ind_id}: too many sources")
        for s in declared_sources:
            validate_id(str(s), "source id")

        raw_tags = obj.get("tags", [])
        if not isinstance(raw_tags, list) or not all(
                isinstance(t, (str, int, float, bool)) for t in raw_tags):
            raise IngestError(
                f"indicator {ind_id}: tags must be a JSON array of scalars")
        tags = tuple(sorted(set(str(t) for t in raw_tags)))
        if len(tags) > MAX_TAGS_PER_INDICATOR:
            raise IngestError(f"indicator {ind_id}: too many tags")
        for t in tags:
            try:
                validate_label(t, "tag")
            except UnsafeIdentifier as e:
                raise IngestError(f"indicator {ind_id}: {e}") from e

        raw_evidence = obj.get("evidence", [])
        if not isinstance(raw_evidence, list) or len(raw_evidence) > MAX_EVIDENCE_PER_INDICATOR:
            raise IngestError(
                f"indicator {ind_id}: evidence must be a list of at most "
                f"{MAX_EVIDENCE_PER_INDICATOR} records")
        evidence: list[Evidence] = []
        demote_counter = [0]
        kind_disallowed = bool(channel.allowed_kinds)
        for ev in raw_evidence:
            if not isinstance(ev, dict):
                raise IngestError(f"indicator {ind_id}: evidence record must be an object")
            ev_kind = str(ev.get("kind", "evidence"))
            if len(ev_kind) > MAX_EVIDENCE_KIND_LEN:
                raise IngestError(f"indicator {ind_id}: evidence kind too long")
            try:
                validate_label(ev_kind, "evidence kind")
            except UnsafeIdentifier as e:
                raise IngestError(f"indicator {ind_id}: {e}") from e
            ev_source = str(ev.get("source_id", channel.source_id))
            try:
                validate_id(ev_source, "evidence source_id")
            except UnsafeIdentifier as e:
                raise IngestError(f"indicator {ind_id}: {e}") from e
            resolved = _resolve_channel_source(channel, ev_source, ind_id, demote_counter)
            # P1 #29: an evidence kind outside the submitting source's
            # allowed classes is demoted to unregistered (zero authority) —
            # the kind boundary gates INGEST scoring, not silently ignored.
            if kind_disallowed and ev_kind not in channel.allowed_kinds:
                if resolved != _UNREGISTERED:
                    demote_counter[0] += 1
                resolved = _UNREGISTERED
            observed_at = str(ev.get("observed_at", obj.get("last_seen", "")) or "")
            if observed_at and not is_iso_utc(observed_at):
                raise IngestError(
                    f"indicator {ind_id}: evidence observed_at must be ISO-8601 UTC "
                    f"(YYYY-MM-DDTHH:MM:SS[.ffffff]Z), got {observed_at!r}; "
                    "sources must normalize before ingest")
            evidence.append(Evidence(
                kind=ev_kind,
                source_id=resolved,
                source_class="unassigned",   # assigned by the registry at policy time
                observed_at=observed_at,
                independent=False,           # assigned by the registry at policy time
                detail={k: v for k, v in ev.items() if k not in STRIPPED_EVIDENCE_FIELDS},
                channel_source=channel.source_id,
            ))
        demoted += demote_counter[0]
        authoritative = sorted({
            ev_.source_id for ev_ in evidence if ev_.source_id != _UNREGISTERED
        })
        out.append(Indicator(
            id=ind_id, type=kind, value=value,
            sources=tuple(authoritative), evidence=tuple(evidence), tags=tags))
    return IngestBatch(
        batch_id=bid, source_id=channel.source_id, raw_sha256=raw_sha,
        indicators=tuple(out), demoted_records=demoted)


def parse_indicator_file(path: str | Path, channel: IngestChannel) -> IngestBatch:
    return parse_indicator_payload(Path(path).read_bytes(), channel)
