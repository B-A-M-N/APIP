"""Ingest-source registry: the operator-owned authority boundary.

A source is registered SEPARATELY from the data it submits. The registry
answers the questions the decision engine asks (the same protocol as the
reference ``SourceRegistry`` so the ported engine is unchanged):

    profile(source_id) -> SourceProfile
    class_of(source_id) -> str
    independence_identity(source_id) -> str
    independent_sources(ids) -> int

Production registry semantics:
  - unknown source id -> class "unregistered", zero authority, never
    merges with anything (reference audit P0-1);
  - independence is derived from UPSTREAM provenance: re-exporters of one
    upstream collapse to a single corroboration identity (docs/04);
  - enabled/disabled state and allowed evidence classes gate INGEST —
    a disabled source's submissions are rejected at the boundary, and
    evidence kinds outside a source's allowed classes are demoted to
    unregistered (not silently scored);
  - ``auto_enforcement_allowed=False`` sources contribute evidence weight
    but never qualify external corroboration for enforcement decisions.
"""
from __future__ import annotations

from dataclasses import dataclass

# Identity sentinels that can never become registered sources (review P0 #9):
# "unregistered" IS the zero-authority class — registering it (e.g. as
# curated) would let deliberately demoted evidence resolve through the
# registry as authoritative. Refused at API, ledger, and DB CHECK layers.
RESERVED_SOURCE_IDS = frozenset({"unregistered"})


@dataclass(frozen=True)
class SourceProfile:
    source_id: str
    source_class: str        # curated | local | community | annotation | attribution | unregistered
    independent: bool
    auto_enforcement_allowed: bool = True
    upstream: str | None = None
    # PROD: registry governance fields (display + boundary gating)
    enabled: bool = True
    allowed_kinds: tuple[str, ...] = ()   # empty = all kinds allowed


class RegistryError(ValueError):
    pass


class SourceRegistry:
    """DB-backed source registry (async-refreshing read view over the
    ledger's sources table). Implements the reference registry protocol."""

    def __init__(self, profiles=()):
        self._by_id: dict[str, SourceProfile] = {p.source_id: p for p in profiles}

    # -- reference protocol -------------------------------------------------

    def profile(self, source_id: str) -> SourceProfile:
        return self._by_id.get(
            source_id,
            SourceProfile(source_id=source_id, source_class="unregistered",
                          independent=False, auto_enforcement_allowed=False),
        )

    def class_of(self, source_id: str) -> str:
        return self.profile(source_id).source_class

    def independence_identity(self, source_id: str) -> str:
        p = self.profile(source_id)
        if p.source_class == "unregistered":
            return f"unregistered:{source_id}"
        return p.upstream or source_id

    def independent_sources(self, source_ids) -> int:
        seen: set[str] = set()
        for sid in source_ids:
            p = self.profile(sid)
            if not p.independent:
                continue
            if p.source_class in ("annotation", "unregistered"):
                continue
            if p.upstream:
                seen.add(p.upstream)
            else:
                seen.add(sid)
        return len(seen)

    # -- production registry surface ---------------------------------------

    def registered(self) -> tuple[SourceProfile, ...]:
        return tuple(sorted(self._by_id.values(), key=lambda p: p.source_id))

    def is_enabled(self, source_id: str) -> bool:
        return self.profile(source_id).enabled

    def kind_allowed(self, source_id: str, kind: str) -> bool:
        p = self.profile(source_id)
        if not p.allowed_kinds:
            return True
        return kind in p.allowed_kinds

    def replace_view(self, profiles) -> "SourceRegistry":
        """Return a new immutable view (the controller refreshes this
        periodically; decisions pin the view that produced them via the
        policy version + decision content hash)."""
        return SourceRegistry(profiles)
