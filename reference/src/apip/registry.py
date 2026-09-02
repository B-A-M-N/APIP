from __future__ import annotations
"""
Governed source registry (docs/04 v2.1).

Server-side assignment of source class and independence. Evidence records
never carry these attributes — they are derived from the operator-owned
registry keyed by authenticated source identity. An unknown source is
class "unregistered" and contributes nothing.

v2.1.1 (adversarial-audit residual fix): independence is DERIVED from
upstream provenance, not asserted per feed. docs/04: "Two records are not
independent merely because they came through two feeds." A source that
re-exports another's telemetry inherits that upstream's identity for
corroboration purposes; a cluster of resellers of the same upstream counts
as ONE source no matter how many feed names appear in the evidence.
"""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SourceProfile:
    source_id: str
    source_class: str        # curated | local | community | annotation | unregistered
    independent: bool
    auto_enforcement_allowed: bool = True
    # Upstream provenance (docs/04): the ultimate origin of this feed's
    # telemetry, when the feed is a re-exporter. None = the source is its
    # own origin (first-party telemetry or an independent curation shop).
    # Feeds sharing an upstream identity are one corroborating source.
    upstream: str | None = None


class SourceRegistry:
    def __init__(self, profiles: tuple[SourceProfile, ...] = ()):
        self._by_id = {p.source_id: p for p in profiles}

    def profile(self, source_id: str) -> SourceProfile:
        return self._by_id.get(
            source_id,
            SourceProfile(source_id=source_id, source_class="unregistered",
                          independent=False, auto_enforcement_allowed=False),
        )

    def class_of(self, source_id: str) -> str:
        return self.profile(source_id).source_class

    def independence_identity(self, source_id: str) -> str:
        """The provenance identity a source counts as for corroboration.

        A re-exporter collapses to its ultimate upstream; a first-party
        source is its own identity, addressed BY its own id so that the
        upstream and its re-exporters all share one identity. Unregistered
        sources map to a per-id identity so they can never merge with
        anything.
        """
        p = self.profile(source_id)
        if p.source_class == "unregistered":
            return f"unregistered:{source_id}"
        return p.upstream or source_id

    def independent_sources(self, source_ids) -> int:
        """Count DISTINCT independent provenance identities among source_ids.

        This is the corroboration arithmetic primitive: three feeds that all
        re-export upstream U count as one, not three (docs/04). The named
        upstream itself counts as the SAME identity as its re-exporters.
        """
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


DEFAULT_REGISTRY = SourceRegistry((
    SourceProfile("curated-a", "curated", True),
    SourceProfile("curated-b", "curated", True),
    SourceProfile("local-behavioral", "local", True, True),
    SourceProfile("local-sensor", "local", True),
))
