from __future__ import annotations
"""
Governed source registry (docs/04 v2.1).

Server-side assignment of source class and independence. Evidence records
never carry these attributes — they are derived from the operator-owned
registry keyed by authenticated source identity. An unknown source is
class "unregistered" and contributes nothing.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class SourceProfile:
    source_id: str
    source_class: str        # curated | local | community | annotation | unregistered
    independent: bool
    auto_enforcement_allowed: bool = True


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


DEFAULT_REGISTRY = SourceRegistry((
    SourceProfile("curated-a", "curated", True),
    SourceProfile("curated-b", "curated", True),
    SourceProfile("local-behavioral", "local", True, True),
    SourceProfile("local-sensor", "local", True),
))
