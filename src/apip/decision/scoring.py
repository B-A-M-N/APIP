"""Policy-owned deterministic scoring — production port of
``reference/src/apip/scoring.py`` (the behavioral oracle).

Authority boundaries carried over unchanged (they ARE the product):
  - evidence records carry facts, never points; the policy weight table is
    the ONLY score authority;
  - only authoritative source classes (curated/local/community) can collect
    weight; annotation/attribution/unregistered contribute zero, produce no
    reason codes, and are byte-identical absent;
  - control-plane safety facts (bounded_scope/verified_rollback/exactness/
    dedicated_use/recent) count ONLY when server-derived;
  - corroboration is DERIVED from distinct upstream provenance identities,
    never from asserted feed counts;
  - stale evidence contributes nothing decision-bearing (negative M still
    applies).

Differential tests assert this module and the reference produce identical
(scores, reason codes) for identical inputs.
"""
from __future__ import annotations

from typing import Literal, overload

from apip.domain.models import Evidence, Indicator

SHARED_INFRA_KINDS = frozenset({
    "shared_cloud", "shared_cdn", "shared_hosting", "anonymizer", "fastflux_shared",
})
DEDICATED_USE_KINDS = frozenset({"dedicated_use", "dedicated_use_provenance"})
LOCAL_ONLY_KINDS = frozenset({
    "behavioral_beacon_periodicity", "behavioral_dga_likelihood",
    "behavioral_dns_tunneling", "behavioral_fastflux", "behavioral_volume_anomaly",
    "behavioral_first_seen_novelty", "behavioral_tls_metadata_mismatch",
    "behavioral_sync_first_contact",
})
CORROBORATION_KINDS = frozenset({
    "single_curated_source", "two_curated_sources",
})
MALICIOUSNESS_ASSERTION_KINDS = frozenset({
    "curated_source", "direct_local_detection",
})
CONTROL_PLANE_KINDS = frozenset({
    "bounded_scope", "verified_rollback", "exactness",
    "dedicated_use", "dedicated_use_provenance", "recent",
})
NON_AUTHORITATIVE_CLASSES = frozenset({"annotation", "attribution"})
ZERO_WEIGHT_CLASSES = NON_AUTHORITATIVE_CLASSES | {"unregistered"}
AUTHORITATIVE_SOURCE_CLASSES = frozenset({"curated", "local", "community"})
_ANY_FALLBACK_CLASSES = frozenset({"curated", "local"})


def clamp(v: int) -> int:
    return max(0, min(100, int(v)))


class EvidenceTable:
    """Policy-owned scoring weights (docs/04 v2.1). (source_class, kind) ->
    (m, s_ctx, s_ip). Unknown pairs contribute 0 and raise a reason code."""

    def __init__(self, table: dict[tuple[str, str], tuple[int, int, int]]):
        self._table = table

    def contribution(self, source_class: str, kind: str, recency: str) -> tuple[int, int, int]:
        if source_class not in AUTHORITATIVE_SOURCE_CLASSES:
            return 0, 0, 0
        base = self._table.get((source_class, kind))
        if base is None and source_class in _ANY_FALLBACK_CLASSES:
            base = self._table.get(("any", kind), (0, 0, 0))
        else:
            base = base or (0, 0, 0)
        m, s_ctx, s_ip = base
        if recency == "stale":
            m = min(0, m)
            s_ctx = 0
            s_ip = 0
        return m, s_ctx, s_ip

    def is_weighted(self, source_class: str, kind: str) -> bool:
        if source_class not in AUTHORITATIVE_SOURCE_CLASSES:
            return False
        if (source_class, kind) in self._table:
            return True
        if source_class in _ANY_FALLBACK_CLASSES and ("any", kind) in self._table:
            return True
        return False


# Reference weight table: (source_class, kind) -> (m, s_ctx, s_ip)
DEFAULT_WEIGHTS: dict[tuple[str, str], tuple[int, int, int]] = {
    ("curated", "curated_source"):                (25, 0, 0),
    ("curated", "single_curated_source"):         (45, 0, 0),
    ("curated", "two_curated_sources"):           (45, 0, 0),
    ("curated", "contradictory_benign"):          (-35, 0, 0),
    ("curated", "prior_false_positive"):          (-50, 0, 0),
    ("local", "direct_local_detection"):          (35, 10, 15),
    ("local", "behavioral_beacon_periodicity"):   (20, 10, 10),
    ("local", "behavioral_dga_likelihood"):       (15, 0, 0),
    ("local", "behavioral_dns_tunneling"):        (20, -10, -10),
    ("local", "behavioral_fastflux"):             (5, -20, -20),
    ("local", "behavioral_volume_anomaly"):       (10, 0, 0),
    ("local", "behavioral_first_seen_novelty"):           (10, 0, 0),
    ("local", "behavioral_tls_metadata_mismatch"):         (10, 0, 0),
    ("local", "behavioral_sync_first_contact"):   (15, 0, 0),
    ("any", "exact_fqdn"):                        (10, 30, 30),
    ("any", "exact_ip"):                          (0, 25, 25),
    ("any", "exact_url"):                         (10, 30, 30),
    ("any", "recent"):                            (25, 15, 15),
    ("any", "bounded_scope"):                     (0, 20, 20),
    ("any", "verified_rollback"):                 (0, 15, 15),
    ("any", "dedicated_use"):                     (0, 25, 25),
    ("any", "dedicated_use_provenance"):          (0, 25, 25),
    ("any", "exactness"):                         (10, 25, 25),
    ("any", "shared_cloud"):                      (0, 0, -45),
    ("any", "shared_cdn"):                        (0, 0, -45),
    ("any", "shared_hosting"):                    (0, 0, -40),
    ("any", "anonymizer"):                        (0, 0, -30),
    ("any", "fastflux_shared"):                   (0, 0, -35),
}


def _provenance_identity(source_registry, source_id: str) -> str:
    return source_registry.independence_identity(source_id)


def corroboration_tier(indicator: Indicator, source_registry,
                       classify_recency=lambda _ts: "fresh") -> tuple[int, int]:
    """Derived corroboration: (distinct_upstream_identities, tier). Counts
    distinct upstream identities among qualified external sources reporting
    a FRESH positive maliciousness assertion. Tier: 0 = single, 1 = two+."""
    seen: set[str] = set()
    for ev in indicator.evidence:
        prof = source_registry.profile(ev.source_id)
        if prof.source_class in NON_AUTHORITATIVE_CLASSES | {"local", "unregistered"}:
            continue
        if not (prof.independent and prof.auto_enforcement_allowed):
            continue
        if ev.kind not in MALICIOUSNESS_ASSERTION_KINDS:
            continue
        if classify_recency(ev.observed_at) == "stale":
            continue
        seen.add(_provenance_identity(source_registry, ev.source_id))
    distinct = len(seen)
    return distinct, (1 if distinct >= 2 else 0)


def dedup_evidence(indicator: Indicator, source_registry):
    """Collapse duplicate observations BEFORE the envelope cap (reference
    v2.2). Same observation = same (provenance identity, kind, observed_at).
    First wins; later duplicates dropped deterministically."""
    seen: set[tuple[str, str, str]] = set()
    kept = []
    for ev in indicator.evidence:
        prof = source_registry.profile(ev.source_id)
        if prof.source_class in NON_AUTHORITATIVE_CLASSES:
            kept.append(ev)
            continue
        key = (_provenance_identity(source_registry, ev.source_id),
               ev.kind, ev.observed_at)
        if key in seen:
            continue
        seen.add(key)
        kept.append(ev)
    if len(kept) == len(indicator.evidence):
        return indicator, 0
    bounded = Indicator(
        id=indicator.id, type=indicator.type, value=indicator.value,
        sources=indicator.sources, evidence=tuple(kept), tags=indicator.tags)
    return bounded, len(indicator.evidence) - len(kept)


def score(indicator: Indicator, table: EvidenceTable,
          classify_recency, source_registry,
          server_derived_kinds: frozenset[str] = frozenset()) -> tuple[int, int, int, bool, bool, tuple[str, ...]]:
    return _score_impl(indicator, table, classify_recency, source_registry,
                       report_behavioral_share=False,
                       server_derived_kinds=server_derived_kinds)


def score_parts(indicator: Indicator, table: EvidenceTable,
                classify_recency, source_registry,
                server_derived_kinds: frozenset[str] = frozenset()) -> tuple[int, int, int, int, bool, bool, tuple[str, ...]]:
    m, bm, s_ctx, s_ip, has_ded, has_unq, reasons = _score_impl(
        indicator, table, classify_recency, source_registry,
        report_behavioral_share=True,
        server_derived_kinds=server_derived_kinds)
    return m, bm, s_ctx, s_ip, has_ded, has_unq, reasons


@overload
def _score_impl(
    indicator: Indicator, table: EvidenceTable, classify_recency,
    source_registry, report_behavioral_share: Literal[False],
    server_derived_kinds: frozenset[str] = frozenset(),
) -> tuple[int, int, int, bool, bool, tuple[str, ...]]: ...


@overload
def _score_impl(
    indicator: Indicator, table: EvidenceTable, classify_recency,
    source_registry, report_behavioral_share: Literal[True],
    server_derived_kinds: frozenset[str] = frozenset(),
) -> tuple[int, int, int, int, bool, bool, tuple[str, ...]]: ...


def _score_impl(indicator: Indicator, table: EvidenceTable,
                classify_recency, source_registry, report_behavioral_share: bool,
                server_derived_kinds: frozenset[str] = frozenset(),
                ) -> tuple[int, int, int, int, bool, bool, tuple[str, ...]] \
                | tuple[int, int, int, bool, bool, tuple[str, ...]]:
    indicator, _ = dedup_evidence(indicator, source_registry)
    distinct_sources, _ = corroboration_tier(indicator, source_registry, classify_recency)

    m = 0
    bm = 0
    s_ctx = 0
    s_ip = 0
    has_dedicated = False
    has_unqualified = False
    reasons: list[str] = []
    for ev in indicator.evidence:
        kind = ev.kind
        src_class = source_registry.effective_class(ev.source_id)
        if src_class in ZERO_WEIGHT_CLASSES:
            continue
        recency = classify_recency(ev.observed_at)
        if kind in LOCAL_ONLY_KINDS and src_class != "local":
            reasons.append(f"provenance_violation:{kind}")
            has_unqualified = True
            continue
        if kind in CONTROL_PLANE_KINDS and kind not in server_derived_kinds:
            reasons.append(f"control_plane_claim_unverified:{kind}")
            has_unqualified = True
            continue
        cm, cs_ctx, cs_ip = table.contribution(src_class, kind, recency)
        if not table.is_weighted(src_class, kind):
            reasons.append(f"unweighted:{src_class}:{kind}")
            has_unqualified = True
        if kind in CORROBORATION_KINDS and cm > 0 and recency != "stale":
            need = 2 if kind == "two_curated_sources" else 1
            if distinct_sources < need:
                plain = table.contribution(src_class, "curated_source", recency)
                reasons.append(f"corroboration_claim_unverified:{kind}"
                               f":distinct_upstreams={distinct_sources}")
                cm = plain[0]
        if kind in SHARED_INFRA_KINDS:
            cs_ctx = 0
        if kind in DEDICATED_USE_KINDS and recency != "stale":
            has_dedicated = True
        if report_behavioral_share and src_class == "local" and kind.startswith("behavioral_"):
            bm += cm
        m += cm
        s_ctx += cs_ctx
        s_ip += cs_ip
        if cm or cs_ctx or cs_ip:
            reasons.append(kind)
    if report_behavioral_share:
        return (m, bm, clamp(s_ctx), clamp(s_ip), has_dedicated, has_unqualified,
                tuple(sorted(set(reasons))))
    return (clamp(m), clamp(s_ctx), clamp(s_ip),
            has_dedicated, has_unqualified, tuple(sorted(set(reasons))))
