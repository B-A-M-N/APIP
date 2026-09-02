from __future__ import annotations
from .models import Indicator

# Evidence kinds that mark shared infrastructure (docs/04/25). Their safety
# penalty applies to IDENTITY safety only: context-acting rungs (L1/L2/L4)
# remain safe on shared infrastructure because they act on client/protocol
# context, not contested IP identity.
SHARED_INFRA_KINDS = frozenset({
    "shared_cloud", "shared_cdn", "shared_hosting", "anonymizer", "fastflux_shared",
})

# Kinds that constitute positive dedicated-use evidence (docs/25 v2.1).
DEDICATED_USE_KINDS = frozenset({"dedicated_use", "dedicated_use_provenance"})

# Kinds that are only valid from local/behavioral origin (docs/23). A feed
# claiming these kinds server-side is a provenance violation.
LOCAL_ONLY_KINDS = frozenset({
    "behavioral_beacon_periodicity", "behavioral_dga_likelihood",
    "behavioral_dns_tunneling", "behavioral_fastflux", "behavioral_volume_anomaly",
    "behavioral_first_seen_novelty", "behavioral_tls_metadata_mismatch", "behavioral_sync_first_contact",
})

# v2.2: corroboration kinds are CLAIMS ABOUT THE ECOSYSTEM ("two independent
# curated sources reported this"), not facts about the world. A single feed
# asserting them about itself manufactures corroboration weight — the audit
# demonstrated one feed self-asserting its way to an L5 auto-deny. The
# engine now DERIVES corroboration from provenance (how many distinct
# upstream identities actually reported) and treats the asserted kind as a
# claim to verify, never as authority in itself. See
# `corroboration_tier` below.
CORROBORATION_KINDS = frozenset({
    "single_curated_source", "two_curated_sources",
})

def clamp(v: int) -> int:
    return max(0, min(100, int(v)))


# Source classes excluded from the decision path entirely (docs/28, docs/30):
# non-authoritative annotations (incl. all AI/ML output) and attribution
# records. No contribution, no reason codes — decisions are byte-identical
# with and without them.
NON_AUTHORITATIVE_CLASSES = frozenset({"annotation", "attribution"})


class EvidenceTable:
    """Policy-owned scoring weights (docs/04 v2.1).

    The ONLY source of score authority. An evidence record contributes
    exactly weight[(source_class, kind, recency)] — the record itself
    carries no points. Unknown (class, kind) pairs contribute 0 and raise
    a reason code rather than defaulting to something generous.
    """

    def __init__(self, table: dict[tuple[str, str], tuple[int, int, int]]):
        # (source_class, kind) -> (m, s_ctx, s_ip)
        self._table = table

    def contribution(self, source_class: str, kind: str, recency: str) -> tuple[int, int, int]:
        # specific (class, kind) weights first, then source-agnostic "any"
        base = self._table.get((source_class, kind), self._table.get(("any", kind), (0, 0, 0)))
        m, s_ctx, s_ip = base
        if recency == "stale":
            # stale evidence contributes no positive M (docs/04 freshness)
            m = min(0, m)
        return m, s_ctx, s_ip

    def is_weighted(self, source_class: str, kind: str) -> bool:
        return (source_class, kind) in self._table or ("any", kind) in self._table


# Reference weight table: (source_class, kind) -> (m, s_ctx, s_ip)
DEFAULT_WEIGHTS: dict[tuple[str, str], tuple[int, int, int]] = {
    # curated intelligence
    ("curated", "curated_source"):                (25, 0, 0),
    ("curated", "single_curated_source"):         (45, 0, 0),
    ("curated", "two_curated_sources"):           (45, 0, 0),
    ("curated", "contradictory_benign"):          (-35, 0, 0),
    ("curated", "prior_false_positive"):          (-50, 0, 0),
    # local detection
    ("local", "direct_local_detection"):          (35, 10, 15),
    # behavioral (origin-gated server-side; see LOCAL_ONLY_KINDS)
    ("local", "behavioral_beacon_periodicity"):   (20, 10, 10),
    ("local", "behavioral_dga_likelihood"):       (15, 0, 0),
    ("local", "behavioral_dns_tunneling"):        (20, -10, -10),
    ("local", "behavioral_fastflux"):             (5, -20, -20),
    ("local", "behavioral_volume_anomaly"):       (10, 0, 0),
    ("local", "behavioral_first_seen_novelty"):           (10, 0, 0),
    ("local", "behavioral_tls_metadata_mismatch"):         (10, 0, 0),
    ("local", "behavioral_sync_first_contact"):   (15, 0, 0),
    # structural/context
    ("any", "exact_fqdn"):                        (10, 30, 30),
    ("any", "exact_ip"):                          (0, 25, 25),
    ("any", "exact_url"):                         (10, 30, 30),
    ("any", "recent"):                            (25, 15, 15),
    ("any", "bounded_scope"):                     (0, 20, 20),
    ("any", "verified_rollback"):                 (0, 15, 15),
    ("any", "dedicated_use"):                     (0, 25, 25),
    ("any", "dedicated_use_provenance"):          (0, 25, 25),
    ("any", "exactness"):                         (10, 25, 25),
    # infra classification (penalty routes to identity safety only)
    ("any", "shared_cloud"):                      (0, 0, -45),
    ("any", "shared_cdn"):                        (0, 0, -45),
    ("any", "shared_hosting"):                    (0, 0, -40),
    ("any", "anonymizer"):                        (0, 0, -30),
    ("any", "fastflux_shared"):                   (0, 0, -35),
}


def _provenance_identity(source_registry, source_id: str) -> str:
    """The upstream identity a record counts as for dedup/corroboration.

    Uses the registry's provenance arithmetic (docs/04: three resellers of
    one upstream are ONE source) so dedup, corroboration derivation, and
    independence counting all share one identity function.
    """
    return source_registry.independence_identity(source_id)


def corroboration_tier(indicator: Indicator, source_registry) -> tuple[int, int]:
    """Derived corroboration (v2.2): (distinct_upstream_identities, tier).

    Counts DISTINCT upstream provenance identities among the indicator's
    qualified external sources (auto-enforcement-allowed, independent,
    non-local, non-annotation) that report a positive-weight M kind.
    Tier: 0 = single source, 1 = two or more.

    This is the engine-side verification for the asserted corroboration
    kinds (`single_curated_source`, `two_curated_sources`): the asserted
    kind contributes its weight ONLY when the provenance arithmetic
    actually supports the claim. One feed self-asserting
    `two_curated_sources` gets single-source weight — never corroboration
    weight. The claimed-vs-derived mismatch is surfaced as a reason code.
    """
    m_kinds = {kind for (cls, kind), (m, _, _)
               in DEFAULT_WEIGHTS.items() if m > 0 and cls == "curated"}
    m_kinds.update(kind for (cls, kind), (m, _, _)
                   in DEFAULT_WEIGHTS.items() if m > 0 and cls == "any")
    seen: set[str] = set()
    for ev in indicator.evidence:
        prof = source_registry.profile(ev.source_id)
        if prof.source_class in NON_AUTHORITATIVE_CLASSES | {"local", "unregistered"}:
            continue
        if not (prof.independent and prof.auto_enforcement_allowed):
            continue
        if ev.kind not in m_kinds:
            continue
        seen.add(_provenance_identity(source_registry, ev.source_id))
    distinct = len(seen)
    return distinct, (1 if distinct >= 2 else 0)


def _dedup_evidence(indicator: Indicator, source_registry):
    """Collapse duplicate records before scoring (v2.2).

    Two records are the same OBSERVATION — for scoring purposes — when they
    share (provenance identity, kind, observed_at). Four copies of one
    feed's report previously scored four times and inflated M from 25 to
    100. Dedup key uses the PROVENANCE identity (not the feed name) so a
    reseller chain cannot multiply one upstream's report by re-exporting
    through sibling feeds, and includes observed_at so genuinely repeated
    sightings at different times (docs/04 "Repeated recent sightings")
    still count as separate observations.

    Records with identical (identity, kind, observed_at) but DIFFERENT
    payloads are suspicious, not additive: first wins, later duplicates are
    dropped deterministically (stable input order).

    Returns (deduped_indicator, dropped_count).
    """
    seen: set[tuple[str, str, str]] = set()
    kept = []
    for ev in indicator.evidence:
        # annotations/attribution never reach the scorer (byte-identical
        # decisions); excluding them from dedup keeps that invariant exact
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
          classify_recency, source_registry) -> tuple[int, int, int, bool, bool, tuple[str, ...]]:
    """Policy-owned deterministic scoring (docs/04 v2.1).

    Returns (M, S_ctx, S_ip, has_dedicated_use, has_unqualified, reasons).

    - Every contribution comes from the policy weight table. The evidence
      record carries no points.
    - source_class and independence are taken from the governed source
      registry (server-side assignment), never from the payload.
    - Evidence kinds reserved for local/behavioral origin are rejected
      (contributing 0 + reason) when asserted by a non-local source.
    - Corroboration kinds are VERIFIED against derived provenance (v2.2):
      an asserted claim that the provenance arithmetic does not support
      degrades to plain curated_source weight with a reason code.
    - has_dedicated_use: positive dedicated-use evidence present (docs/25).
    - has_unqualified: an unqualified/annotation-class record was present.
    """
    return _score_impl(indicator, table, classify_recency, source_registry,
                       report_behavioral_share=False)


def score_parts(indicator: Indicator, table: EvidenceTable,
                classify_recency, source_registry) -> tuple[int, int, int, int, bool, bool, tuple[str, ...]]:
    """Unclamped variant used by policy for behavioral cap arithmetic.

    Returns (m_unclamped, behavioral_m_unclamped, s_ctx, s_ip,
             has_dedicated_use, has_unqualified, reasons).
    """
    m, bm, s_ctx, s_ip, has_ded, has_unq, reasons = _score_impl(
        indicator, table, classify_recency, source_registry,
        report_behavioral_share=True)
    return m, bm, s_ctx, s_ip, has_ded, has_unq, reasons


def _score_impl(indicator: Indicator, table: EvidenceTable,
                classify_recency, source_registry, report_behavioral_share: bool):
    """Shared scoring path. Dedup happens upstream (policy.evaluate applies
    it before the evidence envelope), but this function remains safe
    standalone by deduplicating defensively as well."""
    indicator, _ = _dedup_evidence(indicator, source_registry)

    # derived corroboration for asserted-kind verification (v2.2)
    distinct_sources, derived_tier = corroboration_tier(indicator, source_registry)

    m = 0
    bm = 0
    s_ctx = 0
    s_ip = 0
    has_dedicated = False
    has_unqualified = False
    reasons: list[str] = []
    for ev in indicator.evidence:
        kind = ev.kind
        src_class = source_registry.class_of(ev.source_id)
        if src_class in NON_AUTHORITATIVE_CLASSES:
            # annotations (docs/28) and attribution records (docs/30) are
            # excluded from the decision path entirely: no contribution, no
            # reason codes — decisions are byte-identical without them
            continue
        recency = classify_recency(ev.observed_at)
        if kind in LOCAL_ONLY_KINDS and src_class != "local":
            reasons.append(f"provenance_violation:{kind}")
            has_unqualified = True
            continue
        cm, cs_ctx, cs_ip = table.contribution(src_class, kind, recency)
        if not table.is_weighted(src_class, kind):
            reasons.append(f"unweighted:{src_class}:{kind}")
            has_unqualified = True
        # v2.2: asserted corroboration kinds are claims, verified against
        # derived provenance. `two_curated_sources` requires >= 2 distinct
        # upstream identities; `single_curated_source` requires >= 1. An
        # unsupported claim degrades to the plain curated_source weight and
        # records the mismatch — the claim never adds unearned weight.
        if kind in CORROBORATION_KINDS and cm > 0 and recency != "stale":
            need = 2 if kind == "two_curated_sources" else 1
            if distinct_sources < need:
                plain = table.contribution(src_class, "curated_source", recency)
                reasons.append(f"corroboration_claim_unverified:{kind}"
                               f":distinct_upstreams={distinct_sources}")
                cm = plain[0]
        # infra penalty routes to identity safety only
        if kind in SHARED_INFRA_KINDS:
            cs_ctx = 0
        if kind in DEDICATED_USE_KINDS:
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
