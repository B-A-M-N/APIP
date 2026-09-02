from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
from typing import Any, Callable
from .models import Indicator, Decision, ActionSelector
from .scoring import (score_parts, EvidenceTable, DEFAULT_WEIGHTS,
                      SHARED_INFRA_KINDS as SHARED_INFRA_EVIDENCE,
                      NON_AUTHORITATIVE_CLASSES)
from .registry import SourceRegistry, DEFAULT_REGISTRY
from .randomize import ApipRng, draw_ttl_jitter, draw_scaled_integer

# Interdiction ladder rungs (docs/25)
RUNGS = ("NONE", "L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7")

# Behavioral evidence marker (docs/23)
BEHAVIORAL_PREFIX = "behavioral_"

# Protocols on which L1 challenge is prohibited (docs/25: interactive only)
NON_INTERACTIVE_PROTOCOLS = frozenset({"smtp", "dns", "ics", "ssh", "other"})


@dataclass(frozen=True)
class RungFloor:
    m: int
    s: int


@dataclass(frozen=True)
class RandomizationMechanism:
    enabled: bool
    lo: float
    hi: float


@dataclass(frozen=True)
class AllowlistEntry:
    value: str
    scope: str
    owner: str = ""
    ticket: str = ""
    expires_at: str | None = None   # None = no expiry (requires governance)


@dataclass(frozen=True)
class Policy:
    version: str
    mode: str
    scope: str
    observe_m: int
    fqdn_auto_m: int
    fqdn_auto_s: int
    ip_rate_m: int
    ip_rate_s: int
    ip_deny_m: int
    ip_deny_s: int
    max_auto_ttl_seconds: int
    auto_prefix_deny: bool
    auto_routing: bool
    auto_wildcard_domain: bool
    # authorized target space: targets outside are hard-rejected (docs/04)
    authorized_prefixes: tuple[str, ...] = ()
    allowlist: tuple[AllowlistEntry, ...] = ()
    allowlist_precedence: bool = True
    # v2 (docs/25): per-rung floors
    rung_floors: dict[str, RungFloor] = field(default_factory=dict)
    # v2 (docs/23): behavioral corroboration lattice
    behavioral_rate_limit_families: int = 2
    behavioral_deny_families: int = 3
    behavioral_deny_requires_external: bool = True
    max_behavioral_m_contribution: int = 60
    corroborated_max_behavioral_m_contribution: int = 92
    # v2.1: scoring authority
    evidence_table: EvidenceTable = field(default_factory=lambda: EvidenceTable(DEFAULT_WEIGHTS))
    source_registry: SourceRegistry = field(default_factory=lambda: DEFAULT_REGISTRY)
    classify_recency: Callable[[str], str] = lambda _ts: "fresh"
    # v2 (docs/29): randomization bounds
    randomization_enabled: bool = False
    randomization_bounds_version: str = ""
    randomization_epoch: str = "0"      # wall-clock epoch bucket; see docs/29
    ttl_jitter: RandomizationMechanism = RandomizationMechanism(False, 0.8, 1.0)
    # v2.1.1: L2 rate ceiling (docs/25 client-impact budget) + its jitter
    # bounds (docs/29 rate_ceiling mechanism). A rate_limit without a
    # ceiling is an intent, not a rule; the ceiling is always carried.
    nominal_rate_ceiling_per_min: int = 0
    rate_ceiling_jitter: RandomizationMechanism = RandomizationMechanism(False, 0.5, 1.0)
    # freshness window backing the pinned-clock classifier (set by load_policy)
    _recency_max_age_hours: float = 6.0
    # v2.1.1 (audit residual): replay-clock pinning. When set (ISO-8601 Z),
    # recency classification anchors to this instant instead of the wall
    # clock, making decision byte-replay exact — not just within a
    # freshness window. None = live wall clock (interactive use).
    reference_now: str | None = None
    # v2.1.1 (audit residual): per-indicator evidence envelope (docs/23).
    # Caps the number of evidence records considered per indicator,
    # bounding reason-code cardinality upstream of any streaming stage.
    max_evidence_per_indicator: int = 64


def _decision_id(indicator: Indicator, policy: Policy, m: int, s_ctx: int, s_ip: int,
                 action: str, disposition: str, rung: str) -> str:
    payload = "|".join([
        indicator.id, indicator.type, indicator.value, policy.version,
        str(m), str(s_ctx), str(s_ip), action, disposition, rung, policy.scope,
    ])
    return "decision--" + hashlib.sha256(payload.encode()).hexdigest()[:24]


def _in_scope(value: str, itype: str, policy: Policy) -> bool:
    """Authorization boundary check (docs/04: target outside authorized
    scope prohibited). Empty authorized_prefixes means unrestricted in this
    reference scaffold; production MUST always enumerate."""
    if not policy.authorized_prefixes:
        return True
    import ipaddress
    if itype not in {"ipv4", "ipv6", "cidr"}:
        return True  # domain targets are governed by resolver scope, not prefixes
    try:
        addr = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    for p in policy.authorized_prefixes:
        net = ipaddress.ip_network(p, strict=False)
        if (isinstance(addr, ipaddress.IPv4Network) and isinstance(net, ipaddress.IPv4Network)
                and addr.subnet_of(net)):
            return True
        if (isinstance(addr, ipaddress.IPv6Network) and isinstance(net, ipaddress.IPv6Network)
                and addr.subnet_of(net)):
            return True
    return False


def _allowlisted(value: str, policy: Policy) -> tuple[bool, str]:
    for entry in policy.allowlist:
        if entry.value == value and entry.scope in {policy.scope, "*"}:
            return True, f"allowlist_hit:{entry.value}"
    return False, ""


def _behavioral_families(indicator: Indicator, registry: SourceRegistry) -> set[str]:
    """Distinct behavioral families, counting only evidence from sources the
    registry classifies as local (provenance-gated server-side, docs/23)."""
    fams: set[str] = set()
    for ev in indicator.evidence:
        if ev.kind.startswith(BEHAVIORAL_PREFIX) and registry.class_of(ev.source_id) == "local":
            fams.add(ev.kind)
    return fams


def _external_corroboration(indicator: Indicator, registry: SourceRegistry) -> tuple[bool, int]:
    """Qualified external corroboration (v2.1.1): counted over DISTINCT
    upstream provenance identities, not feed names — three resellers of one
    upstream corroborate once (docs/04: independence is provenance, not feed
    count). Auto-enforcement-allowed, non-local, non-annotation sources only."""
    identities: set[str] = set()
    for ev in indicator.evidence:
        prof = registry.profile(ev.source_id)
        if prof.source_class in {"local", "annotation", "unregistered"}:
            continue
        if not (prof.independent and prof.auto_enforcement_allowed):
            continue
        identities.add(registry.independence_identity(ev.source_id))
    return (len(identities) > 0, len(identities))


def _cap_behavioral_m(m_total: int, bm: int, cap: int) -> int:
    if bm <= cap:
        return m_total
    non_bm = m_total - bm
    return max(0, min(100, non_bm + cap))


def _behavioral_cap(families: set[str], policy: Policy) -> int:
    """Behavioral M cap by corroboration level (docs/23).

    0 families: no cap needed (externally carried).
    < k families: hard cap below every action floor -> observe-only.
    >= k families: corroborated cap reaches L1/L2 floors but never deny
    floors; deny additionally requires external corroboration (gated in
    select_rung regardless of external evidence — v2.1 fix).
    """
    if not families:
        return 100
    if len(families) >= max(1, policy.behavioral_rate_limit_families):
        return policy.corroborated_max_behavioral_m_contribution
    return policy.max_behavioral_m_contribution


def select_rung(indicator: Indicator, policy: Policy, m: int, s_ctx: int, s_ip: int,
                behavioral_families: set[str], external_qualified: bool,
                infra_state: str, dedicated_use: bool,
                protocol_class: str | None = None,
                client: str | None = None) -> tuple[str, str, list[str], ActionSelector | None, list[dict]]:
    """Deterministic ladder selection (docs/25, v2.1 gates).

    Hard rules precede floors:
      - behavioral contribution to a deny candidate requires the configured
        distinct-family minimum AND qualified external corroboration — even
        when external evidence exists (v2.1 fix: no bypass);
      - L5 requires infrastructure_class == DEDICATED with positive
        dedicated-use evidence; SHARED and UNKNOWN both demote (v2.1 fix);
      - L1 requires an interactive protocol class and a client selector;
      - L2 requires a client/destination pair selector — a destination-global
        L2 is never emitted (v2.1 fix) — and carries a concrete rate ceiling
        (docs/25): nominal, or drawn within docs/29 rate_ceiling bounds with
        the draw recorded when randomization is enabled (v2.1.1 fix: the
        scaffold previously emitted rate_limit rules with no ceiling at all);
      - L3/L6/L7 are approval-gated classes not auto-selected here.
    """
    reasons: list[str] = []
    deny_ok = True
    rand_records: list[dict] = []

    # --- behavioral corroboration gate (v2.1): if behavioral evidence
    # contributes AT ALL, deny requires k families AND external corroboration.
    if behavioral_families:
        if len(behavioral_families) < policy.behavioral_deny_families:
            deny_ok = False
            reasons.append("behavioral_corroboration_insufficient")
        if policy.behavioral_deny_requires_external and not external_qualified:
            deny_ok = False
            reasons.append("behavioral_deny_needs_external_corroboration")

    # --- L5 infrastructure tri-state (v2.1): only DEDICATED qualifies. The
    # demotion reason is recorded only where L5 was a candidate at all.
    if indicator.type in {"ipv4", "ipv6"} and (infra_state != "dedicated" or not dedicated_use):
        if infra_state == "shared":
            reasons.append("demoted_shared_infra")
        else:
            reasons.append("demoted_unknown_infra")

    def _action_for(r: str) -> str:
        if r == "L1":
            return "proxy_challenge"
        if r == "L2":
            return "rate_limit"
        if r == "L4":
            return "dns_nxdomain" if indicator.type == "fqdn" else "rate_limit"
        if r == "L5":
            return "firewall_deny"
        return "observe"

    candidates: list[str] = []
    if indicator.type in {"ipv4", "ipv6"}:
        candidates = ["L5", "L2", "L1"] if deny_ok else ["L2", "L1"]
    elif indicator.type == "fqdn":
        candidates = ["L4", "L2", "L1"] if deny_ok else ["L2", "L1"]
    elif indicator.type == "cidr":
        candidates = []
    else:
        candidates = ["L1"]

    # Gate EVERY candidate rung (so gate failures are recorded even when a
    # higher rung is selected), then take the highest rung that passes.
    gated: list[str] = []
    for r in candidates:
        f = policy.rung_floors.get(r)
        if f is None:
            continue
        gate_ok = True
        # --- typed-selector gates (v2.1) ---
        if r == "L1":
            if protocol_class in NON_INTERACTIVE_PROTOCOLS or protocol_class is None:
                reasons.append("l1_requires_interactive_protocol")
                gate_ok = False
            if not client:
                reasons.append("l1_requires_client_selector")
                gate_ok = False
        if r == "L2" and not client:
            # without a client selector a pair scope is impossible;
            # destination-global rate-limit is never emitted
            reasons.append("l2_requires_pair_selector")
            gate_ok = False
        if r == "L5" and (infra_state != "dedicated" or not dedicated_use):
            gate_ok = False   # demotion reason already recorded above
        if not gate_ok:
            continue
        s_eff = s_ip if r == "L5" else s_ctx
        if m >= f.m and s_eff >= f.s:
            gated.append(r)
        else:
            reasons.append(f"below_{r}_floor")

    rung = "L0"
    action = "observe"
    selector: ActionSelector | None = None
    for r in candidates:
        if r in gated:
            rung = r
            action = _action_for(r)
            if r == "L1":
                selector = ActionSelector(
                    scope_type="client_session", client=client,
                    destination=indicator.value, protocol_class=protocol_class)
            elif r == "L2":
                ceiling = policy.nominal_rate_ceiling_per_min
                if policy.randomization_enabled and policy.rate_ceiling_jitter.enabled:
                    # docs/29 rate_ceiling mechanism: the ceiling is drawn
                    # within policy bounds. The seed uses ONLY fields present
                    # in the final decision record (indicator identity, policy
                    # version, M, S_ctx, scope, bounds version, epoch) — an
                    # auditor holding the decision can reproduce the draw
                    # exactly. Same auditability stance as ttl_jitter: bounds
                    # enforcement carries the security, not seed secrecy.
                    rng = ApipRng("|".join([
                        "rate-ceiling", indicator.id, indicator.type,
                        indicator.value, policy.version, str(m), str(s_ctx),
                        policy.scope, policy.randomization_bounds_version,
                        policy.randomization_epoch]))
                    ceiling, frac_micros = draw_scaled_integer(
                        rng, policy.nominal_rate_ceiling_per_min,
                        policy.rate_ceiling_jitter.lo, policy.rate_ceiling_jitter.hi)
                    rand_records.append({
                        "mechanism": "rate_ceiling",
                        "bounds_version": policy.randomization_bounds_version,
                        "epoch": policy.randomization_epoch,
                        "seed_id": "seed--rate-ceiling--"
                                   + hashlib.sha256("|".join([
                                       indicator.id, indicator.type, indicator.value,
                                       policy.version, str(m), str(s_ctx), policy.scope,
                                       policy.randomization_bounds_version,
                                       policy.randomization_epoch]).encode()).hexdigest()[:12],
                        "draw": {"ceiling_fraction_micros": int(frac_micros),
                                 "ceiling_per_min": ceiling},
                    })
                selector = ActionSelector(
                    scope_type="client_destination_pair", client=client,
                    destination=indicator.value, protocol_class=protocol_class,
                    rate_ceiling_per_min=ceiling)
            break

    return rung, action, reasons, selector, rand_records


def _bounded_evidence(indicator: Indicator, policy: Policy) -> tuple[Indicator, int]:
    """docs/23 evidence envelope: cap the records scored per indicator.

    Deterministic order (stable input order), overflow dropped with a
    reason — bounding reason-code cardinality and scorer work upstream of
    any streaming stage. Returns the bounded indicator and the drop count.
    """
    cap = max(1, int(policy.max_evidence_per_indicator))
    if len(indicator.evidence) <= cap:
        return indicator, 0
    bounded = Indicator(
        id=indicator.id, type=indicator.type, value=indicator.value,
        sources=indicator.sources, evidence=indicator.evidence[:cap],
        tags=indicator.tags)
    return bounded, len(indicator.evidence) - cap


def _make_recency_classifier(policy: Policy):
    """Bind the policy's recency window to the replay clock (v2.1.1).

    When reference_now is set, decay is computed against the pinned instant
    instead of the wall clock, so byte-replay of a decision batch is exact
    at any later time. The freshness window is `_recency_max_age_hours`
    (carried by load_policy), matching the live classifier's semantics.
    Unset (interactive use) keeps the policy's own wall-clock classifier.
    """
    if policy.reference_now is None:
        return policy.classify_recency
    from datetime import datetime, timedelta, timezone
    max_age = timedelta(hours=max(0.0, float(policy._recency_max_age_hours)))

    def classify(ts: str) -> str:
        if not ts:
            return "stale"
        try:
            t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            now = datetime.fromisoformat(policy.reference_now.replace("Z", "+00:00"))
        except ValueError:
            return "stale"
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return "fresh" if abs(now - t) <= max_age else "stale"

    return classify


def evaluate(indicator: Indicator, policy: Policy, context: dict[str, Any] | None = None) -> Decision:
    context = context or {}
    client = context.get("client")
    protocol_class = context.get("protocol_class")

    # docs/23 evidence envelope: bound the records scored per indicator,
    # bounding reason-cardinality and scorer work upstream of any stage.
    indicator, ev_dropped = _bounded_evidence(indicator, policy)

    # Policy-owned scoring: evidence carries facts, the weight table and
    # source registry carry authority (docs/04 v2.1). Recency runs on the
    # policy clock — pinned to reference_now when set (exact replay).
    m_total, bm, s_ctx, s_ip, has_dedicated, has_unqualified, reasons = score_parts(
        indicator, policy.evidence_table, _make_recency_classifier(policy),
        policy.source_registry)
    if ev_dropped:
        reasons = tuple(sorted(set(reasons) | {f"evidence_envelope_truncated:{ev_dropped}"}))

    behavioral_fams = _behavioral_families(indicator, policy.source_registry)
    cap = _behavioral_cap(behavioral_fams, policy)
    m = max(0, min(100, _cap_behavioral_m(m_total, bm, cap)))
    if bm > cap:
        reasons = tuple(sorted(set(reasons) | {"behavioral_m_capped"}))
    if has_unqualified:
        reasons = tuple(sorted(set(reasons) | {"unqualified_evidence_present"}))

    # --- authorization gate (docs/04): out-of-scope targets are hard-rejected
    if not _in_scope(indicator.value, indicator.type, policy):
        return Decision(
            id=_decision_id(indicator, policy, m, s_ctx, s_ip, "none", "NO_ACTION", "NONE"),
            indicator_id=indicator.id, maliciousness=m, action_safety=s_ctx,
            disposition="NO_ACTION", action="none", rung="NONE", scope=policy.scope,
            ttl_seconds=0, policy_version=policy.version,
            reason_codes=tuple(sorted(set(reasons) | {"out_of_authorized_scope"})),
            explanation=f"Target outside authorized scope; no action possible. M={m}, S_ctx={s_ctx}.",
        )

    # --- allowlist gate (docs/04): precedence is absolute
    hit, hit_reason = _allowlisted(indicator.value, policy)
    if hit and policy.allowlist_precedence:
        return Decision(
            id=_decision_id(indicator, policy, m, s_ctx, s_ip, "none", "NO_ACTION", "NONE"),
            indicator_id=indicator.id, maliciousness=m, action_safety=s_ctx,
            disposition="NO_ACTION", action="none", rung="NONE", scope=policy.scope,
            ttl_seconds=0, policy_version=policy.version,
            reason_codes=tuple(sorted(set(reasons) | {hit_reason, "allowlist_precedence"})),
            explanation=f"Allowlisted target; enforcement suppressed. M={m}, S_ctx={s_ctx}.",
        )

    action = "none"
    disposition = "NO_ACTION"
    rung = "NONE"
    ttl = 0
    rand_records: list[dict] = []
    selector: ActionSelector | None = None
    external_qualified, _ = _external_corroboration(indicator, policy.source_registry)

    # infrastructure tri-state (docs/25 v2.1): unknown ≠ dedicated. Classification
    # evidence counts only from authoritative (non-annotation) sources — an
    # annotation cannot change the decision (docs/28 v2.1).
    shared = any(ev.kind in SHARED_INFRA_EVIDENCE
                 and policy.source_registry.class_of(ev.source_id) not in NON_AUTHORITATIVE_CLASSES
                 for ev in indicator.evidence)
    infra_state = "shared" if shared else ("dedicated" if has_dedicated else "unknown")

    if policy.mode == "OFF":
        pass
    elif m < policy.observe_m:
        pass
    elif policy.mode == "OBSERVE":
        disposition = "OBSERVE"
        rung = "L0"
        action = "observe"
    else:
        if indicator.type == "fqdn" and "*" in indicator.value and not policy.auto_wildcard_domain:
            action = "dns_nxdomain"
            disposition = "PROPOSE_OPERATOR_APPROVAL" if policy.mode == "ENFORCE" else "SHADOW_ACTION"
            rung = "L4"
            reasons = tuple(sorted(set(reasons) | {"wildcard_requires_approval"}))
        elif indicator.type == "cidr":
            action = "firewall_deny"
            disposition = "PROPOSE_OPERATOR_APPROVAL" if policy.mode == "ENFORCE" else "SHADOW_ACTION"
            rung = "NONE"
            reasons = tuple(sorted(set(reasons) | {"prefix_requires_approval"}))
        else:
            rung, action, ladder_reasons, selector, rand_records = select_rung(
                indicator, policy, m, s_ctx, s_ip, behavioral_fams,
                external_qualified, infra_state, has_dedicated,
                protocol_class=protocol_class, client=client)
            reasons = tuple(sorted(set(reasons) | set(ladder_reasons)))
            if rung == "L0":
                disposition = "OBSERVE"
            elif rung in policy.rung_floors:
                disposition = "AUTO_ENFORCE" if policy.mode == "ENFORCE" else "SHADOW_ACTION"
                ttl = min(3600, policy.max_auto_ttl_seconds)
            else:
                disposition = "PROPOSE_OPERATOR_APPROVAL" if policy.mode == "ENFORCE" else "SHADOW_ACTION"

    did = _decision_id(indicator, policy, m, s_ctx, s_ip, action, disposition, rung)
    ceiling_note = ""
    if selector is not None and selector.rate_ceiling_per_min is not None:
        ceiling_note = f", rate_ceiling_per_min={selector.rate_ceiling_per_min}"
    explanation = (
        f"M={m}, S_ctx={s_ctx}, S_ip={s_ip}, type={indicator.type}, infra={infra_state}, "
        f"families={len(behavioral_fams)}, external_qualified={external_qualified}, "
        f"mode={policy.mode}, rung={rung}, disposition={disposition}, action={action}"
        f"{ceiling_note}."
    )

    nominal_ttl = ttl
    if ttl > 0 and policy.randomization_enabled and policy.ttl_jitter.enabled:
        # Seed includes the wall-clock epoch bucket (docs/29): same indicator
        # + policy draws differently across epochs; replay within an epoch is
        # exact. Fixed-point arithmetic on integer microseconds of the draw.
        #
        # Adversarial-audit note (docs/29 TM-020 reconciliation): the seed is
        # derived from the decision id + bounds version + epoch, all of which
        # appear in the decision record — so ANYONE holding one decision can
        # reproduce its draw. This is deliberate: replay/audit requires it,
        # and docs/29's security claim never rested on seed secrecy. It rests
        # on (a) draws confined to policy bounds — knowing the seed yields no
        # out-of-bounds value, and (b) the epoch component, which makes
        # prediction of the NEXT epoch's draws require predicting operator
        # epoch rotation. Do not "harden" this by hiding the seed; that would
        # break auditability without adding security.
        rng = ApipRng(f"{did}|{policy.randomization_bounds_version}|{policy.randomization_epoch}")
        ttl, frac_micros = draw_ttl_jitter(rng, ttl, policy.ttl_jitter.lo, policy.ttl_jitter.hi)
        rand_records.append({
            "mechanism": "ttl_jitter",
            "bounds_version": policy.randomization_bounds_version,
            "epoch": policy.randomization_epoch,
            "seed_id": f"seed--{did.split('--')[-1]}",
            "draw": {"ttl_fraction_micros": int(frac_micros), "ttl_seconds": ttl},
        })
        explanation += f" ttl_jitter={frac_micros / 1_000_000:.3f}."

    # v2.1.1: a decision may carry MULTIPLE recorded draws (e.g. rate_ceiling
    # at selection + ttl_jitter on the TTL). Legacy single-object shape is
    # kept when only one mechanism applied.
    randomization_record = rand_records[0] if len(rand_records) == 1 else (rand_records or None)
    if isinstance(randomization_record, list):
        randomization_record = list(randomization_record)

    return Decision(
        id=did,
        indicator_id=indicator.id,
        maliciousness=m,
        action_safety=s_ctx if rung != "L5" else s_ip,
        disposition=disposition,
        action=action,
        rung=rung,
        scope=policy.scope,
        ttl_seconds=ttl,
        policy_version=policy.version,
        reason_codes=reasons,
        explanation=explanation,
        selector=selector,
        nominal_ttl_seconds=nominal_ttl,
        randomization=randomization_record,
    )
