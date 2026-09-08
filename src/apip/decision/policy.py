"""Deterministic policy evaluation — production port of
``reference/src/apip/policy.py`` (the behavioral oracle).

Faithful port of evaluate(): decision-bearing evidence strip → dedup →
evidence envelope → server-derived control-plane facts → scoring →
behavioral cap → authorization gate → allowlist gate → mode dispatch →
rung selection → TTL/ceiling randomization → content hash.

Production changes (the only ones):
  - the clock is INJECTED: ``Policy.now_fn`` returns the evaluation instant
    (an ISO-8601 UTC string). The oracle pins this via ``reference_now``;
    the production controller pins it per-batch so replay is exact.
  - authority comes from a DB-backed source registry satisfying the same
    protocol as the reference ``SourceRegistry`` (profile/class_of/
    independence_identity), injected at construction.

No AI component, no network, no filesystem access in the decision path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from typing import Any, Callable

from apip.domain.models import ActionSelector, Decision, Evidence, Indicator
from apip.domain.sanitize import UnsafeIdentifier, validate_client
from apip.decision.rng import ApipRng, draw_scaled_integer, draw_ttl_jitter
from apip.decision.scoring import (
    CONTROL_PLANE_KINDS,
    DEFAULT_WEIGHTS,
    DEDICATED_USE_KINDS,
    MALICIOUSNESS_ASSERTION_KINDS,
    NON_AUTHORITATIVE_CLASSES,
    SHARED_INFRA_KINDS,
    ZERO_WEIGHT_CLASSES,
    EvidenceTable,
    corroboration_tier,
    dedup_evidence,
    score_parts,
)

# Interdiction ladder rungs (docs/25)
RUNGS = ("NONE", "L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7")
BEHAVIORAL_PREFIX = "behavioral_"
NON_INTERACTIVE_PROTOCOLS = frozenset({"smtp", "dns", "ics", "ssh", "other"})

# Explicit clock-skew allowance for evidence recency (reference P1-3):
# freshness is asymmetric — a heavily future-dated observation is stale.
_CLOCK_SKEW_SECONDS = 300


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
    expires_at: str | None = None
    canonical: str = ""

    def __post_init__(self):
        if not self.canonical:
            object.__setattr__(self, "canonical", _allowlist_key(self.value))

    def matches(self, value: str, scope: str) -> bool:
        return (self.scope in {scope, "*"}
                and bool(self.canonical)
                and self.canonical == _allowlist_key(value))


def _allowlist_key(value: str) -> str:
    """Canonical matching key for allowlist entries and indicator values
    (reference v2.2 semantics: canonical matching, single-host /32 == bare
    address, unparseable matches only itself)."""
    import ipaddress
    v = value.strip().rstrip(".")
    if not v:
        return ""
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(v, strict=False)
        if net.num_addresses == 1:
            return str(net.network_address)
        return str(net)
    except ValueError:
        pass
    low = v.lower()
    try:
        return low.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return low


def _parse_instant(ts: str):
    from datetime import datetime, timezone
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass(frozen=True)
class Policy:
    """An immutable, versioned policy object. Identical semantics to the
    reference Policy; the clock and source registry are injected."""
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
    authorized_prefixes: tuple[str, ...] = ()
    authorized_domains: tuple[str, ...] = ()
    reference_unrestricted: bool = True
    allowlist: tuple[AllowlistEntry, ...] = ()
    allowlist_precedence: bool = True
    rung_floors: dict[str, RungFloor] = field(default_factory=dict)
    behavioral_rate_limit_families: int = 2
    behavioral_deny_families: int = 3
    behavioral_deny_requires_external: bool = True
    max_behavioral_m_contribution: int = 60
    corroborated_max_behavioral_m_contribution: int = 92
    enabled_behavioral_families: tuple[str, ...] = ()
    evidence_table: EvidenceTable = field(default_factory=lambda: EvidenceTable(DEFAULT_WEIGHTS))
    source_registry: Any = None          # PROD: injected registry protocol
    classify_recency: Callable[[str], str] = lambda _ts: "fresh"
    now_fn: Callable[[], str] = lambda: "1970-01-01T00:00:00Z"   # PROD: injected clock
    randomization_enabled: bool = False
    randomization_bounds_version: str = ""
    randomization_epoch: str = "0"
    randomization_rotation_interval_seconds: int = 0
    ttl_jitter: RandomizationMechanism = RandomizationMechanism(False, 0.8, 1.0)
    nominal_rate_ceiling_per_min: int = 0
    rate_ceiling_jitter: RandomizationMechanism = RandomizationMechanism(False, 0.5, 1.0)
    _recency_max_age_hours: float = 6.0
    max_evidence_per_indicator: int = 64
    max_new_auto_actions_per_batch: int | None = None
    governed_dedicated_use: tuple[str, ...] = ()
    governed_verified_rollback: tuple[str, ...] = ()
    # SHA-256 over the canonical raw policy text — pinned to every decision
    # via policy_version so a decision never silently acquires new semantics
    # when a policy file changes (PROD: policy lifecycle invariant).
    content_sha256: str = ""

    def now_iso(self) -> str:
        return self.now_fn()


def _decision_id(indicator: Indicator, policy: Policy, m: int, s_ctx: int, s_ip: int,
                 action: str, disposition: str, rung: str) -> str:
    payload = "|".join([
        indicator.id, indicator.type, indicator.value, policy.version,
        str(m), str(s_ctx), str(s_ip), action, disposition, rung, policy.scope,
    ])
    return "decision--" + hashlib.sha256(payload.encode()).hexdigest()[:24]


def _serialize(v: object) -> str:
    if isinstance(v, (list, tuple)):
        return _list_str(v)
    if isinstance(v, dict):
        return _list_str(sorted((repr(k), _serialize(v[k])) for k in v))
    return repr(v)


def _list_str(items) -> str:
    return "[" + ",".join(_serialize(i) for i in items) + "]"


def _content_hash(*parts: object) -> str:
    payload = "\x1f".join(_serialize(p) for p in parts)
    return "hash--" + hashlib.sha256(payload.encode()).hexdigest()[:24]


def in_scope(value: str, itype: str, policy: Policy) -> bool:
    """Authorization boundary check (reference P1-1): fail closed once an
    operator declares a boundary; empty non-unrestricted policy authorizes
    nothing. Exported for the controller dispatch check and the adapter's
    independent re-check (defense in depth)."""
    if policy.reference_unrestricted:
        return True
    import ipaddress
    if itype in {"ipv4", "ipv6", "cidr"}:
        if not policy.authorized_prefixes:
            return False
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
    if not policy.authorized_domains:
        return False
    v = value.lower().rstrip(".")
    for d in policy.authorized_domains:
        d = d.lower().rstrip(".")
        if v == d or v.endswith("." + d):
            return True
    return False


def _allowlisted(value: str, policy: Policy) -> tuple[bool, str]:
    """Allowlist gate (reference v2.2/P1-35): canonical matching; expired
    entries stop protecting with the governance failure recorded; an
    unparsable expiry fails closed — the entry cannot suppress enforcement
    based on an unreadable governance claim, and the condition is surfaced
    as a named reason exactly as the oracle does."""
    now_key = policy.now_iso()
    for entry in policy.allowlist:
        if not entry.matches(value, policy.scope):
            continue
        if entry.expires_at is None:
            return True, f"allowlist_hit:{value}"
        expiry = _parse_instant(entry.expires_at)
        now = _parse_instant(now_key) if now_key else None
        if expiry is None:
            return False, f"allowlist_unparsable_expiry:{value}"
        if now is not None and now > expiry:
            continue
        return True, f"allowlist_hit:{value}"
    return False, ""


def policy_allows_presence(value: str, itype: str, mode: str,
                           policy: Policy) -> str | None:
    """Re-authorization predicate for an ALREADY-ACTIVE control (audit
    P0 #5): returns None when the CURRENT policy still permits this
    control's presence, else the reason it no longer does. Deliberately
    mirrors the evaluate() gates that would decide the control's fate
    today — an active control is an installed instance of a policy
    decision, so the policy that no longer issues the decision no longer
    justifies the control:

      - the mode gate: a persisted ENFORCE posture under a policy that
        no longer permits ENFORCE is stale (a demotion never blocks a
        weaker control);
      - the allowlist gate (absolute precedence): a now-allowlisted
        target must not stay interdicted;
      - the scope gate: a target that left the authorized scope.

    Re-running full evaluate() is NOT wanted here: score inputs (evidence
    recency) drift with time and would churn controls for reasons
    unrelated to the operator's policy promotion. Only the three
    STABLE authorization gates are re-checked."""
    if policy.mode == "OFF":
        return "posture_not_permitted: current policy mode is OFF"
    if mode == "ENFORCE" and policy.mode != "ENFORCE":
        return (f"posture_not_permitted: persisted ENFORCE under "
                f"current policy mode {policy.mode}")
    hit, hit_reason = _allowlisted(value, policy)
    if hit and policy.allowlist_precedence:
        return f"allowlisted_under_current_policy: {hit_reason}"
    if not in_scope(value, itype, policy):
        return (f"target_out_of_scope_under_current_policy: {value}")
    return None


def _current_epoch(policy: Policy) -> str:
    """Effective randomization epoch (reference P1-8): explicit epoch, else
    derived from the policy clock bucketed by rotation interval, else "0"."""
    if policy.randomization_epoch and policy.randomization_epoch != "0":
        return policy.randomization_epoch
    interval = policy.randomization_rotation_interval_seconds or 0
    if interval > 0:
        now = _parse_instant(policy.now_iso())
        if now is None:
            # Deterministic fallback epoch bucket anchor: the unix epoch,
            # constructed directly (never re-parsed, never wall-clock), so the
            # bucket is fully replayable and can never be None.
            now = datetime(1970, 1, 1, tzinfo=timezone.utc)
        return str(int(now.timestamp()) // interval)
    return "0"


def _family_of_kind(kind: str) -> str | None:
    """`behavioral_<family>` -> `<family>`; None for non-behavioral kinds
    or a `behavioral_` kind that names no detector family (which is a
    provenance problem, not a policy-gated family)."""
    if not kind.startswith(BEHAVIORAL_PREFIX):
        return None
    fam = kind[len(BEHAVIORAL_PREFIX):]
    return fam or None


def _behavioral_families(indicator: Indicator, registry) -> set[str]:
    fams: set[str] = set()
    for ev in indicator.evidence:
        if ev.kind.startswith(BEHAVIORAL_PREFIX) and registry.effective_class(ev.source_id) == "local":
            fams.add(ev.kind)
    return fams


def _external_corroboration(indicator: Indicator, registry,
                            classify_recency=lambda _ts: "fresh") -> tuple[bool, int]:
    """Qualified external corroboration over DISTINCT upstream provenance
    identities reporting FRESH maliciousness assertions (reference P1-5)."""
    identities: set[str] = set()
    for ev in indicator.evidence:
        prof = registry.profile(ev.source_id)
        if prof.source_class in {"local", "annotation", "unregistered"}:
            continue
        if not (prof.independent and prof.auto_enforcement_allowed):
            continue
        if ev.kind not in MALICIOUSNESS_ASSERTION_KINDS:
            continue
        if classify_recency(ev.observed_at) == "stale":
            continue
        identities.add(registry.independence_identity(ev.source_id))
    return (len(identities) > 0, len(identities))


def _cap_behavioral_m(m_total: int, bm: int, cap: int) -> int:
    if bm <= cap:
        return m_total
    non_bm = m_total - bm
    return max(0, min(100, non_bm + cap))


def _behavioral_cap(families: set[str], policy: Policy) -> int:
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
    """Deterministic ladder selection (docs/25, reference v2.1 gates)."""
    reasons: list[str] = []
    deny_ok = True
    rand_records: list[dict] = []

    if client is not None:
        try:
            client = validate_client(client)
        except UnsafeIdentifier:
            reasons.append("client_selector_unsafe_for_artifacts")
            client = None

    if behavioral_families:
        if len(behavioral_families) < policy.behavioral_deny_families:
            deny_ok = False
            reasons.append("behavioral_corroboration_insufficient")
        if policy.behavioral_deny_requires_external and not external_qualified:
            deny_ok = False
            reasons.append("behavioral_deny_needs_external_corroboration")

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

    gated: list[str] = []
    for r in candidates:
        f = policy.rung_floors.get(r)
        if f is None:
            continue
        gate_ok = True
        if r == "L1":
            if protocol_class in NON_INTERACTIVE_PROTOCOLS or protocol_class is None:
                reasons.append("l1_requires_interactive_protocol")
                gate_ok = False
            if not client:
                reasons.append("l1_requires_client_selector")
                gate_ok = False
        if r == "L2" and not client:
            reasons.append("l2_requires_pair_selector")
            gate_ok = False
        if r == "L5" and (infra_state != "dedicated" or not dedicated_use):
            gate_ok = False
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
                    _epoch = _current_epoch(policy)
                    rng = ApipRng("|".join([
                        "rate-ceiling", indicator.id, indicator.type,
                        indicator.value, policy.version, str(m), str(s_ctx),
                        policy.scope, policy.randomization_bounds_version,
                        _epoch]))
                    ceiling, frac_micros = draw_scaled_integer(
                        rng, policy.nominal_rate_ceiling_per_min,
                        policy.rate_ceiling_jitter.lo, policy.rate_ceiling_jitter.hi)
                    rand_records.append({
                        "mechanism": "rate_ceiling",
                        "bounds_version": policy.randomization_bounds_version,
                        "epoch": _epoch,
                        "seed_id": "seed--rate-ceiling--"
                                   + hashlib.sha256("|".join([
                                       indicator.id, indicator.type, indicator.value,
                                       policy.version, str(m), str(s_ctx), policy.scope,
                                       policy.randomization_bounds_version,
                                       _epoch]).encode()).hexdigest()[:12],
                        "draw": {"ceiling_fraction_micros": int(frac_micros),
                                 "ceiling_per_min": ceiling},
                    })
                selector = ActionSelector(
                    scope_type="client_destination_pair", client=client,
                    destination=indicator.value, protocol_class=protocol_class,
                    rate_ceiling_per_min=ceiling)
            break

    return rung, action, reasons, selector, rand_records


def _decision_bearing_evidence(indicator: Indicator, registry,
                               policy: Policy | None = None
                               ) -> tuple[Indicator, tuple[str, ...]]:
    """Reference P0-4: strip non-authoritative records BEFORE dedup/cap/score
    so their quantity/order/size can never touch the decision.

    Audit #23: behavioral evidence of a family the effective policy has NOT
    enabled is likewise non-decision-bearing — an operator disabling a
    family in policy must not have scoring silently consume it when it
    enters the ledger. Returns the bounded indicator plus the disabled
    family kinds dropped (surfaced as reason codes)."""
    kept = []
    dropped_disabled: list[str] = []
    for ev in indicator.evidence:
        if registry.effective_class(ev.source_id) in ZERO_WEIGHT_CLASSES:
            continue
        if (policy is not None and ev.kind.startswith(BEHAVIORAL_PREFIX)
                and _family_of_kind(ev.kind) is not None
                and policy.enabled_behavioral_families
                and _family_of_kind(ev.kind)
                not in policy.enabled_behavioral_families):
            dropped_disabled.append(ev.kind)
            continue
        kept.append(ev)
    if len(kept) == len(indicator.evidence):
        return indicator, ()
    return (Indicator(
        id=indicator.id, type=indicator.type, value=indicator.value,
        sources=indicator.sources, evidence=tuple(kept), tags=indicator.tags),
        tuple(dropped_disabled))


def _bounded_evidence(indicator: Indicator, policy: Policy) -> tuple[Indicator, int]:
    cap = max(1, int(policy.max_evidence_per_indicator))
    if len(indicator.evidence) <= cap:
        return indicator, 0
    bounded = Indicator(
        id=indicator.id, type=indicator.type, value=indicator.value,
        sources=indicator.sources, evidence=indicator.evidence[:cap],
        tags=indicator.tags)
    return bounded, len(indicator.evidence) - cap


def make_recency_classifier(policy: Policy):
    """Bind the policy's recency window to the injected clock (reference
    v2.1.1 + P1-3 asymmetric freshness)."""
    from datetime import datetime, timedelta, timezone
    max_age = timedelta(hours=max(0.0, float(policy._recency_max_age_hours)))

    def classify(ts: str) -> str:
        if not ts:
            return "stale"
        try:
            t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            now = datetime.fromisoformat(policy.now_iso().replace("Z", "+00:00"))
        except ValueError:
            return "stale"
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        from datetime import timedelta as _td
        future_skew = t - now
        age = now - t
        if future_skew > _td(seconds=_CLOCK_SKEW_SECONDS):
            return "stale"
        return "fresh" if age <= max_age else "stale"

    return classify


def _server_derived_kinds(indicator: Indicator, policy: Policy,
                          classifier) -> frozenset[str]:
    """Reference P0-3: derive which control-plane safety facts genuinely hold
    from APIP's OWN state — never from a feed assertion."""
    derived: set[str] = set()
    if any(classifier(ev.observed_at) == "fresh" for ev in indicator.evidence):
        derived.add("recent")
    if in_scope(indicator.value, indicator.type, policy):
        derived.add("bounded_scope")
    if indicator.value:
        derived.add("exactness")
    value = indicator.value
    if value in policy.governed_dedicated_use:
        derived.add("dedicated_use")
        derived.add("dedicated_use_provenance")
    if value in policy.governed_verified_rollback:
        derived.add("verified_rollback")
    return frozenset(derived)


def evaluate(indicator: Indicator, policy: Policy,
             context: dict[str, Any] | None = None) -> Decision:
    """Deterministic policy evaluation — semantically identical to
    ``reference.src.apip.policy.evaluate`` (differential-tested)."""
    context = context or {}
    client = context.get("client")
    protocol_class = context.get("protocol_class")
    registry = policy.source_registry

    indicator, disabled_fams = _decision_bearing_evidence(
        indicator, registry, policy)
    indicator, dup_dropped = dedup_evidence(indicator, registry)
    reasons_base = {f"evidence_deduplicated:{dup_dropped}"} if dup_dropped else set()
    for fam in sorted(set(disabled_fams)):
        reasons_base.add(f"behavioral_family_disabled_by_policy:{fam}")
    indicator, ev_dropped = _bounded_evidence(indicator, policy)

    classifier = make_recency_classifier(policy)
    server_derived_kinds = _server_derived_kinds(indicator, policy, classifier)
    m_total, bm, s_ctx, s_ip, has_dedicated, has_unqualified, reasons = score_parts(
        indicator, policy.evidence_table, classifier,
        registry, server_derived_kinds)
    if ev_dropped:
        reasons_base.add(f"evidence_envelope_truncated:{ev_dropped}")
    if reasons_base:
        reasons = tuple(sorted(set(reasons) | reasons_base))

    behavioral_fams = _behavioral_families(indicator, registry)
    cap = _behavioral_cap(behavioral_fams, policy)
    m = max(0, min(100, _cap_behavioral_m(m_total, bm, cap)))
    if bm > cap:
        reasons = tuple(sorted(set(reasons) | {"behavioral_m_capped"}))
    if has_unqualified:
        reasons = tuple(sorted(set(reasons) | {"unqualified_evidence_present"}))

    # --- authorization gate: out-of-scope targets are hard-rejected
    if not in_scope(indicator.value, indicator.type, policy):
        return Decision(
            id=_decision_id(indicator, policy, m, s_ctx, s_ip, "none", "NO_ACTION", "NONE"),
            indicator_id=indicator.id, maliciousness=m, action_safety=s_ctx,
            disposition="NO_ACTION", action="none", rung="NONE", scope=policy.scope,
            ttl_seconds=0, policy_version=policy.version,
            reason_codes=tuple(sorted(set(reasons) | {"out_of_authorized_scope"})),
            explanation=f"Target outside authorized scope; no action possible. M={m}, S_ctx={s_ctx}.",
        )

    # --- allowlist gate: precedence is absolute
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
    external_qualified, _ = _external_corroboration(indicator, registry, classifier)

    shared = any(ev.kind in SHARED_INFRA_KINDS
                 and registry.effective_class(ev.source_id) not in NON_AUTHORITATIVE_CLASSES
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
    elif policy.mode == "EMERGENCY":
        if indicator.type == "fqdn" and "*" in indicator.value and not policy.auto_wildcard_domain:
            action = "dns_nxdomain"
            rung = "L4"
            reasons = tuple(sorted(set(reasons) | {"wildcard_requires_approval"}))
        else:
            rung, action, ladder_reasons, selector, rand_records = select_rung(
                indicator, policy, m, s_ctx, s_ip, behavioral_fams,
                external_qualified, infra_state, has_dedicated,
                protocol_class=protocol_class, client=client)
            reasons = tuple(sorted(set(reasons) | set(ladder_reasons)))
        if rung == "L0":
            disposition = "OBSERVE"
        else:
            disposition = "PROPOSE_OPERATOR_APPROVAL"
            reasons = tuple(sorted(set(reasons) | {"emergency_mode"}))
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
        _epoch = _current_epoch(policy)
        _ttl_seed = "|".join(["ttl-jitter", did, policy.randomization_bounds_version, _epoch])
        rng = ApipRng(_ttl_seed)
        ttl, frac_micros = draw_ttl_jitter(rng, ttl, policy.ttl_jitter.lo, policy.ttl_jitter.hi)
        rand_records.append({
            "mechanism": "ttl_jitter",
            "bounds_version": policy.randomization_bounds_version,
            "epoch": _epoch,
            "seed_id": "seed--" + hashlib.sha256(_ttl_seed.encode()).hexdigest()[:16],
            "draw": {"ttl_fraction_micros": int(frac_micros), "ttl_seconds": ttl},
        })
        explanation += f" ttl_jitter={frac_micros / 1_000_000:.3f}."

    randomization_record = rand_records[0] if len(rand_records) == 1 else (rand_records or None)
    if isinstance(randomization_record, list):
        randomization_record = list(randomization_record)

    content_hash = _content_hash(
        disposition, action, rung, ttl,
        selector.to_dict() if selector is not None else None,
        randomization_record,
        policy.version,
    ) if disposition in {"AUTO_ENFORCE", "SHADOW_ACTION", "PROPOSE_OPERATOR_APPROVAL", "OBSERVE"} else ""

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
        content_hash=content_hash,
    )


# Convenience name matching the reference's public surface.
class DecisionEvaluator:
    """Thin callable wrapper so the engine can be injected as a strategy."""

    def __init__(self, policy: Policy):
        self._policy = policy

    def __call__(self, indicator: Indicator,
                 context: dict[str, Any] | None = None) -> Decision:
        return evaluate(indicator, self._policy, context)
