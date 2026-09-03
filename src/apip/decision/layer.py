"""Per-tenant policy overlay merge (task #11, feature 2).

A tenant of a shared deployment may overlay the GLOBAL active policy with a
tighten-only fragment: the effective policy for that tenant must be AT LEAST
as restrictive as the global — an overlay may RAISE decision thresholds / rung
floors, require more behavioral corroboration, LOWER caps, NARROW the
authorization boundary, and only ADD governed allowlist entries. It may never
loosen any global control (a loosing overlay is not an error at runtime — the
merge CLAMPS it back to the global, so the effective policy is always >= the
global's restrictiveness regardless of input).

``merge_policy_overlay`` is a PURE function of two ``Policy`` objects: no I/O,
no clock, deterministic. It uses ``dataclasses.replace`` so the merged result
is a new immutable ``Policy`` sharing the global's injected registry/clock.

The overlay is built as a *partial* ``Policy`` whose absent fields carry the
permissive ``Policy`` defaults; the tighten-only clamp below guarantees an
all-default overlay merges to the identity (returns the global unchanged), so
only values the overlay author explicitly writes as STRICTER than global take
effect. This is the monotonic invariant: for every overridable control the
effective value is the stricter of (global, overlay).
"""
from __future__ import annotations

from dataclasses import replace

from apip.decision.policy import AllowlistEntry, Policy, RungFloor

# Enforcement-restrictiveness rank. LOWER rank = LESS auto-action (OFF is the
# most conservative — the tenant wants no enforcement); a tenant overlay may
# only move the mode toward less auto-action (never demand a stronger mode the
# global operator did not authorize).
_MODE_RANK = {"OFF": 0, "OBSERVE": 1, "SHADOW": 2, "ENFORCE": 3, "EMERGENCY": 4}


def _max_int(global_v: int, overlay_v: int) -> int:
    return max(global_v, overlay_v)


def _min_int(global_v: int, overlay_v: int) -> int:
    return min(global_v, overlay_v)


def _stricter_mode(global_mode: str, overlay_mode: str) -> str:
    """The effective mode is the LESS auto-action one (lower rank). An overlay
    in a stronger mode than global is clamped back to the global (it may not
    demand enforcement the operator did not authorize)."""
    gr = _MODE_RANK.get(global_mode, 2)
    or_ = _MODE_RANK.get(overlay_mode, 2)
    return overlay_mode if or_ < gr else global_mode


def _narrow_domains(global_domains, overlay_domains):
    """Overlay may only NARROW the authorized domain boundary: effective is the
    intersection. An overlay declaring nothing keeps the global; an overlay
    declaring domains outside the global contributes nothing outside it (the
    tenant cannot widen scope). When the GLOBAL declares no domain boundary
    (an open/unrestricted control plane), the overlay's own boundary is honored
    as the narrower scope — mirroring ``_narrow_prefixes`` — so a tenant
    narrowing an open global to its own domains is not emptied to nothing."""
    if not overlay_domains:
        return global_domains
    g = set(global_domains)
    if not g:
        # Global was unrestricted over domains: nothing to intersect, so the
        # overlay's declared boundary IS the narrower scope (never widen, and
        # never empty an open policy to unintentional-nothing).
        return tuple(sorted(overlay_domains))
    # Overlay may not ADD a domain the global operator did not authorize.
    merged = {d for d in overlay_domains if d in g}
    # If it declares only out-of-scope domains, the effective boundary stays the
    # global (intersection with global is exactly the authorized subset; we do
    # NOT empty it — an attacker must not shrink a tenant's blast radius to
    # unintentional-nothing, but we also never widen it).
    if not merged:
        merged = g
    return tuple(sorted(merged))


def _narrow_prefixes(global_prefixes, overlay_prefixes):
    if not overlay_prefixes:
        return global_prefixes
    g = set(global_prefixes)
    if g:
        merged = [p for p in overlay_prefixes if p in g]
        return tuple(sorted(merged)) if merged else tuple(sorted(g))
    return overlay_prefixes   # global was unrestricted; overlay declares a boundary


def _merge_rung_floors(global_floors, overlay_floors) -> dict[str, RungFloor]:
    """Per-rung floors RAISE monotonically; overlay rungs absent in global are
    ignored (no fabricated rung), global rungs the overlay leaves alone stand."""
    out: dict[str, RungFloor] = {}
    for rung, gf in global_floors.items():
        of = overlay_floors.get(rung)
        if of is None:
            out[rung] = gf
            continue
        out[rung] = RungFloor(m=max(gf.m, of.m), s=max(gf.s, of.s))
    return out


def _union_allowlist(global_al, overlay_al) -> tuple[AllowlistEntry, ...]:
    """Overlay may only RE-AFFIRM governable allowlist entries — never ADD a
    value the global operator did not already allowlist.

    An allowlist entry suppresses enforcement (``evaluate`` returns NO_ACTION
    for any matching value), so an overlay introducing a brand-new allowlisted
    value would LOOSEN the global control — the tenant could self-whitelist its
    own C2 surface and defeat the operator's mandate. That violates the
    module's monotonic invariant ("an overlay may never loosen any global
    control"). The overlay keeps the global set unchanged and may carry an
    already-governed entry forward, but cannot broaden suppression.
    """
    governed = {e.canonical or e.value for e in global_al}
    seen = {}
    for e in global_al:
        seen[e.canonical or e.value] = e
    for e in overlay_al:
        key = e.canonical or e.value
        if key in governed:
            seen.setdefault(key, e)   # re-affirm a governed entry
    return tuple(sorted(seen.values(), key=lambda e: (e.scope, e.value)))


def merge_policy_overlay(global_policy: Policy, overlay: Policy) -> Policy:
    """Return a NEW Policy that is the deterministic, monotonic merge of the
    global policy and a tenant overlay. The result is at least as restrictive
    as the global on every overridable control."""
    # thresholds only RAISE (harder to act/observe)
    thresholds = {}
    for name in ("observe_m", "fqdn_auto_m", "fqdn_auto_s",
                 "ip_rate_m", "ip_rate_s", "ip_deny_m", "ip_deny_s"):
        thresholds[name] = _max_int(
            getattr(global_policy, name), getattr(overlay, name))

    # caps only LOWER
    caps = {
        "max_auto_ttl_seconds": _min_int(
            global_policy.max_auto_ttl_seconds, overlay.max_auto_ttl_seconds),
        "max_behavioral_m_contribution": _min_int(
            global_policy.max_behavioral_m_contribution,
            overlay.max_behavioral_m_contribution),
        "corroborated_max_behavioral_m_contribution": _min_int(
            global_policy.corroborated_max_behavioral_m_contribution,
            overlay.corroborated_max_behavioral_m_contribution),
        "max_evidence_per_indicator": _min_int(
            global_policy.max_evidence_per_indicator,
            overlay.max_evidence_per_indicator),
    }

    # behavioral corroboration only RAISES; the "requires external" gate only
    # moves False -> True (never lifts a requirement).
    corroboration = {
        "behavioral_rate_limit_families": _max_int(
            global_policy.behavioral_rate_limit_families,
            overlay.behavioral_rate_limit_families),
        "behavioral_deny_families": _max_int(
            global_policy.behavioral_deny_families,
            overlay.behavioral_deny_families),
        "behavioral_deny_requires_external": (
            overlay.behavioral_deny_requires_external
            or global_policy.behavioral_deny_requires_external),
    }

    # reference_unrestricted may only move True -> False (never back to open)
    ref_unrestricted = (
        global_policy.reference_unrestricted
        and overlay.reference_unrestricted)

    # max_new_auto_actions_per_batch gets stricter (lower) when both set
    if (global_policy.max_new_auto_actions_per_batch is not None
            and overlay.max_new_auto_actions_per_batch is not None):
        max_new = min(global_policy.max_new_auto_actions_per_batch,
                      overlay.max_new_auto_actions_per_batch)
    else:
        max_new = global_policy.max_new_auto_actions_per_batch

    # behavioral families: overlay may ADD gating families (union)
    families = tuple(sorted(set(global_policy.enabled_behavioral_families)
                            | set(overlay.enabled_behavioral_families)))

    return replace(
        global_policy,
        observe_m=thresholds["observe_m"],
        fqdn_auto_m=thresholds["fqdn_auto_m"],
        fqdn_auto_s=thresholds["fqdn_auto_s"],
        ip_rate_m=thresholds["ip_rate_m"],
        ip_rate_s=thresholds["ip_rate_s"],
        ip_deny_m=thresholds["ip_deny_m"],
        ip_deny_s=thresholds["ip_deny_s"],
        max_auto_ttl_seconds=caps["max_auto_ttl_seconds"],
        max_behavioral_m_contribution=caps["max_behavioral_m_contribution"],
        corroborated_max_behavioral_m_contribution=(
            caps["corroborated_max_behavioral_m_contribution"]),
        max_evidence_per_indicator=caps["max_evidence_per_indicator"],
        behavioral_rate_limit_families=(
            corroboration["behavioral_rate_limit_families"]),
        behavioral_deny_families=corroboration["behavioral_deny_families"],
        behavioral_deny_requires_external=(
            corroboration["behavioral_deny_requires_external"]),
        reference_unrestricted=ref_unrestricted,
        rung_floors=_merge_rung_floors(
            global_policy.rung_floors, overlay.rung_floors),
        authorized_domains=_narrow_domains(
            global_policy.authorized_domains, overlay.authorized_domains),
        authorized_prefixes=_narrow_prefixes(
            global_policy.authorized_prefixes, overlay.authorized_prefixes),
        allowlist=_union_allowlist(global_policy.allowlist, overlay.allowlist),
        mode=_stricter_mode(global_policy.mode, overlay.mode),
        enabled_behavioral_families=families,
        max_new_auto_actions_per_batch=max_new,
    )