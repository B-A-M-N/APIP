from __future__ import annotations
import tomllib
from pathlib import Path
from .policy import Policy, RungFloor, RandomizationMechanism, AllowlistEntry


class PolicyValidationError(ValueError):
    pass


# Strict monotonic ladder (docs/25): each stronger rung must have floors at
# least as strict as the rung below it.
_LADDER_ORDER = ["L1", "L2", "L4", "L5"]


def validate_policy(raw: dict) -> list[str]:
    """Semantic validation beyond syntax (docs/10 v2.1): impossible or
    unsafe configurations are rejected at load, not at 3 a.m."""
    problems: list[str] = []
    safety = raw.get("safety", {})
    if safety.get("auto_prefix_deny") is True:
        problems.append("auto_prefix_deny must be false (hard invariant)")
    if safety.get("auto_routing") is True:
        problems.append("auto_routing must be false (hard invariant)")
    if "no_ai_components" in safety and safety["no_ai_components"] is not True:
        problems.append("no_ai_components must be true when present (docs/28)")
    if raw.get("mode") not in {"OFF", "OBSERVE", "SHADOW", "ENFORCE", "EMERGENCY"}:
        problems.append(f"invalid mode: {raw.get('mode')!r}")
    rungs = (raw.get("thresholds", {}).get("rungs") or {})
    floors: dict[str, tuple[int, int]] = {}
    for name, fl in rungs.items():
        key = name.upper()
        if key not in {"L1", "L2", "L4", "L5"}:
            problems.append(f"unknown rung floor: {name}")
            continue
        floors[key] = (int(fl["m"]), int(fl["s"]))
    prev = None
    for r in _LADDER_ORDER:
        if r not in floors:
            continue
        if prev is not None:
            pm_, ps_ = floors[prev]
            m_, s_ = floors[r]
            if (m_, s_) < (pm_, ps_):
                problems.append(
                    f"rung floors not monotonic: {r} {floors[r]} weaker than {prev} {floors[prev]}")
        prev = r
    beh = raw.get("behavioral", {})
    corr = beh.get("corroboration", {})
    if int(corr.get("distinct_families_for_deny", 3)) < int(corr.get("distinct_families_for_rate_limit", 2)):
        problems.append("deny family minimum cannot be below rate-limit minimum")
    if int(beh.get("max_behavioral_m_contribution", 60)) >= 95:
        problems.append("uncorroborated behavioral cap must sit below the L4 deny floor")
    if not safety.get("allowlist_precedence", True):
        problems.append("allowlist_precedence=false is prohibited in the reference policy (docs/04)")
    return problems


def load_policy(path: str | Path) -> Policy:
    with open(path, "rb") as f:
        raw = tomllib.load(f)
    problems = validate_policy(raw)
    if problems:
        raise PolicyValidationError("; ".join(problems))
    t = raw["thresholds"]
    l = raw.get("limits", {})
    s = raw.get("safety", {})

    rung_floors = {}
    for key, fl in (t.get("rungs") or {}).items():
        rung_floors[key.upper()] = RungFloor(m=int(fl["m"]), s=int(fl["s"]))

    b = raw.get("behavioral") or {}
    corr = b.get("corroboration") or {}

    rz = raw.get("randomization") or {}
    mech = (rz.get("mechanisms") or {}).get("ttl_jitter") or {}
    ttl_jitter = RandomizationMechanism(
        enabled=bool(mech.get("enabled", False)),
        lo=float(mech.get("min", 0.8)),
        hi=float(mech.get("max", 1.0)),
    )

    allowlist = tuple(
        AllowlistEntry(
            value=str(e["value"]),
            scope=str(e.get("scope", raw.get("scope", "*"))),
            owner=str(e.get("owner", "")),
            ticket=str(e.get("ticket", "")),
            expires_at=e.get("expires_at"),
        )
        for e in (raw.get("allowlist") or [])
    )

    return Policy(
        version=raw["policy_version"],
        mode=raw["mode"],
        scope=raw["scope"],
        observe_m=int(t["observe_m"]),
        fqdn_auto_m=int(t["fqdn_auto_m"]),
        fqdn_auto_s=int(t["fqdn_auto_s"]),
        ip_rate_m=int(t["ip_rate_m"]),
        ip_rate_s=int(t["ip_rate_s"]),
        ip_deny_m=int(t["ip_deny_m"]),
        ip_deny_s=int(t["ip_deny_s"]),
        max_auto_ttl_seconds=int(l.get("max_auto_ttl_seconds", 3600)),
        auto_prefix_deny=bool(s.get("auto_prefix_deny", False)),
        auto_routing=bool(s.get("auto_routing", False)),
        auto_wildcard_domain=bool(s.get("auto_wildcard_domain", False)),
        allowlist=allowlist,
        allowlist_precedence=bool(s.get("allowlist_precedence", True)),
        rung_floors=rung_floors,
        behavioral_rate_limit_families=int(corr.get("distinct_families_for_rate_limit", 2)),
        behavioral_deny_families=int(corr.get("distinct_families_for_deny", 3)),
        behavioral_deny_requires_external=bool(corr.get("deny_also_requires_external", True)),
        max_behavioral_m_contribution=int(b.get("max_behavioral_m_contribution", 60)),
        randomization_enabled=bool(rz.get("enabled", False)),
        randomization_bounds_version=str(rz.get("bounds_version", "")),
        randomization_epoch=str(rz.get("epoch", "0")),
        ttl_jitter=ttl_jitter,
    )
