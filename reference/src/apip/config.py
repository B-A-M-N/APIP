from __future__ import annotations
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .policy import Policy, RungFloor, RandomizationMechanism, AllowlistEntry


def _default_recency_classifier(max_age_hours: float):
    """Deterministic recency over the policy clock (docs/04 freshness).

    Adversarial-audit fix: the scaffold previously defaulted to a classifier
    that returned 'fresh' for every timestamp — the shipped demo therefore
    never exercised evidence decay. The default now actually decays, and is
    anchored to an explicit reference_now so it stays replayable.
    """
    def classify(ts: str) -> str:
        if not ts:
            return "stale"
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return "stale"
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return "fresh" if abs(now - dt) <= timedelta(hours=max_age_hours) else "stale"
    return classify


class PolicyValidationError(ValueError):
    pass


def canonical_allowlist_entry(value: str, scope: str, owner: str = "",
                              ticket: str = "",
                              expires_at: str | None = None):
    """Public constructor for canonical allowlist entries (v2.2)."""
    return _canonical_allowlist_entry(value=value, scope=scope, owner=owner,
                                      ticket=ticket, expires_at=expires_at)


def _canonical_allowlist_entry(value: str, scope: str, owner: str = "",
                               ticket: str = "", expires_at: str | None = None):
    """Build an AllowlistEntry with its canonical matching key (v2.2).

    Matching is canonical so 'Example.COM.' protects 'example.com'. An
    entry whose value cannot be parsed at all keeps a stripped-lowercase
    key that matches only itself — fail closed.
    """
    from .policy import AllowlistEntry, _allowlist_key
    key = _allowlist_key(value)
    return AllowlistEntry(value=value, scope=scope, owner=owner,
                          ticket=ticket, expires_at=expires_at, canonical=key)


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
    # v2.1.1: an L2 floor with no nominal rate ceiling means the platform
    # would emit rate_limit rules with no ceiling semantics — the exact gap
    # the audit named. Require the ceiling whenever L2 is automated.
    rung_names = {k.upper() for k in rungs}
    limits = raw.get("limits", {})
    if "L2" in rung_names and int(limits.get("nominal_rate_ceiling_per_min", 0)) <= 0:
        problems.append(
            "nominal_rate_ceiling_per_min must be > 0 when an L2 floor is "
            "configured (rate_limit without a ceiling is not a rule)")
    rc = ((raw.get("randomization", {}).get("mechanisms") or {}).get("rate_ceiling") or {})
    if rc.get("enabled") and not limits.get("nominal_rate_ceiling_per_min"):
        problems.append("rate_ceiling randomization enabled but nominal_rate_ceiling_per_min is unset")
    rn = (raw.get("replay") or {}).get("reference_now")
    if rn is not None:
        import re as _re
        if not (isinstance(rn, str) and _re.match(
                r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$", rn)):
            problems.append("replay.reference_now must be ISO-8601 UTC (...Z)")
    # v2.2 (docs/04 §8): a batch-action budget must be a positive integer
    # when present; production policies are expected to set it.
    mb = limits.get("max_new_auto_actions_per_batch")
    if mb is not None and (not isinstance(mb, int) or isinstance(mb, bool) or mb < 1):
        problems.append("limits.max_new_auto_actions_per_batch must be a positive integer when set")
    # v2.2 (docs/25 L1 client-impact budget): the challenged-transaction
    # fraction must be a real fraction in (0, 1] when present; zero would
    # silently disable every challenge while looking configured, and >1 is
    # not a fraction. The measured transaction count (CLI-side) must be a
    # non-negative integer when supplied.
    cf = limits.get("max_challenged_transaction_fraction_per_hour")
    if cf is not None and (isinstance(cf, bool) or not isinstance(cf, (int, float))
                           or not (0 < float(cf) <= 1)):
        problems.append(
            "limits.max_challenged_transaction_fraction_per_hour must be a number in (0, 1] when set")
    mi = (raw.get("measurement") or {}).get("interactive_transactions_per_hour")
    if mi is not None and (not isinstance(mi, int) or isinstance(mi, bool) or mi < 0):
        problems.append(
            "measurement.interactive_transactions_per_hour must be a non-negative integer when set")
    # v2.2 (docs/26): governed allowlist entries carry owner and ticket;
    # unowned or unticketed entries are rejected at load — allow-first
    # posture treats a stale/ungoverned entry as a finding, not a feature.
    for pos, e in enumerate(raw.get("allowlist") or []):
        if not str(e.get("owner", "")).strip() or not str(e.get("ticket", "")).strip():
            problems.append(f"allowlist entry #{pos} must carry owner and ticket "
                            "(docs/26 governed entries)")
        exp = e.get("expires_at")
        if exp is not None:
            import re as _re2
            if not (isinstance(exp, str) and _re2.match(
                    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$", exp)):
                problems.append(
                    f"allowlist entry #{pos} expires_at must be ISO-8601 UTC (...Z)")
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
    rmech = (rz.get("mechanisms") or {}).get("rate_ceiling") or {}
    rate_ceiling_jitter = RandomizationMechanism(
        enabled=bool(rmech.get("enabled", False)),
        lo=float(rmech.get("min", 0.5)),
        hi=float(rmech.get("max", 1.0)),
    )

    allowlist = tuple(
        _canonical_allowlist_entry(
            value=str(e["value"]),
            scope=str(e.get("scope", raw.get("scope", "*"))),
            owner=str(e.get("owner", "")),
            ticket=str(e.get("ticket", "")),
            expires_at=e.get("expires_at"),
        )
        for e in (raw.get("allowlist") or [])
    )

    recency_max_age = float((raw.get("freshness") or {}).get("max_age_hours", 6.0))

    return Policy(
        version=raw["policy_version"],
        mode=raw["mode"],
        scope=raw["scope"],
        classify_recency=_default_recency_classifier(recency_max_age),
        # replay clock (docs/10): pin evaluation to an instant so byte-replay
        # is exact. Reference scaffold: policy knob when present; production
        # determinism harness derives it from the batch manifest.
        reference_now=(raw.get("replay") or {}).get("reference_now"),
        _recency_max_age_hours=recency_max_age,
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
        max_evidence_per_indicator=int(l.get("max_evidence_per_indicator", 64)),
        nominal_rate_ceiling_per_min=int(l.get("nominal_rate_ceiling_per_min", 0)),
        # v2.2: blast-radius budget (docs/04 §8). None when unset.
        max_new_auto_actions_per_batch=(
            int(l["max_new_auto_actions_per_batch"])
            if l.get("max_new_auto_actions_per_batch") is not None else None),
        # v2.2: L1 client-impact budget (docs/25) + the measured interactive
        # transaction volume that gives the fraction its denominator. The
        # measurement is operator-supplied telemetry — the scaffold never
        # invents it; unset measurement + set fraction = zero allowance
        # (fail closed, see policy.challenge_allowance).
        max_challenged_transaction_fraction_per_hour=(
            float(l["max_challenged_transaction_fraction_per_hour"])
            if l.get("max_challenged_transaction_fraction_per_hour") is not None else None),
        measured_interactive_transactions_per_hour=(
            int((raw.get("measurement") or {})["interactive_transactions_per_hour"])
            if (raw.get("measurement") or {}).get("interactive_transactions_per_hour") is not None
            else None),
        # v2.2: authorized target space (docs/04) — empty list means the
        # operator has explicitly NOT enumerated a boundary, which the
        # loader records rather than assuming unrestricted production scope.
        authorized_prefixes=tuple(
            str(p) for p in ((raw.get("authorization") or {}).get("authorized_prefixes") or ())),
        randomization_enabled=bool(rz.get("enabled", False)),
        randomization_bounds_version=str(rz.get("bounds_version", "")),
        randomization_epoch=str(rz.get("epoch", "0")),
        ttl_jitter=ttl_jitter,
        rate_ceiling_jitter=rate_ceiling_jitter,
    )
