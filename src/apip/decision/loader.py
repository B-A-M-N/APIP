"""Policy loading + semantic validation — production port of
``reference/src/apip/config.py``.

Same fail-closed rules (hard invariants, monotonic ladder floors, schema-
bound ranges, declared-mechanism honesty, boundary-required-for-ENFORCE,
governed allowlist entries, actual-instant parsing). The production loader
additionally returns the SHA-256 of the raw policy text so every staged
policy version is content-addressed and decisions pin (version, hash).
"""
from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path
from typing import cast

from apip.decision.policy import (
    AllowlistEntry,
    Policy,
    RandomizationMechanism,
    RungFloor,
    _allowlist_key,
)

_CLOCK_SKEW = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")

# The randomization mechanisms this engine actually implements (docs/29);
# anything else fails closed rather than shipping an inert knob.
_SUPPORTED_RANDOMIZATION_MECHANISMS = frozenset({"ttl_jitter", "rate_ceiling"})

# Behavioral families come from ONE source of truth: the detector runtime
# (apip.telemetry.behavioral, audit #23). All eight docs/23 families are
# implemented as bounded deterministic detectors; PENDING_FAMILIES is empty
# so an operator requesting a family is never told it exists while detecting
# nothing.
from apip.telemetry.behavioral import (  # noqa: E402
    IMPLEMENTED_FAMILIES,
    PENDING_FAMILIES,
)

_LADDER_ORDER = ["L1", "L2", "L4", "L5"]

# Fields the schema may accept that the runtime does NOT implement: rejected
# at load (accept it => implement it or fail), per reference audit P1-32.
_P1_32_UNIMPLEMENTED_NESTED = {
    "limits": ("max_actions_per_bundle",
               "max_auto_actions_per_tenant_window",
               "max_segment_denied_volume_alarm_per_hour"),
    "safety": ("require_expiry",),
}
_P1_32_UNIMPLEMENTED_SECTIONS = ("segments",)


class PolicyValidationError(ValueError):
    pass


def parse_policy_instant(value):
    """Parse a policy-borne ISO-8601 UTC instant; None unless GENUINELY valid
    (reference P1-35: parse the actual date, not just the shape)."""
    from datetime import datetime, timezone
    if not (isinstance(value, str) and _CLOCK_SKEW.match(value)):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _valid_domain_suffix(d: str) -> bool:
    s = d.strip().lower().rstrip(".")
    if not s or " " in s or "/" in s or "://" in d or "\\" in d:
        return False
    return bool(re.match(
        r"^([a-z0-9]([a-z0-9\-]*[a-z0-9])?)(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$", s))


def validate_policy(raw: dict) -> list[str]:
    """Semantic validation beyond syntax — ported from the oracle."""
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
    for _tname in ("observe_m", "fqdn_auto_m", "fqdn_auto_s",
                   "ip_rate_m", "ip_rate_s", "ip_deny_m", "ip_deny_s"):
        _tv: object | None = (raw.get("thresholds") or {}).get(_tname)
        if _tv is None:
            # Absent thresholds pass through untouched (unchanged).
            continue
        # Thresholds are JSON scalars (int/float/str/bool in practice); int()
        # coercion below is defensively guarded for malformed configs.
        _conv = cast("int | str | float | bool", _tv)
        try:
            _ti = int(_conv)
        except (TypeError, ValueError):
            problems.append(f"threshold {_tname} must be an integer")
            continue
        if not (0 <= _ti <= 100):
            problems.append(f"threshold {_tname} out of range [0,100]: {_ti}")
    authz = raw.get("authorization") or {}
    unrestricted = bool(authz.get("reference_unrestricted", False))
    has_ip = any(x is not None and str(x).strip() for x in authz.get("authorized_prefixes") or ())
    has_domains = any(x is not None and str(x).strip() for x in authz.get("authorized_domains") or ())
    if raw.get("mode") in {"ENFORCE", "EMERGENCY"}:
        if unrestricted:
            problems.append(
                "reference_unrestricted=true is prohibited in ENFORCE/EMERGENCY "
                "(a control plane must declare an explicit authorization boundary)")
        if not (has_ip or has_domains):
            problems.append(
                "ENFORCE/EMERGENCY requires an explicit [authorization] boundary "
                "(authorized_prefixes and/or authorized_domains) — never fail-open")
    rungs = (raw.get("thresholds", {}).get("rungs") or {})
    floors: dict[str, tuple[int, int]] = {}
    for name, fl in rungs.items():
        key = name.upper()
        if key not in {"L1", "L2", "L4", "L5"}:
            problems.append(f"unknown rung floor: {name}")
            continue
        try:
            m_ = int(fl["m"]); s_ = int(fl["s"])
        except (TypeError, ValueError, KeyError):
            problems.append(f"rung floor {name} must be an int m and s")
            continue
        if not (0 <= m_ <= 100 and 0 <= s_ <= 100):
            problems.append(f"rung floor {name} out of range [0,100]: m={m_} s={s_}")
        floors[key] = (m_, s_)
    prev = None
    for r in _LADDER_ORDER:
        if r not in floors:
            continue
        if prev is not None:
            pm_, ps_ = floors[prev]
            m_, s_ = floors[r]
            if m_ < pm_ or s_ < ps_:
                problems.append(
                    f"rung floors not monotonic: {r} {floors[r]} weaker than {prev} {floors[prev]}")
        prev = r
    beh = raw.get("behavioral", {})
    corr = beh.get("corroboration", {})
    _fam_rate = corr.get("distinct_families_for_rate_limit")
    _fam_deny = corr.get("distinct_families_for_deny")
    if _fam_rate is not None and (not isinstance(_fam_rate, int) or isinstance(_fam_rate, bool)
                                  or _fam_rate < 2):
        problems.append("behavioral.corroboration.distinct_families_for_rate_limit must be an integer >= 2")
    if _fam_deny is not None and (not isinstance(_fam_deny, int) or isinstance(_fam_deny, bool)
                                  or _fam_deny < 3):
        problems.append("behavioral.corroboration.distinct_families_for_deny must be an integer >= 3")
    if int(corr.get("distinct_families_for_deny", 3)) < int(corr.get("distinct_families_for_rate_limit", 2)):
        problems.append("deny family minimum cannot be below rate-limit minimum")
    if int(beh.get("max_behavioral_m_contribution", 60)) >= 95:
        problems.append("uncorroborated behavioral cap must sit below the L4 deny floor")
    _KNOWN_FAMS = IMPLEMENTED_FAMILIES | PENDING_FAMILIES
    for _fam in beh.get("enabled_families") or ():
        if _fam not in _KNOWN_FAMS:
            problems.append(f"behavioral.enabled_families names unknown family {_fam!r}")
    if not safety.get("allowlist_precedence", True):
        problems.append("allowlist_precedence=false is prohibited in the policy (docs/04)")
    rung_names = {k.upper() for k in rungs}
    limits = raw.get("limits", {})
    if "L2" in rung_names and int(limits.get("nominal_rate_ceiling_per_min", 0)) <= 0:
        problems.append(
            "nominal_rate_ceiling_per_min must be > 0 when an L2 floor is "
            "configured (rate_limit without a ceiling is not a rule)")
    rc = ((raw.get("randomization", {}).get("mechanisms") or {}).get("rate_ceiling") or {})
    if rc.get("enabled") and not limits.get("nominal_rate_ceiling_per_min"):
        problems.append("rate_ceiling randomization enabled but nominal_rate_ceiling_per_min is unset")
    _rz_mech = (raw.get("randomization", {}).get("mechanisms") or {})
    for _name in _rz_mech:
        if _name not in _SUPPORTED_RANDOMIZATION_MECHANISMS:
            problems.append(
                f"unsupported randomization mechanism '{_name}': the engine "
                "implements ttl_jitter and rate_ceiling only; an unwired "
                "mechanism would be silently inert")
    _rnd = raw.get("randomization") or {}
    for _mname in _SUPPORTED_RANDOMIZATION_MECHANISMS:
        _b = (_rnd.get("mechanisms") or {}).get(_mname) or {}
        if not _b.get("enabled"):
            continue
        _lo, _hi = _b.get("min"), _b.get("max")
        if not (isinstance(_lo, (int, float)) and not isinstance(_lo, bool)
                and isinstance(_hi, (int, float)) and not isinstance(_hi, bool)):
            problems.append(
                f"randomization.mechanisms.{_mname}.min/.max must be numbers")
            continue
        if _lo > _hi:
            problems.append(
                f"randomization.mechanisms.{_mname}.min ({_lo}) exceeds "
                f"max ({_hi})")
        if _lo < 0 or _hi < 0:
            problems.append(
                f"randomization.mechanisms.{_mname} bounds must be non-negative "
                f"(got min={_lo}, max={_hi})")
    if _rnd.get("enabled") and not str(_rnd.get("bounds_version", "") or "").strip():
        problems.append(
            "randomization enabled requires a non-empty bounds_version "
            "(P1-8 roll-forward/bounds provenance anchor)")
    rn = (raw.get("replay") or {}).get("reference_now")
    if rn is not None and parse_policy_instant(rn) is None:
        problems.append(
            "replay.reference_now must be a VALID ISO-8601 UTC instant (...Z)")
    mb = limits.get("max_new_auto_actions_per_batch")
    if mb is not None and (not isinstance(mb, int) or isinstance(mb, bool) or mb < 1):
        problems.append("limits.max_new_auto_actions_per_batch must be a positive integer when set")
    _ttl = limits.get("max_auto_ttl_seconds")
    if _ttl is not None and (not isinstance(_ttl, int) or isinstance(_ttl, bool) or _ttl < 1):
        problems.append("limits.max_auto_ttl_seconds must be a positive integer (>=1)")
    _cap = limits.get("max_evidence_per_indicator")
    if _cap is not None and (not isinstance(_cap, int) or isinstance(_cap, bool)
                             or not (1 <= _cap <= 1024)):
        problems.append("limits.max_evidence_per_indicator must be an integer in [1,1024]")
    cf = limits.get("max_challenged_transaction_fraction_per_hour")
    if cf is not None and (isinstance(cf, bool) or not isinstance(cf, (int, float))
                           or not (0 < float(cf) <= 1)):
        problems.append(
            "limits.max_challenged_transaction_fraction_per_hour must be a number in (0, 1] when set")
    mi = (raw.get("measurement") or {}).get("interactive_transactions_per_hour")
    if mi is not None and (not isinstance(mi, int) or isinstance(mi, bool) or mi < 0):
        problems.append(
            "measurement.interactive_transactions_per_hour must be a non-negative integer when set")
    for pos, e in enumerate(raw.get("allowlist") or []):
        if not str(e.get("owner", "")).strip() or not str(e.get("ticket", "")).strip():
            problems.append(f"allowlist entry #{pos} must carry owner and ticket "
                            "(docs/26 governed entries)")
        exp = e.get("expires_at")
        if exp is not None and parse_policy_instant(exp) is None:
            problems.append(
                f"allowlist entry #{pos} expires_at must be a VALID "
                "ISO-8601 UTC instant (...Z)")
    import ipaddress as _ipa
    for pos, p in enumerate(authz.get("authorized_prefixes") or ()):
        if not isinstance(p, str) or not p.strip():
            problems.append(f"authorization.authorized_prefixes entry #{pos} must be a string")
            continue
        try:
            _ipa.ip_network(p, strict=False)
        except ValueError:
            problems.append(
                f"authorization.authorized_prefixes entry #{pos} is not a valid CIDR: {p!r}")
    for pos, d in enumerate(authz.get("authorized_domains") or ()):
        if not isinstance(d, str) or not d.strip():
            problems.append(f"authorization.authorized_domains entry #{pos} must be a string")
        elif not _valid_domain_suffix(d):
            problems.append(
                f"authorization.authorized_domains entry #{pos} is not a valid domain suffix: {d!r}")
    for pos, v in enumerate((raw.get("governed") or {}).get("dedicated_use") or ()):
        if not isinstance(v, str) or not v.strip():
            problems.append(f"governed.dedicated_use entry #{pos} must be a non-empty string")
    for pos, v in enumerate((raw.get("governed") or {}).get("verified_rollback") or ()):
        if not isinstance(v, str) or not v.strip():
            problems.append(f"governed.verified_rollback entry #{pos} must be a non-empty string")
    for _section, _fields in _P1_32_UNIMPLEMENTED_NESTED.items():
        for _field in _fields:
            if (raw.get(_section) or {}).get(_field) is not None:
                problems.append(
                    f"unsupported policy field {_section}.{_field}: the runtime "
                    "does not implement it; remove it or fail closed")
    for _section in _P1_32_UNIMPLEMENTED_SECTIONS:
        if raw.get(_section):
            problems.append(
                f"unsupported policy section '{_section}': the runtime "
                "does not implement allow-first segment policies; remove it or "
                "fail closed")
    return problems


def build_policy(raw: dict, raw_text: str, *, source_registry, now_fn,
                 canonical_allowlist: bool = True) -> Policy:
    """Build an immutable Policy from VALIDATED raw TOML data.

    ``source_registry`` and ``now_fn`` are injected by the caller (DB-backed
    registry + controller clock) — the decision path never reads them from
    the file. ``raw_text`` is hashed into the policy so staged versions are
    content-addressed.
    """
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
        AllowlistEntry(
            value=str(e["value"]),
            scope=str(e.get("scope", raw.get("scope", "*"))),
            owner=str(e.get("owner", "")),
            ticket=str(e.get("ticket", "")),
            expires_at=e.get("expires_at"),
            canonical=(_allowlist_key(str(e["value"])) if canonical_allowlist else ""),
        )
        for e in (raw.get("allowlist") or [])
    )

    recency_max_age = float((raw.get("freshness") or {}).get("max_age_hours", 6.0))

    import ipaddress
    _authz = raw.get("authorization") or {}
    _canonical_prefixes = tuple(
        str(ipaddress.ip_network(str(p), strict=False))
        for p in (_authz.get("authorized_prefixes") or ()))
    _canonical_domains = tuple(
        str(d).strip().lower().rstrip(".") for d in (_authz.get("authorized_domains") or ()))
    _declared_boundary = bool(_canonical_prefixes or _canonical_domains)
    _reference_unrestricted = (
        False if _declared_boundary else bool(_authz.get("reference_unrestricted", False)))

    return Policy(
        version=raw["policy_version"],
        mode=raw["mode"],
        scope=raw["scope"],
        classify_recency=lambda _ts: "fresh",  # replaced below via now-bound classifier
        now_fn=now_fn,
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
        max_new_auto_actions_per_batch=(
            int(l["max_new_auto_actions_per_batch"])
            if l.get("max_new_auto_actions_per_batch") is not None else None),
        authorized_prefixes=_canonical_prefixes,
        authorized_domains=_canonical_domains,
        reference_unrestricted=_reference_unrestricted,
        governed_dedicated_use=tuple(
            str(v) for v in ((raw.get("governed") or {}).get("dedicated_use") or ())),
        governed_verified_rollback=tuple(
            str(v) for v in ((raw.get("governed") or {}).get("verified_rollback") or ())),
        enabled_behavioral_families=tuple(str(x) for x in b.get("enabled_families") or ()),
        randomization_enabled=bool(rz.get("enabled", False)),
        randomization_bounds_version=str(rz.get("bounds_version", "")),
        randomization_epoch=str(rz.get("epoch", "0")),
        randomization_rotation_interval_seconds=int(rz.get("rotation_interval_seconds", 0) or 0),
        ttl_jitter=ttl_jitter,
        rate_ceiling_jitter=rate_ceiling_jitter,
        source_registry=source_registry,
        content_sha256=hashlib.sha256(raw_text.encode()).hexdigest(),
    )


def validate_overlay(raw: dict, global_raw: dict) -> list[str]:
    """Stage-time tighten-only check for a tenant overlay (task #11, feature 2).

    These are *advice* surfaced at staging time — the authoritative monotonic
    guarantee is the runtime clamp in ``merge_policy_overlay``, which applies
    even if a loosing overlay slips through. Problems here tell the operator
    early what the overlay would (and would not) do.
    """
    problems: list[str] = []
    # shape safety reuses the full policy validator (it is a real policy shape)
    problems.extend(validate_policy(raw))
    g_t = global_raw.get("thresholds") or {}
    o_t = raw.get("thresholds") or {}
    for name in ("observe_m", "fqdn_auto_m", "fqdn_auto_s",
                 "ip_rate_m", "ip_rate_s", "ip_deny_m", "ip_deny_s"):
        gv = g_t.get(name)
        ov = o_t.get(name)
        if gv is None or ov is None:
            continue
        if int(ov) < int(gv):
            problems.append(
                f"overlay would LOOSEN threshold {name} ({ov} < global {gv}); "
                "the runtime clamps it back to the global (monotonic)")
    g_l = global_raw.get("limits") or {}
    o_l = raw.get("limits") or {}
    for name, kind in (("max_auto_ttl_seconds", "cap"),
                       ("max_evidence_per_indicator", "cap"),
                       ("max_behavioral_m_contribution", "cap")):
        gv, ov = g_l.get(name), o_l.get(name)
        if gv is not None and ov is not None and ov >= gv and name != "max_behavioral_m_contribution":
            problems.append(
                f"overlay cap {name} ({ov}) is not stricter than global ({gv}); "
                "raise-only is clamped")
    if o_l.get("max_behavioral_m_contribution") is not None:
        if g_l.get("max_behavioral_m_contribution") is not None and \
                raw.get("limits", {}).get("max_behavioral_m_contribution") >= \
                g_l.get("max_behavioral_m_contribution", 1 << 31):
            problems.append(
                "overlay max_behavioral_m_contribution not stricter than global")
    g_auth = global_raw.get("authorization") or {}
    o_auth = raw.get("authorization") or {}
    g_domains = {str(d).strip().lower().rstrip(".")
                 for d in (g_auth.get("authorized_domains") or ())}
    o_domains = {str(d).strip().lower().rstrip(".")
                 for d in (o_auth.get("authorized_domains") or ())}
    if o_domains - g_domains:
        problems.append(
            "overlay proposes authorized_domains outside the global boundary "
            "(never widen scope)")
    if o_auth.get("reference_unrestricted") is True and not (
        G := g_auth.get("authorized_domains") or g_auth.get("authorized_prefixes")):
        problems.append("overlay must not set reference_unrestricted=true")
    return problems


def build_overlay(raw: dict, raw_text: str, *, source_registry=None,
                  now_fn=None) -> Policy:
    """Build a PARTIAL ``Policy`` from a tenant overlay TOML.

    Only the override fields the author wrote are non-default; everything else
    keeps the permissive ``Policy`` default so the merge clamp in
    ``layer.merge_policy_overlay`` treats absence as "keep global". This is a
    relaxed builder (no full validation pressure) but still bounds field
    ranges the way ``validate_policy`` does for the fields it accepts.
    """
    from datetime import datetime, timezone  # noqa: PLC0415
    from apip.decision.policy import AllowlistEntry, RungFloor  # noqa: PLC0415

    now_fn = now_fn or (lambda: "1970-01-01T00:00:00Z")
    t = raw.get("thresholds") or {}
    l = raw.get("limits") or {}
    s = raw.get("safety") or {}
    b = raw.get("behavioral") or {}
    corr = b.get("corroboration") or {}
    authz = raw.get("authorization") or {}
    _ref_unrestricted = bool(authz.get("reference_unrestricted", False))

    rung_floors = {}
    for key, fl in (t.get("rungs") or {}).items():
        rung_floors[key.upper()] = RungFloor(m=int(fl["m"]), s=int(fl["s"]))

    allowlist = tuple(
        AllowlistEntry(
            value=str(e["value"]),
            scope=str(e.get("scope", raw.get("scope", "*"))),
            owner=str(e.get("owner", "")),
            ticket=str(e.get("ticket", "")),
            expires_at=e.get("expires_at"),
            canonical=str(e["value"]),
        )
        for e in (raw.get("allowlist") or []))

    import ipaddress
    prefixes = tuple(
        str(ipaddress.ip_network(str(p), strict=False))
        for p in (authz.get("authorized_prefixes") or ()))

    # An overlay that does not declare a mode must NOT silently force one onto
    # the tenant (defaulting to SHADOW stepped a global ENFORCE down to SHADOW
    # for every threshold-only overlay). Absence carries the ``UNSET`` sentinel
    # into the merge, which treats it as "keep the global mode" (identity). The
    # sentinel is internal to the merge and never survives it — the effective
    # policy always carries one of the five real modes.
    _mode = str(raw.get("mode", "UNSET")).upper()

    return Policy(
        version=str(raw.get("policy_version", "")),
        mode=_mode,
        scope=str(raw.get("scope", "*")),
        observe_m=int(t.get("observe_m", 0)),
        fqdn_auto_m=int(t.get("fqdn_auto_m", 0)),
        fqdn_auto_s=int(t.get("fqdn_auto_s", 0)),
        ip_rate_m=int(t.get("ip_rate_m", 0)),
        ip_rate_s=int(t.get("ip_rate_s", 0)),
        ip_deny_m=int(t.get("ip_deny_m", 0)),
        ip_deny_s=int(t.get("ip_deny_s", 0)),
        max_auto_ttl_seconds=int(l.get("max_auto_ttl_seconds", 1 << 31)),  # lenient default
        auto_prefix_deny=bool(s.get("auto_prefix_deny", False)),
        auto_routing=bool(s.get("auto_routing", False)),
        auto_wildcard_domain=bool(s.get("auto_wildcard_domain", False)),
        allowlist=allowlist,
        allowlist_precedence=bool(s.get("allowlist_precedence", True)),
        rung_floors=rung_floors,
        behavioral_rate_limit_families=int(corr.get("distinct_families_for_rate_limit", 0)),
        behavioral_deny_families=int(corr.get("distinct_families_for_deny", 0)),
        behavioral_deny_requires_external=bool(
            corr.get("deny_also_requires_external", False)),
        max_behavioral_m_contribution=int(
            b.get("max_behavioral_m_contribution", 1 << 31)),  # cap-safe default
        max_evidence_per_indicator=int(l.get("max_evidence_per_indicator", 1 << 31)),
        authorized_prefixes=prefixes,
        authorized_domains=tuple(
            str(d).strip().lower().rstrip(".")
            for d in (authz.get("authorized_domains") or ())),
        reference_unrestricted=_ref_unrestricted,
        enabled_behavioral_families=tuple(str(x) for x in b.get("enabled_families") or ()),
        max_new_auto_actions_per_batch=(
            int(l["max_new_auto_actions_per_batch"])
            if l.get("max_new_auto_actions_per_batch") is not None else None),
        source_registry=source_registry,
        now_fn=now_fn,
    )


def load_policy_text(text: str, *, source_registry=None, now_fn=None) -> Policy:
    """Parse + validate + build from TOML text (staging path)."""
    raw = tomllib.loads(text)
    return build_policy(raw, text,
                        source_registry=source_registry,
                        now_fn=now_fn or (lambda: "1970-01-01T00:00:00Z"))


def load_policy_file(path: str | Path, *, source_registry=None, now_fn=None) -> Policy:
    text = Path(path).read_text(encoding="utf-8")
    return load_policy_text(text, source_registry=source_registry, now_fn=now_fn)
