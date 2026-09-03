from __future__ import annotations
import ipaddress
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from .policy import Policy, RungFloor, RandomizationMechanism


_CLOCK_SKEW = timedelta(minutes=5)

# Validators routing JSON output are NOT kept here; see tests. This is the
# runtime's own ISO-8601 UTC (Z) timestamp grammar for policy-borne instants
# (replay.reference_now, allowlist[].expires_at). It matches the JSON Schema
# `pattern` used for the same fields so schema and runtime agree (P1-29/P1-34).
_ISO_UTC_RE = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$"


def _parse_policy_instant(value):
    """Parse a policy-borne ISO-8601 UTC instant and return a timezone-aware
    datetime, or None for anything that is not a GENUINELY valid instant.

    audit P1-35: date validation must check the ACTUAL date/time values, not
    just the shape. A regex-shaped-but-invalid timestamp (e.g. '2026-99-99
    T99:99:99Z') passes the pattern yet later parses as None; an allowlist
    expiry that parses as None is treated as "not expired" — a configured
    expiry + parse failure would silently become "allow forever". Parsing the
    real instant at load rejects those before they can fail open.
    """
    import re as _re_iso
    if not (isinstance(value, str) and _re_iso.match(_ISO_UTC_RE, value)):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt

# The randomization mechanisms this engine actually implements (docs/29).
# `[randomization.mechanisms]` in a policy file may ONLY name keys from this
# set — an enabled mechanism we do not wire would be silently inert, an
# operator believing moving-target defense was active for defense it never
# got. Any other key fails closed at validation (audit P1-7..11: declared
# knobs must be real or rejected, never ghosts).
_SUPPORTED_RANDOMIZATION_MECHANISMS = frozenset({"ttl_jitter", "rate_ceiling"})


def _default_recency_classifier(max_age_hours: float):
    """Deterministic recency over the policy clock (docs/04 freshness).

    Adversarial-audit fix: the scaffold previously defaulted to a classifier
    that returned 'fresh' for every timestamp — the shipped demo therefore
    never exercised evidence decay. The default now actually decays, and is
    anchored to an explicit reference_now so it stays replayable.

    v2.3 (audit P1-3): freshness is ASYMMETRIC. An observation stamped hours
    in the future is not evidence — only a small explicit clock-skew
    allowance (`_CLOCK_SKEW`) is tolerated; anything older than max_age is
    stale.
    """
    max_age = timedelta(hours=max(0.0, max_age_hours))

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
        future_skew = dt - now
        age = now - dt
        if future_skew > _CLOCK_SKEW:
            return "stale"
        return "fresh" if age <= max_age else "stale"
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


def _valid_domain_suffix(d: str) -> bool:
    """Minimal validity for an authorization domain scope (P1-2/P1-1).

    A scope is a DNS label or dotted domain (e.g. `invalid`, `example.com`);
    `_in_scope` matches a target against it as `v == d or v.endswith('.' + d)`.
    Rejects scheme-bearing, spaced, or slash-carrying values so a scope can
    never be smuggled into a URL-ish match.
    """
    import re as _re3
    s = d.strip().lower().rstrip(".")
    if not s or " " in s or "/" in s or "://" in d or "\\" in d:
        return False
    # one or more DNS labels; 'invalid' and 'example.com' both valid
    if not _re3.match(r"^([a-z0-9]([a-z0-9\-]*[a-z0-9])?)(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$", s):
        return False
    return True


# Strict monotonic ladder (docs/25): each stronger rung must have floors at
# least as strict as the rung below it.
_LADDER_ORDER = ["L1", "L2", "L4", "L5"]

# audit P1-32: fields the JSON schema ACCEPTS (so a machine-valid policy can
# carry them) that the runtime does NOT implement. A security policy must
# never silently ignore an accepted safety-bearing field: if the parser
# accepts one, it must implement it or fail with "unsupported policy field".
# Each of these is rejected at load when present, so an operator who configures
# it believing it is active gets a loud load failure, never silent inaction.
# Nested unimplemented fields, keyed by the enclosing section.
_P1_32_UNIMPLEMENTED_NESTED = {
    "limits": ("max_actions_per_bundle",
               "max_auto_actions_per_tenant_window",
               "max_segment_denied_volume_alarm_per_hour"),
    "safety": ("require_expiry",),
}
# Top-level unimplemented sections (allow-first segment policies, docs/26).
_P1_32_UNIMPLEMENTED_SECTIONS = ("segments",)


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
    # audit P1-34: the JSON schema constrains every automation threshold to
    # [0,100]; the runtime MUST enforce the same bound at load, or a policy
    # that is schema-invalid on a safety-bearing threshold could still load
    # and mis-order decisions. Non-integer or out-of-range is rejected here.
    for _tname in ("observe_m", "fqdn_auto_m", "fqdn_auto_s",
                   "ip_rate_m", "ip_rate_s", "ip_deny_m", "ip_deny_s"):
        _tv = (raw.get("thresholds") or {}).get(_tname)
        try:
            _ti = int(_tv)
        except (TypeError, ValueError):
            if _tv is not None:
                problems.append(f"threshold {_tname} must be an integer")
            continue
        if not (0 <= _ti <= 100):
            problems.append(f"threshold {_tname} out of range [0,100]: {_ti}")
    # v2.3 (audit P1-1): an enforcement-capable policy must carry an explicit
    # authorization boundary. ENFORCE/EMERGENCY may not be authorize-by-
    # default; the reference_unrestricted opt-in is FORBIDDEN in these modes.
    authz = raw.get("authorization") or {}
    unrestricted = bool(authz.get("reference_unrestricted", False))
    # P1-2 below parses/canonicalizes entries; here we only need the
    # empty-vs-nonempty signal (presence), which does not depend on type.
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
        # v2.3 (audit P0-5): each floor component is validated as an integer
        # in [0,100] at LOAD. A non-integer or out-of-range value previously
        # reached comparison as a float/string and could silently mis-order
        # the ladder. Reject here so an impossible floor never loads.
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
            # v2.3 (audit P0-5): a stronger rung must be at least as strict
            # in BOTH components. The old `(m_, s_) < (pm_, ps_)` was a
            # LEXICOGRAPHIC tuple compare: L1(85,90) -> L2(90,1) passed
            # because 90>=85, even though S collapsed 90->1. Componentwise:
            # M_new < M_prev OR S_new < S_prev rejects.
            if m_ < pm_ or s_ < ps_:
                problems.append(
                    f"rung floors not monotonic: {r} {floors[r]} weaker than {prev} {floors[prev]}")
        prev = r
    beh = raw.get("behavioral", {})
    corr = beh.get("corroboration", {})
    # audit P1-34: enforce the JSON-schema minima on the corroboration family
    # counts (rate_limit >= 2, deny >= 3) the runtime previously left to the
    # schema alone, in addition to their relative ordering.
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
    # audit P1-29/P1-20: behavioral.enabled_families must name a family the
    # schema/behavioral module actually defines — the single vocab source is
    # behavioral.py, and a policy naming an unknown family is a spelling error
    # that silently requests nothing (never silently accept it as inert).
    from .behavioral import IMPLEMENTED_FAMILIES, PENDING_FAMILIES
    _KNOWN_FAMS = IMPLEMENTED_FAMILIES | PENDING_FAMILIES
    for _fam in beh.get("enabled_families") or ():
        if _fam not in _KNOWN_FAMS:
            problems.append(f"behavioral.enabled_families names unknown family {_fam!r}")
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
    # audit P1-7..11: a randomization mechanism the engine does not wire is a
    # declared-but-inert knob — it MUST fail closed rather than silently do
    # nothing. Only ttl_jitter and rate_ceiling are implemented; any other
    # key (challenge_sampling, threshold_dither, shadow_review_sampling, ...)
    # in [randomization.mechanisms] is rejected here at load.
    _rz_mech = (raw.get("randomization", {}).get("mechanisms") or {})
    for _name in _rz_mech:
        if _name not in _SUPPORTED_RANDOMIZATION_MECHANISMS:
            problems.append(
                f"unsupported randomization mechanism '{_name}': the engine "
                "implements ttl_jitter and rate_ceiling only; an unwired "
                "mechanism would be silently inert")
    # audit P1-34: randomization bounds are numbers, min < = max, and both
    # must be finite. A jitter whose min exceeds its max (or a non-numeric
    # bound) would draw outside the intended range every time — enforce at
    # load rather than shipping a policy that mis-draws silently. Bounds_w
    # version (P1-8) is a required roll-back anchor: randomization enabled
    # with NO bounds version means draws cannot be audited/reproduced across
    # policy revisions — fail closed. Rotation interval (P1-8) must be a
    # positive integer when set.
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
    if rn is not None:
        # audit P1-35: parse the ACTUAL instant. A regex-shaped-but-invalid
        # value is rejected here (would otherwise parse to None later and
        # behave as "no replay clock"). Genuine instants only.
        if _parse_policy_instant(rn) is None:
            problems.append(
                "replay.reference_now must be a VALID ISO-8601 UTC instant (...Z)")
    # v2.2 (docs/04 §8): a batch-action budget must be a positive integer
    # when present; production policies are expected to set it.
    mb = limits.get("max_new_auto_actions_per_batch")
    if mb is not None and (not isinstance(mb, int) or isinstance(mb, bool) or mb < 1):
        problems.append("limits.max_new_auto_actions_per_batch must be a positive integer when set")
    # audit P1-34: enforce the JSON-schema bounds the runtime previously left
    # to the schema alone. A positive max auto TTL (schema minimum 1) and an
    # evidence cap in [1,1024] (docs/23 envelope) are safety-bearing limits —
    # accepting a policy that violates them at load is loading a schema-invalid
    # configuration as if it were valid.
    _ttl = limits.get("max_auto_ttl_seconds")
    if _ttl is not None and (not isinstance(_ttl, int) or isinstance(_ttl, bool) or _ttl < 1):
        problems.append("limits.max_auto_ttl_seconds must be a positive integer (>=1)")
    _cap = limits.get("max_evidence_per_indicator")
    if _cap is not None and (not isinstance(_cap, int) or isinstance(_cap, bool)
                             or not (1 <= _cap <= 1024)):
        problems.append("limits.max_evidence_per_indicator must be an integer in [1,1024]")
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
            # audit P1-35: parse the ACTUAL expiry. An allowlist entry whose
            # expiry cannot parse as a genuine instant is rejected at load —
            # never allowed to silently read as "not expired" (allow forever).
            if _parse_policy_instant(exp) is None:
                problems.append(
                    f"allowlist entry #{pos} expires_at must be a VALID "
                    "ISO-8601 UTC instant (...Z)")
    # v2.3 (audit P1-2): authorization prefixes and domains are parsed and
    # canonicalized at LOAD. A malformed CIDR previously reached `_in_scope`
    # and raised during evaluation (fail-open by crash); now an invalid rule
    # makes the policy un-loadable. Domains are normalized to lowercase,
    # trailing-dot-stripped suffixes for canonical suffix matching.
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
        # a domain suffix must not itself look like a CIDR or carry scheme;
        # minimal validity: no spaces, at least one dot once normalized
        elif not _valid_domain_suffix(d):
            problems.append(
                f"authorization.authorized_domains entry #{pos} is not a valid domain suffix: {d!r}")
    # v2.3 (audit P0-3): the governed infrastructure registry. Entries are
    # the operator's explicit, per-value certification that a target is
    # dedicated-use and/or rollback-verified control-plane infra. They must
    # be non-empty strings. A `[governed]` section in an automated mode is
    # expected but not REQUIRED to be non-empty here (empty registry = the
    # conservative fail-closed default the audit asked for); ENFORCE already
    # requires authorized scope (see P1-1 below).
    for pos, v in enumerate((raw.get("governed") or {}).get("dedicated_use") or ()):
        if not isinstance(v, str) or not v.strip():
            problems.append(f"governed.dedicated_use entry #{pos} must be a non-empty string")
    for pos, v in enumerate((raw.get("governed") or {}).get("verified_rollback") or ()):
        if not isinstance(v, str) or not v.strip():
            problems.append(f"governed.verified_rollback entry #{pos} must be a non-empty string")
    # audit P1-32: never silently ignore a safety-bearing field the schema
    # accepts. Reject any present-but-unimplemented field/section at load so a
    # policy carrying it fails loudly instead of loading with that knob inert.
    for _section, _fields in _P1_32_UNIMPLEMENTED_NESTED.items():
        for _field in _fields:
            if (raw.get(_section) or {}).get(_field) is not None:
                problems.append(
                    f"unsupported policy field {_section}.{_field}: the reference "
                    "runtime does not implement it; remove it or fail closed")
    for _section in _P1_32_UNIMPLEMENTED_SECTIONS:
        if raw.get(_section):
            problems.append(
                f"unsupported policy section '{_section}': the reference runtime "
                "does not implement allow-first segment policies; remove it or "
                "fail closed")
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

    # v2.3 (audit P1-2): parse + canonicalize every authorization prefix at
    # load (a CIDR is stored in its canonical network form) and normalize
    # domain suffixes. `validate_policy` already rejected malformed entries,
    # so the ip_network calls below are guaranteed to succeed.
    _authz = raw.get("authorization") or {}
    _prefix_entries = _authz.get("authorized_prefixes") or ()
    _canonical_prefixes = tuple(
        str(ipaddress.ip_network(str(p), strict=False)) for p in _prefix_entries)
    _domain_entries = _authz.get("authorized_domains") or ()
    _canonical_domains = tuple(
        str(d).strip().lower().rstrip(".") for d in _domain_entries)
    # a declared boundary switches the policy OUT of the reference-unrestricted
    # default; a reference mode with no boundary keeps the named scaffold
    # unrestricted behavior (P1-1; ENFORCE/EMERGENCY forbid it entirely).
    _declared_boundary = bool(_canonical_prefixes or _canonical_domains)
    _reference_unrestricted = (
        False if _declared_boundary else bool(_authz.get("reference_unrestricted", False)))

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
        # v2.2: authorized target space (docs/04). v2.3 (audit P1-1/P1-2):
        # prefixes are canonicalized at LOAD (computed above); ENFORCE already
        # requires a boundary; reference_unrestricted flips off once any
        # boundary is declared.
        authorized_prefixes=_canonical_prefixes,
        authorized_domains=_canonical_domains,
        reference_unrestricted=_reference_unrestricted,
        # v2.3 (audit P0-3): governed infrastructure registry. The operator
        # declares (per value) which targets are dedicated-use and/or
        # rollback-verified control-plane infrastructure. These are the ONLY
        # way `dedicated_use` / `verified_rollback` (and their provenance)
        # become server-derived safety facts — a feed asserting them on a
        # value NOT listed here contributes zero. Default (section absent):
        # empty, so a feed can never self-grant a control-plane fact.
        governed_dedicated_use=tuple(
            str(v) for v in ((raw.get("governed") or {}).get("dedicated_use") or ())),
        governed_verified_rollback=tuple(
            str(v) for v in ((raw.get("governed") or {}).get("verified_rollback") or ())),
        # v2.3 (audit P1-20): behavioral family gate — what the operator asked
        # for. Empty default = the implemented families only (behavioral.py
        # resolves requested-but-not-implemented to honest "pending").
        enabled_behavioral_families=tuple(str(x) for x in b.get("enabled_families") or ()),
        randomization_enabled=bool(rz.get("enabled", False)),
        randomization_bounds_version=str(rz.get("bounds_version", "")),
        randomization_epoch=str(rz.get("epoch", "0")),
        # P1-8 (audit): versioned rotation interval -> derived epoch on the
        # policy clock; 0 keeps the explicit/default epoch.
        randomization_rotation_interval_seconds=int(rz.get("rotation_interval_seconds", 0) or 0),
        ttl_jitter=ttl_jitter,
        rate_ceiling_jitter=rate_ceiling_jitter,
    )
