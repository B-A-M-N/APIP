"""Deterministic OpenC2 command emission for APIP enforcement intents.

Maps a canonical ``Decision`` (docs/25 v2.1, FULL_SPEC section 5.6) to an
OpenC2 ``x-open-command``-style command: action / target / actuator /
modifiers as the enforcement-intent abstraction. This is **emit-only**: the
payload is a pure function of the decision and never feeds back into the
decision path (docs/28 — interop lives off the security decision path and is
AI-free). Field sets are fixed and emitted in a stable order, so the output
is byte-reproducible for a given decision.

This does not claim full OpenC2 profile compliance; it maps APIP's
action/target/actuator/modifier vocabulary onto OpenC2 concepts (docs/05).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from apip.domain.models import Decision

# OpenC2 action (nouns from the OpenC2 Language Specification 1.0) chosen
# deterministically from an APIP action. Unknown/unmappable actions map to
# ``query`` (observational, never a state change) rather than guessing.
_ACTION_MAP: dict[str, str] = {
    "none": "query",
    "observe": "query",
    "challenge": "contain",
    "proxy_challenge": "contain",
    "host_quarantine": "contain",
    "rate_limit": "deny",
    "egress_allowlist_deny": "deny",
    "dns_nxdomain": "deny",
    "dns_nodata": "deny",
    "firewall_deny": "deny",
    "proxy_deny": "deny",
    "routing_filter": "deny",
    "virtual_patch": "update",
}

# OpenC2 actuator profile chosen from the enforcement actuator APIP would
# drive for a decision's action.
_ACTUATOR_MAP: dict[str, str] = {
    "none": "openc2:actuator:unknown:1.0",
    "observe": "openc2:actuator:unknown:1.0",
    "challenge": "openc2:actuator:proxy-waf:1.0",
    "proxy_challenge": "openc2:actuator:proxy-waf:1.0",
    "host_quarantine": "openc2:actuator:nac:1.0",
    "rate_limit": "openc2:actuator:ips:1.0",
    "egress_allowlist_deny": "openc2:actuator:firewall:1.0",
    "dns_nxdomain": "openc2:actuator:dns-rpz:1.0",
    "dns_nodata": "openc2:actuator:dns-rpz:1.0",
    "firewall_deny": "openc2:actuator:firewall:1.0",
    "proxy_deny": "openc2:actuator:proxy-waf:1.0",
    "routing_filter": "openc2:actuator:routing:1.0",
    "virtual_patch": "openc2:actuator:ips:1.0",
}


def _resolve_target(decision: Decision) -> dict[str, Any]:
    """Pick the OpenC2 target object from the decision selector/action.

    destination_global -> domain / ipv4 / ipv6; host-quarantine (L6) ->
    device; client-scoped -> a device/process pair is left as-is on the
    destination to avoid inventing a client identity. ``None`` target when
    the action carries no selectable object (e.g. pure ``query``).
    """
    if decision.action in {"none", "observe"}:
        return {}
    sel = decision.selector
    if decision.action == "host_quarantine":
        host = getattr(sel, "host", None) or getattr(sel, "destination", None)
        if host:
            return {"device": {"hostname": host}}
        return {}
    if sel is None or sel.scope_type == "internal_host":
        host = (getattr(sel, "host", None)
                if sel is not None else None) or decision.id
        return {"device": {"hostname": host}}
    dest = getattr(sel, "destination", "") or ""
    if not dest:
        return {}
    if "." in dest and ":" not in dest and "/" not in dest:
        return {"domain_name": {"value": dest.rstrip(".")}}
    if "/" in dest or ":" in dest:
        return {"ipv4_connection": {"src_addr": "0.0.0.0/0",
                                    "dst_addr": dest}}
    return {"ipv4_addr": {"value": dest}}


def _modifiers(decision: Decision, now: datetime) -> dict[str, Any]:
    """OpenC2 command modifiers: TTL window + APIP response context.

    Standard OpenC2 modifiers carry the enforcement window; APIP-specific
    response context (disposition, reason, scope) is namespaced under
    ``x_apip`` so it never collides with OpenC2 vocabulary.
    """
    m: dict[str, Any] = {
        "response_requested": "none",
    }
    if decision.ttl_seconds > 0:
        m["start_time"] = now
        m["stop_time"] = now + timedelta(seconds=decision.ttl_seconds)
    m["x_apip"] = {
        "command_id": decision.content_hash or decision.id,
        "disposition": decision.disposition,
        "scope": decision.scope,
        "reason": list(decision.reason_codes),
    }
    return m


def decision_to_openc2(
    decision: Decision,
    *,
    now_fn: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Serialize a decision to an OpenC2-style command (emit-only).

    ``now_fn`` injects the clock so output is replayable/deterministic;
    defaults to the fixed epoch anchor (no wall clock) to make bare calls
    byte-stable. A call that must carry real timestamps passes its own
    deterministic clock.
    """
    now = (now_fn() if now_fn is not None
           else datetime(1970, 1, 1, tzinfo=timezone.utc))
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    target = _resolve_target(decision)
    return {
        "command_type": "open-command",
        "command_id": decision.content_hash or decision.id,
        "action": _ACTION_MAP.get(decision.action, "query"),
        "target": target,
        "actuator": {"specifiers": {}, "type": _ACTUATOR_MAP[decision.action]},
        "modifiers": _modifiers(decision, now),
        "metadata": {
            "source": decision.policy_version,
            "rung": decision.rung,
            "indicator_id": decision.indicator_id,
            "action": decision.action,
            "disposition": decision.disposition,
            "ttl_seconds": decision.ttl_seconds,
        },
    }