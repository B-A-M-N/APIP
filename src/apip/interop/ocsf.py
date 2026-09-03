"""Deterministic OCSF-compatible event emission for SIEM/data-lake export.

Maps a canonical ``Decision`` (and, where available, an adapter receipt)
onto the OCSF ``Detection Finding`` class (class_uid 2004) with the OCSF
header fields, so APIP decisions/actions export cleanly to a SIEM or
data-lake consumer. This is **emit-only**: export never feeds back into the
decision path (docs/28) and the output is a deterministic function of the
decision + injected clock.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from apip.domain.models import Decision

_OCSF_VERSION = "1.2.0"
_DETECTION_FINDING_CLASS_UID = 2004
_DETECTION_FINDING_CATEGORY_UID = 2  # findings

# activity_id per OCSF Detection Finding: 1=Create, 2=Read, 3=Update,
# 4=Delete, 6=Other. APIP decisions are created when recorded; lifecycle
# stages (approve / revoke) map to Update (3) / Delete (4).
_ACTIVITY_ID = {
    "recorded": 1,
    "approved": 3,
    "expired": 4,
    "revoked": 4,
    "other": 6,
}

def _severity(maliciousness: int, action_safety: int) -> int:
    """OCSF severity_id (0=Unknown .. 4=High .. 7=Critical), mapped from the
    decision's maliciousness score."""
    if maliciousness >= 90:
        return 7
    if maliciousness >= 75:
        return 6
    if maliciousness >= 50:
        return 5
    if maliciousness >= 25:
        return 4
    if maliciousness > 0:
        return 3
    return 1  # informational for a no-action decision


def decision_to_ocsf(
    decision: Decision,
    *,
    stage: str = "recorded",
    receipt: dict[str, Any] | None = None,
    now_fn: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Serialize a decision to an OCSF ``Detection Finding`` event.

    ``now_fn`` injects the clock for replayable timestamps (defaults to a
    fixed epoch anchor so bare calls are byte-stable). ``receipt`` (an
    adapter receipt dict) is folded into observables when provided.
    """
    now = (now_fn() if now_fn is not None
           else datetime(1970, 1, 1, tzinfo=timezone.utc))
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    # OCSF header + finding fields. Field order is stable/deterministic.
    event: dict[str, Any] = {
        "metadata": {
            "product": {"name": "APIP", "vendor_name": "B-A-M-N"},
            "version": _OCSF_VERSION,
        },
        "time": now,
        "category_uid": _DETECTION_FINDING_CATEGORY_UID,
        "class_uid": _DETECTION_FINDING_CLASS_UID,
        "activity_id": _ACTIVITY_ID.get(stage, _ACTIVITY_ID["other"]),
        "activity_name": stage,
        "severity_id": _severity(decision.maliciousness,
                                 decision.action_safety),
        "type_name": "Detection Finding: " + stage,
        "finding": {
            "title": f"APIP decision {decision.id}",
            "uid": decision.id,
            "desc": decision.explanation,
            "src_url": "https://example.invalid/apip/decision",
        },
        "count": 1,
        "metadata_tags": list(decision.reason_codes),
    }

    if decision.selector is not None:
        event["observables"] = [
            {
                "name": k,
                "value": v,
                "type_name": k,
                "type_id": 0,
            }
            for k, v in decision.selector.to_dict().items()
        ]
    else:
        event["observables"] = []

    event["unmapped"] = {
        "indicator_id": decision.indicator_id,
        "rung": decision.rung,
        "scope": decision.scope,
        "disposition": decision.disposition,
        "action": decision.action,
        "policy_version": decision.policy_version,
        "ttl_seconds": decision.ttl_seconds,
        "nominal_ttl_seconds": decision.nominal_ttl_seconds,
        "content_hash": decision.content_hash,
        "maliciousness": decision.maliciousness,
        "action_safety": decision.action_safety,
        "attribution_refs": list(decision.attribution_refs),
    }

    if receipt is not None:
        event["unmapped"]["receipt"] = receipt

    return event