"""Deterministic CACAO 2.0 playbook emission for APIP response workflows.

Represents the operator-reviewed APIP response round-trip —
observe -> validate -> approve -> enforce -> verify -> expire/revoke
(docs/05, FULL_SPEC section 5.7) — as a CACAO 2.0 playbook. This is
**emit-only**: the playbook is a pure, deterministic function of a decision
and the configured workflow; it is never executed by APIP and never feeds
back into the decision path (docs/28).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from apip.domain.models import Decision

# CACAO 2.0 playbook step types the round-trip maps onto.
_OBSERVE_STEP_ID = "step--observe"
_VALIDATE_STEP_ID = "step--validate"
_APPROVE_STEP_ID = "step--approve"
_ENFORCE_STEP_ID = "step--enforce"
_VERIFY_STEP_ID = "step--verify"
_REVOKE_STEP_ID = "step--revoke"

_STEP_ORDER = (
    _OBSERVE_STEP_ID,
    _VALIDATE_STEP_ID,
    _APPROVE_STEP_ID,
    _ENFORCE_STEP_ID,
    _VERIFY_STEP_ID,
    _REVOKE_STEP_ID,
)


def _sha_id(seed: str) -> str:
    import hashlib
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def decision_to_cacao(
    decision: Decision,
    *,
    workflow_name: str = "apip-response-workflow",
    now_fn: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Emit a CACAO 2.0 ``playbook`` for a decision's lifecycle (emit-only).

    ``now_fn`` injects the clock for replayable timestamps; the default is a
    fixed epoch anchor, so bare calls are byte-stable. Unpromotable/`none`
    decisions still emit a playbook whose steps reflect observation only.
    """
    now = (now_fn() if now_fn is not None
           else datetime(1970, 1, 1, tzinfo=timezone.utc))
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    pid = f"playbook--{_sha_id(decision.id)}"
    end = None
    if decision.ttl_seconds > 0:
        end = now + timedelta(seconds=decision.ttl_seconds)

    actionable = decision.action not in {"none", "observe"}
    enforce_step = {
        "type": "action",
        "name": "enforce",
        "description": ("Publish the exact selector to the authorized "
                        "adapter (never broadens)."),
        "commands": [
            {
                "type": "openc2",
                "command": {
                    "action": "deny" if actionable else "query",
                    "target": decision.selector.destination
                    if decision.selector else decision.indicator_id,
                },
            }
        ],
    } if actionable else {
        "type": "action",
        "name": "observe",
        "description": "No enforceable action; record the observation only.",
        "commands": [],
    }

    steps = {
        _OBSERVE_STEP_ID: {
            "type": "action",
            "name": "observe",
            "description": "Ingest + record evidence for the decision.",
            "commands": [],
        },
        _VALIDATE_STEP_ID: {
            "type": "action",
            "name": "validate",
            "description": "Re-check authorization scope and selector "
                           "bounds (three defense-in-depth layers).",
            "commands": [],
        },
        _APPROVE_STEP_ID: {
            "type": "action",
            "name": "approve",
            "description": "Operator approval of the proposed action where "
                           "the disposition requires it.",
            "commands": [],
        },
        _ENFORCE_STEP_ID: enforce_step,
        _VERIFY_STEP_ID: {
            "type": "action",
            "name": "verify",
            "description": "Independently confirm the actuator loaded the "
                           "intended state (no fabricated success).",
            "commands": [],
        },
        _REVOKE_STEP_ID: {
            "type": "action",
            "name": "expire-or-revoke",
            "description": "Remove exactly this selector through the "
                           "controlled path at TTL expiry or operator "
                           "revoke.",
            "commands": [],
        },
    }

    playbook = {
        "type": "playbook",
        "id": pid,
        "name": workflow_name,
        "description": (f"APIP response lifecycle for decision "
                        f"{decision.id} ({decision.action})."),
        "playbook_types": ["investigation"],
        "created": now,
        "valid_from": now,
        "valid_until": end,
        "metaschema_version": "cacao-2.0",
        "playbook_variables": {
            "decision_id": {
                "type": "string",
                "value": decision.id,
            },
            "indicator_id": {
                "type": "string",
                "value": decision.indicator_id,
            },
            "content_hash": {
                "type": "string",
                "value": decision.content_hash,
            },
        },
        "workflow": {
            "workflow_id": f"workflow--{_sha_id(decision.id)}",
            "workflow_start": _OBSERVE_STEP_ID,
            "workflow_start_step_type": "start",
        },
        "steps": steps,
    }
    # Enforce a stable, documented step ordering (determinism): the steps
    # object above is already built in that order, but CACAO steps are a
    # map — keep ``on_completion`` edges so a consumer can follow the chain.
    _add_linear_edges(playbook["steps"], _STEP_ORDER)
    return playbook


def _add_linear_edges(steps: dict[str, Any], order: tuple[str, ...]) -> None:
    """Wire each step's ``on_completion`` to the next step (deterministic)."""
    for i, step_id in enumerate(order):
        if step_id not in steps:
            continue
        next_id = order[i + 1] if i + 1 < len(order) else None
        if next_id:
            steps[step_id]["on_completion"] = [
                {"id": next_id, "type": "next-step"}
            ]
        else:
            steps[step_id].setdefault("on_completion", [])