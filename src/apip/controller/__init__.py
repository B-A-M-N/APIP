"""APIP controller service.

Explicit lifecycle: configure -> connect storage -> migrate -> load policy ->
start workers (dispatch, verify, expiry reconciliation) -> serve API ->
drain -> stop. No security state lives only in this process: every decision,
action, attempt, receipt, and transition is in the ledger, and a restart
reconciles from it.

Failure posture (docs/20): when any subsystem degrades the controller
FAILS TOWARD NO NEW ENFORCEMENT — pending actions stay pending (nothing is
half-applied silently), degraded status is surfaced, and state is retained
for reconciliation.
"""
from apip.controller.service import (  # noqa: F401
    Controller,
    ControllerState,
)
from apip.controller.engine import DecisionPipeline  # noqa: F401
