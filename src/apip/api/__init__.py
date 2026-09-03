"""Operator API surface (beta).

The CLI talks to the controller through THIS API rather than poking the
service internals, so there is one front door for operator actions. The API
exposes:

  - health / readiness (component-level, never a generic healthy=true);
  - operator read surfaces (sources, indicators, decisions, actions, policy,
    receipts, audit);
  - operator state-changing actions (stage/promote policy, enable/disable
    source, ingest file, create/revoke action) — all routed through the
    controller so authorization/scope/idempotency invariants hold.

Auth: requests carry an Operator token (APIP_OPERATOR_TOKEN). Incoming
ingest carries a SOURCE key — the API NEVER trusts a payload-declared
source_id; source identity is derived from the authenticated channel
(reference P0-2). See apip.ingest.

Security note: every mutation is appended to the audit ledger with the
requesting actor identity.
"""
from apip.api.app import build_app  # noqa: F401