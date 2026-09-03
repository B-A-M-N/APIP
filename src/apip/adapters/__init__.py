"""Enforcement adapter contract.

An adapter is the ONLY path from a decision to infrastructure. Contract
(goal E):

    compile   decision+target -> fragments (pure; rejects out-of-contract)
    validate  candidate -> syntax + scope + mode checks before any apply
    apply     publish to infrastructure (returns receipt or failure)
    verify    INDEPENDENT check that infra holds the intended state
    revoke    remove exactly the authorized selector, verify removal
    get_state current actual state for the selector
    max_mode  the adapter's configured maximum posture

Invariants:
  - NEVER accept a wider selector than the decision authorized;
  - NEVER fabricate success: no receipt without observed infrastructure
    state, and apply/verify/revoke failures propagate as AdapterError;
  - enforcement scope is re-checked here independently of the policy and
    the controller (defense in depth layer 3).
"""
from apip.adapters.base import (  # noqa: F401
    AdapterError,
    EnforcementAdapter,
)
from apip.adapters.rpz import RpzAdapter  # noqa: F401
from apip.adapters.suricata import SuricataAdapter  # noqa: F401


def build_adapters(config) -> dict[str, EnforcementAdapter]:
    """Instantiate the configured enforcement adapters, keyed by name.

    The controller dispatches a decision's fragment to the adapter it names
    (`fragment["adapter"]`), so a fragment compiled by one adapter is always
    applied/verified/revoked by that same adapter.
    """
    adapters: dict[str, EnforcementAdapter] = {
        RpzAdapter.name: RpzAdapter(config.adapter),
        SuricataAdapter.name: SuricataAdapter(config.adapter),
    }
    return adapters
