"""Deterministic, emit-only interoperability serializers.

APIP maps canonical enforcement intents onto OpenC2 commands, CACAO 2.0
playbooks, and OCSF events so that decisions/actions export cleanly to
standards-facing consumers (controllers, response orchestrators, SIEMs,
data lakes). See ``docs/05_DATA_AND_INTERFACES.md`` and ``FULL_SPEC.md``
section 5.6.

INVARIANT: these serializers are **emit-only output formatters**. They never
parse or re-ingest external control/response messages into the security
decision path, and they are AI-free + deterministic (fixed field sets, stable
ordering, injectable clock for replay). Docs/28's "no AI on the decision
path" is preserved precisely because interop output never loops back into a
decision.
"""
from apip.interop.openc2 import decision_to_openc2  # noqa: F401
from apip.interop.cacao import decision_to_cacao  # noqa: F401
from apip.interop.ocsf import decision_to_ocsf  # noqa: F401

__all__ = [
    "decision_to_openc2",
    "decision_to_cacao",
    "decision_to_ocsf",
]