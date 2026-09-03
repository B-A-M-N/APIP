"""Deterministic decision engine (production port of the reference oracle).

The decision path is stdlib-only and AI-free (docs/28): scoring, rung
selection, and policy evaluation are pure functions of

    (normalized indicator, source authority, policy version, clock)

validated against ``reference/`` by differential tests. No component in this
package may import an AI/ML SDK, make a network call, or read the wall clock
except through the clock injected into the Policy (deterministic replay).
"""
from apip.decision.policy import (  # noqa: F401
    DecisionEvaluator,
    Policy,
    evaluate,
)
from apip.decision.scoring import (  # noqa: F401
    DEFAULT_WEIGHTS,
    EvidenceTable,
)
