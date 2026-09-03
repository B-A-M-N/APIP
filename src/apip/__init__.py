"""APIP public beta — the deployable defensive control plane.

Package layout (clean architecture; the reference oracle under ``reference/``
stays independent and runnable):

    apip.domain       canonical models, sanitize, canonicalization
    apip.decision     deterministic scoring + policy evaluation (ported from
                      the reference oracle; validated by differential tests)
    apip.config       service configuration + policy file loading
    apip.auth         source/operator credential handling
    apip.registry     ingest-source registry (DB-backed authority profiles)
    apip.ingest       channel-bound normalization + ingest application
    apip.ledger       PostgreSQL persistence: migrations + repositories
    apip.adapters     enforcement adapter contract + the RPZ adapter
    apip.controller   long-running service: dispatch, verify, expiry/revoke,
                      reconciliation, health
    apip.api          operator HTTP API
    apip.cli          operator CLI

INVARIANT (docs/28): nothing in the decision path (domain, decision,
registry authority assignment) imports or invokes any AI/ML component.
Decisions are pure functions of (normalized evidence, source authority,
policy version, clock). Machine-checked by tests/test_no_ai_conformance.py.
"""

__version__ = "0.1.0b1"
