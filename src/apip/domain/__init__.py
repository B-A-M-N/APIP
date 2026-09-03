"""Canonical APIP domain objects (production port of the reference models).

These dataclasses are the shared contract between ingest, decision, ledger,
controller, and adapters. They mirror ``reference/src/apip/models.py`` field
for field where the reference semantics are normative (the differential test
suite relies on this), plus the production-only fields a durable product
needs (identity, provenance, channel binding).

Evidence carries NO score and NO authority: ``source_class`` and
``independent`` are assigned server-side from the ingest-source registry,
never trusted from a payload (reference v2.2/v2.3 lesson, docs/04).
"""
from apip.domain.models import (  # noqa: F401
    ActionSelector,
    CompiledFragment,
    Decision,
    Evidence,
    Indicator,
)
from apip.domain.sanitize import (  # noqa: F401
    UnsafeIdentifier,
    validate_client,
    validate_fqdn,
    validate_id,
    validate_ip_literal,
    validate_label,
)
