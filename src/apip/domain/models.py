"""Canonical domain models.

Ported from ``reference/src/apip/models.py`` — the reference implementation is
the behavioral oracle and these shapes must stay semantically identical
(differential tests pin decision output to it). Production additions are
marked PROD:.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(frozen=True)
class Evidence:
    """A fact asserted about an indicator. Carries NO score.

    Scoring authority belongs exclusively to the policy weight table.
    ``source_class`` and ``independent`` are assigned server-side from the
    governed source registry — never trusted from the input payload.

    PROD additions over the reference shape:
      - ``detail`` stays (reference parity) but production ingest bounds it;
      - ``channel_source`` records the authenticated source that submitted
        the record (audit trail), distinct from the asserted provenance id.
    """
    kind: str
    source_id: str
    source_class: str          # assigned from source registry, not input
    observed_at: str           # ISO-8601; recency computed by policy clock
    independent: bool          # assigned from source registry, not input
    detail: dict[str, Any] = field(default_factory=dict)
    channel_source: str = ""   # PROD: authenticated ingest channel id


@dataclass(frozen=True)
class Indicator:
    id: str
    type: str
    value: str
    sources: tuple[str, ...]
    evidence: tuple[Evidence, ...]
    tags: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ActionSelector:
    """Typed enforcement selector (docs/25 v2.1).

    A context-acting action (L1/L2) MUST carry the client/protocol context
    it acts on; adapters must refuse to broaden a pair-scoped selector to a
    destination-global one.
    """
    scope_type: str            # destination_global | client_destination_pair | client_session | internal_host
    client: str | None = None
    destination: str | None = None
    protocol_class: str | None = None   # interactive_http | smtp | dns | ics | other
    host: str | None = None
    rate_ceiling_per_min: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


def _demotion_content_hash(d: "Decision") -> str:
    """Deterministic content hash over the DEMOTED fields — byte-for-byte
    the same construction as the engine's
    ``_content_hash("OBSERVE", "observe", "L0", 0, None, None, version)``
    (repr serialization, unit-separator join) so a demoted record is
    self-consistent without importing the engine (models stay
    dependency-free)."""
    payload = "\x1f".join(repr(p) for p in (
        "OBSERVE", "observe", "L0", 0, None, None, d.policy_version))
    return "hash--" + hashlib.sha256(payload.encode()).hexdigest()[:24]


@dataclass(frozen=True)
class Decision:
    """A deterministic decision record. Immutable once persisted (append-only
    ledger semantics; corrections are new decisions, never rewrites)."""
    id: str
    indicator_id: str
    maliciousness: int
    action_safety: int
    disposition: str
    action: str
    rung: str
    scope: str
    ttl_seconds: int
    policy_version: str
    reason_codes: tuple[str, ...]
    explanation: str
    selector: ActionSelector | None = None
    nominal_ttl_seconds: int = 0
    # A single draw record (dict) or a list of draw records when multiple
    # mechanisms applied. None when no randomized mechanism applied.
    randomization: Any | None = field(default=None)
    attribution_refs: tuple[str, ...] = ()   # docs/30: display-only, never a decision input
    # P1-10: action-instance content hash over the FULL parameterized output.
    content_hash: str = ""

    def with_budget_demotion(self) -> "Decision":
        """Demote this decision to OBSERVE under a blast-radius budget
        (docs/04 §8): the action class is dropped, rung downgraded to L0,
        TTL zeroed, and the demotion recorded with a named reason
        (blast_radius_budget_exceeded). Deterministic: same decision in,
        same demoted decision out; content_hash recomputed over the DEMOTED
        fields so an observer never conflates this observe instance with
        the enforcement one that was dropped."""
        demoted_hash = _demotion_content_hash(self)
        return Decision(
            id=self.id + "-demoted",
            indicator_id=self.indicator_id,
            maliciousness=self.maliciousness,
            action_safety=self.action_safety,
            disposition="OBSERVE",
            action="observe",
            rung="L0",
            scope=self.scope,
            ttl_seconds=0,
            policy_version=self.policy_version,
            reason_codes=tuple(sorted(set(self.reason_codes)
                                      | {"blast_radius_budget_exceeded"})),
            explanation=self.explanation,
            selector=None,
            nominal_ttl_seconds=self.nominal_ttl_seconds,
            content_hash=demoted_hash,
        )

    def to_dict(self) -> dict[str, Any]:
        d = {
            "id": self.id,
            "indicator_id": self.indicator_id,
            "maliciousness": self.maliciousness,
            "action_safety": self.action_safety,
            "disposition": self.disposition,
            "action": self.action,
            "rung": self.rung,
            "scope": self.scope,
            "ttl_seconds": self.ttl_seconds,
            "policy_version": self.policy_version,
            "reason_codes": list(self.reason_codes),
            "explanation": self.explanation,
            "content_hash": self.content_hash,
            "nominal_ttl_seconds": self.nominal_ttl_seconds,
            "attribution_refs": list(self.attribution_refs),
            "selector": self.selector.to_dict() if self.selector else None,
            "randomization": self.randomization,
        }
        return d


@dataclass(frozen=True)
class CompiledFragment:
    """One compiled adapter fragment for a decision (reference
    CompiledArtifact, narrowed to what the production pipeline persists).

    Receipts are generated from these — never by inspecting
    ``Decision.action``. A decision that renders no fragment compiles to
    nothing and gets no action.
    """
    decision_id: str
    adapter: str
    rule_id: str
    fragment: str
    fragment_hash: str
    bundle_id: str
    bundle_hash: str
    selector_snapshot: dict[str, Any] = field(default_factory=dict)
