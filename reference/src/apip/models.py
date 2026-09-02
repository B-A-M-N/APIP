from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Any

@dataclass(frozen=True)
class Evidence:
    """A fact asserted about an indicator. Carries NO score.

    Scoring authority belongs exclusively to the policy weight table
    (docs/04 v2.1): (source_class, kind, recency) -> contribution.
    `source_class` and `independent` are assigned server-side from the
    governed source registry — never trusted from the input payload.
    """
    kind: str
    source_id: str
    source_class: str          # assigned from source registry, not input
    observed_at: str           # ISO-8601; recency computed by policy clock
    independent: bool          # assigned from source registry, not input
    detail: dict[str, Any] = field(default_factory=dict)

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
    destination-global one. NEVER interprets as "rate_limit <ip> globally".
    """
    scope_type: str            # destination_global | client_destination_pair | client_session | internal_host
    client: str | None = None
    destination: str | None = None
    protocol_class: str | None = None   # interactive_http | smtp | dns | ics | other
    host: str | None = None
    # Rate-limit ceiling (docs/25 client-impact budget, docs/29 rate_ceiling
    # mechanism): requests per minute the rule permits for the pair/session.
    # A rate_limit action without this value has no ceiling semantics and is
    # not exportable; the drawn (or nominal) ceiling is always carried.
    rate_ceiling_per_min: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

@dataclass(frozen=True)
class Decision:
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
    # A single draw record (dict, legacy shape) or a list of draw records
    # when multiple mechanisms applied to one decision (e.g. ttl_jitter +
    # rate_ceiling). None when no randomized mechanism applied.
    randomization: Any | None = field(default=None)
    attribution_refs: tuple[str, ...] = ()   # docs/30: display-only, never a decision input

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["reason_codes"] = list(self.reason_codes)
        if self.selector is not None:
            d["selector"] = self.selector.to_dict()
        return d
