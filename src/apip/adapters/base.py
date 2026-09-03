"""Adapter protocol."""
from __future__ import annotations

from typing import Any, Protocol


class AdapterError(RuntimeError):
    """An adapter operation failed. Never silently converted to success."""


class EnforcementAdapter(Protocol):
    name: str

    def max_mode(self) -> str:
        """The configured maximum posture: OFF | OBSERVE | SHADOW | ENFORCE."""
        ...

    def compile(self, decision: Any, indicator_value: str, indicator_type: str) -> list[dict]:
        """Decision -> fragment dicts (rule_id/fragment/hashes/bundle).

        Pure function. Returns [] when this adapter does not implement the
        decision's action/type — a decision that compiles to nothing creates
        no action and gets no receipt."""
        ...

    def validate(self, candidate: dict) -> dict:
        """Validate a candidate before apply; raises AdapterError."""
        ...

    def apply(self, candidate: dict) -> dict:
        """Publish to infrastructure. Returns {ok, receipt?} or raises."""
        ...

    def verify(self, candidate: dict) -> dict:
        """Independent check of actual infrastructure state."""
        ...

    def revoke(self, candidate: dict) -> dict:
        """Remove exactly this selector; verify removal."""
        ...

    def get_state(self, selector: dict) -> dict:
        """Current actual state for a selector."""
        ...

    def health(self) -> dict:
        """Adapter health: status + configuration summary."""
        ...
