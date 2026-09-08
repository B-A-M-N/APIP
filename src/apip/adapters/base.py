"""Adapter protocol."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class AdapterError(RuntimeError):
    """An adapter operation failed. Never silently converted to success."""


MODE_RANK = {"OFF": 0, "OBSERVE": 1, "SHADOW": 2, "ENFORCE": 3}


def validate_adapter_config(config: "object") -> list[str]:
    """Artifact-boundary validation (review P1 #37): refuse adapter configs
    that could turn configuration into code injection or path traversal.
    Returns a list of problems (empty = valid)."""
    import re
    problems: list[str] = []
    zone_dir = getattr(config, "zone_dir", "")
    rules_dir = getattr(config, "suricata_rules_dir", "")
    for label, d in (("zone_dir", zone_dir), ("suricata_rules_dir", rules_dir)):
        if ".." in Path(d).parts:
            problems.append(f"adapter.{label} contains path traversal: {d!r}")
    zone_name = str(getattr(config, "zone_name", ""))
    # a safe canonical DNS name: letters/digits/hyphen labels, no dots-only
    # tricks, overall <= 253 chars
    if zone_name:
        if len(zone_name) > 253:
            problems.append("adapter.zone_name exceeds 253 characters")
        if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                            r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
                            r"\.?", zone_name):
            problems.append(f"adapter.zone_name is not a safe DNS name: "
                            f"{zone_name!r}")
    rules_file = str(getattr(config, "suricata_rules_file", ""))
    # basename only — never a path
    if rules_file and (Path(rules_file).name != rules_file or ".." in rules_file):
        problems.append(f"adapter.suricata_rules_file must be a bare "
                        f"filename: {rules_file!r}")
    port = getattr(config, "verify_query_port", 53)
    if not (1 <= int(port) <= 65535):
        problems.append(f"adapter.verify_query_port out of range: {port}")
    timeout = getattr(config, "verify_timeout_s", 3.0)
    if float(timeout) <= 0:
        problems.append(f"adapter.verify_timeout_s must be positive: {timeout}")
    return problems


def effective_mode(action_mode: str | None, adapter_max: str) -> str:
    """The posture an adapter may actually operate at for one action:
    ``min(persisted action mode, adapter maximum posture)``.

    The PERSISTED action mode is the authority (review P0 #1): a stored
    SHADOW action must never become live because APIP was restarted with an
    adapter configured ENFORCE — configuration can only ever weaken an
    action, never strengthen it. A missing/unreadable action mode fails
    closed to OFF (no publish, no reload).
    """
    rank = MODE_RANK.get((action_mode or "").upper(), MODE_RANK["OFF"])
    cap = MODE_RANK.get(adapter_max.upper(), MODE_RANK["OFF"])
    eff = min(rank, cap)
    for name, r in MODE_RANK.items():
        if r == eff:
            return name
    return "OFF"


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

    def probe_startup(self) -> None:
        """Startup capability probe (audit P1 #13): physically exercise the
        posture's prerequisites before the controller accepts work. Raises
        AdapterError to refuse startup; a no-op default is fine."""
        ...
