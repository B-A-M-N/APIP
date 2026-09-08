"""Operational metrics (audit #37) — Prometheus text exposition.

The control plane already KNOWS most of what an operator needs (action
state counts, source registry, behavioral feed lag/drop, lease state,
RPZ generation); it just didn't EXPOSE it as metrics. This module renders
the live controller state as Prometheus text — no new counters to keep
honest, no second bookkeeping to drift. Counters that only exist as
in-memory feed statistics are labeled as per-process (they reset on
restart); ledger-derived gauges are cluster truth.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apip.controller.service import Controller

# Per-process monotonic counters, incremented at the boundaries that care.
# These are the events that have no ledger row to count later (rejections
# happen before anything durable; failures are times, not states).
_IN_MEMORY: dict[str, float] = {
    "apip_ingest_rejected_total": 0.0,
    "apip_source_auth_failures_total": 0.0,
    "apip_apply_failures_total": 0.0,
    "apip_verify_failures_total": 0.0,
    "apip_revoke_failures_total": 0.0,
}


def inc(metric: str, n: float = 1.0) -> None:
    """Increment an in-memory event counter. Unknown metric names are
    refused (a typo must fail loudly, not invent a series)."""
    if metric not in _IN_MEMORY:
        raise KeyError(f"unknown metric {metric!r}")
    _IN_MEMORY[metric] += n


def _san(s: object) -> str:
    """Label-value escaping per the Prometheus text format."""
    return (str(s).replace("\\", "\\\\").replace("\n", "\\n")
            .replace("\"", "\\\""))


def _fmt(v: float) -> str:
    if v == int(v):
        return str(int(v))
    return repr(float(v))


def _line(out: list[str], name: str, mtype: str, help_: str,
          samples: list[tuple[str, float]]) -> None:
    out.append(f"# HELP {name} {help_}")
    out.append(f"# TYPE {name} {mtype}")
    for labels, value in samples:
        out.append(f"{name}{labels} {_fmt(value)}")


def render(controller: "Controller") -> str:
    """Render the FULL metric surface from live controller state."""
    out: list[str] = []

    # -- ledger truth: action state gauges -----------------------------------
    try:
        counts = controller.ledger.action_counts()
    except Exception:                                  # noqa: BLE001
        counts = {}
    for state in ("pending", "dispatching", "applied", "verified",
                  "drifted", "failed", "expired", "revoked"):
        _line(out, f"apip_actions_{state}", "gauge",
              f"Actions currently in the {state} state.",
              [("", float(counts.get(state, 0)))])

    # decisions by disposition (bounded window = whole table, cheap GROUP BY)
    try:
        disp = controller.ledger.decision_disposition_counts()
    except Exception:                                  # noqa: BLE001
        disp = {}
    _line(out, "apip_decisions_total", "gauge",
          "Decisions recorded, by disposition.",
          [(f'{{disposition="{_san(d)}"}}', float(n))
           for d, n in sorted(disp.items())])

    # -- sources --------------------------------------------------------------
    try:
        sources = controller.ledger.list_sources()
    except Exception:                                  # noqa: BLE001
        sources = []
    _line(out, "apip_sources_registered", "gauge",
          "Registered ingest sources.",
          [("", float(len(sources)))])
    _line(out, "apip_sources_enabled", "gauge",
          "Enabled ingest sources.",
          [("", float(sum(1 for s in sources if s.get("enabled"))))])

    # -- leader lease ----------------------------------------------------------
    role = ("leader" if controller.state.is_leader
            else ("lease_stale" if controller.state.lease_stale
                  else "follower"))
    _line(out, "apip_leader", "gauge",
          "1 when this process holds the cluster worker lease.",
          [("", 1.0 if controller.state.is_leader else 0.0)])
    _line(out, "apip_leader_lease_age_seconds", "gauge",
          "Age of the current lease (0 when not the leader).",
          [("", 0.0 if not controller.state.is_leader else
            float(controller.state.lease_s or 0))])
    _line(out, "apip_controller_role_info", "gauge",
          "Process HA role (leader/follower/lease_stale) as a label.",
          [(f'{{role="{role}"}}', 1.0)])

    # -- behavioral feed (per-process) ----------------------------------------
    try:
        beh = controller.behavioral_status()
    except Exception:                                  # noqa: BLE001
        beh = {}
    if not isinstance(beh, dict):
        beh = {}
    for key, mname, mtype, help_ in (
            ("detections_emitted", "apip_behavioral_detections_total",
             "counter", "Behavioral detections produced by this process."),
            ("dropped_detections", "apip_behavioral_dropped_oldest_total",
             "counter", "Oldest-detections dropped by the bounded feed."),
            ("pending_unknown_targets", "apip_behavioral_pending_unknown",
             "gauge", "Unknown-target detections held in the dormancy cache."),
            ("pending_expired", "apip_behavioral_pending_expired_total",
             "counter", "Dormancy-cache entries expired unclaimed."),
            ("pending_overflow_dropped",
             "apip_behavioral_pending_overflow_dropped_total",
             "counter", "Dormancy-cache inserts dropped when full."),
    ):
        v = beh.get(key)
        if isinstance(v, (int, float)):
            _line(out, mname, mtype, help_, [("", float(v))])
    src = beh.get("source", {}) if isinstance(beh.get("source"), dict) else {}
    for key, mname, mtype, help_ in (
            ("lines_read", "apip_behavioral_source_lines_read_total",
             "counter", "Telemetry lines read from the datasource."),
            ("events_converted", "apip_behavioral_events_converted_total",
             "counter", "Telemetry events converted to detections."),
            ("malformed_lines", "apip_behavioral_malformed_lines_total",
             "counter", "Telemetry lines that failed to parse."),
            ("unsupported_events", "apip_behavioral_unsupported_events_total",
             "counter", "Telemetry events of an unsupported type (counted)."),
    ):
        v = src.get(key)
        if isinstance(v, (int, float)):
            _line(out, mname, mtype, help_, [("", float(v))])

    # -- RPZ generation --------------------------------------------------------
    for ah in (controller.adapters_status() or []):
        name = _san(ah.get("name", "adapter"))
        gen = ah.get("generation")
        if isinstance(gen, (int, float)):
            _line(out, "apip_adapter_artifact_generation", "gauge",
                  "Published artifact generation (advances on every write).",
                  [(f'{{adapter="{name}"}}', float(gen))])
        if ah.get("status") == "ok":
            _line(out, "apip_adapter_ok", "gauge",
                  "1 when the adapter's last health probe passed.",
                  [(f'{{adapter="{name}"}}', 1.0)])
        else:
            _line(out, "apip_adapter_ok", "gauge",
                  "1 when the adapter's last health probe passed.",
                  [(f'{{adapter="{name}"}}', 0.0)])

    # -- in-process event counters ----------------------------------------------
    _line(out, "apip_ingest_rejected_total", "counter",
          "Ingest requests rejected at the boundary (auth, size, parse).",
          [("", _IN_MEMORY["apip_ingest_rejected_total"])])
    _line(out, "apip_source_auth_failures_total", "counter",
          "Failed source authentications.",
          [("", _IN_MEMORY["apip_source_auth_failures_total"])])
    _line(out, "apip_apply_failures_total", "counter",
          "Action apply dispatch failures.",
          [("", _IN_MEMORY["apip_apply_failures_total"])])
    _line(out, "apip_verify_failures_total", "counter",
          "Independent verification failures (drift suspects).",
          [("", _IN_MEMORY["apip_verify_failures_total"])])
    _line(out, "apip_revoke_failures_total", "counter",
          "Action removal dispatch failures.",
          [("", _IN_MEMORY["apip_revoke_failures_total"])])

    out.append("")
    return "\n".join(out)
