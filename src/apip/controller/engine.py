"""Decision pipeline: ledger facts -> normalized indicator -> decision.

The pipeline rebuilds the decision input from DURABLE state (indicators +
evidence rows in the ledger), applies the active policy version, and
persists the resulting decision. It never re-reads a policy file at
decision time: the active policy is the staged, promoted row content —
a file changing on disk cannot silently re-semantics an existing decision
(goal H invariant).
"""
from __future__ import annotations

from datetime import datetime, timezone

from apip.decision.loader import load_policy_text
from apip.decision.policy import Policy, evaluate
from apip.domain.models import Evidence, Indicator
from apip.ledger.repo import Ledger
from apip.registry import SourceProfile, SourceRegistry


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DecisionPipeline:
    def __init__(self, ledger: Ledger):
        self._ledger = ledger

    def registry_from_sources(self, rows: list[dict]) -> SourceRegistry:
        profiles = tuple(
            SourceProfile(
                source_id=r["source_id"],
                source_class=r["source_class"],
                independent=bool(r["independent"]),
                auto_enforcement_allowed=bool(r["auto_enforcement_allowed"]),
                upstream=r["upstream"],
                enabled=bool(r["enabled"]),
                allowed_kinds=tuple(r.get("allowed_kinds") or ()),
            )
            for r in rows)
        return SourceRegistry(profiles)

    def load_active_policy(self, registry: SourceRegistry,
                           now_fn=None) -> tuple[Policy, dict] | None:
        row = self._ledger.current_policy_row()
        if row is None:
            return None
        policy = load_policy_text(
            row["raw_text"], source_registry=registry,
            now_fn=now_fn or now_iso_utc)
        return policy, dict(row)

    def indicator_from_rows(self, ind_row: dict, ev_rows: list[dict]) -> Indicator:
        def _utc_iso(value) -> str:
            """Emit true UTC ISO-8601. psycopg2 returns tz-aware datetimes in
            the server's local offset; strftime('%Y-%m-%dT%H:%M:%SZ') would
            force-append a 'Z' while dropping the offset, mislabelling non-UTC
            wall-clock as UTC and silently ageing fresh evidence to 'stale'."""
            if isinstance(value, datetime):
                if value.tzinfo is None:
                    value = value.replace(tzinfo=timezone.utc)
                return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            return value or ""

        evidence = tuple(
            Evidence(
                kind=r["kind"], source_id=r["source_id"], source_class="unassigned",
                observed_at=_utc_iso(r.get("observed_at")),
                independent=False,
                detail=r.get("detail") or {},
                channel_source=r.get("channel_source") or "",
            )
            for r in ev_rows)
        return Indicator(
            id=ind_row["indicator_id"], type=ind_row["itype"],
            value=ind_row["value"],
            sources=tuple(sorted({r["source_id"] for r in ev_rows
                                  if r["source_id"] != "unregistered"})),
            evidence=evidence,
            tags=tuple(ind_row.get("tags") or ()),
        )

    def decide_indicator(self, indicator_id: str, actor: str,
                         batch_id: str | None = None) -> dict | None:
        """Re-evaluate one indicator from ledger state; append the decision.
        Returns the decision row (or None when no policy is active)."""
        ind_row = self._ledger.get_indicator(indicator_id)
        if ind_row is None:
            return None
        registry = self.registry_from_sources(self._ledger.list_sources())
        loaded = self.load_active_policy(registry)
        if loaded is None:
            return None
        policy, policy_row = loaded
        ev_rows = self._ledger.indicator_evidence(indicator_id)
        indicator = self.indicator_from_rows(ind_row, ev_rows)
        decision = evaluate(indicator, policy)
        recorded = self._ledger.record_decision(
            decision, indicator_id=indicator.id,
            batch_id=batch_id or ev_rows[0]["batch_id"] if ev_rows else None,
            policy_content_sha256=policy_row["content_sha256"], actor=actor)
        return {
            "decision": decision,
            "recorded": recorded,
            "policy_row": policy_row,
            "indicator": indicator,
        }
