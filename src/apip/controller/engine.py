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

from apip.decision.layer import merge_policy_overlay
from apip.decision.loader import build_overlay, load_policy_text
from apip.decision.policy import NON_INTERACTIVE_PROTOCOLS, Policy, evaluate
from apip.domain.models import Evidence, Indicator
from apip.ledger.repo import Ledger
from apip.registry import SourceProfile, SourceRegistry

# audit #24: the observation-context keys an ingest payload may carry in
# evidence ``detail``. Everything else in detail is informational; these
# three — when present and well-formed — become the TRUSTED policy context
# the pipeline derives server-side and hands to the evaluator, so the L1/L2
# rung gates (client selector, interactive protocol) are reachable from
# normal product ingestion and not just from tests.
_CONTEXT_KEYS = ("client", "protocol_class")
_KNOWN_PROTOCOL_CLASSES = frozenset(
    {"interactive_http", "smtp", "dns", "ics", "ssh", "other"})


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

    def load_active_policy_effective(self, registry: SourceRegistry,
                                     *, tenant_id: str | None = None,
                                     now_fn=None) -> tuple[Policy, dict] | None:
        """Load the active policy, merging a tenant overlay (if any) onto it.

        ``tenant_id=None`` (a global-only tenant) returns the global policy
        unchanged — identical to ``load_active_policy``. With a tenant overlay
        present, the deterministic monotonic merge in layer.py applies so the
        effective policy is at least as restrictive as the global."""
        loaded = self.load_active_policy(registry, now_fn)
        if loaded is None:
            return None
        policy, policy_row = loaded
        if tenant_id is None:
            return loaded
        overlay_row = self._ledger.get_tenant_overlay(tenant_id)
        if overlay_row is None:
            return loaded
        import tomllib
        overlay = build_overlay(
            tomllib.loads(overlay_row["raw_text"]),
            overlay_row["raw_text"], source_registry=registry,
            now_fn=now_fn or now_iso_utc)
        return merge_policy_overlay(policy, overlay), policy_row

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

    @staticmethod
    def _observation_context(ev_rows: list[dict]) -> dict:
        """Derive TRUSTED policy context from durable evidence detail
        (audit #24).

        L1/L2 rung gates need a client selector and an interactive protocol
        class; ``decide_indicator`` previously called the evaluator with no
        context, so normal product ingestion could never satisfy those
        gates. The context is DERIVED here, server-side, from bounded
        evidence fields — never trusted from a header or the decision
        payload:

          - ``client``: the most frequently observed non-empty
            ``detail.client`` across the indicator's evidence (deterministic
            tie-break: lexicographically smallest). A pair/session-scoped
            rung is only ever bound to an identity an actual observation
            asserted.
          - ``protocol_class``: the most frequently observed well-formed
            ``detail.protocol_class``; anything unknown or non-interactive
            keeps L1 closed (fail closed). Ties break deterministically.
        """
        client_votes: dict[str, int] = {}
        proto_votes: dict[str, int] = {}
        for r in ev_rows:
            detail = r.get("detail") or {}
            if not isinstance(detail, dict):
                continue
            client = detail.get("client")
            if isinstance(client, str) and client.strip():
                c = client.strip()
                client_votes[c] = client_votes.get(c, 0) + 1
            proto = detail.get("protocol_class")
            if isinstance(proto, str) and proto.strip() in _KNOWN_PROTOCOL_CLASSES:
                p = proto.strip()
                proto_votes[p] = proto_votes.get(p, 0) + 1
        context: dict = {}
        if client_votes:
            context["client"] = min(
                ((-n, c) for c, n in client_votes.items()))[1]
        if proto_votes:
            # deterministic: most votes, lexicographic tie-break
            proto = min(((-n, p) for p, n in proto_votes.items()))[1]
            if proto not in NON_INTERACTIVE_PROTOCOLS:
                context["protocol_class"] = proto
        return context

    def decide_indicator(self, indicator_id: str, actor: str,
                         batch_id: str | None = None,
                         tenant_id: str | None = None) -> dict | None:
        """Re-evaluate one indicator from ledger state; append the decision.
        Returns the decision row (or None when no policy is active).

        ``tenant_id`` resolves which effective policy governs: an explicit
        value, else the indicator's own tenant assignment. A tenant with an
        overlay gets the merge(global, overlay) policy; everyone else the
        global policy exactly (unchanged behavior for prior callers)."""
        ind_row = self._ledger.get_indicator(indicator_id)
        if ind_row is None:
            return None
        registry = self.registry_from_sources(self._ledger.list_sources())
        if tenant_id is None:
            tenant_id = ind_row.get("tenant_id")
        loaded = self.load_active_policy_effective(
            registry, tenant_id=tenant_id)
        if loaded is None:
            return None
        policy, policy_row = loaded
        ev_rows = self._ledger.indicator_evidence(indicator_id)
        indicator = self.indicator_from_rows(ind_row, ev_rows)
        context = self._observation_context(ev_rows)
        decision = evaluate(indicator, policy, context=context)
        recorded = self._ledger.record_decision(
            decision, indicator_id=indicator.id,
            batch_id=batch_id or ev_rows[0]["batch_id"] if ev_rows else None,
            policy_content_sha256=policy_row["content_sha256"], actor=actor)
        return {
            "decision": decision,
            # recorded is now the decision instance's seq (None when this
            # exact instance was already recorded) — truthy/falsy semantics
            # are unchanged for callers.
            "recorded": recorded,
            "policy_row": policy_row,
            "indicator": indicator,
        }
