"""Ledger repository: typed operations over the durable tables.

Rules:
  - decisions are append-only: a (decision_id) may repeat with a new seq
    only when content_hash differs (action-instance identity); identical
    re-evaluations are idempotent no-ops;
  - every state-changing call takes an ``actor`` — the auditable identity;
  - action state transitions are recorded with reason + actor, and adapter
    attempts/receipts are never fabricated by this layer.
"""
from __future__ import annotations

from datetime import datetime

import psycopg2
import psycopg2.extras

from apip.domain.models import Decision, Indicator
from apip.ledger.db import Database


class Ledger:
    def __init__(self, db: Database):
        self.db = db

    # -- sources ------------------------------------------------------------

    def register_source(self, *, source_id: str, source_class: str, independent: bool,
                        key_hash: str, actor: str, auto_enforcement_allowed: bool = True,
                        upstream: str | None = None, enabled: bool = True,
                        allowed_kinds: tuple[str, ...] = (),
                        provenance_note: str = "") -> None:
        self.db.execute("""
INSERT INTO sources (source_id, source_class, independent, auto_enforcement_allowed,
                     upstream, enabled, allowed_kinds, provenance_note, key_hash, created_by)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON CONFLICT (source_id) DO UPDATE SET
    source_class = EXCLUDED.source_class,
    independent = EXCLUDED.independent,
    auto_enforcement_allowed = EXCLUDED.auto_enforcement_allowed,
    upstream = EXCLUDED.upstream,
    allowed_kinds = EXCLUDED.allowed_kinds,
    provenance_note = EXCLUDED.provenance_note,
    key_hash = EXCLUDED.key_hash,
    updated_at = now()
""", (source_id, source_class, independent, auto_enforcement_allowed,
      upstream, enabled, list(allowed_kinds), provenance_note, key_hash, actor))
        self.audit(actor, "source.register", source_id,
                   {"class": source_class, "upstream": upstream, "enabled": enabled})

    def set_source_enabled(self, source_id: str, enabled: bool, actor: str) -> bool:
        row = self.db.query_one(
            "UPDATE sources SET enabled=%s, updated_at=now() WHERE source_id=%s RETURNING source_id",
            (enabled, source_id))
        if row:
            self.audit(actor, "source.enable" if enabled else "source.disable",
                       source_id, {})
        return bool(row)

    def get_source(self, source_id: str) -> dict | None:
        # Operator-facing read: never expose key_hash (the PBKDF2 credential
        # hash) or created_by. Same safe projection list_sources uses.
        return self.db.query_one(
            "SELECT source_id, source_class, independent, auto_enforcement_allowed, "
            "upstream, enabled, allowed_kinds, provenance_note, created_at, "
            "last_success_at, health FROM sources WHERE source_id=%s", (source_id,))

    def source_by_credential(self, secret: str) -> dict | None:
        """Resolve the source that owns `secret` by verifying it against each
        stored PBKDF2 hash (channel auth). The hashes are salted with random
        salts, so lookup is an equality scan via verify_credential — never
        re-hashing the input. Returns None when nothing matches."""
        from apip.auth import verify_credential
        # Fast-fail: every source key this product generates is prefixed
        # ``apipk_``. A presented secret that lacks the prefix cannot satisfy
        # any stored hash, so skip the PBKDF2 scan (O(N x iterations) per
        # unauthenticated request) — a cheap default-deny against CPU
        # amplification on the ingest boundary.
        if not secret.startswith("apipk_"):
            return None
        rows = self.db.query(
            "SELECT source_id, source_class, independent, auto_enforcement_allowed, "
            "upstream, enabled, allowed_kinds, key_hash FROM sources")
        for row in rows:
            if row.get("key_hash") and verify_credential(secret, row["key_hash"]):
                return row
        return None

    def list_sources(self) -> list[dict]:
        return self.db.query(
            "SELECT source_id, source_class, independent, auto_enforcement_allowed, "
            "upstream, enabled, allowed_kinds, provenance_note, created_at, "
            "last_success_at, health FROM sources ORDER BY source_id")

    def touch_source_success(self, source_id: str) -> None:
        self.db.execute(
            "UPDATE sources SET last_success_at=now(), health='ok', updated_at=now() "
            "WHERE source_id=%s", (source_id,))

    # -- ingest ---------------------------------------------------------------

    def batch_exists(self, batch_id: str) -> bool:
        return self.db.query_one(
            "SELECT batch_id FROM ingest_batches WHERE batch_id=%s", (batch_id,)) is not None

    def record_batch(self, *, batch_id: str, source_id: str, raw_sha256: str,
                     indicator_count: int, demoted: int, channel: str,
                     actor: str) -> bool:
        """Idempotent by (source_id, raw_sha256): returns True if recorded,
        False if this exact batch was already ingested."""
        try:
            self.db.execute("""
INSERT INTO ingest_batches (batch_id, source_id, raw_sha256, indicator_count,
                            demoted_records, channel)
VALUES (%s,%s,%s,%s,%s,%s)
""", (batch_id, source_id, raw_sha256, indicator_count, demoted, channel))
        except psycopg2.errors.UniqueViolation:
            self.audit(actor, "ingest.duplicate_ignored", batch_id,
                       {"source_id": source_id})
            return False
        self.audit(actor, "ingest.accept", batch_id,
                   {"source_id": source_id, "indicators": indicator_count,
                    "demoted": demoted})
        return True

    def upsert_indicator(self, ind: Indicator, batch_id: str) -> None:
        with self.db.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
INSERT INTO indicators (indicator_id, itype, value, tags)
VALUES (%s,%s,%s,%s)
ON CONFLICT (indicator_id) DO UPDATE SET
    last_seen = now(), tags = EXCLUDED.tags
""", (ind.id, ind.type, ind.value, list(ind.tags)))
                # source refs are NOT FK'd to sources: a channel-certified
                # upstream id may be asserted before the operator registers
                # it; unregistered ids simply carry zero authority at
                # decision time (registry protocol).
                for sid in ind.sources:
                    cur.execute("""
INSERT INTO indicator_source_refs (indicator_id, source_id)
VALUES (%s,%s) ON CONFLICT DO NOTHING
""", (ind.id, sid))
                for ev in ind.evidence:
                    cur.execute("""
INSERT INTO evidence (indicator_id, batch_id, kind, source_id, channel_source,
                      observed_at, detail)
VALUES (%s,%s,%s,%s,%s,%s,%s)
""", (ind.id, batch_id, ev.kind, ev.source_id, ev.channel_source,
      None if not ev.observed_at else ev.observed_at,
      psycopg2.extras.Json(ev.detail)))

    # -- decisions ------------------------------------------------------------

    def record_decision(self, d: Decision, *, indicator_id: str, batch_id: str | None,
                        policy_content_sha256: str, actor: str) -> bool:
        """Append a decision; idempotent on (decision_id, content_hash).

        Atomic: the uniqueness is pinned by migration idx_decisions_dedup
        (UNIQUE on decision_id, content_hash) and enforced with a single
        ``ON CONFLICT DO NOTHING`` statement — no check-then-insert race.
        Returns False when this exact decision instance is already recorded."""
        inserted = self.db.query_one("""
INSERT INTO decisions (decision_id, indicator_id, batch_id, maliciousness,
    action_safety, disposition, action, rung, scope, ttl_seconds,
    policy_version, policy_content_sha256, reason_codes, explanation,
    selector, randomization, content_hash)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON CONFLICT (decision_id, content_hash) DO NOTHING
RETURNING seq
""", (d.id, indicator_id, batch_id, d.maliciousness, d.action_safety,
      d.disposition, d.action, d.rung, d.scope, d.ttl_seconds,
      d.policy_version, policy_content_sha256, list(d.reason_codes),
      d.explanation,
      psycopg2.extras.Json(d.selector.to_dict()) if d.selector else None,
      psycopg2.extras.Json(d.randomization) if d.randomization is not None else None,
      d.content_hash))
        if inserted is None:
            return False
        self.audit(actor, "decision.record", d.id,
                   {"disposition": d.disposition, "action": d.action,
                    "rung": d.rung, "policy": d.policy_version})
        return True

    def get_decision(self, decision_id: str) -> dict | None:
        return self.db.query_one(
            "SELECT * FROM decisions WHERE decision_id=%s ORDER BY seq DESC LIMIT 1",
            (decision_id,))

    def get_decision_evidence(self, decision_id: str) -> list[dict]:
        d = self.get_decision(decision_id)
        if not d:
            return []
        return self.db.query(
            "SELECT * FROM evidence WHERE indicator_id=%s ORDER BY evidence_id",
            (d["indicator_id"],))

    def list_decisions(self, limit: int = 50, disposition: str | None = None) -> list[dict]:
        if disposition:
            return self.db.query(
                "SELECT decision_id, created_at, indicator_id, maliciousness, "
                "action_safety, disposition, action, rung, ttl_seconds, policy_version "
                "FROM decisions WHERE disposition=%s ORDER BY seq DESC LIMIT %s",
                (disposition, limit))
        return self.db.query(
            "SELECT decision_id, created_at, indicator_id, maliciousness, "
            "action_safety, disposition, action, rung, ttl_seconds, policy_version "
            "FROM decisions ORDER BY seq DESC LIMIT %s", (limit,))

    # -- actions ------------------------------------------------------------

    def record_action(self, *, action_id: str, decision: Decision,
                      indicator_id: str, adapter: str, mode: str,
                      fragment: dict, expires_at: datetime | None,
                      requested_by: str) -> None:
        self.db.execute("""
INSERT INTO actions (action_id, decision_id, decision_seq, indicator_id, adapter,
    action_type, mode, selector, rule_id, fragment, fragment_hash, bundle_id,
    bundle_hash, requested_by, expires_at, state)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending')
""", (action_id, decision.id, 0, indicator_id, adapter, decision.action, mode,
      psycopg2.extras.Json(fragment.get("selector", {})),
      fragment["rule_id"], fragment["fragment"], fragment["fragment_hash"],
      fragment["bundle_id"], fragment["bundle_hash"], requested_by, expires_at))
        self.audit(requested_by, "action.created", action_id,
                   {"decision_id": decision.id, "adapter": adapter,
                    "mode": mode, "rule_id": fragment["rule_id"],
                    "expires_at": expires_at.isoformat() if expires_at else None})

    def get_action(self, action_id: str) -> dict | None:
        return self.db.query_one("SELECT * FROM actions WHERE action_id=%s", (action_id,))

    def list_actions(self, limit: int = 50, state: str | None = None) -> list[dict]:
        if state:
            return self.db.query(
                "SELECT action_id, decision_id, indicator_id, adapter, action_type, "
                "mode, rule_id, state, state_reason, created_at, expires_at, verified_at "
                "FROM actions WHERE state=%s ORDER BY created_at DESC LIMIT %s",
                (state, limit))
        return self.db.query(
            "SELECT action_id, decision_id, indicator_id, adapter, action_type, "
            "mode, rule_id, state, state_reason, created_at, expires_at, verified_at "
            "FROM actions ORDER BY created_at DESC LIMIT %s", (limit,))

    def set_action_state(self, action_id: str, state: str, reason: str,
                         actor: str, *, verified_at: datetime | None = None) -> bool:
        row = self.db.query_one("""
UPDATE actions SET state=%s, state_reason=%s, last_reconciled_at=now(),
    verified_at = COALESCE(%s, verified_at)
WHERE action_id=%s RETURNING action_id
""", (state, reason, verified_at, action_id))
        if row:
            self.audit(actor, f"action.{state}", action_id, {"reason": reason})
        return bool(row)

    def actions_due_for_expiry(self, now: datetime) -> list[dict]:
        # Full row (SELECT *): the controlled revoke path reads fragment/selector/
        # bundle_ids from the action to build the exact removal candidate. A
        # narrow column list would KeyError in the controller revoke path.
        return self.db.query("""
SELECT * FROM actions
WHERE state IN ('applied','verified','drifted') AND expires_at IS NOT NULL
  AND expires_at <= %s
""", (now,))

    def actions_needing_dispatch(self, limit: int = 100) -> list[dict]:
        return self.db.query("""
SELECT * FROM actions WHERE state='pending' ORDER BY created_at LIMIT %s
""", (limit,))

    def actions_needing_verification(self, older_than: datetime, limit: int = 100) -> list[dict]:
        return self.db.query("""
SELECT * FROM actions WHERE state IN ('applied','verified')
  AND (verified_at IS NULL OR verified_at <= %s)
ORDER BY created_at LIMIT %s
""", (older_than, limit))

    def active_action_count(self) -> int:
        row = self.db.query_one(
            "SELECT count(*) AS n FROM actions WHERE state IN ('pending','applied','verified','drifted')")
        return int(row["n"]) if row else 0

    # -- attempts / receipts -------------------------------------------------

    def record_attempt(self, *, action_id: str, phase: str, ok: bool,
                       detail: dict, actor: str) -> None:
        self.db.execute("""
INSERT INTO adapter_attempts (action_id, phase, ok, detail, actor)
VALUES (%s,%s,%s,%s,%s)
""", (action_id, phase, ok, psycopg2.extras.Json(detail), actor))

    def record_receipt(self, *, receipt_id: str, action_id: str, adapter: str,
                       rule_id: str, fragment_hash: str, bundle_id: str,
                       bundle_hash: str, observed: dict, status: str,
                       verified: bool) -> None:
        self.db.execute("""
INSERT INTO adapter_receipts (receipt_id, action_id, adapter, rule_id,
    fragment_hash, bundle_id, bundle_hash, observed, status, verified)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON CONFLICT (receipt_id) DO UPDATE SET
    observed = EXCLUDED.observed, status = EXCLUDED.status,
    verified = EXCLUDED.verified
""", (receipt_id, action_id, adapter, rule_id, fragment_hash, bundle_id,
      bundle_hash, psycopg2.extras.Json(observed), status, verified))

    def list_receipts(self, action_id: str) -> list[dict]:
        return self.db.query(
            "SELECT * FROM adapter_receipts WHERE action_id=%s ORDER BY created_at",
            (action_id,))

    # -- policy lifecycle ------------------------------------------------------

    def next_policy_revision(self, policy_version: str) -> int:
        row = self.db.query_one(
            "SELECT COALESCE(MAX(revision), 0) AS m FROM policy_versions "
            "WHERE policy_version=%s", (policy_version,))
        return (0 if row is None else row["m"]) + 1

    def stage_policy(self, *, policy_version: str, revision: int, content_sha256: str,
                     raw_text: str, mode: str, staged_by: str,
                     problems: list[str] | None = None) -> None:
        self.db.execute("""
INSERT INTO policy_versions (policy_version, revision, content_sha256, raw_text,
    mode, status, staged_by, problems)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
""", (policy_version, revision, content_sha256, raw_text, mode,
      "rejected" if problems else "staged", staged_by,
      psycopg2.extras.Json(problems) if problems is not None else None))
        self.audit(staged_by, "policy.staged", policy_version,
                   {"revision": revision, "mode": mode,
                    "rejected": bool(problems)})

    def promote_policy(self, policy_version: str, revision: int, actor: str) -> None:
        with self.db.connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT status FROM policy_versions WHERE policy_version=%s AND revision=%s FOR UPDATE",
                    (policy_version, revision))
                row = cur.fetchone()  # RealDictCursor -> dict
                if row is None:
                    raise ValueError(f"policy {policy_version} r{revision} not staged")
                if row["status"] != "staged":
                    raise ValueError(
                        f"policy {policy_version} r{revision} is {row['status']!r}, not staged")
                cur.execute(
                    "UPDATE policy_versions SET status='retired' WHERE policy_version=%s AND status='active'",
                    (policy_version,))
                cur.execute(
                    "UPDATE policy_versions SET status='active', promoted_by=%s, promoted_at=now() "
                    "WHERE policy_version=%s AND revision=%s",
                    (actor, policy_version, revision))
                cur.execute("""
INSERT INTO policy_current (singleton, policy_version, revision)
VALUES (TRUE, %s, %s)
ON CONFLICT (singleton) DO UPDATE SET
    policy_version = EXCLUDED.policy_version, revision = EXCLUDED.revision
""", (policy_version, revision))
        self.audit(actor, "policy.promoted", policy_version, {"revision": revision})

    def current_policy_row(self) -> dict | None:
        cur = self.db.query_one("""
SELECT v.* FROM policy_current c
JOIN policy_versions v ON v.policy_version = c.policy_version AND v.revision = c.revision
WHERE c.singleton
""")
        if cur and cur.get("status") != "active":
            return None
        return cur

    def policy_history(self) -> list[dict]:
        return self.db.query("""
SELECT policy_version, revision, content_sha256, mode, status, staged_by,
       staged_at, promoted_by, promoted_at
FROM policy_versions ORDER BY staged_at DESC, revision DESC""")

    # -- audit -----------------------------------------------------------------

    def audit(self, actor: str, event_type: str, subject: str = "",
              detail: dict | None = None) -> None:
        self.db.execute(
            "INSERT INTO audit_events (actor, event_type, subject, detail) VALUES (%s,%s,%s,%s)",
            (actor, event_type, subject, psycopg2.extras.Json(detail or {})))

    def list_audit(self, limit: int = 100) -> list[dict]:
        return self.db.query(
            "SELECT event_id, at, actor, event_type, subject, detail "
            "FROM audit_events ORDER BY event_id DESC LIMIT %s", (limit,))

    # -- indicators --------------------------------------------------------------

    def list_indicators(self, limit: int = 50) -> list[dict]:
        return self.db.query(
            "SELECT indicator_id, itype, value, first_seen, last_seen, tags "
            "FROM indicators ORDER BY last_seen DESC LIMIT %s", (limit,))

    def get_indicator(self, indicator_id: str) -> dict | None:
        return self.db.query_one(
            "SELECT * FROM indicators WHERE indicator_id=%s", (indicator_id,))

    def indicator_evidence(self, indicator_id: str) -> list[dict]:
        return self.db.query(
            "SELECT evidence_id, kind, source_id, channel_source, observed_at, "
            "detail, recorded_at, batch_id FROM evidence WHERE indicator_id=%s "
            "ORDER BY evidence_id", (indicator_id,))

    # -- health -------------------------------------------------------------------

    def action_counts(self) -> dict:
        rows = self.db.query(
            "SELECT state, count(*) AS n FROM actions GROUP BY state")
        return {r["state"]: int(r["n"]) for r in rows}
