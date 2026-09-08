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

import hashlib
from datetime import datetime, timedelta

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
                        provenance_note: str = "",
                        key_id: str | None = None) -> None:
        # Domain-layer reservation guard (review P0 #9): the same sentinel
        # refusal as the API and the DB CHECK — "unregistered" is the
        # zero-authority class and can never become a registered identity.
        from apip.registry import RESERVED_SOURCE_IDS as _RESERVED
        v = (source_id or "").strip()
        if not v or v.lower() in _RESERVED:
            raise ValueError(
                f"source_id {source_id!r} is reserved and cannot be registered")
        self.db.execute("""
INSERT INTO sources (source_id, source_class, independent, auto_enforcement_allowed,
                     upstream, enabled, allowed_kinds, provenance_note, key_hash,
                     key_id, created_by)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON CONFLICT (source_id) DO UPDATE SET
    source_class = EXCLUDED.source_class,
    independent = EXCLUDED.independent,
    auto_enforcement_allowed = EXCLUDED.auto_enforcement_allowed,
    upstream = EXCLUDED.upstream,
    allowed_kinds = EXCLUDED.allowed_kinds,
    provenance_note = EXCLUDED.provenance_note,
    key_hash = EXCLUDED.key_hash,
    key_id = EXCLUDED.key_id,
    updated_at = now()
""", (source_id, source_class, independent, auto_enforcement_allowed,
      upstream, enabled, list(allowed_kinds), provenance_note, key_hash,
      key_id, actor))
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

    def source_by_credential(self, token: str, pepper: str | None = None) -> dict | None:
        """Resolve the source that owns `token` (channel auth). The token
        carries its PUBLIC key_id (``apipk_<key_id>.<secret>``), so lookup is
        ONE indexed row + ONE PBKDF2 verification (review P0 #14) — never a
        per-source scan an attacker could amplify. Tokens not in the keyed
        form default-deny (None). Returns None when nothing matches."""
        from apip.auth import parse_source_key, verify_credential
        parsed = parse_source_key(token)
        if parsed is None:
            return None
        key_id, secret = parsed
        row = self.db.query_one(
            "SELECT source_id, source_class, independent, "
            "auto_enforcement_allowed, upstream, enabled, allowed_kinds, "
            "key_hash FROM sources WHERE key_id=%s", (key_id,))
        if (row is not None and row.get("key_hash")
                and verify_credential(secret, row["key_hash"], pepper)):
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

    def batch_status(self, batch_id: str) -> str | None:
        """The batch's processing status: None (never seen), 'processing'
        (a crashed/interrupted ingest — the retry must RESUME it, review
        P0 #11) or 'complete' (a replay no-op)."""
        row = self.db.query_one(
            "SELECT status FROM ingest_batches WHERE batch_id=%s", (batch_id,))
        return row["status"] if row else None

    def begin_batch(self, *, batch_id: str, source_id: str, raw_sha256: str,
                    indicator_count: int, demoted: int, channel: str,
                    actor: str) -> bool:
        """Claim the batch for processing: insert it as 'processing' in its
        own transaction. Returns False when this exact batch was already
        recorded (same source + raw bytes — a replay), which is the ONLY
        state treated as a no-op. A crash mid-processing leaves the row
        'processing' so the retry resumes instead of skipping forever
        (review P0 #11)."""
        try:
            self.db.execute("""
INSERT INTO ingest_batches (batch_id, source_id, raw_sha256, indicator_count,
                            demoted_records, channel, status)
VALUES (%s,%s,%s,%s,%s,%s,'processing')
""", (batch_id, source_id, raw_sha256, indicator_count, demoted, channel))
        except psycopg2.errors.UniqueViolation:
            self.audit(actor, "ingest.duplicate_ignored", batch_id,
                       {"source_id": source_id})
            return False
        self.audit(actor, "ingest.accept", batch_id,
                   {"source_id": source_id, "indicators": indicator_count,
                    "demoted": demoted})
        return True

    def record_batch(self, *, batch_id: str, source_id: str, raw_sha256: str,
                     indicator_count: int, demoted: int, channel: str,
                     actor: str) -> bool:
        """Direct-seeding form used by labs/tests: records the batch already
        'complete' (there is no in-flight processing to resume). Same
        idempotency by (source_id, raw_sha256) as begin_batch."""
        try:
            self.db.execute("""
INSERT INTO ingest_batches (batch_id, source_id, raw_sha256, indicator_count,
                            demoted_records, channel, status)
VALUES (%s,%s,%s,%s,%s,%s,'complete')
""", (batch_id, source_id, raw_sha256, indicator_count, demoted, channel))
        except psycopg2.errors.UniqueViolation:
            self.audit(actor, "ingest.duplicate_ignored", batch_id,
                       {"source_id": source_id})
            return False
        self.audit(actor, "ingest.accept", batch_id,
                   {"source_id": source_id, "indicators": indicator_count,
                    "demoted": demoted})
        return True

    def complete_batch(self, batch_id: str) -> None:
        """Mark the batch 'complete' — only now is a replay of the same raw
        bytes a no-op (review P0 #11)."""
        self.db.execute(
            "UPDATE ingest_batches SET status='complete' WHERE batch_id=%s",
            (batch_id,))

    def fail_batch(self, batch_id: str, error: str) -> None:
        self.db.execute(
            "UPDATE ingest_batches SET status='failed' WHERE batch_id=%s",
            (batch_id,))
        self.audit("controller", "ingest.failed", batch_id, {"error": error[:400]})

    @staticmethod
    def observable_id(itype: str, canonical_value: str) -> str:
        """The SERVER-DERIVED durable identity of an observable (review P0
        #10): a content hash of (itype, canonical value). Two sources
        assigning different ids to the same observable derive the SAME id
        (corroboration merges); one source reusing another's id for a
        different observable derives a DIFFERENT id and can never attach
        evidence to it. Source-native ids survive as provenance only."""
        digest = hashlib.sha256(
            f"{itype}|{canonical_value.strip().rstrip('.').lower() if itype == 'fqdn' else canonical_value.strip()}".encode()
        ).hexdigest()[:24]
        return "indicator--" + digest

    def upsert_indicator(self, ind: Indicator, batch_id: str,
                         tenant_id: str | None = None) -> str:
        """Upsert by the server-derived observable id (review P0 #10); the
        submitted id is stored as provenance (source_object_id), never as
        identity. Returns the durable indicator id used."""
        durable_id = self.observable_id(ind.type, ind.value)
        with self.db.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
INSERT INTO indicators (indicator_id, itype, value, tags, tenant_id, source_object_id)
VALUES (%s,%s,%s,%s,%s,%s)
ON CONFLICT (indicator_id) DO UPDATE SET
    last_seen = now(), tags = EXCLUDED.tags,
    tenant_id = COALESCE(EXCLUDED.tenant_id, indicators.tenant_id)
""", (durable_id, ind.type, ind.value, list(ind.tags), tenant_id, ind.id))
                # source refs are NOT FK'd to sources: a channel-certified
                # upstream id may be asserted before the operator registers
                # it; unregistered ids simply carry zero authority at
                # decision time (registry protocol).
                for sid in ind.sources:
                    cur.execute("""
INSERT INTO indicator_source_refs (indicator_id, source_id)
VALUES (%s,%s) ON CONFLICT DO NOTHING
""", (durable_id, sid))
                for ev in ind.evidence:
                    cur.execute("""
INSERT INTO evidence (indicator_id, batch_id, kind, source_id, channel_source,
                      observed_at, detail)
VALUES (%s,%s,%s,%s,%s,%s,%s)
""", (durable_id, batch_id, ev.kind, ev.source_id, ev.channel_source,
      None if not ev.observed_at else ev.observed_at,
      psycopg2.extras.Json(ev.detail)))
        return durable_id

    # -- decisions ------------------------------------------------------------

    def record_decision(self, d: Decision, *, indicator_id: str, batch_id: str | None,
                        policy_content_sha256: str, actor: str) -> int | None:
        """Append a decision; idempotent on (decision_id, content_hash).

        Atomic: the uniqueness is pinned by migration idx_decisions_dedup
        (UNIQUE on decision_id, content_hash) and enforced with a single
        ``ON CONFLICT DO NOTHING`` statement — no check-then-insert race.
        Returns the decision instance's seq (the immutable versioned row a
        later action cites as its authorization provenance, review P0 #17),
        or None when this exact decision instance is already recorded."""
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
            return None
        self.audit(actor, "decision.record", d.id,
                   {"disposition": d.disposition, "action": d.action,
                    "rung": d.rung, "policy": d.policy_version})
        return int(inserted["seq"])

    def decision_seq_for(self, decision_id: str, content_hash: str) -> int | None:
        """The seq of the exact decision instance (decision_id, content_hash)
        — the authorization provenance an action cites (review P0 #17)."""
        row = self.db.query_one(
            "SELECT seq FROM decisions WHERE decision_id=%s AND content_hash=%s",
            (decision_id, content_hash))
        return int(row["seq"]) if row else None

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
                      requested_by: str, decision_seq: int,
                      monitoring_only: bool = False) -> bool:
        """Persist an action citing the EXACT decision instance that
        authorized it (decision_id, decision_seq — review P0 #17). Idempotent
        per (decision instance, adapter, rule): a re-evaluated identical
        decision can never mint a second action (review P0 #12) — that
        invariant is pinned by uq_actions_per_decision at the database.
        Returns False when this logical action already exists."""
        try:
            self.db.execute("""
INSERT INTO actions (action_id, decision_id, decision_seq, indicator_id, adapter,
    action_type, mode, selector, rule_id, fragment, fragment_hash, bundle_id,
    bundle_hash, requested_by, expires_at, state)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending')
""", (action_id, decision.id, decision_seq, indicator_id, adapter,
      decision.action, mode,
      psycopg2.extras.Json({**fragment.get("selector", {}),
                            "monitoring_only": monitoring_only}),
      fragment["rule_id"], fragment["fragment"], fragment["fragment_hash"],
      fragment["bundle_id"], fragment["bundle_hash"], requested_by, expires_at))
        except psycopg2.errors.UniqueViolation:
            self.audit(requested_by, "action.duplicate_ignored", action_id,
                       {"decision_id": decision.id, "decision_seq": decision_seq,
                        "adapter": adapter, "rule_id": fragment["rule_id"]})
            return False
        self.audit(requested_by, "action.created", action_id,
                   {"decision_id": decision.id, "decision_seq": decision_seq,
                    "adapter": adapter, "mode": mode,
                    "monitoring_only": monitoring_only,
                    "rule_id": fragment["rule_id"],
                    "expires_at": expires_at.isoformat() if expires_at else None})
        return True
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

    def active_co_owners(self, *, adapter: str, rule_id: str,
                         exclude_action_id: str, mode: str | None = None) -> list[dict]:
        """Other non-terminal actions that require the SAME physical rule
        (review P0 #6): the adapter's desired state is keyed by the physical
        identity (RPZ owner / Suricata sid), so revoking one action must not
        remove a shared rule another active action still justifies. Terminal
        states (revoked/expired/failed) don't count as owners.

        ``mode`` partitions ownership by ARTIFACT: a SHADOW action owns a
        rule in the shadow artifact, an ENFORCE action one in the live
        artifact — same rule_id, different physical state, so a shadow
        action never defers a live revoke (or vice versa)."""
        query = """
SELECT action_id FROM actions
WHERE adapter=%s AND rule_id=%s AND action_id <> %s
  AND state IN ('pending','dispatching','applied','verified','drifted')
"""
        params: list = [adapter, rule_id, exclude_action_id]
        if mode is not None:
            query += "  AND mode=%s"
            params.append(mode)
        return self.db.query(query, tuple(params))

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

    def claim_pending_action(self, action_id: str) -> bool:
        """Atomically claim a pending action for dispatch.

        The claim flips state pending -> dispatching in ONE UPDATE guarded by
        ``state='pending'``, so exactly one controller (the first to win the
        CAS) dispatches it. A second controller racing the same row gets
        ``RETURNING`` nothing and skips. This makes dispatch idempotent even
        across a lease handoff or a crash between SELECT and apply: the loser
        never double-applies, and a re-queue after a crash returns the action
        to pending for the next leader to re-claim.
        """
        row = self.db.query_one("""
UPDATE actions SET state='dispatching', last_reconciled_at=now()
WHERE action_id=%s AND state='pending'
RETURNING action_id
""", (action_id,))
        return bool(row)

    def unclaim_action(self, action_id: str) -> None:
        """Return a claimed-but-not-applied action toward its DESIRED state
        (audit P0 #4): an APPLY claim (state='dispatching') returns to
        'pending' so the next leader re-applies; a REMOVAL claim
        (state='removing') can only converge toward removal — it goes to
        'applied' (re-queued for removal) if the control was live, never to
        'pending', so a crash during revoke can NEVER become a re-apply."""
        self.db.execute("""
UPDATE actions SET state='pending', last_reconciled_at=now()
WHERE action_id=%s AND state='dispatching'
  AND desired_state='PRESENT'
""", (action_id,))
        self.db.execute("""
UPDATE actions SET state='applied', last_reconciled_at=now()
WHERE action_id=%s AND state='removing'
  AND desired_state='ABSENT'
""", (action_id,))

    def request_removal(self, action_id: str, from_states: tuple[str, ...]) -> bool:
        """Commit the durable ABSENT intent BEFORE touching infrastructure
        (audit P0 #4): CAS desired_state PRESENT->ABSENT and flip the
        action into the 'removing' phase from the given states. Recovery
        semantics after a crash: a 'removing' action retries removal — it
        can never be re-claimed as an apply."""
        # Exclusivity comes from the state CAS (the first claimer moves the
        # row to 'removing', outside every caller's from_states). The
        # desired_state guard admits both a fresh intent commit (PRESENT)
        # and a recovery re-entry (already ABSENT — intent committed, the
        # removal never completed); it can never flip ABSENT back.
        row = self.db.query_one("""
UPDATE actions SET desired_state='ABSENT', state='removing',
    last_reconciled_at=now()
WHERE action_id=%s AND state = ANY(%s) AND desired_state IN ('PRESENT','ABSENT')
RETURNING action_id
""", (action_id, list(from_states)))
        return row is not None

    def retry_removal(self, action_id: str) -> None:
        """A 'removing' action whose removal failed returns to the
        pre-removal active state for a bounded retry — desired_state stays
        ABSENT, so no code path can ever interpret it as apply-work."""
        self.db.execute("""
UPDATE actions SET state='applied', last_reconciled_at=now()
WHERE action_id=%s AND state='removing' AND desired_state='ABSENT'
""", (action_id,))

    def actions_desired_absent_active(self) -> list[dict]:
        """Actions whose durable intent is ABSENT but which still sit in an
        active state — e.g. a removal committed (desired ABSENT) and then
        the process died before entering the 'removing' phase. The
        reconciler converges these toward removal."""
        return self.db.query("""
SELECT * FROM actions
WHERE desired_state='ABSENT'
  AND state IN ('applied','verified','drifted')
ORDER BY created_at
""")

    def actions_stuck_removing(self, older_than: datetime) -> list[dict]:
        """Actions wedged in 'removing' past a full reconcile window (their
        leader died mid-removal): the next leader retries the removal — the
        desired state is durably ABSENT."""
        return self.db.query("""
SELECT * FROM actions
WHERE state='removing' AND desired_state='ABSENT'
  AND last_reconciled_at IS NOT NULL AND last_reconciled_at < %s
ORDER BY created_at
""", (older_than,))

    def claim_for_removal(self, action_id: str, from_states: tuple[str, ...]) -> bool:
        """Atomic CAS claim for ANY removal path (operator revoke, worker
        expiry, reconcile drift removal — review P0 #21): flips
        state -> 'dispatching' only from the given states, so an operator
        revoke racing the worker's expiry (in another controller, or in the
        same one) is serialized — exactly one path performs the adapter
        removal; the loser sees False and reports already-removing."""
        q = "UPDATE actions SET state='dispatching', last_reconciled_at=now() "
        q += "WHERE action_id=%s AND state = ANY(%s) RETURNING action_id"
        row = self.db.query_one(q, (action_id, list(from_states)))
        return row is not None

    def actions_stuck_dispatching(self, older_than: datetime) -> list[dict]:
        """Actions wedged in 'dispatching' (a leader died mid-apply) older than
        a full reconcile window — safe for the next leader to re-queue. A live
        in-flight apply bumps last_reconciled_at, so it stays excluded."""
        return self.db.query("""
SELECT * FROM actions
WHERE state='dispatching' AND last_reconciled_at IS NOT NULL
  AND last_reconciled_at < %s
ORDER BY created_at
""", (older_than,))

    def actions_needing_verification(self, older_than: datetime, limit: int = 100) -> list[dict]:
        """Periodic verification set: applied/verified actions on cadence,
        PLUS drifted actions — a drifted control stays eligible for bounded
        reconciliation retry, and a successful later verification returns it
        to 'verified' (review P1 #26: drifted was previously terminal for
        the sweep, so a transient drift never recovered)."""
        return self.db.query("""
SELECT * FROM actions WHERE state IN ('applied','verified','drifted')
  AND (verified_at IS NULL OR verified_at <= %s)
ORDER BY created_at LIMIT %s
""", (older_than, limit))

    def actions_active_state(self, limit: int = 1000) -> list[dict]:
        """All non-terminal, infra-bearing actions (audit P0 #5): the
        policy-promotion reconciliation set. Every row here physically
        exists (or is about to) at an actuator, so each must re-justify
        its presence under the CURRENT effective policy. Full rows — the
        controlled removal path reads fragment/selector/mode."""
        return self.db.query("""
SELECT * FROM actions WHERE state IN ('applied','verified','drifted')
ORDER BY created_at LIMIT %s
""", (limit,))

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
                # P0 #18: the documented posture ladder
                # (OBSERVE -> SHADOW -> ENFORCE) is ENFORCED, not remembered:
                # a stronger-posture promotion advances at most ONE governed
                # stage; downgrades (safety) and EMERGENCY (a separate
                # explicit transition) are always permitted.
                new_mode = str(self._staged_mode(cur, policy_version, revision)
                               or "").upper()
                cur.execute("""
SELECT v.mode FROM policy_current c
JOIN policy_versions v ON v.policy_version = c.policy_version
    AND v.revision = c.revision
WHERE c.singleton
""")
                active = cur.fetchone()
                active_mode = str((active or {}).get("mode") or "").upper()
                ladder = {"OFF": 0, "OBSERVE": 1, "SHADOW": 2, "ENFORCE": 3}
                new_rank = ladder.get(new_mode)
                active_rank = ladder.get(active_mode)
                if (new_rank is not None and active_rank is not None
                        and new_mode != "EMERGENCY"
                        and active_mode != "EMERGENCY"
                        and new_rank - active_rank > 1):
                    raise ValueError(
                        f"posture ladder violation: {active_mode} -> "
                        f"{new_mode} skips a governed stage; promote "
                        f"through the intermediate stage first (P0 #18)")
                # Retire the GLOBALLY active row regardless of version (review
                # P0 #19): promoting a different version must not leave an
                # older row active while policy_current points elsewhere —
                # exactly one active policy row is the invariant.
                cur.execute(
                    "UPDATE policy_versions SET status='retired' WHERE status='active'")
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

    @staticmethod
    def _staged_mode(cur, policy_version: str, revision: int) -> str | None:
        """The mode INSIDE the staged raw policy text — the runtime truth
        (P0 #20: the staging-time mode column may drift from the text)."""
        import re as _re
        cur.execute(
            "SELECT raw_text FROM policy_versions "
            "WHERE policy_version=%s AND revision=%s",
            (policy_version, revision))
        row = cur.fetchone()
        if not row:
            return None
        m = _re.search(r'^\s*mode\s*=\s*"([^"]+)"', row["raw_text"] or "",
                       _re.MULTILINE)
        return m.group(1) if m else None

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

    # -- approvals -----------------------------------------------------------

    def record_approval(self, *, approval_id: str, decision_id: str,
                        decision_seq: int, outcome: str, actor: str,
                        reason: str, policy_version: str,
                        policy_content_sha256: str,
                        action_ids: tuple[str, ...] = (),
                        expires_at: datetime | None = None) -> bool:
        """Persist the one-shot approval/rejection of an exact decision
        instance (review P0 #16). Idempotent-refusing: a second approval of
        the same decision instance is refused at the DATABASE
        (uq_approvals_per_decision) — returns False when an approval already
        exists."""
        try:
            self.db.execute("""
INSERT INTO decision_approvals (approval_id, decision_id, decision_seq, outcome,
    actor, reason, policy_version, policy_content_sha256, action_ids, expires_at)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
""", (approval_id, decision_id, decision_seq, outcome, actor, reason,
      policy_version, policy_content_sha256, list(action_ids), expires_at))
        except psycopg2.errors.UniqueViolation:
            self.audit(actor, "approval.duplicate_ignored", decision_id,
                       {"decision_seq": decision_seq, "outcome": outcome})
            return False
        self.audit(actor, f"decision.{outcome}", decision_id,
                   {"decision_seq": decision_seq, "approval_id": approval_id,
                    "reason": reason, "action_ids": list(action_ids)})
        return True

    def approval_for(self, decision_id: str,
                     decision_seq: int | None = None) -> dict | None:
        """The approval row for a decision instance (or its latest instance
        when no seq is given)."""
        if decision_seq is not None:
            return self.db.query_one(
                "SELECT * FROM decision_approvals "
                "WHERE decision_id=%s AND decision_seq=%s",
                (decision_id, decision_seq))
        return self.db.query_one(
            "SELECT * FROM decision_approvals WHERE decision_id=%s "
            "ORDER BY decision_seq DESC LIMIT 1", (decision_id,))

    def set_approval_actions(self, approval_id: str,
                             action_ids: tuple[str, ...]) -> None:
        """Attach the compiled action ids to a recorded approval."""
        self.db.execute(
            "UPDATE decision_approvals SET action_ids=%s WHERE approval_id=%s",
            (list(action_ids), approval_id))

    def list_approvals(self, limit: int = 100) -> list[dict]:
        return self.db.query(
            "SELECT approval_id, decision_id, decision_seq, outcome, actor, "
            "reason, policy_version, action_ids, created_at, expires_at "
            "FROM decision_approvals ORDER BY created_at DESC LIMIT %s",
            (limit,))

    def audit(self, actor: str, event_type: str, subject: str = "",
              detail: dict | None = None) -> None:
        self.db.execute(
            "INSERT INTO audit_events (actor, event_type, subject, detail) VALUES (%s,%s,%s,%s)",
            (actor, event_type, subject, psycopg2.extras.Json(detail or {})))

    def list_audit(self, limit: int = 100) -> list[dict]:
        return self.db.query(
            "SELECT event_id, at, actor, event_type, subject, detail "
            "FROM audit_events ORDER BY event_id DESC LIMIT %s", (limit,))

    # -- HA leader lease -----------------------------------------------------------

    def claim_leadership(self, leader_id: str, lease_s: int,
                         now: datetime) -> bool:
        """Atomic optimistic claim of the single-cluster worker lease.

        True only for the single winner. Gives an expired lease to
        ``leader_id``; renews an unexpired lease only if this controller
        already holds it. One guarded UPDATE — never a read-then-write — so two
        controllers can't both observe "expired" and both win (Postgres row
        lock serializes them; the second sees ``expires_at`` already bumped).
        """
        row = self.db.query_one("""
UPDATE controller_leases
SET leader_id=%s, acquired_at=%s, expires_at=%s, heartbeat_at=now()
WHERE singleton AND (leader_id=%s OR expires_at <= %s)
RETURNING leader_id
""", (leader_id, now, (now + timedelta(seconds=lease_s)).replace(microsecond=0),
      leader_id, now))
        return bool(row) and row["leader_id"] == leader_id

    def release_lease(self, leader_id: str) -> None:
        """Best-effort release on clean stop; never blocks leadership. A
        caller that is not the current leader is a no-op."""
        self.db.execute(
            "UPDATE controller_leases SET expires_at=now() "
            "WHERE singleton AND leader_id=%s", (leader_id,))

    def lease_state(self) -> dict | None:
        return self.db.query_one(
            "SELECT leader_id, acquired_at, expires_at, heartbeat_at "
            "FROM controller_leases WHERE singleton")

    # -- indicators --------------------------------------------------------------

    def list_indicators(self, limit: int = 50,
                        tenant_id: str | None = None) -> list[dict]:
        if tenant_id is not None:
            return self.db.query(
                "SELECT indicator_id, itype, value, first_seen, last_seen, tags, "
                "tenant_id FROM indicators WHERE tenant_id=%s "
                "ORDER BY last_seen DESC LIMIT %s", (tenant_id, limit))
        return self.db.query(
            "SELECT indicator_id, itype, value, first_seen, last_seen, tags, "
            "tenant_id FROM indicators ORDER BY last_seen DESC LIMIT %s", (limit,))

    def get_indicator(self, indicator_id: str) -> dict | None:
        return self.db.query_one(
            "SELECT * FROM indicators WHERE indicator_id=%s", (indicator_id,))

    def set_indicator_tenant(self, indicator_id: str, tenant_id: str | None,
                             actor: str) -> bool:
        row = self.db.query_one(
            "UPDATE indicators SET tenant_id=%s WHERE indicator_id=%s "
            "RETURNING indicator_id", (tenant_id, indicator_id))
        if row:
            self.audit(actor, "indicator.tenant", indicator_id, {"tenant": tenant_id})
        return bool(row)

    def indicator_evidence(self, indicator_id: str) -> list[dict]:
        return self.db.query(
            "SELECT evidence_id, kind, source_id, channel_source, observed_at, "
            "detail, recorded_at, batch_id FROM evidence WHERE indicator_id=%s "
            "ORDER BY evidence_id", (indicator_id,))

    # -- tenant policy overlays ---------------------------------------------------

    def upsert_tenant_overlay(self, *, tenant_id: str, raw_text: str,
                              overlay_sha256: str, created_by: str,
                              problems: list[str] | None = None) -> None:
        self.db.execute("""
INSERT INTO tenant_overlays
    (tenant_id, overlay_sha256, raw_text, created_by, problems)
VALUES (%s,%s,%s,%s,%s)
ON CONFLICT (tenant_id) DO UPDATE SET
    overlay_sha256 = EXCLUDED.overlay_sha256,
    raw_text = EXCLUDED.raw_text,
    created_by = EXCLUDED.created_by,
    created_at = now(),
    problems = EXCLUDED.problems
""", (tenant_id, overlay_sha256, raw_text, created_by,
      psycopg2.extras.Json(problems) if problems else None))
        self.audit(created_by, "policy.overlay.upsert", tenant_id,
                   {"sha256": overlay_sha256})

    def get_tenant_overlay(self, tenant_id: str) -> dict | None:
        return self.db.query_one(
            "SELECT tenant_id, overlay_sha256, raw_text, created_by, created_at, "
            "problems FROM tenant_overlays WHERE tenant_id=%s", (tenant_id,))

    def delete_tenant_overlay(self, tenant_id: str) -> bool:
        row = self.db.query_one(
            "DELETE FROM tenant_overlays WHERE tenant_id=%s RETURNING tenant_id",
            (tenant_id,))
        if row:
            self.audit("operator", "policy.overlay.deleted", tenant_id, {})
        return bool(row)

    def list_tenant_overlays(self) -> list[dict]:
        return self.db.query(
            "SELECT tenant_id, overlay_sha256, created_by, created_at "
            "FROM tenant_overlays ORDER BY created_at DESC")

    # -- health -------------------------------------------------------------------

    def action_counts(self) -> dict:
        rows = self.db.query(
            "SELECT state, count(*) AS n FROM actions GROUP BY state")
        return {r["state"]: int(r["n"]) for r in rows}
