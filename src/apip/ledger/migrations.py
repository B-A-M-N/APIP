"""Ordered, idempotent schema migrations.

Each migration runs once, inside a transaction, recorded in
``apip_schema_migrations``. Migration tests verify: fresh install applies
all; re-running applies none; a partially-applied sequence resumes.
"""
from __future__ import annotations

from apip.ledger.db import Database

MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "core tables", """
CREATE TABLE sources (
    source_id        TEXT PRIMARY KEY,
    source_class     TEXT NOT NULL CHECK (source_class IN
        ('curated','local','community','annotation','attribution')),
    independent      BOOLEAN NOT NULL DEFAULT TRUE,
    auto_enforcement_allowed BOOLEAN NOT NULL DEFAULT TRUE,
    upstream         TEXT,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    allowed_kinds    TEXT[] NOT NULL DEFAULT '{}',
    provenance_note  TEXT NOT NULL DEFAULT '',
    key_hash         TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by       TEXT NOT NULL,
    last_success_at  TIMESTAMPTZ,
    health           TEXT NOT NULL DEFAULT 'unknown',
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ingest_batches (
    batch_id     TEXT PRIMARY KEY,
    source_id    TEXT NOT NULL REFERENCES sources(source_id),
    raw_sha256   TEXT NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    channel      TEXT NOT NULL DEFAULT 'http',
    demoted_records INTEGER NOT NULL DEFAULT 0,
    indicator_count INTEGER NOT NULL DEFAULT 0,
    raw_path     TEXT,
    UNIQUE (source_id, raw_sha256)
);
CREATE INDEX idx_batches_source ON ingest_batches(source_id, received_at DESC);

CREATE TABLE indicators (
    indicator_id  TEXT PRIMARY KEY,
    itype         TEXT NOT NULL CHECK (itype IN ('fqdn','ipv4','ipv6','cidr','url')),
    value         TEXT NOT NULL,
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    tags          TEXT[] NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_indicators_value ON indicators(itype, value);

CREATE TABLE indicator_source_refs (
    indicator_id TEXT NOT NULL REFERENCES indicators(indicator_id),
    source_id    TEXT NOT NULL,
    PRIMARY KEY (indicator_id, source_id)
);

CREATE TABLE evidence (
    evidence_id  BIGSERIAL PRIMARY KEY,
    indicator_id TEXT NOT NULL REFERENCES indicators(indicator_id),
    batch_id     TEXT NOT NULL REFERENCES ingest_batches(batch_id),
    kind         TEXT NOT NULL,
    source_id    TEXT NOT NULL,
    channel_source TEXT NOT NULL,
    observed_at  TIMESTAMPTZ,
    detail       JSONB NOT NULL DEFAULT '{}',
    recorded_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_evidence_indicator ON evidence(indicator_id);

CREATE TABLE policy_versions (
    policy_version TEXT,
    revision       INTEGER,
    content_sha256 TEXT NOT NULL,
    raw_text       TEXT NOT NULL,
    mode           TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN
        ('staged','active','retired','rejected')),
    staged_by      TEXT NOT NULL,
    staged_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    promoted_by    TEXT,
    promoted_at    TIMESTAMPTZ,
    problems       JSONB,
    PRIMARY KEY (policy_version, revision)
);
CREATE TABLE policy_current (
    singleton   BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    policy_version TEXT NOT NULL,
    revision       INTEGER NOT NULL
);

CREATE TABLE decisions (
    decision_id   TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    seq           BIGSERIAL,
    indicator_id  TEXT NOT NULL REFERENCES indicators(indicator_id),
    batch_id      TEXT REFERENCES ingest_batches(batch_id),
    maliciousness INTEGER NOT NULL CHECK (maliciousness BETWEEN 0 AND 100),
    action_safety INTEGER NOT NULL CHECK (action_safety BETWEEN 0 AND 100),
    disposition   TEXT NOT NULL,
    action        TEXT NOT NULL,
    rung          TEXT NOT NULL,
    scope         TEXT NOT NULL,
    ttl_seconds   INTEGER NOT NULL DEFAULT 0,
    policy_version TEXT NOT NULL,
    policy_content_sha256 TEXT NOT NULL,
    reason_codes  TEXT[] NOT NULL DEFAULT '{}',
    explanation   TEXT NOT NULL,
    selector      JSONB,
    randomization JSONB,
    content_hash  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (decision_id, seq)
);
CREATE INDEX idx_decisions_indicator ON decisions(indicator_id, created_at DESC);
CREATE INDEX idx_decisions_created ON decisions(created_at DESC);

CREATE TABLE actions (
    action_id     TEXT PRIMARY KEY,
    decision_id   TEXT NOT NULL,
    decision_seq  BIGINT NOT NULL,
    indicator_id  TEXT NOT NULL,
    adapter       TEXT NOT NULL,
    action_type   TEXT NOT NULL,
    mode          TEXT NOT NULL CHECK (mode IN ('OFF','OBSERVE','SHADOW','ENFORCE')),
    selector      JSONB NOT NULL,
    rule_id       TEXT NOT NULL,
    fragment      TEXT NOT NULL,
    fragment_hash TEXT NOT NULL,
    bundle_id     TEXT NOT NULL,
    bundle_hash   TEXT NOT NULL,
    requested_by  TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    state         TEXT NOT NULL CHECK (state IN
        ('pending','applied','verified','failed','expired','revoked','drifted')),
    state_reason  TEXT NOT NULL DEFAULT '',
    expires_at    TIMESTAMPTZ,
    revoked_by    TEXT,
    revoked_at    TIMESTAMPTZ,
    verified_at   TIMESTAMPTZ,
    last_reconciled_at TIMESTAMPTZ
);
CREATE INDEX idx_actions_state ON actions(state);
CREATE INDEX idx_actions_expiry ON actions(state, expires_at);

CREATE TABLE adapter_attempts (
    attempt_id  BIGSERIAL PRIMARY KEY,
    action_id   TEXT NOT NULL REFERENCES actions(action_id),
    phase       TEXT NOT NULL CHECK (phase IN
        ('prepare','validate','apply','verify','revoke','get_state')),
    ok          BOOLEAN NOT NULL,
    detail      JSONB NOT NULL DEFAULT '{}',
    actor       TEXT NOT NULL,
    at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_attempts_action ON adapter_attempts(action_id, at);

CREATE TABLE adapter_receipts (
    receipt_id   TEXT PRIMARY KEY,
    action_id    TEXT NOT NULL REFERENCES actions(action_id),
    adapter      TEXT NOT NULL,
    rule_id      TEXT NOT NULL,
    fragment_hash TEXT NOT NULL,
    bundle_id    TEXT NOT NULL,
    bundle_hash  TEXT NOT NULL,
    observed     JSONB NOT NULL,
    status       TEXT NOT NULL,
    verified     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    event_id   BIGSERIAL PRIMARY KEY,
    at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor      TEXT NOT NULL,
    event_type TEXT NOT NULL,
    subject    TEXT NOT NULL DEFAULT '',
    detail     JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_audit_at ON audit_events(at DESC);
"""),
    (2, "decision idempotency unique", """
-- record_decision is idempotent on (decision_id, content_hash); the app-level
-- check-then-insert was racy, so pin it at the DB. A repeated exact decision
-- (same id + same content hash) is refused; a NEWER content_hash for the same
-- decision_id is still allowed (the decision row is versioned by seq).
CREATE UNIQUE INDEX IF NOT EXISTS idx_decisions_dedup
    ON decisions (decision_id, content_hash);
"""),
    (3, "controller leader lease (HA)", """
-- Single-row, whole-cluster leader lease for the controller workers
-- (dispatch/expiry/verify). A freshly-started controller seeds the row as
-- expired (epoch) so leadership is always immediately reclaimable; whoever
-- wins the atomic compare-and-set owns the worker loops until the lease
-- lapses (dead/failed leader) and another controller takes over. This keeps
-- multiple controllers pointed at the same ledger from double-dispatching or
-- double-expiring the same action.
CREATE TABLE controller_leases (
    singleton    BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    leader_id    TEXT NOT NULL,
    acquired_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO controller_leases (singleton, leader_id, expires_at)
VALUES (TRUE, '', '1970-01-01T00:00:00Z')
ON CONFLICT (singleton) DO NOTHING;
"""),
    (4, "per-tenant policy overlays", """
-- A tenant of a shared deployment may overlay the GLOBAL active policy with a
-- tighten-only fragment: it may RAISE decision thresholds / rung floors,
-- require more behavioral corroboration, LOWER caps, and ADD governed
-- allowlist entries -- never loosen the global boundary or control. The
-- effective policy for that tenant is merge(global, overlay) computed
-- deterministically at decide-time (see decision/layer.py). indicators carry
-- an OPTIONAL tenant_id so the pipeline can select the right effective policy;
-- NULL means "global only".
CREATE TABLE tenant_overlays (
    tenant_id     TEXT PRIMARY KEY,
    overlay_sha256 TEXT NOT NULL,
    raw_text      TEXT NOT NULL,
    created_by    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    problems      JSONB
);
ALTER TABLE indicators ADD COLUMN IF NOT EXISTS tenant_id TEXT;
CREATE INDEX IF NOT EXISTS idx_indicators_tenant ON indicators(tenant_id);
"""),
    (5, "action dispatch claim state", """
-- Add the transient 'dispatching' state used by the controller's atomic
-- dispatch claim. A pending action is claimed (pending -> dispatching) in one
-- UPDATE guarded by state='pending', so exactly one leader dispatches it, and
-- a crash between claim and apply leaves it dispatching for the next leader's
-- reconcile to re-queue (unclaim_action) rather than double-apply. Replaces the
-- constraint that lacked this state.
ALTER TABLE actions DROP CONSTRAINT IF EXISTS actions_state_check;
ALTER TABLE actions ADD CONSTRAINT actions_state_check CHECK (state IN
    ('pending','dispatching','applied','verified','failed','expired','revoked','drifted',
     'cancelled_policy_changed'));
"""),
    (6, "single active policy invariant", """
-- Exactly one active policy row is a database invariant, not an operator
-- convention (review P0 #19): promote_policy retires the globally active row
-- regardless of version before activating the new one, and this partial
-- unique index makes any second 'active' row impossible even under a race.
-- First, retire any duplicate actives an earlier version-conditional retire
-- may have left behind, keeping the row policy_current points at.
UPDATE policy_versions SET status='retired'
WHERE status='active'
  AND policy_version <> (SELECT policy_version FROM policy_current WHERE singleton);
CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_versions_one_active
    ON policy_versions ((1)) WHERE status='active';
"""),
]


def migration_status(db: Database) -> list[dict]:
    rows = db.query(
        "SELECT version, name, applied_at FROM apip_schema_migrations ORDER BY version")
    return [dict(r) for r in rows]


def apply_migrations(db: Database) -> list[int]:
    """Apply all pending migrations, each in its own transaction. Returns
    the versions applied this call."""
    db.execute("""
CREATE TABLE IF NOT EXISTS apip_schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)""")
    applied = {r["version"] for r in migration_status(db)}
    done: list[int] = []
    for version, name, sql in MIGRATIONS:
        if version in applied:
            continue
        with db.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                cur.execute(
                    "INSERT INTO apip_schema_migrations (version, name) VALUES (%s, %s)",
                    (version, name))
        done.append(version)
    return done
