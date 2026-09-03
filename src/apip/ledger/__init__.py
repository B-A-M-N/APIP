"""PostgreSQL-backed durable ledger.

Append-only security state with auditable identity on every mutation:
sources, ingest batches, indicators, evidence, policy versions, decisions,
actions, adapter attempts/receipts, verifications, expirations, revocations,
failures, and audit events. Historical security decisions are never
overwritten — corrections are new rows.
"""
from apip.ledger.db import Database, DatabaseUnavailable  # noqa: F401
from apip.ledger.migrations import MIGRATIONS, apply_migrations, migration_status  # noqa: F401
from apip.ledger.repo import Ledger  # noqa: F401
