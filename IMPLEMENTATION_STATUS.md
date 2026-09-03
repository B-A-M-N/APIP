# APIP implementation status

*Maintained for and attributed to **B-A-M-N** (the OS account the tooling runs
under is `bamn`; that local account is not the maintainer identity).*

This document states, honestly and per component, where each APIP capability
sits on the ladder below. The goal of the beta is to eliminate the "spec
reads like a product" ambiguity: **enum/schema presence is not implementation,
and reference code is not product code.**

## Status tiers

| Tier | Meaning |
|------|---------|
| **SPECIFIED** | Designed in `docs/` / `FULL_SPEC.md`. No runnable code. |
| **REFERENCE IMPLEMENTED** | Present in `reference/` (the deterministic oracle). Not the shippable product. |
| **PRODUCT IMPLEMENTED** | Present in `src/apip/` (the beta product package). Importable/runnable. |
| **BETA SUPPORTED** | PRODUCT IMPLEMENTED *and* exercised by the beta acceptance test + failure-mode tests. Claimed for v0.1.0. |
| **FUTURE** | Explicitly deferred out of the v0.1.0 beta. |

---

## Decision path integrity (non-negotiable across ALL tiers)

The security decision path (ingestion authority → evidence scoring → policy
decision → behavioral detection → action selection → approval → enforcement →
rollback → health → safety) is **deterministic and AI-free**. No LLM, ML
model, external inference API, AI SDK, classifier model, or agent participates
anywhere on it. `src/apip/decision/` imports only the Python standard library.

**Differential oracle:** `tests/test_differential_oracle.py` validates the
production decision engine byte-for-byte against `reference/` through a
subprocess oracle — same normalized input + same policy → equivalent decision.
The reference is never imported into the production process.

---

## Component status

### Core product components

| Component | Tier | Notes |
|-----------|------|-------|
| Controller service (lifecycle, dispatch, reconcile, expiry, verify, health) | BETA SUPPORTED | `src/apip/controller/` |
| Durable PostgreSQL ledger + migrations | BETA SUPPORTED | `src/apip/ledger/` |
| Authenticated ingest boundary (channel-bound source identity) | BETA SUPPORTED | `src/apip/ingest/`, `src/apip/auth/` |
| Operator CLI | BETA SUPPORTED | `src/apip/cli/` (incl. `decision approve`, `decision replay`, `adapter list/status` across all adapters) |
| Operator HTTP API | BETA SUPPORTED | `src/apip/api/` (incl. `POST /decisions/{id}/approve`, `POST /policy/replay`, `GET /adapters`) |
| RPZ adapter (exact FQDN, OFF/OBSERVE/SHADOW/ENFORCE) | BETA SUPPORTED | `src/apip/adapters/rpz.py` |
| Suricata/IPS adapter (IP rate-limit/deny, exact selectors, OFF/OBSERVE/SHADOW/ENFORCE, home-net scope) | BETA SUPPORTED | `src/apip/adapters/suricata.py` |
| Adapter verification/conciliation (no fabricated receipts) | BETA SUPPORTED | `rpz.verify`, `suricata.verify`, controller `_verify_action` |
| Expiry + revoke through controlled path, restart-safe | BETA SUPPORTED | controller `_remove_action` |
| Policy lifecycle (validate/stage/promote/current/history) | BETA SUPPORTED | `src/apip/ledger/repo.py`, `loader.py` |
| Policy replay / re-baseline after promote | BETA SUPPORTED | `Controller.replay_policy`, `POST /policy/replay`, `apip decision replay` |
| Operator approval of `PROPOSE_OPERATOR_APPROVAL` decisions | BETA SUPPORTED | `Controller.approve_decision`, `POST /decisions/{id}/approve`, `apip decision approve` |
| Triple authorization-boundary scope check | BETA SUPPORTED | policy `in_scope` + controller dispatch + adapter scope (RPZ `_in_adapter_scope`, Suricata home-net) |
| Component-level health (multi-adapter, defense-in-depth) | BETA SUPPORTED | `ControllerState.snapshot`, `Controller.adapters_status` — every configured adapter surfaces; any unhealthy adapter degrades overall status |
| Component-level health | BETA SUPPORTED | `ControllerState.snapshot`, `rpz.health` |
| Standards interop, emit-only (OpenC2 / CACAO / OCSF) | PRODUCT IMPLEMENTED | `src/apip/interop/` — `decision_to_openc2` / `decision_to_cacao` / `decision_to_ocsf`, exercised by `tests/test_interop.py` (23 tests); surface at `apip decision interop`.

  **Deterministic + AI-free output only.** These serializers map the canonical `Decision` onto OpenC2 commands, CACAO 2.0 playbooks, and OCSF Detection-Finding events. They are emit-only: pure functions of a decision with an injectable clock (byte-reproducible), and they never parse external control/response messages back into the decision path (docs/28 preserved). No claim of full OpenC2/CACAO/OCSF profile compliance — they map the spec's vocabulary (docs/05). |

### Behavioral detection

| Family | Status |
|--------|--------|
| `beacon_periodicity` (BD-1) | PRODUCT IMPLEMENTED — deterministic detector in `src/apip/telemetry/behavioral.py`, parity-checked against `reference/behavioral.py`. Emits `local` evidence only; detector degradation reduces authority (stop-and-mark). |
| `first_seen_novelty` (BD-6) | PRODUCT IMPLEMENTED — same, second implemented family. |
| `dga_likelihood`, `dns_tunneling`, `fastflux`, `volume_anomaly`, `tls_metadata_mismatch`, `sync_first_contact` | **PENDING / SPECIFIED** — explicitly `PENDING_FAMILIES`. Enum presence ≠ detector existence. |

Live behavioral *detection* in the enforcement path is **FUTURE** for the
beta. The decision engine does consume `behavioral_*` evidence kinds (with
policy-set caps), but you don't need a live detector to exercise the beta loop.

### Attribution

Requester attribution is **display-only** in the beta. It carries **zero
enforcement authority** and never contributes to a score. Active attribution
challenges remain `FUTURE` / disabled by default.

---

## Beta acceptance test (the proof the beta loop works)

The v0.1.0 beta is not complete until this passes end-to-end against an
authorized local resolver:

1. Start APIP + database.
2. Register two synthetic trusted sources (channel key per source).
3. Install a **SHADOW** policy.
4. Ingest evidence for `c2-test.invalid`.
5. APIP generates a deterministic decision.
6. Operator runs `apip decision explain`.
7. APIP prepares an exact-FQDN RPZ rule.
8. Adapter validates the candidate.
9. In SHADOW mode no live resolver behavior changes (monitor-only zone).
10. Promote only that test policy/domain to CANARY/ENFORCE.
11. APIP applies the RPZ rule to the test resolver.
12. APIP independently verifies the resolver loaded the intended state.
13. Query demonstrates the expected response.
14. Ledger shows decision, policy, evidence, adapter receipt, verification.
15. Operator invokes revoke.
16. APIP removes the exact rule.
17. APIP verifies removal.
18. Query demonstrates baseline restored.
19. Repeat with TTL expiry rather than manual revoke.
20. Restart APIP mid-run; state + reconciliation survive.

**Negative cases (all must fail safely):** allowlisted FQDN, out-of-scope
FQDN, insufficient evidence, poisoned source identity, malformed evidence,
adapter unavailable, rule-syntax failure, resolver-refused-reload, expired
policy, controller restart.

This acceptance run, plus the failure-mode suite (`tests/`), is what raises
components above to **BETA SUPPORTED**.

**Verified end-to-end on 2026-09-03** against a local Postgres, two registered
curated feeds + a `local` sensor, a SHADOW policy, a promoted ENFORCE policy,
and the lab resolver in `lab/resolver.py`. Both the SHADOW and ENFORCE exact-FQDN
paths completed: deterministic decisions, `decision explain`, RPZ zone write,
adapter apply → **real-DNS NXDOMAIN verification**, operator revoke → removal
verified → baseline restored, TTL expiry through the controlled path, and a
controller restart with full state + reconciliation survival. Negative cases
(out-of-scope → `out_of_authorized_scope`, poisoned source identity → demoted
to `unregistered`, malformed evidence → batch rejected, insufficient evidence →
NO_ACTION, adapter-unavailable → action fails without a fabricated success) all
fail safely.

Two product bugs were found and fixed during this run: (1) a timezone
mis-serialization in `controller/engine.py` that aged fresh evidence to
`stale` for non-UTC servers (silencing its decision weight), and (2) a narrow
column list in `ledger/repo.py: actions_due_for_expiry` that crashed the
controlled expiry/revoke path with `KeyError('fragment')`. Both are covered by
the differential oracle suite (`tests/test_differential_oracle.py`).

**Failure-mode + property suite:** `tests/test_failure_modes.py` (27 tests)
exercises the real production modules with no running Postgres/DNS required.
It hammers the adapter's selector-never-broadens invariant (wildcards, wider
destinations, wrong scope types, network selectors all refused), proves the
adapter enforces its own authorized-domain scope independently of policy, and
asserts the decision engine fails toward NO_ACTION/no-authority for
out-of-scope, allowlisted, insufficient, stale, future-dated, poisoned-identity
and private-client-control-plane-claim inputs. Fixing one assert exposed a
genuine gap: `RpzAdapter.validate` only pinned `exact_fqdn` to the rule owner, so
a selector could carry a wider `destination` field while a narrow `exact_fqdn`
slipped through; the destination field is now required to equal the owner
(`selector-never-broadens` closes at the destination field too).

**Adversarial audit (2026-09-03, B-A-M-N):** a boundary/correctness pass fixed
several real defects without touching decision semantics (the differential
oracle still passes):

- **Suricata SID matching was substring-based** across apply/verify/revoke/
  get_state — a revoke could over-remove a rule whose SID merely shares a
  prefix, and verify could report a prefix-colliding SID as "present"
  (fabricated-success risk). Now matched on the exact `sid:NNN;` token
  (`_SID_RE` + `_rule_sid`); pinned by `test_sid_matches_exact_not_substring`.
- **The ingest API's `replay` flag was always `False`** (computed after the
  batch was recorded). Now computed from the actual fresh-vs-replay branch.
- **`GET /sources/{id}` leaked the PBKDF2 `key_hash`** (it did `SELECT *`).
  `get_source` now uses the same safe projection as `list_sources`.
- **`record_decision` idempotency was a racy check-then-insert.** Migration #2
  adds a UNIQUE index on `(decision_id, content_hash)` and the write is one
  atomic `ON CONFLICT DO NOTHING` — pinned by
  `test_record_decision_idempotent_at_the_database`.
- **`source_by_credential` ran a 240k-iteration PBKDF2 scan over every source
  per unauthenticated ingest.** Now fast-fails on the `apipk_` source-key
  prefix (defense-in-depth against CPU amplification).
- **`register_source` passed `source_class` through unvalidated** (the DB
  CHECK would 500). Now validated against the closed class set → clean 400.
- **THE operator API ignored `config.operator_token`** and re-read the env at
  request time. `_operator` now honors the injected config (fails closed when
  no token is configured).

Full product suite: 152 tests pass, `pyright --project pyproject.toml
src/apip tests` reports 0 errors, and the decision path / differential oracle
is unchanged.

---

## Failure semantics (fail-closed by default)

On `database unavailable`, `source auth failure`, `malformed input`, `policy
invalid/missing`, `adapter apply/verify failure`, `drift`, `controller
restart`, `action expires during outage`, `resolver unavailable`, or `partial
bundle apply`, APIP fails toward:

- **no new enforcement**;
- **preserve known-safe existing state**;
- **surface degraded status** (component-level health);
- **retain enough state to reconcile later**.

It **never** silently broadens a selector and **never** fabricates a success
receipt.

---

## Roadmap (FUTURE, explicitly out of v0.1.0)

- Additional RPZ modes beyond exact-FQDN (wildcards, prefix deny) — **FUTURE**.
- Additional enforcement adapters beyond the shipped RPZ + Suricata/IPS
  (proxy/WAF, BGP, routing, arbitrary-IP block, NAC/host containment) —
  **FUTURE**.
- Live streaming behavioral detection beyond the deterministic families —
  **FUTURE**.
- Active requester-attribution challenges — **FUTURE**.
- TAXII / broader ingest transports — **FUTURE**.
- AI analyst-explanation surface (zero authority) — **FUTURE and optional**;
  deliberately not implemented, per the no-AI invariant.