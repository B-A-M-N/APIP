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
| HA leader-election + lease (single-winner dispatch/expiry/verify across controllers on one ledger) | BETA SUPPORTED | `controller_leases` (migration 3), atomic optimistic-CAS `claim_leadership`, lease-gated worker loops, bounded follower takeover; `tests/test_ha_lease.py` |
| Per-tenant policy layering (tighten-only overlay onto the global active policy) | BETA SUPPORTED | `tenant_overlays` + `indicators.tenant_id` (migration 4), deterministic monotonic `merge_policy_overlay` (`src/apip/decision/layer.py`); `tests/test_tenant_overlay.py` |
| Standards interop, emit-only (OpenC2 / CACAO / OCSF) | PRODUCT IMPLEMENTED | `src/apip/interop/` — `decision_to_openc2` / `decision_to_cacao` / `decision_to_ocsf`, exercised by `tests/test_interop.py` (23 tests); surface at `apip decision interop`.

  **Deterministic + AI-free output only.** These serializers map the canonical `Decision` onto OpenC2 commands, CACAO 2.0 playbooks, and OCSF Detection-Finding events. They are emit-only: pure functions of a decision with an injectable clock (byte-reproducible), and they never parse external control/response messages back into the decision path (docs/28 preserved). No claim of full OpenC2/CACAO/OCSF profile compliance — they map the spec's vocabulary (docs/05). |

### Behavioral detection

| Family | Status |
|--------|--------|
| `beacon_periodicity` (BD-1) | PRODUCT IMPLEMENTED — deterministic detector in `src/apip/telemetry/behavioral.py`, parity-checked against `reference/behavioral.py`. Emits `local` evidence only; detector degradation reduces authority (stop-and-mark). |
| `first_seen_novelty` (BD-6) | PRODUCT IMPLEMENTED — same, second implemented family. |
| `dga_likelihood`, `dns_tunneling`, `fastflux`, `volume_anomaly`, `tls_metadata_mismatch`, `sync_first_contact` | PRODUCT IMPLEMENTED — all six extended families (BD-2/3/4/5/7/8) are real bounded, deterministic detectors in `src/apip/telemetry/behavioral.py` (`DgaDetector`, `DnsTunnelingDetector`, `FastFluxDetector`, `VolumeAnomalyDetector`, `TlsMetadataMismatchDetector`, `SyncFirstContactDetector`), each with direct unit tests in `tests/test_behavioral_detectors.py`. `PENDING_FAMILIES` is empty (no family is enum-presence-only). These families have **no** reference-oracle parity (the reference only ever implemented BD-1/BD-6) — they are a product extension proven by direct tests, not oracle parity. |

**Live detection wiring (docs/23 as a feed):** `src/apip/telemetry/feed.py` provides `LiveBehavioralFeed` — a deterministic, AI-free, stdlib-only feed that owns the enabled detector instances, exposes typed intake (`on_dns_query` / `on_dns_answer` / `on_flow` / `on_tls`), and folds emitted `Detection`s onto KNOWN indicators via `attach_to_indicators` (a detection for a domain nobody ingested stays dormant — no authority is invented from thin air). It carries the detectors' resource envelopes and P1-23 epoch discipline. Exercised by `tests/test_behavioral_feed.py`. This raises the behavioral surface to PRODUCT IMPLEMENTED; live *streaming ingestion from a real DNS/flow/TLS source* remains **FUTURE** (the feed is a library + evidence frontier awaiting a datasource, matching the reference's observe-only live layer).

Live behavioral detection is implemented as a deterministic evidence
frontier: all 8 detector families emit, and `LiveBehavioralFeed` wires them
onto existing indicators. *Streaming ingestion from a live DNS/flow/TLS
source* (a datasource feeding `on_dns_query` / `on_flow` / `on_tls`) is
**FUTURE** for the beta. The decision engine does consume `behavioral_*`
evidence kinds (with policy-set caps), and detector output never invents
authority — it only ever folds onto indicators that already exist.

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

**Re-runnable acceptance driver (`lab/acceptance.py`):** the 20-step loop is
now a one-command executable a reviewer can (re)run from a fresh clone. It
drives the REAL product wiring — `controller.pipeline.decide_indicator`,
`Controller.approve_decision`, `_dispatch_one`, `_verify_action`,
`_remove_action` — against a scratch Postgres, and proves every enforcement
step with a **real UDP DNS query** against `lab/resolver.py` (a stdlib-only
loopback resolver that re-reads the APIP RPZ zone on every query). It exits 0
ONLY when all 20 steps pass and **skips cleanly (exit 0) when no Postgres is
reachable** (`--socket-dir` overrides the unix-socket path); the always-on
baseline stays green without a database.
`PYTHONPATH="lab:." .venv-apip/bin/python lab/acceptance.py`

Verified end-to-end on 2026-09-03 by **B-A-M-N**: SHADOW-leg proves the
monitor-only zone is NOT consumed (real DNS keeps the baseline 10.99.0.9);
after the operator "goes to enforcement" (reified as a controller stop+start
against the same ledger — the step-20 restart-survival check), the ENFORCE-leg
proves a real live `NXDOMAIN` (rcode 3), an independent live-DNS verify, revoke
→ baseline restored (10.99.0.9), and TTL expiry through the controlled path.

One semantic honesty note the driver documents: reaching an exact-FQDN RPZ
action in this beta is an **operator approval** (`PROPOSE_OPERATOR_APPROVAL`)
of a proposed high-impact action. The deterministic engine for a bare FQDN
crosses no client/pair context and yields `OBSERVE` (L0) — the engine observes
but never invents an enforcement intention; the operator keys it. Approving a
PROPOSE decision tags the action mode `SHADOW`, but the compiled **adapter's
posture governs live enforcement** — an ENFORCE-posture adapter writes a live
(non-monitor-only) zone and live-DNS-verifies NXDOMAIN, which the driver
asserts rather than trusting the action-row mode tag.

### Multi-tenancy + HA

**HA single-winner lease (task #13, B-A-M-N, 2026-09-03):** multiple
controllers on the same ledger must not double-dispatch or double-expire.
A single-row `controller_leases` table plus an optimistic compare-and-swap
(`UPDATE controller_leases SET leader_id=... WHERE singleton AND
(leader_id=%s OR expires_at <= %s) RETURNING leader_id`) grants **exactly one**
winner per lease window; every worker loop re-checks the lease on each
iteration, so only the live lease holder runs pending-dispatch, the expiry
sweep, and verification. A follower observes the current leader and attempts an
orderly takeover once the lease expires — bounded, no split-brain. `stop()`
releases the lease. Proved by `tests/test_ha_lease.py` (4 tests): single-winner,
expired-lease-reclaimable, release-is-noop-for-non-holder, and two-controller
lease-gated single-worker contention.

**Per-tenant policy layering (task #14, B-A-M-N, 2026-09-03):** a tenant of a
shared deployment may overlay the GLOBAL active policy with a
**tighten-only fragment** — the effective policy for that tenant is at least as
restrictive as the global on every overridable control. `merge_policy_overlay`
(`src/apip/decision/layer.py`) is a PURE, deterministic, monotonic function of
two `Policy` objects (no I/O, no clock): it may **raise** decision thresholds /
rung floors, require **more** behavioral corroboration, **lower** caps,
**narrow** the authorization boundary (intersection), and only **re-affirm**
governed allowlist entries the global operator already allowlisted (an overlay
can never introduce a NEW suppressed value — that would loosen the control; see
the audit note below). A loosing overlay is not an error at runtime — the merge
CLAMPS it back to the global, so an all-default overlay is the identity and a
deliberately loosening overlay cannot widen scope. `build_overlay`
(`loader.py`) produces the partial overlay whose permissive defaults make
"absent means keep global" work. `DecisionPipeline.load_active_policy_effective`
resolves which policy governs `decide_indicator` (explicit `tenant_id`, else the
indicator's own `tenant_id`); `Controller.create_action_from_decision` uses the
tenant's effective policy for its scope check. Proved by
`tests/test_tenant_overlay.py`: monotonic tighten (raise/lower honored, loosing
clamped), overlay-cannot-widen-scope, rung/corroboration monotonicity, mode /
allowlist semantics, and a scratch-DB integration test showing a tenant with a
stricter overlay gets a no-less-permissive decision than the global on
identical evidence.

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

**Second adversarial audit (2026-09-03, B-A-M-N)** — a deeper boundary pass
over four independent reviewer tracks (adapters, controller/HA, scoring,
API/CLI/interop). Every finding was verified against source before the fix;
the decision path / differential oracle is unchanged:

- **RPZ/Suricata adapter fragment-injection.** The adapter `validate()` methods
  checked only a `startswith`/keyword prefix, so a `fragment` carrying a
  newline passed `validate` and was written to the zone/ruleset file verbatim —
  injecting an arbitrary RR/rule. Both `validate()` methods now refuse any
  fragment containing a newline/carriage-return (plus RPZ multi-line parens). Pinned by
  `test_rpz_validate_rejects_multiline_zone_injection`,
  `test_suricata_validate_rejects_multiline_ruleset_injection`.
- **RPZ ENFORCE verified a file write alone when no resolver was configured.**
  In ENFORCE the contract is resolver-confirmed NXDOMAIN; with `verify_query_server`
  unset it reported success on zone-file presence — a fabricated success. `verify`
  now fails closed (no independent resolver → not verified). Pinned by
  `test_rpz_enforce_verify_fails_closed_without_resolver`.
- **Suricata `validate` never re-checked adapter home-net scope nor target
  exactness.** Scope (defense-in-depth layer 3) and selector-never-broadens
  were enforced only at `compile`; a candidate outside the authorized prefix
  (or targeting a different IP than the selector) passed `validate`. Both are
  now re-checked at `validate`. Pinned by
  `test_suricata_validate_rechecks_home_net_scope`,
  `test_suricata_validate_catches_exactness_mismatch`.
- **Suricata fqdn http.host rate-limit dead-end.** `compile()` legitimately
  produces an fqdn pair-scoped intent rule, but `validate()` refused all
  `_PAIR_SCOPED` selectors — so a compilable action could never be applied
  (validate/apply/verify/revoke all raised). `validate` now distinguishes the
  IP pair-scoped case (still refused: would broaden to destination-global)
  from the fqdn http.host case, which is bound by its `content:"<host>"` field
  and validates. Pinned by `test_suricata_fqdn_http_intent_rule_validates`.
- **Overlay allowlist could LOOSEN the global control.** `_union_allowlist`
  unioned the overlay's allowlist into the effective policy, letting a tenant
  introduce a brand-new allowlisted value and suppress enforcement the global
  operator would apply (the tenant whitelisting its own C2 surface) — violating
  the module's own "never loosen" invariant. The merge now only re-affirms an
  entry already governed by the global allowlist; a new value is dropped.
  Pinned by `test_overlay_may_not_introduce_new_allowlist_value`.
- **Overlay without a `mode` silently downgraded the tenant.** `build_overlay`
  defaulted an absent `mode` to `SHADOW`, and `_stricter_mode` treated that
  fabricated SHADOW as tenant intent — so a threshold-only overlay stepped a
  global `ENFORCE` down to `SHADOW` for the whole tenant, violating the
  monotonic "never loosen" invariant. An overlay that omits `mode` now carries
  the internal `UNSET` sentinel, and `_stricter_mode` returns the global mode
  unchanged (identity, like every other overlay field). The sentinel never
  survives the merge; the effective policy always has a real mode. Explicit
  weaker modes still opt a tenant down; explicit stronger modes are still
  clamped to the global. Pinned by `test_overlay_without_mode_keeps_global_mode`
  and the explicit-weaker/stronger siblings.
- **Overlay scope narrowing used exact-set intersection on a containment
  hierarchy.** `_narrow_domains`/`_narrow_prefixes` compared entries by exact
  string equality, but `in_scope` authorizes by suffix (domains) and subnet
  (prefixes) — so a genuine sub-boundary narrowing (`tenant.corp.test` over
  `corp.test`, `10.1.0.0/16` over `10.0.0.0/8`) was silently dropped and the
  broader global boundary kept. The merge now honors any overlay value that is
  at-or-below a global boundary by the same containment `in_scope` uses, while
  refusing unrelated values and strict super-boundaries (widening); the global
  still governs when nothing valid is declared (never emptied to nothing).
  Pinned by `test_overlay_narrows_domains_by_suffix_containment`,
  `test_overlay_domain_outside_global_stays_global`,
  `test_overlay_domain_superdomain_is_refused`,
  `test_overlay_narrows_prefixes_by_subnet_containment`.
- **Dispatch double-apply under lease handoff / crash.** `_dispatch_pending`
  SELECTed `state='pending'` rows with no claim, so a lease handoff (or a crash
  between SELECT and apply) could dispatch the same action twice. Dispatch now
  atomically claims each action (`pending → dispatching` via one UPDATE guarded
  by `state='pending'`); a second winner skipped. Migration #5 extends the
  `actions` CHECK to include `dispatching`; the reconcile sweep re-queues a
  discovered `dispatching` action that sat past a full reconcile window.
- **OpenC2 export fabricated targets.** An unknown action crashed on an
  unguarded `_ACTUATOR_MAP[action]` (KeyError); a bind-less `firewall_deny`
  fabricated a device named after the decision id; a CIDR/port destination
  fabricated a `0.0.0.0/0` source the decision never asserted. The emitter now
  guards the actuator map (falls back to `openc2:actuator:unknown:1.0`), never
  invents a target from a decision id, and omits the unasserted source.
  Pinned by `test_openc2_unknown_action_is_guarded`,
  `test_openc2_does_not_fabricate_target_from_decision_id`,
  `test_openc2_cidr_has_no_fabricated_source`.
- **Operator API 500s and disclosure.** Unknown-action revoke raised a 500
  (now 404); a non-integer promote `revision` raised 500 (now 400); `policy_stage`
  accepted an arbitrary `mode` (now validated against the closed set → 400);
  `/ingest` buffered an unbounded body (now capped at 10 MiB → 413);
  unauthenticated `/health` disclosed adapter modes, zones, authorized scopes
  and registry detail (now liveness-only; rich health stays behind operator auth).
  Pinned by the `api_harness` tests in `tests/test_audit_regressions.py`.
- **Regression lock.** `tests/test_audit_regressions.py` (22 tests) pins every
  fix above, including the two-layer tenant narrowing (`_narrow_domains` open-global
  fix from the first pass).

Full product suite: 190 tests pass, `pyright --project pyproject.toml
src/apip tests` reports 0 errors, the acceptance drive passes 20/20 against a
real UDP resolver, and the decision path / differential oracle is unchanged.

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