# 12 — Implementation Backlog

This backlog is organized as engineering work packages rather than calendar estimates.

## WP-0 Repository and invariants

Create:

```text
cmd/apip/
internal/ingest/
internal/normalize/
internal/evidence/
internal/scoring/
internal/policy/
internal/ledger/
internal/compile/
internal/adapters/
internal/api/
schemas/
tests/
docs/
```

Define hard invariants in code and tests before external integrations.

Deliverables:
- canonical model schemas;
- policy version model;
- action enum;
- mode enum;
- immutable decision ID/content hash;
- scope types.

## WP-1 Canonical indicator/evidence store

Implement:
- FQDN/IP canonicalization;
- source table;
- raw object hash;
- evidence expiry;
- provenance relation;
- deduplication.

## WP-2 Deterministic scoring

Implement:
- M feature vector;
- S feature vector;
- reason codes;
- golden test corpus;
- score versioning;
- no floating-point nondeterminism across architectures if exact replay is required (fixed-point integers are preferable).

## WP-3 Policy engine

Implement:
- hard safety rules;
- thresholds;
- tenant overlays;
- allowlists;
- action budgets;
- approval requirement calculation;
- policy simulator.

OPA may be used as an external policy engine, but a small native deterministic policy layer is acceptable for the initial product. If OPA is used, pin bundle versions and preserve decision logs.

## WP-4 Ledger and receipts

Implement append-only events, idempotency, decision/evidence hashes, adapter receipts, revocation links, and current-state projections.

## WP-5 RPZ compiler

Implement:
- exact QNAME rules;
- PASSTHRU allowlist zone;
- zone serial/version;
- disabled shadow zone;
- syntax checker integration;
- rollback bundle.

Start with file output. Add live resolver integration only after shadow tests are stable.

## WP-6 Firewall/IPS compiler

Implement portable rule artifact output first. Add native device adapters later.

Requirements:
- exact IP only for automatic deny;
- tenant/HOME_NET scoping;
- TTL metadata;
- rule IDs tied to decision IDs;
- alert vs drop mode.

## WP-7 Adapter protocol

Implement prepare/apply/verify/revoke/get-state. Add signed bundle verification and scope enforcement at adapter side.

## WP-8 Operator API/CLI

Commands:

```text
apip source list
apip ingest <file>
apip indicator show <id>
apip decision explain <id>
apip decision approve <id>
apip action list
apip action revoke <id>
apip policy validate <file>
apip policy replay <snapshot>
apip adapter status
```

## WP-9 Telemetry and OCSF export

Implement normalized events, metrics, match counters, tenant aggregation, and privacy-preserving retention settings.

## WP-10 STIX/TAXII

Use robust schema libraries. Preserve markings and source IDs. Normalize into APIP internal objects. Do not allow arbitrary STIX content to become executable adapter data.

## WP-11 CACAO/OpenC2 interoperability

Implement:
- OpenC2-like intent serializer;
- action/target/actuator mappings;
- CACAO export for playbook sequences;
- conformance tests where practical.

## WP-12 Provider multi-tenancy

Add tenant partitioning, global+tenant policy layering, per-tenant telemetry, tenant allowlists, and signed edge bundles.

## WP-13 HA and scale

Add:
- controller leader election or idempotent workers;
- durable queue;
- incremental compilation;
- edge bundle caching;
- load testing;
- disaster recovery.

## WP-14 Routing adapter — last

Do not begin until:
- core action safety is mature;
- operator approval system is production-grade;
- adapter-side scope enforcement exists;
- dedicated authorized routing lab exists;
- rollback is proven.

Initial routing implementation should be compile/validate-only, then lab-only, then narrowly piloted.

## WP-15 Security hardening

- SBOM;
- signed releases;
- dependency pinning;
- secret scanning;
- SAST;
- container hardening;
- service account isolation;
- mTLS;
- key rotation test;
- backup/restore test.

## WP-16 Advanced passive analytics

Implement provenance-preserving temporal correlation, shared-infrastructure classification, authorized DNS lifecycle/fast-flux features, local prevalence, outcome feedback, and evidence decay. Analytics do not directly authorize actions.

## WP-17 Provider bundle/signing system

Implement canonical signed manifests, sequence/replay protection, edge trust roots, key rotation, desired-state reconciliation, and per-tenant bundle partitioning.

## WP-18 Operator experience

Implement evidence/decision explainability, approval queue, active-action health, one-step revoke, rollout rings, source health, replay, and audit export.

## WP-19 Pilot harness

Build resolver shadow/canary harness with synthetic/reserved namespaces, historical replay, false-positive/shared-infrastructure corpus, performance counters, and automatic stop-condition injection.

## WP-20 Formal safety and security tests

Add property tests, fuzzing, fault injection, tenant confused-deputy tests, bundle replay/signature tests, stale-rule tests, partial-actuator rollback, and high-risk routing hard-reject tests.

## WP-21 Behavioral detection suite (v2)

Implement `docs/23`:

- telemetry ingestion interfaces (resolver logs, flow metadata, proxy metadata, IDS events);
- BD-1..BD-7 deterministic feature extractors with fixed-point arithmetic;
- population baseline computation as versioned artifacts;
- k-of-n corroboration lattice enforcement in the policy engine;
- host-cluster grouping with pseudonymous identifiers;
- family-level disable/re-enable with conservative re-evaluation;
- golden corpus + adversarial shaping test suite.

## WP-22 Coverage ledger and DoH/DoT containment (v2)

Implement `docs/24`:

- per-segment coverage measurement (resolver-observed vs. total egress sessions);
- coverage reporting and protected-population claim gating;
- DoH/DoT known-hosts list as a signed versioned feed artifact;
- bootstrap-lookup interception policy responses;
- egress controls for 853/known-DoH with shadow-first staging and tenant opt-out;
- v4/v6 parity hard tests.

## WP-23 Layered interdiction compiler (v2)

Implement `docs/25`:

- ladder rung selection (L0–L7) as a deterministic compiler stage;
- shared-infrastructure registry (versioned, signed) and demotion logic with reason codes;
- L1 challenge, L2 per-pair ceiling, L6 host-quarantine action compilation;
- client-impact budgets for L1/L2;
- multi-rung campaign composition view;
- renewal-time rung re-evaluation.

## WP-24 Allow-first segments (v2)

Implement `docs/26`:

- segment object model + lifecycle state machine (ENUMERATE→SIMULATE→SHADOW→CANARY→ENFORCE→REVIEW) with backwards transitions;
- SIMULATE report: 30-day destination/path usage replay with volume ranking and owner-attribution fields;
- governed allowlist entries (owner/ticket/expiry/review cadence);
- denial telemetry ingestion as evidence and BD-6 feed;
- break-glass profiles (dual control, time-boxed, auto-expiring, offline-expiry-proven);
- quarterly review workflow and stale-entry findings.

## WP-25 Virtual patching (v2)

Implement `docs/27`:

- asset/service/exposure-path inventory objects;
- advisory/rule-feed ingestion with VP class selection (VP-3 always evaluated first);
- patch-tracking links to remediation tickets; retirement on patch confirmation;
- orphaned-VP alarms; VP review-date escalation;
- VP-1 alert→canary→drop staging with match-volume alarms;
- VP-3 SIMULATE path-usage replay.

## WP-26 Deterministic randomization (v2)

Implement `docs/29`:

- CSPRNG abstraction (all draws through it; no scattered `random`);
- seeded draw recording in decisions (mechanism, bounds version, seed, context, values);
- mechanisms: challenge sampling, ceiling draw, TTL/renewal jitter, shadow sampling, threshold dither, window placement;
- bounds enforcement downstream of the draw (out-of-bounds impossible to act on);
- replay-with-seed CI test; statistical uniformity/independence tests;
- adaptive-attacker simulation harness.

## WP-27 No-AI conformance enforcement (v2)

Implement `docs/28` conformance:

- dependency allowlist review in CI (reject model/LLM SDK dependencies);
- static check: no inference calls in scoring/policy/compile paths;
- AI-evidence invariance regression: decisions byte-identical with and without `annotation`-class records; no scoring origin exists through which AI output could contribute authority;
- automation-abuse controls: per-principal budgets, automation audit flags, human-gate verification for high-risk classes;
- injection-corpus tests over evidence channels.

## WP-28 Operator UI extensions (v2)

Extend `docs/22` screens for: coverage dashboard, segment lifecycle views, ladder/run demotion explanations, denial worklists, VP tracking, randomization audit (reproduce any historical draw), behavioral cluster views.

## WP-29 Attack-surface closure pack (v2.1)

Implements the six residual-surface reductions:

- plaintext-53 redirect-to-managed egress class with governed exceptions + resolver baseline checks (FR-029, `docs/24`);
- tuple-form allowlist entries + traffic profiles + drift alarms (FR-030, `docs/26`);
- capacity ceilings on constrained segments with break-glass exemptions and randomized bounds (FR-031, `docs/25`);
- BD-8 synchronized first-contact family with population-scaled N (FR-032, `docs/23`);
- standing exposure inventory diff + operator-owned-space scan reconciliation, incident-by-default on undocumented listeners (FR-033, `docs/27`);
- defend-the-defender deployment profile: controller allow-first segment, pull-only agents, pinned adapter egress (FR-034, `docs/09`).
