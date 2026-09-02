# 10 — Testing and Validation

## Test philosophy

The most important tests are not “does a known bad domain get blocked?” They are “does the system refuse to block when evidence is weak, scope is broad, state is inconsistent, or the actuator cannot prove the requested change?”

## Unit tests

- indicator canonicalization;
- invalid domains/IPs rejected;
- source trust bounds;
- M/S score determinism;
- hard safety overrides;
- allowlist precedence;
- TTL calculation;
- policy version parsing;
- action matrix;
- scope enforcement.

## Property tests

Properties:

- increasing contradictory evidence never increases M;
- making a target broader never increases S;
- adding an allowlist always suppresses automatic deny;
- an expired decision cannot create a new action;
- same inputs produce same decision ID/content hash;
- automatic prefix/routing deny is impossible under default policy;
- **a single behavioral family can never produce a deny disposition (`docs/23`)**;
- **profile drift never triggers enforcement, only findings (`docs/26`)**;
- **capacity ceilings throttle, never drop, and break-glass exempts (`docs/25`)**;
- **exposure scanning cannot target non-operator-owned address space (`docs/27`)**;
- **shared-infrastructure class caps the selected rung at L4 regardless of M (`docs/25`)**;
- **every randomized draw lies within policy bounds; floors are never violated (`docs/29`)**;
- **replay with recorded seed reproduces the exact randomized values (`docs/29`)**;
- **an allow-first segment that has not completed onboarding cannot enforce (`docs/26`)**;
- **no code path in scoring/policy/compile invokes model inference — enforced by dependency allowlist review (`docs/28`)**;
- **virtual patches expire or retire on patch confirmation; orphaned VPs alarm (`docs/27`)**.

## Parser fuzzing

Fuzz:
- STIX bundles;
- TAXII envelopes;
- FQDN/IDN inputs;
- JSON schemas;
- adapter receipts;
- policy configuration.

Malformed external content must not crash or bypass validation.

## Replay tests

Replay a stored day/week of authorized telemetry and evidence against:

- current policy;
- candidate policy;
- previous production policy.

Compare:
- newly blocked indicators;
- removed blocks;
- affected tenant/client counts;
- estimated false positives;
- action-rate spikes.

## Shadow validation

A production pilot should first emit exact candidate rules into a disabled/log-only policy layer. Measure what would have matched without changing traffic.

## Integration tests

DNS RPZ:
- zone compile;
- syntax validation;
- shadow zone load;
- serial increment;
- allowlist precedence;
- exact rollback.

IPS/firewall:
- rule compile;
- parser validation;
- alert-only load;
- drop-mode canary;
- counter verification;
- removal/expiry.

Routing:
- offline route-policy validation only in normal CI;
- dedicated authorized lab for live BGP tests;
- reject out-of-scope prefixes;
- reject unapproved actions;
- verify rollback.

## Fault injection

Inject:
- feed outage;
- stale feed;
- duplicate feed;
- poisoned burst of indicators;
- DB write failure;
- adapter timeout;
- partial apply;
- controller crash after prepare but before apply;
- clock skew;
- malformed receipt;
- rule-count explosion;
- canary impact threshold breach;
- **behavioral-family failure/removal (decisions re-evaluate conservatively, no orphaned actions, `docs/23`)**;
- **randomization subsystem failure (degrades to fixed nominal parameters within bounds; no enforcement interruption, `docs/29`)**;
- **segment allowlist entry expiry mid-enforcement (expired entries flag for review, never silently allow-or-deny, `docs/26`)**;
- **patch-confirmation event for an active virtual patch (VP rules retire atomically, `docs/27`)**.

Expected outcome: no unsafe expansion of enforcement.

## Behavioral suite validation (v2)

Per family, before contributing to automatic enforcement:

- deterministic replay of candidate generation from raw telemetry (bit-identical);
- at least one week of production-shadow false-positive measurement;
- decorrelation evidence: k-of-n combination measurably reduces combined false positives below any single family;
- adversarial shaping tests (periodicity evasion via jitter inflation, lexical grooming, threshold probing) produce no enforcement without corroborating families;
- population-baseline recalibration produces a versioned, reviewed change (never silent adaptation).

## Adaptive-attacker simulation (v2)

Offline, replayed-corpus simulation pitting a shaping attacker against fixed vs. randomized parameters (`docs/29`): sustained exploitation rate measurably suppressed and enforcement-collision rate measurably raised under randomization; near-miss cluster evidence accumulates on probing.

## Performance tests

Measure:
- indicators/minute normalized;
- decisions/second;
- policy compile time;
- bundle size;
- edge activation latency;
- telemetry events/second;
- database growth;
- replay throughput.

## Security tests

- RBAC/tenant isolation;
- signed-bundle tampering;
- replayed old bundle rejection;
- credential rotation;
- adapter scope bypass attempts;
- injection into generated RPZ/rule formats;
- dependency/SBOM scanning;
- secret scanning.

## Safety release gate

No production enforcement until all are true:

- shadow results reviewed;
- allowlist workflow tested;
- rollback tested;
- hard-safety invariants covered by tests;
- adapter drift detection works;
- TTL expiry works without central controller;
- action budget trips correctly;
- audit chain can explain each synthetic decision end-to-end.
