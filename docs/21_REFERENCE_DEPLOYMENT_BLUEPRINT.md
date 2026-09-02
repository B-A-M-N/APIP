# 21 — Reference Deployment Blueprint

## Purpose

This is a concrete, implementation-oriented blueprint for moving from the dry-run scaffold to a production candidate while preserving APIP's safety properties. Component names are recommendations, not mandatory dependencies.

## Stage A — single-node engineering build

Recommended stack:

- Go or Rust for the production control-plane daemon and adapters; Python reference remains specification/test oracle.
- PostgreSQL for canonical objects, evidence metadata, policies, decisions, approvals, and receipts.
- Content-addressed local/object storage for raw imported CTI and replay snapshots.
- Native deterministic policy evaluator initially; OPA is optional for policy-as-code once its bundle/version behavior is integrated into replay.
- Prometheus-format metrics and OpenTelemetry traces/logs.
- JSON/JSONL event export plus optional OCSF mapping.
- Filesystem RPZ and Suricata exporters only during early stages.

No message broker is required until measured workload or fault isolation requires one.

## Stage B — authorized resolver pilot

Components:

```text
TAXII/files/internal CTI
        |
        v
+-----------------------+
| APIP controller       |
| normalize/evidence    |
| score/policy/ledger   |
+-----------+-----------+
            |
       signed bundle
            |
            v
+-----------------------+       +------------------+
| APIP resolver adapter | ----> | recursive DNS    |
| local hard limits     |       | RPZ integration  |
+-----------+-----------+       +------------------+
            |
        receipt/metrics
            |
            v
      APIP controller
```

The adapter gets credentials only for the minimum resolver policy operation needed. It does not receive unrestricted administrative access if the resolver supports narrower authorization.

## Stage C — multi-edge provider build

Introduce only when needed:

- durable work queue/event transport for ingest and bundle fanout;
- stateless decision workers using authoritative versioned state;
- separate signing service/HSM or cloud KMS abstraction;
- edge identity and enrollment service;
- regional bundle cache/distributor;
- tenant-aware metrics and audit export;
- HA PostgreSQL and tested restore path;
- object storage with retention/lifecycle controls.

## Suggested internal tables

### `sources`

- source_id
- type
- trust_profile
- enabled
- auth_reference (secret handle, not secret value)
- parser_version
- last_success
- freshness_limit

### `observables`

- observable_id
- type
- canonical_value
- created_at
- last_seen
- content_hash

### `evidence`

- evidence_id
- observable_id
- source_id
- kind
- assertion/confidence
- observed_at
- expires_at
- raw_object_hash
- provenance metadata

### `decisions`

- decision_id
- observable_id
- tenant/scope
- M
- S
- disposition
- action
- TTL
- policy_version
- score_version
- evidence_snapshot_hash
- explanation/reason codes
- created_at

### `approvals`

- approval_id
- decision_id
- principal
- approve/reject
- reason
- timestamp
- authentication context

### `bundles`

- bundle_id
- sequence
- edge/scope
- policy/compiler version
- created/expires
- manifest hash
- signature/key ID
- previous bundle hash

### `receipts`

- receipt_id
- bundle/decision IDs
- adapter/edge ID
- prepared/applied/verified/reverted/expired status
- target revision
- artifact hash
- timestamp
- error details

### `segments` (v2, `docs/26`)

- segment_id / scope / owner
- mode + lifecycle stage
- allowlist entries (value, owner, ticket, expiry, review_cadence)
- denied-volume alarm thresholds
- break-glass profile reference + active break-glass state

### `assets` / `services` / `exposure_paths` (v2, `docs/27`)

- asset_id / criticality / owner / review cadence
- service → owning population → paths
- active VP links with remediation ticket + review date

### `randomized_draws` (v2, `docs/29`)

- decision_id / mechanism / bounds_version
- seed_id / draw context
- resulting values (recorded for exact replay)

## Cryptographic control

Production bundles should be signed over a canonical manifest. Key design requirements:

- signing key never stored in source control or ordinary config;
- key IDs and rotation epochs recorded in bundles;
- edges trust an explicit key set;
- rotation supports overlap without accepting an unbounded historical key set;
- compromised/revoked keys can be denied at edges;
- signatures do not replace authorization/scope checks.

## Adapter contract

Every adapter implements equivalent semantics:

```text
Capabilities() -> supported targets/actions/limits
Prepare(desired_state) -> validated diff + preparation receipt
Apply(prepared_change) -> application receipt
Verify(expected_state) -> verification receipt
Revoke(decision_or_bundle) -> revocation receipt
GetState() -> normalized current state
Health() -> status/freshness/version
```

`Prepare` and `Verify` are mandatory; an adapter exposing only “execute arbitrary command” is non-conforming.

## Reconciliation loop

The controller compares:

```text
authorized desired state
        vs
edge-reported actual state
```

Drift resolution rules:

- unknown extra APIP-owned rule: remove or quarantine per policy;
- missing expected rule: retry within budget, otherwise mark degraded;
- expired rule: remove immediately and incident if stale;
- wrong tenant/scope: emergency revoke and stop edge rollout;
- mismatched bundle sequence/signature: refuse convergence until operator review.

## Credentials

Use separate identities for:

- feed acquisition;
- controller database;
- bundle signing;
- each edge adapter;
- operator/analyst API;
- telemetry export.

Secrets are references to an external secret store in production; never embed them in policy bundles, decisions, receipts, logs, or CTI exports.

## Build/release pipeline

Minimum release pipeline:

1. formatting/lint/type checks;
2. unit tests;
3. schema/OpenAPI validation;
4. deterministic golden replay;
5. fuzz/property tests for canonicalization and policy boundaries;
6. adapter simulation tests;
7. fault injection;
8. dependency/SBOM/security scans;
9. signed artifact build;
10. install/upgrade/rollback test;
11. canary package publication.

A release is not provider-ready solely because unit tests pass.
