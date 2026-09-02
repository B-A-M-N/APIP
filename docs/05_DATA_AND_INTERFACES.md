# 05 — Data and Interfaces

## External interoperability

### STIX 2.1
Use STIX as an ingress/egress threat-intelligence interchange format. Preserve STIX IDs, markings, confidence, object references, and raw object hashes. Internally normalize into APIP objects optimized for decisioning.

### TAXII 2.1
Use TAXII Collections for pulling/publishing CTI where available. Authentication/authorization is deployment-specific and must be isolated per source.

### OpenC2
Use OpenC2 semantics as the enforcement-intent abstraction. The initial implementation does not need to claim full profile compliance; however, action/target/actuator/modifier concepts should map cleanly to OpenC2.

### CACAO 2.0
Represent response workflows such as:

```text
trigger → validate evidence → shadow → approval → enforce → verify → expire/revoke
```

as CACAO-compatible playbooks when external interoperability is required.

### OCSF
Export normalized operational events into OCSF-compatible classes/objects for SIEM and analytics integration. APIP's internal ledger may use a purpose-built schema.

## Core APIP entities

### Source (v2 additions noted)

Sources now also cover: behavioral detector output (`origin: local_behavioral`), detection-rule feeds for virtual patching, and the DoH/DoT known-hosts list (`docs/24`, signed versioned feed artifact). Output of AI/ML models — internal or external, including vendor "AI analytics" feeds — is ingested only under the **annotation** source class (`docs/28`): it is recorded for analyst review, carries `auto_enforcement_allowed=false`, and contributes **zero** to M, S, corroboration counts, or rung eligibility. No `external_analytic` scoring class exists; all sources are subject to the same trust-profile, provenance, and corroboration rules.

### Source (v1 fields)
- id
- name
- kind
- owner
- reliability
- freshness policy
- markings policy
- parser version
- enabled state

### Indicator
- id
- type
- canonical value
- original value
- first seen
- last seen
- expires at
- markings
- tags
- STIX references

### Evidence
- id
- indicator id
- source id
- evidence kind
- observed time
- confidence contribution
- safety contribution
- upstream provenance
- raw object hash
- metadata

### Observation
Local sighting on an authorized network:
- tenant/scope
- sensor
- timestamp
- indicator
- protocol
- count
- direction
- optional flow metadata

### Decision
- evidence snapshot hash
- M score
- S score
- requested action
- selected rung (L0–L7) + demotion reason codes (`docs/25`)
- disposition
- reason codes
- policy version
- scope
- TTL (post-jitter actual + policy nominal, `docs/29`)
- randomization record (mechanism, bounds version, seed, draw) where applicable
- approval requirement

### Segment (`docs/26`)
- segment_id, scope, owner
- mode (ALLOW_FIRST | STANDARD)
- lifecycle stage (ENUMERATE | SIMULATE | SHADOW | CANARY | ENFORCE | REVIEW)
- allowlist entries (value, owner, ticket, expiry, review cadence)
- denied-volume alarm thresholds
- break-glass profile reference

### Asset / Service / ExposurePath (`docs/27`)
- asset_id, criticality, owner, review cadence
- exposed services, owning population, paths
- remediation ticket links for active virtual patches

### EnforcementIntent
- action
- target
- actuator class
- scope
- timing
- decision ID
- safety constraints

### ActionReceipt
- adapter ID
- device/domain ID
- prepared/applied/verified/revoked status
- adapter revision
- timestamps
- errors
- observed rule hash

## API security

- Mutations require RBAC/ABAC authorization.
- Tenant identity is derived from authenticated context, not arbitrary request fields.
- Every mutation accepts an idempotency key.
- Broad action approval requires a distinct approval permission.
- API returns decision IDs, not raw secrets.

## Suggested adapter gRPC/HTTP contract

```text
Prepare(intent_batch) -> PreparedChange
Apply(prepared_change) -> ApplyReceipt
Verify(apply_receipt) -> VerificationReceipt
Revoke(action_ids) -> RevokeReceipt
GetState(scope) -> ObservedState
Health() -> AdapterHealth
```

Adapter implementations must validate scope independently from the central controller.

## Schemas

See `schemas/indicator.schema.json`, `schemas/decision.schema.json`, `schemas/behavior_event.schema.json` (v2), and `schemas/action_receipt.schema.json`.
