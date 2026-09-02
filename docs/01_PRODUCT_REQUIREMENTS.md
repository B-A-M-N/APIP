# 01 — Product Requirements

## Functional requirements

### FR-001 Intelligence ingestion
APIP MUST accept JSON indicators and SHOULD support STIX 2.1 bundles and TAXII 2.1 collection polling. Each imported object MUST retain source identity, timestamps, data markings, parser version, and raw-object hash.

### FR-002 Canonicalization
APIP MUST canonicalize supported indicator types and reject malformed values. FQDN canonicalization MUST be case-insensitive and handle IDN/punycode consistently.

### FR-003 Source trust
Each source MUST have an operator-controlled reliability profile. Source reliability MUST NOT be learned silently from enforcement outcomes without operator-visible policy changes.

### FR-004 Evidence correlation
The system MUST support multiple independent evidence records per indicator and MUST preserve source provenance.

### FR-005 Two-score decision model
Every proposed enforcement decision MUST contain a maliciousness score and action-safety score.

### FR-006 Explainability
Every score and disposition MUST include machine-readable reason codes and a human-readable explanation assembled from deterministic inputs.

### FR-007 Modes
The system MUST implement OFF, OBSERVE, SHADOW, and ENFORCE. EMERGENCY is optional but, if implemented, MUST be operator-invoked.

### FR-008 Policy isolation
Policy evaluation MUST be a separate step from feed ingestion. Feeds MUST NOT invoke adapter actions directly.

### FR-009 TTL
Every automatic deny/rate-limit action MUST contain an expiry time. Expiry MUST be enforceable locally at or near the actuator where practical.

### FR-010 Allowlist precedence
Allowlist/exception matches MUST prevent automatic deny actions.

### FR-011 Atomic rollout
Adapters SHOULD apply a batch atomically or via staged transaction semantics. Partial application MUST create an explicit failure receipt.

### FR-012 Verification
Each action MUST be verifiable after application. Verification data MUST be linked to the originating decision.

### FR-013 Revocation
Every applied action MUST have a deterministic revocation path.

### FR-014 Reconciliation
The controller MUST detect drift between desired and observed actuator state.

### FR-015 Multi-tenant scope
Provider deployments MUST prevent one tenant’s policy or telemetry from affecting another tenant unless a global policy is explicitly configured.

### FR-016 Approval workflow
Broad or high-risk actions MUST support manual approval and SHOULD support dual approval.

### FR-017 Audit ledger
Policy changes, decisions, approvals, action attempts, receipts, verification results, and revocations MUST be durably recorded.

### FR-018 Dry run / replay
Operators MUST be able to run historical evidence through a candidate policy version without making live changes.

### FR-019 Data export
The system SHOULD emit normalized event data aligned with OCSF or a similarly open event schema.

### FR-020 Playbooks
The system SHOULD represent multi-step response workflows in a format that can map to CACAO 2.0.

### FR-021 Behavioral detection evidence
The system MUST accept behavioral detection evidence (beacon periodicity, DGA-likelihood, DNS tunneling, fast-flux, volume anomaly, first-seen novelty, TLS metadata mismatch — `docs/23`) as ordinary evidence records with `origin: local_behavioral`, and MUST subject them to the same scoring, corroboration, and policy gates as external intelligence. A single behavioral family MUST NOT alone authorize a deny action.

### FR-022 Chokepoint coverage accounting
The system MUST measure and report, per protected population segment, the fraction of DNS-bearing sessions observed at the managed resolver versus total egress sessions (`docs/24`). Populations below the coverage floor MUST be excluded from protected-population claims.

### FR-023 Layered response selection
The system MUST select enforcement actions via the deterministic interdiction ladder (`docs/25`), including automatic shared-infrastructure demotion and demotion reason codes, rather than a binary block/no-block decision.

### FR-024 Allow-first segments
The system MUST support per-segment allow-first (deny-by-default egress) posture with the staged onboarding lifecycle (ENUMERATE → SIMULATE → SHADOW → CANARY → ENFORCE → REVIEW), governed allowlist entries with owner/expiry/review cadence, break-glass profiles, and denial telemetry as evidence (`docs/26`).

### FR-025 Virtual patching
The system MUST support virtual patch classes VP-1–VP-4 (`docs/27`) linked to asset inventory and remediation tickets, with automatic retirement on patch confirmation and orphaned-VP alarms. Virtual patches MUST NOT outlive the vulnerability they address without review.

### FR-026 No-AI operation
The platform MUST be fully operable with zero AI, machine-learning, or LLM components (`docs/28`). No operational path may invoke model inference. Output of any AI/ML system — internal or external — is admissible only under the non-authoritative `annotation` source class (`docs/04` v2.1): recorded for analyst review, provably unable to alter any score, corroboration count, rung eligibility, or emitted action; decisions are byte-identical with and without it.

### FR-027 Deterministic randomization
The system MUST support seeded randomization of defensive parameters within policy bounds (`docs/29`) using recorded seeds so every randomized decision remains exactly replayable; randomized mechanisms MUST be incapable of producing values outside policy bounds or weakening any safety floor.

### FR-028 Asset and segment inventory
The system MUST maintain asset, service, and exposure-path inventory as first-class governed objects (owner, review cadence, criticality), used by virtual patching, allow-first enumeration, L6 scoping, and blast-radius estimation (`docs/26`/`27`).

### FR-029 Plaintext DNS closure
The platform MUST support restricting outbound DNS transport (UDP/53, TCP/53) to enumerated resolvers, with redirect-to-managed as the preferred function-preserving form, and governed per-device exceptions (`docs/24`).

### FR-030 Dependency-path narrowing
Allowlist entries MUST default to tuple form (destination, protocol, port-range) with per-entry traffic profiles (volume band, cadence, peer scope); profile drift MUST be an incident signal, never an enforcement trigger (`docs/26`).

### FR-031 Capacity ceilings
Constrained segments MUST support baseline-derived per-(host,destination) and per-host aggregate byte ceilings (throttle-not-drop, shadow-staged, break-glass-exemptible, randomized within bounds) (`docs/25`).

### FR-032 Population-scale novelty detection
The behavioral suite MUST include synchronized first-contact detection (BD-8): population-scaled N-host first-contact of a never-seen destination within a bounded window, as one family in the corroboration lattice (`docs/23`).

### FR-033 Standing exposure drift detection
The platform MUST continuously diff observed inbound listening state / unknown-port flows against the exposure inventory; an undocumented listener MUST be an incident-by-default finding. Authorized scanning is restricted to operator-owned address space (`docs/27`).

### FR-034 Defend-the-defender
The APIP control plane MUST be deployable in its own allow-first segment with pull-only edge agents (no inbound listeners) and adapter egress pinned to specific device APIs (`docs/09`).

## Non-functional requirements

### NFR-001 Availability
The control plane MUST NOT be a per-packet or per-query synchronous dependency.

### NFR-002 Change safety
A controller failure MUST default to no new change.

### NFR-003 Determinism
Decision output MUST be reproducible from versioned evidence, policy, and clock inputs.

### NFR-004 Performance
At provider scale, enforcement bundle compilation MUST be incremental and avoid full-rule regeneration when possible.

### NFR-005 Horizontal scale
Feed processing, evidence correlation, and telemetry ingestion SHOULD be independently scalable.

### NFR-006 Security
All mutation APIs MUST require authenticated, authorized identities. Adapter credentials MUST be isolated by enforcement domain.

### NFR-007 Privacy
Payload collection MUST be minimized. Network metadata sufficient for decision verification is preferred over raw content where possible.

### NFR-008 Observability
Metrics MUST expose queue depth, feed freshness, decision counts, enforcement counts, error rates, match rates, and rollback events.

### NFR-009 Upgrade safety
Policy schema and adapter protocol versions MUST be explicit and backward-compatibility tested.

### NFR-010 Portable deployment
The control plane SHOULD run on commodity Linux and container platforms without proprietary runtime dependencies.

## Prohibited default automation

- ASN-wide blocks.
- Internet route hijacks.
- inter-domain BGP FlowSpec propagation.
- wildcard TLD/registrable-domain blocks.
- CIDR denies broader than exact-host semantics.
- blocks of shared cloud/CDN infrastructure based on one source.
- non-expiring automatic deny rules.
- deny actions authorized by a single behavioral detection family or a single external analytic source.
- model inference anywhere in the enforcement decision path (`docs/28`).
- allow-first enforcement on a segment that has not completed its onboarding lifecycle (`docs/26`).
- challenge actions against non-interactive protocols (`docs/25`).
