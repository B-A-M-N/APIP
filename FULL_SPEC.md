# APIP — Full Product and System Specification

## Specification revision

This is the **v2.1 consolidated specification** (2026-09-01, rev 2.1; rev **2.1.1** closes the adversarial-audit residuals — rate-ceiling semantics, resource-envelope reference detector, keyed pseudonymization, pinned replay clock, provenance independence, evidence envelopes — see `AUDIT_ADVERSARIAL_2026_09_01.md`). It integrates the upgraded design — behavioral detection, encryption/bypass resistance, layered interdiction, allow-first critical segments, virtual patching, AI-era posture, deterministic randomization, and requester attribution — as first-class parts of the platform. Companion documents `docs/23`–`docs/30` are normative alongside `docs/01`–`docs/22`. Where a companion document imposes a stricter safety requirement, the stricter requirement governs.

## 1. Mission

The Attack-Path Interdiction Platform (APIP) is a defensive control plane for turning verified cyber-threat intelligence and local network evidence into reversible, tightly scoped traffic suppression at an **authorized shared communications chokepoint**.

The system is designed around a specific constraint: meaningful defensive value should not require every downstream organization, endpoint, or operational-technology environment to install an agent. A managed resolver, ISP, utility WAN edge, security provider, cloud edge, or other authorized intermediary can deploy APIP once and use it to protect a larger downstream population.

The platform does not claim to create a universal public control layer. Its effectiveness is bounded by where it is deployed and what traffic traverses that enforcement domain.

## 2. Product principles

APIP SHALL follow these principles:

1. **Authorization is a hard boundary.** Enforcement may affect only networks, customer scopes, prefixes, resolvers, proxies, or security devices the operator is authorized to control.
2. **Threat intelligence is evidence, never an instruction.** A feed record cannot directly cause a block.
3. **Separate maliciousness from action safety.** An indicator can be highly likely malicious while still being unsafe to block because it is shared infrastructure or too broad.
4. **Every action is scoped and expiring.** Permanent block entries are the exception and require explicit operator governance.
5. **Availability outranks aggressive automation in OT.** Loss of grid/industrial availability can be more damaging than an unblocked suspicious flow.
6. **No central datapath dependency.** The control plane compiles and distributes local rules; traffic should not depend on a central API call per packet or DNS query.
7. **Shadow before enforcement.** Operators must be able to see exactly what would be blocked and the projected blast radius.
8. **Rollback is a first-class operation.** Every action produces a receipt and has an inverse/revert operation.
9. **Deterministic decisions.** Given the same evidence, policy version, and clock bucket, decision output should be reproducible.
10. **Vendor-neutral core.** Connectors/adapters isolate product-specific enforcement details.

## 3. Intended users and deployment owners

Primary deployment owners:

- Managed DNS/resolver providers.
- Internet service providers and regional carriers.
- Managed security providers.
- Enterprises or utilities with centralized egress/ingress controls.
- Cloud/WAF/security-edge operators.
- Government or sector coordination environments where delegated authority exists.

Secondary users:

- Security operations centers.
- Threat-intelligence teams.
- Network engineering teams.
- OT security teams.
- Incident responders and compliance teams.

## 4. Non-goals

APIP MUST NOT provide or automate:

- Unauthorized access to third-party systems.
- Exploitation, persistence, credential access, destructive actions, or “hack back.”
- Route hijacking or manipulation outside operator-authorized routing policy.
- Denial-of-service attacks against suspected hostile infrastructure.
- Malware deployment.
- Mass internet scanning as a prerequisite for operation.
- Domain or account takedown as its primary mechanism.
- Honeypot or deception dependence. The platform must not expose protected hosts or decoy services to make attackers reveal themselves.
- Endpoint-agent dependence.
- TLS interception/decryption as a platform mechanism. Chokepoint inspection is metadata- and signature-level only.

External validation may use passive/public data sources and ordinary metadata lookups. Any active validation against third-party services must remain within normal, non-invasive client behavior and the operator’s legal/contractual authority.

## 4a. The denylist gap — why v2 adds structural layers

Indicator-based interdiction alone has a structural limitation: it can only block infrastructure that is already known. AI-assisted offensive tooling has collapsed the cost of generating *novel* attack infrastructure (per-victim C2 domains, machine-speed recon, adaptive tooling that probes filters and adapts). A denylist-only chokepoint is therefore always racing detection latency against generation speed.

v2 closes this gap with six mutually-reinforcing layers, each deterministic, none requiring AI, none exposing the host:

1. **Behavioral detection suite** (`docs/23`) — recognizes *classes* of hostile behavior (beaconing, DGA cycling, DNS tunneling, exfiltration volume, first-seen novelty, TLS metadata mismatch) from chokepoint telemetry, as evidence generation feeding the same two-score pipeline.
2. **Encryption/bypass resistance** (`docs/24`) — keeps the chokepoint the practical DNS path (DoH/DoT known-hosts containment), measures coverage continuously, and compensates where covering is impossible.
3. **Layered interdiction** (`docs/25`) — replaces binary block/no-block with an escalation ladder (challenge → rate-limit → allowlist-egress → domain-block → IP-deny → host-quarantine → routing) where each rung is safe on shared infrastructure because it acts on context, not contested identity. This removes the "host C2 on a CDN" safe harbor.
4. **Allow-first critical segments** (`docs/26`) — deny-by-default egress for fixed-function segments (OT boundaries, DMZ vectors, management networks). Novel infrastructure is denied *before first contact* because it is not on the list — the only posture with zero detection latency.
5. **Virtual patching** (`docs/27`) — compiles advisory/exploit signatures into inspection layers and, most deterministically, reduces exposure of vulnerable paths for populations that do not need them, interdicting known-CVE exploit paths while patches lag.
6. **AI-era attack posture** (`docs/28`) — maps each AI-era offensive property to a structural counter that is fully deterministic, and states the no-AI design invariant: the platform's defense does not involve AI anywhere in order to work. AI is a property of the threat model, never a component of the platform.

The v1 safety apparatus — two-score model, TTLs, allowlist precedence, staged enforcement, budgets, signed bundles, edge-side limits — applies unchanged to every new layer. The layers widen safe automation; they do not weaken any v1 guarantee.

## 5. Core functional flow

```text
INGEST → NORMALIZE → CORRELATE → SCORE → POLICY → RUNG-SELECT → STAGE → ENFORCE → VERIFY → EXPIRE/ROLLBACK
                                        ↑                    ↑
                          behavioral detections       randomized parameter draw
                          (docs/23, evidence only)    (docs/29, within policy bounds)
```

### 5.1 Ingest

Input classes:

- STIX 2.1 bundles.
- TAXII 2.1 collections.
- CISA/sector feeds available to the operator.
- Internal SOC indicators.
- DNS telemetry.
- NetFlow/IPFIX metadata.
- Zeek/Suricata observations.
- WAF/proxy logs.
- Operator-created allowlists/denylists.
- Behavioral detection evidence (`docs/23`) — beacon periodicity, DGA-likelihood, DNS tunneling, fast-flux, volume anomalies, first-seen novelty, TLS metadata mismatch, all emitted as evidence records with `origin: local_behavioral`.
- Detection-rule feeds (Suricata/Zeek rule sources) for virtual patching (`docs/27`).
- Denial telemetry from allow-first segments (`docs/26`) — denied egress attempts as high-signal evidence.
- Vulnerability context such as CISA KEV for prioritization, driving virtual-patch worklists (`docs/27`), not as a direct network blocklist.

Each feed receives a source identity, trust profile, update cadence, data marking, and parser version.

### 5.2 Normalize

Indicators normalize into canonical types:

- IPv4 address.
- IPv6 address.
- CIDR prefix.
- FQDN.
- URL.
- file hash.
- certificate fingerprint.
- JA4/other network fingerprint if supported by the operator.
- ASN only as context by default, not an automatically blockable atomic indicator.

Canonicalization includes punycode handling, lowercase FQDNs, normalized IP formatting, validation, deduplication, and source preservation.

### 5.3 Correlate

The evidence layer builds relations among:

- indicators;
- campaigns;
- malware families;
- ATT&CK techniques;
- source reports;
- first/last seen times;
- local observations;
- infrastructure ownership/sharing context;
- prior enforcement outcomes;
- false-positive history.

The initial implementation can use relational tables plus adjacency tables. A graph database is optional and not required to establish product value.

### 5.4 Score

APIP computes two independent scores:

**Maliciousness confidence (M, 0–100):** how strongly evidence supports the conclusion that the specific indicator is associated with malicious activity.

**Action safety (S, 0–100):** how safe it is to apply a proposed control at the operator’s chokepoint without unacceptable collateral impact.

These scores MUST NOT be collapsed into a single opaque model output. Behavioral evidence (BD families) contributes to M/S exactly like feed evidence — decorrelated families corroborate; a single family can never alone justify a deny. **The platform involves no AI, machine learning, or LLM components anywhere in its operation** — every detection, score, and policy evaluation is a deterministic, versioned, replayable computation (`docs/28`). Evidence records carry facts only; all scoring authority lives in the policy weight table and the server-side source registry (`docs/04` v2.1). Output of any AI/ML system is admissible only under the non-authoritative `annotation` source class and cannot alter any score, corroboration count, rung eligibility, or emitted action.

### 5.5 Policy

The policy engine consumes:

- indicator and evidence;
- M and S scores;
- operator scope;
- protected asset/customer class;
- proposed action;
- enforcement adapter capability;
- policy version;
- current mode;
- approval state;
- action TTL;
- allowlist exceptions;
- action budget and blast-radius limits.

The output is one of:

- `NO_ACTION`
- `OBSERVE`
- `SHADOW_ACTION`
- `PROPOSE_OPERATOR_APPROVAL`
- `AUTO_ENFORCE`
- `REVOKE`

### 5.6 Compile

The decision compiler produces a vendor-neutral Enforcement Intent. The intent maps naturally to OpenC2 concepts:

- action: deny, contain, query, allow, update, delete, challenge, rate-limit, quarantine;
- target: domain, IPv4, IPv6, flow, URL, prefix, host, segment;
- actuator: dns-rpz, ips, firewall, proxy-waf, routing, nac;
- modifiers: start time, stop time/TTL, scope, rate, reason, decision ID, response rung.

Every decision carries a **response rung** (L0–L7, `docs/25`) selected deterministically from scores, infrastructure class, and scope, with demotions recorded as reason codes.

### 5.7 Stage and enforce

Before an adapter changes a live device it MUST:

1. validate current operator mode;
2. validate authorization scope;
3. validate object type and blast radius;
4. confirm rule expiry;
5. check allowlist precedence;
6. calculate the delta against currently active rules;
7. enforce maximum change-size limits;
8. create a signed/prepared change set;
9. either require approval or atomically apply it;
10. record the resulting device receipt/version.

### 5.8 Verify

Post-enforcement verification checks:

- the target device accepted the change;
- the rule is present;
- expected traffic matches occur;
- control-plane health remains normal;
- error/latency/customer-impact thresholds remain below limits;
- the change has not produced unexpected high-volume collateral matches.

Verification can automatically revoke a newly introduced rule if a predefined safety condition is exceeded.

## 6. Enforcement classes

### 6.1 DNS RPZ — preferred first enforcement surface

DNS RPZ is a strong first production adapter because it is standardized across major resolver implementations, supports multiple trigger types, allows local exceptions, and can be deployed in disabled/log-only modes before enforcement.

Supported desired actions:

- NXDOMAIN.
- NODATA.
- policy redirect/walled garden where organizationally appropriate.
- DROP only when specifically approved.
- PASSTHRU for allowlist overrides.

Default automation policy:

- exact FQDN: eligible for auto-enforcement at very high M/S thresholds;
- wildcard domains: approval required;
- parent-zone actions: approval required;
- NS/IP-triggered broad policies: approval required.

### 6.2 Firewall / IPS

Used for exact IP/flow interdiction, protocol-aware suppression, per-pair rate ceilings (L2), and virtual-patch signature enforcement (VP-1, `docs/27`).

Default automation policy:

- exact IP only;
- short TTL;
- no automatic prefix block;
- no automatic shared-cloud/CDN IP block unless independent evidence establishes dedicated malicious use and safety checks pass;
- inline drop rules require stricter thresholds than alert-only rules;
- shared-infrastructure endpoints receive L2 rate ceilings (per client/destination pair) instead of destination-wide denies (`docs/25`).

Suricata-style rules are a useful portable artifact, but production adapters should support native firewall APIs as well.

### 6.3 Proxy / WAF / secure web gateway

Useful when the operator controls application-layer ingress or egress. Can enforce domain/URL/path/client reputation decisions with better context than L3/L4 blocking.

Actions can include deny, challenge, rate-limit, or route-to-analysis. Challenge/rate-limit may be safer than immediate deny for uncertain inbound traffic — these are the L1/L2 rungs of the interdiction ladder (`docs/25`) and the VP-2/VP-4 virtual-patch classes (`docs/27`). Challenge is never applied to non-interactive protocols.

### 6.4 NAC / host containment

Where the operator operates NAC or host-firewall management, APIP can scope containment to a single internal asset (L6 host quarantine, `docs/25`): a corroborated behavioral cluster or active-compromise signal justifies restricting that host's egress at the chokepoint while investigation proceeds. Acts on the operator's own assets; no endpoint agent required; approval-gated per `docs/08` OT defaults.

### 6.5 Routing / BGP FlowSpec

Routing-based filtering has the largest blast radius and strongest operational coupling. APIP therefore treats it as a separate high-risk actuator tier.

Rules:

- only operator-owned or explicitly delegated address space;
- no automated inter-domain propagation by default;
- human approval required;
- hard prefix-length and destination-scope constraints;
- mandatory peer/community allowlists;
- max-TTL enforcement;
- precomputed rollback;
- route-policy dry run and route-reflector validation before publish;
- emergency kill switch independent of the APIP controller.

The safe reference scaffold does not implement live BGP actions.

## 7. Confidence model

### 7.1 Evidence categories

Positive evidence may include:

- direct local observation of a network destination tied to a high-confidence detection;
- two or more independent credible intelligence sources;
- signed/curated sector or government intelligence;
- strong temporal correlation with an active campaign;
- specific malware/C2 linkage;
- recent repeated observations;
- consistent certificate/domain/hosting relationship evidence.

Negative or safety-reducing evidence may include:

- shared CDN/cloud hosting;
- sinkhole/research infrastructure;
- large multi-tenant service;
- stale sightings;
- conflicting benign reputation;
- excessive age;
- wildcard/prefix breadth;
- critical vendor/update/service dependency;
- prior false positive.

### 7.2 Deterministic reference formula

The initial product should use explainable deterministic scoring rather than an LLM or opaque classifier in the enforcement path.

Reference maliciousness score:

```text
M = clamp(
      source_reliability
    + independent_corroboration
    + direct_local_observation
    + campaign_specificity
    + recency
    - stale_penalty
    - contradictory_evidence,
    0, 100)
```

Reference action-safety score:

```text
S = clamp(
      exactness
    + dedicated_infrastructure_evidence
    + bounded_customer_scope
    + short_ttl
    + rollback_confidence
    - shared_infrastructure_penalty
    - prefix_breadth_penalty
    - critical_dependency_penalty
    - uncertainty_penalty,
    0, 100)
```

The exact weights are operator policy, versioned and testable.

### 7.3 Default action matrix

The binary matrix below is the v1 core; in v2 each action maps to a **rung** in the layered interdiction ladder (`docs/25`), and shared-infrastructure demotion is automatic:

| Indicator/action | Rung | Auto-enforce eligibility | Default floor |
|---|---|---:|---:|
| Behavioral OBSERVE evidence (single family) | L0 | Yes (evidence only) | M ≥ observe floor |
| Challenge at proxy (interactive paths) | L1 | Yes | M≥85 and S≥75 |
| Rate limit per client/destination pair | L2 | Yes | M≥90 and S≥80 |
| Segment egress allowlisting (fixed segments) | L3 | After segment onboarding approval | approval-gated |
| Exact FQDN → RPZ NXDOMAIN | L4 | Yes | M≥95 and S≥90 |
| Exact URL → proxy deny | L4 | Yes | M≥95 and S≥90 |
| Exact IP → firewall deny | L5 | Limited | M≥98 and S≥95 + dedicated-use |
| Host quarantine (own asset) | L6 | Limited | 3-family cluster + approval |
| CIDR prefix → firewall deny | — | No | Approval required |
| Wildcard domain → RPZ | — | No | Approval required |
| BGP FlowSpec filter | L7 | No | Dual approval required |
| ASN-wide action | — | No | Prohibited by default |

Hard demotion rules (deterministic, recorded as reason codes): shared infrastructure class → rung capped at L4; no dedicated-use evidence → L5 demotes to L4; L6 requires behavioral-cluster depth ≥ 3 or an active-compromise signal. These are reference defaults, not universal truth. The operator owns the risk policy.

## 8. Safety budgets

Every enforcement domain must define budgets such as:

- maximum new auto-enforced rules per five-minute window;
- maximum customer population affected by one decision;
- maximum matched requests/flows per minute for a newly activated rule before automatic review;
- maximum IPv4/IPv6 breadth;
- maximum TTL by action class;
- maximum simultaneous emergency actions;
- maximum percentage change in active rule set per rollout;
- **maximum fraction of a tenant's interactive transactions challenged per hour (L1 client-impact budget)**;
- **maximum per-pair rate-limit ceiling relative to observed legitimate baseline (L2)**;
- **denied-volume alarm thresholds per allow-first segment (`docs/26`)**.

If a budget is exceeded the system enters `PROPOSE_OPERATOR_APPROVAL`, not silent degradation into more aggressive enforcement.

## 9. Allowlist and exception semantics

Allowlist precedence is absolute unless the operator explicitly chooses a break-glass emergency override.

Allowlist entries must support:

- indicator/value;
- tenant/customer scope;
- reason;
- owner;
- created/updated time;
- expiration;
- ticket/reference;
- signature/approver for sensitive scopes.

A rule touching an allowlisted value produces an audit event and is not enforced.

## 10. Multi-tenant model

For provider deployment, the system must isolate:

- customer policies;
- customer telemetry;
- customer allowlists;
- enforcement scopes;
- reporting;
- data-retention settings.

A provider may maintain a global high-confidence policy layer and customer-specific overlays. Global rules MUST still permit customer exceptions unless contractually and explicitly configured otherwise.

## 11. Data model

Core objects:

### Indicator

```json
{
  "id": "indicator--...",
  "type": "fqdn",
  "value": "example.invalid",
  "sources": ["source-a"],
  "first_seen": "...",
  "last_seen": "...",
  "marking": "TLP:CLEAR",
  "tags": ["c2"],
  "evidence": [],
  "expires_at": "..."
}
```

### Decision

```json
{
  "id": "decision--...",
  "indicator_id": "indicator--...",
  "maliciousness": 97,
  "action_safety": 94,
  "disposition": "AUTO_ENFORCE",
  "action": "dns_nxdomain",
  "rung": "L4",
  "scope": "tenant-a",
  "ttl_seconds": 3600,
  "policy_version": "2026-09-01.1",
  "reason_codes": ["multi_source", "exact_fqdn", "recent"],
  "randomization": {"mechanism": "ttl_jitter", "bounds_version": "rv-2026-09-01.1", "seed_id": "seed--...", "draw": {"ttl_seconds": 3120}}
}
```

Behavioral evidence records (BD families, `docs/23`) are ordinary Evidence objects with `origin: local_behavioral`, a feature vector, and the family version; segment and asset objects (`docs/26`/`27`) are first-class entities with owners and review cadence.

### Enforcement intent

```json
{
  "command_id": "cmd--...",
  "action": "deny",
  "target": {"domain_name": "example.invalid"},
  "actuator": {"type": "dns-rpz"},
  "modifiers": {"duration": 3600, "scope": "tenant-a"}
}
```

### Receipt

Records compile/apply/verify/revoke outcomes and device-specific revision identifiers.

## 12. APIs

Suggested northbound API:

- `POST /v1/indicators`
- `POST /v1/stix/bundles`
- `POST /v1/observations`
- `POST /v1/behavior-events` (behavioral family output ingest, `docs/23`)
- `GET /v1/segments` / `POST /v1/segments/{id}/stage-transitions` (`docs/26`)
- `POST /v1/virtual-patches` / `GET /v1/virtual-patches` (`docs/27`)
- `GET /v1/coverage` (chokepoint coverage ledger, `docs/24`)
- `GET /v1/indicators/{id}`
- `GET /v1/decisions`
- `GET /v1/decisions/{id}`
- `POST /v1/decisions/{id}/approve`
- `POST /v1/decisions/{id}/revoke`
- `GET /v1/actions`
- `GET /v1/actions/{id}/receipts`
- `GET /v1/policy`
- `POST /v1/policy/validate`
- `GET /v1/health`
- `GET /v1/metrics`

All mutation APIs require authenticated operator identity and explicit authorization. High-risk approval endpoints should support two-person control.

## 13. Internal service boundaries

Recommended initial components:

1. `ingestd` — connectors, TAXII polling, file/webhook ingestion.
2. `normalizer` — canonicalization and schema validation.
3. `evidence` — deduplication, relationships, source trust, expiry.
4. `decisiond` — deterministic scoring and policy evaluation.
5. `ledgerd` — append-only decision/action history.
6. `compilerd` — vendor-neutral intent → adapter-specific artifact.
7. `adapterd` — per-target apply/verify/revoke interface.
8. `reaper` — TTL expiration and revocation.
9. `api` — operator/API surface.
10. `ui` — optional administrative UI/TUI.

For the first implementation these can be modules in one process with clean interfaces rather than microservices. Split them only when scale or trust-boundary requirements justify it.

## 14. Persistence

Minimum durable stores:

- PostgreSQL for authoritative entities/decisions/policy metadata.
- Object storage or immutable files for raw feed snapshots and signed policy bundles.
- Optional event bus at provider scale.

The ledger should be append-oriented. Materialized “current state” tables may be rebuilt from signed policy and action events.

## 15. Cryptographic controls

Production design:

- TLS for all control-plane communication.
- mTLS for adapter agents where feasible.
- signed policy bundles.
- signed action batches for high-risk actuators.
- short-lived service credentials.
- least-privilege device/API credentials isolated per adapter.
- HSM/TPM-backed signing for provider/routing environments where justified.

## 16. Failure behavior

The preferred failure mode is **no new change**, not “block everything” and not “allow the controller to become a datapath dependency.”

- Controller unavailable: deployed last-known-good rules continue until their local TTL/reconciliation policy expires.
- Feed unavailable: no confidence inflation; source freshness decays.
- Database unavailable: no new enforcement actions.
- Adapter partially fails: mark batch incomplete, stop rollout, and reconcile.
- Policy engine error: fail closed for *change authorization* (do not publish new blocks).
- Telemetry failure: do not automatically increase enforcement severity.

## 17. OT and energy-specific requirements

APIP should normally sit **outside** the safety-critical control loop:

```text
Internet / WAN
      |
[APIP-controlled edge]
      |
Enterprise / DMZ / remote-access boundary
      |
OT DMZ / ESP controls
      |
Control network
```

It should not require an inline dependency inside PLC/relay/protection traffic paths.

OT deployment defaults:

- prefer DNS/egress/inter-zone controls at existing boundary devices;
- prohibit automatic broad network blocks;
- use short TTLs;
- maintain explicit critical-vendor/update allowlists;
- require change windows or operator approval for controls that may affect control-center communications;
- preserve evidence needed for NERC/CIP or incident-response workflows where applicable;
- integrate with established ESP/EACMS architecture instead of bypassing it.

## 18. Standards alignment

### NIST CSF 2.0

- Govern: policy ownership, approvals, change control, audit.
- Identify: scope, assets, dependencies, threat context.
- Protect: preventive network controls.
- Detect: local telemetry, matches, anomalies.
- Respond: containment/interdiction actions and playbooks.
- Recover: rule rollback, restoration, lessons learned.

### NIST SP 800-61 Rev. 3

APIP supports incident-response integration by preserving evidence, decisions, mitigation actions, communication metadata, and recovery/rollback outcomes.

### CISA CPGs / DOE-NARUC energy baselines

APIP is a tool that can support prioritized network defense, monitoring, and incident mitigation. It is not itself a compliance framework.

### STIX/TAXII

Use as interoperability at the threat-intelligence boundary; do not force all internal objects to remain raw STIX.

### OpenC2

Use as the conceptual command contract between decisions and actuators. Device-specific details live in profiles/adapters.

### CACAO

Use for operator-reviewed response/playbook workflows, especially multi-step actions such as observe → validate → approve → enforce → verify → revoke.

### OCSF

Use for normalized telemetry/event export to SIEM/data-lake consumers.

### NERC CIP

Where the deploying organization is a covered entity, APIP must be integrated into the entity’s compliance scope and change/incident/evidence processes. Applicability must be determined by the entity; APIP does not declare systems to be BES Cyber Systems.

## 19. Minimum viable product

The MVP is intentionally narrow:

1. ingest local JSON plus STIX 2.1;
2. normalize FQDN/IP indicators;
3. deterministic evidence score;
4. policy engine with observe/shadow/enforce modes;
5. DNS RPZ compiler;
6. Suricata/firewall rule compiler;
7. immutable decision/action log;
8. TTL expiry;
9. allowlists;
10. dry-run and replay test harness;
11. operator API/CLI;
12. metrics and receipts;
13. **ladder-aware action selection with shared-infrastructure demotion (L1–L5 paths, `docs/25`)**;
14. **one behavioral family (BD-2 DGA-likelihood or BD-1 beacon periodicity) as deterministic evidence, `docs/23`**;
15. **segment object model with lifecycle state machine (SHADOW stage implementable without live enforcement, `docs/26`)**.

The MVP is successful if it can demonstrate, in a lab or authorized pilot, that a single central deployment can safely distribute high-confidence short-lived blocking policies to one or more shared enforcement points and prove exactly what was blocked, why, for how long, and how it was reversed — **and that a shared-infrastructure indicator produces a safe L2/L4 composed response rather than nothing, and a never-before-seen DGA-like domain produces at minimum behavioral evidence and a rate-limit candidate rather than silence.**

## 20. Provider-grade target state

Provider-grade APIP adds:

- multi-tenant policy and telemetry isolation;
- HA controllers;
- signed bundle distribution;
- per-edge local adapter agents;
- canary rollout;
- customer-specific exceptions;
- high-volume streaming telemetry;
- scalable decision ledger;
- SLO/SLA monitoring;
- approval workflows;
- routing adapter under stricter governance;
- external SIEM/SOAR integration;
- policy simulation against historical traffic.

## 21. Success metrics

Security efficacy:

- malicious connection attempts suppressed;
- time from high-confidence intelligence receipt to safe policy publication;
- confirmed C2/phishing/malware resolution attempts blocked;
- campaign reuse detected across tenants without leaking tenant-specific data;
- **time from first behavioral signal (first-seen contact, beacon onset, tunneling signature) to first interdiction action — the novel-infrastructure latency metric (`docs/23`)**;
- **chokepoint coverage fraction by population segment (`docs/24`)**;
- **denied-egress count and mean time to triage on allow-first segments (`docs/26`)**;
- **exploit attempts rejected by virtual patches while patches lagged; orphaned-VP count (must be zero) (`docs/27`)**;
- **enforcement-collision rate against adaptive probing (randomization effect, `docs/29`)**.

Safety:

- false-positive rate;
- rules auto-revoked due to safety thresholds;
- percentage of actions first proven in shadow mode;
- change rollback success;
- customer-impact incidents attributable to APIP;
- **client-impact budget utilization for L1/L2 rungs (`docs/25`)**.

Operational efficiency:

- manual analyst minutes per actionable indicator;
- mean time to explain a decision;
- adapter reconciliation success;
- stale-rule count;
- percentage of actions with complete evidence/receipt chain;
- **allowlist entry review currency (percentage unexpired-reviewed, `docs/26`)**.

## 22. Release philosophy

The system should not be considered production-ready because it “can block.” It is production-ready only when it can reliably **refuse unsafe blocks, explain allowed blocks, stage them, prove they were applied, observe impact, expire them, and roll them back**.


## 23. Advanced production specifications

The consolidated design is expanded in the following normative companion specifications:

- `docs/16_ADVANCED_ANALYTICS.md`: analytics can enrich evidence but never bypass deterministic policy.
- `docs/17_PROVIDER_SCALE_AND_SLOS.md`: control-plane/edge separation, tenant isolation, signed bundles, rollout rings, backpressure, DR, and measurable SLO fields.
- `docs/18_PILOT_AND_DEMONSTRATION_PLAN.md`: staged proof from offline replay through resolver shadow/canary and provider multi-edge validation.
- `docs/19_CONTROLS_AND_STANDARDS_MAPPING.md`: engineering crosswalk to NIST CSF 2.0, NIST SP 800-61r3, CISA CPGs, DOE/C2M2, NERC CIP, STIX/TAXII, OpenC2, CACAO, OCSF, RPZ, Suricata, and FlowSpec.
- `docs/20_SAFETY_CASE_AND_FAILURE_ANALYSIS.md`: explicit hazard model, independent controls, fault injection, and abuse resistance.
- `docs/21_REFERENCE_DEPLOYMENT_BLUEPRINT.md`: concrete production component boundaries, storage, signing, adapter, reconciliation, credential, and release architecture.
- `docs/22_OPERATOR_UI_AND_WORKFLOWS.md`: explainability, approvals, live-action health, revoke, rollout, source health, and replay workflows.
- `docs/23_BEHAVIORAL_DETECTION_SUITE.md`: deterministic detection families (beaconing, DGA, tunneling, fast-flux, volume, novelty, TLS mismatch) as evidence generators; corroboration lattice; anti-gaming.
- `docs/24_ENCRYPTION_AND_BYPASS_RESISTANCE.md`: DoH/DoT known-hosts containment, coverage accounting, compensating posture for non-coverable paths.
- `docs/25_LAYERED_INTERDICTION_AND_SHARED_INFRASTRUCTURE.md`: the L0–L7 response ladder; context-acting rungs that remove the shared-infrastructure safe harbor; shared-infrastructure registry.
- `docs/26_ALLOW_FIRST_MODE_FOR_CRITICAL_SEGMENTS.md`: deny-by-default egress for fixed-function segments; onboarding lifecycle; denial telemetry as evidence.
- `docs/27_VIRTUAL_PATCHING_AND_EXPLOIT_PREVENTION.md`: VP-1–VP-4 virtual patch classes; exposure reduction; patch-tracking expiry; asset inventory as a platform object.
- `docs/28_AI_ERA_ATTACK_POSTURE.md`: the no-AI design invariant; deterministic counters to AI-era offensive properties; evidence-channel injection resistance; automation abuse resistance.
- `docs/29_DETERMINISTIC_RANDOMIZATION.md`: moving-target defense via seeded randomization of defensive parameters within policy bounds; replay-preserving.
- `docs/30_REQUESTER_ATTRIBUTION_AND_FINGERPRINTING.md`: deterministic challenge-based requester fingerprinting for campaign correlation; attribution output is never an enforcement input.
- `api/openapi.yaml`: draft API contract.
- `schemas/*.json`: canonical object/policy schemas.
- `sources.json`: machine-readable research inventory.

These documents are part of the specification, not optional commentary. Where a companion document imposes a stricter safety requirement than an earlier overview, the stricter requirement governs.

## 24. Product maturity ladder

APIP has four intentionally distinct maturity states:

1. **Reference scaffold** — offline/dry-run logic and portable artifacts only.
2. **Engineering prototype** — real feed parsing, persistent evidence/ledger, still no unattended live enforcement.
3. **Authorized pilot** — shadow plus narrowly bounded live exact-FQDN/exact-IP actions at a cooperating operator's chokepoint.
4. **Provider-grade platform** — multi-tenant signed bundle distribution, independent edge safety enforcement, HA/DR, security review, audited approvals, SLOs, and demonstrated rollback.

No stage may claim the guarantees of a later stage merely because the code path exists.

## 25. Core acceptance theorem

The product thesis is considered demonstrated only when a controlled evaluation shows all of the following simultaneously:

- a single authorized chokepoint deployment covers many downstream systems without endpoint agents;
- verified malicious communication attempts are converted into bounded controls quickly enough to be operationally useful;
- **novel, never-before-seen attack infrastructure is interdicted before or at first contact for allow-first segments, and detected at first contact everywhere else** (v2 addition);
- **shared-infrastructure C2 receives a composed interdiction posture (challenge/rate-limit/domain-block/host-quarantine) instead of a safe harbor** (v2 addition);
- shared/ambiguous infrastructure is prevented from becoming unsafe automatic denial;
- actions expire and roll back reliably;
- loss of the APIP controller does not interrupt the protected traffic path;
- every action is attributable to an evidence snapshot, policy version, scope, approval state, edge application receipt, and outcome;
- **the platform's full defensive capability is demonstrated with zero AI components** (v2 invariant).

That is the distinction between APIP and a threat-feed aggregator, blocklist generator, honeypot, or takedown workflow.
