# 03 — Threat Model

## Assets to protect

1. Integrity of enforcement policy.
2. Availability of downstream networks.
3. Confidentiality of tenant/customer telemetry.
4. Adapter credentials and signing keys.
5. Audit/decision history.
6. Feed provenance and raw evidence.
7. Operator identity and approval workflow.

## Primary adversarial/failure scenarios

### TM-001 Threat-feed poisoning
An attacker causes a legitimate domain/IP to appear in a feed to induce defensive denial-of-service.

Mitigations:

- feed records never directly enforce;
- independent-source corroboration;
- source reliability profiles;
- action-safety scoring;
- shared-infrastructure detection;
- TTLs;
- shadow mode;
- allowlists;
- feed anomaly limits.

### TM-002 Compromised feed account or TAXII server
Mitigations:

- TLS and credential validation;
- object size/rate limits;
- source-specific change budgets;
- compare update distributions to historical norms;
- quarantine sudden large changes;
- require independent corroboration for auto-enforcement.

### TM-003 Compromised APIP controller
Impact could include malicious policy distribution.

Mitigations:

- least privilege;
- separate signing key from web/API identity;
- signed bundles;
- adapter-side hard safety constraints;
- two-person approval for broad actions;
- independent kill switch;
- immutable logs;
- short-lived credentials;
- no shared root credential across adapters.

### TM-004 Compromised adapter agent
Mitigations:

- scope-limited device credentials;
- one enforcement domain per credential;
- controller reconciles device state;
- agent cannot originate globally trusted policy;
- host hardening and mTLS.

### TM-005 False-positive outage
This is one of APIP's highest-risk failure classes.

Mitigations:

- separate M and S scores;
- broad actions require approval;
- shadow mode;
- match-rate alarms;
- canary deployment;
- local exception lists;
- auto-revoke thresholds;
- max TTL;
- rapid rollback receipts.

### TM-006 Shared-cloud collateral damage
A malicious service may coexist with legitimate services on a cloud/CDN IP.

Mitigations:

- treat hosting provider/ASN as context, not proof;
- prefer domain/URL controls over shared IP blocks;
- large penalty to S for multi-tenant infrastructure;
- exact-IP deny only at very high confidence and dedicated-use evidence.

### TM-007 Stale intelligence
Mitigations:

- age decay;
- explicit feed freshness;
- indicator expiry;
- action TTL less than or equal to evidence TTL unless reviewed;
- no indefinite automatic blocks.

### TM-008 Replay / rollback corruption
Mitigations:

- immutable event IDs;
- monotonic policy/bundle versions;
- previous-bundle hash chain;
- idempotency keys for adapter actions;
- rollback uses recorded device revision, not only reconstructed desired state.

### TM-009 Clock manipulation
TTL and freshness depend on time.

Mitigations:

- authenticated NTP/time monitoring;
- monotonic timers for local action expiry where possible;
- reject policy bundles with implausible timestamps;
- record controller and adapter clock delta.

### TM-010 Privacy leakage across tenants
Mitigations:

- tenant-scoped identifiers;
- separate authorization scopes;
- aggregate only non-sensitive campaign conclusions into global policy;
- minimize raw payload retention;
- redact or hash where operationally sufficient.

### TM-011 Unsafe routing rule
Mitigations:

- routing adapter disabled by default;
- authorized destination-prefix allowlist;
- no auto propagation;
- manual approval;
- route-policy simulation;
- max NLRI/action count;
- independent router-side prefix/community filters;
- short expiry.

### TM-012 Operator error
Mitigations:

- policy validation;
- preview exact diff;
- approval for broad scopes;
- typed target/action schemas;
- rollback test before production promotion;
- configuration linting.

### TM-013 Novel infrastructure at machine speed (AI-generated)
An attacker generates per-victim C2 domains/infrastructure that has never appeared in any feed, defeating indicator matching entirely.

Mitigations:

- behavioral detection families produce evidence on never-before-seen destinations (`docs/23`);
- k-of-n decorrelated-family corroboration before any enforcement proposal;
- allow-first segments deny novel egress destinations by default — zero detection latency (`docs/26`);
- domain-class evidence (DGA-likelihood bands) rather than instance matching;
- randomized detection thresholds dither within policy bands so shaped evasion does not transfer (`docs/23`/`29`).

### TM-014 Chokepoint bypass via encrypted DNS
Endpoints use DoH/DoT/DoQ to public or attacker resolvers, routing around resolver-layer policy.

Mitigations:

- known-hosts DoH/DoT containment at egress (block 853 and known DoH endpoints except the managed resolver; answer bootstrap lookups with the operator policy response) (`docs/24`);
- coverage ledger makes residual bypass a measured, reported risk object rather than an assumption;
- behavioral families on flow metadata (which encrypted DNS does not hide) compensate on non-coverable paths;
- v4/v6 parity requirements prevent sparse-rule family bypass.

### TM-015 Shared-infrastructure safe harbor
An attacker deliberately hosts C2 on shared cloud/CDN/anonymizer infrastructure, correctly betting the platform will refuse to block contested IPs.

Mitigations:

- the layered interdiction ladder acts on context rather than identity (`docs/25`): challenge (L1), per-pair rate ceilings (L2), exact-FQDN domain block (L4), and host quarantine (L6) all remain safe on shared infrastructure;
- demotion is recorded, not silent — operators see why L5 was withheld;
- anonymizer class policy (challenge/rate-limit by default) with per-segment block-by-context;
- sustained rate-limited beaconing at ceiling is continued-compromise evidence feeding L6.

### TM-016 Adaptive filter probing
Automated tooling observes defensive responses and shapes traffic to sit just under fixed thresholds (beacon jitter above detection floor, volume below ceiling, challenges avoided).

Mitigations:

- thresholds are operator-private, population-baselined, and dithered within bands (`docs/23`, `docs/29`);
- corroboration lattice requires defeating all decorrelated families simultaneously;
- seeded randomization of ceilings/challenge sampling/TTL jitter makes past observation a poor predictor (`docs/29`);
- near-miss clusters produced by probing are themselves evidence;
- residual: slow-and-quiet operation remains possible at material capability cost (documented residual risk, `docs/28`).

### TM-017 Exploit window on unpatchable services
A published CVE is actively exploited against exposed services that cannot be patched for weeks (OT change windows, legacy systems).

Mitigations:

- virtual patch classes VP-1–VP-4 (`docs/27`), with exposure reduction (VP-3) applied first as the deterministic floor;
- patch-tracking expiry links every VP action to a remediation ticket; VPs never silently persist;
- SIMULATE-stage path-usage replay prevents VP-3 from breaking needed access;
- allow-first segments additionally deny novel C2 egress from compromised hosts.

### TM-018 Injection via evidence channels
Attacker-controlled strings (feed text, domain names, URLs) carry payloads aimed at analytic or policy layers — including payloads that attempt to smuggle score points, origin/family claims, independence flags, or a trusted `source_class` into an evidence record.

Mitigations:

- no LLM, interpreter, or generated logic exists in any operational path (`docs/28`) — the classic injection target does not exist;
- evidence records carry **facts only** (`docs/04` v2.1): score fields (`points_m`/`points_s`/`origin`/`family`/`independent`/`source_class` in a payload) are stripped on ingestion and ignored server-side — the weight table and source registry are the sole scoring authority;
- `source_class` and independence are assigned server-side from the governed source registry, never read from the payload;
- strict per-type grammars reject malformed values rather than interpreting them;
- policy is declarative schema-validated data, never generated or self-modified at runtime;
- provenance-preserving records allow poisoned evidence removal and decision re-evaluation.

### TM-019 Automation/agent abuse of the platform
A hijacked operator script, SOAR integration, or agentic client attempts to flood approvals or push bulk changes.

Mitigations:

- programmatic clients share human RBAC — no machine privilege escalation (`docs/28`);
- high-risk classes stay human-gated; automation may prepare, never approve;
- per-principal proposal-rate and change-volume budgets;
- automation distinguishable in audit (principal + automation flag + session);
- signing authority never granted to programmatic clients;
- full reversibility of everything automation caused.

### TM-020 Randomization subsystem compromise
Recorded seeds or the CSPRNG layer are attacked to predict draws or manipulate draws outside bounds.

Mitigations:

- bounds are enforced downstream of the draw: any value outside policy bounds is impossible to act on regardless of RNG behavior (`docs/29`);
- seeds are recorded for replay, but knowing a seed does not help an attacker who cannot observe future evidence snapshots and clock buckets;
- per-mechanism independent streams prevent cross-mechanism inference;
- property tests verify draws are always in-bounds and floors respected.

### TM-021 Plaintext DNS bypass
Endpoints or appliances with hardcoded external resolvers send plain UDP/53–TCP/53 traffic that never touches managed-resolver policy — bypass without encryption.

Mitigations: outbound 53 restricted to enumerated resolvers with **redirect-to-managed (DNAT) as the preferred form** (function-preserving, gains full policy/telemetry visibility); governed per-device exceptions; resolver baseline (no open recursion, DNSSEC validation, response-rate limiting) (`docs/24`).

### TM-022 Allowed-dependency envelope abuse
A compromised allowed dependency (vendor server, update server) inherits the whole allowlist envelope — any port/protocol/volume — from a bare destination entry.

Mitigations: tuple-form entries `(destination, protocol, port-range)` by default with justified exceptions; per-entry traffic profiles (volume band, cadence, peer scope) whose **drift is an incident signal, never an enforcement trigger**; capacity ceilings on constrained segments bound exfiltration to ceiling rate (`docs/26`/`25`).

### TM-023 Distributed low-and-slow first contact
An attacker distributes a campaign across many hosts so no single host shows enough per-host novelty (BD-6) to fire.

Mitigations: BD-8 population-scale synchronized first-contact detection — N hosts contacting the same never-seen destination within a bounded window, N population-scaled to defeat tiny-cohort evasion; decorrelated from all per-host families (`docs/23`).

### TM-024 Undocumented inbound exposure
Misconfiguration, shadow services, or an attacker-opened pivot listener persist silently because VP-3 only reduces exposure per advisory.

Mitigations: standing exposure inventory with continuous config diff and periodic authorized scan of operator-owned space only; an undocumented listener is an incident by default — the inbound mirror of BD-6 (`docs/27`).

### TM-025 Compromise of APIP itself as force multiplier
The control plane is the highest-value target in the deployment.

Mitigations: controller in its own allow-first segment; pull-only edge agents (no inbound listeners); adapter egress pinned to specific device APIs; HSM/KMS-isolated signing; the full TM-003/TM-004/H5/H6 controls apply unchanged (`docs/09`).

## Security invariants

- No source record can directly reach an actuator.
- No automatic action may lack an expiry.
- No adapter may enforce outside its configured scope.
- No broad routing action may be automatic in the default product policy.
- No allowlisted target may be automatically denied.
- No enforcement decision may be untraceable to a policy version and evidence snapshot.
- No deny action may rest on a single behavioral family or single external analytic source.
- No randomized parameter may exceed its policy bounds or weaken a safety floor (`docs/29`).
- No AI/model inference may appear in any operational path (`docs/28`).
- No segment may enforce allow-first posture without completing its onboarding lifecycle (`docs/26`).
