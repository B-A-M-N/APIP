# 14 — Acceptance Criteria

## Gate A — Research prototype

All must pass:

- dependency-free or pinned reproducible build;
- deterministic score tests;
- exact FQDN/IP normalization;
- hard safety invariants;
- allowlist precedence;
- action TTL;
- decision explanation;
- RPZ file compile;
- Suricata file compile;
- no live actuator access in default scaffold;
- all examples use reserved/test values.

## Gate B — Authorized lab pilot

- PostgreSQL-backed ledger;
- STIX ingestion;
- shadow DNS zone on real resolver;
- adapter prepare/apply/verify/revoke interface;
- signed policy bundle prototype;
- historical replay;
- action budgets;
- false-positive injection test;
- controller outage test;
- adapter drift detection;
- rollback proven.

## Gate C — Limited production pilot

- explicit operator authorization boundary documented;
- resolver/firewall canary group;
- customer/critical-vendor allowlists loaded;
- on-call ownership;
- emergency stop proven;
- no broad automatic actions;
- metrics/alerts integrated;
- privacy/retention policy approved;
- policy promotion workflow enforced;
- post-action verification and auto-revoke thresholds enabled.

## Gate D — Provider-grade

- multi-tenant isolation tested;
- HA controller and database;
- signed edge bundles;
- edge scope enforcement;
- high-volume performance test;
- canary rollout automation;
- customer-specific exceptions;
- audit export;
- disaster recovery exercise;
- security review/penetration test;
- operational SLOs defined.

## Gate V2-A — Layered interdiction + behavioral evidence

- ladder rung selection deterministic and test-covered, including demotion reason codes;
- shared-infrastructure registry drives L5→L4 demotion (property test);
- at least two behavioral families implemented with deterministic replay proven;
- single-family evidence cannot produce a deny disposition (property test);
- k-of-n corroboration rule enforced and visible in decision explanations;
- client-impact budgets trip correctly on L1/L2 rungs.

## Gate V2-B — Allow-first segments

- segment lifecycle state machine implemented, including backwards transitions and break-glass expiry (offline expiry proven);
- SIMULATE report produces volume-ranked denied-destination preview with owner-attribution fields;
- SHADOW stage reports novel-destination rate before any enforcement;
- governed allowlist entries all owned/ticketed/unexpired;
- denial telemetry flows into evidence and BD-6;
- platform OFF does not disable an enforcing segment; EMERGENCY tightens segments to break-glass profiles (tested).

## Gate V2-C — Virtual patching

- inventory objects exist and drive VP class selection;
- VP-3 SIMULATE 30-day path-usage replay produced before any enforcement;
- VP-1/2 never in drop mode without prior shadow/alert evidence;
- retirement on patch confirmation tested; orphaned-VP alarm tested;
- no VP outlives its vulnerability without review (property test).

## Gate V2-D — Randomization and no-AI conformance

- all draws through the deterministic DRBG abstraction (SHA-256 counter mode) with recorded seeds — documented as parameter diversity, not a secret-key CSPRNG;
- replay-with-seed reproduces exact outputs (CI);
- draws provably within bounds; floors never violated (property tests);
- adaptive-attacker simulation shows measurable suppression vs. fixed parameters;
- dependency review confirms zero AI/ML/LLM components in the platform;
- automation-abuse controls verified: per-principal budgets, human gates on high-risk classes, audit flags.

## Gate V2-E — Attack-surface closure pack

- plaintext-53 redirect functions for a hardcoded-resolver test device; exceptions expire; resolver baseline verified (no open recursion, DNSSEC, RRL);
- allowlist entries default to tuple form; destination-only requires recorded justification; profile-drift alarm fires on synthetic deviation and never auto-enforces;
- capacity ceilings throttle (not drop) above threshold; break-glass exemption works and re-arms;
- BD-8 fires on a synthetic multi-host first-contact pattern and stays silent for single-host novelty; population-scaled N recalculates with population;
- an undocumented listener on operator-owned space becomes an incident finding within one scan/diff cycle; scan scope cannot be configured outside operator-owned space (hard test);
- controller segment enforce-mode proven with agents pull-only; an inbound connection attempt to an agent is refused by design.

## Gate E — Routing adapter

Additional mandatory criteria:

- separate network-engineering approval;
- dedicated authorized routing lab passed;
- router-side prefix/community constraints independently configured;
- only authorized destination scopes possible;
- manual approval cannot be bypassed;
- route-policy simulation passed;
- rollback under controller loss proven;
- inter-domain propagation disabled unless explicitly engineered and approved.
