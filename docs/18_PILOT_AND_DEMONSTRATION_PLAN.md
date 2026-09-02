# 18 — Safe Pilot, Demonstration, and Transition-to-Practice Plan

## Objective

Demonstrate that one authorized deployment can reduce communication to verified malicious destinations for a protected population **without endpoint agents and without creating unacceptable collateral impact**.

The pilot proves the control-plane thesis; it does not require access to live OT process-control networks.

## Phase 0 — Offline replay

Inputs:

- synthetic indicators;
- historical/sanitized DNS or flow telemetry supplied by the operator;
- representative allowlists;
- known benign shared-hosting/CDN cases;
- known malicious exact-domain/exact-IP cases.

Produce decisions, candidate rules, expected matches, blast-radius estimates, expirations, and rollback events. No live network change occurs.

Exit criteria:

- deterministic replay;
- zero unauthorized-scope actions;
- zero automatic prefix/routing actions;
- false-positive scenarios produce approval/no-action rather than automatic denial;
- all actions have TTLs and receipts;
- malformed feeds fail closed at ingestion, not by blocking traffic.

## Phase 1 — Shadow resolver

Deploy next to an authorized recursive resolver. The adapter compiles RPZ candidates but runs in disabled/log-only/shadow configuration. Compare:

- candidate matches;
- legitimate-domain overlap;
- resolver latency and error metrics;
- allowlist behavior;
- evidence freshness;
- expected expiry behavior.

No query is blocked.

## Phase 2 — Canary exact-FQDN enforcement

Enable only exact FQDN rules meeting the operator's highest confidence/safety thresholds. Requirements:

- short TTL;
- explicit allowlist precedence;
- limited canary population;
- health and customer-impact guardrails;
- one-command/operator rollback;
- no wildcard/parent-zone automation.

This is the preferred first live proof because exact-domain DNS policy is narrower than prefix/routing suppression.

## Phase 3 — Exact-IP shadow and constrained enforcement

Evaluate exact IP rules against flow/firewall telemetry. Shared-infrastructure detection must be active. Begin with alert/rate-limit/shadow semantics. Exact IP deny can be introduced only after replay/canary evidence shows acceptable collateral risk.

No automatic CIDR/prefix denial.

## Phase 4 — Multi-tenant provider pilot

Add tenant isolation and signed bundle distribution. Demonstrate:

- tenant-specific scope;
- shared intelligence without shared enforcement leakage;
- per-tenant policy;
- rollout rings;
- control-plane outage continuity;
- bundle replay protection;
- revocation and expiry across multiple edges.

## Phase 5 — Optional high-risk actuators

Proxy/WAF actions can be added where the operator already controls those systems. Routing/FlowSpec remains a separately governed capability with manual approval, hard prefix limits, propagation controls, and router-lab validation before any production consideration.

## Demonstration scenario

A safe public demo can use only reserved namespaces:

1. ingest `c2-alpha.invalid` from two synthetic sources;
2. correlate a synthetic local resolver sighting;
3. calculate high maliciousness and high action safety for the exact FQDN;
4. emit a SHADOW decision and RPZ artifact;
5. promote policy to an authorized local test resolver;
6. apply the exact test-domain rule;
7. show receipt and simulated match telemetry;
8. expire/revoke the rule;
9. prove the resolver returns to baseline;
10. inject `shared-service.invalid` with high maliciousness but low safety and show that APIP refuses automatic denial — **but selects an L2 rate-limit rung with the L4 domain block instead of doing nothing (v2, `docs/25`)**;
11. **feed a synthetic first-seen high-entropy domain through the DGA family and show behavioral evidence + corroboration gates working (v2, `docs/23`)**;
12. **put a test segment in SHADOW allow-first stage and show the SIMULATE report of what would have been denied (v2, `docs/26`)**;
13. **show a virtual-patch VP-3 proposal with SIMULATE path-usage replay and patch-tracking link (v2, `docs/27`)**;
14. **show a randomized TTL draw recorded with its seed and reproduced exactly on replay (v2, `docs/29`)**.

This demonstrates the key product innovation: **not merely identifying bad infrastructure, but safely converting evidence into bounded, reversible interdiction at one authorized chokepoint — including infrastructure that was never seen before and infrastructure deliberately hidden on shared services.**

## Metrics

Measure separately by actuator and indicator type:

- precision of enforced decisions;
- number/rate of false-positive reports;
- percentage of candidate actions blocked by safety policy;
- time from evidence availability to staged decision;
- time from approval to edge receipt;
- time from rollback/revoke to edge confirmation;
- percentage of actions expired on schedule;
- percentage of decisions with complete provenance;
- traffic/query matches prevented during controlled exercises;
- resolver/firewall/proxy performance impact;
- number of downstream systems/users covered by the single deployment.

## Stop conditions

Automatically halt new enforcement or roll back the current rollout ring if operator-defined conditions are crossed, including:

- unexpected error/latency increase;
- a protected allowlist dependency matches a deny;
- rule volume/change budget exceeded;
- feed provenance/authentication failure;
- edge verification failure;
- large unexpected match volume;
- stale evidence beyond policy threshold;
- loss of policy/signing integrity;
- operator emergency stop.

## Evidence package for a strategic operator

A credible pilot proposal should include:

- threat model;
- scope/authorization model;
- dry-run source code and tests;
- architecture and data-flow diagrams;
- standards mapping;
- sample signed bundle format;
- replay results;
- false-positive and shared-infrastructure test corpus;
- rollback demonstration;
- performance measurements;
- operator runbook;
- security review findings;
- explicit list of functions that remain disabled in the pilot.
