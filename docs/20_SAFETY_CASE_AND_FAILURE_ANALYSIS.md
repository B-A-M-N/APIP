# 20 — Safety Case and Failure Analysis

## Safety claim

Within an explicitly authorized enforcement domain, APIP can automate narrowly scoped defensive traffic controls while bounding the principal systemic hazard: **a false or overbroad decision causing loss of legitimate connectivity**.

The safety case is built from independent controls rather than confidence in one detector.

## Primary hazards

### H1 — False-positive exact-domain block

Controls: source corroboration, exact-name normalization, high M/S threshold, allowlist precedence, short TTL, shadow observation, canary rollout, rapid revoke.

### H2 — Shared IP blocked

Controls: separate action-safety score, shared-infrastructure classification, stricter exact-IP thresholds, prefer rate/observe before deny, no automatic prefix aggregation.

### H3 — Prefix or routing blast radius

Controls: no automatic prefix denial in baseline policy; routing actuator manually approved; prefix limits; operator scope validation at both control plane and edge; propagation constraints; lab validation; TTL and withdrawal receipt.

### H4 — Poisoned threat feed

Controls: feed identity/authentication, schema validation, per-source reliability, source rate limits, independent corroboration, feed cannot directly command an actuator, sudden-change guard.

### H5 — Compromised control plane

Controls: least privilege, signing key isolation, signed desired-state bundles, edge-side scope/safety validation, sequence/replay checks, action budgets, local emergency stop.

### H6 — Compromised edge agent

Controls: limited actuator credentials, tenant/edge-specific authority, no general shell requirement, immutable/remote receipts where feasible, target-device audit, credential rotation, anomaly alerting.

### H7 — Stale evidence/rules

Controls: evidence freshness windows, TTL on every automatic rule, edge-enforced expiry, stale-bundle rejection, reconciliation and stale-rule metrics.

### H8 — Control-plane outage

Controls: no central per-packet dependency, edge continues last-known-good non-expired state, no automatic “block all” failover, health alarm and bounded offline period.

### H9 — Operator mistake/emergency misuse

Controls: role separation, approval tiers, previewed diffs, blast-radius estimates, two-person approval option for high-risk actuators, immutable audit, emergency mode never entered automatically.

### H10 — OT availability impact

Controls: keep APIP outside deterministic process-control loops, coordinate with OT owners, constrain deployment to authorized northbound/DMZ/WAN surfaces, use conservative action classes, validate failover and rollback.

### H11 — Behavioral false positive (v2)

A behavioral family misfires (cron job looks like beaconing; CDN label looks DGA-like) and drives enforcement.

Controls: families are evidence-only; k-of-n decorrelated corroboration before any proposal; deny requires 3 distinct families + external corroboration; population baselines; per-family shadow validation with FP measurement before contributing to enforcement; family-level disable with conservative re-evaluation (`docs/23`).

### H12 — Allow-first outage (v2)

An unenumerated legitimate dependency is denied by a segment and a critical function fails.

Controls: staged onboarding with ≥30-day passive enumeration; SIMULATE replay of what would have been denied with volume ranking and owner attribution; SHADOW ≥2 weeks including a patch cycle; break-glass profiles (dual control, time-boxed, auto-expiring); denied-volume alarms surface missing dependencies as review events, not outages discovered at 3 a.m. (`docs/26`).

### H13 — Virtual patch false positive (v2)

A VP signature drops legitimate traffic to a vulnerable service.

Controls: VP-3 (authorization-context) applied first — cannot FP on exploit bytes; VP-1/2 alert-first staging, match-volume alarms, per-rule auto-revert; scoped only to inventoried vulnerable services; patch-confirmation retirement bounds exposure duration (`docs/27`).

### H14 — Randomization misuse (v2)

Randomized parameters drift outside safe bounds or make behavior unpredictable to operators.

Controls: bounds enforced downstream of the draw (out-of-bounds values impossible to act on); floors never violable; seeds recorded with every decision for exact replay; per-mechanism policy flags; statistical property tests; client-impact budgets respected on the floor side (`docs/29`).

### H15 — Coverage complacency (v2)

Operators believe a population is protected while endpoints bypass the chokepoint via encrypted DNS.

Controls: coverage ledger measures actual coverage per segment; below-floor segments are excluded from protection claims and flagged; compensating-controls posture assigned automatically; DoH/DoT containment reduces the gap where authorized (`docs/24`).

## Fault-injection matrix

| Injected fault | Required behavior |
|---|---|
| malformed feed object | reject object; no action |
| feed authentication failure | quarantine source; preserve current valid state |
| one source marks major CDN IP malicious | evidence recorded; no broad automatic deny |
| clock skew | reject/flag bundles outside tolerated window; never extend action indefinitely |
| policy service unavailable | no new action; edge keeps valid last-known-good rules |
| signer unavailable | no unsigned bundle accepted |
| bundle replay | edge rejects old sequence/version |
| partial device update | adapter reports failure and reverts/repairs to defined desired state |
| receipt missing | action becomes unverified; rollout stops/escalates per policy |
| match volume spike after new rule | canary/guardrail revokes or halts promotion |
| allowlisted dependency conflicts with deny | allowlist wins; conflict logged |
| expired rule still present | reconciliation removes it and raises stale-rule incident |
| routing proposal exceeds prefix scope | hard reject before approval path |
| behavioral family disabled/failed | its evidence decays; dependent decisions re-evaluate conservatively; no orphaned actions |
| randomization subsystem unavailable | parameters fall back to fixed nominal values within bounds; enforcement continues |
| segment allowlist entry expires | entry flagged for review; no silent allow/deny change; alarm raised |
| patch confirmed for active virtual patch | VP rules retire atomically with receipt |
| DoH bypass traffic detected | coverage ledger updated; segment flagged if below floor; compensating posture applied |
| randomized draw (any) | value provably within policy bounds; floor respected; recorded for replay |

## Abuse resistance

APIP should assume an authorized user account can still be misused. Therefore:

- read-only analyst roles cannot approve actions;
- feed administrators cannot silently expand enforcement scope;
- policy administrators cannot bypass edge hard limits without a separately audited configuration change;
- high-risk actuators can require dual authorization;
- the product stores reason codes and evidence hashes for every action;
- emergency actions are time-limited and prominently distinguishable from normal automation.

## Security test classes

Before provider deployment, test:

- parser fuzzing and oversized inputs;
- Unicode/IDNA/domain canonicalization edge cases;
- IPv4/IPv6/CIDR canonicalization and boundary errors;
- tenant-scope confused-deputy cases;
- replay and stale-bundle attacks;
- signing key rotation and revocation;
- allowlist/deny precedence;
- partial actuator failure;
- concurrency/idempotency/reconciliation;
- source poisoning and correlated false intelligence;
- sudden rule-volume changes;
- rollback under actuator/API failure;
- audit-log tampering attempts;
- privilege escalation between analyst/approver/admin/edge roles.

## Release principle

APIP is ready for broader enforcement only when the operator can demonstrate that **safety controls fail independently**. A high confidence score is not a substitute for authorization, scope validation, action-safety scoring, TTL, canary rollout, and rollback.
