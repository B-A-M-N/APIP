# 22 — Operator UI and Workflow Specification

## UI objective

The operator experience should answer five questions without requiring database access:

1. **What is APIP seeing?**
2. **Why does it believe this indicator is malicious?**
3. **Why is a proposed action considered safe or unsafe?**
4. **What would change if I approve it?**
5. **Can I undo it immediately and prove that it was undone?**

## Primary screens

### Overview

Show:

- current global/tenant mode;
- feed freshness and failures;
- pending approvals;
- active actions by actuator/type;
- expiring actions;
- unverified or drifted actions;
- rollout/canary status;
- edge health;
- recent automatic rollback events.

Avoid vanity threat counts. Emphasize actionable state and safety health.

### Indicator/evidence view

Show normalized value, type, aliases, sources, evidence timeline, local sightings, source conflicts, maliciousness score, action-safety score, shared-infrastructure context, freshness, and past outcomes.

Every score should have reason codes and a human-readable explanation.

### Decision view

Show:

- decision ID/hash;
- exact evidence snapshot/version;
- policy and score versions;
- proposed action;
- target edge/tenant/scope;
- TTL;
- expected rule diff;
- projected match/blast-radius data when available;
- approval tier;
- conflicts/allowlist suppressions;
- rollback action.

### Approval queue

Sort/filter by criticality, freshness, action class, tenant, and requested approval tier. The default action is not “approve all.” Bulk approval is disabled for high-risk classes unless an explicit operator policy allows it.

### Active actions

For every live action show apply time, expiry, edge/device revision, match count, health impact, verification status, and revoke control.

### Rollout view

Show rings/cohorts, current policy/bundle version, promotion gate status, safety metrics, halted/reverted rings, and exact reasons for a promotion stop.

### Source health

Show authentication, freshness, object volume, parse failures, sudden-volume anomalies, source reliability, and last successful ingestion. Source administrators can disable a feed but cannot independently expand enforcement scope.

### Audit/replay

Allow an operator to select any historical decision and replay it against its original evidence/policy versions. Display whether current policy would differ, without mutating production. For randomized decisions (`docs/29`), display and reproduce the exact draw from the recorded seed and bounds version.

### Coverage dashboard (v2)

Per-segment chokepoint coverage fraction vs. floor, bypass-trend sparkline, populations on compensating posture, DoH/DoT containment status (`docs/24`).

### Segments and allow-first (v2)

Segment lifecycle stage per segment with promotion gates; SIMULATE preview (what would have been denied, ranked, with owner attribution); denial worklist; allowlist entry expiry/review status; break-glass activation state (`docs/26`).

### Behavioral clusters (v2)

Host clusters accumulating cross-family evidence: families fired, depth, escalation eligibility (L6), analyst actions (`docs/23`).

### Virtual patches (v2)

Active VPs per asset with class, stage, match counts, remediation ticket link and age; orphaned/past-review alarms (must be zero) (`docs/27`).

## Role model

Suggested roles:

- **Viewer:** read-only dashboards and evidence.
- **Analyst:** annotate evidence, create allowlist/exception proposals, request action review.
- **Approver:** approve/reject action classes within assigned scopes.
- **Policy administrator:** modify versioned policy, subject to change workflow.
- **Edge administrator:** enroll/revoke edges and manage actuator credentials.
- **Auditor:** read immutable records and export evidence.
- **Emergency operator:** invoke emergency stop/revoke; use should be tightly controlled and audited.

No role should automatically combine feed administration, policy administration, signing authority, and unrestricted edge administration in a mature provider deployment.

## Required workflows

### Explain a block

```text
user/service report -> search value/time -> matched action -> decision -> evidence/policy -> receipt -> resolve/allowlist/revoke
```

Target: an operator can establish *why* a rule existed without reconstructing logs manually.

### False positive

```text
report -> immediate scoped exception/revoke -> verify restoration -> annotate evidence -> reduce source/reason confidence if justified -> replay -> close
```

### Feed compromise

```text
source alert -> disable/quarantine feed -> identify decisions dependent on source -> recompute -> revoke decisions no longer meeting threshold -> verify edges
```

### Policy change

```text
edit -> schema validate -> replay against golden/historical corpus -> review diff -> sign/version -> shadow/canary -> promote
```

### Emergency stop

One action should prevent **new** enforcement and initiate operator-selected rollback without taking the existing traffic path down. Emergency stop must not require access to the failed component it is intended to bypass.

## CLI parity

Critical UI workflows should have scriptable CLI/API equivalents, including decision explain, approve/reject, policy validate/replay, action revoke, bundle inspect, edge status, and audit export. This supports incident response when the web UI is unavailable.
