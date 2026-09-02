# 11 — Operations Runbook

## Daily operational checks

- controller health;
- feed freshness;
- ingestion error rate;
- evidence backlog;
- decision rate by disposition;
- new automatic actions;
- approval queue;
- adapter health;
- rule drift;
- expiring/expired rules;
- top rule match counts;
- safety-budget events;
- false-positive reports;
- **coverage metrics per segment vs. floor (`docs/24`)**;
- **segment denial volume + novel-destination worklist (`docs/26`)**;
- **active virtual patches past review date / orphaned VPs (must be zero) (`docs/27`)**;
- **behavioral cluster queue (hosts accumulating cross-family evidence) (`docs/23`)**;
- **allowlist entries nearing expiry without review (`docs/26`)**.

## Feed failure

If a feed misses its freshness window:

1. mark source stale;
2. stop adding freshness/corroboration credit;
3. decay evidence according to policy;
4. do not create new auto-enforcement solely from stale evidence;
5. allow existing actions to expire normally unless another source sustains them.

## Sudden feed surge

If a source submits an anomalously large update:

- quarantine the delta;
- remain able to ingest for analysis;
- prohibit auto-enforcement from the quarantined delta;
- require review/corroboration.

## False-positive handling

1. create emergency scoped allowlist if needed;
2. revoke affected action batch;
3. verify restoration;
4. preserve incident evidence;
5. mark source/evidence false-positive association;
6. evaluate whether scoring or hard rules need change;
7. replay candidate policy against historical cases before deployment.

## Adapter drift

When observed device state differs from APIP desired state:

- classify as missing, extra, or modified rule;
- do not automatically delete unknown operator-created rules unless adapter ownership semantics are explicit;
- reconcile APIP-owned rule namespace only;
- alert on repeated drift.

## Emergency stop

Every production deployment needs a control independent of the normal decision path to:

- stop new APIP publications;
- disable APIP-owned rule groups/zones;
- preserve logs;
- leave unrelated operator rules untouched.

## Policy promotion

1. validate schema;
2. run unit/golden tests;
3. historical replay;
4. shadow compile;
5. canary rollout;
6. review metrics;
7. production promotion;
8. record signed release metadata.

## Incident response

If APIP itself is suspected compromised:

- freeze new publications;
- revoke controller/adapter credentials as appropriate;
- validate signing keys;
- compare active device state to last known signed-good bundle;
- restore from known-good policy;
- preserve immutable logs;
- rotate secrets;
- treat unauthorized rule changes as a security incident.

## Compromised internal host (v2, `docs/23`/`25`)

1. behavioral cluster reaches depth ≥ 3 (or active-compromise signal confirms);
2. proposal L6 quarantine auto-prepared with business-function context from asset inventory;
3. approver (OT-operations for OT assets) approves reduced-egress or full isolation;
4. receipts confirm containment; investigation proceeds with preserved evidence;
5. on clearance, host released from quarantine and cluster archived with outcome labels.

## Segment dependency outage (v2, `docs/26`)

A denied dependency report from an allow-first segment:

1. confirm the denial (decision lookup by destination + segment);
2. verify the destination against owner documentation and intelligence;
3. if legitimate: emergency allowlist addition via change control (not break-glass unless time-critical), notify reviewers;
4. if not legitimate: the denial was an interdiction — feed evidence into the behavioral/indicator pipeline and treat as a potential compromise indicator;
5. either way, capture the outcome as inventory feedback (missing dependency = onboarding gap).

## Virtual patch lifecycle (v2, `docs/27`)

1. advisory/KEV scan against inventory daily;
2. VP worklist ordering: VP-3 exposure reduction first, then VP-1/2 as signature quality allows;
3. patch-confirmation events retire VPs automatically — verify retirement receipts;
4. VPs past review date without patch confirmation escalate to the remediation owner.
