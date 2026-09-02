# 17 — Provider-Scale Architecture, Multi-Tenancy, and SLO Model

## Provider topology

APIP should scale as a **control-plane / edge-actuator** system, not a centralized inline packet-processing service.

```text
                    CONTROL PLANE
  feeds -> normalize -> evidence -> policy -> signed bundles
                                  |              |
                                  v              v
                           decision ledger   rollout manager
                                                  |
                   +------------------------------+-------------------+
                   |                              |                   |
                   v                              v                   v
             resolver edge                  firewall edge       proxy/WAF edge
             local rules                    local rules          local rules
                   |                              |                   |
                   +---------- operator-owned traffic --------------+
```

A temporary control-plane outage MUST NOT interrupt traffic. Edges continue using the last valid, non-expired policy bundle and local platform defaults.

## Control-plane services

A production decomposition can include:

- **ingest gateway** — feed authentication, TAXII/client connectors, schema validation;
- **normalizer** — canonical observables and source provenance;
- **evidence service** — time-bounded relationships and source reliability;
- **decision service** — deterministic M/S computation and policy evaluation;
- **policy service** — versioned tenant/operator policy and authorization scopes;
- **bundle compiler** — generates actuator-specific desired-state bundles;
- **signing service** — signs immutable bundle manifests with protected keys;
- **rollout manager** — staged/canary deployment and rollback;
- **receipt collector** — adapter application state and verification results;
- **audit ledger** — append-oriented decision, approval, mutation, and rollback records;
- **operator API/UI** — inspection, approval, exception, incident, and health workflows.

Services may begin in one process. The boundaries are logical first, physical only when scale or trust separation justifies them.

## Edge agent properties

Each edge actuator SHOULD:

- authenticate the control plane mutually;
- verify bundle signature, tenant, scope, sequence, creation time, and expiry;
- reject stale or replayed bundles;
- validate local hard safety limits independently of the control plane;
- compute a before/after diff;
- apply atomically where the target platform permits;
- preserve the previous known-good revision;
- emit a signed or authenticated receipt;
- operate safely when disconnected;
- support immediate local operator override.

The edge is a safety boundary. A compromised control-plane component should not be sufficient to publish an unconstrained rule.

## Multi-tenant isolation

Provider deployments require hard separation among customer scopes.

Each decision and rule MUST carry:

- `tenant_id`;
- authorization scope;
- target enforcement domain;
- applicable protected population/service class;
- policy version;
- rule lifetime;
- approval requirements.

A tenant's indicator may be globally useful evidence, but a tenant-specific enforcement decision must not silently become a global provider rule. Promotion from local to shared policy is an explicit workflow.

## Bundle model

A signed bundle should contain:

- bundle ID and monotonically increasing sequence;
- policy and compiler versions;
- tenant/operator scope;
- creation and expiration timestamps;
- desired rules with decision IDs;
- hashes of normalized inputs/evidence snapshots needed for audit;
- emergency-revoke entries;
- cryptographic signature metadata.

Edges apply desired state, not unordered imperative mutations. This makes convergence and rollback tractable.

## Rollout rings

Recommended promotion rings:

1. offline/replay;
2. shadow edge;
3. internal/operator canary;
4. small customer/tenant canary where authorized;
5. bounded production cohort;
6. general authorized population.

A policy may advance only after the prior ring satisfies its safety gates. Emergency promotion remains possible but requires an explicit operator action and is fully audited.

## SLO/SLA measurement model

Do not hard-code universal targets into the product specification. Operators should declare measurable objectives for each deployment. APIP must expose at least:

- **control-plane availability** — ability to ingest/evaluate/compile new decisions;
- **edge continuity** — traffic continues during control-plane outage;
- **bundle propagation latency** — decision approved to edge receipt;
- **decision latency** — normalized evidence available to decision complete;
- **rollback latency** — revoke initiated to edge confirmation;
- **freshness** — age of current feed/evidence/bundle;
- **false-positive rate** by action and indicator type;
- **unverified action rate** — actions lacking successful post-apply verification;
- **stale-rule rate** — rules remaining after intended expiry;
- **blast-radius utilization** — action budget consumed per tenant/edge;
- **resolver/firewall/proxy health impact**;
- **audit completeness** — expected decisions/actions with corresponding receipts;
- **coverage fraction per segment (`docs/24`)** — protected-population claims gate on this;
- **novel-infrastructure latency (`docs/23`)** — first behavioral signal to first interdiction action;
- **L1/L2 client-impact budget utilization (`docs/25`)**;
- **segment denial triage time + allowlist review currency (`docs/26`)**;
- **virtual-patch coverage of inventoried KEVs + orphaned-VP count (must be zero) (`docs/27`)**.

## Capacity model

Capacity planning should model four independent rates:

- indicators ingested per second;
- evidence updates per second;
- decisions compiled per second;
- rule deltas pushed per edge per interval.

Provider scale is primarily a state-distribution problem; the packet/query datapath remains in the operator's existing resolver/firewall/proxy infrastructure.

## Backpressure and overload

When overloaded, APIP prioritizes safety and freshness:

1. continue edge enforcement of currently valid known-good rules;
2. stop low-priority enrichment before dropping core provenance;
3. bound queues and expose lag;
4. reject unauthenticated/invalid feed data early;
5. avoid widening automation thresholds to catch up;
6. if evidence freshness exceeds policy limits, downgrade new actions to OBSERVE/approval rather than auto-enforce.

## Disaster recovery

Required recovery assets:

- versioned policy repository;
- signing-key recovery/rotation procedure;
- decision and receipt ledger backups;
- last-known-good edge bundles;
- deterministic rebuild from normalized evidence snapshots where retention allows;
- documented failover that does not require disabling local safety limits.
