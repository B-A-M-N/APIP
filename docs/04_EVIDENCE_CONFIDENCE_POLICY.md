# 04 — Evidence, Confidence, and Policy

## Why two scores are mandatory

A single “badness” score creates dangerous ambiguity. For example, a known compromised CDN edge can be malicious in context while being unsafe to block globally. APIP therefore computes:

- **M — maliciousness confidence**: strength of the attribution of malicious activity to the exact observable.
- **S — action safety**: confidence that the proposed defensive action is appropriately scoped and low-collateral.

## Example evidence weights

These values are a reference starting point and must be versioned policy data.

### Maliciousness contributors

| Evidence | Points |
|---|---:|
| High-confidence direct local detection | +35 |
| Two independent curated sources | +25 |
| Government/sector curated indicator with current context | +20 |
| Strong campaign-specific linkage | +15 |
| Repeated recent sightings | +10 |
| Single unknown-quality source | +5 |
| Older than source TTL | -25 |
| Credible contradictory benign evidence | -35 |
| Prior confirmed false positive | -50 |

### Action-safety contributors

| Condition | Points |
|---|---:|
| Exact FQDN/URL | +30 |
| Exact IP with dedicated-use evidence | +20 |
| Tenant-bounded scope | +15 |
| TTL ≤ 1 hour | +15 |
| Verified rollback | +10 |
| Shared CDN/cloud endpoint | -45 |
| Wildcard domain | -30 |
| CIDR prefix | -40 |
| Critical vendor dependency | -50 |
| No recent local/sector corroboration | -15 |

Scores are clamped to 0–100.

### Behavioral evidence contributions (v2)

Behavioral detection families (`docs/23`) contribute to M/S as versioned evidence kinds with capped weights, subject to the corroboration lattice (k-of-n distinct families, default 2 for any rate-limit proposal, 3 distinct families + external corroboration for any deny):

| Behavioral evidence kind | Typical M contribution | Typical S contribution |
|---|---:|---:|
| Beacon periodicity (high regularity, N≥threshold intervals) | +10..+20 | 0 |
| DGA-likelihood high band | +5..+15 | 0 |
| DGA cycling burst (NXDOMAIN-rich) | +15..+25 | 0 |
| DNS tunneling signature (high confidence) | +20 | −10 (client-scoped action preferred) |
| Fast-flux suspicion | +5 | −20 (address-blocking unsafe) |
| Volume anomaly | +5..+10 | 0 |
| First-seen novelty (as corroboration amplifier) | +10 | 0 |
| TLS metadata mismatch | +10 | 0 |

Behavioral contributions alone cannot reach any deny floor (combined cap well below L4 floor); they must combine with feed evidence or multiple distinct families. Exact weights are operator policy, versioned like all scoring.

### Infrastructure class registry input (v2)

The shared-infrastructure registry class (`docs/25`) is a mandatory S input: shared classes cap the achievable rung at L4 (domain/context actions) regardless of M. Dedicated-use evidence is the only path to L5.

## Source reliability

Each source profile includes:

- `source_id`
- `owner`
- `type`
- `source_class` — one of `curated | local | community | annotation | unregistered` (v2.1, server-assigned; see below)
- `base_reliability`
- `expected_update_interval`
- `max_staleness`
- `default_tlp`
- `supports_revocation`
- `requires_corroboration`
- `auto_enforcement_allowed`

Source reliability should be explicit configuration. Any adaptive adjustment must be visible, bounded, and reversible.

### Source class assignment (v2.1)

`source_class` is assigned **server-side** from the governed source registry; it is never read from an evidence payload. The classes are mutually exclusive:

| class | weight-table authority | auto-enforcement |
|---|---|---|
| `curated` | full | per profile |
| `local` | full (sole origin of `behavioral_*` kinds) | per profile |
| `community` | capped, corroboration-required | per profile |
| `annotation` | **zero** — non-authoritative | **never** |
| `unregistered` | **zero** | **never** |

The `annotation` class is the only admissible form for output of any AI/ML system (internal or external, including vendor "AI analytics" feeds): such records are stored with provenance for analyst review and are provably unable to alter M, S, corroboration counts, family counts, rung eligibility, or any emitted action. An `external_analytic` or `ai_assisted` scoring origin does not exist. Every decision must be byte-identical with and without its annotation records; the reference test suite enforces this invariant.

## Independence

Two records are not independent merely because they came through two feeds. APIP should track upstream provenance where available so one original report re-published by multiple aggregators does not falsely count as independent corroboration.

**Enforced in the reference scaffold (v2.1.1):** each `SourceProfile` carries an optional `upstream` provenance identity; corroboration counts **distinct upstream identities**, not feed names. Three resellers re-exporting one upstream corroborate **once**; the upstream's own first-party feed counts as the *same* identity as its re-exporters; unregistered sources can never merge with anything. The external-corroboration gate for behavioral deny and the curated-source weights both consume this identity arithmetic (`reference/src/apip/registry.py`, pinned by `ProvenanceIndependenceTests`).

## Freshness

Every evidence type has a half-life or TTL. Example defaults:

- active C2 FQDN: hours to days;
- exact malicious IP: hours;
- malware file hash: longer-lived as evidence but usually not a network-control target;
- infrastructure ownership relation: days/weeks with refresh;
- campaign association: days/weeks;
- vulnerability exploit status: handled separately from endpoint blocking.

## Action selection

Reference decision logic. In v2 the action is selected by the interdiction ladder (`docs/25`) rather than a fixed per-type matrix:

```text
if allowlisted(target, scope):
    NO_ACTION
elif mode == OFF:
    NO_ACTION
elif M < observe_floor:
    NO_ACTION
elif mode == OBSERVE:
    OBSERVE
elif segment(target) is ALLOW_FIRST and destination not on segment allowlist:
    deny is the segment's standing posture (docs/26) — emit denial event + evidence
elif action violates hard safety rule:
    PROPOSE_OPERATOR_APPROVAL or NO_ACTION
elif mode == SHADOW:
    SHADOW_ACTION (rung selected, not enforced)
else:
    rung = ladder_select(M, S, infra_class, scope)      # docs/25
    apply randomized parameter draws within bounds      # docs/29
    if rung meets auto-enforce floor and auto_allowed(rung):
        AUTO_ENFORCE
    else:
        PROPOSE_OPERATOR_APPROVAL
```

Demotions (`demoted_shared_infra`, `demoted_no_dedicated_use`, `demoted_scope`) are reason codes, so operators see exactly why a weaker rung was chosen.

## Hard safety rules

Hard rules override numeric scores:

- ASN-wide action prohibited.
- prefix block prohibited for automatic enforcement.
- routing action always approval-gated.
- target outside authorized scope prohibited.
- expired evidence cannot create a new auto-enforced rule.
- malformed/ambiguous domain prohibited.
- allowlist hit prohibits automatic deny.
- known shared-infrastructure category prohibits automatic exact-IP deny unless dedicated-use override is explicitly established.
- a single behavioral detection family can never authorize a deny action (`docs/23`).
- model inference is prohibited in scoring and policy evaluation (`docs/28`).
- no randomized parameter may exceed policy bounds or weaken a floor (`docs/29`).
- allow-first enforcement requires a segment that completed onboarding (`docs/26`).

## Blast radius model

Estimate blast radius from:

- target breadth;
- observed unique clients/tenants contacting target;
- historical traffic volume;
- infrastructure sharing category;
- action type;
- customer criticality;
- DNS hierarchy breadth;
- network prefix size.

A high expected blast radius reduces S and may force approval regardless of M.

## Policy testing

Every policy change must be testable against:

- golden synthetic cases;
- historical decisions;
- previous false positives;
- sampled real traffic metadata from authorized environments;
- maximum action-rate scenarios;
- malformed input corpus.

The policy engine should output a diff such as:

```text
candidate policy 2026-09-01.2 vs active 2026-08-28.4
+ 42 additional auto-enforced exact FQDN decisions
- 6 exact IP auto-enforcements converted to approval-required
0 wildcard rules newly auto-enforced
max affected historical tenant count: 3
```
