# 16 — Advanced Passive Analytics and Evidence Fusion

> **v2 note:** the deterministic analytic families in this document are the foundation of the behavioral detection suite (`docs/23`), which normatively specifies their detection-family contracts, corroboration lattice, and anti-gaming requirements. This document retains the evidence-fusion framing; where the two documents differ on detection-family specifics, `docs/23` governs. No analytic in this document may involve model inference in the enforcement path (`docs/28`).

## Purpose

APIP's analytics plane exists to improve the quality of evidence presented to the deterministic policy engine. It is **not** an autonomous attack system and it is **not** authorized to probe, exploit, log into, degrade, or alter third-party infrastructure. Analytics consume threat intelligence, public/contractually available metadata, and telemetry produced inside the deploying operator's authorized environment.

The core invariant is:

> Analytics may create or update evidence. Analytics may not directly create an enforcement action.

Every live action still requires the normal decision pipeline: evidence → maliciousness score → action-safety score → policy → approval/automation gate → bounded actuator.

## Evidence graph

Represent each normalized observable as a node with time-bounded relationships to contextual entities:

- FQDN, IPv4/IPv6 address, CIDR, URL, certificate fingerprint, network fingerprint;
- malware/campaign/intrusion-set identifiers when supplied by trusted CTI;
- ASN/provider and service classification;
- first-seen, last-seen, and observation count;
- source identities and source reliability;
- local sightings by tenant or protected service;
- past enforcement actions and measured outcomes;
- false-positive and allowlist history.

Edges MUST retain provenance and timestamps. A relationship inferred by APIP is distinguishable from one asserted by an external source.

## Passive analytic families

### Temporal concurrence

Measure whether multiple independent sources and local observations converge within a bounded time window. Useful signals include:

- first-seen proximity across independent sources;
- repeated local contacts after a threat advisory;
- short-lived infrastructure appearing in a known campaign window;
- evidence freshness and decay.

Old evidence decays rather than remaining permanently authoritative.

### Infrastructure-sharing classification

Before blocking an IP or prefix, estimate whether the address appears dedicated or shared. Inputs can include operator-owned DNS/flow telemetry and passive infrastructure metadata available under the operator's agreements. Shared CDN, hyperscaler, hosting, recursive DNS, VPN, NAT, anycast, and multi-tenant indicators reduce action-safety even when maliciousness is high.

This is a key reason APIP keeps maliciousness and action safety separate.

### Domain structure and lifecycle signals

On domains observed by the authorized resolver, calculate non-invasive features such as:

- domain age/freshness when lawful metadata is available;
- entropy and lexical structure;
- label depth and length;
- observed answer churn;
- TTL behavior;
- number of distinct resolved addresses;
- local prevalence and novelty;
- relationship to known campaign indicators.

A DGA-like score is evidence only. It MUST NOT be a direct deny rule.

### Fast-flux suspicion

Using authorized DNS observations, estimate whether a domain exhibits unusually rapid answer rotation, short TTLs, broad address diversity, or ASN diversity. Fast-flux suspicion raises maliciousness only when combined with corroborating evidence; legitimate CDNs can exhibit superficially similar properties.

### Certificate and service clustering

Where certificate metadata is lawfully available, cluster by exact certificate fingerprint, issuer/subject patterns, validity windows, SAN relationships, and repeated service fingerprints. Do not infer ownership solely from a shared certificate or hosting provider.

### Local prevalence and criticality

For each tenant or protected population, track:

- number of affected clients/services without retaining unnecessary identifiers;
- protected-service criticality;
- whether traffic is northbound IT/DMZ traffic versus safety-sensitive OT traffic;
- historical baseline prevalence;
- expected business dependency.

High prevalence can mean active compromise **or** common legitimate infrastructure. Therefore prevalence can raise incident priority while lowering action safety.

### Outcome feedback

The system records whether a control:

- matched traffic;
- reduced observed suspicious communication;
- produced helpdesk/SOC reports;
- caused resolver/firewall errors or latency regression;
- was later determined false positive;
- expired or was revoked early.

Outcome data adjusts source reliability and safety priors only through versioned, reviewable logic — there is no model to retrain and no learning in the platform; every adjustment is a deterministic, replayable ruleset change that requires a policy/version change to take effect.

## Optional statistical/ML components

**v2 stance (`docs/28` tightens this):** the platform itself involves no AI, machine learning, or LLM components anywhere in its operation — the enforcement path is deterministic end-to-end, and the platform is fully operable with zero AI. Where an operator deploys *external* analytic products (SIEM anomaly models, EDR, NDR), their outputs are ingested only as **annotations** (`docs/28`):

- they carry an `annotation` source class with the model/tool identity and artifact hash recorded in provenance;
- they contribute **zero** to M, S, corroboration counts, family counts, and rung eligibility — they cannot alter any decision, only surface for analyst review;
- they can never influence enforcement, directly or through any combination;
- removing them degrades nothing — the decision path is byte-identical with and without them.

Historical note: v1 permitted optional internal ML for clustering and prioritization. v2 removes internal ML from the design entirely; the determinism, auditability, and supply-chain arguments are documented in `docs/28`. The sections above already describe the deterministic feature computations (entropy, n-gram statistics, periodicity arithmetic, volume baselines) that replace any learned component.

## Privacy minimization

Provider-scale deployments SHOULD prefer aggregates and keyed/pseudonymous identifiers over raw subscriber identity. Recommended practices:

- retain only fields necessary to make or audit the decision;
- separate tenant/customer identity from threat evidence;
- aggregate local prevalence where possible;
- enforce retention windows by data class;
- prohibit payload capture by default;
- document lawful authority for each telemetry source;
- expose deletion/export controls according to operator policy and applicable law.

## Adversarial robustness

Assume adversaries may attempt to poison feeds or manipulate heuristics. Required defenses include:

- per-source reliability and rate limits;
- independent-source requirements for high-impact actions;
- provenance-preserving deduplication;
- signed feed/bundle validation where supported;
- sudden-volume and sudden-score-change guards;
- allowlist precedence;
- protection against a single source causing a broad block;
- canary rollout and automatic rollback;
- immutable decision/audit records.

## Minimum advanced-analytics release gate

Before any analytic feature can affect automatic enforcement, the operator must demonstrate on replay data that:

1. the feature is deterministic or version-pinned;
2. its provenance is visible in the decision explanation;
3. absence/failure of the feature fails conservatively;
4. adversarial or malformed input cannot create a broad action;
5. false-positive impact is measured separately by indicator/action class;
6. the feature has unit, replay, and rollback tests.
