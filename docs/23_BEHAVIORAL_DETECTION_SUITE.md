# 23 — Behavioral Detection Suite

## Purpose

Indicator (denylist) matching alone cannot interdict attack paths that use infrastructure which did not exist until the moment of the attack. AI-assisted offensive tooling has made "generate fresh C2 domain, register it, use it, discard it" a sub-hour activity. The behavioral detection suite closes this gap by recognizing **classes** of hostile behavior rather than **instances** of known-hostile infrastructure.

Behavioral detections are deterministic functions over telemetry the operator is already authorized to collect at the chokepoint (resolver query logs, flow metadata, proxy metadata, IDS events). No endpoint agent is required. No third-party system is probed.

## Position in the architecture

Behavioral detections are **evidence generators**, exactly like external feeds. They feed the same evidence plane, produce the same evidence records with provenance (`origin: local_behavioral`), and are consumed by the same two-score model (M/S) and policy engine. They have no path to an actuator that bypasses scoring, policy, staging, or safety budgets.

```text
resolver/flow/proxy/IDS telemetry
        |
        v
+---------------------------+
| behavioral detection suite |   (deterministic feature extractors
|  - beacon periodicity      |    + fixed thresholds; versioned
|  - DGA-lexicals            |    like any other policy input)
|  - DNS tunneling           |
|  - fast-flux / churn       |
|  - longline/exfil volume   |
|  - first-seen anomalies    |
|  - TLS/JA4 mismatch        |
+---------------------------+
        |  evidence records (origin=local_behavioral)
        v
evidence plane -> M/S scoring -> policy -> staged enforcement
```

This placement is deliberate: a behavioral alert can never be an automatic deny on its own. It must combine with corroboration and pass action-safety, exactly as feed evidence does.

## Detection families

Each family specifies: input, deterministic signal, corroboration requirements, and the evidence kind it emits. Thresholds are versioned operator policy (see `docs/04`), never hard-coded magic numbers in code.

### BD-1 Beacon periodicity (C2 check-in detection)

**Input:** flow metadata or proxy logs (per internal host ↔ external endpoint pair), DNS resolution logs.

**Signal:** for each (source host, destination) pair over a sliding window, compute inter-arrival-time regularity — the ratio of the standard deviation to the mean of connection intervals (jitter ratio), plus minimum observation count. Human- and service-driven traffic is bursty; implant check-ins are periodic with low jitter. A pair with N≥ threshold intervals and jitter ratio ≤ threshold is a beacon candidate.

**Determinism:** pure arithmetic over timestamp sets; identical inputs yield identical candidates; fixed-point arithmetic is preferred (see WP-2).

**Corroboration requirement:** periodicity alone is *evidence* (raises M), never a block. It must combine with at least one of: destination is first-seen recently (BD-6), destination domain lexical anomalies (BD-2), or an external feed hit, before any action beyond OBSERVE/rate-limit can be proposed.

**Evidence kind:** `behavioral_beacon_periodicity`.

**Emitted fields:** jitter_ratio, interval_mean, interval_count, window, first_observed, destination (host-level identifier, pseudonymized per privacy policy).

### BD-2 DGA-like domain structure

**Input:** resolver query logs at the authorized resolver.

**Signal:** lexical and structural features of queried FQDNs that the resolver has **never resolved before** (first-seen): label-length distribution, Shannon entropy of the leftmost label, n-gram abnormality against a baseline corpus of the protected population's normal domains, label depth, character-class alternation. Each feature is scored and combined with fixed versioned weights into a DGA-likelihood band (low/medium/high). This is fixed statistical scoring — exact arithmetic over a versioned corpus — not a trained classifier; identical inputs always yield identical bands.

**Determinism:** entropy and n-gram statistics are exact integer/fixed-point computations over the domain string; the baseline corpus is a versioned, hashed artifact so a given corpus version always yields the same score for the same string.

**Corroboration requirement:** high-band DGA-likelihood alone → OBSERVE. Auto-eligible proposals additionally require NXDOMAIN-rich bursts (many high-entropy queries with no answer — the signature of a DGA implant cycling through candidate domains) or beacon correlation on the one domain that does resolve.

**Evidence kind:** `behavioral_dga_likelihood` (with band and feature vector).

**Hard rule (inherited):** a DGA score is never a deny rule by itself. Legitimate services (CDN edge labels, generated asset names) can look DGA-like; that is precisely why corroboration is mandatory.

### BD-3 DNS tunneling

**Input:** resolver query logs.

**Signal:** high-entropy, long leftmost labels; unusually high TXT/NULL query share per client; query-name length near protocol maxima; bytes-per-second transported via query names (estimate from label sizes × query rate). Per-client thresholds over a sliding window.

**Corroboration requirement:** tunneling signatures are comparatively specific; a high-confidence signature (length + entropy + record-type anomaly + rate) may support a **client-scoped rate-limit** proposal without external corroboration, but any destination-affecting action still requires corroboration and full policy.

**Evidence kind:** `behavioral_dns_tunneling`.

### BD-4 Fast-flux / answer churn

**Input:** resolver answer logs (authorized resolver only).

**Signal:** per-domain count of distinct A/AAAA answers in a window, answer-set turnover rate, DNS TTL values as answered, ASN diversity of answers. Compare against the domain's own history and the population baseline for its infrastructure class.

**Corroboration requirement:** fast-flux suspicion reduces action safety for the domain (blocking a fast-flux domain's current IPs is futile and may hit rotating innocent IPs) and raises M only when combined with other evidence. Preferred action for confirmed fast-flux + malicious: **domain-level RPZ** (block the name, not the addresses).

**Evidence kind:** `behavioral_fastflux`.

### BD-5 Volumetric exfiltration pattern

**Input:** flow metadata (NetFlow/IPFIX) at the chokepoint.

**Signal:** per (host, destination) sustained outbound byte volume above baseline for that host class; upload:download ratio inversions; destination diversity collapse (a host that previously talked to many destinations concentrating on one new destination).

**Corroboration requirement:** volume anomalies alone raise incident priority, never enforcement. They primarily drive SOC worklists and host-scoped proposals (see `docs/25`), because volume is the least specific signal in the suite.

**Evidence kind:** `behavioral_volume_anomaly`.

### BD-6 First-seen / novelty anomalies

**Input:** resolver and flow history within the operator's retention window.

**Signal:** a destination contacted by an internal host for the first time ever (within retention) that simultaneously exhibits other risk features (non-standard port for its service class, no prior population exposure, fresh registration metadata where lawfully available). Novelty is most valuable as a **corroboration amplifier**, sharply raising M when combined with BD-1/BD-2/BD-5, and as a **shadow-mode watch class** — in SHADOW mode first-seen destinations matching risk features are watched more closely without any enforcement.

**Evidence kind:** `behavioral_first_seen_novelty`.

### BD-7 TLS metadata mismatch

**Input:** passive TLS handshake metadata (client-hello fingerprints such as JA4, SNI vs. resolved-address consistency, certificate properties where visible).

**Signal:** an SNI whose served certificate does not cover it; a client fingerprint associated with scripted tooling contacting an unusual destination class; HTTPS to a raw-IP destination with no SNI from a host class that normally uses named services.

**Corroboration requirement:** same as BD-1: evidence only; combines with other families for any enforcement proposal.

**Evidence kind:** `behavioral_tls_metadata_mismatch`.

### BD-8 Synchronized first-contact (population-scale novelty)

**Input:** resolver and flow history across the protected population.

**Signal:** a destination that has never been seen by *any* client within retention is contacted near-simultaneously (within a bounded window) by multiple internal hosts. Per-host first-seen novelty (BD-6) misses a low-and-slow distributed pattern; population-scale synchronization exposes it. N is population-scaled (a floor of hosts plus a fraction of population, versioned) to defeat tiny-cohort evasion. Decorrelated from every per-host family: it fires on *coordination*, not on any single host's behavior — which is precisely what AI-generated per-victim infrastructure still cannot avoid producing when a campaign touches many victims at once.

**Corroboration requirement:** counts as one family in the k-of-n lattice; on its own, observe-only.

**Evidence kind:** `behavioral_sync_first_contact`.

## Cross-family combination semantics

Families are designed so their false-positive modes are **decorrelated**: periodicity misfires on cron jobs; DGA-lexicals misfire on CDN labels; volume misfires on backups. A combination rule therefore requires **k-of-n distinct families** (versioned; default 2-of-any) before a behavioral cluster can support even a rate-limit proposal, and 3 distinct families plus external corroboration for any deny proposal.

Every combination is recorded in the evidence record as a derivation tree so the decision explanation shows exactly which families and thresholds fired.

## Host-scoped behavioral clusters

The suite groups evidence by affected internal host (pseudonymized identifier). A host accumulating cross-family evidence becomes a **behavioral cluster** with an escalating worklist priority. This is the detection input to host-level containment options in `docs/25` — the chokepoint can see that host H is beaconing; containment options (isolation via existing NAC/firewall APIs, never a new inline dependency) are separately governed actions.

## Anti-gaming analysis

An attacker who knows the thresholds could shape traffic to sit just under them. The suite's countermeasures are structural, not threshold-based:

1. **Corroboration lattice:** thresholds are only the entry point; every enforcement path requires independent families agreeing. Shaping around one family does not defeat the others.
2. **Population baselines:** thresholds adapt to the protected population's measured normal (versioned, reviewed), so "just under a global threshold" does not transfer across deployments.
3. **Shadow telemetry:** in SHADOW mode the suite logs which families *would* have fired — an operator reviewing shadow telemetry sees shaping attempts as near-miss clusters, which themselves become evidence.
4. **No published thresholds:** exact thresholds are operator policy, not product constants, and never leave the control plane.
5. **Slow-and-quiet residual:** an attacker accepting machine-hour-long beacon intervals to defeat periodicity detection remains exposed to BD-6 novelty, BD-5 concentration, BD-8 population-scale synchronization, and — most importantly — the deterministic interdiction ladders of `docs/25`, which do not depend on detection at all.

## Young-domain friction class

Behavioral families detect properties of *observed* traffic; a complementary deterministic input is domain **age**. Where lawful metadata is available (newly-registered-domain feeds, passive DNS), domains younger than a policy threshold form a friction class:

- young domains are **L1/L2-eligible but never deny-eligible on age alone** — age is context, not malice (legitimate services launch daily);
- the friction is bounded by the existing L1 client-impact budgets, so even a fully poisoned NRD feed can cause at most challenges/rate-limits within budget — never an outage;
- age evidence decays automatically as the domain ages out of the band;
- the NRD feed is an ordinary signed source with a trust profile; its failure removes friction, not protection.

This closes part of the population-scale novelty gap for general user populations (which cannot be allow-firsted) without turning "new" into "blocked."

## Privacy constraints

- Behavioral evidence is computed from metadata the operator already collects; the suite introduces no new payload capture.
- Host identifiers in evidence are pseudonymous by default; re-identification is a separate audited permission.
- Retention of behavioral features follows the same data-class windows as other telemetry (`docs/09`).
- Per-family raw feature retention may be shorter than decision records; decisions retain hashes of the feature inputs.

## Resource envelopes (v2.1, mandatory per family)

Every detector runs against attacker-influenceable cardinality (a flood of novel domains, hosts, or pairs is cheap for the attacker to produce and expensive for a naive implementation to track). Each family therefore carries a **policy-versioned resource envelope**; exceeding one is a monitored event with **deterministic degradation** — never silent unbounded growth, never a crash, and never an increase in enforcement authority:

| family | bounded state | bound (default, versioned) | eviction |
|---|---|---|---|
| BD-1 beacon periodicity | (host,destination) interval windows | max tracked pairs | oldest-window-first, fixed |
| BD-2 DGA-likelihood | baseline corpus + per-window first-seen set | corpus version hash; first-seen set cap | windowed expiry |
| BD-3 DNS tunneling | per-client query-feature windows | max tracked clients | oldest-window-first |
| BD-4 fast-flux | per-domain answer-set history | max tracked domains | oldest-window-first |
| BD-5 volume anomaly | per (host,destination) byte counters | max tracked pairs | windowed reset |
| BD-6 first-seen novelty | population first-seen table | max entries | TTL (retention window) |
| BD-7 TLS mismatch | (SNI, fingerprint) observation cache | max entries | TTL |
| BD-8 synchronized first-contact | population novelty table + contact windows | max entries | TTL |

Degradation rules (normative):

1. **Overflow → stop-and-mark.** When a family's bound is hit, that family **stops generating new evidence** for untracked keys, emits a `detection_degraded:<family>` signal to the operations plane, and continues to score already-tracked keys until their windows expire.
2. **Degradation never raises authority.** A degraded suite can only *reduce* M contributions (fewer families contributing), never bypass corroboration, floors, caps, or gates. Under load, the system fails toward OBSERVE, never toward enforcement.
3. **Eviction is deterministic.** Eviction order is a fixed function of state (oldest window, nearest TTL expiry), not memory pressure or timing — replay remains exact.
4. **Envelopes are versioned policy.** Bounds live in the policy artifact like every other threshold, so a bound change is a reviewed, auditable change.
5. **Overflow is an attack signal.** Sustained envelope exhaustion on first-seen-driven families (BD-2/BD-6/BD-8) is itself a campaign signature and raises an operator worklist item — the attacker pays a detection cost for the flood they sent.

## Release gate additions

Before a behavioral family can contribute to automatic enforcement the operator must demonstrate on replay:

1. deterministic replay of candidate generation from raw telemetry;
2. false-positive impact measured per family on at least a week of production-shadow telemetry;
3. decorrelation evidence: the k-of-n combination rule measurably reduces combined false positives below any single family;
4. adversarial shaping tests (periodicity evasion, lexical grooming) produce no enforcement without corroborating families;
5. removal of any single family fails conservatively (evidence decays, decisions re-evaluate, no orphaned actions).
