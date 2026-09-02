# 28 — AI-Era Attack Posture and the No-AI Design Invariant

## Purpose

The motivating threat model for APIP v2 is the current, measurable uplift in AI-assisted offensive operations: machine-speed reconnaissance and credential testing, polymorphic malware generated per-victim, LLM-generated phishing at population scale with per-target personalization, and defensive-constraint-aware tooling that adapts to whatever filtering it encounters.

This document does two things:

1. Defines what that threat changes defensively — each structural property AI gives the attacker maps to a structural counter that does not depend on winning a generation race.
2. States and enforces the **no-AI design invariant**: APIP's defense does not involve AI, machine learning, or LLMs anywhere in order to work. AI appears in this specification only as a property of the threat model, never as a component of the platform.

## The no-AI design invariant

> **APIP MUST be fully operable and fully effective with zero AI components.** Every detection, score, policy evaluation, compilation, and safety control in the platform is a deterministic, versioned, replayable computation over evidence the operator is authorized to collect. There is no model inference, no learned component, and no generated logic in any operational path.

This invariant is a design decision, not a limitation of ambition. Its rationale:

1. **Determinism is the safety case.** APIP's entire safety argument (`docs/20`) rests on reproducible decisions: same evidence, same policy, same clock → same output. Learned components break exact replay, complicate audit, and make certification (NERC CIP change control, incident reconstruction) materially harder.
2. **The generation race is unwinnable by design.** A defensive model trained on yesterday's attacks inherits the denylist's core weakness — it defends against what has already been seen. The v2 layers do not learn the attacker's pattern; they change the *structure* of the defense (enumeration, context-acting, corroboration) so that novelty itself is expensive.
3. **No AI supply chain.** Models, embeddings endpoints, and prompt pipelines are dependencies with their own attack surface (poisoning, extraction, prompt injection). A platform with none of them has none of those exposures. This is a deliberate hardening choice for a system whose compromise would itself be a critical-infrastructure incident.
4. **Offline and degraded operation.** The platform runs in air-gapped and bandwidth-constrained environments (OT boundaries, incident-response isolation) where external model APIs are unavailable or prohibited. No-AI means no quiet operational dependency on a service that must not be reachable.

What the invariant does not prohibit: an operator's *separate* tooling — a SIEM with anomaly models, an EDR product, an analyst's own LLM assistant — producing artifacts that humans or connectors submit through the standard ingestion path. Such artifacts are recorded under the **`annotation` source class** (v2.1, `docs/04`): they are stored for analyst review with full provenance, but they are **non-authoritative by construction** — the `annotation` class contributes zero to M, zero to S, and is excluded from corroboration counts, family counts, external-corroboration qualification, and every rung gate. A decision must be byte-identical with and without any annotation record. They are not part of APIP, APIP does not require them, and removing them degrades nothing.

### Conformance requirements

- No component in the enforcement path may invoke model inference (local or remote).
- Score contributions from any evidence record are computed by fixed, versioned arithmetic — a record's contribution is fully specified by its fields, its registry-assigned source class, and the policy version.
- Output of any AI/ML system is admissible only under the `annotation` source class and is provably unable to alter M, S, corroboration, rung eligibility, or any emitted action (`docs/04` v2.1). An `ai_assisted` or `external_analytic` scoring origin does not exist.
- The reference implementation (`reference/`) is dependency-free standard library and demonstrates the invariant concretely; its test suite includes an AI-evidence invariance regression (annotation-suffused decisions are byte-identical).

## What AI changes on offense — and the deterministic counter per property

The defensive claim is not "AI is defeated" but: **each structural property AI gives the attacker maps to a structural counter that does not depend on winning a generation race.**

| AI-era offensive property | Why the v1 posture was insufficient | v2 counter (deterministic) |
|---|---|---|
| Polymorphic infrastructure: per-victim C2 domains generated at machine speed | denylist latency: indicator must exist before block | BD-2/BD-6 behavioral evidence on never-seen domains (fixed entropy/n-gram/novelty computations); L3/L4 default-deny for fixed segments (`docs/25`/`26`); domain-generation **class** evidence rather than instance matching |
| Machine-speed recon/cred-stuffing against exposed services | no inbound posture at chokepoint | VP-3 exposure reduction; L1 challenge on interactive paths; L2 rate ceilings per source; deterministic source-reputation accumulation |
| Defensive-aware tooling that probes and adapts around filters | static thresholds published or inferable | thresholds are operator-private, population-baselined (BD anti-gaming, `docs/23`); multi-family corroboration lattice; staged friction (L1/L2) that shapes attacker into observability |
| LLM-phishing at scale, personalized | domain takedowns too slow; feed latency | resolver-level suppression of corroborated campaign domains (L4) with campaign-burst TTL semantics; delivery-domain reputation feeding mail-gateway via standard exporter; user-report loop as evidence source |
| Automated supply-chain/dependency attacks | out of chokepoint scope | acknowledged boundary (`docs/08`); inventory + allow-first shrink the blast radius of what a compromised dependency can reach |
| Agentic attack chains orchestrating multi-step intrusions | per-indicator response too slow for chained attack | campaign objects correlating families/hosts/infra into one composed response (`docs/25` multi-rung composition); playbook automation of the *approval* path, never of the safety gates |
| Adaptive tooling that observes defensive responses and reroutes | a fixed single control is inferable and avoidable | algorithmic randomization of defensive parameters (`docs/29`): randomized challenge placement, rotating rate-limit ceilings within policy bounds, jittered TTL/renewal schedules, and varied rung composition, so the observed response at time T does not determine the response at T+1 |

## Design invariants under AI-era attack

None of these requires the defender to outrun the attacker's model, because none of them learns anything:

1. **Enumerability beats novelty.** Wherever a population's legitimate behavior is enumerable (fixed segments), the default is denial; novelty itself is the attack signature (`docs/26`).
2. **Context beats identity.** Where infrastructure is shared, act on client/protocol/reputation context (L1/L2/L6), not on contested IP identity (`docs/25`).
3. **Corroboration lattices beat single detectors.** Every enforcement path requires decorrelated families/sources agreeing; an attacker must defeat all of them simultaneously while remaining functional.
4. **Friction is observable.** Challenge/rate-limit rungs convert adaptation attempts into telemetry; an attacker probing the filter's shape produces near-miss clusters that are themselves evidence.
5. **Unpredictability is cheaper for the defender.** Randomizing defensive parameters within policy bounds (which challenge fires, what the ceiling is this window, when rules renew) costs the defender nothing and forces the attacker to solve a stochastic observation problem on every attempt (`docs/29`).
6. **Automation never widens authority.** Machine speed is granted only inside the safety envelope: budgets, scopes, TTLs, staging, edge-side limits. Speed multiplies what is safe; it cannot manufacture new authority. This is the core defense against an attacker *inside* the decision path.

## Evidence-channel injection attacks

CTI text, feed metadata, and even domain names/URLs are attacker-controllable strings that could carry injection payloads aimed at analytic layers. Because APIP has no LLM or interpreter in any operational path, the classic injection target does not exist:

- There is no prompt, no eval, no generated logic for a payload to execute. The worst an embedded instruction can do is be stored as inert evidence text.
- Indicator **values** are canonicalized against strict per-type grammars (v1 FR-002); an instruction hidden in a malformed domain string is rejected with the value, not executed.
- Policy is declarative data validated against schemas — never generated, interpreted, or self-modified at runtime.
- Provenance is preserved end-to-end so poisoned records are removable and their dependent decisions re-evaluated (v1 feed-compromise workflow applies unchanged).
- If an operator's *external* analytic tooling is prompt-injectable, the blast radius into APIP is bounded by the corroboration and contribution-cap rules every external source is subject to.

## Automation and agentic abuse resistance

Operators may drive APIP programmatically — scripts, SOAR platforms, or agentic AI tooling chosen by the operator. The platform does not require any of it (manual CLI/UI operation is complete), and its contract for any programmatic client is:

1. **Programmatic clients act through the same RBAC as humans.** No machine-specific privilege escalation; a client's principal is accountable for every action.
2. **High-risk classes stay human-gated.** L5+ rungs, segment onboarding, break-glass, and any approval tier ≥ 2 require a human approver identity; automation may prepare, never approve. Dual control remains available and is recommended for machine-prepared changes.
3. **Per-principal rate budgets.** Action-proposal rate limits and change-volume budgets per principal, so a runaway or hijacked client cannot flood approvals or push bulk changes through staging faster than humans can watch.
4. **Automation is distinguishable in audit.** Every mutation records principal, automation flag, and session, so post-incident review can separate automated from human actions.
5. **Reversibility is unchanged.** Everything automation caused is revocable by the standard one-action rollback, provable by receipts.
6. **No programmatic client holds signing authority.** Bundle signing keys and policy signing remain human-controlled service identities.

## Residual risk statement

An attacker with sufficient resources and time can always: (a) fully mimic legitimate behavior inside allowed envelopes, (b) compromise an allowed dependency, (c) operate entirely within paths no chokepoint observes, or (d) defeat specific detection families by sacrificing capability (dropping to slow, quiet, infrastructure-resident operation). The v2.1 posture does not claim elimination; it claims each surviving path is **bounded and evidenced** rather than invisible:

- (a) mimicry: capacity ceilings on constrained segments bound exfiltration to ceiling rate while the anomaly accumulates — rate-bounded, evidenced loss, not unbounded loss (`docs/25`);
- (b) dependency compromise: tuple-form entries and traffic profiles narrow the inherited envelope to the enumerated path and alarm on deviation (`docs/26`);
- (c) unobserved paths: bounded by coverage accounting and compensating posture (`docs/24`), and by plaintext-53 redirect that converts stray DNS into observed DNS;
- (d) detection evasion: BD-8 population-scale synchronization and young-domain friction raise the coordination cost of distributed low-and-slow campaigns (`docs/23`).

Each counter is deterministic, auditable, and replayable. That is the honest ceiling of a chokepoint defense, and the reason APIP positions itself as one layer within a broader critical-infrastructure security program rather than a complete answer.
