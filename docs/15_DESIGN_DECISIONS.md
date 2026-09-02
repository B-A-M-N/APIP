# 15 — Design Decisions

## DD-001 Control plane, not inline universal proxy
Chosen because a control plane can program existing high-leverage enforcement devices without becoming a national-scale datapath dependency.

## DD-002 No endpoint agent requirement
The value proposition depends on a shared chokepoint protecting many downstream systems. Endpoints can provide optional telemetry but are not required.

## DD-003 Intelligence does not equal enforcement
Threat feeds are noisy, stale, duplicative, and sometimes wrong. Every record must pass evidence, scoring, policy, and safety checks.

## DD-004 Two-score model
Maliciousness and safe-to-block are distinct questions. This prevents high-confidence maliciousness on shared infrastructure from automatically producing destructive filtering.

## DD-005 DNS first
Resolver-layer filtering is broadly deployable, supports explicit exceptions, does not require packet payload inspection, and can be shadowed/logged before enforcement.

## DD-006 Routing last
BGP FlowSpec is powerful but operationally dangerous. It belongs behind mature governance and adapter-side constraints.

## DD-007 Deterministic policy path
No LLM is required in the enforcement decision loop, and no AI output contributes authority to it (v2.1, `docs/04`/`docs/28`): AI-derived artifacts enter only as non-authoritative `annotation`-class records and cannot alter any score, corroboration count, rung, or action. AI may assist analysts *outside* the platform with explanation, report summarization, feed triage, or policy review, but live control authorization remains deterministic, auditable, and byte-identical with and without any annotation.

## DD-008 Local enforcement state
Traffic processing should continue if the controller is unavailable. Rules are compiled to local devices/agents with TTL and version metadata.

## DD-009 Automatic expiration
Threat infrastructure changes quickly. Short-lived rules reduce stale-block risk and force current evidence to sustain continued enforcement.

## DD-010 Modular monolith first
A single-operator build benefits from strong module boundaries without premature distributed-systems overhead. Provider scaling can split ingestion/telemetry/adapter distribution later.

## DD-011 Behavioral detection as evidence, not verdicts (v2)
Recognizing *classes* of hostile behavior (beaconing, DGA cycling, tunneling, volume, novelty, TLS mismatch) closes the denylist's structural gap against machine-speed infrastructure generation. Placed as evidence generators behind the same corroboration and policy gates as feeds, they add coverage without adding authority (`docs/23`).

## DD-012 Context-acting rungs instead of binary block (v2)
The v1 safe harbor — host C2 on shared infrastructure and nothing can be blocked — is closed by acting on client/protocol/reputation context (challenge, per-pair rate ceilings, host quarantine) rather than contested IP identity (`docs/25`).

## DD-013 Allow-first for enumerable populations (v2)
Where legitimate egress is enumerable (OT/DMZ/fixed-function segments), deny-by-default beats detection because novelty itself is the signature; zero detection latency. Kept safe by the mirrored v1 machinery: SIMULATE replay, staged onboarding, governed expiring entries, break-glass (`docs/26`).

## DD-014 Virtual patching with mandatory exposure reduction (v2)
Known-CVE exploitation windows on unpatchable services need boundary controls; VP-3 exposure reduction (authorization-context-based, no signature quality required) is always applied first, signature classes second, with patch-tracking expiry so patches never silently persist (`docs/27`).

## DD-015 No AI anywhere in the platform (v2)
The defense does not involve AI in order to work. Determinism is the safety case; the generation race is unwinnable by learning; the AI supply chain is an avoidable attack surface; offline/air-gapped operation is a hard requirement. AI remains only in the threat model (`docs/28`).

## DD-016 Seeded randomization within bounds (v2)
Fixed defenses are learnable; adaptive tooling probes and shapes. Randomizing defensive parameters within policy bounds — with recorded seeds preserving exact replay — makes observation a poor predictor for the attacker at near-zero defender cost, without weakening any floor (`docs/29`).

## DD-017 Coverage as a measured quantity (v2)
Resolver-layer policy is void if endpoints bypass via DoH/DoT. Bypass resistance is engineered (known-hosts containment) and, where not forceable, measured (coverage ledger) and compensated (behavioral layers on flow metadata) rather than assumed (`docs/24`).

## Rejected alternative — attacker infrastructure disruption
Rejected for this product because it depends on takedowns, abuse escalation, provider action, or unsafe/unauthorized interference with third-party systems.

## Rejected alternative — honeypot/deception system
Rejected because it does not inherently intercept attack paths to unrelated downstream infrastructure. The v2 randomization layer (`docs/29`) was reviewed against this boundary: it perturbs parameters of already-justified controls and creates no deceptive surfaces or exposed hosts.

## Rejected alternative — mass endpoint deployment
Rejected because value would depend on broad target adoption.

## Rejected alternative — autonomous BGP filtering from public feeds
Rejected because false positives or feed compromise could create severe service impact; broad routing actions require independent operator controls.

## Rejected alternative — defensive AI/ML in the enforcement path (v2)
Rejected because learned components break exact replay and audit, inherit the denylist's "defends yesterday's attack" weakness, add a poisoned-model/extraction/prompt-injection supply chain into a system whose compromise would itself be critical, and conflict with air-gapped OT operation. Deterministic structural counters (enumeration, context-acting, corroboration, randomization) do not need to win a generation race (`docs/28`).
