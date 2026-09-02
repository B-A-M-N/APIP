# 25 — Layered Interdiction and Shared-Infrastructure Response

## Problem

The v1 action matrix has a structural weakness an AI-assisted attacker can exploit deterministically: **host malicious infrastructure on shared cloud/CDN services and the platform's own safety model refuses to block you.** The shared-infrastructure penalty (−45 or more to S) exists for a good reason — blocking a CDN edge IP takes down every innocent tenant on it — but the result is a safe harbor: high-M, low-S indicators produce `PROPOSE_OPERATOR_APPROVAL`, and in practice nothing is enforced before the campaign rotates.

The same weakness appears with anonymizing infrastructure (Tor exits, commercial VPNs, open proxies): hugely overrepresented in attack paths, yet impossible to treat as "malicious indicators" because each address also carries legitimate traffic.

This document replaces the binary block/no-block decision with a **layered response ladder**: an ordered set of increasingly strong controls, where each rung is individually safe on shared infrastructure because it acts on **context** (which client, which protocol, which reputation) rather than **identity** (which IP).

## The response ladder

For any indictable target, the ladder rungs in ascending strength — each rung requires at least the M/S gating of the rung below it, and each is a first-class compiled action with TTL, receipts, and rollback:

| Rung | Control class | Acts on | Safe on shared infra? | Automation floor (reference) |
|---|---|---|---|---|
| L0 | OBSERVE — evidence enrichment only | — | yes | M ≥ observe floor |
| L1 | CHALLENGE — interactive proof (CAPTCHA-class, device attestation) at proxy/WAF | client reputation + context | yes — only suspicious clients are challenged | M ≥ 85, S ≥ 75 |
| L2 | RATE_LIMIT — transaction-rate ceiling per client/destination pair | flow context | yes — legitimate volume unaffected | M ≥ 90, S ≥ 80 |
| L3 | EGRESS_ALLOWLIST — deny-by-default egress for fixed-function segments | segment policy | yes — segment scope, not destination identity | approval-gated segment onboarding |
| L4 | DOMAIN_BLOCK — RPZ exact-FQDN | name identity | yes (exact names on shared IPs are attacker-owned) | M ≥ 95, S ≥ 90 |
| L5 | IP_DENY — exact-IP firewall drop | address identity | **no** — requires dedicated-use evidence | M ≥ 98, S ≥ 95 |
| L6 | HOST_QUARANTINE — isolate compromised internal host at chokepoint | internal host | n/a (acts on own assets) | 3-family behavioral cluster + approval; or active-compromise signal |
| L7 | PREFIX/ROUTING — FlowSpec / prefix controls | routing | no | dual approval, all v1 constraints unchanged |

Key property: **L4 (domain block) does not punish shared infrastructure.** An exact FQDN on a CDN is attacker-owned even though its IPs are not; RPZ blocks the name. Conversely L5 remains as guarded as v1. The ladder converts the shared-infra safe harbor into a **friction and observability gradient**: the attacker on shared infrastructure can still be challenged, rate-limited, domain-blocked, and their internal hosts quarantined — everything except collapsing the shared IP itself, which was never safe.

## Ladder selection logic (deterministic)

Given an indicator with scores (M, S), infrastructure class, and context, the compiler selects the highest rung whose floor is met, subject to hard rules:

```text
select_action(indicator, M, S):
    if hard_rule_violation(action_class):       demote to highest non-violating rung
    if infrastructure_class == shared and rung > L4: demote to L4
    if scope == general_population and rung == L3: prohibited (L3 only for onboarded fixed segments)
    if rung == L5: require dedicated_use_evidence else demote to L4
    if rung == L6: require behavioral_cluster_depth >= 3 or active_compromise else demote to L2
    if rung == L7: require dual_approval (unchanged v1 routing constraints)
    return highest rung passing floors + hard rules + budgets
```

Demotions are recorded as reason codes (`demoted_shared_infra`, `demoted_no_dedicated_use`, `demoted_scope`) so operators see exactly why a weaker rung was chosen and what evidence would justify promotion.

## Rung details

### L1 — Challenge

At proxy/WAF/secure-web-gateway actuators the operator already operates. Suspicious-reputation clients (destinations they contact are L1-eligible) receive an interactive challenge on the proxied transaction. Honest users pass transparently; automated tooling fails. Deterministic inputs: client reputation class, destination eligibility flag, transaction class. Challenge is **never** applied to non-interactive protocols (no SMTP/ICS/DNS challenges — only human-facing HTTP-class transactions).

### L2 — Rate limit

Ceilings per (client, destination) pair at firewall/proxy. Converts C2 beaconing into detectable, throttled leakage rather than a working channel; preserves legitimate shared use because ceilings are per-pair, not per-destination-global. Feed for BD-1: a rate-limited pair that continues attempting at ceiling is strong continued-compromise evidence and feeds L6 justification.

**Ceiling semantics (v2.1.1, mandatory):** every L2 decision carries a concrete `rate_ceiling_per_min` on its selector — `limits.nominal_rate_ceiling_per_min` from policy, or a draw within the docs/29 `rate_ceiling` bounds when randomization is enabled (draw recorded on the decision, reproducible from decision-record fields). A rate_limit without a ceiling is an intent, not a rule: enforcement compilers REFUSE it, and policy validation rejects an L2 floor configured without a nominal ceiling. A destination-global L2 remains prohibited — the pair selector is mandatory (v2.1).

### L3 — Egress allowlisting for fixed-function segments

The strongest preventive control in the platform, and the one most aligned with OT guidance: for segments whose external communication requirements are **fixed and enumerable** (vendor remote access, historian uplink, time sync, update servers), egress is deny-by-default with an explicit allowlist. Every new egress destination is then an **approval event or an incident**, never silent. Onboarding a segment to L3 is approval-gated (change-managed, OT-owner signed off), but thereafter the enforcement itself is fully automatic: any destination not on the segment list is denied, logged, and raised as a first-seen egress incident (BD-6).

This rung is what makes the platform *preventive* rather than *reactive* for its most critical populations: a 0-day implant phoning home from an L3 segment is denied **by default**, without any indicator existing yet.

### L4 — Domain block (RPZ)

Unchanged from v1: exact-FQDN NXDOMAIN at the managed resolver, with allowlist precedence, TTL, shadow mode. The ladder elevates its role: it is the **primary blocking rung** for the shared-infrastructure era, and the reference exporter now emits shadow/enforce variants.

### L5 — Exact-IP deny

Unchanged from v1: highest thresholds, dedicated-use evidence, no shared infra, short TTL.

### L6 — Host quarantine

The chokepoint acts on the operator's **own** asset: an internal host with a corroborated behavioral cluster (BD families ≥ 3, or an active-compromise signal such as confirmed malware callback) has its egress restricted at the chokepoint to allowlisted destinations only (or fully, per policy) while investigation proceeds. Implemented via existing firewall/NAC APIs the operator already owns; no endpoint agent; no new inline dependency. Always approval-gated for full isolation; a reduced "quarantine-to-allowlist" form may auto-enforce under EMERGENCY policy with mandatory review expiry.

L6 is the answer to "the endpoint is already compromised and the C2 is on shared infrastructure": you cannot block the shared IP, but you can stop your own host from talking to it.

### L7 — Prefix/routing

Carried over from v1 unchanged (see `docs/06`): highest governance, dual approval, no automation.

## Capacity ceilings on constrained segments

Mimicry residual (a) — an attacker who perfectly imitates legitimate behavior inside an allowed envelope — is not detectable at the chokepoint, but its *impact* is boundable. Constrained segments (L3/allow-first populations) additionally carry **capacity ceilings**: per-(host, destination) and per-host aggregate byte ceilings derived from the segment's baseline (enumeration window plus rolling recompute, versioned like policy). Above the ceiling, traffic is throttled to the ceiling, not dropped — availability-preserving — and the event is worklisted as a capacity anomaly.

Properties:

- ceilings inherit L2/L3 semantics: shadow-staged, alarmed, break-glass-exemptible for documented bulk operations (backup windows, vendor uploads), and randomized within policy bounds per `docs/29` so the exact edge is not a fixed target;
- the honest claim is **rate-bounded loss, not prevention**: an exfiltrating mimic leaks at ceiling rate while the anomaly accumulates; the ceiling converts "unbounded data loss" into "bounded, evidenced data loss";
- ceilings apply only to constrained segments — never general user populations, where volume heterogeneity makes baselines meaningless.

## Shared-infrastructure registry

Central to demotion logic is a versioned **infrastructure class registry**: CDN, hyperscaler, hosting, anycast, recursive-DNS, VPN/anonymizer, Tor-exit, sinkhole/research, education/enterprise multi-tenant, dedicated/host. Sources: operator observation, contractually available metadata, community classifications. It is evidence (affects S), not an indictment (does not affect M by itself). Registry entries carry their own provenance and freshness windows, and the registry is signed/versioned like policy.

Anonymizer classes get explicit policy: `anon_policy ∈ {allow, challenge, rate_limit, block_by_context}` — default `rate_limit` for interactive traffic, `block_by_context` only for fixed segments (where L3 already handles it). Tor-exit traffic to non-approved destinations from OT segments is an incident by default.

## Multi-rung composition

Rungs compose: a single campaign may simultaneously hold L4 on its domains, L2 on its shared-IP endpoints, and L6 on two internal hosts, with L1 challenges at the proxy for anything that resolves through. The decision ledger records all active rungs per indicator/campaign; the campaign view shows the composed posture. Escalation rung-by-rung is the normal path; de-escalation on evidence decay is automatic (rung re-evaluation at each TTL renewal — see below).

## TTL and re-evaluation semantics

Every rung keeps the v1 TTL discipline with one addition: at each renewal the rung is **recomputed against current evidence**, not merely extended. If M decayed below the floor, the action lapses rather than renewing. If new evidence justifies a higher rung, renewal is an escalation event (new decision, new approval state if needed). Rungs never silently persist on stale evidence.

## Safety case integration

Each rung inherits the full v1 safety apparatus — staging, receipts, verification, budgets, canary rollout, auto-revoke on match-volume anomalies — plus:

- L1/L2 add **client-impact budgets**: max fraction of a tenant's interactive transactions challenged per hour; exceeding it alarms and auto-reverts to L0 for the overflow.
- L3 adds **segment-onboarding governance**: per-segment allowlist review, dry-run of "what would have been denied last 30 days" before activation (turning on L3 must never be a surprise).
- L6 adds **host-impact gates**: quarantine proposals must enumerate the host's business function (from the asset registry) and require owner-scope approval; OT-host quarantine additionally requires OT-operations signoff per `docs/08` defaults.

## What this preserves from v1

Every v1 hard rule survives unchanged: no ASN-wide automation, no automatic prefix deny, routing behind dual approval, allowlist precedence absolute, every action expiring, staged enforcement, edge-side scope validation. The ladder **narrows** what requires approval-only (only L5-without-dedicated-use, L3 onboarding, L6 full isolation, L7) by giving the policy engine safe intermediate rungs that v1 lacked.
