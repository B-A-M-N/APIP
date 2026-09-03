# 29 — Deterministic Randomization (Moving-Target Defense)

## Purpose

A fixed defense is a *learnable* defense. An attacker — especially automated, adaptive tooling — observes the defensive response over time and adapts: probing until it finds the rate-limit ceiling, mapping which clients get challenged, timing activity to rule-expiry boundaries, and learning exactly how much beacon jitter stays under the periodicity threshold. Every fixed parameter is a specification of how to comply with the attack's requirements while staying under the filter.

The counter is **algorithmic randomization of defensive parameters within policy bounds**. The defender randomizes at near-zero cost; the attacker must then solve a stochastic observation problem on every attempt, with every probe itself generating evidence. Crucially, this is done without breaking APIP's determinism guarantees: randomization uses **recorded seeds**, so every randomized decision remains exactly replayable and auditable.

Two properties hold simultaneously:

- **To the attacker:** the defense's observable behavior at time T is a *drawn* value within policy bounds, not a stable constant the attacker can tune a single probe against and then stay under indefinitely. Because the draw changes per epoch/window (docs/29 P1-8), an attacker who adapted to the last observed value must re-probe and re-adapt, and each re-probe generates more evidence. This is **deterministic parameter diversity** intended to complicate simplistic adaptation — it is NOT cryptographic unpredictability (see "Security model — what this is and is not").
- **To the operator/auditor:** given the evidence snapshot, policy version, clock bucket, and recorded seed, the exact same decision is reproduced. NFR-003 is preserved.

## Scope — what may be randomized

Randomization applies to **how** a policy executes, never to **whether** safety applies. It is never a source of new authority. The randomized draw happens *inside* the envelope the policy already authorized; a draw can only select within safe bounds, never outside them.

| Mechanism | Randomized parameter | Policy bounds (reference defaults) |
|---|---|---|
| L1 challenge sampling | which fraction of eligible clients are challenged this window; per-client challenge probability | 10–100% of eligible set; floor guarantees (see budgets) |
| L2 rate ceilings | per-pair ceiling value for the window | drawn from [floor, ceiling] range set by policy, e.g. [0.5×, 1.0×] of nominal |
| TTL/renewal jitter | rule renewal instant and TTL within class bounds | ±20% of class TTL, never below minimum evidence TTL, never above max TTL |
| Shadow review sampling | which shadow matches escalate to analyst worklist | 1–100% by priority band |
| BD threshold dithering | detection thresholds dithered within a band around the policy value | ±10% band; band itself is policy |
| Shadow-window placement | start/duration of behavioral analysis windows | within window-bound policy |
| Quarantine allowlist form | reduced-egress vs allowlist-only quarantine variant where both are authorized | both variants pre-approved |
| Canonical orderings | non-semantic output ordering (bundle entry order where order-insensitive) | any permutation of an order-insensitive set |

What is **never** randomized:

- authorization and scope checks;
- safety scores, hard rules, and floors (only dithering *around* a policy value, and only in the direction/width policy allows);
- allowlist precedence;
- TTL *existence* (every action still expires; jitter changes when, within bounds, not whether);
- approval requirements;
- anything in the signing/verification chain.

## Seeded-randomization architecture

```text
policy (versioned bounds)
        +
evidence snapshot hash
        +        SHA-256 counter-mode DRBG
clock bucket  -------------> seed (recorded in decision)
        +                        |
        v                        v
decision context ------> parameter draw(s) ------> enforcement parameters
                                 |
recorded in decision: seed_id, draw context, bounds version, resulting values
```

Requirements:

1. **Deterministic DRBG, not a secret-key CSPRNG.** All draws go through one SHA-256 counter-mode DRBG (`ApipRng`); no language `random` calls scattered in logic. The seed is recorded in the decision, so an outside observer who holds a past decision can reconstruct the seed and predict every draw that shares that seed material. Draws are therefore **deterministic parameter diversity**, not cryptographic unpredictability — see the security-model note below. Statistical quality (uniformity, cross-mechanism independence, no short cycle) is still required and tested.
2. **Seed is recorded, never secret.** Reproducibility is the point: the seed is part of the decision record, so replay reproduces the exact draw. Where the threat model genuinely requires that an outside observer cannot predict future windows, the operator MUST add real edge entropy per window (deployment secret or edge-generated random seed mixed into the clock bucket), as described below; the base engine ships the deterministic-diversity mode by default.
3. **Draw context is recorded.** What was drawn, from what bounds, for which mechanism — fully explicit in the decision/receipt.
4. **Bounds are policy versioning.** Changing a bound is a policy change, with replay/diff/gates, exactly like thresholds.
5. **Independence across mechanisms.** Correlated draws would let one observed parameter predict others; each mechanism draws from an independent stream.

## Attacker model and effect

Consider the adaptive probing loop the randomized design is aimed at:

```text
classic:  probe -> observe fixed response -> adapt once -> compliant forever
randomized: probe -> observe one draw -> adapt -> next draw differs -> re-probe
                    -> each re-probe is more evidence (BD near-miss clusters)
```

Quantified intuition: against a fixed ceiling C, the attacker converges to "just under C" after a handful of probes and leaks indefinitely at rate ~C. Against a ceiling drawn per window from [0.5C, C] with renewal jitter, the attacker's stable choice is bounded by the *floor of the range* to avoid repeated enforcement, and any attempt to exploit the upper range collides with the draw stochastically — converting steady exfiltration into intermittent, detectable enforcement events. The defense pays a parameter draw; the attacker pays a permanent throughput tax and a persistent detection risk. Similar logic applies to challenge sampling (the attacker cannot certify "clients like mine pass") and TTL jitter (no clockwork window opens reliably).

This is asymmetric-cost deterrence implementable in a few hundred lines of deterministic code — the point of combining it with the rest of the platform rather than relying on it alone.

## Security model — what this is and is not (audit P1-11)

APIP's randomization is **not** a cryptographically unpredictable CSPRNG deployment. `ApipRng` is a deterministic SHA-256 counter-mode DRBG seeded *entirely* from recorded decision context — indicator identity, policy version, scores, scope, bounds version, and the epoch bucket. Every one of those inputs is published in the decision record (that is what makes replay exact). Therefore:

- **An outside observer who sees one past decision can reconstruct its seed and predict every future draw that shares the same seed material** (same indicator, policy, and epoch bucket). Within an epoch, the defense does not hide its draw from a patient observer.
- The value supplied by these drawn parameters is that the *specific* value is not a fixed constant the attacker can probe once, converge to, and then stay under indefinitely — each epoch yields a freshly *drawn* value, so the attacker must keep probing/re-adapting and keeps generating evidence while doing so. This is **deterministic parameter diversity intended to complicate simplistic adaptation**, not secrecy of the draw.

The design deliberately trades "unpredictable to an outside observer" for "exactly replayable by the operator." Where the threat model actually requires that no outside observer can predict future windows, that is a deployment-time enhancement, not something the seed-only engine can claim:

> **Optional edge-entropy mode.** Mix a high-entropy per-window secret into the seed material: a deployment secret or an edge-generated random seed drawn once per epoch (e.g. `seed = H(deployment_secret ‖ window ‖ context)` via the same DRBG). Record the actual replay seed in the protected audit ledger *after* use, so the operator can still reproduce the draw while an outside observer without the secret cannot predict future windows. This is the honest way to reach docs/29's "unpredictable to an outside observer" claim, and it is opt-in because it moves the platform from "dependency-free deterministic replay" to "secrets must be guarded."

Deterministic hash generation and unpredictable CSPRNG deployment are different properties; this document claims the former by default and describes the latter only as an operator-sourced enhancement.

## Interaction with safety machinery

- **Budgets:** randomized parameters still consume action/safety budgets at their nominal (pre-draw) values; conservative accounting.
- **Client-impact budgets (L1/L2):** the *floor* side of every randomized range respects impact budgets — randomization may reduce impact below budget, never exceed it.
- **Replay:** with seed + evidence + policy + clock bucket, replay is bit-identical. The reaper, receipts, and reconciliation compare recorded values, not re-drawn ones.
- **Renewal re-evaluation (`docs/25`):** jitter changes the renewal instant; at renewal the rung is recomputed against current evidence and a fresh draw, preserving both anti-prediction and no-stale-enforcement properties.
- **Shadow mode:** randomized sampling still applies in SHADOW (which shadow matches would have been enforced), so shadow statistics reflect production behavior rather than a deterministic pipeline that production later diverges from.
- **Property tests:** `bounds` invariants — for every mechanism, every possible draw lies within policy bounds; floors respected; independence of streams verified statistically over large samples.

## Placement note (why this is not a honeypot)

Randomization here perturbs parameters of controls that are already justified on evidence — which clients are challenged, what ceiling applies, when a rule renews. It does **not** create deceptive surfaces, advertise fake services, or invite attackers into exposed hosts. The no-honeypot boundary (FULL_SPEC §4) is unchanged: nothing in this document makes the host more visible or more attractive to an attacker than it already was.

## Conformance requirements

1. All draws through the platform deterministic DRBG abstraction (`ApipRng`, SHA-256 counter mode); no language `random` calls scattered in logic. (Not a secret-key CSPRNG — see "Security model — what this is and is not".)
2. Every randomized decision records: mechanism, bounds version, seed, draw context, resulting value.
3. Replay with recorded seed reproduces exact outputs (CI test).
4. No randomized mechanism can produce a value outside its policy bounds (property test).
5. Every randomized mechanism degrades cleanly when disabled (policy flag per mechanism; defaults documented per deployment profile).
6. Statistical tests over large draw samples: uniformity within bounds, cross-mechanism independence, no cycle within operational horizon.

## Acceptance criteria additions

- Adaptive-attacker simulation: against randomized ceilings, sustained exploitation rate is measurably suppressed and enforcement-collision rate measurably raised versus fixed parameters (offline, replayed corpus).
- Audit demonstration: pick any historical randomized action; reproduce its parameters exactly from recorded seed and policy version.
- All property tests above running in CI.
