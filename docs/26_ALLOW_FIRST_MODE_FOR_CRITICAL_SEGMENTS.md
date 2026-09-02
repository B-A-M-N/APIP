# 26 — Allow-First Mode for Critical Segments

## Purpose

Everything else in APIP is **deny-list-by-default with layered escalation**: identify hostile infrastructure, then interdict it. This document specifies the inverse posture — **allowlist-by-default** — for the small set of network segments where the defensive argument inverts: fixed-function critical segments (OT control-network boundaries, DMZ service vectors, safety-adjacent zones, management networks) whose legitimate external communication is small, enumerable, and stable.

For these populations, "what is not explicitly allowed is denied" is not merely another control; it is the only posture under which novel, AI-generated, never-before-seen attack infrastructure is interdicted **before first contact**, because the default answer to a destination that did not exist yesterday is *no*.

This is the highest-leverage deterministic control in the platform. It requires no detection, no intelligence, no scoring, and no indicator — only the discipline of enumeration.

## Why this is the right default for critical infrastructure

1. **Zero-day-agnostic.** Novel C2 infrastructure, fresh DGA domains, newly registered attack infrastructure: all are denied by default because they are not on the list. No detection latency exists because no detection is required.
2. **Deterministic and provable.** The enforced state is a finite list; the safety question ("what could this break?") is answered by comparing traffic against the list — auditable, replayable, and simulatable before activation.
3. **Aligned with sector guidance.** CISA CPGs, NERC CIP-005 electronic security perimeter thinking, and ICS guidance (e.g., CISA's free ICS defenses portfolio) converge on deny-by-default egress for control networks. APIP operationalizes the pattern at the chokepoint with staged rollout.
4. **It composes with every other layer.** Allow-first segments still receive behavioral detection (on denied-attempt telemetry — which becomes an extremely high-signal detection source), full ledger/receipt/rollback discipline, and can host higher ladder rungs where policy allows.

## The catastrophic-failure objection, answered

The classical objection to deny-by-default egress is the false-positive outage: an undocumented legitimate dependency is denied and a critical function fails at 3 a.m. APIP's answer is that it already built the machinery to make allow-first safe — the same machinery that makes blocks safe, applied in mirror image:

| Block-mode hazard (v1) | Allow-first mirror (v2) |
|---|---|
| blocking a legitimate domain | allowing a malicious destination |
| allowlist prevents the FP | deny-list of known-malicious still applies beneath the allow-mode floor (defense in depth) |
| shadow mode previews the blast radius | shadow mode previews **denied-destination** volume before any denial exists |
| match-volume alarm → auto-revoke | denied-volume alarm → segment flags "missing dependency" review |
| TTL forces re-derivation | allowlist entries carry owner/expiry/review cadence |

The last mirror is the crucial operational difference: allowlist entries are **governed objects** with owner, ticket, expiration, and review cadence — not eternally-open firewall lines. A stale entry is a finding, not a feature.

## Segment onboarding lifecycle

Allow-first is per-segment, approval-gated, and staged. A segment never "just becomes" deny-by-default.

```text
1. ENUMERATE  — inventory the segment's legitimate external dependencies
                (passive observation window ≥ 30 days, asset-owner interview,
                 vendor documentation, protocol/port matrix)
2. SIMULATE   — replay the observed destination set against the candidate
                allowlist; report coverage %, denied-volume-by-destination,
                top denied destinations with owner attribution attempts
3. SHADOW     — enforce nothing; log every would-be denial, alert on
                novel destinations, run ≥ 2 weeks including a patch cycle
                and a maintenance window
4. CANARY     — enforce on one non-critical sub-segment or one time window
5. ENFORCE    — deny-by-default live; every denial is an event; every novel
                destination is an approval workflow or an incident
6. REVIEW     — scheduled allowlist review (quarterly default); entries
                expire without review; additions require owner+approver
```

Exit from any stage is backwards to the previous stage; exit from ENFORCE to SHADOW is the segment-level emergency stop and is one operator action.

The SIMULATE stage is the platform's distinctive capability here: because the chokepoint already holds flow history, it can compute — before anything is denied — exactly what deny-by-default would have denied last month, ranked by volume, with asset-owner attribution. The "3 a.m. surprise" is engineered out.

## Dependency-path narrowing and traffic profiles

A bare allowlist entry (destination only) hands a compromised allowed dependency the entire envelope: any port, any protocol, any volume. Two default disciplines narrow what an allowed dependency inherits:

**Tuple entries.** Allowlist entries are `(destination, protocol, port-range)` tuples by default; destination-only entries are the exception, requiring explicit justification at addition time. A compromised vendor server then reaches only the enumerated service path, not arbitrary ports on the segment.

**Traffic profiles.** Each entry carries a baseline profile derived from the enumeration window and maintained by review: expected volume band (bytes/hour), session cadence class (continuous / business-hours / batch), and peer scope (which hosts may use the entry). Sustained deviation outside the profile band raises a drift alarm — profile **drift is an incident signal, not an enforcement trigger**: the entry stays allowed (availability first) but the deviation is worklisted, correlated with behavioral evidence, and reviewed. This converts residual (b) — compromise of an allowed dependency — from "unnoticed full-envelope access" into "bounded path with an anomaly signal on deviation."

Both disciplines use only data the chokepoint already collects; profiles are recomputed at each scheduled review and versioned like policy.

## Interaction with the ladder (docs/25)

- An L3 (EGRESS_ALLOWLIST) rung **is** allow-first mode for that segment. Docs 25 and 26 describe the same control from two views: 25 as a ladder rung in campaign response, 26 as a standing posture for critical segments.
- Within an allow-first segment, the other rungs still apply beneath the default-deny floor: known-malicious destinations on the allowlist (a compromised vendor server, a poisoned entry) are still denied by the indicator layers (L4/L5 targets on the deny side); challenges and rate-limits apply to allowed destinations whose reputation decays. Defense in depth: **allow-first does not mean allow-blindly**.
- L6 host quarantine inside an allow-first segment reduces to "remove the host from the segment allowlist" — the simplest containment primitive in the platform.

## Denial telemetry as a detection goldmine

Every denied egress attempt from an allow-first segment is a high-signal event: by construction, nothing legitimate generates them. This feeds:

- BD-6 first-seen/novelty: a denied destination is the purest form of first-seen anomaly;
- immediate L4/L5 candidate generation for destinations denied repeatedly across hosts (cross-host denial clustering is near-campaign evidence);
- SOC worklists ranked by cross-host repetition and asset criticality;
- asset-owner notification workflows ("your historian tried to reach a new destination; approve or investigate").

The denied-destination log is retained with full decision provenance, subject to the same privacy minimization as all telemetry.

## Policy object extensions

The policy schema gains a `[segments]` table:

```toml
[segments.historian_uplink]
mode = "ALLOW_FIRST"            # ALLOW_FIRST | STANDARD
scope = "ot-dmz-a"
onboarding_stage = "SHADOW"     # ENUMERATE | SIMULATE | SHADOW | CANARY | ENFORCE | REVIEW
owner = "ot-ops"
review_cadence_days = 90
allowlist_ttl_days = 180        # entries expire without review
max_denied_volume_alarm_per_hour = 50
emergency_egress = "QUARANTINE_ALLOWLIST"  # documented break-glass profile

[segments.historian_uplink.allowlist]
# entries carry owner, ticket, expiry — managed as governed objects
```

Each segment has its own mode independent of the global mode. Global ENFORCE never implies segment ENFORCE: a segment advances through its own lifecycle regardless of platform mode, and **platform OFF does not disable an enforcing segment** (its allowlist is standing infrastructure policy, not a threat response that should vanish when the platform is quiescent) — but platform EMERGENCY can tighten all segments to their break-glass profiles.

## Break-glass and emergency access

Deny-by-default must never block incident response or vendor emergency access:

- each segment defines a **break-glass egress profile** (broader temporary allowlist, or quarantine-allowlist) activatable by dual control, time-boxed (default 4h), fully audited, auto-expiring;
- emergency-access servers (vendor VPN terminations) are enumerated in the onboarding inventory like any other dependency;
- break-glass activation is an alarmed, reported event — never silent.

## OT-specific defaults (extends docs/08)

1. Control-network boundaries and OT DMZ northbound edges are **primary candidates** for ALLOW_FIRST; enterprise user segments are not.
2. OT-owner signoff is a mandatory approver for segment onboarding and every allowlist addition in OT scopes.
3. Engineering-workstation and vendor-access paths get the strictest profiles (smallest allowlists, shortest entry TTLs).
4. Safety-instrumented-system and protection-relay traffic paths are **out of scope entirely** — APIP never inserts controls into protection paths (unchanged v1 rule); allow-first applies at the boundary *around* them, not inside them.
5. Time synchronization, grid-comms, and other latency/jitter-sensitive dependencies must be enumerated with protocol-aware allow entries (port/protocol-constrained, not just destination-wide open).

## What allow-first does not solve

- Attack paths that stay entirely inside a segment (lateral movement) — see docs 27 detection at inter-zone boundaries.
- Compromised **allowed** destinations (vendor server hacked): mitigated by indicator layers beneath the allow floor, challenge/rate-limit rungs on allowed destinations, and rapid allowlist revocation workflow; not eliminated.
- Populations whose function is not enumerable (general enterprise users) — explicitly out of profile; those populations keep the standard posture with the full ladder.

## Acceptance criteria additions

- Segment lifecycle state machine implemented and test-covered (including backwards transitions and break-glass expiry).
- SIMULATE report produces volume-ranked denied-destination preview with owner-attribution fields.
- SHADOW stage measures and reports novel-destination rate before any enforcement.
- ENFORCE segments show: zero undocumented denials, all denials evented, allowlist entries all unexpired-owned-governed.
- Break-glass: activation audited, time-boxed, auto-expiring; test proves expiry works with the controller offline.
- Allowlist entries default to tuple form; destination-only entries carry recorded justification (property test).
- Profile drift alarms fire on synthetic deviation; drift never auto-enforces (property test).
