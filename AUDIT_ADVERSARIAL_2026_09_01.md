# Adversarial Audit — 2026-09-01

Scope: full reference scaffold, live capture package, attribution engine,
lab. Method: attack the code with working proofs-of-concept (13 probes),
then fix what broke and pin every fix with a regression test
(`reference/tests/test_adversarial_audit.py`). Nothing in this report is
speculation; every finding was demonstrated against the running code.

## Findings — fixed and pinned

| # | finding | severity | fix | regression test |
|---|---------|----------|-----|-----------------|
| 1 | **RPZ comment injection**: `evil.com;` passed `_canonicalize` and reached the RPZ zone file, where `;` opens a comment — indicator-controlled injection into a compiled enforcement artifact | high | closed LDH charset `[a-z0-9_-]` + label ≤63 / total ≤253 enforced in `io._canonicalize` | `ZoneInjectionTests` |
| 2 | **Freshness control was a lie**: `load_policy` shipped an always-`fresh` classifier — the packaged demo never exercised evidence decay, contradicting docs/04 | high | default classifier actually decays (`config._default_recency_classifier`, 6h default, `freshness.max_age_hours` policy knob) | `RecencyDefaultTests` |
| 3 | **Cross-format handle fragmentation**: Envoy logs `ip`, HAProxy logs `ip:port` — the same client derived different pseudonymous handles per terminator, silently destroying cross-format correlation (the engine's core feature) | high | `_safe_client` normalizes to address-only (port stripped, address still validated) | `HandleStabilityTests` |
| 4 | **Self-poisoning artifact chain**: the live origin writes `{"rejected": true}` markers; the offline loader crashed on its own partner component's output | medium | CLI loader skips rejection markers | `RejectionMarkerTests` |
| 5 | **State pinning via future timestamps**: a requester stamped `9999` survived TTL eviction forever — bounded-store exhaustion via log-controlled clocks (TM-009 live variant) | medium | future-stamped entries beyond the TTL horizon are evicted as stale | `FutureStampTests` |
| 6 | **Seed publication unstated**: the randomization seed derives from decision-id + bounds-version + epoch, all printed in the decision record — anyone holding one decision can reproduce its draw | accepted (documented) | documented in `policy.py`: security never rested on seed secrecy; it rests on bounds-enforcement (no out-of-bounds value is actionable) + epoch rotation. Hiding the seed would break auditability without adding security | code comment, docs/29 aligned |
| 7 | **P1 hop sensitivity**: one reordering hop (HTTP/2, some proxies) changes the header-order vector | accepted (documented) | order-insensitive `P1:header_set` retained for containment linking; order-vector instability is inherent to the feature class | `P1HopSensitivityTests` |
| 8 | **Unbounded reason growth**: 5000 unknown evidence kinds → 5001 reason codes | low (dup kinds collapse; residual: distinct-kind growth) | duplicates collapse via set-dedup; per-indicator evidence bounds remain a docs/23 envelope duty | `ReasonCardinalityTests` |

## Probes that did NOT break anything

- **Evidence-payload score smuggling** (`points_m`, `points_s`, `origin`,
  `family`, `independent`, `source_class` in payloads): inert, as designed —
  stripped at ingestion, authority lives server-side.
- **Annotation/attribution isolation**: byte-identical decisions with
  adversarial attribution/annotation records attached, at every evidence
  strength. The docs/28 and docs/30 boundaries held.
- **Corroboration lattice bypass attempts**: unregistered and annotation
  sources claiming `curated_source` kinds qualify for nothing; family counts
  provenance-gated to local sources.
- **Adapter log injection**: malformed client refs, dup-list header orders,
  non-ISO timestamps, unknown fields — all rejected, never coerced.
- **Challenge-origin exposure**: non-loopback binds refused by default; no
  enforcement vocabulary exists in the live package (structural CI test).
- **Behavioral caps**: single-family and uncorroborated M contributions cap
  below all action floors regardless of evidence volume.

## Residual risks (stated, not hidden)

1. The scaffold is a **decision engine**, not a deployed product: resource
   envelopes for the *behavioral* suite are specified (docs/23) but the
   reference has no streaming detector to bound; the shipped CLI loads
   indicator files wholesale. An operator scaling this must implement the
   envelope code, not just configure it.
2. **L2 `rate_limit` has no rate parameter** — the rung is selected and
   compiled as an intent, but ceiling values (per docs/25 client-impact
   budgets) are production-compiler work. The scaffold would emit a rule
   with no ceiling semantics.
3. The P5 key-order extractor is a best-effort lexical scan, not a JSON
   parser; exotic serializations could yield an empty or partial order.
   It fails closed (empty feature → no contribution).
4. Attribution handles are unsalted SHA-256 prefixes. Within one deployment
   the input space (client IPs) is low-entropy; anyone who can guess the IP
   space can invert handles. This is acceptable for per-deployment
   pseudonymization (docs/09 threat model: handles must not be
   cross-deployment joinable), but it is NOT anonymization against a
   determined insider — salted HMAC with a deployment key would be the
   production upgrade.
5. Recency in the scaffold is wall-clock anchored (`datetime.now`), so
   byte-replay of decisions is only exact within a freshness window.
   Production replay must pin the reference clock (the policy schema
   already carries the knob; the deterministic-replay harness in docs/10
   describes the anchoring).

## Verdict

**Not theater in design; partially theater in completeness — and the
theater was in specific, named places, all now fixed or named above.**

The core claims survive adversarial attack: evidence cannot carry scores,
AI/attribution output cannot move decisions, corroboration cannot be
satisfied by unqualified sources, bounds cannot be escaped, and the
decision path is deterministic. What the audit invalidated was the gap
between *specified* and *enforced* in three places (zone-injection
charset, freshness default, handle normalization) — all demonstrations of
the same failure mode: an invariant stated in docs but not enforced in
the last mile of code. That failure mode is exactly what regression
tests are for, and every gap now has one.
