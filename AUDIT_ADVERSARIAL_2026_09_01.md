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

> **v2.1.1 status: residuals 2, 4, 5 CLOSED in code; residuals 1 and 3
> closed as named. See the "Residual closure (v2.1.1)" section below.**

1. ~~The scaffold is a **decision engine**, not a deployed product~~:
   CLOSED AS NAMED for the detector gap — `apip/behavioral.py` now ships a
   bounded streaming detector (BD-1 beacon periodicity) exercising the
   docs/23 envelope contract (bounded windows, bounded events, bounded
   per-window emission, stop-and-mark degradation, deterministic eviction).
   What remains open is inherent: production-scale streaming, buffering,
   and backpressure around the detector are deployment code, and the
   shipped CLI still loads indicator files wholesale (batch is its
   contract).
2. ~~**L2 `rate_limit` has no rate parameter**~~: **CLOSED.** The L2
   selector now carries `rate_ceiling_per_min` (docs/25 client-impact
   budget) — nominal, or drawn within docs/29 `rate_ceiling` bounds with
   the draw recorded and reproducible from decision-record fields. The
   Suricata exporter REFUSES to compile a ceilingless rate_limit (raises),
   compiles ceilings as `detection_filter:track by_src, count N,
   seconds 60`, and fqdn pair rate-limits now compile as `http.host`
   rules instead of vanishing while receipts claimed otherwise. Policy
   validation rejects an L2 floor configured without a nominal ceiling.
   (`tests/test_audit_residuals.py::RateCeilingTests`)
3. The P5 key-order extractor is a best-effort lexical scan, not a JSON
   parser; exotic serializations could yield an empty or partial order.
   It fails closed (empty feature → no contribution). **HARDENED
   (v2.1.1)**: bounded scan budget, bounded key count/length, JSON-key
   charset validation, escape-aware scanning; hostile bodies yield an
   empty order rather than polluted features.
   (`tests/test_audit_residuals.py::P5HardeningTests`)
4. ~~Attribution handles are unsalted SHA-256 prefixes~~: **CLOSED.**
   Handles are now keyed HMAC-SHA-256 under a per-deployment key
   (`APIP_DEPLOYMENT_KEY` env or `APIP_DEPLOYMENT_KEY_FILE`), so the
   low-entropy client-address space can no longer be brute-forced from a
   stolen report. Determinism within a deployment (and therefore
   correlation and replay) is unchanged; rotation of the key re-baselines
   handles by design; keys must not be shared across deployments. Absent
   a key, the scaffold degrades to a marked dev fallback and the report
   itself prints an UNKEYED HANDLES banner.
   (`tests/test_audit_residuals.py::KeyedHandleTests`)
5. ~~Recency is wall-clock anchored, so byte-replay is only exact within a
   freshness window~~: **CLOSED.** `Policy.reference_now` (policy knob
   `[replay].reference_now`) pins the recency clock; the packaged example
   policy pins it, so the demo evaluates byte-identically at any date.
   (`tests/test_audit_residuals.py::ReplayClockTests`)
6. **Independence was asserted per feed** (two records were counted as two
   sources merely for arriving through two feeds — docs/04 says they are
   not): **CLOSED.** `SourceProfile.upstream` carries provenance;
   corroboration counts DISTINCT upstream identities — three resellers of
   one upstream corroborate once.
   (`tests/test_audit_residuals.py::ProvenanceIndependenceTests`)
7. **Unbounded per-indicator evidence** (reason growth by distinct kind):
   **CLOSED.** `limits.max_evidence_per_indicator` (docs/23 envelope) caps
   scored records with a deterministic truncation reason.
   (`tests/test_audit_residuals.py::EvidenceEnvelopeTests`)
8. **Lab adversary never rotated behavior** (the rotation scenario was
   friendlier than reality): **CLOSED.** Lab scenario `churn` now runs the
   honest adversary — full behavioral rotation is demonstrated UNTRACEABLE
   (the engine claims nothing), partial churn leaves value-matched
   containment links. The HTTP/2 and real-TLS-stack fidelity limits of the
   loopback lab remain and are inherent to an offline stdlib-only
   demonstration (documented in lab/README.md).

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

## Residual closure (v2.1.1)

Every residual named by this audit and the follow-up verdict was closed
with code + regression tests (`tests/test_audit_residuals.py`, 23 tests)
or closed-as-named with the boundary stated:

| residual | status | enforcement |
|---|---|---|
| L2 rate_limit had no ceiling | **CLOSED** | selector carries drawn/nominal ceiling; exporter refuses ceilingless; draw recorded + replayable; policy validation requires the nominal |
| fqdn rate-limits compiled to nothing | **CLOSED** (found during closure) | http.host + detection_filter rules; ceiling in metadata |
| docs/23 envelopes unexercised | **CLOSED** | `apip/behavioral.py` BD-1: bounded windows/events/emission, stop-and-mark degradation, deterministic eviction |
| P5 lexical scan steerable | **HARDENED** | bounded budget, charset, escape-aware; hostile bodies fail closed |
| unsalted handles | **CLOSED** | keyed HMAC-SHA-256 per deployment; unkeyed state bannered in reports |
| wall-clock-only replay | **CLOSED** | `reference_now` pin; example policy ships pinned |
| asserted independence | **CLOSED** | `upstream` provenance; corroboration counts upstream identities |
| unbounded per-indicator evidence | **CLOSED** | `max_evidence_per_indicator` envelope + truncation reason |
| lab adversary never rotated behavior | **CLOSED** | lab `churn` scenario: full rotation untraceable (stated), partial churn linkable |
| production streaming/backpressure | open, inherent | deployment code around the reference detector; CLI batch contract unchanged |
