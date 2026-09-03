# Changelog

All notable changes to the **reference implementation** (`reference/`), the
APIP specification revision, and the shipped contracts are recorded here.
Versioning: reference declares its own `0.x` version (`pyproject.toml`) and the
spec revision is tracked separately — see `RELEASES.md` for the version model.

## [Unreleased]

### Audit zero-trust hardening pass (P0–P2 residuals, 2026-09-02)

- **Evidence/source authority boundary rebuilt (P0-1/2/3):** source identity is
  bound to the ingest channel (`trusted_sources`); a payload that names an
  un-certified source is demoted to `unregistered` (zero authority); client
  score fields are ignored; safety facts (verified rollback, robustness) are
  derived server-side from the governed registry, not read from input.
- **Annotation invariance before the evidence cap (P0-4):** the evidence
  envelope is deduplicated then capped so exculpatory evidence is never crowded
  out.
- **Policy validation hardening (P0-5/6, P1-1/2):** component-wise floor
  monotonicity, ENFORCE authorization boundary required, strict dates/CIDRs/
  ranges, and the family/randomization bounds rejected at load. A **negative
  `--transactions-per-hour` is rejected** (previously overloaded the
  "unconfigured" sentinel and disabled the L1 budget).
- **Time-aware freshness/corroboration (P1-3/4/5):** stale safety facts can no
  longer corroborate; future-dated evidence is stale, not fresh.
- **Randomization semantics repaired (P1-7..11):** only wired/supported
  mechanisms, real epoch from rotation interval, action-instance identity +
  content hashes, honest seed model, byte-exact draws.
- **Attribution lab repairs (P1-12..19):** two-step P5 challenge, identity
  handling, loopback bind enforcement, key fail-closed behavior, correlation
  locking; capture is never an enforcement input.
- **Behavioral subsystem repairs (P1-20..24):** BD-1 re-arm/timestamps, bounded
  emission, deterministic envelope shedding.
- **Exporter + receipt truthfulness (P1-25..28):** structured exporters return
  `CompiledArtifact`s; a rule not turned into an actuator is flagged
  `monitoring_only`; receipts are **artifact-derived** (a decision that produced
  no artifact gets no receipt) and carry bundle + fragment identity; batch/parser
  integration gates.
- **Schema/API/runtime contract unification (P1-29..35):** one canonical
  indicator `type` enum and receipt lifecycle across JSON Schema + OpenAPI +
  runtime; unknown/unimplemented policy fields rejected at load; duplicate
  schema keys linted; runtime `validate_policy` enforces schema constraints;
  dates are parsed to real instants (a parse failure expires an allow, never
  "allow forever").
- **CI / tests / input hardening (P1-39..42, P2-43/44):** clean-checkout CI
  (`git clean -xffd`) + tests generate their own fixtures; `ResourceWarning`
  lane + context-manager capture writer lifetime; no-AI module coverage made
  structural (package-prefix, covers `behavioral`, `sanitize`, `exporters.*`,
  `live.*`); deterministic property tests (selector-never-broadens, fragment
  determinism, evidence-permutation invariance, hostile-value fuzz); hard byte
  gate before reading indicator files; strict array/object type validation
  (`type=[]` / `tags="abc"` reject cleanly instead of crashing).
- **Docs truth-pass (P1-31, release):** OpenAPI marked "DRAFT FUTURE"; offline/
  socket claim corrected (loopback-only attribution socket is real); `RELEASES.md`
  documented (version model + implementation-status matrix); `SECURITY.md`,
  `CONTRIBUTING.md`, `CHANGELOG.md` added.

## 0.1.0-2026-09-02 — v2.2 (closed independent-audit residuals)

- L1 client-impact budget enforced per invocation with fail-closed reversion
  (`docs/25`), replacing the -1 sentinel.
- Deterministic randomization draw recording (`docs/29`) with exact replay.
- References the v2.2 spec revision; `examples/policy.toml` schema revision
  is `2026-09-01.2`.

## 0.1.0-2026-09-01 — v2.1.1 (closed adversarial-audit residuals)

- Zone-file/rule injection class closed (FQDN charset, comment-safe escaping).
- Canonical allowlist matching; allowlist `expires_at` enforced; governed
  entries require owner + ticket.
- Blast-radius batch budget with overflow demotion and named reasons.
- Authorized-prefix enforcement boundary; malformed CIDR rejected at load.
- Thread-safe capture writer/counter/store (exact cap under contention).
- IPv6 cross-format handle stability; hostile Content-Length refused/clamped.

## 0.1.0 — v2.1 (initial reference scaffold)

- Deterministic, dependency-free scoring with M/S scores and two rung variants.
- Evidence-source registry with class + independence assigned server-side.
- Dry-run RPZ/Suricata exporters; offline evaluation of synthetic indicators.
- Attribution lab (`lab/`) demonstrating the docs/30 boundary end-to-end.
- No-AI conformance gate (`docs/28`).