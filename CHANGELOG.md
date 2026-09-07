# Changelog

All notable changes to the **reference implementation** (`reference/`), the
APIP specification revision, and the shipped contracts are recorded here.
Versioning: reference declares its own `0.x` version (`pyproject.toml`) and the
spec revision is tracked separately — see `RELEASES.md` for the version model.

## [Unreleased]

### 48-finding rereview remediation (P0 #1–#21, P1 #22–#41, P1/P2 #42–#48)

The full rereview verdict was "APIP is not public-beta stable yet"; this
release implements every finding. Highlights (commits `94e5910`..HEAD):

- **P0 safety core:** action posture is immutable and enforced at the adapter
  boundary (effective posture = min(action mode, adapter maximum)); SHADOW is
  structurally non-enforcing (separate shadow artifact, never attached to the
  live response-policy chain / ruleset); RPZ rewritten to real BIND
  policy-zone semantics and proven against real `named`
  (`lab/bind_gate.py`); Suricata ENFORCE withdrawn from beta (IDS/export
  surface, truthfully refused); SIDs allocated durably (no restart reuse);
  RPZ physical rules are co-owned with refcount semantics; actions are
  re-authorized at dispatch time and revocation never depends on current
  scope.
- **P0 identity/ingest:** source identity reserved at every layer (incl. a
  DB CHECK); observable identity is SERVER-DERIVED from canonical
  (itype, value) with submitted ids kept as provenance; ingest is a
  resumable unit of work (processing/complete/failed); the blast-radius
  budget is enforced per batch with deterministic demotion; duplicate
  actions from unchanged decisions are refused at the database.
- **P0 credentials/approvals/provenance:** keyed source credentials
  (`apipk_<key_id>.<secret>`, one indexed row + one PBKDF2 verify),
  optional deployment-secret pepper (versioned scheme); durable one-shot
  approvals (`decision_approvals`); every action cites the exact immutable
  decision instance (composite FK); policy promotion enforces the governed
  posture ladder; one-active-policy is a DB invariant; operator revoke vs
  worker expiry serialize on one CAS claim.
- **P1 product surface:** loopback-only Compose publish + `.dockerignore`;
  env layering (defaults → TOML → `APIP_*`); CLI/API contract aligned;
  `/health`,`/ready` bare + authenticated `/status` with explicit degraded
  reasons; DB pool survives a Postgres restart (connection-level recovery,
  proven against a real killed-backend outage); adapter artifact-boundary
  config validation; reload command takes a no-shell argv form; acceptance
  gains `--require-postgres` release mode and a two-level evidence model.
- **P1/P2 release honesty:** product CI lanes (pytest against required
  Postgres, pyright, no-AI invariant, deprecation-warning lane, wheel +
  clean-venv CLI, Compose smoke, real-BIND gate); dependency pins to the
  tested-at lines; `api/openapi.yaml` renamed `openapi.future.yaml` and the
  real contract generated as `api/openapi.beta.json` with a drift test;
  placeholder pyproject URL and false `Typing :: Typed` classifier removed;
  SECURITY.md rewritten (private reporting via GitHub security advisories,
  real scope/supported versions); release/version docs state the product
  version truth (`0.1.0b1`).

### Release-verification artifact audit (v2.3, 2026-09-03)

- **MANIFEST.json regenerated against the git tree.** The v2.2 snapshot never
  covered the product package (`src/apip/`), `deploy/`, or `lab/acceptance.py`,
  and 43 of its 88 hashed files had drifted from the tree, while
  `BUILD_VERIFICATION.txt` asserted "all hashes match this tree." The manifest
  now pins **166 files** — every tracked path except `MANIFEST.json` itself
  (self-excluded) — with SHA-256 verified to match on all 166.
- **BUILD_VERIFICATION.txt corrected.** Its `python -m unittest discover -s
  tests -v: PASS (187 tests)` claim was stale on two axes: the product suite is
  pytest-run (that unittest invocation discovers 0 tests at the repo root) and
  stands at 190, while the reference `unittest` suite it describes is 264.
  Header bumped to v2.3; true reproductions for both suites documented; a
  copy-paste MANIFEST verifier added.
- **RELEASES.md version authority aligned to v2.3.** Spec-revision matrix and
  the `BUILD_VERIFICATION.txt` cross-reference updated; only these
  verification-record artifacts changed — no production or test code.

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