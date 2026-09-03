# Contributing to APIP

Thanks for helping. APIP is a **deterministic, dependency-free** security
decision engine, and its reference scaffold is deliberately minimal. Before you
open a change, read the invariants below — the CI gate and the no-AI/schema
conformance tests enforce them.

## The hard invariants (do not break these)

1. **No AI / no model inference.** The reference must stay free of every
   inference SDK. `reference/tests/test_no_ai_conformance.py` machine-checks the
   dependency allowlist, the AI package ban list, and forbidden call shapes.
2. **Determinism.** Every draw must flow through `apip.randomize.ApipRng`
   (SHA-256 DRBG). Never import Python's `random`, `secrets`, or `os.urandom` in
   a decision path. Tests that need pseudo-random fuzzing use a fixed-seed LCG
   (see `PropertyBasedTests` in `tests/test_adversarial_audit.py`), never
   `random`.
3. **Zero runtime dependencies.** The scaffold is dependency-free stdlib-only.
   `pyproject.toml` declares no runtime dependencies; tests may use optional
   deps (`jsonschema`, `PyYAML`) only as gated cross-checks.
4. **Fail closed.** A security policy/tool must never silently ignore an
   accepted safety-bearing field. Implement it or reject it loudly. Rejecting
   hostile input is always preferable to coercing it into something plausible.
5. **One canonical model.** Never maintain parallel enums/contracts (schema vs
   OpenAPI vs runtime). When they must agree, add a cross-check test
   (`tests/test_schema_conformance.py`).
6. **Schema-valid == loadable.** If the schema declares a field the runtime
   cannot honor, reject it at load rather than accept-and-ignore.

## Before you submit

- Run the full gate: `cd reference && ./verify.sh`. It must pass (it is also
  green from a pristine `git clean -xffd` checkout).
- Run the tests: `cd reference && PYTHONPATH=src python -m pytest tests/ -q`.
- Ensure no `ResourceWarning` under
  `PYTHONWARNINGS=error::ResourceWarning` (CI enforces this).
- If you touch exporter/selector logic, add or update the selector-never-
  broadens and artifact-derived-receipt invariants.
- Add a regression test for any defect you fix (the repo's convention is that
  every demonstrated finding has a pinned test).

## What to update when you change behavior

- `reference/` source + `tests/`.
- If an emitted artifact or contract changes: `schemas/`, `api/openapi.yaml`,
  and the schema-conformance tests.
- If a documented version/status changes: `RELEASES.md` (the single version and
  implementation-status authority) and `CHANGELOG.md`.
- `BUILD_VERIFICATION.txt` records which invariant checks pass.

## Style

Match the surrounding code: `from __future__ import annotations`, type
annotations, the docstring convention. Keep the differential to the enclosing
comment density and idioms.

## Security

See `SECURITY.md`. Report suspected vulnerabilities privately, not in a public
issue. Do not add code that assumes attacker-owned infrastructure; APIP is a
hack-back-free design (`docs/03_THREAT_MODEL.md`).