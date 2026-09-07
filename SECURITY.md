# Security Policy

APIP is a defensive network-control platform for infrastructure an operator
owns or is explicitly authorized to control. The repository ships two
codebases:

- **`src/apip` (product, `apip-beta` 0.1.0b1)** — the operator control plane:
  ingest → deterministic decision ledger → exact-FQDN RPZ shadow/enforce
  publishing (level-2-proven against real BIND) and an IDS/export Suricata
  surface. **This is a public beta: it is not hardened for hostile-network
  exposure.** Follow the deployment profile in `docs/07` (loopback bind,
  TLS-terminating reverse proxy for any remote access, secrets via
  environment/`*_FILE` only).
- **`reference/` (scaffold)** — a deterministic, dependency-free,
  offline/dry-run decision engine and test oracle. It makes **no outbound
  network connections** and performs **no actuator mutations**. It is **not**
  an enforcement deployment; do not run it as one. Its L1 budget /
  blast-radius gates are per-invocation approximations, not durable
  enforcement accounting.

## Supported versions

| Version | Status | Security fixes |
| --- | --- | --- |
| `apip-beta` 0.1.0b1 (product, `src/apip`) | public beta | **supported** — fixes land on `main` |
| reference 0.1.0 (`reference/`) | scaffold / oracle | supported while it remains the test oracle |
| any other / unreleased state | unsupported | no fixes |

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.** Report it
privately via GitHub's **"Report a vulnerability"** security advisory on this
repository (`github.com/B-A-M-N/APIP` → Security → Advisories → New draft
security advisory). That channel is private to the maintainers until you
choose to publish.

Please include:

- the product version (`pip show apip-beta`, or the wheel/git SHA you run);
- a description of the issue and steps to reproduce (config, policy text, and
  redacted requests are far more useful than descriptions alone);
- the impact you believe it has (and, if you have one, a suggested fix).

Please do **not** include live credentials, real source keys, or real
indicator data in reports.

## Scope

**In scope** — the beta control plane: the operator API and its
authentication (`src/apip/api`), the decision path and policy loader
(`src/apip/decision`, `src/apip/ingest`), the ledger and migrations
(`src/apip/ledger`), the enforcement adapters and their artifact boundaries
(`src/apip/adapters`), the CLI (`src/apip/cli`), and the shipped deployment
files (`deploy/`).

**Out of scope** — reports requiring a deliberately unsupported deployment
(exposing the plain-HTTP API to a hostile network contrary to `docs/07`,
disabling auth, sharing the operator token); the `reference/` scaffold's
offline dry-run nature (it performs no enforcement by design); volume-based
denial of service against a lab deployment; the attribution lab
(`lab/`, loopback-only by construction).

The platform's own threat model and guardrails (hack-back prohibition,
shared-infrastructure safety, false-positive outage limits) are in
`docs/03_THREAT_MODEL.md` and
`docs/20_SAFETY_CASE_AND_FAILURE_ANALYSIS.md`. The no-AI invariant is
machine-checked (`docs/28`), and the product CI lane enforces it on the
decision path.

## Disclosure process

1. Maintainer acknowledges the private report within a reasonable window.
2. Maintainer triages, reproduces, and fixes (with a regression test).
3. Maintainer releases the fix and credits the reporter (unless anonymity is
   requested).
4. Public disclosure happens **after** the fix is available, so users can
   upgrade before details are public.
