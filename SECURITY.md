# Security Policy

APIP is a defensive network-control platform for infrastructure an operator
owns or is explicitly authorized to control. The `reference/` scaffold is a
**deterministic, dependency-free, offline/dry-run decision engine** — it is a
reference implementation and test oracle, **not** a production enforcement
deployment.

## Supported versions

| Version                 | Status          | Detail                                            |
| ----------------------- | --------------- | ------------------------------------------------- |
| Reference `0.1.0`       | beta (reference) | deterministic scaffold; spec revision v2.2       |
| All other versions      | unsupported     | unreleased / pre-beta, subject to change without notice |

Only the current reference version receives security fixes. Earlier `0.x`
scaffold iterations and any unpublished state are not supported.

## What this reference is, and is not, safe for

**Is:** evaluating sample indicator feeds, canonicalizing FQDN/IP/CIDR,
computing deterministic decisions, emitting **dry-run** RPZ/Suricata artifact
files, and running the loopback-only attribution lab. It makes **no outbound
network connections** and performs **no actuator mutations**.

**Is NOT:** a production firewall/DNS enforcement point, a durable policy
ledger, or a multi-edge operator. Its L1 budget / blast-radius gates are
**per-invocation approximations** — a real deployment needs durable
tenant/principal/window accounting and trusted telemetry denominators before
treating those gates as production enforcement. Do not deploy `reference/` as
an enforcement daemon.

## Reporting a vulnerability

Please do **not** open a public issue for a suspected vulnerability. Report it
privately to the maintainers:

- Placeholder contact channel for the project owners. Substitute the
  maintainers' preferred private channel (e.g. a private security mailbox or
  a Security Advisory via the repository's "Report a vulnerability" affordance)
  before public release.

Please include:

- repository version (from `reference/pyproject.toml` and the `CHANGELOG.md`);
- description of the issue and steps to reproduce;
- the impact you believe it has (and, if you have one, a suggested fix).

## Disclosure process

1. Maintainer acknowledges receipt within a reasonable window.
2. Maintainer triages, reproduces, and fixes (with a regression test).
3. Maintainer releases the fix and credits the reporter (unless anonymity is
   requested).
4. The public disclosure happens **after** the fix is available, so users can
   upgrade before details are public.

## Scope of the threat model

For the platform's own threat model and guardrails (hack-back prohibition,
shared-infrastructure safety, false-positive outage limits), see
`docs/03_THREAT_MODEL.md` and `docs/20_SAFETY_CASE_AND_FAILURE_ANALYSIS.md`.
The no-AI invariant is machine-checked by `reference/tests/test_no_ai_conformance.py`
(`docs/28`).