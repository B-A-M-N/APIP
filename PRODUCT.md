# APIP 0.1.0 Public Beta

*Maintained for and attributed to **B-A-M-N**. Where tooling refers to the
local OS account (`bamn`), that is the Linux account the tooling runs under,
not the maintainer identity.*

**A deterministic, AI-free defensive control-plane beta** capable of ingesting
governed evidence, producing explainable *bounded* decisions, persisting them
in a durable ledger, and safely shadowing / applying / verifying / revoking
**exact-FQDN DNS RPZ** controls on DNS infrastructure an operator owns or is
explicitly authorized to operate.

The repository also contains the broader APIP **specification** (`docs/`,
`FULL_SPEC.md`) and an independent **deterministic reference oracle**
(`reference/`). Features described in the specification are **not necessarily
implemented in the beta** — see `IMPLEMENTATION_STATUS.md` for the precise
split between `SPECIFIED`, `REFERENCE IMPLEMENTED`, `PRODUCT IMPLEMENTED`,
`BETA SUPPORTED`, and `FUTURE`.

> **AI-free, deterministic-by-construction.** No LLM, ML model, external
> inference API, AI SDK, classifier, or agent participates anywhere in the
> security decision path — ingestion authority, evidence scoring, policy
> decisions, behavioral detection, action selection, approval, enforcement,
> rollback, health, or safety controls. The decision path (evidence →
> scoring → policy → decision) imports only the Python standard library. AI
> is deliberately out of scope for the beta and may only ever appear (later)
> as an analyst-facing, zero-authority explanation surface.

---

## What this beta actually does

The fundamental APIP loop, end to end:

```
telemetry / intelligence
        ↓
authenticated ingestion (channel-bound source identity)
        ↓
canonical evidence (closed charsets, strippped of score claims)
        ↓
deterministic scoring + versioned policy
        ↓
explainable decision ledger (append-only, auditable)
        ↓
compiled action -> adapter (exact FQDN only)
        ↓
operator-authorized DNS infrastructure (RPZ)
        ↓
independent verification (no fabricated success receipts)
        ↓
expiry / revoke through the SAME controlled path
        ↓
outcome recorded in the ledger
```

Supported out of the box:

- **Controller service** (`apip serve`) with an explicit lifecycle and
  restart-safe worker loops (dispatch, reconcile, expiry, verify).
- **Durable PostgreSQL ledger** — sources, ingest hashes, indicators,
  evidence, policy versions, decisions, actions, adapter attempts/receipts,
  verification state, expirations, revocations, failures, approvals, audit
  events. Historical decisions are never overwritten; every mutation has an
  auditable actor identity.
- **Authenticated ingest boundary** — source identity is DERIVED from the
  authenticated channel (a source key), never from a payload-declared
  `source_id`. A request body can never promote itself to another trusted
  source (the reference audit P0-2 lesson, carried into production).
- **Operator CLI** (`apip status / source / ingest / indicator / decision /
  action / policy / adapter / audit / migrate / serve`) — you can answer:
  *what does APIP believe? why? what would it do? what has it done? where?
  for how long? which evidence? which policy? did the infrastructure accept
  it? is it still active? how do I revoke it?*
- **One real RPZ adapter** (exact FQDN only; no wildcards, no prefix deny,
  no IP rules) with the postures `OFF / OBSERVE / SHADOW / ENFORCE`.
  **SHADOW is the default** and is genuinely useful: it publishes a
  monitor-only zone file that APIP independently verifies, with **no** live
  resolver behavior change.
- **Triple authorization-boundary scope check** — decision engine + controller
  dispatch + adapter each re-check that a target falls inside the
  operator-authorized domain scope. An out-of-scope target is refused even if
  every score says ENFORCE.
- **No fabricated success** — adapter receipts carry *observed* state (file
  hash / DNS answer), never a repetition of intent. If a rule cannot be
  verified, APIP surfaces a failure or marks the action drifted.
- **Component-level health** — never a single generic `healthy=true` while a
  subsystem is failing.

## What this beta deliberately does NOT do

- No BGP, firewall/IPS, proxy/WAF, routing, or arbitrary-IP blocking.
- No wildcard or prefix/domain-wide automatic enforcement.
- No behavioral detection in the live enforcement path beyond the
  deterministic beacon/novelty evidence families (see status doc).
- No requester "attribution" of any enforcement authority (display only).
- No TAXII, no Kubernetes requirement, no multi-adapter matrix.
- **No AI of any kind** in the decision path (see above).

## Quick start

Prerequisites: Python 3.11+, PostgreSQL 14+ (or Docker).

```bash
# install
python3 -m venv .venv-apip
.venv-apip/bin/pip install -e '.[dev]'

# secrets (never commit these)
export APIP_OPERATOR_TOKEN="$(openssl rand -hex 32)"
export APIP_DB_PASSWORD="your-db-password"
export APIP_SECRET_KEY="$(openssl rand -hex 32)"

# migrate + run the controller
.venv-apip/bin/apip migrate
.venv-apip/bin/apip serve

# in another shell: the CLI
.venv-apip/bin/apip status
```

A full walkthrough from source registration through a SHADOW run, an ENFORCE
promotion, verification, and revoke is in `IMPLEMENTATION_STATUS.md`.

## Deployment

`deploy/` provides **Docker Compose** (controller + PostgreSQL) as the
canonical deployment, plus a local-development path. The DNS resolver to which
RPZ is applied is **operator-managed** and separate from this compose — APIP
does not, and can not, touch a resolver it isn't explicitly pointed at and
authorized for.

See `deploy/docker-compose.yml`, `deploy/.env.example`, and
`deploy/config/apip.toml.example`.

## Security posture

- Secrets live only in the environment or `*_FILE` mounts — never in policy
  files and never as shipped defaults.
- Fail-closed semantics: on database/adapter/resolver/policy failure, APIP
  makes **no new enforcement**, preserves known-safe existing state, surfaces
  degraded status, and retains enough state to reconcile later. It never
  silently broadens or fabricates successful enforcement.
- Scope is enforced at three independent layers.
- Every state-changing operation is audited with an actor identity.

## License

Apache-2.0.