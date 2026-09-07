# APIP Releases, Version Truth, and Implementation Status

This file is the single authority for APIP's versioning model, the offline
truth of the reference scaffold, and what is actually implemented versus
specified. If a version number or an implementation claim appears elsewhere in
the repo and disagrees with this file, **this file is correct** — update the
other location to agree here.

Last verified for the state committed against this document.

---

## 1. Version truth — four distinct concepts, documented once

APIP ships several things that have historically been conflated under loose
"v2.x" labels. They are deliberately distinct and version independently:

| Concept                                 | Meaning                                                          | Current value      |
| --------------------------------------- | ---------------------------------------------------------------- | ------------------ |
| **APIP specification revision**         | The product/system design documents (`FULL_SPEC.md`, `docs/*`).  | `v2.3`             |
| **PRODUCT version (beta)**              | The operator control plane in `src/apip` (`pyproject.toml`).     | `0.1.0b1`          |
| **Reference implementation version**    | The deterministic Python scaffold in `reference/` (`pyproject`). | `0.1.0`            |
| **Policy schema version**               | The policy format `examples/policy.toml` and `schemas/policy.schema.json`. | `2026-09-01.2` |
| **Beta API version**                    | The control-plane contract the product ACTUALLY SERVES, generated from the FastAPI app into `api/openapi.beta.json` (regenerate via `scripts/generate_openapi.py`). | see that file's `info.version` |
| **Future API version**                  | The forward design artifact `api/openapi.future.yaml` — NOT implemented by any server here. | `0.1.0-draft` |

These are **not** interchangeable. "v2.3" in `BUILD_VERIFICATION.txt` refers to
the spec revision in force; the product and the reference scaffold carry
independent `0.x` versions; the policy file carries a dated policy-schema
revision; and the future API is marked draft because it is a forward design
artifact, not a running service — the contract the running service answers on
is `api/openapi.beta.json`.

---

## 2. Offline / socket truth

The reference scaffold is **offline and dry-run for evaluation and enforcement
compilation**. It makes **no outbound network connections** and performs **no
actuator mutations** (no firewall/DNS/router changes, no BGP, no scanning, no
third-party modification).

The one deliberate exception is the attribution lab's **loopback-only HTTP
observation socket**: `apip.cli capture serve` and `lab/` open a
`127.0.0.1`/`::1`-bound challenge origin (`ChallengeOrigin`, bind enforced) to
harvest behavioral fingerprints from **local synthetic HTTP**. That is an
**inbound test channel** — not outbound network and not an actuator. Attribution
harvest otherwise reads an already-captured JSONL of transaction logs.

> If a README or doc says the scaffold "opens no socket," treat it as an
> (already-corrected) over-statement. The accurate claim is the one above.

---

## 3. Implementation-status matrix

Every advertised component in the spec is listed with its real maturity. This
prevents confusing a schema/API declaration with working software.

| Feature                  | Spec | Reference impl. | Lab | Production |
| ------------------------ | ---- | --------------- | --- | ---------- |
| Deterministic scoring (M/S) | yes | yes             | yes | no         |
| Evidence-source authority boundary | yes | yes      | yes | no         |
| BD-1 (beacon detection)  | yes  | yes             | yes | no         |
| TTL jitter (seeded, replayed) | yes | yes          | yes | no         |
| Rate-ceiling draw (seeded) | yes | yes            | yes | no         |
| Output escaping (RPZ/Suricata) | yes | yes        | yes | no         |
| Selector-faithful exporters + artifact-derived receipts | yes | yes | yes | no |
| Requester attribution (loopback lab) | yes | yes    | yes | no         |
| DGA detector (BD-2)      | yes  | no              | no  | no         |
| DNS tunneling / fast-flux / other BD families | yes | no  | no  | no         |
| Behavioral **correlation lattice as authority** | yes | partial | partial | no |
| Allow-first segments (deny-by-default) | yes | no  | no  | no         |
| Virtual patching (VP-1..4) | yes | no             | no  | no         |
| Adaptive-attacker simulation gate | yes | no       | no  | no         |
| Real enforcement adapters (prepare/apply/verify/revoke) | yes | no | no | no |
| PostgreSQL ledger / STIX ingest / durable replay | yes | no | no | no      |
| Multi-edge signed bundles | yes | no             | no  | no         |

**Key**: "Spec" = the design is documented; "Reference impl." = the deterministic
Python scaffold actually does it; "Lab" = `lab/` demonstrates it; "Production" =
it is a runnable, operationally-deployable system. Only the first four columns
are claims about this repository; the Production column is intentionally empty
— this repo is a reference scaffold, not a deployment.

---

## 4. Known stateless-reference limitations

The L1 "hourly" client-impact budget, the blast-radius batch budget, and the
`--transactions-per-hour` denominator are **per-invocation** in the reference
(the measurement source is an operator argument). They are enforced as faithful
*approximations* of the production budget model documented in `docs/04` and
`docs/25`, not as durable tenant/principal/window accounting. A live deployment
must move these denominators to trusted telemetry with an observation interval
and add durable accounting before the budget gates are construed as production
enforcement.

`BUILD_VERIFICATION.txt` records which invariant checks currently pass against
this state.

---

## 5. Release checklist (per release)

See `.github/workflows/verify.yml` for the automated gate (clean-checkout job,
no-AI + schema conformance, ResourceWarning lane, real parsers). `SECURITY.md`
lists supported versions and the reporting process. Minimum before tagging any
public release:

1. `reference/verify.sh` green from a clean checkout (`git clean -xffd`).
2. No-AI conformance, schema conformance, and the ResourceWarning lane pass.
3. Property/fuzz suite and hostile-input tests pass.
4. Update this file's version matrix + matrix status to match.
5. `CHANGELOG.md` updated; `SECURITY.md` supported-versions list updated.