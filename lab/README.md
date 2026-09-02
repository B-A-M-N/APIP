# APIP Attribution Lab

> **WHAT THIS IS:** a hands-on demonstration lab for the APIP v2.1
> **requester attribution engine** (`docs/30`) and the offline decision
> pipeline that it is forbidden from influencing. Run it and you will *see*:
> rotating attacker infrastructure collapsing into one fingerprint, distinct
> toolchains staying separate, the same campaign correlating across different
> vendor log formats — and proof that none of it can change a single
> enforcement decision.
>
> **WHAT THIS IS NOT:** no enforcement happens here. No traffic leaves your
> machine — the lab server binds **loopback (127.x) only and refuses any
> other bind**. The "attackers" are a few sockets from your own kernel. Every
> artifact lands in `lab/output/` for inspection.

## Run it

```bash
cd lab
./run.sh                 # runs all scenarios, artifacts in lab/output/
```

Then open **`output/attribution_report.html`** — the analyst correlation
view built from the traffic the lab just generated.

Individual scenarios (see `run_lab.py --list`):

```bash
python3 run_lab.py rotation        # 1: one toolchain, four "IPs" -> ONE group
python3 run_lab.py campaigns      # 2: three toolchains -> THREE separate groups
python3 run_lab.py formats        # 3: same campaign in envoy+nginx logs -> linked
python3 run_lab.py churn          # 4: attacker rotates BEHAVIOR too — honest limits
python3 run_lab.py live           # 5: real HTTP through the loopback origin
python3 run_lab.py boundary       # 6: decisions byte-identical with/without attribution
python3 run_lab.py degradation    # 7: bounded store degrades; authority unaffected
python3 run_lab.py all            # everything (what run.sh does)
```

## The scenarios and what each proves

| # | scenario | spec claim it demonstrates |
|---|----------|-----------------------------|
| 1 | `rotation` | Per-victim/per-IP infrastructure rotation does **not** defeat attribution: one toolchain behind 4 rotating source IPs produces **one** fingerprint group (`docs/30` "Rotation resistance") |
| 2 | `campaigns` | Attribution **separates** campaigns: three different toolchains produce three distinct groups, and the dissimilar client links to nothing |
| 3 | `formats` | The same behavior observed through **different terminators** (Envoy vs NGINX logs) correlates — value-matched containment linking (`docs/30` collection channel) |
| 4 | `churn` | **The honest limit:** an attacker who rotates *behavior* as well as IPs. FULL behavioral rotation is **untraceable** — the engine claims nothing rather than pretending to track. PARTIAL churn (an operator keeps the HTTP library because changing it once broke the implant) leaves value-matched containment **links**. Correlation is best-effort display, never enforcement |
| 5 | `live` | The loopback challenge origin captures **observable behaviors** (P1 header order, P4 cache correctness, P5 challenge key order) from real HTTP — not self-declared answers |
| 6 | `boundary` | **The hard boundary:** decisions are **byte-identical** with and without attribution records; attribution cannot alter M, S, corroboration, rung, or action (`docs/30` hard boundary; regression-tested) |
| 7 | `degradation` | Resource envelopes degrade **deterministically** (stop-and-mark), and degradation can only reduce attribution coverage — it touches no enforcement authority (`docs/23` discipline applied to `docs/30`) |

## How the rotation simulation works

Linux treats the entire `127.0.0.0/8` as local. The lab's simulated attacker
binds each connection's **source address** to `127.0.0.10`, `127.0.0.11`, …
so the challenge origin genuinely observes four different source IPs — real
rotation through the real capture path — while all traffic stays on your
machine.

## Fidelity limits of the simulation (stated, not hidden)

- **TLS is Python's `ssl`, not an implant's.** The `tls_ja4` values in
  scenarios are contract-valid records fed to the store directly; the live
  scenario's loopback HTTP exercises P1/P4/P5 but not a real TLS client
  fingerprint. Production JA4 capture belongs at a real TLS terminator.
- **HTTP/1.1 over loopback.** Header-order features of HTTP/2
  (pseudo-headers, HPACK) are represented through the adapter contract,
  not re-derived. `P1:header_order` order-sensitivity across reordering
  hops is a documented, pinned limitation.
- **The churn adversary is scripted, not adaptive.** It demonstrates the
  linkage properties; it does not hunt for a detection-evasion strategy
  against them.

## Safety statements (enforced, not promised)

- the lab server refuses non-loopback binds by construction (`ChallengeOrigin.serve`);
- the live package contains no enforcement vocabulary — a CI test fails the
  build if `deny`/`block`/`rpz`/`rate_limit` logic ever appears in it;
- attribution records carry source class `attribution`, which the evidence
  weight table has **no entries for** and can never gain; scenario 5
  re-proves the byte-identity invariant every run;
- artifacts are files: `transactions.jsonl`, `attribution_report.json`,
  `attribution_report.html`. Nothing is executed from them, nothing phones
  home.

## Layout

```
lab/
  README.md      <- you are here
  run.sh         <- one-command entry point
  run_lab.py     <- scenario driver (stdlib-only, imports the reference package)
  output/        <- artifacts (gitignored) — inspect, then delete freely
```
