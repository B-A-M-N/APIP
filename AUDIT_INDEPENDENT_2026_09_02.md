# Independent Audit — 2026-09-02

Scope: full reference scaffold, live capture package, exporters, schemas, lab,
and every claim in `AUDIT_ADVERSARIAL_2026_09_01.md`, `BUILD_VERIFICATION.txt`,
and `MANIFEST.json`. Method: read the whole implementation (~5,100 LOC), then
attack it with working proofs-of-concept (15+ probes) rather than reasoning
from the docs. Every HIGH/CRITICAL finding below was demonstrated against the
running code. All 143 shipped tests pass; the findings are in the spaces
between the tests.

## Verdict in one line

The v2.1.1 self-audit is honest about what it fixed, and everything it claims
to fix is genuinely fixed — but the release framing ("close all adversarial-audit
residuals", "verified state") overstates coverage: this audit found one new
injection path, one design-level scoring flaw, two broken safety promises, and
three shipped artifacts that contradict their own verification claims.

## Findings — demonstrated

| # | finding | severity | proof |
|---|---------|----------|-------|
| 1 | **Suricata rule injection via indicator `id`** (`apip_client` metadata). The CLI derives the demo client as `f"host-{i.id.split('--')[-1]}"` (`cli.py:54`) with no charset restriction, and `exporters/suricata.py` interpolates `dec.selector.client` unescaped into rule metadata. A crafted `id` terminates the rule and appends an attacker-chosen rule. Same class as audit finding #1 (RPZ), missed because the fix covered only `value` canonicalization. | **high** | end-to-end: crafted id → `suricata.rules` contains a second injected `alert ... sid:4242` rule (see `PoC` below) |
| 2 | **Single feed self-asserts corroboration → L5 AUTO_ENFORCE.** `two_curated_sources` / `single_curated_source` are *claims about other feeds*, but any registered source can assert them about itself; weight table grants +45 M each. One feed, one batch: 2×`two_curated_sources` + `dedicated_use` + structural kinds = M=100, S_ip=100 → `L5 firewall_deny AUTO_ENFORCE`. The upstream-provenance fix (audit residual 6) gates *behavioral deny* corroboration, but curated M-inflation kinds are unverified. | **high** | probe: single feed (`curated-a`) → L5 deny, AUTO_ENFORCE, no reason code flags self-assertion |
| 3 | **Duplicate records inflate M without dedup.** N copies of one kind from one source score N times (4×`curated_source` → M=100). Corroboration arithmetic dedups by *upstream identity* for the deny gate, but the weight table itself has no per-(source,kind) dedup or diminishing-returns rule. docs/04's "Repeated recent sightings +10" implies sighting-level, not record-level, scoring. | **high** | probe: 1→4 copies of one record: M 25→100 |
| 4 | **`decision.schema.json` rejects every shipped decision.** `randomization` is `object|null` in the schema but a *list* in code when ≥2 mechanisms draw (v2.1.1 change), and `attribution_refs` is emitted by `to_dict()` but absent from the schema. `jsonschema` validation: **6/6 INVALID**. `BUILD_VERIFICATION.txt` claims "PASS (6/6)". The verification text is stale against the code it ships with. | **medium** | `jsonschema Draft202012Validator` on `examples/generated/decisions.json` |
| 5 | **Allowlist match is verbatim-string, not canonical.** Entries like `bank-partner.example.` (trailing dot), `BANK-PARTNER.Example`, `/32` forms, or extra whitespace silently fail to suppress — the indicator value is canonicalized (`io._canonicalize`) but the allowlist entry is not. The operator believes an asset is protected; it is not. | **medium** | probe: canonical entry suppresses; trailing-dot/case variants do not |
| 6 | **Allowlist `expires_at` parsed, never checked.** `config.py` loads it, `AllowlistEntry` carries it, nothing compares against any clock. An entry expired in 2020 still suppresses enforcement today. docs/26 calls stale entries "a finding, not a feature". | **medium** | probe: `expires_at="2020-01-01T00:00:00Z"` → still allowlisted |
| 7 | **Live capture writer races under its own server model.** `_TxWriter` has no lock; `ThreadingHTTPServer` runs a handler thread per request. Demonstrated: cap overshoot (500→504) and `ValueError: write to closed file` exceptions in threads when one thread hits the cap and closes `_fh` while others are mid-write. | **medium** | 6-thread probe ×3 trials |
| 8 | **`do_POST` crashes on non-numeric `Content-Length`, blocks forever on negative.** `int(self.headers.get("Content-Length") or 0)` raises `ValueError` → handler dies mid-request; negative value → `min(-5, 65536) = -5` → `rfile.read(-5)` = read-until-EOF, pinning a thread per connection with no socket timeout (slow-loris-style thread exhaustion, loopback-scope only). | **low** | offline semantics check + hung probe (killed) |
| 9 | **IPv6:port form rejected by `_safe_client`.** `ref.count(":") == 1` heuristic only strips v4 `ip:port`; `[2001:db8::1]:443` → rejected, fragmenting cross-format correlation for IPv6 (the exact defect audit finding #3 fixed for IPv4). Also: `handle_for()` is HMAC over the address, so the *same* IPv6 client in different notations (`2001:db8::1` vs `2001:db8:0:0::1`) derives different handles. | **low** | probe table |
| 10 | **README quick-start fails as written.** `python -m unittest discover -s tests` errors (9 module errors) without `PYTHONPATH=src`; only `verify.sh` works. | **low** | run |

## Probes that did NOT break anything

- **Scope gate**: out-of-scope targets (incl. v4-mapped IPv6 vs v4-only
  prefixes) are hard-rejected with `out_of_authorized_scope`. Correct.
- **Manifest integrity**: all 82 hashes in `MANIFEST.json` match disk; no
  missing, no extra tracked-file drift. Clean.
- **Decision byte-replay**: two full CLI runs → `decisions.json` byte-identical.
  (`receipts.json` differs by wall-clock `created_at` — expected, and not
  claimed otherwise.)
- **Evidence payload smuggling**: still inert end-to-end.
- **Attribution isolation**: lab 7/7 pass; decisions invariant with
  attribution/annotation attached; UNKEYED HANDLES banner fires correctly on
  the dev fallback.
- **Receipt forging**: receipts embed only sha256 of artifacts + hash-derived
  ids; raw indicator ids never reach receipt fields unhashed.
- **Exporter scope**: exporters take pre-decided pairs and do not widen rungs;
  the ceilingless-rate_limit refusal works.
- **Wildcard L4 branch is dead code in file-load mode** (not a vuln — but
  note: `*.x` is rejected by `_canonicalize`, so the wildcard approval branch
  in `evaluate()` is unreachable via `load_indicators`).

## Gap audit: specified vs enforced (this round)

Beyond the self-audit's own list, these spec controls have **no code**:

1. **Blast-radius budgets** — `max_new_auto_actions_per_batch`,
   `max_challenged_transaction_fraction_per_hour` exist in
   `examples/policy.toml` and FULL_SPEC §8, but `config.py` never reads them
   and nothing enforces them. The policy file *advertises* controls the engine
   does not have.
2. **`authorized_prefixes` cannot be loaded from policy** — the scope gate
   works when set programmatically, but `config.load_policy` never reads an
   authorization section, so the packaged CLI always runs with the empty
   (unrestricted) boundary. docs/04:152 makes authorization mandatory for
   production; the reference CLI cannot express it.
3. **Scalar thresholds are dead** — `fqdn_auto_m/s`, `ip_rate_m/s`,
   `ip_deny_m/s` are loaded, stored, never consulted (rung floors superseded
   them; the fields are vestigial).
4. **`BeaconDetector` (the flagship v2.1.1 deliverable) is not wired into the
   pipeline** — instantiated only by tests. Same for
   `registry.independent_sources()` (the docs-cited corroboration primitive —
   `policy.py` reimplements it locally in `_external_corroboration`) and
   `CorrelationStore.attribution_refs_for()` / `Decision.attribution_refs`
   (never populated by any code path; always `()` — while breaking schema
   validation, finding #4).
5. **docs/25 L1 client-impact budget** ("exceeding it alarms and auto-reverts
   to L0") — no implementation, not even a knob in `config.py`.
6. **No LICENSE** — package is public on GitHub with no license file.
7. **No CI** — `.github/` absent; `verify.sh` exists but nothing runs it.

## Production readiness

This is an honest, well-built **specification + dry-run scaffold**, not a
deployable product — which the docs say plainly ("deliberately offline and
dry-run only"). Readiness notes for whoever builds on it:

- Blocking for any real use: findings 1–3 (input integrity), 4 (schema
  drift — indicates no schema validation in CI), 6 (allowlist expiry), and
  gap 2 (no way to configure authorization).
- The `live/` package's loopback default and bind refusal are genuinely
  enforced (CLI + server double-check); the server is still not production
  surface (findings 7–8) and is correctly documented as demo-grade.
- Determinism engineering (pinned clocks, integer DRBG, recorded draws) is
  real and replayable — the strongest part of the codebase.
- `examples/generated/` and `lab/output/` are correctly gitignored but ship
  in the package tree; `MANIFEST.json` covers only source files (verified
  accurate), and `BUILD_VERIFICATION.txt` needs regeneration (finding 4).

## What was actually verified clean

- All 143 tests pass under `verify.sh` (and `PYTHONPATH=src`).
- MANIFEST hashes: 82/82 match.
- The three headline v2.1.1 residual closures (rate ceiling, keyed handles,
  replay pinning) hold under attack: ceiling refusal works, keyed-handle
  divergence across deployment keys works, pinned replay is byte-exact.
- No-AI conformance tests are real (import scan, call-shape scan, offline
  socket-blocked execution) and pass.

## Recommended fix order

1. (HIGH) Charset-validate indicator `id` at load (`^[A-Za-z0-9_.\-]{1,128}$`)
   **and** escape/validate `selector.client` in `suricata.py` — defense in
   depth, same as the RPZ fix.
2. (HIGH) Per-(source_id, kind) dedup or diminishing-returns scoring; reject
   self-asserted corroboration kinds (`single_curated_source`,
   `two_curated_sources`) unless ≥2 distinct upstream identities appear in
   the indicator's `sources`.
3. (MED) Canonicalize allowlist entries at load; enforce `expires_at`
   against `reference_now` with a reason code on suppression-by-expired.
4. (MED) Add `attribution_refs` + list-form `randomization` to
   `decision.schema.json`; add a jsonschema validation step to `verify.sh`
   so the schema and the code cannot drift silently again.
5. (MED) Lock in `_TxWriter` with a `threading.Lock`.
6. (LOW) `_safe_client`: handle bracketed IPv6; clamp `Content-Length`
   parse (`int()` in try/except, `max(0, n)`), set a handler timeout.
7. (LOW) Fix README quick-start; delete the dead scalar threshold fields or
   wire them; decide fate of unwired knobs (`max_new_auto_actions_per_batch`
   etc.) — implement or remove from the example policy.

---

## Resolution (v2.2) — all findings fixed, re-attacked, and pinned

Every finding above was fixed the same day, then the fixes were themselves
attacked with a second battery of proofs-of-concept (sibling-reseller
corroboration forgery, dedup evasion via timestamp jitter, expiry-boundary
probing, unicode/invisible-character id injection, scope-escape entries,
/32-vs-host allowlist mismatch, P5 bypass attempts). All 179 tests pass
(v2.2 follow-up: 187 with the docs/25 client-impact budget closures),
including 40+ new regression tests pinning every fix
(`reference/tests/test_independent_audit.py`,
`reference/tests/test_schema_conformance.py`).

| # | finding | resolution | pinned by |
|---|---------|-----------|-----------|
| 1 | Suricata injection via indicator id | `apip/sanitize.py`: closed-charset ingest boundary (`validate_id`/`validate_label`/`validate_client`) enforced in `io.load_indicators`, at selector construction (`policy.select_rung` refuses artifact-unsafe clients with a reason), and again at every exporter interpolation (`suricata_safe`, `validate_fqdn`, `validate_ip_literal`). The CLI no longer derives client selectors from indicator ids at all. **Load → selector → compile: three independent refusal points.** | `Finding1SuricataInjectionTests` |
| 2 | self-asserted corroboration → L5 | corroboration kinds are now *claims, verified server-side*: `scoring.corroboration_tier` derives distinct upstream identities from provenance; `two_curated_sources` pays corroboration weight only when ≥2 identities actually reported. Unsupported claims degrade to plain weight + `corroboration_claim_unverified` reason. Reseller chains count once. | `Finding2SelfAssertedCorroborationTests` |
| 3 | duplicate-record M inflation | `(provenance-identity, kind, observed_at)` dedup in `scoring._dedup_evidence`, applied **before** the evidence envelope in `policy.evaluate` — ordering matters: a duplicate flood can no longer crowd out exculpatory evidence (e.g. `prior_false_positive`) within the envelope. Distinct-time sightings still count (docs/04). | `Finding3DuplicateInflationTests` |
| 4 | decisions failed own schema | schema updated for list-form randomization + `attribution_refs` (+ `epoch` draw field); new dependency-free `tests/test_schema_conformance.py` validates every emitted artifact against every shipped schema and FAILS LOUDLY on any schema keyword it does not implement; `verify.sh` cross-checks with the real `jsonschema` package when present; CI (`.github/workflows/verify.yml`) runs it on push across 3.11/3.12/3.13. | `Finding4SchemaConformanceTests` |
| 5 | verbatim allowlist matching | entries canonicalize at construction (`AllowlistEntry.__post_init__` — every construction path), matched against canonicalized indicator values: case, trailing dot, whitespace, and /32-vs-host spellings all collapse to one key. Wider prefixes deliberately do NOT match a host (fail closed). | `Finding5AllowlistCanonicalizationTests` |
| 6 | `expires_at` never enforced | enforced against the replay clock (`reference_now` when pinned, wall clock otherwise); an expired entry no longer suppresses; load-time validation requires owner+ticket (docs/26 governance) and an ISO-8601 expiry. | `Finding6AllowlistExpiryTests` |
| 7 | writer race | `_TxWriter` fully lock-protected (cap now exact, no closed-file flushes); session counters and `CorrelationStore` state likewise; lock-starvation degrades stop-and-mark rather than blocking. | `Finding7WriterRaceTests` (6 threads × cap 500: exact) |
| 8 | Content-Length crash/hang | `_safe_content_length`: digits-only parse → 400 on garbage, hard cap on all reads, 30s handler socket timeout (slow-loris pins a thread for seconds, not forever). | `Finding8ContentLengthTests` |
| 9 | IPv6 handle fragmentation | `_safe_client` handles `[v6]:port`, canonicalizes all spellings via `ipaddress` (RFC 5952), rejects zone ids; cross-format IPv6 correlation now exact. | `Finding9ClientNormalizationTests` |
| 10 | README quick-start broken | fixed (documented `PYTHONPATH=src` requirement); `./verify.sh` is the one-command entry. | docs |
| gaps | budgets/authorization/detector unwired | `max_new_auto_actions_per_batch` loaded and enforced (overflow demotes with `blast_radius_budget_exceeded`); `[authorization].authorized_prefixes` loadable; BD-1 detector wired via `--events` (detections fold into indicators through the same caps/lattice); budget + authorization knobs added to `policy.schema.json`; LICENSE added (Apache-2.0). | `BlastRadiusBudgetTests`, `LoaderBoundaryTests` |
| docs/25 L1 client-impact budget | **closed (v2.2, same-day follow-up)**: `max_challenged_transaction_fraction_per_hour` is now loaded, validated ((0,1]), and ENFORCED batch-wide — `policy.apply_client_impact_budget` counts every `proxy_challenge` decision against `challenge_allowance()` = floor(fraction × measured volume); the overflow ALARMS (docs/25's exact response) and AUTO-REVERTS to L0/OBSERVE with `client_impact_budget_exceeded` + `challenge_auto_reverted_to_L0`, selector dropped, TTL zeroed, id suffixed `-challenge-budget-reverted` for traceability. The fraction's denominator — the trailing-hour interactive transaction count — cannot be observed by an offline batch scaffold, so it is explicit operator input (`[measurement].interactive_transactions_per_hour` in policy, or the CLI `--transactions-per-hour` flag, which wins), and the engine FAILS CLOSED: fraction set + volume unmeasured → allowance 0 → every challenge reverts. Survivors are chosen in (policy_version, decision id) order, so replay reverts the SAME decisions; allowance arithmetic is integer fixed-point (no float drift in a decision-bearing quantity); non-challenge rungs (L4/L5/L2) are never counted or reverted; reversion is idempotent and leaves no enforcement artifact (challenges compile to no RPZ/Suricata rule; receipts match). | `ClientImpactBudgetTests` (8 tests incl. CLI end-to-end + fail-closed + determinism) |

Second-wave additions found while attacking the fixes: /32-vs-host allowlist
mismatch (fixed — single-host prefixes canonicalize to the bare address),
`threading` added to the no-AI stdlib allowlist with justification (locks
only; no timers, no entropy, determinism unaffected).

Remaining open items (stated, not hidden): production streaming/backpressure
around the CLI's batch contract; the docs/25 L1 client-impact budget is now
ENFORCED as a batch-scoped control (see the resolution table) — what remains
inherent to the offline scaffold is that the trailing-hour denominator is
operator-supplied measurement rather than live proxy telemetry, and a live
deployment would additionally track the budget across batches within the
hour; the vestigial scalar thresholds (`fqdn_auto_m` etc.) are retained for
policy compatibility but superseded by rung floors.
