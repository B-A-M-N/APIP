# 30 — Requester Attribution and Fingerprinting Engine

## Purpose

When an attacker's infrastructure rotates (per-victim C2 domains, fresh proxies, AI-generated hosts at machine speed), per-indicator blocking chases instances while the *operator* chases answers to a different question: **who, or what, is on the other end?** Attribution evidence — that the same requester, the same toolchain, the same campaign harness is present behind many rotating identifiers — feeds campaign correlation, scope-of-compromise estimation, feed-package authoring, takedown/abuse packages, and post-incident reporting.

This document specifies a deterministic request-attribution engine for APIP. Its defining constraint, stated first:

> **Hard boundary: attribution output is never an enforcement input.** Fingerprint matches contribute exactly zero to M, zero to S, zero to corroboration counts, and zero to rung eligibility. They cannot select, alter, suppress, or extend any action, and they cannot enter the allowlist or the evidence weight table. Attribution answers "who is this," never "block this." The authorization path of `docs/04`/`docs/25` is unchanged by this document.

## Relationship to L1 (challenge)

The L1 rung (`docs/25`) issues a bounded interactive challenge as a *friction* control: its purpose is to cost automated clients transactionally, it is budget-capped, and its outcome affects only that session. The attribution engine **reuses the challenge channel** as a *sensor*:

- the same HTTP interaction that applies friction also requests specific, deterministic, versioned probe material;
- challenge *pass/fail* remains a session-scoped friction result (as in `docs/25`), never a reputation score;
- the *responses* to probe material — if present, well-formed, and consistent — become **attribution features**, stored under the annotation-adjacent attribution class described below.

An operator that disables L1 for a segment disables the collection channel too; attribution is a consumer of friction already being applied, not a reason to apply more of it.

## Probe set (deterministic, versioned, randomized-in-order)

Probes are fixed material chosen by policy version — no generated content, no model involvement, no adaptive selection. Each probe has an ID, and the *order and subset* presented is drawn by the recorded ApipRng (`docs/29`), seeded per (session, epoch), so the same client sees a varying order across epochs (resisting fingerprint-freezing caches) while every draw remains replayable.

| ID | probe | feature harvested |
|---|---|---|
| P1 | HTTP header ordering/presence surface on a synthetic 404 | header-order vector, header-set hash |
| P2 | `Accept-Language`/`Accept-Encoding` consistency echo | locale/encoding coherence vector |
| P3 | TLS client-hello capture at the proxy (passive, no script) | JA3/JA4-family digest |
| P4 | cache-behavior check on a versioned-URL asset with known validators | conditional-request correctness vector |
| P5 | well-formed challenge object requiring canonical JSON serialization | serialization-order signature |
| P6 | range/encoding edge request with deterministic expected fallback | client-library behavior class |

No probe executes attacker-controlled code, references third-party origins, or exfiltrates data: every probe is served from the operator's own challenge origin. P3 is passive telemetry at the TLS terminator the operator already runs.

A critical framing: the engine harvests **observable behaviors**, not self-declared answers. Nothing a requester *says about itself* is trusted — `User-Agent` text, claimed locales, declared capabilities are all trivially spoofable and are treated as raw material only insofar as *how* they are used (ordering, consistency, structure, timing) is hard to fake coherently. A probe's value is the behavioral signature of constructing a response, not the response's content: the order in which headers are emitted, whether conditional-request semantics are honored correctly, how a serializer orders keys, which TLS extensions a client library offers and in what order. Most of the harvest is also **passive-first**: P1/P2/P3 features are observable from traffic the operator already terminates (and are collected whenever a session transits the challenge origin), with active challenge material (P4/P5/P6) reserved for sessions already receiving L1 friction — so the engine adds zero new interactions of its own.

## Feature extraction and collection channel

Each probe maps to a deterministic feature extractor over an **observed transaction record** — the metadata a proxy/TLS terminator logs anyway, in a schema the operator already emits:

| probe | extractor input (from the transaction log) | behavioral feature |
|---|---|---|
| P1 | ordered header-name list of a request | header-order vector + set hash |
| P2 | header value-pairs (Accept-Language, Accept-Encoding) | coherence vector (declared vs. structurally consistent) |
| P3 | TLS handshake metadata at the terminator | JA3/JA4-family digest (passive) |
| P4 | request/conditional-header/response-code sequence on a versioned asset | conditional-request correctness vector |
| P5 | body bytes of the response to the canonical-JSON challenge object | serialization-order signature (key order, formatting choices) |
| P6 | Range/Accept-Encoding request structure and fallback behavior | client-library behavior class |

The **collection channel** (v2.1: specified and implemented in reference form) is the pipeline from transaction logs to fingerprints:

1. **Ingest** observed transaction records from the challenge origin / TLS terminator log stream (in the reference scaffold: a JSONL file of already-captured observations — the scaffold remains offline and never terminates traffic itself; the reference's optional loopback-only challenge origin harvests local synthetic HTTP and is NOT a production TLS terminator).
2. **Extract** per-probe features with the fixed versioned extractors; a transaction missing the material for a probe contributes nothing for that probe (absence is recorded, never guessed).
3. **Reduce** per requester handle (pseudonymous, keyed) into a feature vector under a bounded-state policy: max tracked requesters, TTL eviction, oldest-first — the same resource-envelope discipline as `docs/23`; overflow stops feature reduction for new handles (degradation never increases authority, and attribution has none to begin with).
4. **Derive** the fingerprint; **emit** an attribution record (source class `attribution`) and update the correlation store.

## Fingerprint construction and matching

A **requester fingerprint** is the fixed, versioned derivation (hash) of the harvested feature vector — computed by explicit arithmetic, reproducible from the stored features, never inferred. Matching is exact-or-bucketed equality over a *versioned fingerprint schema*:

- `fp--<schema-version>--<sha256[:16] of canonical feature serialization>`;
- schema versions are additive and versioned like every other policy input; a schema bump re-baselines all stored fingerprints (no silent cross-version comparison);
- similarity is a deterministic function (e.g., shared-probe subset count), thresholded by policy for *correlation display*, never used as a score.

## Storage, correlation, and lifecycle

- Fingerprints are stored keyed by pseudonymous requester handle (**keyed HMAC-SHA-256** of client identity at the chokepoint under a per-deployment key, v2.1.1 — not raw subscriber identity, and not an unkeyed hash, which a stolen report + a guessed client-address space could invert); retention follows `docs/09` data-class windows for observational metadata. Keys come from `APIP_DEPLOYMENT_KEY` / `APIP_DEPLOYMENT_KEY_FILE`, are per-deployment (handles must never be cross-deployment joinable), and rotation re-baselines all handles by design. A deployment running without a key degrades to a marked development fallback and every report displays an UNKEYED HANDLES banner so the state cannot be mistaken for protection.
- **Campaign correlation:** indicators, decisions, and clusters (`docs/23`) carry optional `attribution_refs`; the operator UI links fingerprints to campaign objects for analysis. Correlation lists are analyst worklists — they do not propagate to scoring.
- **Cross-tenant matching is prohibited by default**; where a provider-scale deployment enables it, it is a separately governed, audited, privacy-reviewed feature with its own legal basis (`docs/09`), never an automatic join.
- **Rotation resistance, honestly bounded:** fingerprints are evadable by a sufficiently careful adversary; the design treats a *changed* fingerprint as a signal of *volatility* (itself campaign-relevant metadata), not as a bypass that breaks anything — because nothing enforcement-related ever depended on the fingerprint.

## Privacy and abuse constraints

- No persistent browser-state tracking: no cookies, no supercookies, no canvas/WebGL/JS-fingerprinting of end-user browsers; probes are server-side and transport/session-scoped. (The platform is a network chokepoint, not a browser; the design keeps it that way.)
- The engine must not increase challenge volume: budget and sampling of L1 remain exactly those of `docs/25` (including the randomized challenge sampling mechanism of `docs/29`). Attribution piggybacks; it never multiplies.
- Probe responses from *internal* hosts (scanned or exploited clients) are subject to the same retention minimization; internal-host fingerprints support containment analysis (`docs/25` host scoping) under the same no-enforcement-input boundary.
- Explicit legal/privacy review is a release gate for the feature in any deployment (mirrors `docs/23` release gates).

## Conformance requirements

- Attribution records carry source class `attribution`, distinct from `annotation` and from every authoritative class in `docs/04`; the weight table has no entries for it and MUST NOT gain any.
- Decisions are byte-identical with and without attribution records (same invariant as `docs/28`; enforced by regression test in `reference/tests`).
- Probe material and derivation logic are versioned, deterministic, and replayable; fingerprint computation involves no model, no learned component, and no generated logic.
- Removing the entire engine degrades nothing: friction (L1) still works, scoring still works, enforcement still works.

## Reference scaffold scope

The reference implementation (`reference/src/apip/attribution.py`, `reference/src/apip/uireport.py`) includes the deterministic derivation primitives, the **adapter contract validator** (`validate_transaction`, enforcing `schemas/observed_transaction.schema.json` — malformed records are rejected, never coerced), the feature-extraction pipeline from observed transaction records (offline, JSONL form), bounded per-requester state with deterministic eviction, the campaign correlation report, and a **deterministic read-only HTML rendering of the analyst correlation view** (fingerprint groups, shared-probe links, degraded-state banner, pseudonymous handles only). Regression tests demonstrate the byte-identity invariant, pipeline determinism, adapter rejection behavior, and render determinism. Live HTTP/TLS termination itself is a deployment concern — the scaffold never terminates production traffic and never makes an outbound connection — so the remaining production integration is the per-terminator log-shipper adapter work in WP-30 (emitting records the contract validator already accepts). The reference does provide an **optional loopback-only challenge origin** (`apip.cli capture serve` and `lab/`): an inbound `127.0.0.1`/`::1`-bound HTTP observation socket that harvests fingerprints from local synthetic HTTP (`ChallengeOrigin`, bind enforced). That is an inbound test channel, not outbound network and not an actuator.
