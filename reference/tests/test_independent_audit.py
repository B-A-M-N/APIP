"""Independent-audit regressions (2026-09-02, v2.2).

Each test pins one finding from the independent audit
(AUDIT_INDEPENDENT_2026_09_02.md). Every finding was demonstrated against
the running code with a proof-of-concept; if one of these fails, a
demonstrated attack or defect has been reintroduced.

Findings pinned here:
  1  Suricata rule injection via indicator id -> apip_client metadata
  2  single feed self-asserting corroboration reaches L5 AUTO_ENFORCE
  3  duplicate records inflate M (4 copies: M 25 -> 100)
  4  shipped decisions failed their own JSON schema
  5  allowlist matching was verbatim (spelling variants failed to protect)
  6  allowlist expires_at never enforced
  7  _TxWriter race: cap overshoot + closed-file exceptions under threads
  8  Content-Length: crash on non-numeric, read-until-EOF on negative
  9  _safe_client rejected [v6]:port; non-canonical v6 split handles
  10 README quick-start failed as written (pinned by docs consistency test)
plus the blast-radius budget and dup-before-envelope ordering guarantees.
"""
import json
import os
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from apip.models import Indicator, Evidence
from apip.policy import Policy, RungFloor, AllowlistEntry, evaluate
from apip.registry import SourceRegistry, SourceProfile
from apip.scoring import EvidenceTable, DEFAULT_WEIGHTS, score
from apip.sanitize import UnsafeIdentifier


def _pinned_classifier():
    from datetime import datetime, timedelta, timezone

    def classify(ts: str) -> str:
        if not ts:
            return "stale"
        try:
            t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return "stale"
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        now = datetime(2026, 9, 1, 20, 0, 0, tzinfo=timezone.utc)
        return "fresh" if abs(now - t) <= timedelta(hours=6) else "stale"

    return classify


REG = SourceRegistry((
    SourceProfile("curated-a", "curated", True),
    SourceProfile("curated-b", "curated", True),
    SourceProfile("local-sensor", "local", True),
    SourceProfile("local-behavioral", "local", True, True),
))

POL = Policy(
    version="v", mode="ENFORCE", scope="t",
    observe_m=40, fqdn_auto_m=95, fqdn_auto_s=90,
    ip_rate_m=90, ip_rate_s=85, ip_deny_m=98, ip_deny_s=95,
    max_auto_ttl_seconds=3600, auto_prefix_deny=False,
    auto_routing=False, auto_wildcard_domain=False,
    nominal_rate_ceiling_per_min=240,
    rung_floors={"L1": RungFloor(85, 75), "L2": RungFloor(90, 80),
                 "L4": RungFloor(95, 90), "L5": RungFloor(98, 95)},
    source_registry=REG,
    classify_recency=_pinned_classifier(),
    # audit P0-3: control-plane facts are server-certified. Fixtures here
    # carry verified_rollback on test targets declared governed infra.
    governed_dedicated_use=("198.51.100.44",),
    governed_verified_rollback=tuple(
        ["198.51.100.44"] + [f"c{k}.invalid" for k in range(8)]
    ),
)

CTX = {"client": "h1", "protocol_class": "interactive_http"}
T = "2026-09-01T19:00:00Z"


def ev(kind, source="curated-a", at=T):
    return Evidence(kind=kind, source_id=source, source_class="x",
                    observed_at=at, independent=True)


# Structural + local-detection stack used by the original PoCs (single
# source of each fact: exactly the shape finding 2 abused).
SELF_ASSERT_STACK = (
    ev("two_curated_sourceS".lower().replace("s", "s")),  # placeholder replaced below
)


def _stack(*kinds):
    return tuple(ev(k) for k in kinds)


class Finding1SuricataInjectionTests(unittest.TestCase):
    """Indicator ids ride the client selector into Suricata metadata."""

    EVIL_ID = 'x"; data;) alert ip any any -> any any (sid:4242;) #'

    def test_load_rejects_hostile_indicator_id(self):
        from apip.io import load_indicators
        with TemporaryDirectory() as td:
            p = Path(td) / "i.json"
            p.write_text(json.dumps([{
                "id": self.EVIL_ID, "type": "fqdn", "value": "c2.evil.example",
                "sources": ["curated-a"], "evidence": []}]))
            with self.assertRaises(UnsafeIdentifier):
                load_indicators(p)

    def test_selector_refuses_hostile_client_even_if_constructed(self):
        # defense in depth: even bypassing the loader, the selector gate
        # refuses an artifact-unsafe client reference
        d = evaluate(Indicator("ok", "fqdn", "c2.evil.example", (), _stack(
            "curated_source", "curated_source", "direct_local_detection",
            "exact_fqdn", "recent", "bounded_scope", "verified_rollback")),
            POL, context={"client": self.EVIL_ID,
                          "protocol_class": "interactive_http"})
        if d.selector is not None:
            self.assertNotIn(";", d.selector.client or "")
            self.assertNotIn('"', d.selector.client or "")
        # and the L2 path was demoted (client selector unusable)
        self.assertNotIn(";", d.reason_codes)
        self.assertTrue(any("client_selector_unsafe" in r for r in d.reason_codes)
                        or d.selector is None
                        or d.rung in ("L0", "L4"))

    def test_exporter_never_emits_rule_syntax_from_any_field(self):
        from apip.exporters.suricata import compile_rules
        # hostile id + hostile client at the EXPORT boundary directly
        ind = Indicator(self.EVIL_ID, "fqdn", "c2.evil.example", (), ())
        d = evaluate(ind, POL, context={"client": "safe-client",
                                        "protocol_class": "interactive_http"})
        # force a selector-bearing decision shape via a valid client
        if d.selector is None:
            d = evaluate(ind, POL, CTX)
        rules = compile_rules([(ind, d)])
        self.assertNotIn("sid:4242", rules)

    def test_clean_ids_still_load(self):
        from apip.io import load_indicators
        with TemporaryDirectory() as td:
            p = Path(td) / "i.json"
            p.write_text(json.dumps([{
                "id": "indicator--demo-domain", "type": "fqdn",
                "value": "c2-demo.invalid",
                "sources": ["curated-a", "curated-b"],
                "evidence": [{"kind": "curated_source", "source_id": "curated-a",
                              "observed_at": T}]}]))
            inds = load_indicators(p)
            self.assertEqual(inds[0].id, "indicator--demo-domain")


class Finding2SelfAssertedCorroborationTests(unittest.TestCase):
    """One feed claiming 'two_curated_sources' about itself reached L5."""

    def test_self_asserted_corroboration_gets_single_source_weight(self):
        # old behavior: 2x two_curated_sources + dedicated + structural
        # = M=100 S_ip=100 -> L5 AUTO_ENFORCE from ONE feed
        e = _stack("two_curated_sources", "two_curated_sources",
                   "dedicated_use", "exact_ip", "recent",
                   "verified_rollback", "bounded_scope")
        d = evaluate(Indicator("solo", "ipv4", "198.51.100.44", ("curated-a",), e),
                     POL, CTX)
        self.assertNotEqual(d.rung, "L5")
        self.assertTrue(any(r.startswith("corroboration_claim_unverified")
                            for r in d.reason_codes))

    def test_verified_corroboration_retains_weight(self):
        # two genuinely distinct upstreams reporting the target MALICIOUS ->
        # the two_curated_sources claim verifies (audit P1-5: corroboration
        # rests on fresh MALICIOUSNESS ASSERTIONS, not structural metadata —
        # so both upstreams must actually assert malice).
        e = (ev("two_curated_sources", "curated-a"),
             ev("curated_source", "curated-a"),
             ev("curated_source", "curated-b"),
             ev("dedicated_use", "curated-a"),
             ev("exact_ip", "curated-a"))
        d = evaluate(Indicator("duo", "ipv4", "198.51.100.44",
                               ("curated-a", "curated-b"), e), POL, CTX)
        self.assertFalse(any(r.startswith("corroboration_claim_unverified")
                             for r in d.reason_codes))

    def test_structural_metadata_does_not_corroborate(self):
        # audit P1-5: a second source that merely OBSERVES the target
        # (recent / exact_* / exactness) is NOT corroborating a maliciousness
        # claim. Only curated-a asserts malice; curated-b adds only metadata.
        e = (ev("two_curated_sources", "curated-a"),
             ev("curated_source", "curated-a"),
             ev("recent", "curated-b"),
             ev("exact_ip", "curated-b"))
        d = evaluate(Indicator("partial", "ipv4", "198.51.100.44",
                               ("curated-a", "curated-b"), e), POL, CTX)
        self.assertTrue(any(r.startswith("corroboration_claim_unverified")
                            for r in d.reason_codes))

    def test_reseller_chain_counts_once_for_claims(self):
        # three resellers of one upstream cannot jointly verify a claim
        from apip.registry import SourceRegistry, SourceProfile
        reg = SourceRegistry((
            SourceProfile("upstream-U", "curated", True),
            SourceProfile("re-1", "curated", True, upstream="upstream-U"),
            SourceProfile("re-2", "curated", True, upstream="upstream-U"),
        ))
        pol = Policy(**{**POL.__dict__, "source_registry": reg})
        e = (ev("two_curated_sources", "upstream-U"),
             ev("curated_source", "re-1"),
             ev("curated_source", "re-2"),
             ev("dedicated_use", "upstream-U"),
             ev("exact_ip", "upstream-U"),
             ev("recent", "upstream-U"),
             ev("verified_rollback", "upstream-U"),
             ev("bounded_scope", "upstream-U"))
        d = evaluate(Indicator("resellers", "ipv4", "198.51.100.44",
                               ("upstream-U",), e), pol, CTX)
        self.assertNotEqual(d.rung, "L5")


class Finding3DuplicateInflationTests(unittest.TestCase):
    """N copies of one record scored N times (M 25 -> 100)."""

    def test_duplicates_collapse_before_scoring(self):
        e = _stack("curated_source", "curated_source", "curated_source",
                   "curated_source")
        d = evaluate(Indicator("dup", "fqdn", "bad.invalid", ("curated-a",), e),
                     Policy(**{**POL.__dict__, "mode": "OBSERVE"}), CTX)
        self.assertLessEqual(d.maliciousness, 25)
        self.assertTrue(any(r.startswith("evidence_deduplicated")
                            for r in d.reason_codes))

    def test_dedup_uses_provenance_identity(self):
        # a reseller chain cannot multiply one upstream's report
        from apip.registry import SourceRegistry, SourceProfile
        reg = SourceRegistry((
            SourceProfile("upstream-U", "curated", True),
            SourceProfile("re-1", "curated", True, upstream="upstream-U"),
        ))
        e = (ev("curated_source", "upstream-U"),
             ev("curated_source", "re-1"))
        m, _, _, _, _, _ = score(
            Indicator("d", "fqdn", "bad.invalid", (), e),
            EvidenceTable(DEFAULT_WEIGHTS), _pinned_classifier(), reg)
        self.assertEqual(m, 25)   # one identity, one count

    def test_repeated_sightings_still_count(self):
        # same kind at DIFFERENT times = distinct observations (docs/04)
        e = (ev("curated_source", at="2026-09-01T19:00:00Z"),
             ev("curated_source", at="2026-09-01T18:00:00Z"))
        m, _, _, _, _, _ = score(
            Indicator("d", "fqdn", "bad.invalid", (), e),
            EvidenceTable(DEFAULT_WEIGHTS), _pinned_classifier(), REG)
        self.assertEqual(m, 50)

    def test_dup_flood_cannot_crowd_out_exculpatory_evidence(self):
        # dedup runs BEFORE the envelope cap: 100 duplicates + 1
        # prior_false_positive must not lose the dissent within the envelope
        e = list(_stack(*(["curated_source"] * 100)))
        e.append(ev("prior_false_positive"))
        d = evaluate(Indicator("flood", "fqdn", "bad.invalid", ("curated-a",), tuple(e)),
                     Policy(**{**POL.__dict__, "mode": "OBSERVE",
                               "max_evidence_per_indicator": 16}), CTX)
        self.assertIn("prior_false_positive", d.reason_codes)


class Finding4SchemaConformanceTests(unittest.TestCase):
    """Shipped decisions failed their own schema (6/6 INVALID)."""

    def test_generated_decisions_conform(self):
        # re-asserted through the dependency-free conformance validator.
        # audit P1-39: generate the fixtures ourselves (TemporaryDirectory),
        # never read the gitignored examples/generated — so a clean checkout
        # still passes without any pre-existing local artifacts.
        from tests.test_schema_conformance import validate, generate_artifacts
        schema = json.loads((Path(__file__).resolve().parent.parent.parent
                             / "schemas" / "decision.schema.json").read_text())
        decisions = json.loads(generate_artifacts()["decisions.json"])
        for d in decisions:
            validate(d, schema, schema)   # raises on drift


class Finding5AllowlistCanonicalizationTests(unittest.TestCase):
    """Verbatim matching let spelling variants silently fail to protect."""

    def _d(self, entry_value):
        pol = Policy(**{**POL.__dict__,
                        "allowlist": (AllowlistEntry(value=entry_value,
                                                     scope="t", owner="o",
                                                     ticket="T-1"),)})
        e = _stack("curated_source", "curated_source", "curated_source",
                   "curated_source", "exact_fqdn", "recent",
                   "bounded_scope", "verified_rollback")
        return evaluate(Indicator("a", "fqdn", "bank-partner.example",
                                  ("curated-a",), e), pol, CTX)

    def test_canonical_spellings_all_suppress(self):
        for spelling in ("bank-partner.example", "bank-partner.example.",
                         "BANK-PARTNER.Example", "  bank-partner.example  "):
            with self.subTest(spelling=spelling):
                d = self._d(spelling)
                self.assertEqual(d.disposition, "NO_ACTION")

    def test_different_domain_never_suppressed(self):
        d = self._d("other-host.example")
        self.assertNotEqual(d.disposition, "NO_ACTION")

    def test_host_prefix_forms_match(self):
        # a /32 allowlist entry and the bare host are the same target
        # (second-wave finding: /32 spelling silently failed to protect)
        ip_ev = (ev("curated_source"), ev("curated_source"),
                 ev("curated_source"), ev("curated_source"),
                 ev("exact_ip"), ev("recent"), ev("dedicated_use"),
                 ev("verified_rollback"), ev("bounded_scope"))
        for entry in ("198.51.100.44/32", "198.51.100.44"):
            pol = Policy(**{**POL.__dict__,
                            "allowlist": (AllowlistEntry(value=entry, scope="t",
                                                         owner="o", ticket="T"),)})
            d = evaluate(Indicator("a", "ipv4", "198.51.100.44",
                                   ("curated-a",), ip_ev), pol, CTX)
            with self.subTest(entry=entry):
                self.assertEqual(d.disposition, "NO_ACTION")

    def test_wider_prefix_never_matches_host(self):
        # an /24 entry is a DIFFERENT grant than a host entry: it must not
        # silently protect one host (scope explosion is fail-open)
        ip_ev = (ev("curated_source"), ev("exact_ip"), ev("recent"))
        pol = Policy(**{**POL.__dict__,
                        "allowlist": (AllowlistEntry(value="198.51.100.0/24",
                                                     scope="t", owner="o",
                                                     ticket="T"),)})
        d = evaluate(Indicator("a", "ipv4", "198.51.100.44",
                               ("curated-a",), ip_ev), pol, CTX)
        self.assertNotEqual(d.disposition, "NO_ACTION")


class Finding6AllowlistExpiryTests(unittest.TestCase):
    """expires_at was parsed but never enforced."""

    def _pol(self, expires_at, reference_now="2026-09-01T20:00:00Z"):
        return Policy(**{**POL.__dict__,
                         "reference_now": reference_now,
                         "allowlist": (AllowlistEntry(
                             value="bank-partner.example", scope="t",
                             owner="o", ticket="T-1",
                             expires_at=expires_at),)})

    def _decision(self, pol):
        e = _stack("curated_source", "curated_source", "curated_source",
                   "curated_source", "exact_fqdn", "recent",
                   "bounded_scope", "verified_rollback")
        return evaluate(Indicator("a", "fqdn", "bank-partner.example",
                                  ("curated-a",), e), pol, CTX)

    def test_unexpired_entry_suppresses(self):
        d = self._decision(self._pol("2027-01-01T00:00:00Z"))
        self.assertEqual(d.disposition, "NO_ACTION")

    def test_expired_entry_no_longer_suppresses(self):
        d = self._decision(self._pol("2020-01-01T00:00:00Z"))
        self.assertNotEqual(d.disposition, "NO_ACTION")

    def test_governed_entries_required_at_load(self):
        from apip.config import validate_policy
        raw = {"policy_version": "t", "mode": "ENFORCE", "scope": "s",
               "thresholds": {"observe_m": 40},
               "limits": {"max_auto_ttl_seconds": 3600},
               "allowlist": [{"value": "x.invalid"}]}   # no owner/ticket
        problems = validate_policy(raw)
        self.assertTrue(any("owner and ticket" in p for p in problems))


class Finding7WriterRaceTests(unittest.TestCase):
    """_TxWriter raced: cap overshoot + closed-file exceptions."""

    def test_cap_exact_under_contention(self):
        with TemporaryDirectory() as td:
            p = Path(td) / "tx.jsonl"
            w = _writer(p, max_records=500)

            errors = []

            def worker(n):
                for i in range(1000):
                    try:
                        w.write({"n": n, "i": i, "client_ref": "203.0.113.9",
                                 "observed_at": "2026-09-01T20:00:00Z"})
                    except Exception as e:      # noqa: BLE001 - any escape fails
                        errors.append(repr(e))
                        return

            ts = [threading.Thread(target=worker, args=(k,)) for k in range(6)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
            w.close()
            self.assertEqual(errors, [])
            self.assertEqual(len(p.read_text().splitlines()), 500)
            self.assertTrue(w.degraded)


def _writer(path, max_records):
    from apip.live.server import _TxWriter
    return _TxWriter(path, max_records=max_records)


class Finding8ContentLengthTests(unittest.TestCase):
    """Content-Length: int() crash on garbage, read-until-EOF on negative."""

    def test_garbage_and_negative_refused(self):
        from apip.live.server import _safe_content_length
        self.assertIsNone(_safe_content_length("abc"))
        self.assertIsNone(_safe_content_length("-5"))
        self.assertIsNone(_safe_content_length("10;evil"))
        self.assertIsNone(_safe_content_length(""))
        self.assertEqual(_safe_content_length(None), 0)
        self.assertEqual(_safe_content_length("2048"), 2048)

    def test_clamped_to_hard_cap(self):
        from apip.live.server import _safe_content_length, MAX_BODY_BYTES
        self.assertEqual(_safe_content_length("999999999"), MAX_BODY_BYTES)


class Finding9ClientNormalizationTests(unittest.TestCase):
    """[v6]:port was rejected; non-canonical v6 fragmented handles."""

    def test_all_ipv4_forms_normalize(self):
        from apip.live.adapters import _safe_client
        self.assertEqual(_safe_client("203.0.113.9"), "203.0.113.9")
        self.assertEqual(_safe_client("203.0.113.9:52844"), "203.0.113.9")

    def test_bracketed_ipv6_accepted_and_canonical(self):
        from apip.live.adapters import _safe_client
        self.assertEqual(_safe_client("[2001:db8::1]:443"), "2001:db8::1")
        self.assertEqual(_safe_client("2001:db8::1"), "2001:db8::1")
        # zero-padded / expanded spellings canonicalize to ONE handle
        self.assertEqual(_safe_client("2001:0db8:0000:0000:0000:0000:0000:0001"),
                         "2001:db8::1")

    def test_zone_ids_and_garbage_rejected(self):
        from apip.live.adapters import _safe_client
        self.assertIsNone(_safe_client("fe80::1%eth0"))
        self.assertIsNone(_safe_client("not-an-address"))
        self.assertIsNone(_safe_client("300.300.300.300"))

    def test_cross_format_handle_stability_ipv6(self):
        from apip.live.adapters import recognize
        from apip.attribution import handle_for
        envoy = recognize('[2026-09-01T19:00:00Z] "GET / HTTP/1.1" 2001:db8::1')
        nginx = recognize('{"time":"2026-09-01T19:00:01Z",'
                          '"remote_addr":"2001:0db8:0000::1",'
                          '"http_accept_language":"en"}')
        self.assertIsNotNone(envoy)
        self.assertIsNotNone(nginx)
        self.assertEqual(handle_for(envoy["client_ref"]),
                         handle_for(nginx["client_ref"]))


class BlastRadiusBudgetTests(unittest.TestCase):
    """docs/04 §8 budget: overflow demotes, never silently exceeds."""

    def test_budget_demotes_overflow_with_reason(self):
        pol = Policy(**{**POL.__dict__, "max_new_auto_actions_per_batch": 1})
        strong = _stack("curated_source", "curated_source", "curated_source",
                        "curated_source", "exact_fqdn", "recent",
                        "bounded_scope", "verified_rollback")
        inds = [Indicator(f"i{k}", "fqdn", f"bad{k}.invalid", ("curated-a",), strong)
                for k in range(3)]
        demoted = [evaluate(i, pol, CTX).with_budget_demotion() for i in inds[1:]]
        for d in demoted:
            self.assertEqual(d.disposition, "OBSERVE")
            self.assertIn("blast_radius_budget_exceeded", d.reason_codes)
            self.assertEqual(d.action, "observe")
            self.assertEqual(d.ttl_seconds, 0)


class LoaderBoundaryTests(unittest.TestCase):
    """The ingest boundary closes the whole class, not one instance."""

    def test_hostile_fields_rejected(self):
        from apip.io import load_indicators
        bad_payloads = [
            {"id": "ok", "type": "fqdn", "value": "a.invalid",
             "sources": ["cu; rated"]},                              # source id
            {"id": "ok", "type": "fqdn", "value": "a.invalid",
             "evidence": [{"kind": "k\"ind", "source_id": "s"}]},    # kind
            {"id": "ok", "type": "bogus_type", "value": "a.invalid"},  # type
            {"id": "ok", "type": "fqdn", "value": "a.invalid",
             "evidence": [{"kind": "k", "source_id": "s",
                           "observed_at": "not-a-date"}]},            # timestamp
            {"id": "ok", "type": "fqdn", "value": "a.invalid",
             "evidence": [{"kind": "k", "source_id": "s"}] * 5000},  # unbounded
        ]
        for pos, payload in enumerate(bad_payloads):
            with self.subTest(payload=pos):
                with TemporaryDirectory() as td:
                    p = Path(td) / "i.json"
                    p.write_text(json.dumps([payload]))
                    with self.assertRaises((UnsafeIdentifier, ValueError)):
                        load_indicators(p)

    def test_long_ids_rejected(self):
        from apip.io import load_indicators
        with TemporaryDirectory() as td:
            p = Path(td) / "i.json"
            p.write_text(json.dumps([{"id": "x" * 500, "type": "fqdn",
                                      "value": "a.invalid"}]))
            with self.assertRaises(UnsafeIdentifier):
                load_indicators(p)


class ClientImpactBudgetTests(unittest.TestCase):
    """docs/25 L1 client-impact budget: at most
    max_challenged_transaction_fraction_per_hour of the tenant's measured
    interactive transactions may be challenged per hour; exceeding it
    alarms and AUTO-REVERTS the overflow to L0. Fail closed: fraction set
    but volume unmeasured -> allowance 0 -> every challenge reverts."""

    def _challengeable(self, n: str) -> Indicator:
        # M=85, S_ctx=80 -> exactly the L1 band (floor 85/75): challenges
        # without reaching L2 (90) or L4 (95). Two distinct curated sources
        # + structural context, all fresh under the pinned clock.
        stack = (
            ev("curated_source", "curated-a"),
            ev("curated_source", "curated-b"),
            ev("exact_fqdn", "local-sensor"),
            ev("recent", "local-sensor"),
            ev("bounded_scope", "local-sensor"),
            ev("verified_rollback", "local-sensor"),
        )
        return Indicator(n, "fqdn", f"{n}.invalid",
                         ("curated-a", "curated-b", "local-sensor"), stack)

    def _policy(self, **over):
        base = dict(
            max_challenged_transaction_fraction_per_hour=0.05,
            measured_interactive_transactions_per_hour=100,
        )
        base.update(over)
        return Policy(**{**POL.__dict__, **base})

    def test_allowance_arithmetic(self):
        from apip.policy import challenge_allowance
        # floor(0.05 * 100) = 5; integer fixed-point, no float drift
        self.assertEqual(challenge_allowance(self._policy()), 5)
        # unmeasured but configured -> fail CLOSED to zero
        self.assertEqual(
            challenge_allowance(self._policy(measured_interactive_transactions_per_hour=None)), 0)
        # unconfigured -> None (P0-6: no negative sentinel; a negative value
        # used to overload -1 and silently disable the budget)
        self.assertIsNone(
            challenge_allowance(self._policy(max_challenged_transaction_fraction_per_hour=None)))

    def test_within_allowance_no_reversion(self):
        from apip.policy import apply_client_impact_budget
        pol = self._policy()   # allowance 5
        inds = [self._challengeable(f"c{k}") for k in range(3)]
        decisions = [evaluate(i, pol, CTX) for i in inds]
        for d in decisions:
            self.assertEqual(d.action, "proxy_challenge")
        out, alarmed = apply_client_impact_budget(list(zip(inds, decisions)), pol)
        self.assertFalse(alarmed)
        for _, d in out:
            self.assertEqual(d.action, "proxy_challenge")
            self.assertNotIn("client_impact_budget_exceeded", d.reason_codes)

    def test_overflow_reverts_to_L0_with_named_reasons(self):
        from apip.policy import apply_client_impact_budget
        pol = self._policy()   # allowance 5
        inds = [self._challengeable(f"c{k}") for k in range(8)]
        decisions = [evaluate(i, pol, CTX) for i in inds]
        self.assertEqual(sum(1 for d in decisions if d.action == "proxy_challenge"), 8)
        out, alarmed = apply_client_impact_budget(list(zip(inds, decisions)), pol)
        self.assertTrue(alarmed)   # the docs/25 alarm fired
        kept = [d for _, d in out if d.action == "proxy_challenge"]
        reverted = [d for _, d in out if d.action == "observe"]
        self.assertEqual(len(kept), 5)
        self.assertEqual(len(reverted), 3)
        for d in reverted:
            self.assertEqual(d.disposition, "OBSERVE")
            self.assertEqual(d.rung, "L0")
            self.assertEqual(d.ttl_seconds, 0)
            self.assertIsNone(d.selector)
            self.assertIn("client_impact_budget_exceeded", d.reason_codes)
            self.assertIn("challenge_auto_reverted_to_L0", d.reason_codes)
            # traceable back to the challenge it reverts
            self.assertTrue(d.id.endswith("-challenge-budget-reverted"))

    def test_unmeasured_fail_closed_reverts_all_challenges(self):
        from apip.policy import apply_client_impact_budget
        pol = self._policy(measured_interactive_transactions_per_hour=None)
        inds = [self._challengeable(f"c{k}") for k in range(2)]
        decisions = [evaluate(i, pol, CTX) for i in inds]
        self.assertEqual(sum(1 for d in decisions if d.action == "proxy_challenge"), 2)
        out, alarmed = apply_client_impact_budget(list(zip(inds, decisions)), pol)
        self.assertTrue(alarmed)
        self.assertTrue(all(d.action == "observe" and d.rung == "L0"
                            for _, d in out))

    def test_unconfigured_budget_passes_through(self):
        from apip.policy import apply_client_impact_budget
        pol = self._policy(max_challenged_transaction_fraction_per_hour=None)
        inds = [self._challengeable(f"c{k}") for k in range(3)]
        decisions = [evaluate(i, pol, CTX) for i in inds]
        out, alarmed = apply_client_impact_budget(list(zip(inds, decisions)), pol)
        self.assertFalse(alarmed)
        self.assertEqual([d.id for _, d in out], [d.id for d in decisions])

    def test_survivor_set_is_deterministic_in_batch_content(self):
        from apip.policy import apply_client_impact_budget
        pol = self._policy()
        inds = [self._challengeable(f"c{k}") for k in range(6)]
        decisions = [evaluate(i, pol, CTX) for i in inds]
        out_a, _ = apply_client_impact_budget(list(zip(inds, decisions)), pol)
        out_b, _ = apply_client_impact_budget(
            list(zip(inds[::-1], decisions[::-1])), pol)
        survivors_a = {d.indicator_id for _, d in out_a if d.action == "proxy_challenge"}
        survivors_b = {d.indicator_id for _, d in out_b if d.action == "proxy_challenge"}
        self.assertEqual(survivors_a, survivors_b)

    def test_non_challenge_actions_never_counted(self):
        from apip.policy import apply_client_impact_budget
        # v2.3 (audit P0-3): the challenge target and the L4 deny target are
        # both declared governed infra so their verified_rollback is server-
        # derived (a feed may not assert it). The shared POL governs the
        # generic c{k}.invalid challenge space; this test's named targets
        # are covered here.
        pol = self._policy(measured_interactive_transactions_per_hour=1,  # allowance 0
                           governed_verified_rollback=(
                               *POL.governed_verified_rollback,
                               "ch.invalid", "l4.invalid"))
        # one challenge + one L4-class stack (dns_nxdomain, not a challenge):
        # M=100, S_ctx=90 clears the L4 floor (95/90) exactly
        l4_stack = (
            ev("curated_source", "curated-a", "2026-09-01T19:00:00Z"),
            ev("curated_source", "curated-a", "2026-09-01T19:10:00Z"),
            ev("curated_source", "curated-a", "2026-09-01T19:20:00Z"),
            ev("curated_source", "curated-a", "2026-09-01T19:30:00Z"),
            ev("direct_local_detection", "local-sensor"),
            ev("exact_fqdn", "local-sensor"),
            ev("recent", "local-sensor"),
            ev("bounded_scope", "local-sensor"),
            ev("verified_rollback", "local-sensor"),
        )
        inds = [self._challengeable("ch"), Indicator("l4", "fqdn", "l4.invalid",
                                                     ("curated-a", "local-sensor"), l4_stack)]
        decisions = [evaluate(i, pol, CTX) for i in inds]
        by_action = {d.action for d in decisions}
        self.assertIn("proxy_challenge", by_action)
        self.assertIn("dns_nxdomain", by_action)
        out, alarmed = apply_client_impact_budget(list(zip(inds, decisions)), pol)
        self.assertTrue(alarmed)   # the challenge reverted...
        final = {d.indicator_id: d for _, d in out}
        self.assertEqual(final["ch"].action, "observe")
        # ...but the L4 domain block was untouched — it is not a challenge
        self.assertEqual(final["l4"].action, "dns_nxdomain")

    def test_cli_rejects_negative_measurement(self):
        """P0-6 (audit): `--transactions-per-hour -1` must be REJECTED at the
        CLI entry point, not silently disable the L1 budget by colliding with
        the old -1 "unconfigured" sentinel."""
        import sys as _sys
        from apip import cli as apip_cli
        with TemporaryDirectory() as td:
            inds_path = Path(td) / "i.json"
            inds_path.write_text("[]")
            policy_path = (Path(__file__).resolve().parent.parent.parent
                           / "examples" / "policy.toml")
            out_dir = Path(td) / "out"
            argv = ["evaluate", str(inds_path), "--policy", str(policy_path),
                    "--out", str(out_dir), "--transactions-per-hour", "-1"]
            saved = _sys.argv
            try:
                _sys.argv = ["apip.cli"] + argv
                code = apip_cli.main()
            finally:
                _sys.argv = saved
            # the CLI catches ValueError -> exit code 2, budget never applied
            self.assertEqual(code, 2)

    def test_cli_end_to_end_flag_overrides_and_reverts(self):
        """End-to-end through cmd_evaluate: a challenge-heavy batch under a
        configured budget with no CLI measurement reverts EVERY challenge
        (the policy's [measurement] block supplies 1000 -> allowance 50,
        so with only 2 challenges nothing reverts; forcing the flag lower
        reverts the overflow)."""
        import sys as _sys
        from apip import cli as apip_cli
        with TemporaryDirectory() as td:
            inds_path = Path(td) / "i.json"
            inds_path.write_text(json.dumps([
                {"id": f"c{k}", "type": "fqdn", "value": f"c{k}.invalid",
                 "sources": ["curated-a", "curated-b", "local-sensor"],
                 "evidence": [
                     {"kind": "curated_source", "source_id": "curated-a",
                      "observed_at": "2026-09-01T19:00:00Z"},
                     {"kind": "curated_source", "source_id": "curated-b",
                      "observed_at": "2026-09-01T19:05:00Z"},
                     {"kind": "exact_fqdn", "source_id": "local-sensor",
                      "observed_at": "2026-09-01T19:50:00Z"},
                     {"kind": "recent", "source_id": "local-sensor",
                      "observed_at": "2026-09-01T20:00:00Z"},
                     {"kind": "bounded_scope", "source_id": "local-sensor",
                      "observed_at": "2026-09-01T20:00:00Z"},
                     {"kind": "verified_rollback", "source_id": "local-sensor",
                      "observed_at": "2026-09-01T20:00:00Z"},
                 ]} for k in range(3)]))
            out_dir = Path(td) / "out"
            shipped = Path(__file__).resolve().parent.parent.parent \
                / "examples" / "policy.toml"
            # v2.3 (audit P0-3): the shipped example governs its OWN demo
            # infrastructure, not this test's c{k}.invalid challenge targets.
            # Derive a test policy from it so the values carry server-certified
            # verified_rollback — a feed may not assert that fact itself. Strip
            # any prior [governed] table (TOML forbids duplicates), then prepend
            # a combined one covering the example infra + this test's targets.
            import re as _re_gov
            policy_path = Path(td) / "policy.toml"
            toml = shipped.read_text()
            # A TOML `[governed]` table must NOT precede the top-level scalars
            # (every later bare `key = value` would become a governed field).
            # Strip any existing [governed] section and APPEND a combined one
            # at the end, so the top-level keys stay top-level.
            toml, _ = _re_gov.subn(
                r"(?ms)^\[governed\].*?(?=^\[[A-Za-z_])", "", toml)
            gov = ("[governed]\n"
                   "dedicated_use = [\n"
                   '  "198.51.100.44",\n'
                   "]\n"
                   "verified_rollback = [\n"
                   '  "198.51.100.44",\n'
                   '  "c2-demo.invalid",\n'
                   '  "c2-on-cdn-demo.invalid",\n'
                   '  "c0.invalid",\n'
                   '  "c1.invalid",\n'
                   '  "c2.invalid",\n'
                   "]\n")
            toml = toml.rstrip("\n") + "\n\n" + gov + "\n"
            policy_path.write_text(toml)
            argv = ["evaluate", str(inds_path), "--policy", str(policy_path),
                    "--out", str(out_dir), "--transactions-per-hour", "40",
                    "--demo-trust-fixture"]
            saved = _sys.argv
            try:
                _sys.argv = ["apip.cli"] + argv
                apip_cli.main()
            finally:
                _sys.argv = saved
            decisions = json.loads((out_dir / "decisions.json").read_text())
            # flag 40 * 0.05 = allowance 2; 3 challenges -> 1 reverts
            challenges = [d for d in decisions if d["action"] == "proxy_challenge"]
            reverted = [d for d in decisions
                        if d["reason_codes"] and "client_impact_budget_exceeded" in d["reason_codes"]]
            self.assertEqual(len(challenges), 2)
            self.assertEqual(len(reverted), 1)
            self.assertEqual(reverted[0]["rung"], "L0")
            self.assertIn("challenge_auto_reverted_to_L0", reverted[0]["reason_codes"])


def load_policy_safe():
    """Load the shipped example policy (path-independent)."""
    from apip.config import load_policy
    p = Path(__file__).resolve().parent.parent.parent / "examples" / "policy.toml"
    return load_policy(p)


if __name__ == "__main__":
    unittest.main()
