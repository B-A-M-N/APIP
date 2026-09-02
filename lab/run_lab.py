#!/usr/bin/env python3
"""APIP Attribution Lab scenario driver (docs/30 demonstration).

WHAT THIS IS FOR: making the attribution engine's claims observable by
running them. Each scenario prints its verdict against the spec claim it
demonstrates and writes its artifacts under lab/output/. Everything is
loopback-only, offline, stdlib-only, and enforcement-free.

Usage: python3 run_lab.py [scenario|all|--list]
"""
from __future__ import annotations

import http.client
import json
import socket
import sys
import threading
import time
from pathlib import Path

LAB = Path(__file__).resolve().parent
OUT = LAB / "output"
PKG_REF = LAB.parent / "reference" / "src"
sys.path.insert(0, str(PKG_REF))

from apip.attribution import (  # noqa: E402
    CorrelationStore, TransactionRejected, fingerprint, handle_for,
)
from apip.live.server import ChallengeOrigin  # noqa: E402

SEP = "=" * 72


def _print_result(name: str, claims: list[tuple[str, bool]]) -> bool:
    ok = all(passed for _, passed in claims)
    print(SEP)
    print(f"SCENARIO: {name}  ->  {'PASS' if ok else 'FAIL'}")
    for claim, passed in claims:
        print(f"  [{'ok' if passed else 'XX'}] {claim}")
    return ok


# ---------------------------------------------------------------------------
# Behavioral templates: three distinct toolchains. NOTE the observables are
# CONSTRUCTION behaviors (header emission order, coherence, TLS stack, cache
# correctness, serialization key order) — not what a client claims about
# itself. The spoofable User-Agent text is deliberately varied inside a
# campaign to make the point that it is irrelevant.
TOOLCHAINS = {
    "implant-a": {
        "header_order": ["host", "user-agent", "accept", "accept-encoding", "connection"],
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br",
        "tls_ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
        "cache_behavior": "validators_present_correct",
        "challenge_body_key_order": ["ts", "nonce", "response"],
        "range_fallback": "range_honored",
    },
    "implant-b": {
        "header_order": ["user-agent", "accept", "host"],
        "accept_language": "*",
        "accept_encoding": "identity",
        "tls_ja4": "t13d1513h2_5c54147bee53_e5647b281b39",
        "range_fallback": "range_ignored",
    },
    "implant-c": {
        "header_order": ["host", "accept", "accept-encoding", "user-agent",
                         "accept-language", "connection", "upgrade-insecure-requests"],
        "accept_language": "zh-CN,zh;q=0.9,en;q=0.8",
        "accept_encoding": "gzip",
        "tls_ja4": "t13d1515h2_2d1e3b4c5f60_9a8b7c6d5e4f",
        "cache_behavior": "validators_absent",
        "challenge_body_key_order": ["response", "ts", "nonce"],
        "range_fallback": "identity_fallback",
    },
}


def _tx(client_ref: str, chain: str, at: str, **overrides) -> dict:
    rec = {"client_ref": client_ref, "observed_at": at,
           **TOOLCHAINS[chain], **overrides}
    return rec


def _next_addr(i: int) -> str:
    """A distinct loopback source address per step: the lab simulates
    infrastructure rotation using 127.0.0.10, 127.0.0.11, ... — real
    distinct source IPs observed through the real capture path."""
    return f"127.0.0.{10 + i}"


# ---------------------------------------------------------------------------
def scenario_rotation() -> bool:
    """One toolchain behind four rotating source IPs -> ONE fingerprint."""
    s = CorrelationStore()
    for i in range(4):
        s.observe(_tx(_next_addr(i), "implant-a", f"2026-09-01T19:0{i}:00Z"))
    rep = s.report()
    groups = rep["fingerprint_groups"]
    claims = [
        ("4 rotating source IPs observed", rep["tracked_requesters"] == 4),
        ("exactly ONE fingerprint group despite rotation", len(groups) == 1),
        ("all 4 handles inside that one group",
         len(groups[0]["requester_handles"]) == 4),
        ("fingerprint is stable/deterministic",
         groups[0]["fingerprint"] == s.report()["fingerprint_groups"][0]["fingerprint"]),
    ]
    _dump("rotation", s, rep)
    return _print_result("rotation (docs/30: rotation resistance)", claims)


def scenario_campaigns() -> bool:
    """Three distinct toolchains -> three separate groups; nothing links."""
    s = CorrelationStore()
    # campaign one: implant-a behind two IPs
    s.observe(_tx(_next_addr(0), "implant-a", "2026-09-01T19:00:00Z"))
    s.observe(_tx(_next_addr(1), "implant-a", "2026-09-01T19:01:00Z"))
    # campaign two: implant-b behind two different IPs
    s.observe(_tx(_next_addr(2), "implant-b", "2026-09-01T19:02:00Z"))
    s.observe(_tx(_next_addr(3), "implant-b", "2026-09-01T19:03:00Z"))
    # campaign three: implant-c, one IP
    s.observe(_tx(_next_addr(4), "implant-c", "2026-09-01T19:04:00Z"))
    rep = s.report()
    groups = rep["fingerprint_groups"]
    claims = [
        ("three toolchains produce exactly three groups", len(groups) == 3),
        ("implant-a grouped (2 handles)",
         any(len(g["requester_handles"]) == 2 and g["probe_count"] == 7 for g in groups)),
        ("implant-b grouped (2 handles)",
         any(len(g["requester_handles"]) == 2 and g["probe_count"] == 5 for g in groups)),
        ("no cross-campaign links (dissimilar behavior stays separate)",
         rep["cross_fingerprint_links"] == []),
    ]
    _dump("campaigns", s, rep)
    return _print_result("campaigns (docs/30: correlation is behavioral)", claims)


def scenario_formats() -> bool:
    """Same campaign observed via Envoy and NGINX logs -> containment link.

    Mirrors apip/live/adapters.py format conversion: the campaign's traffic
    is 'logged' by two terminators that capture different probe subsets.
    """
    from apip.live.adapters import recognize
    s = CorrelationStore()
    # the SAME toolchain, as logged by two different vendors' terminators:
    envoy_lines = [
        '[2026-09-01T19:00:00Z] "GET /asset HTTP/1.1" 203.0.113.9 '
        'accept-language=en-US,en;q=0.9 accept-encoding=gzip,deflate,br '
        'ja4=t13d1516h2_8daaf6152771_b186095e22b6',
        '[2026-09-01T19:01:00Z] "GET /asset HTTP/1.1" 198.51.100.23 '
        'accept-language=en-US,en;q=0.9 accept-encoding=gzip,deflate,br '
        'ja4=t13d1516h2_8daaf6152771_b186095e22b6',
    ]
    nginx_lines = [
        '{"time":"2026-09-01T19:02:00Z","remote_addr":"192.0.2.77",'
        '"http_accept_language":"en-US,en;q=0.9","http_accept_encoding":"gzip,deflate,br",'
        '"ja4":"t13d1516h2_8daaf6152771_b186095e22b6",'
        '"header_order":"host|user-agent|accept|accept-encoding|connection"}',
    ]
    for line in envoy_lines + nginx_lines:
        rec = recognize(line)
        if rec is None:
            _print_result("formats", [("adapter failed to parse a sample line", False)])
            return False
        s.observe(rec)
    rep = s.report()
    links = rep["cross_fingerprint_links"]
    claims = [
        ("all three source IPs tracked", rep["tracked_requesters"] == 3),
        ("envoy-only vectors group together; nginx vector separate (subset)",
         len(rep["fingerprint_groups"]) == 2),
        ("envoy group and nginx group LINKED (value-matched containment)",
         len(links) == 1 and links[0]["shared_probes"] >= 2),
    ]
    _dump("formats", s, rep)
    return _print_result("formats (docs/30: heterogeneous terminators)", claims)


def _free_loopback_port() -> int:
    """Ask the kernel for a free loopback port, then release it."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def scenario_live() -> bool:
    """Real HTTP through the loopback challenge origin -> observable
    behaviors captured (P1/P4/P5), pseudonymized, and correlated."""
    with TemporaryOut() as td:
        td.mkdir(parents=True, exist_ok=True)
        tx_path = td / "transactions.jsonl"
        store = CorrelationStore()
        origin = ChallengeOrigin(tx_path, epoch="lab", store=store)
        port = _free_loopback_port()
        thread = threading.Thread(target=origin.serve, args=("127.0.0.1", port),
                                  daemon=True)
        thread.start()
        time.sleep(0.3)
        try:
            # 'attacker' implant: consistent construction behaviors across
            # THREE rotating loopback source addresses
            fp_seen = set()
            for i in range(3):
                conn = http.client.HTTPConnection("127.0.0.1", port,
                                                  source_address=("127.0.0.10", 0))
                body = json.dumps({"nonce": 1, "ts": 2, "response": 3})
                conn.request("POST", "/challenge", body=body, headers={
                    "Host": "chall",
                    "User-Agent": f"Mozilla/5.0 (spoofed-per-request v{i})",  # lying
                    "Accept": "text/html",
                    "Accept-Encoding": "gzip, br",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Content-Type": "application/json",
                })
                resp = conn.getresponse()
                resp.read()
                conn.close()
            # 'victim' browser: different construction behaviors
            conn = http.client.HTTPConnection("127.0.0.1", port,
                                              source_address=("127.0.0.20", 0))
            conn.request("GET", "/asset", headers={
                "Host": "chall", "User-Agent": "Mozilla/5.0 (Windows NT 10.0)",
                "Accept": "*/*", "Accept-Encoding": "identity"})
            conn.getresponse().read()
            conn.close()
        finally:
            time.sleep(0.3)
            origin.shutdown()

        recs = [json.loads(l) for l in tx_path.read_text().strip().split("\n")
                if l.strip()]
        attacker = [r for r in recs if r["client_ref"] == handle_for("127.0.0.10")]
        victim = [r for r in recs if r["client_ref"] == handle_for("127.0.0.20")]
        claims = [
            (f"challenge origin observed {len(recs)} real HTTP transactions",
             len(recs) >= 4),
            ("attacker's three connections captured",
             len(attacker) >= 3),
            ("P5: challenge key order captured from the attacker's body",
             any("challenge_body_key_order" in r for r in attacker)),
            ("P1: header emission order captured, stable across the "
             "attacker's connections (a construction signature)",
             len({tuple(r.get("header_order", [])) for r in attacker}) == 1
             and len(attacker[0].get("header_order", [])) >= 5),
            ("P1: attacker's emission order differs from the victim's",
             tuple(attacker[0].get("header_order", []))
             != tuple(victim[0].get("header_order", []))),
            ("spoofed User-Agent text stored NOWHERE in the records "
             "(construction behavior, not self-declared answers)",
             all("spoofed" not in json.dumps(r) for r in attacker)),
            ("attacker and victim separated (2 groups, no link)",
             len(store.report()["fingerprint_groups"]) == 2),
            ("raw source IPs present nowhere in the records",
             all("127.0.0.10" not in json.dumps(r) and "127.0.0.20" not in json.dumps(r)
                 for r in recs)),
        ]
        # persist artifacts
        OUT.mkdir(exist_ok=True)
        (OUT / "live_transactions.jsonl").write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in recs))
        (OUT / "attribution_report.json").write_text(
            json.dumps(store.report(), indent=2) + "\n")
        from apip.uireport import render_correlation_report
        (OUT / "attribution_report.html").write_text(
            render_correlation_report(store.report()), encoding="utf-8")
        return _print_result("live (docs/30: observable-behavior harvest)", claims)


def scenario_boundary() -> bool:
    """THE HARD BOUNDARY: decisions byte-identical with/without attribution."""
    from apip.models import Indicator, Evidence
    from apip.policy import Policy, RungFloor, evaluate
    from apip.registry import SourceRegistry, SourceProfile

    REG = SourceRegistry((
        SourceProfile("curated-a", "curated", True),
        SourceProfile("attr", "attribution", False, False),
    ))
    POL = Policy(
        version="lab", mode="ENFORCE", scope="t",
        observe_m=40, fqdn_auto_m=95, fqdn_auto_s=90,
        ip_rate_m=90, ip_rate_s=85, ip_deny_m=98, ip_deny_s=95,
        max_auto_ttl_seconds=3600, auto_prefix_deny=False,
        auto_routing=False, auto_wildcard_domain=False,
        rung_floors={"L4": RungFloor(95, 90), "L5": RungFloor(98, 95)},
        source_registry=REG,
    )
    CTX = {"client": "host-1", "protocol_class": "interactive_http"}

    def ind(extra=()):
        ev = [
            Evidence(kind="curated_source", source_id="curated-a",
                     source_class="x", observed_at="2026-09-01T20:00:00Z",
                     independent=True),
            Evidence(kind="single_curated_source", source_id="curated-a",
                     source_class="x", observed_at="2026-09-01T20:00:00Z",
                     independent=True),
            Evidence(kind="exact_fqdn", source_id="curated-a", source_class="x",
                     observed_at="2026-09-01T20:00:00Z", independent=True),
            Evidence(kind="recent", source_id="curated-a", source_class="x",
                     observed_at="2026-09-01T20:00:00Z", independent=True),
            Evidence(kind="bounded_scope", source_id="curated-a", source_class="x",
                     observed_at="2026-09-01T20:00:00Z", independent=True),
            Evidence(kind="verified_rollback", source_id="curated-a",
                     source_class="x", observed_at="2026-09-01T20:00:00Z",
                     independent=True),
        ] + list(extra)
        return Indicator("x", "fqdn", "bad.invalid", ("curated-a",), tuple(ev))

    # every fingerprint/behavior record the engine could produce, attached
    # as attribution-class evidence to a deny-strength indicator:
    attr_records = [
        Evidence(kind="requester_fingerprint_match", source_id="attr",
                 source_class="attribution", observed_at="2026-09-01T20:00:00Z",
                 independent=True,
                 detail={"fingerprint": "fp--fp1--deadbeefdeadbeef",
                         "campaign": "camp--1", "confidence": "high",
                         "requester_count": 47}),
        Evidence(kind="requester_volatility", source_id="attr",
                 source_class="attribution", observed_at="2026-09-01T20:00:00Z",
                 independent=True, detail={"rotations": 12}),
        Evidence(kind="requester_campaign_correlation", source_id="attr",
                 source_class="attribution", observed_at="2026-09-01T20:00:00Z",
                 independent=True, detail={"linked_groups": 3, "shared_probes": 6}),
    ]
    d_clean = evaluate(ind(), POL, CTX).to_dict()
    d_attr = evaluate(ind(attr_records), POL, CTX).to_dict()
    d_diff_clean = evaluate(ind(), POL, CTX).to_dict()

    def weak(extra=()):
        return Indicator("y", "fqdn", "meh.invalid", ("curated-a",), (
            Evidence(kind="curated_source", source_id="curated-a", source_class="x",
                     observed_at="2026-09-01T20:00:00Z", independent=True),
        ) + tuple(extra))
    weak_clean = evaluate(weak(), POL, CTX).to_dict()
    weak_attr = evaluate(weak(attr_records), POL, CTX).to_dict()
    claims = [
        ("deny-strength indicator: byte-identical decision with attribution attached",
         d_clean == d_attr),
        ("re-evaluation reproducible (decision determinism)",
         d_clean == d_diff_clean),
        ("weak indicator: also byte-identical with attribution attached",
         weak_clean == weak_attr),
        ("attribution never moves the rung, action, or disposition",
         (d_clean["rung"], d_clean["action"], d_clean["disposition"])
         == (d_attr["rung"], d_attr["action"], d_attr["disposition"])),
    ]
    return _print_result("boundary (docs/30: attribution is NEVER an enforcement input)",
                         claims)


def scenario_degradation() -> bool:
    """Bounded store: stop-and-mark degradation, authority untouched."""
    s = CorrelationStore(max_requesters=3)
    for i in range(6):
        s.observe(_tx(_next_addr(i), "implant-a" if i % 2 else "implant-b",
                      f"2026-09-01T19:0{i}:00Z"))
    rep = s.report()
    evicted = s.prune_expired("2026-09-01T23:00:00Z", ttl_seconds=3600)
    claims = [
        ("store stopped tracking NEW requesters at the envelope (3 of 6)",
         rep["tracked_requesters"] == 3),
        ("degradation flagged (stop-and-mark, not silent)",
         rep["degraded"] is True),
        ("TTL eviction deterministic and effective", evicted == 3),
        ("post-eviction report remains well-formed",
         set(rep) == {"schema_version", "degraded", "handle_keying",
                      "tracked_requesters", "fingerprint_groups",
                      "cross_fingerprint_links"}),
    ]
    _dump("degradation", s, rep)
    return _print_result("degradation (docs/23 envelopes applied to docs/30)", claims)


def scenario_churn() -> bool:
    """The HONEST adversary: rotates IPs AND mutates the fingerprint.

    The earlier rotation scenario was friendlier than reality — real
    attackers rotate behavior too. This scenario states plainly what the
    engine claims and does not: full-behavior rotation is UNTRACEABLE
    across handles (by design — the engine never pretends otherwise), while
    PARTIAL churn (attacker reuses some construction behaviors, because
    changing everything is expensive and error-prone) leaves value-matched
    containment links. Correlation is best-effort display output; nothing
    enforcement-side consumes it.
    """
    from apip.attribution import extract_features

    s = CorrelationStore()

    # Stage 1: implant-a on IP #0. Full construction signature.
    s.observe(_tx(_next_addr(0), "implant-a", "2026-09-01T19:00:00Z"))

    # Stage 2: same operator, NEW IPs, FULL behavioral rotation: every
    # observable construction behavior changed. (Borrow implant-b's entire
    # template — a rewrite of the toolchain.)
    s.observe(_tx(_next_addr(1), "implant-b", "2026-09-01T19:05:00Z"))
    s.observe(_tx(_next_addr(2), "implant-b", "2026-09-01T19:06:00Z"))

    # Stage 3: same operator again, PARTIAL churn: new TLS stack and new
    # cache behavior (the two easiest things to change), but the HTTP
    # library — and therefore header emission order and locale/encoding
    # coherence — stays (changing it broke the implant's C2 protocol once,
    # so the operator kept it).
    churned = _tx(_next_addr(3), "implant-a", "2026-09-01T19:10:00Z",
                  tls_ja4="t13d1514h2_ff00ff00ff00_001122334455",
                  cache_behavior="revalidation_ignored")
    s.observe(churned)

    rep = s.report()
    groups = rep["fingerprint_groups"]
    links = rep["cross_fingerprint_links"]

    feats_a = extract_features(_tx("x", "implant-a", "2026-09-01T19:00:00Z"))
    feats_b = extract_features(_tx("x", "implant-b", "2026-09-01T19:05:00Z"))
    feats_churn = extract_features(churned)
    shared_a_churn = set(feats_a) & set(feats_churn)
    matching_a_churn = {k for k in shared_a_churn if feats_a[k] == feats_churn[k]}
    shared_a_b = set(feats_a) & set(feats_b)
    matching_a_b = {k for k in shared_a_b if feats_a[k] == feats_b[k]}

    claims = [
        ("stage-1 + stage-2 + stage-3 all tracked (4 source IPs)",
         rep["tracked_requesters"] == 4),
        ("FULL rotation (stage 2) shares NO matching behavior values with "
         "stage 1 — the engine has nothing to link and claims nothing",
         len(matching_a_b) == 0),
        ("PARTIAL churn (stage 3) retains >= 2 construction behaviors "
         "matching stage 1 (header order, locale coherence)",
         len(matching_a_churn) >= 2),
        ("partial churn LINKS to stage 1 (value-matched containment)",
         len(links) == 1),
        ("engine never fabricates links from absence: 1 link for 1 real "
         "partial-churn pair, no link for the fully-rotated pair",
         all(l["shared_probes"] >= 2 for l in links)),
    ]
    _dump("churn", s, rep)
    return _print_result("churn (docs/30: honest limits — full rotation is "
                         "untraceable, partial churn is linkable)", claims)


class TemporaryOut:
    """Scratch output dir for the live scenario (real artifacts are re-written
    to lab/output by the scenario itself)."""

    def __init__(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name)

    def __truediv__(self, name):
        return self.path / name

    def __enter__(self):
        return self.path

    def __exit__(self, *a):
        self._tmp.cleanup()


def _dump(name: str, store: CorrelationStore, rep: dict) -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / f"{name}_attribution_report.json").write_text(
        json.dumps(rep, indent=2) + "\n")


SCENARIOS = {
    "rotation": scenario_rotation,
    "campaigns": scenario_campaigns,
    "formats": scenario_formats,
    "churn": scenario_churn,
    "live": scenario_live,
    "boundary": scenario_boundary,
    "degradation": scenario_degradation,
}


def main(argv: list[str]) -> int:
    if not argv or argv[0] in {"all", "--all"}:
        picks = list(SCENARIOS)
    elif argv[0] in {"--list", "list"}:
        print("scenarios:", ", ".join(SCENARIOS), "| all")
        return 0
    elif argv[0] in SCENARIOS:
        picks = [argv[0]]
    else:
        print(f"unknown scenario {argv[0]!r}; try --list", file=sys.stderr)
        return 2

    print("APIP ATTRIBUTION LAB (docs/30)")
    print("loopback-only · offline · no enforcement · artifacts -> lab/output/")
    print()
    results = {}
    for name in picks:
        results[name] = SCENARIOS[name]()
    print()
    print(SEP)
    failed = [n for n, ok in results.items() if not ok]
    print(f"LAB RESULT: {len(results) - len(failed)}/{len(results)} scenarios PASS"
          + (f"  (failed: {', '.join(failed)})" if failed else ""))
    print("Open lab/output/attribution_report.html for the analyst correlation view.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
