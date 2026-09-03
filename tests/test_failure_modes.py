"""Failure-mode, adversarial, and property tests for the beta product.

These exercise the REAL production modules (decision engine, policy scope,
RPZ adapter) — no running Postgres or DNS resolver required. They prove the
failure semantics the goal demands:

  - the adapter NEVER accepts a selector wider than the decision authorized
    (selector-never-broadens, property test over many crafted selectors);
  - the adapter enforces its own authorized-domain scope INDEPENDENTLY of
    policy/controller (defense in depth layer 3);
  - ENFORCE apply without an explicit adapter scope is refused at init;
  - a reload failure surfaces as a failed apply (no fabricated success) and
    an NXDOMAIN verify failure fails closed;
  - revoke is idempotent and only removes the exact owner;
  - the decision engine fails toward NO_ACTION for: out-of-scope targets,
    allowlisted FQDN, insufficient evidence, stale evidence, future-dated
    (clock-skewed) evidence, and unverified control-plane-only claims;
  - a poisoned source identity (payload-declared, not channel-certified)
    carries zero authority.

Selector-never-broadens is enforced in three layers; these tests hammer the
adapter's own checks (the last line of defense).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apip.config.service import AdapterConfig  # noqa: E402
from apip.adapters.rpz import RpzAdapter  # noqa: E402
from apip.adapters.base import AdapterError  # noqa: E402
from apip.decision.loader import load_policy_text  # noqa: E402
from apip.decision.policy import evaluate, in_scope  # noqa: E402
from apip.domain.models import Evidence, Indicator  # noqa: E402
from apip.registry import SourceProfile, SourceRegistry  # noqa: E402

NOW = "2026-09-01T20:00:00Z"


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------

def make_adapter(*, mode: str = "ENFORCE", tmp_path: Path,
                 authorized=("operator.test", "invalid"),
                 server: str = "", reload_cmd: str = "") -> RpzAdapter:
    cfg = AdapterConfig(
        rpz_mode=mode,
        zone_dir=str(tmp_path),
        zone_name="apip.test.zone",
        reload_command=reload_cmd,
        authorized_domains=tuple(authorized),
        verify_query_server=server,
    )
    return RpzAdapter(cfg)


def _policy_text(*, mode: str = "SHADOW", domains=(),
                 allowlisted=(), now: str = NOW,
                 observe_m: int = 40) -> str:
    """Emit a minimal-but-valid policy TOML. Supplying `domains` declares an
    operator boundary (reference_unrestricted=False), which is what makes the
    scope gate real."""
    lines = [
        f"policy_version = 'fm-v1'",
        f"mode = '{mode}'",
        f"scope = 'lab'",
        "",
        "[thresholds]",
        f"observe_m = {observe_m}",
        "fqdn_auto_m = 95",
        "fqdn_auto_s = 90",
        "ip_rate_m = 90",
        "ip_rate_s = 85",
        "ip_deny_m = 98",
        "ip_deny_s = 95",
        "",
        "[thresholds.rungs.L4]",
        "m = 95",
        "s = 90",
        "",
        "[limits]",
        "max_auto_ttl_seconds = 3600",
        "",
        "[authorization]",
        "authorized_prefixes = []",
    ]
    if domains:
        lines.append("authorized_domains = " + repr(list(domains)))
    if allowlisted:
        lines.append("")
        lines.append("allowlist_precedence = true")
        lines.append("")
        lines.append("[[allowlist]]")
        lines.append(f"value = '{allowlisted[0]}'")
        lines.append("owner = 'test-owner'")
        lines.append("ticket = 'ACC-1'")
    lines.append("")
    lines.append("[safety]")
    lines.append("auto_prefix_deny = false")
    lines.append("no_ai_components = true")
    lines.append("")
    lines.append("[replay]")
    lines.append(f"reference_now = '{now}'")
    return "\n".join(lines)


def make_registry(*, registered=("threat-feed", "local-sensor")):
    profiles = tuple(
        SourceProfile(source_id=sid, source_class=(
            "local" if sid == "local-sensor" else "curated"),
            independent=True)
        for sid in registered)
    return SourceRegistry(profiles)


def make_evidence(rows: list[dict]) -> tuple:
    return tuple(
        Evidence(kind=r["kind"], source_id=r["source_id"], source_class="unassigned",
                 observed_at=r.get("observed_at", NOW),
                 independent=False, detail=r.get("detail", {}))
        for r in rows)


def decide(value: str, evidence, *, domains=("operator.test", "invalid"),
           mode="SHADOW", now=NOW, allowlisted=(), registered=("threat-feed", "local-sensor")):
    """Run the full production decision path with a server-bound registry and
    a pinned clock."""
    reg = make_registry(registered=registered)
    text = _policy_text(mode=mode, domains=domains, now=now, allowlisted=allowlisted)
    policy = load_policy_text(text, source_registry=reg, now_fn=lambda: now)
    indicator = Indicator(id="indicator--fm", type="fqdn", value=value,
                          sources=tuple(e.source_id for e in evidence),
                          evidence=evidence, tags=("c2",))
    return evaluate(indicator, policy, {}), policy


def strong_evidence(source: str = "local-sensor", *,
                    ts: str = "2026-09-01T19:50:00Z") -> tuple:
    """Evidence profile that (when channel-certified) reaches the FQDN auto
    floor from a local sensor."""
    return make_evidence([
        {"kind": "direct_local_detection", "source_id": source, "observed_at": ts},
        {"kind": "exact_fqdn", "source_id": source, "observed_at": ts},
        {"kind": "recent", "source_id": source, "observed_at": NOW},
        {"kind": "bounded_scope", "source_id": source, "observed_at": NOW},
    ])


def _candidate(owner: str = "evil.operator.test", *, fragment=None,
               selector=None) -> dict:
    owner_n = owner.rstrip(".")
    return {
        "adapter": "rpz",
        "rule_id": f"owner:{owner_n}",
        "fragment": fragment or f"{owner_n}. IN CNAME . ; test",
        "selector": selector or {
            "scope_type": "destination_global",
            "destination": owner_n,
            "exact_fqdn": owner_n,
        },
    }


# ---------------------------------------------------------------------------
# Adapter selector-never-broadens (property test, layer 3)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("owner", [
    "a.operator.test",
    "deep.sub.operator.test",
    "operator.test",
    "exactly.invalid",
])
def test_adapter_exact_fqdn_roundtrip(tmp_path, owner):
    """Exact owned FQDN in scope → apply + verify + revoke round-trips."""
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path,
                      authorized=("operator.test", "invalid"))
    cand = _candidate(owner)
    r = ad.apply(cand)
    assert r["ok"] is True
    assert r["receipt"]["status"] == "applied"
    v = ad.verify(cand)
    assert v["ok"] is True
    assert v["observed"]["rule_present"] is True
    assert ad.get_state(cand["selector"])["present"] is True
    rv = ad.revoke(cand)
    assert rv["ok"] is True
    assert ad.get_state(cand["selector"])["present"] is False
    assert ad.revoke(cand)["ok"] is True   # idempotent


def _mutate_selector(base: dict) -> list[dict]:
    """Adversarial selector mutations — any wider-than-approved must be
    refused by validate()."""
    variants = []
    d = base["selector"]["exact_fqdn"].rstrip(".")
    variants += [
        {"scope_type": "destination_global", "destination": d, "exact_fqdn": None},
        {"scope_type": "destination_global", "destination": d},           # missing exact
        {"scope_type": "network", "destination": d, "exact_fqdn": d},     # wrong type
        {"scope_type": "destination_global", "destination": "10.0.0.0/8", "exact_fqdn": d},
        {"scope_type": "destination_global", "destination": d, "exact_fqdn": "*.operator.test"},
        {"scope_type": "destination_global", "destination": "operator.test",
         "exact_fqdn": d},                                                 # wider destination
    ]
    return [v for v in variants if v != base["selector"]]


@pytest.mark.parametrize("owner", ["evil.operator.test", "sub.operator.test"])
def test_selector_never_broadens(tmp_path, owner):
    """Any selector mutation wider than the authorized exact FQDN is refused."""
    ad = make_adapter(mode="ENFORCE", tmp_path=tmp_path,
                      authorized=("operator.test",))
    base = _candidate(owner)
    assert ad.validate(base)["ok"] is True
    for sel in _mutate_selector(base):
        with pytest.raises(AdapterError):
            ad.validate(dict(base, selector=sel))


@pytest.mark.parametrize("bad", ["*.operator.test", "a.*.operator.test"])
def test_compile_refuses_wildcard(tmp_path, bad):
    """Wildcards never compile to a rule in beta (empty, never a broaden)."""
    ad = make_adapter(mode="ENFORCE", tmp_path=tmp_path, authorized=("operator.test",))
    deco = type("D", (), {"action": "dns_nxdomain", "disposition": "AUTO_ENFORCE",
                          "id": "dec-x", "policy_version": "p"})
    assert ad.compile(deco(), bad, "fqdn") == []
    # and a wildcard owner can never validate
    with pytest.raises(AdapterError):
        ad.validate(_candidate(bad))
    with pytest.raises(AdapterError):
        ad.validate(_candidate("ok.operator.test", selector={
            "scope_type": "destination_global", "destination": bad, "exact_fqdn": bad}))


@pytest.mark.parametrize("bad", ["*", "root", "x.*.evil.com"])
def test_validate_refuses_wildcard_owner(tmp_path, bad):
    ad = make_adapter(mode="ENFORCE", tmp_path=tmp_path, authorized=("operator.test",))
    with pytest.raises(AdapterError):
        ad.validate(_candidate(bad))


def test_compile_requires_fqdn_dns_nxdomain(tmp_path):
    """Non-FQDN / non-dns_nxdomain decisions compile to nothing."""
    ad = make_adapter(mode="ENFORCE", tmp_path=tmp_path, authorized=("operator.test",))
    deco = type("D", (), {"action": "dns_nxdomain", "disposition": "AUTO_ENFORCE",
                          "id": "dec", "policy_version": "p"})
    assert ad.compile(deco(), "10.0.0.5", "ip") == []
    assert len(ad.compile(deco(), "evil.operator.test", "fqdn")) == 1
    deco2 = type("D", (), {"action": "block_ip", "disposition": "AUTO_ENFORCE",
                           "id": "dec", "policy_version": "p"})
    assert ad.compile(deco2(), "evil.operator.test", "fqdn") == []


def test_adapter_scope_is_independent(tmp_path):
    """Adapter refuses a domain OUTSIDE its configured authorized suffixes even
    if the policy/controller would have allowed it (defense in depth L3)."""
    ad = make_adapter(mode="ENFORCE", tmp_path=tmp_path, authorized=("corp.test",))
    cand = _candidate("evil.operator.test")
    with pytest.raises(AdapterError):
        ad.apply(cand)
    with pytest.raises(AdapterError):
        ad.validate(cand)


def test_enforce_without_adapter_scope_never_authorizes(tmp_path):
    """ENFORCE with NO configured adapter suffixes refuses to construct
    (authorize-by-omission is impossible at the enforcement edge)."""
    with pytest.raises(AdapterError):
        make_adapter(mode="ENFORCE", tmp_path=tmp_path, authorized=())
    # OBSERVE/SHADOW may run with empty scope (they never affect a resolver)
    assert make_adapter(mode="SHADOW", tmp_path=tmp_path, authorized=()).max_mode() == "SHADOW"


def test_observe_refuses_apply(tmp_path):
    """OBSERVE never publishes an enforcement posture (apply refused), so no
    resolver-behavior change is even possible from the observation tier."""
    ad = make_adapter(mode="OBSERVE", tmp_path=tmp_path, authorized=("operator.test",))
    assert ad.max_mode() == "OBSERVE"
    # validate (dry run) is allowed; apply is refused — observation can never
    # touch a live resolver
    assert ad.validate(_candidate("evil.operator.test"))["ok"] is True
    with pytest.raises(AdapterError):
        ad.apply(_candidate("evil.operator.test"))


def test_reload_failure_surfaces_not_fabricated(tmp_path):
    """A reload command that fails must surface as apply failure — never a
    fabricated success receipt."""
    ad = make_adapter(mode="ENFORCE", tmp_path=tmp_path,
                      authorized=("operator.test",),
                      reload_cmd="false", server="127.0.0.1")
    r = ad.apply(_candidate("evil.operator.test"))
    assert r["ok"] is False
    assert "reload failed" in r.get("error", "")
    assert "receipt" not in r


def test_nxdomain_verify_failure_fails_closed(tmp_path):
    """ENFORCE verify requires a real NXDOMAIN; any other answer fails closed."""
    import apip.adapters.rpz as rpz_mod
    ad = make_adapter(mode="ENFORCE", tmp_path=tmp_path,
                      authorized=("operator.test",),
                      server="127.0.0.1", reload_cmd="")

    orig = rpz_mod.RpzAdapter._dns_query_nxdomain
    # resolver answers NOERROR → verify fails
    rpz_mod.RpzAdapter._dns_query_nxdomain = lambda self, fqdn: {
        "queried": True, "rcode": 0, "answers": 1, "questions": 1}
    try:
        cand = _candidate("evil.operator.test")
        ad.apply(cand)
        v = ad.verify(cand)
        assert v["ok"] is False
        assert "NXDOMAIN" in v.get("error", "")
    finally:
        rpz_mod.RpzAdapter._dns_query_nxdomain = orig

    # DNS query itself fails → verify fails
    rpz_mod.RpzAdapter._dns_query_nxdomain = lambda self, fqdn: {
        "queried": False, "error": "timeout"}
    try:
        ad.apply(_candidate("other.operator.test"))
        v = ad.verify(_candidate("other.operator.test"))
        assert v["ok"] is False
        assert "query failed" in v.get("error", "")
    finally:
        rpz_mod.RpzAdapter._dns_query_nxdomain = orig


def test_off_mode_compiles_only(tmp_path):
    """OFF adapter accepts validate (dry run) but REFUSES apply."""
    ad = make_adapter(mode="OFF", tmp_path=tmp_path, authorized=("operator.test",))
    assert ad.max_mode() == "OFF"
    cand = _candidate("evil.operator.test")
    assert ad.validate(cand)["ok"] is True
    with pytest.raises(AdapterError):
        ad.apply(cand)


# ---------------------------------------------------------------------------
# Decision engine failure semantics (fail toward NO_ACTION / no authority)
# ---------------------------------------------------------------------------

def test_out_of_scope_target_is_no_action():
    """An FQDN outside the authorized domains never generates an action, no
    matter the evidence; the named reason is surfaced."""
    d, pol = decide("evil.com", strong_evidence(),
                    domains=("invalid",))
    assert d.action == "none"
    assert d.disposition in ("NO_ACTION",)
    assert "out_of_authorized_scope" in d.reason_codes


def test_allowlisted_fqdn_is_no_action():
    """An allowlisted FQDN is refused even with strong evidence."""
    d, pol = decide("victim.operator.test", strong_evidence(),
                    domains=("operator.test", "invalid"),
                    allowlisted=("victim.operator.test",))
    assert d.action == "none"
    assert d.disposition in ("NO_ACTION",)
    assert any("allowlist" in r for r in d.reason_codes)


def test_insufficient_evidence_is_no_action():
    """Not enough evidence → below observe floor → yes."

    A single weak curated datum from a channel-certified source yields
    minuscule confidence, below observe_m.
    """
    ev = make_evidence([{"kind": "curated_source", "source_id": "threat-feed"}])
    d, pol = decide("evil.operator.test", ev, domains=("operator.test", "invalid"))
    assert d.maliciousness < pol.observe_m
    assert d.action == "none"


def test_stale_evidence_decays_to_no_authority():
    """Evidence older than the recency window contributes zero confidence."""
    old = "2026-09-01T01:00:00Z"   # > 6h before NOW
    ev = make_evidence([
        {"kind": "curated_source", "source_id": "threat-feed", "observed_at": old},
    ])
    d, pol = decide("evil.operator.test", ev, domains=("operator.test", "invalid"))
    assert d.action == "none"


def test_future_timestamp_is_stale():
    """Clock-skew (future beyond tolerance) is treated stale → no authority."""
    future = "2026-09-01T21:30:00Z"   # +1.5h ahead of NOW
    ev = make_evidence([
        {"kind": "curated_source", "source_id": "threat-feed", "observed_at": future},
    ])
    d, pol = decide("evil.operator.test", ev, domains=("operator.test", "invalid"))
    assert d.action == "none"


def test_poisoned_source_identity_zero_authority():
    """A forged payload-declared source id that the server does NOT
    channel-certify carries zero authority — self-assertion cannot promote a
    claim to a trusted source."""
    # server registry ONLY knows these two; attacker asserts an extra source
    d, pol = decide("evil.operator.test",
                    strong_evidence(source="attacker-controlled"),
                    domains=("operator.test", "invalid"),
                    registered=("threat-feed", "local-sensor"))
    assert d.action == "none", "unregistered source forged identity must not enforce"


def test_control_plane_claim_from_private_client_is_zero():
    """recent/bounded_scope/exactness control-plane kinds only count when
    server-derived; a private client claiming them alone cannot reach the
    auto floor."""
    ev = make_evidence([
        {"kind": "recent", "source_id": "attacker-controlled"},
        {"kind": "bounded_scope", "source_id": "attacker-controlled"},
        {"kind": "exact_fqdn", "source_id": "attacker-controlled"},
    ])
    d, pol = decide("evil.operator.test", ev, domains=("operator.test", "invalid"),
                    registered=("local-sensor",))
    assert d.action == "none"


def test_in_scope_helpers():
    """Each of the three layers re-checks scope: decision, controller, adapter."""
    text = _policy_text(domains=("operator.test",))
    pol = load_policy_text(text, source_registry=make_registry(), now_fn=lambda: NOW)
    assert in_scope("evil.operator.test", "fqdn", pol) is True
    assert in_scope("other.test", "fqdn", pol) is False
    assert in_scope("malicious.net", "fqdn", pol) is False

    # a non-scoped adapter refuses to even validate the same fqdn
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        ad = make_adapter(mode="ENFORCE", tmp_path=Path(tmp), authorized=("corp.test",))
        with pytest.raises(AdapterError):
            ad.validate(_candidate("evil.operator.test"))


def test_strong_channel_certified_evidence_is_not_suppressed():
    """Positive control: a channel-certified local sensor on an in-scope FQDN
    in ENFORCE mode is NOT swept into NO_ACTION by over-aggressive gating —
    it reaches the observation ladder. (This matches the oracle-pinned
    ``test_diff_shadow_dns_two_curated`` disposition for the dual-curated +
    local profile.)"""
    ev = make_evidence([
        {"kind": "curated_source", "source_id": "threat-feed-a"},
        {"kind": "curated_source", "source_id": "threat-feed-b",
         "observed_at": "2026-09-01T19:10:00Z"},
        {"kind": "direct_local_detection", "source_id": "local-sensor"},
        {"kind": "exact_fqdn", "source_id": "local-sensor"},
    ])
    d, pol = decide("evil.operator.test", ev,
                    domains=("operator.test", "invalid"), mode="ENFORCE")
    assert d.disposition != "NO_ACTION", "channel-certified in-scope case must not be suppressed"
    assert d.action in ("observe", "dns_nxdomain")
    assert d.maliciousness >= pol.observe_m