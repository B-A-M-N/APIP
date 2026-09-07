"""Suricata/IPS adapter tests (docs/06, goal E enforcement surface).

The beta Suricata surface is an IDS/EXPORT surface (review P0 #4, option A):
OFF/OBSERVE/SHADOW file export only, every rule alert-only, no reload path,
ENFORCE config refused at construction. These tests prove the failure
semantics the surface holds:

  - ENFORCE configuration is REFUSED (no fabricated enforcement claims);
  - exact-IP-only: CIDR deny never compiles to a rule; exact IP does;
  - even firewall_deny decisions render as `alert` (cannot drop) — a
    drop/reject fragment is refused at validate (never secretly enforced);
  - home-net scoping is enforced INDEPENDENTLY of policy/controller (defense
    in depth layer 3): a target outside the configured home net is refused;
  - pair/session-scoped selectors with no boundable client never broaden to
    a destination-global rule (refused, not widened);
  - rate-limits compile as MONITORING intent artifacts (alert +
    detection_filter), never silently upgraded to an enforcement actuator;
  - every rule carries decision id + TTL metadata;
  - apply/verify/revoke round-trips and revoke is idempotent; OFF refuses
    apply; the persisted action mode caps publish (SHADOW + OFF adapter
    refuses; SHADOW + SHADOW adapter publishes to the shadow ruleset).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apip.adapters.base import AdapterError  # noqa: E402
from apip.adapters.suricata import SuricataAdapter  # noqa: E402
from apip.config.service import AdapterConfig  # noqa: E402


def make_adapter(*, mode: str = "SHADOW", tmp_path: Path,
                 authorized=("198.51.100.0/24",),
                 reload_cmd: str = "") -> SuricataAdapter:
    if reload_cmd:
        raise ValueError(
            "the beta Suricata surface has no reload path; reload_cmd must "
            "be empty (truthfulness)")
    cfg = AdapterConfig(
        suricata_mode=mode,
        suricata_rules_dir=str(tmp_path),
        suricata_rules_file="apip",
        suricata_reload_command="",
        suricata_authorized_prefixes=tuple(authorized),
    )
    return SuricataAdapter(cfg)


def _decision(*, action="firewall_deny", disposition="AUTO_ENFORCE",
              dec_id="decision--x", rung="L5", ttl=3600,
              selector=None):
    return type("D", (), {
        "action": action, "disposition": disposition, "id": dec_id,
        "rung": rung, "ttl_seconds": ttl, "selector": selector,
    })()


def _candidate(*, rule_id, fragment, selector, mode="SHADOW"):
    """Dispatch-shaped candidate: carries the PERSISTED action mode."""
    return {"adapter": "suricata", "mode": mode, "rule_id": rule_id,
            "fragment": fragment, "selector": selector}


def test_enforce_mode_refused_at_construction(tmp_path):
    """ENFORCE is not offered in beta: no reload path, no parser validation,
    no engine-loaded confirmation. Configuration fails closed."""
    with pytest.raises(AdapterError):
        make_adapter(mode="ENFORCE", tmp_path=tmp_path)


def test_compile_exact_ip_firewall_deny_is_alert_only(tmp_path):
    """Even firewall_deny compiles to an IDS `alert` — the beta surface
    cannot drop traffic (truthfulness)."""
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    fr = ad.compile(_decision(action="firewall_deny", dec_id="decision--a",
                              rung="L5"), "198.51.100.7", "ipv4")
    assert len(fr) == 1
    f = fr[0]
    assert f["adapter"] == "suricata"
    assert f["rule_id"].startswith("sid:")
    assert f["fragment"].startswith("alert ip $HOME_NET any -> 198.51.100.7 any ")
    assert "metadata:apip_decision decision--a" in f["fragment"]
    assert "apip_ttl_seconds 3600" in f["fragment"]
    assert "sid:" in f["fragment"]
    assert f["monitoring_only"] is True
    assert f["selector"]["exact_ip"] == "198.51.100.7"


def test_compile_refuses_cidr_deny(tmp_path):
    """CIDR auto-deny never compiles to a rule (exact-IP-only, docs/06)."""
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    fr = ad.compile(_decision(action="firewall_deny", dec_id="decision--b"),
                    "198.51.100.0/24", "cidr")
    assert fr == []


def test_validate_refuses_drop_fragment(tmp_path):
    """A drop/reject fragment is refused even if hand-crafted — an IDS export
    can never be secretly upgraded to inline enforcement."""
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    cand = _candidate(
        rule_id="sid:9100001",
        fragment=('drop ip $HOME_NET any -> 198.51.100.7 any '
                  '(msg:"x"; metadata:apip_decision d; sid:9100001; rev:1;)'),
        selector={"scope_type": "destination_global",
                  "destination": "198.51.100.7", "exact_ip": "198.51.100.7"})
    with pytest.raises(AdapterError):
        ad.validate(cand)


def test_compile_ip_rate_limit_is_monitoring(tmp_path):
    """IP rate-limit = alert + detection_filter intent artifact (monitoring)."""
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    sel = type("S", (), {
        "scope_type": "client_destination_pair", "client": "host-1",
        "destination": "198.51.100.9",
        "rate_ceiling_per_min": 120})()
    fr = ad.compile(_decision(action="rate_limit", dec_id="decision--c",
                              selector=sel), "198.51.100.9", "ipv4")
    assert len(fr) == 1
    f = fr[0]
    assert f["fragment"].startswith("alert ip $HOME_NET any -> 198.51.100.9 any ")
    assert "detection_filter:track by_src, count 120, seconds 60" in f["fragment"]
    assert f["monitoring_only"] is True


def test_pair_selector_no_client_refuses_to_broaden(tmp_path):
    """A pair-scoped selector with no boundable client is REFUSED, never
    broadened to a destination-global rule (docs/25 / docs/06)."""
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    sel = type("S", (), {
        "scope_type": "client_destination_pair", "client": None,
        "destination": "198.51.100.10",
        "rate_ceiling_per_min": 100})()
    with pytest.raises(AdapterError):
        ad.compile(_decision(action="rate_limit", dec_id="decision--d",
                             selector=sel), "198.51.100.10", "ipv4")


def test_home_net_scope_is_independent(tmp_path):
    """A target outside the configured home net is refused at compile even if
    policy/controller would have allowed it (defense in depth layer 3)."""
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path,
                      authorized=("203.0.113.0/24",))
    with pytest.raises(AdapterError):
        ad.compile(_decision(action="firewall_deny"), "198.51.100.7", "ipv4")


def test_enforce_without_home_net_never_authorizes(tmp_path):
    """OBSERVE/SHADOW may run with empty scope (they never actuate)."""
    assert make_adapter(mode="OBSERVE", tmp_path=tmp_path,
                        authorized=()).max_mode() == "OBSERVE"


def test_apply_verify_revoke_roundtrip(tmp_path):
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    fr = ad.compile(_decision(action="firewall_deny", dec_id="decision--e"),
                    "198.51.100.15", "ipv4")[0]
    cand = _candidate(rule_id=fr["rule_id"], fragment=fr["fragment"],
                      selector=fr["selector"], mode="SHADOW")
    r = ad.apply(cand)
    assert r["ok"] is True
    assert r["receipt"]["observed"]["monitoring_only"] is True
    assert r["receipt"]["observed"]["sid"] == fr["rule_id"].split("sid:")[1]
    v = ad.verify(cand)
    assert v["ok"] is True
    assert v["observed"]["rule_present"] is True
    assert v["observed"]["monitoring_only"] is True
    assert ad.get_state(cand["selector"])["present"] is True
    rv = ad.revoke(cand)
    assert rv["ok"] is True
    assert ad.get_state(cand["selector"])["present"] is False
    assert ad.revoke(cand)["ok"] is True   # idempotent


def test_persisted_mode_caps_publish(tmp_path):
    """Posture immutability (review P0 #1): the persisted action mode governs.
    OFF action mode -> refuse to publish; the adapter max can only weaken,
    never strengthen. A mode-less candidate fails closed (OFF)."""
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    fr = ad.compile(_decision(action="firewall_deny", dec_id="decision--pm"),
                    "198.51.100.16", "ipv4")[0]
    off_cand = _candidate(rule_id=fr["rule_id"], fragment=fr["fragment"],
                          selector=fr["selector"], mode="OFF")
    with pytest.raises(AdapterError):
        ad.apply(off_cand)
    missing = {k: v for k, v in off_cand.items() if k != "mode"}
    with pytest.raises(AdapterError):
        ad.apply(missing)


def test_verify_without_rule_fails_closed(tmp_path):
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    fr = ad.compile(_decision(action="firewall_deny", dec_id="decision--f"),
                    "198.51.100.20", "ipv4")[0]
    cand = _candidate(rule_id=fr["rule_id"], fragment=fr["fragment"],
                      selector=fr["selector"])
    # never applied
    assert ad.verify(cand)["ok"] is False


def test_sid_matches_exact_not_substring(tmp_path):
    """A rule whose SID shares a prefix with the target must be neither
    reported-present by verify nor removed by revoke. (Substring matching
    would fake success / over-remove — selector/boundary never broadens.)"""
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    fr = ad.compile(_decision(action="firewall_deny", dec_id="decision--s1"),
                    "198.51.100.40", "ipv4")[0]
    cand = _candidate(rule_id=fr["rule_id"], fragment=fr["fragment"],
                      selector=fr["selector"])
    r = ad.apply(cand)
    assert r["ok"] is True
    target_sid = r["receipt"]["observed"]["sid"]

    # A decoy rule whose SID has the target as a numeric prefix
    # (e.g. target 9100001 vs decoy 91000010). Never applied by APIP — an
    # out-of-band rule that must survive a revoke targeting only our SID.
    decoy_sid = target_sid + "0"
    decoy = ('drop ip $HOME_NET any -> 198.51.100.41 any (msg:"decoy"; '
             f'sid:{decoy_sid}; rev:1;)')
    rules_file = Path(tmp_path) / "apip.rules"
    rules_file.write_text(rules_file.read_text() + "\n" + decoy + "\n")

    # verify must still be true for our exact rule, and must NOT confuse the
    # decoy's longer SID for ours.
    assert ad.verify(cand)["ok"] is True

    # get_state: revoking the decoy scenario — our rule's exact sid should
    # still be the only thing present for this selector/IP.
    st = ad.get_state(cand["selector"])
    assert st["present"] is True

    # revoke our rule only; the decoy must survive untouched.
    rv = ad.revoke(cand)
    assert rv["ok"] is True
    remaining = rules_file.read_text()
    assert f"sid:{target_sid};" not in remaining   # ours removed
    assert f"sid:{decoy_sid};" in remaining        # decoy still present
    assert ad.get_state(cand["selector"])["present"] is False


def test_off_refuses_apply(tmp_path):
    ad = make_adapter(mode="OFF", tmp_path=tmp_path)
    fr = ad.compile(_decision(action="firewall_deny", dec_id="decision--g"),
                    "198.51.100.21", "ipv4")[0]
    cand = _candidate(rule_id=fr["rule_id"], fragment=fr["fragment"],
                      selector=fr["selector"])
    assert ad.validate(cand)["ok"] is True   # dry-run allowed
    with pytest.raises(AdapterError):
        ad.apply(cand)


def test_fqdn_rate_limit_http_host_intent(tmp_path):
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    sel = type("S", (), {
        "scope_type": "client_destination_pair", "client": "host-2",
        "destination": "tunnel.invalid", "protocol_class": "interactive_http",
        "rate_ceiling_per_min": 60})()
    fr = ad.compile(_decision(action="rate_limit", dec_id="decision--i",
                              selector=sel), "tunnel.invalid", "fqdn")
    assert len(fr) == 1
    f = fr[0]
    assert f["fragment"].startswith("alert http any any -> any any ")
    assert 'http.host; content:"tunnel.invalid"; nocase;' in f["fragment"]
    assert f["monitoring_only"] is True
    assert "apip_client host-2" in f["fragment"]


def test_validate_refuses_pair_selector(tmp_path):
    """validate() re-refuses a pair-scoped selector (selector-never-broadens,
    enforced twice)."""
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    cand = {
        "rule_id": "sid:9100002",
        "mode": "SHADOW",
        "fragment": "alert ip $HOME_NET any -> 198.51.100.7 any "
                    "(msg:\"x\"; metadata:apip_decision abc; "
                    "apip_ttl_seconds 60; sid:9100002; rev:1;)",
        "selector": {"scope_type": "client_destination_pair",
                     "destination": "198.51.100.7"},
    }
    with pytest.raises(AdapterError):
        ad.validate(cand)


# ---------------------------------------------------------------------------
# Durable SID allocation (review P0 #5): deterministic per decision id,
# restart-safe, multi-controller collision-free.
# ---------------------------------------------------------------------------

def test_sid_deterministic_per_decision_across_restart(tmp_path):
    """Two FRESH adapter instances (simulating two APIP processes) compiling
    the same decision derive the SAME sid — no process-local counter drift,
    so a restart can never allocate a colliding new sid range."""
    ad1 = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    ad2 = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    fr1 = ad1.compile(_decision(dec_id="decision--restart"), "198.51.100.50", "ipv4")[0]
    fr2 = ad2.compile(_decision(dec_id="decision--restart"), "198.51.100.50", "ipv4")[0]
    assert fr1["rule_id"] == fr2["rule_id"]


def test_sid_distinct_across_decisions_and_controllers(tmp_path):
    """Different decisions on fresh instances (independent 'restarts' /
    controllers) get different sids — the failure mode of the old per-process
    counter, which restarted at the same value and overwrote an installed
    rule owned by a different action."""
    sids = set()
    for i in range(8):
        ad = make_adapter(mode="SHADOW", tmp_path=tmp_path)
        fr = ad.compile(_decision(dec_id=f"decision--multi-{i}"),
                        "198.51.100.60", "ipv4")[0]
        sids.add(fr["rule_id"])
    assert len(sids) == 8


def test_sid_avoids_installed_rules_from_other_decisions(tmp_path):
    """A foreign rule already occupying the derived sid slot (out-of-band
    install or hash-bucket collision) shifts the allocation past it — the
    new rule must never overwrite an unrelated installed rule."""
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    derived = ad._next_sid("decision--occupy", "")
    foreign = (f'alert ip $HOME_NET any -> 198.51.100.70 any '
               f'(msg:"foreign"; sid:{derived}; rev:1;)')
    (tmp_path / "apip.rules").write_text(foreign + "\n")
    fr = ad.compile(_decision(dec_id="decision--occupy"), "198.51.100.70", "ipv4")[0]
    assert fr["rule_id"] != f"sid:{derived}"


def test_same_decision_recompiles_to_same_sid_after_apply(tmp_path):
    """Re-dispatching an already-applied action (crash recovery, reconcile)
    recompiles to the identical sid, so apply() replaces its own rule rather
    than piling up duplicates."""
    ad = make_adapter(mode="SHADOW", tmp_path=tmp_path)
    fr = ad.compile(_decision(dec_id="decision--reapply"), "198.51.100.80", "ipv4")[0]
    cand = _candidate(rule_id=fr["rule_id"], fragment=fr["fragment"],
                      selector=fr["selector"])
    assert ad.apply(cand)["ok"] is True
    fr2 = ad.compile(_decision(dec_id="decision--reapply"), "198.51.100.80", "ipv4")[0]
    assert fr2["rule_id"] == fr["rule_id"]
    assert ad.apply(_candidate(rule_id=fr2["rule_id"], fragment=fr2["fragment"],
                               selector=fr2["selector"]))["ok"] is True
    content = (tmp_path / "apip.rules").read_text()
    assert content.count(f'sid:{fr["rule_id"].split("sid:")[1]};') == 1
