"""Action-posture immutability (review P0 #1) and SHADOW no-enforcement
guarantees (review P0 #2).

The PERSISTED action mode is the authority at the adapter boundary:
effective posture = min(action mode, adapter maximum posture). A restart or
config change must never upgrade an already-created action. And SHADOW is
technically incapable of enforcement: separate shadow artifacts, spec-defined
no-op rule forms, no reload below effective ENFORCE.

DB-free tests hammer the adapter boundary directly; the restart-survival
semantics (serialized mode authoritative across a config flip) are exercised
in tests/test_controller_integration.py against a real Postgres.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apip.adapters.base import AdapterError, effective_mode  # noqa: E402
from apip.adapters.rpz import RpzAdapter  # noqa: E402
from apip.adapters.suricata import SuricataAdapter  # noqa: E402
from apip.config.service import AdapterConfig  # noqa: E402


def _rpz(tmp_path, mode, authorized=("operator.test",), server=""):
    return RpzAdapter(AdapterConfig(
        rpz_mode=mode, zone_dir=str(tmp_path), zone_name="apip.test",
        reload_command="", authorized_domains=tuple(authorized),
        verify_query_server=server))


def _cand(owner="evil.operator.test", mode="SHADOW"):
    return {"adapter": "rpz", "mode": mode, "rule_id": f"owner:{owner}",
            "fragment": f"{owner} IN CNAME . ; posture",
            "selector": {"scope_type": "destination_global",
                         "destination": owner, "exact_fqdn": owner}}


# -- effective_mode algebra ----------------------------------------------------

def test_effective_mode_never_upgrades():
    """min(action, adapter): either side weaker wins; config cannot promote."""
    assert effective_mode("SHADOW", "ENFORCE") == "SHADOW"
    assert effective_mode("ENFORCE", "SHADOW") == "SHADOW"
    assert effective_mode("ENFORCE", "ENFORCE") == "ENFORCE"
    assert effective_mode("OBSERVE", "ENFORCE") == "OBSERVE"
    assert effective_mode("OFF", "ENFORCE") == "OFF"
    assert effective_mode("ENFORCE", "OFF") == "OFF"


def test_effective_mode_fails_closed_on_missing():
    """A missing/unreadable mode must degrade to OFF, never guess."""
    assert effective_mode(None, "ENFORCE") == "OFF"
    assert effective_mode("", "ENFORCE") == "OFF"
    assert effective_mode("garbage", "ENFORCE") == "OFF"


# -- RPZ: persisted mode governs the artifact -----------------------------------

def test_rpz_shadow_action_enforce_adapter_stays_shadow(tmp_path):
    """SHADOW action + ENFORCE adapter: the rule lands in the SHADOW artifact
    (rpz-passthru), never the live resolver-consumed zone."""
    ad = _rpz(tmp_path, "ENFORCE")
    r = ad.apply(_cand(mode="SHADOW"))
    assert r["ok"] is True
    assert r["receipt"]["observed"]["effective_mode"] == "SHADOW"
    live = tmp_path / "apip.test.zone"
    shadow = tmp_path / "apip.test.shadow.zone"
    assert shadow.exists() and not live.exists()
    assert "rpz-passthru" in shadow.read_text()
    # and verification stays at the shadow tier: no DNS probe, no live claim
    v = ad.verify(_cand(mode="SHADOW"))
    assert v["ok"] is True
    assert v["observed"]["effective_mode"] == "SHADOW"
    assert "dns" not in v["observed"]


def test_rpz_enforce_action_shadow_adapter_capped(tmp_path):
    """ENFORCE action + SHADOW adapter: capped to SHADOW — the rule lands in
    the shadow artifact; the live zone is never written and no DNS probe
    happens (an ENFORCE verify against a capped adapter fails closed)."""
    ad = _rpz(tmp_path, "SHADOW")
    r = ad.apply(_cand(mode="ENFORCE"))
    assert r["ok"] is True
    assert r["receipt"]["observed"]["effective_mode"] == "SHADOW"
    assert (tmp_path / "apip.test.shadow.zone").exists()
    assert not (tmp_path / "apip.test.zone").exists()
    # verify at the capped posture is file-state only; a live ENFORCE claim
    # from a SHADOW adapter would be fabrication
    v = ad.verify(_cand(mode="ENFORCE"))
    assert v["ok"] is True
    assert v["observed"]["effective_mode"] == "SHADOW"
    assert "dns" not in v["observed"]


def test_rpz_shadow_below_shadow_refused(tmp_path):
    """An OFF-posture (or mode-less) action publishes nothing — fail closed."""
    ad = _rpz(tmp_path, "ENFORCE")
    with pytest.raises(AdapterError):
        ad.apply(_cand(mode="OFF"))
    with pytest.raises(AdapterError):
        ad.apply({k: v for k, v in _cand().items() if k != "mode"})
    assert not (tmp_path / "apip.test.zone").exists()
    assert not (tmp_path / "apip.test.shadow.zone").exists()


def test_rpz_shadow_artifact_technically_incapable(tmp_path):
    """The shadow artifact never carries the live NXDOMAIN action, even when
    the adapter is ENFORCE-capable and the owner is in scope. An operator
    who mistakenly attaches the shadow zone gets rpz-passthru — BIND's
    continue-normal-resolution action — for every entry."""
    ad = _rpz(tmp_path, "ENFORCE")
    ad.apply(_cand("a.operator.test", mode="SHADOW"))
    ad.apply(_cand("b.operator.test", mode="SHADOW"))
    text = (tmp_path / "apip.test.shadow.zone").read_text()
    assert "a.operator.test IN CNAME rpz-passthru." in text
    assert "b.operator.test IN CNAME rpz-passthru." in text
    assert "CNAME ." not in text   # the live enforcement form is impossible here


def test_rpz_enforce_action_enforce_adapter_is_live(tmp_path):
    """ENFORCE + ENFORCE: the live artifact carries CNAME . — and only then
    does verify demand a resolver NXDOMAIN."""
    ad = _rpz(tmp_path, "ENFORCE", server="127.0.0.1")
    ad.apply(_cand(mode="ENFORCE"))
    text = (tmp_path / "apip.test.zone").read_text()
    assert "evil.operator.test IN CNAME ." in text
    assert "rpz-passthru" not in text
    # no resolver actually listening -> live verify fails closed (no
    # file-only fabrication)
    v = ad.verify(_cand(mode="ENFORCE"))
    assert v["ok"] is False
    assert "dns verify query failed" in v["error"]


# -- Suricata: persisted mode governs publish -----------------------------------

def _sur(tmp_path, mode):
    return SuricataAdapter(AdapterConfig(
        suricata_mode=mode, suricata_rules_dir=str(tmp_path),
        suricata_rules_file="apip", suricata_reload_command="",
        suricata_authorized_prefixes=("198.51.100.0/24",)))


def _sur_decision():
    return type("D", (), {
        "action": "firewall_deny", "disposition": "AUTO_ENFORCE",
        "id": "decision--pm", "rung": "L5", "ttl_seconds": 600,
        "selector": None})()


def test_suricata_persisted_mode_caps_publish(tmp_path):
    """Same cap semantics at the IPS export edge: OFF / mode-less refused."""
    ad = _sur(tmp_path, "SHADOW")
    fr = ad.compile(_sur_decision(), "198.51.100.30", "ipv4")[0]
    cand = {"adapter": "suricata", "mode": "SHADOW", "rule_id": fr["rule_id"],
            "fragment": fr["fragment"], "selector": fr["selector"]}
    assert ad.apply(cand)["ok"] is True
    with pytest.raises(AdapterError):
        ad.apply(dict(cand, mode="OFF"))
    with pytest.raises(AdapterError):
        ad.apply({k: v for k, v in cand.items() if k != "mode"})


def test_suricata_enforce_never_constructible(tmp_path):
    """The beta surface refuses ENFORCE entirely — no config can make this
    adapter drop traffic, so no restart can upgrade an action into an IPS
    enforcement posture."""
    with pytest.raises(AdapterError):
        _sur(tmp_path, "ENFORCE")
