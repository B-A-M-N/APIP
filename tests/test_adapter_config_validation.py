"""Adapter artifact-boundary config validation (review P1 #37).

The adapter config is an artifact boundary: a hostile or careless value in a
config FILE must not become code execution or an escape from the intended
publish location. These tests pin:

  - `zone_dir`/`suricata_rules_dir` path traversal is refused at
    construction (never discovered at first apply);
  - `zone_name` must be a safe canonical DNS name;
  - `suricata_rules_file` must be a bare filename (basename only);
  - `verify_query_port` must be in 1..65535 and `verify_timeout_s` positive;
  - `reload_command` has two accepted forms: a JSON array string executed
    WITHOUT a shell (argv), and any other string executed via the shell as
    explicitly trusted operator code — the argv form must actually run the
    named program without shell interpretation.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apip.adapters.base import AdapterError, validate_adapter_config  # noqa: E402
from apip.adapters.rpz import RpzAdapter  # noqa: E402
from apip.adapters.suricata import SuricataAdapter  # noqa: E402
from apip.config.service import AdapterConfig  # noqa: E402


def _rpz(tmp_path: Path, **over) -> RpzAdapter:
    base = dict(rpz_mode="SHADOW",
                zone_dir=str(tmp_path / "rpz"),
                authorized_domains=("operator.test",))
    base.update(over)
    return RpzAdapter(AdapterConfig(**base))


def _sur(tmp_path: Path, **over) -> SuricataAdapter:
    base = dict(
        suricata_mode="SHADOW",
        suricata_rules_dir=str(tmp_path / "suri"),
        suricata_rules_file="apip.rules",
        suricata_authorized_prefixes=("198.51.100.0/24",),
    )
    base.update(over)
    return SuricataAdapter(AdapterConfig(**base))


def _candidate(fqdn: str = "bad.operator.test") -> dict:
    return {
        "action_id": "action--cfg",
        "decision_id": "decision--cfg",
        "mode": "SHADOW",
        "action_type": "dns_nxdomain",
        "selector": {"fqdn": fqdn},
        "ttl_seconds": 600,
    }


# --------------------------------------------------------------------------- #
# validation helper — shared boundary checks
# --------------------------------------------------------------------------- #

def test_zone_dir_traversal_is_refused(tmp_path):
    cfg = AdapterConfig(rpz_mode="SHADOW", zone_dir=str(tmp_path / ".." / "rpz"))
    problems = validate_adapter_config(cfg)
    assert any("zone_dir" in p and "traversal" in p for p in problems)


def test_rules_dir_traversal_is_refused(tmp_path):
    cfg = AdapterConfig(suricata_rules_dir=str(tmp_path / ".." / "suri"))
    problems = validate_adapter_config(cfg)
    assert any("suricata_rules_dir" in p and "traversal" in p for p in problems)


def test_unsafe_zone_names_are_refused():
    for bad in ("..", "a..b", "-lead.example", "trail-.example",
                "under_score.example", "sp ace.example", "x" * 254 + ".test"):
        cfg = AdapterConfig(zone_name=bad)
        problems = validate_adapter_config(cfg)
        assert any("zone_name" in p for p in problems), bad


def test_safe_zone_names_pass():
    assert validate_adapter_config(
        AdapterConfig(zone_name="apip.shadow.invalid")) == []
    assert validate_adapter_config(
        AdapterConfig(zone_name="apip.shadow.invalid.")) == []


def test_rules_file_must_be_a_bare_filename():
    for bad in ("../apip.rules", "sub/dir/apip.rules", "/etc/apip.rules",
                ".."):
        problems = validate_adapter_config(AdapterConfig(suricata_rules_file=bad))
        assert any("suricata_rules_file" in p for p in problems), bad
    assert validate_adapter_config(
        AdapterConfig(suricata_rules_file="apip.rules")) == []


def test_port_range_and_positive_timeout():
    problems = validate_adapter_config(AdapterConfig(verify_query_port=0))
    assert any("verify_query_port" in p for p in problems)
    problems = validate_adapter_config(AdapterConfig(verify_query_port=70000))
    assert any("verify_query_port" in p for p in problems)
    problems = validate_adapter_config(AdapterConfig(verify_timeout_s=0))
    assert any("verify_timeout_s" in p for p in problems)


# --------------------------------------------------------------------------- #
# construction-time enforcement
# --------------------------------------------------------------------------- #

def test_rpz_adapter_refuses_traversal_config_at_construction(tmp_path):
    with pytest.raises(AdapterError, match="traversal"):
        _rpz(tmp_path, zone_dir=str(tmp_path / ".." / "rpz"))


def test_rpz_adapter_refuses_unsafe_zone_name(tmp_path):
    with pytest.raises(AdapterError, match="zone_name"):
        _rpz(tmp_path, zone_name="bad zone..name")


def test_suricata_adapter_refuses_path_rules_file(tmp_path):
    with pytest.raises(AdapterError, match="suricata_rules_file"):
        _sur(tmp_path, suricata_rules_file="../escape.rules")


def test_suricata_validation_ignores_rpz_only_fields(tmp_path):
    # an RPZ zone_name problem must not fail Suricata construction — each
    # adapter applies only the checks that touch its own artifacts
    adapter = _sur(tmp_path, zone_name="not a dns name")
    assert adapter is not None


# --------------------------------------------------------------------------- #
# reload command: argv (no shell) vs documented trusted-operator shell
# --------------------------------------------------------------------------- #

def test_reload_command_argv_form_runs_without_shell(tmp_path):
    (tmp_path / "marker").write_text("")
    # argv form: a shell metacharacter in an argument must NOT be
    # interpreted by a shell — it reaches the program verbatim.
    cfg = _rpz(tmp_path).config
    cfg = AdapterConfig(**{**cfg.__dict__,
                           "reload_command": json.dumps(
                               ["touch", str(tmp_path / "a;b`id`")])})
    adapter = RpzAdapter(cfg)
    result = adapter._reload()
    assert result["reloaded"] is True
    assert (tmp_path / "a;b`id`").exists()      # verbatim filename
    assert not (tmp_path / "b`id`").exists()    # never split by the shell


def test_reload_command_shell_form_is_trusted_operator_code(tmp_path):
    # non-JSON form runs via the shell — this is documented trusted operator
    # configuration, and this test only pins that it still works for a
    # benign command.
    cfg = _rpz(tmp_path).config
    cfg = AdapterConfig(**{**cfg.__dict__,
                           "reload_command": "true"})
    adapter = RpzAdapter(cfg)
    assert adapter._reload()["reloaded"] is True


def test_reload_command_malformed_argv_is_refused(tmp_path):
    cfg = _rpz(tmp_path).config
    cfg = AdapterConfig(**{**cfg.__dict__,
                           "reload_command": '["not-an-argv"'})
    adapter = RpzAdapter(cfg)
    with pytest.raises(AdapterError, match="argv form is invalid"):
        adapter._reload()


def test_reload_command_argv_rejects_non_string_elements(tmp_path):
    cfg = _rpz(tmp_path).config
    cfg = AdapterConfig(**{**cfg.__dict__,
                           "reload_command": '["touch", 42]'})
    adapter = RpzAdapter(cfg)
    with pytest.raises(AdapterError, match="argv form is invalid"):
        adapter._reload()


# --------------------------------------------------------------------------- #
# adapters still construct with the shipped defaults
# --------------------------------------------------------------------------- #

def test_default_configs_construct_cleanly(tmp_path):
    cfg = AdapterConfig(zone_dir=str(tmp_path / "z"),
                        suricata_rules_dir=str(tmp_path / "s"))
    assert validate_adapter_config(cfg) == []
    adapter = _sur(tmp_path)
    assert adapter.config.suricata_rules_file == "apip.rules"


def test_timeout_enforced_on_reload(tmp_path):
    # a hanging argv command must not wedge the controller: subprocess
    # timeout still applies (existing behavior preserved for argv form)
    cfg = _rpz(tmp_path).config
    script = tmp_path / "hang.sh"
    script.write_text("#!/bin/sh\nsleep 30\n")
    script.chmod(0o755)
    cfg = AdapterConfig(**{**cfg.__dict__,
                           "reload_command": json.dumps([str(script)])})
    adapter = RpzAdapter(cfg)
    with pytest.raises(subprocess.TimeoutExpired):
        adapter._reload()
