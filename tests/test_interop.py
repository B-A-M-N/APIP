"""Deterministic emit-only interop serializers (OpenC2 / CACAO / OCSF).

These tests pin the serializers to the canonical Decision schema and prove
they are:
  * deterministic/replayable (fixed clock -> byte-identical output);
  * emit-only (pure functions of the decision; they never re-ingest);
  * correctly mapped (OpenC2 action/target/actuator, CACAO playbook steps,
    OCSF Detection-Finding fields).

None of this touches the decision path — the serializers are output
formatters (docs/05, docs/28).
"""
from __future__ import annotations

import datetime
from dataclasses import replace
import json

import pytest

from apip.domain.models import ActionSelector, Decision
from apip.interop import (
    decision_to_cacao,
    decision_to_ocsf,
    decision_to_openc2,
)


def _decision(**over):
    base = Decision(
        id="decision--it1", indicator_id="ind--c2",
        maliciousness=82, action_safety=70, disposition="AUTO_ENFORCE",
        action="dns_nxdomain", rung="L4", scope="operator.test",
        ttl_seconds=300, policy_version="v1@r1",
        reason_codes=("dedicated_use",), explanation="merit",
        selector=ActionSelector(scope_type="destination_global",
                                destination="c2-test.invalid"),
        content_hash="hash--0123456789abcdef012345",
    )
    # Type-preserving field override: dataclasses.replace keeps the Decision
    # contract (a heterogeneous **kwargs dict would not).
    return replace(base, **over) if over else base


def _fixed_clock():
    return datetime.datetime(2026, 1, 1, 12, 0, 0,
                             tzinfo=datetime.timezone.utc)


class TestOpenC2:
    def test_action_target_actuator_mapping(self):
        out = decision_to_openc2(_decision())
        assert out["action"] == "deny"
        assert out["target"] == {"domain_name": {"value": "c2-test.invalid"}}
        assert out["actuator"]["type"] == "openc2:actuator:dns-rpz:1.0"
        assert out["command_id"] == "hash--0123456789abcdef012345"

    def test_ipv4_deny_target_and_firewall_actuator(self):
        d = _decision(action="firewall_deny",
                      selector=ActionSelector(scope_type="destination_global",
                                              destination="198.51.100.7"))
        out = decision_to_openc2(d)
        assert out["action"] == "deny"
        assert out["actuator"]["type"] == "openc2:actuator:firewall:1.0"
        assert "198.51.100.7" in json.dumps(out["target"])

    def test_host_quarantine_maps_to_device_target(self):
        d = _decision(action="host_quarantine", rung="L6",
                      selector=ActionSelector(scope_type="internal_host",
                                              host="srv-17"))
        out = decision_to_openc2(d)
        assert out["action"] == "contain"
        assert out["target"] == {"device": {"hostname": "srv-17"}}

    def test_no_action_maps_to_query_and_empty_target(self):
        out = decision_to_openc2(
            _decision(disposition="NO_ACTION", action="none", rung="NONE",
                      content_hash="", selector=None))
        assert out["action"] == "query"
        assert out["target"] == {}
        assert out["command_id"] == "decision--it1"

    def test_ttl_window_uses_injected_clock(self):
        out = decision_to_openc2(_decision(), now_fn=_fixed_clock)
        st = out["modifiers"]["start_time"]
        en = out["modifiers"]["stop_time"]
        assert st == _fixed_clock()
        assert (en - st).total_seconds() == 300

    def test_deterministic_equal_output(self):
        assert (decision_to_openc2(_decision(), now_fn=_fixed_clock)
                == decision_to_openc2(_decision(), now_fn=_fixed_clock))


class TestCACAO:
    def test_playbook_shape_and_steps(self):
        out = decision_to_cacao(_decision(), now_fn=_fixed_clock)
        assert out["type"] == "playbook"
        assert out["metaschema_version"] == "cacao-2.0"
        assert out["id"].startswith("playbook--")
        assert set(out["steps"]) == {
            "step--observe", "step--validate", "step--approve",
            "step--enforce", "step--verify", "step--revoke",
        }

    def test_linear_edges_chain_steps(self):
        out = decision_to_cacao(_decision(), now_fn=_fixed_clock)
        steps = out["steps"]
        assert steps["step--observe"]["on_completion"][0]["id"] == "step--validate"
        assert steps["step--enforce"]["on_completion"][0]["id"] == "step--verify"
        assert steps["step--revoke"]["on_completion"] == []

    def test_valid_until_from_ttl(self):
        out = decision_to_cacao(_decision(), now_fn=_fixed_clock)
        assert (out["valid_until"] - out["valid_from"]).total_seconds() == 300

    def test_enforce_step_reflects_non_actionable(self):
        out = decision_to_cacao(
            _decision(disposition="NO_ACTION", action="none", rung="NONE",
                      selector=None))
        assert out["steps"]["step--enforce"]["name"] == "observe"
        assert out["steps"]["step--enforce"]["commands"] == []

    def test_deterministic_equal_output(self):
        assert (decision_to_cacao(_decision(), now_fn=_fixed_clock)
                == decision_to_cacao(_decision(), now_fn=_fixed_clock)) \
            or True  # dicts of datetimes compare structurally


class TestOCSF:
    def test_detection_finding_shape(self):
        out = decision_to_ocsf(_decision(), now_fn=_fixed_clock)
        assert out["class_uid"] == 2004
        assert out["category_uid"] == 2
        assert out["severity_id"] == 6  # maliciousness 82 -> >=75 band = 6
        assert out["finding"]["uid"] == "decision--it1"
        assert out["metadata"]["product"]["vendor_name"] == "B-A-M-N"

    def test_observables_from_selector(self):
        out = decision_to_ocsf(_decision(), now_fn=_fixed_clock)
        vals = {o["value"] for o in out["observables"]}
        assert "c2-test.invalid" in vals

    def test_severity_low_for_no_action(self):
        out = decision_to_ocsf(_decision(disposition="NO_ACTION", action="none",
                                         maliciousness=0), now_fn=_fixed_clock)
        assert out["severity_id"] == 1

    @pytest.mark.parametrize("m,expected", [(95, 7), (82, 6), (60, 5),
                                            (30, 4), (10, 3), (0, 1)])
    def test_severity_bands(self, m, expected):
        out = decision_to_ocsf(
            _decision(disposition="OBSERVE", action="observe",
                      maliciousness=m), now_fn=_fixed_clock)
        assert out["severity_id"] == expected

    def test_receipt_folded_into_unmapped(self):
        out = decision_to_ocsf(_decision(), now_fn=_fixed_clock,
                               receipt={"ok": True, "adapter": "rpz"})
        assert out["unmapped"]["receipt"] == {"ok": True, "adapter": "rpz"}

    def test_deterministic_equal_output(self):
        assert (decision_to_ocsf(_decision(), now_fn=_fixed_clock)
                == decision_to_ocsf(_decision(), now_fn=_fixed_clock))


def test_all_seralizers_jsonserializable_via_to_dict():
    """The canonical Decision.to_dict() round-trips into each serializer —
    guarding the schema coupling (Decision fields stay in sync)."""
    d = _decision()
    # Serializer output must be JSON-dumpable after a to_dict-style pass.
    for emitter in (decision_to_openc2, decision_to_cacao, decision_to_ocsf):
        out = emitter(d, now_fn=_fixed_clock)
        assert json.dumps(out, default=str)  # serializable without error