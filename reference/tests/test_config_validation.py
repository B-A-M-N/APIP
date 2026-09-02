"""Policy semantic validation (v2.1, P1).

Impossible or unsafe policy configurations must be rejected at load with a
named problem — never discovered during an incident. Each rule in
config.validate_policy gets an explicit positive/negative case.
"""
import unittest
from apip.config import validate_policy


def _base():
    return {
        "policy_version": "test.1",
        "mode": "ENFORCE",
        "scope": "t",
        "thresholds": {
            "observe_m": 40,
            "fqdn_auto_m": 95, "fqdn_auto_s": 90,
            "ip_rate_m": 90, "ip_rate_s": 85,
            "ip_deny_m": 98, "ip_deny_s": 95,
            "rungs": {
                "L1": {"m": 85, "s": 75},
                "L2": {"m": 90, "s": 80},
                "L4": {"m": 95, "s": 90},
                "L5": {"m": 98, "s": 95},
            },
        },
        "limits": {"max_auto_ttl_seconds": 3600,
                   "nominal_rate_ceiling_per_min": 240},
        "safety": {"auto_prefix_deny": False, "auto_routing": False,
                   "allowlist_precedence": True, "no_ai_components": True},
        "behavioral": {
            "max_behavioral_m_contribution": 60,
            "corroboration": {"distinct_families_for_rate_limit": 2,
                              "distinct_families_for_deny": 3,
                              "deny_also_requires_external": True},
        },
    }


class PolicyValidationTests(unittest.TestCase):
    def test_valid_policy_has_no_problems(self):
        self.assertEqual(validate_policy(_base()), [])

    def test_auto_prefix_deny_rejected(self):
        raw = _base()
        raw["safety"]["auto_prefix_deny"] = True
        self.assertTrue(any("auto_prefix_deny" in p for p in validate_policy(raw)))

    def test_auto_routing_rejected(self):
        raw = _base()
        raw["safety"]["auto_routing"] = True
        self.assertTrue(any("auto_routing" in p for p in validate_policy(raw)))

    def test_no_ai_false_rejected(self):
        raw = _base()
        raw["safety"]["no_ai_components"] = False
        self.assertTrue(any("no_ai_components" in p for p in validate_policy(raw)))

    def test_invalid_mode_rejected(self):
        raw = _base()
        raw["mode"] = "YOLO"
        self.assertTrue(any("invalid mode" in p for p in validate_policy(raw)))

    def test_non_monotonic_floors_rejected(self):
        raw = _base()
        raw["thresholds"]["rungs"]["L4"] = {"m": 70, "s": 60}   # weaker than L2
        self.assertTrue(any("not monotonic" in p for p in validate_policy(raw)))

    def test_unknown_rung_rejected(self):
        raw = _base()
        raw["thresholds"]["rungs"]["L9"] = {"m": 99, "s": 99}
        self.assertTrue(any("unknown rung" in p for p in validate_policy(raw)))

    def test_deny_below_rate_limit_families_rejected(self):
        raw = _base()
        raw["behavioral"]["corroboration"]["distinct_families_for_deny"] = 1
        self.assertTrue(any("cannot be below" in p for p in validate_policy(raw)))

    def test_behavioral_cap_at_deny_floor_rejected(self):
        raw = _base()
        raw["behavioral"]["max_behavioral_m_contribution"] = 95
        self.assertTrue(any("below the L4 deny floor" in p for p in validate_policy(raw)))

    def test_allowlist_precedence_false_rejected(self):
        raw = _base()
        raw["safety"]["allowlist_precedence"] = False
        self.assertTrue(any("allowlist_precedence" in p for p in validate_policy(raw)))

    def test_demo_policy_passes(self):
        import tomllib
        from pathlib import Path
        demo = Path(__file__).resolve().parent.parent.parent / "examples" / "policy.toml"
        raw = tomllib.loads(demo.read_text(encoding="utf-8"))
        self.assertEqual(validate_policy(raw), [])


if __name__ == "__main__":
    unittest.main()
