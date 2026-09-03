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
        # v2.3 (audit P1-1): a VALID ENFORCE policy must declare an explicit
        # authorization boundary — enforcement is never authorize-by-default.
        "authorization": {
            "authorized_prefixes": ["203.0.113.0/24"],
            "authorized_domains": ["example.invalid"],
        },
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

    def test_componentwise_monotonicity_rejects_S_regression(self):
        """P0-5 (audit): monotonicity is COMPONENTWISE, not lexicographic.
        The old `(m, s) < (pm, ps)` tuple compare let a stronger M mask an S
        collapse: L1(85,90) -> L2(90,1) passed because 90>=85 in the first
        element. Every genuinely weaker component must reject."""
        # M increases but S collapses -> REJECT (the audit's exact case)
        raw = _base()
        raw["thresholds"]["rungs"]["L1"] = {"m": 85, "s": 90}
        raw["thresholds"]["rungs"]["L2"] = {"m": 90, "s": 1}
        self.assertTrue(any("not monotonic" in p for p in validate_policy(raw)))
        # M same, S decreases -> REJECT
        raw2 = _base()
        raw2["thresholds"]["rungs"]["L1"] = {"m": 90, "s": 85}
        raw2["thresholds"]["rungs"]["L2"] = {"m": 90, "s": 40}
        self.assertTrue(any("not monotonic" in p for p in validate_policy(raw2)))
        # both equal -> ACCEPT
        raw3 = _base()
        raw3["thresholds"]["rungs"]["L1"] = {"m": 85, "s": 80}
        raw3["thresholds"]["rungs"]["L2"] = {"m": 85, "s": 80}
        self.assertFalse(any("not monotonic" in p for p in validate_policy(raw3)))
        # both increase -> ACCEPT
        raw4 = _base()
        raw4["thresholds"]["rungs"]["L1"] = {"m": 85, "s": 80}
        raw4["thresholds"]["rungs"]["L2"] = {"m": 90, "s": 85}
        self.assertFalse(any("not monotonic" in p for p in validate_policy(raw4)))

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


class RandomizationMechanismTests(unittest.TestCase):
    """P1-7..11 (audit): a declared randomization mechanism the engine does
    not wire is a silently inert knob — fail closed at load, never let an
    operator believe a defense (challenge sampling, BD threshold dithering)
    is active when it has no effect."""

    def test_wired_mechanisms_are_accepted(self):
        raw = _base()
        raw["randomization"] = {"enabled": True, "bounds_version": "rv1",
                                "mechanisms": {
                                    "ttl_jitter": {"enabled": True, "min": 0.8, "max": 1.0},
                                    "rate_ceiling": {"enabled": True, "min": 0.5, "max": 1.0},
                                }}
        self.assertEqual(validate_policy(raw), [])

    def test_unsupported_mechanism_rejected(self):
        # challenge_sampling / threshold_dither are docs/29 aspirational
        # mechanisms the reference engine does not implement; declaring one
        # must fail closed, not silently do nothing.
        raw = _base()
        raw["randomization"] = {"enabled": True,
                                "mechanisms": {"threshold_dither": {"enabled": True}}}
        probs = validate_policy(raw)
        self.assertTrue(any("unsupported randomization mechanism" in p for p in probs))

    def test_aspirational_challenge_sampling_rejected(self):
        raw = _base()
        raw["randomization"] = {"enabled": True,
                                "mechanisms": {"challenge_sampling": {"enabled": True}}}
        probs = validate_policy(raw)
        self.assertTrue(any("unsupported randomization mechanism" in p for p in probs))

    def test_disabled_unsupported_mechanism_still_rejected(self):
        # even a disabled unwired mechanism is a ghost — it asserts the knob
        # could be turned on. Reject regardless of the enabled flag.
        raw = _base()
        raw["randomization"] = {"enabled": False,
                                "mechanisms": {"threshold_dither": {"enabled": False}}}
        probs = validate_policy(raw)
        self.assertTrue(any("unsupported randomization mechanism" in p for p in probs))


class AuthorizationBoundaryTests(unittest.TestCase):
    """v2.3 (audit P1-1/P1-2): enforcement cannot be authorize-by-default;
    authorization entries are parsed + canonicalized at load."""

    def test_enforce_without_boundary_rejected(self):
        raw = _base()
        del raw["authorization"]
        problems = validate_policy(raw)
        self.assertTrue(any("requires an explicit" in p for p in problems))

    def test_enforce_with_reference_unrestricted_rejected(self):
        raw = _base()
        raw["authorization"]["reference_unrestricted"] = True
        problems = validate_policy(raw)
        self.assertTrue(any("prohibited in ENFORCE/EMERGENCY" in p for p in problems))

    def test_emergency_without_boundary_rejected(self):
        raw = _base()
        raw["mode"] = "EMERGENCY"
        del raw["authorization"]
        problems = validate_policy(raw)
        self.assertTrue(any("requires an explicit" in p for p in problems))

    def test_shadow_reference_unrestricted_allowed(self):
        # reference scaffold, explicitly named: allowed outside enforcement
        raw = _base()
        raw["mode"] = "SHADOW"
        raw["authorization"] = {"reference_unrestricted": True}
        self.assertEqual(validate_policy(raw), [])

    def test_malformed_cidr_rejected_at_load(self):
        raw = _base()
        raw["authorization"]["authorized_prefixes"].append("not-a-cidr")
        problems = validate_policy(raw)
        self.assertTrue(any("not a valid CIDR" in p for p in problems))

    def test_bad_domain_suffix_rejected(self):
        raw = _base()
        raw["authorization"]["authorized_domains"].append("not a domain")
        problems = validate_policy(raw)
        self.assertTrue(any("valid domain suffix" in p for p in problems))

    def test_load_policy_canonicalizes_prefixes(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path
        from apip.config import load_policy
        with TemporaryDirectory() as td:
            p = Path(td) / "pol.toml"
            p.write_text(
                'policy_version = "t"\nmode = "ENFORCE"\nscope = "s"\n'
                '[authorization]\n'
                'authorized_prefixes = ["203.0.113.5/24"]\n'
                '[thresholds]\nobserve_m = 40\nfqdn_auto_m = 95\n'
                'fqdn_auto_s = 90\nip_rate_m = 90\nip_rate_s = 85\n'
                'ip_deny_m = 98\nip_deny_s = 95\n'
                '[limits]\nmax_auto_ttl_seconds = 3600\n')
            pol = load_policy(p)
            # canonical host form -> network form, without trailing host bits
            self.assertIn("203.0.113.0/24", pol.authorized_prefixes)
            self.assertFalse(pol.reference_unrestricted)


if __name__ == "__main__":
    unittest.main()
