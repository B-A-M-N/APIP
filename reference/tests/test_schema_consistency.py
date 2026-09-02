"""Cross-schema consistency (v2.1 drift guard, P1).

The behavioral family enum appears in three places — the behavior-event
schema, the policy schema, and the OpenAPI spec. All three must list the
same set, or a detector family becomes silently unrepresentable in one
surface while being valid in another (the sync_first_contact drift class).
"""
import json
import re
import unittest
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent.parent

# Canonical family list: docs/23 BD-1..BD-8.
CANONICAL_FAMILIES = {
    "beacon_periodicity", "dga_likelihood", "dns_tunneling", "fastflux",
    "volume_anomaly", "first_seen_novelty", "tls_metadata_mismatch",
    "sync_first_contact",
}


def _read(*p):
    return PKG.joinpath(*p).read_text(encoding="utf-8")


class FamilyEnumConsistencyTests(unittest.TestCase):
    def test_behavior_event_schema_enum(self):
        s = json.loads(_read("schemas", "behavior_event.schema.json"))
        text = json.dumps(s)
        families = {f for f in CANONICAL_FAMILIES if f in text}
        self.assertEqual(families, CANONICAL_FAMILIES,
                         "behavior_event.schema.json family enum drift")

    def test_policy_schema_enum(self):
        s = json.loads(_read("schemas", "policy.schema.json"))
        enum = s["properties"]["behavioral"]["properties"]["enabled_families"]["items"]["enum"]
        self.assertEqual(set(enum), CANONICAL_FAMILIES)

    def test_openapi_enum(self):
        text = _read("api", "openapi.yaml")
        m = re.search(r"family: \{type: string, enum: \[([^\]]+)\]\}", text)
        self.assertIsNotNone(m, "openapi BehaviorEvent.family enum not found")
        families = {f.strip() for f in m.group(1).split(",")}
        self.assertEqual(families, CANONICAL_FAMILIES)

    def test_reference_weights_cover_every_local_only_family(self):
        # every canonical family must have a server-side evidence weight for
        # the local source class — a family without a weight can never
        # contribute and is dead configuration.
        import sys
        sys.path.insert(0, str(PKG / "reference" / "src"))
        from apip.scoring import DEFAULT_WEIGHTS, LOCAL_ONLY_KINDS
        for f in CANONICAL_FAMILIES:
            kind = f"behavioral_{f}"
            self.assertIn(kind, LOCAL_ONLY_KINDS, f"{kind} missing from LOCAL_ONLY_KINDS")
            self.assertIn(("local", kind), DEFAULT_WEIGHTS,
                          f"no weight entry for ('local', '{kind}')")


class EvidenceKindCoverageTests(unittest.TestCase):
    """Every kind the reference example data uses must be scored or be a
    recognized infra/dedicated-use marker — never silently zero."""

    def test_example_kinds_are_weighted(self):
        import sys
        sys.path.insert(0, str(PKG / "reference" / "src"))
        from apip.scoring import DEFAULT_WEIGHTS, EvidenceTable
        table = EvidenceTable(DEFAULT_WEIGHTS)
        inds = json.loads(_read("examples", "indicators.json"))
        for i in inds:
            for e in i["evidence"]:
                kind = e["kind"]
                self.assertTrue(
                    table.is_weighted("curated", kind) or table.is_weighted("local", kind)
                    or table.is_weighted("any", kind),
                    f"example indicator {i['id']} uses unweighted kind '{kind}'")


if __name__ == "__main__":
    unittest.main()
