import unittest
from apip.models import Indicator, Evidence
from apip.scoring import score, score_parts, EvidenceTable, DEFAULT_WEIGHTS
from apip.registry import SourceRegistry, SourceProfile
from datetime import datetime, timedelta, timezone

NOW = datetime(2026, 9, 1, 20, 0, 0, tzinfo=timezone.utc)

def recency(ts: str) -> str:
    if not ts:
        return "stale"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return "stale"
    return "fresh" if (NOW - dt) <= timedelta(hours=6) else "stale"

REG = SourceRegistry((
    SourceProfile("curated-a", "curated", True),
    SourceProfile("local-behavioral", "local", True),
))

def ev(kind, source="curated-a", at="2026-09-01T20:00:00Z"):
    return Evidence(kind=kind, source_id=source, source_class="x",
                    observed_at=at, independent=True)

def ind(evidence):
    return Indicator("x", "fqdn", "a.invalid", tuple({e.source_id for e in evidence}),
                     tuple(evidence))

class ScoringAuthorityTests(unittest.TestCase):
    def test_policy_table_is_sole_authority(self):
        i = ind([ev("curated_source")])   # weight (25,0,0)
        m, s_ctx, s_ip, has_ded, has_unq, _ = score(i, EvidenceTable(DEFAULT_WEIGHTS), recency, REG)
        self.assertEqual((m, s_ctx, s_ip), (25, 0, 0))
        self.assertFalse(has_ded)

    def test_unweighted_kind_contributes_zero(self):
        i = ind([ev("totally_unknown_kind")])
        m, s_ctx, s_ip, _, has_unq, reasons = score(i, EvidenceTable(DEFAULT_WEIGHTS), recency, REG)
        self.assertEqual((m, s_ctx, s_ip), (0, 0, 0))
        self.assertTrue(has_unq)

    def test_shared_penalty_routes_to_identity_only(self):
        i = ind([ev("curated_source"), ev("shared_cloud")])  # (25,0,0) + (0,0,-45)
        m, s_ctx, s_ip, _, _, _ = score(i, EvidenceTable(DEFAULT_WEIGHTS), recency, REG)
        self.assertEqual((m, s_ctx, s_ip), (25, 0, 0))  # s_ctx untouched, s_ip floored at 0

    def test_dedicated_use_detected(self):
        i = ind([ev("dedicated_use")])
        _, _, _, has_ded, _, _ = score(i, EvidenceTable(DEFAULT_WEIGHTS), recency, REG)
        self.assertTrue(has_ded)

    def test_provenance_violation(self):
        # local-only kind claimed by a curated feed: rejected
        i = ind([ev("behavioral_dga_likelihood", source="curated-a")])
        m, _, _, _, _, reasons = score(i, EvidenceTable(DEFAULT_WEIGHTS), recency, REG)
        self.assertEqual(m, 0)
        self.assertTrue(any(r.startswith("provenance_violation") for r in reasons))

    def test_stale_curated_loses_positive_m(self):
        i = ind([ev("curated_source", at="2026-08-01T00:00:00Z")])
        m, _, _, _, _, _ = score(i, EvidenceTable(DEFAULT_WEIGHTS), recency, REG)
        self.assertEqual(m, 0)

    def test_behavioral_share_reported_unclamped(self):
        e = [ev(f"behavioral_{f}", source="local-behavioral")
             for f in ("dga_likelihood", "first_seen_novelty", "beacon_periodicity")] * 3
        m, bm, _, _, _, _, _ = score_parts(ind(e), EvidenceTable(DEFAULT_WEIGHTS), recency, REG)
        self.assertGreater(bm, 100)    # unclamped share visible to cap logic
        self.assertEqual(m, bm)        # all M is behavioral here

if __name__ == "__main__":
    unittest.main()
