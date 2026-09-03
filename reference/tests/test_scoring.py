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
        self.assertFalse(has_ded)  # audit P0-3: not server-certified -> no dedicated flag

    def test_dedicated_use_requires_server_certification(self):
        # P0-3: a feed assertion of dedicated_use contributes nothing unless
        # the server derived it (governed infrastructure registry). With the
        # kind certified, it contributes and sets has_dedicated.
        i = ind([ev("dedicated_use"), ev("curated_source")])
        m0, _, _, _, has0, _, reasons0 = score_parts(
            i, EvidenceTable(DEFAULT_WEIGHTS), recency, REG)
        m1, _, _, _, has1, _, reasons1 = score_parts(
            i, EvidenceTable(DEFAULT_WEIGHTS), recency, REG,
            server_derived_kinds=frozenset({"dedicated_use"}))
        # uncertified: zeroed, flagged, no dedicated
        self.assertEqual(m0, 25)  # only curated_source contributes
        self.assertFalse(has0)
        self.assertTrue(any(r.startswith("control_plane_claim_unverified:dedicated_use")
                            for r in reasons0))
        # certified: dedicated contributes + sets the flag
        self.assertEqual(m1, 25 + 0)  # dedicated_use has m=0; S changes
        self.assertTrue(has1)
        self.assertFalse(any(r.startswith("control_plane_claim_unverified") for r in reasons1))

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
        # v2.2: duplicate records from one source dedup, so the unclamped
        # share is built from REPEATED SIGHTINGS — same kinds, distinct
        # observation times (docs/04 'repeated recent sightings'), all
        # inside the freshness window.
        e = []
        for rep in range(3):
            for f in ("dga_likelihood", "first_seen_novelty", "beacon_periodicity"):
                e.append(ev(f"behavioral_{f}", source="local-behavioral",
                            at=f"2026-09-01T19:{rep * 10:02d}:00Z"))
        m, bm, _, _, _, _, _ = score_parts(ind(e), EvidenceTable(DEFAULT_WEIGHTS), recency, REG)
        self.assertGreater(bm, 100)    # unclamped share visible to cap logic
        self.assertEqual(m, bm)        # all M is behavioral here

    def test_duplicate_records_dedup(self):
        # v2.2 regression: N copies of one record scored N times and
        # inflated M from 25 to 100 (independent-audit finding 3).
        from copy import copy
        e = [ev("curated_source")] * 4
        m, _, _, _, _, _ = score(ind(e), EvidenceTable(DEFAULT_WEIGHTS), recency, REG)
        self.assertEqual(m, 25)        # one observation, scored once

if __name__ == "__main__":
    unittest.main()
