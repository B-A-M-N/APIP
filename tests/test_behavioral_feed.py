"""Live behavioral feed tests.

The feed wires the bounded streaming detectors (BD-1..BD-8) into a live
evidence frontier. These tests prove:

  - typed intake routes observations to the right detector(s) and aggregates
    the emitted ``Detection`` records;
  - attach-only discipline: a detection is folded onto an indicator that
    ALREADY exists; a detection for a domain nobody ingested stays dormant
    (no authority is invented from thin air);
  - enabled-family gating: only implemented families detect; requested-but-
    pending families are surfaced honestly on health (never silent);
  - P1-23 epoch agreement: an ISO/epoch mismatch is rejected, never folded;
  - ``health()`` aggregates every enabled detector (the newest family,
    sync-first-contact, previously lacked it — now all 8 expose ``health``).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apip.telemetry.behavioral import (  # noqa: E402
    DGA_KIND, TUNNEL_KIND, FASTFLUX_KIND, VOLUME_KIND, TLS_KIND,
    SYNC_KIND, NOVELTY_KIND, BEACON_KIND, IMPLEMENTED_FAMILIES,
)
from apip.telemetry.feed import LiveBehavioralFeed  # noqa: E402


def _entropyish(label: str) -> str:
    import hashlib
    return hashlib.sha256(label.encode()).hexdigest()


def _epoch(iso: str) -> int:
    from datetime import datetime, timezone
    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())


def _iso(epoch: int) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


T0 = "2026-09-03T05:00:00Z"
E0 = _epoch(T0)


def test_dns_query_feeds_dga_and_novelty_and_sync():
    feed = LiveBehavioralFeed()
    domain = f"{_entropyish('c2a')}.invalid"
    hits = feed.on_dns_query(src="host-1", domain=domain, qtype="A",
                             ts_iso=T0, epoch_s=E0)
    kinds = {d.kind for d in hits}
    assert DGA_KIND in kinds          # high-entropy leftmost label
    assert NOVELTY_KIND in kinds      # first contact of a fresh dst
    assert SYNC_KIND not in kinds     # one host is under the sync floor


def test_dns_answer_feeds_fastflux_and_attaches_only_to_known_indicator():
    feed = LiveBehavioralFeed()
    domain = "flux.invalid"
    for i in range(9):
        # 9 distinct A answers => distinct-set (9) > max(5) and total >= 8
        feed.on_dns_answer(domain=domain, answer=f"198.51.{100 + i}.7",
                           ttl=60, ts_iso=T0, epoch_s=E0)
    # every answer folded; the domain now has >= max_distinct_answers churn,
    # but fast-flux needs >= min_answers_total observations
    # attach to an indicator for THAT domain -> evidence surfaces
    ev = feed.attach_to_indicators({"flux.invalid": "ind--flux"})
    # NOTE: fast-flux min_total default is 8, so 9 answers clear it.
    assert any(e["kind"] == FASTFLUX_KIND for e in ev)
    # audit #19: the record carries the RESOLVED indicator identity
    rec = next(e for e in ev if e["kind"] == FASTFLUX_KIND)
    assert rec["indicator_id"] == "ind--flux"
    assert rec["target"] == "flux.invalid"


def test_beacon_detector_emits_through_live_feed():
    """Audit #18: the beacon detector is actually FED by the live feed —
    a periodic (src, dst) DNS contact stream drives BD-1 to emit."""
    feed = LiveBehavioralFeed()
    domain = "c2-beacon.invalid"
    # exact 60s periodicity, 8 contacts (>= min_events default 6)
    for i in range(8):
        ts_iso = _iso(E0 + i * 60)
        feed.on_dns_query(src="workstation-7", domain=domain, qtype="A",
                          ts_iso=ts_iso, epoch_s=E0 + i * 60)
    ev = feed.attach_to_indicators({domain: "ind--beacon"})
    beacon = [e for e in ev if e["kind"] == BEACON_KIND]
    assert beacon, "beacon detector never emitted through the live feed"
    assert beacon[0]["indicator_id"] == "ind--beacon"
    assert beacon[0]["detail"]["median_gap_s"] == 60


def test_attach_only_never_invents_authority_for_unknown_domain():
    feed = LiveBehavioralFeed()
    domain = f"{_entropyish('orphan')}.invalid"
    feed.on_dns_query(src="host-1", domain=domain, qtype="A",
                      ts_iso=T0, epoch_s=E0)
    # the detector fired (DGA + novelty), but no indicator exists for it:
    # attach_to_indicators({}) must attach NOTHING — no fabricated evidence.
    ev = feed.attach_to_indicators({domain: None} and {})
    assert ev == []
    # audit #20: the detection is not DISCARDED either — it waits, dormant
    assert feed.pending_unknown >= 1
    # once the indicator is ingested, a later attach picks it up
    ev2 = feed.attach_to_indicators({domain: "ind--late"})
    assert ev2 and all(e["indicator_id"] == "ind--late" for e in ev2)
    assert feed.pending_unknown == 0


def test_epoch_mismatch_is_rejected_not_folded():
    feed = LiveBehavioralFeed()
    hits = feed.on_dns_query(src="h", domain="ok.invalid", qtype="A",
                             ts_iso=T0, epoch_s=E0 + 5000)   # 83 min off
    assert hits == []
    assert feed.rejected_epoch_mismatch == 1


def test_volume_and_tls_intake_route():
    feed = LiveBehavioralFeed()
    # volume exfil: high out, low in -> inversion
    feed.on_flow(host="srv-1", dst="exfil.invalid", out_bytes=99_999_999,
                 in_bytes=10, ts_iso=T0, epoch_s=E0)
    ev = feed.attach_to_indicators({"exfil.invalid": "ind--exfil"})
    assert any(e["kind"] == VOLUME_KIND for e in ev)

    # tls mismatch: SNI not covered by cert
    feed2 = LiveBehavioralFeed()
    feed2.on_tls(client="c-1", dst="tls.invalid", sni="legit.invalid",
                 cert_covers_sni=False, is_ip_https=True, has_sni=True,
                 ts_iso=T0, epoch_s=E0)
    ev2 = feed2.attach_to_indicators({"tls.invalid": "ind--tls"})
    assert any(e["kind"] == TLS_KIND for e in ev2)


def test_enabled_family_gating_and_health():
    # only dga_likelihood enabled; everything else must be inert
    feed = LiveBehavioralFeed(enabled_families=("dga_likelihood",))
    assert feed.beacon is None and feed.tunnel is None and feed.sync is None
    domain = f"{_entropyish('c2b')}.invalid"
    hits = feed.on_dns_query(src="h", domain=domain, qtype="A",
                             ts_iso=T0, epoch_s=E0)
    assert any(d.kind == DGA_KIND for d in hits)   # enabled: detects
    assert not any(d.kind == NOVELTY_KIND for d in hits)   # disabled: silent
    # health reports the enabled set + no pending families requested
    h = feed.health()
    assert h["enabled_families"] == ["dga_likelihood"]
    assert h["pending_families_requested"] == []
    # every implemented family is health-reportable (sync now included)
    names = {d["name"] for d in feed.health()["detectors"]}
    assert {"dga_likelihood"} == names


def test_all_eight_detectors_expose_consistent_health():
    feed = LiveBehavioralFeed()   # all implemented families enabled
    names = {d["name"] for d in feed.health()["detectors"]}
    assert names == set(IMPLEMENTED_FAMILIES)
    # mirror-symmetry: the newest family reports the same health keys
    sync_health = next(d for d in feed.health()["detectors"]
                       if d["name"] == "sync_first_contact")
    assert {"name", "degraded", "tracked_destinations", "detections",
            "suppressed_new_dsts"} <= set(sync_health)

def test_retention_queue_is_bounded_and_counts_drops():
    """Audit #21: the feed's own output queue is bounded — a blocked
    persistence path degrades coverage (drops OLDEST, counted) instead of
    growing without bound."""
    feed = LiveBehavioralFeed(max_retained_detections=4)
    for i in range(10):
        feed.on_flow(host="h", dst=f"v{i}.invalid", out_bytes=99_999_999,
                     in_bytes=10, ts_iso=T0, epoch_s=E0)
    assert len(feed._detections) == 4          # hard cap honored
    assert feed.dropped_detections == 6        # oldest dropped, counted
    assert feed.detections_emitted == 10
    # drain: exactly the 4 NEWEST survive
    got = feed._drain_pending_matches({})
    assert [d.dst for d in got] == [f"v{i}.invalid" for i in range(6, 10)]


def test_pending_cache_ttls_out_dormant_detections():
    """Audit #20: dormancy is bounded — a detection waiting past the TTL
    expires (counted) rather than lingering forever."""
    from apip.telemetry.behavioral import _epoch_of_iso
    feed = LiveBehavioralFeed(pending_ttl_s=60)
    domain = f"{_entropyish('ttl')}.invalid"
    feed.on_dns_query(src="h", domain=domain, qtype="A",
                      ts_iso=T0, epoch_s=E0)
    ev = feed.attach_to_indicators({}, now_epoch=1_000_000)
    assert ev == [] and feed.pending_unknown == 1
    # far past the TTL: the dormant detection expires
    ev2 = feed.attach_to_indicators({}, now_epoch=1_000_000 + 3600)
    assert ev2 == []
    assert feed.pending_unknown == 0
    assert feed.pending_expired == 2   # DGA + novelty detections, both parked
    # and the indicator arriving late finds nothing — TTL honored
    assert feed.attach_to_indicators({domain: "ind--x"}) == []
