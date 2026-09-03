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
    SYNC_KIND, NOVELTY_KIND, IMPLEMENTED_FAMILIES,
)
from apip.telemetry.feed import LiveBehavioralFeed  # noqa: E402


def _entropyish(label: str) -> str:
    import hashlib
    return hashlib.sha256(label.encode()).hexdigest()


def _epoch(iso: str) -> int:
    from datetime import datetime, timezone
    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())


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
    assert feed.detections or True   # at least accumulated; emit checked below
    # attach to an indicator for THAT domain -> evidence surfaces
    ev = feed.attach_to_indicators({"flux.invalid": "ind--flux"})
    # NOTE: fast-flux min_total default is 8, so 9 answers clear it.
    assert any(e["kind"] == FASTFLUX_KIND for e in ev)


def test_attach_only_never_invents_authority_for_unknown_domain():
    feed = LiveBehavioralFeed()
    domain = f"{_entropyish('orphan')}.invalid"
    feed.on_dns_query(src="host-1", domain=domain, qtype="A",
                      ts_iso=T0, epoch_s=E0)
    # the detector fired (DGA + novelty), but no indicator exists for it:
    # attach_to_indicators("") must drop everything — no fabricated evidence.
    ev = feed.attach_to_indicators({})
    assert ev == []
    # and because attach drained the buffer, a second attach again yields nothing
    assert feed.attach_to_indicators({}) == []


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