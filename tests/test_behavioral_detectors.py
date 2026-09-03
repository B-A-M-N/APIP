"""Behavioral detector tests (docs/23 family coverage BD-2/3/4/5/7/8).

The deterministic streaming detectors added to close the family map are
EVIDENCE-only by design (never authority by themselves), bounded, and always
degrade to reduced authority (stop-and-mark). These tests prove:

  - each new detector emits the correct ``behavioral_*`` kind with its
    family-specific deterministic facts in ``detail``;
  - every verdict path is integer / fixed-point (no float gates);
  - state is bounded: exceeding the configured capacity marks the detector
    degraded and stops emission (never unlimited growth, never authority);
  - existing-families (BD-1 beacon / BD-6 novelty) are not regressed — the
    family map is complete (no pending families).

Radio silence (None) is the correct no-signal answer in every case.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apip.telemetry.behavioral import (  # noqa: E402
    BeaconDetector,
    FirstSeenNoveltyDetector,
    DgaDetector,
    DnsTunnelingDetector,
    FastFluxDetector,
    VolumeAnomalyDetector,
    TlsMetadataMismatchDetector,
    SyncFirstContactDetector,
    IMPLEMENTED_FAMILIES,
    PENDING_FAMILIES,
)


def _entropyish(label: str) -> str:
    """Deterministic, high-entropy-looking label (near-uniform hex)."""
    import hashlib
    return hashlib.sha256(label.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Family map completeness
# ---------------------------------------------------------------------------

EXPECTED_FAMILIES = {
    "beacon_periodicity",       # BD-1
    "dga_likelihood",           # BD-2
    "dns_tunneling",            # BD-3
    "fastflux",                 # BD-4
    "volume_anomaly",           # BD-5
    "first_seen_novelty",       # BD-6
    "tls_metadata_mismatch",    # BD-7
    "sync_first_contact",       # BD-8
}


def test_family_map_complete():
    assert frozenset(EXPECTED_FAMILIES) == IMPLEMENTED_FAMILIES
    assert PENDING_FAMILIES == frozenset()   # nothing left unimplemented


# ---------------------------------------------------------------------------
# BD-2 — DGA-like domain structure
# ---------------------------------------------------------------------------

def test_dga_high_entropy_label_emits():
    det = DgaDetector()
    d = det.observe("zq8xk2mnwv9p.evil.example", "t1", 1000)
    assert d is not None
    assert d.kind == "behavioral_dga_likelihood"
    assert d.extra["band"] == "high"
    assert d.extra["leftmost_entropy_microbits"] > 2_850_000


def test_dga_human_readable_label_stays_silent():
    det = DgaDetector()
    assert det.observe("www.example.com", "t1", 1000) is None
    assert det.observe("login.evil.example", "t2", 1001) is None


def test_dga_first_seen_only_not_repeated():
    det = DgaDetector()
    d1 = det.observe("x8kl2mnwq.evil.example", "t1", 1000)
    assert d1 is not None
    # a repeat of the SAME domain within retention is NOT a first-seen DGA
    d2 = det.observe("x8kl2mnwq.evil.example", "t2", 1001)
    assert d2 is None


def test_dga_bounded_capacity_degrades():
    det = DgaDetector(max_entries=3)
    for i in range(3):
        det.observe(f"a{i}.example", "t", 1000)
    assert det.degraded is False
    # exceeding capacity -> stop-and-mark: degraded, emits nothing
    d = det.observe("overflow-domain.example", "t", 1000)
    assert det.degraded is True
    assert d is None
    assert det.health()["suppressed_new_domains"] == 1


# ---------------------------------------------------------------------------
# BD-3 — DNS tunneling
# ---------------------------------------------------------------------------

def test_tunnel_long_high_entropy_window_emits():
    det = DnsTunnelingDetector(min_queries=5, avg_bytes_per_query=20)
    d = None
    for i in range(40):
        label = _entropyish(f"tunnel-{i}")
        d = det.observe("host-1", f"{label}.exfil.net", "TXT", "t", 1000)
    assert d is not None
    assert d.kind == "behavioral_dns_tunneling"
    assert d.extra["high_entropy_share_micros"] > 350_000
    assert d.extra["queries_in_window"] > 0


def test_tunnel_normal_dns_stays_silent():
    det = DnsTunnelingDetector(min_queries=5, avg_bytes_per_query=60)
    for i in range(40):
        det.observe("host-1", "www.corp.example", "A", "t", 1000)
    assert det.detections == 0


def test_tunnel_below_min_share_silent():
    """Mostly normal queries with occasional random labels must NOT emit."""
    det = DnsTunnelingDetector(min_queries=5, avg_bytes_per_query=20,
                               high_entropy_share=0.8)
    for i in range(40):
        q = _entropyish(f"r{i}") + ".example" if i % 20 == 0 else "www.corp.example"
        det.observe("host-2", q, "A", "t", 1000)
    assert det.detections == 0


def test_tunnel_capacity_degrades():
    det = DnsTunnelingDetector(max_clients=2)
    det.observe("c1", "www.a.example", "A", "t", 1000)
    det.observe("c2", "www.b.example", "A", "t", 1000)
    assert det.degraded is False
    assert det.observe("c3", "www.c.example", "A", "t", 1000) is None
    assert det.degraded is True


# ---------------------------------------------------------------------------
# BD-4 — fast-flux / answer churn
# ---------------------------------------------------------------------------

def test_fastflux_many_distinct_answers_emits():
    det = FastFluxDetector(min_answers_total=5)
    d = None
    for i in range(12):
        d = det.observe("flux.example", f"192.0.2.{i}", 60, "t", 1000)
    assert d is not None
    assert d.kind == "behavioral_fastflux"
    assert d.extra["distinct_answers"] >= 5


def test_fastflux_single_answer_silent():
    det = FastFluxDetector(min_answers_total=5)
    for i in range(12):
        det.observe("stable.example", "192.0.2.10", 60, "t", 1000)
    assert det.detections == 0


# ---------------------------------------------------------------------------
# BD-5 — volumetric exfiltration
# ---------------------------------------------------------------------------

def test_volume_inversion_emits():
    det = VolumeAnomalyDetector(min_bytes_out=10, min_diversity=0)
    d = det.observe("host-a", "10.0.0.9", 100, 1, "t", 0)
    assert d is not None
    assert d.kind == "behavioral_volume_anomaly"
    assert d.extra["inversion"] is True


def test_volume_below_floor_silent():
    det = VolumeAnomalyDetector(min_bytes_out=1_000_000, min_diversity=0)
    for i in range(10):
        det.observe("host-b", "10.0.0.8", 100, 1, "t", i)
    assert det.detections == 0


def test_volume_plain_talk_silent():
    det = VolumeAnomalyDetector(min_bytes_out=10, min_diversity=0)
    # balanced upload/download — no inversion, no focus
    assert det.observe("host-c", "10.0.0.7", 100, 100, "t", 0) is None


# ---------------------------------------------------------------------------
# BD-7 — TLS metadata mismatch
# ---------------------------------------------------------------------------

def test_tls_sni_not_covered_emits():
    det = TlsMetadataMismatchDetector()
    d = det.observe("c1", "192.0.2.5", "badsni.example",
                    cert_covers_sni=False, is_ip_https=False,
                    has_sni=True, ts_iso="t", epoch_s=100)
    assert d is not None
    assert d.kind == "behavioral_tls_metadata_mismatch"
    assert d.extra["mismatch"] == "sni_not_covered"


def test_tls_raw_ip_no_sni_emits():
    det = TlsMetadataMismatchDetector()
    d = det.observe("c1", "192.0.2.6", None,
                    cert_covers_sni=True, is_ip_https=True,
                    has_sni=False, ts_iso="t", epoch_s=100)
    assert d is not None
    assert d.extra["mismatch"] == "raw_ip_no_sni"


def test_tls_consistent_metadata_silent():
    det = TlsMetadataMismatchDetector()
    d = det.observe("c1", "service.example", "service.example",
                    cert_covers_sni=True, is_ip_https=False,
                    has_sni=True, ts_iso="t", epoch_s=100)
    assert d is None


# ---------------------------------------------------------------------------
# BD-8 — synchronized first-contact
# ---------------------------------------------------------------------------

def test_sync_first_contact_emits():
    det = SyncFirstContactDetector(min_hosts=3)
    d = None
    for h in ("h1", "h2", "h3"):
        d = det.observe(h, "newdst.invalid", "t", 1000)
    assert d is not None
    assert d.kind == "behavioral_sync_first_contact"
    assert d.extra["distinct_hosts"] == 3


def test_sync_under_min_hosts_silent():
    det = SyncFirstContactDetector(min_hosts=3)
    for h in ("h1", "h2"):
        det.observe(h, "rare.invalid", "t", 1000)
    assert det.detections == 0


def test_sync_single_client_repeat_silent():
    """One client repeatedly contacting a domain is NOT synchronization."""
    det = SyncFirstContactDetector(min_hosts=3)
    for i in range(5):
        det.observe("h1", "solo.invalid", "t", 1000 + i)
    assert det.detections == 0


# ---------------------------------------------------------------------------
# Determinism + no-regression on existing families
# ---------------------------------------------------------------------------

def test_detectors_are_deterministic():
    """Re-feeding the same stream yields identical emission (no RNG, no float)."""
    def feed(det):
        out = []
        for i in range(200):
            q = f"a{i}bcdefghij.example" if i % 2 else "www.example.com"
            d = det.observe(q, f"t{i}", i)
            out.append(d.extra if d else None)
        return out

    assert feed(DgaDetector()) == feed(DgaDetector())


def test_existing_beacon_and_novelty_still_work():
    """BD-1 and BD-6 (pre-existing) remain functional alongside new families."""
    b = BeaconDetector(min_events=4)
    got = [b.observe("c", "dst", f"t{i}", i * 60) for i in range(6)]
    # a regular beacon should eventually emit
    assert any(x is not None for x in got)

    nv = FirstSeenNoveltyDetector()
    assert nv.observe("h1", "brand-new.example", "t0", 0) is not None