"""Telemetry and behavioral detection.

The decision path is deterministic and AI-free: behavioral detections are
local EVIDENCE (facts with ``behavioral_*`` kinds) entering the ordinary
ingest + weight table. This package holds the deterministic streaming
detectors (all 8 families BD-1..BD-8) and health surfaces. Detector
degradation always reduces authority (stop-and-mark).
"""
from apip.telemetry.behavioral import (  # noqa: F401
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
from apip.telemetry.feed import LiveBehavioralFeed  # noqa: F401