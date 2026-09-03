"""Live behavioral detection feed — deterministic, AI-free, stdlib-only.

This is the wiring that turns the bounded streaming detectors
(``apip.telemetry.behavioral``, all BD-1..BD-8) into a *live* evidence
frontier: it owns the detector instances, exposes typed intake methods, and
aggregates the emitted ``Detection`` records so a caller can fold them into
the evidence ledger.

Security invariants carried over from the detector layer and the decision
path (docs/28):

  - authorities, never a decision: a detection is just a ``behavioral_*``
    fact (class ``local``). This feed never scores and never invents
    authority — see ``attach_to_indicators`` below, which folds a detection
    onto an indicator that ALREADY exists, so a domain nobody ever ingested
    stays dormant (no new authority injected from thin air);
  - bounded: the feed carries the detectors' resource envelopes (max keys /
    shedding); overflow degrades a detector (stop-and-mark), which only
    REDUCES detections, never grows them;
  - deterministic: integer epoch math, fixed entropy, no wall-clock in a
    verdict; same observation stream -> same evidence stream;
  - single source of troth for recency: ``observed_at`` is the trigger
    instant (last contact), never window birth.

Intake shape: each method takes a ``ts_iso`` (ISO-8601) and ``epoch_s``
(integer unix seconds) that MUST agree within ``EPOCH_TS_TOLERANCE_S`` or the
event is rejected (P1-23) — never folded.
"""
from __future__ import annotations

from apip.telemetry.behavioral import (
    BeaconDetector,
    Detection,
    DgaDetector,
    DnsTunnelingDetector,
    FastFluxDetector,
    FirstSeenNoveltyDetector,
    SyncFirstContactDetector,
    TlsMetadataMismatchDetector,
    VolumeAnomalyDetector,
    IMPLEMENTED_FAMILIES,
)


class LiveBehavioralFeed:
    """Own the enabled detector instances and route typed observations.

    ``enabled_families`` is the operator's policy gate: only implemented
    families actually detect (the others are recorded on ``pending`` so the
    run says so honestly).
    """

    def __init__(self, enabled_families: tuple[str, ...] | None = None):
        enabled = set(enabled_families) if enabled_families is not None \
            else set(IMPLEMENTED_FAMILIES)
        self.pending = sorted(enabled - IMPLEMENTED_FAMILIES)

        self.beacon = BeaconDetector(enabled_families=enabled_families) \
            if "beacon_periodicity" in enabled else None
        self.novelty = FirstSeenNoveltyDetector() \
            if "first_seen_novelty" in enabled else None
        self.dga = DgaDetector() if "dga_likelihood" in enabled else None
        self.tunnel = DnsTunnelingDetector() if "dns_tunneling" in enabled else None
        self.fastflux = FastFluxDetector() if "fastflux" in enabled else None
        self.volume = VolumeAnomalyDetector() if "volume_anomaly" in enabled else None
        self.tls = TlsMetadataMismatchDetector() \
            if "tls_metadata_mismatch" in enabled else None
        self.sync = SyncFirstContactDetector() \
            if "sync_first_contact" in enabled else None

        self.detections: list[Detection] = []
        self.rejected_epoch_mismatch = 0

    # -- typed intake ---------------------------------------------------------

    def _check_epoch(self, ts_iso: str, epoch_s: int) -> bool:
        """Reject when ISO and epoch disagree beyond tolerance (P1-23)."""
        from apip.telemetry.behavioral import _epoch_of_iso, EPOCH_TS_TOLERANCE_S
        iso_epoch = _epoch_of_iso(ts_iso)
        if iso_epoch is not None and abs(iso_epoch - epoch_s) > EPOCH_TS_TOLERANCE_S:
            self.rejected_epoch_mismatch += 1
            return False
        return True

    def on_dns_query(self, src: str, domain: str, qtype: str | None,
                     ts_iso: str, epoch_s: int) -> list[Detection]:
        """A DNS query for a domain. Feeds DGA + tunnel + novelty + sync;
        the first occurrence drives per-domain structure detectors."""
        if not self._check_epoch(ts_iso, epoch_s):
            return []
        out: list[Detection] = []
        for d in (self.dga.observe(domain, ts_iso, epoch_s, src=src)
                  if self.dga else None,
                  self.tunnel.observe(src, domain, qtype, ts_iso, epoch_s)
                  if self.tunnel else None,
                  self.novelty.observe(src, domain, ts_iso, epoch_s)
                  if self.novelty else None,
                  self.sync.observe(src, domain, ts_iso, epoch_s)
                  if self.sync else None):
            if d is not None:
                out.append(d)
        self.detections.extend(out)
        return out

    def on_dns_answer(self, domain: str, answer: str, ttl: int,
                      ts_iso: str, epoch_s: int) -> list[Detection]:
        """An A/AAAA answer for a domain — feeds fast-flux answer churn."""
        if not self._check_epoch(ts_iso, epoch_s):
            return []
        d = self.fastflux.observe(domain, answer, ttl, ts_iso, epoch_s) \
            if self.fastflux else None
        out = [d] if d is not None else []
        self.detections.extend(out)
        return out

    def on_flow(self, host: str, dst: str, out_bytes: int, in_bytes: int,
                ts_iso: str, epoch_s: int) -> list[Detection]:
        """A network flow record — feeds volumetric exfiltration."""
        if not self._check_epoch(ts_iso, epoch_s):
            return []
        d = self.volume.observe(host, dst, out_bytes, in_bytes, ts_iso, epoch_s) \
            if self.volume else None
        out = [d] if d is not None else []
        self.detections.extend(out)
        return out

    def on_tls(self, client: str, dst: str, sni: str | None,
               cert_covers_sni: bool, is_ip_https: bool, has_sni: bool,
               ts_iso: str, epoch_s: int) -> list[Detection]:
        """A passive TLS handshake observation — feeds metadata mismatch."""
        if not self._check_epoch(ts_iso, epoch_s):
            return []
        d = self.tls.observe(client, dst, sni, cert_covers_sni, is_ip_https,
                             has_sni, ts_iso, epoch_s) if self.tls else None
        out = [d] if d is not None else []
        self.detections.extend(out)
        return out

    # -- evidence frontier -----------------------------------------------------

    def attach_to_indicators(self, known: dict[str, str]) -> list[dict]:
        """Fold detections that reference a KNOWN indicator value into
        evidence-bearing records.

        ``known`` maps indicator value -> indicator id (e.g. the ledger's
        current indicator population). A detection whose ``dst`` (domain/IP)
        matches a known indicator is emitted as a ``behavioral_*`` evidence
        record; anything else is dropped (the detection stays dormant —
        no new authority is invented). Returns the evidence records (the
        caller persists them), ordered deterministically by kind.
        """
        out = []
        for det in self.detections:
            target = det.dst
            ind_id = known.get(target)
            if ind_id is None:
                continue
            out.append(det.as_evidence_fields())
        self.detections = []
        return out

    def health(self) -> dict:
        dets = [d for d in (self.beacon, self.novelty, self.dga, self.tunnel,
                            self.fastflux, self.volume, self.tls, self.sync)
                if d is not None]
        return {
            "enabled_families": sorted({d.KIND for d in dets}),
            "pending_families_requested": self.pending,
            "detectors": [d.health() for d in dets],
            "rejected_epoch_mismatch": self.rejected_epoch_mismatch,
        }