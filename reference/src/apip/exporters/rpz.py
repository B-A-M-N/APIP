from __future__ import annotations
import hashlib as _hl
from ..models import Indicator, Decision, CompiledArtifact
from ..sanitize import rpz_comment_safe, validate_fqdn

_RPZ_HEADER = [
    "$TTL 60",
    "$ORIGIN apip.invalid.",
    "@ IN SOA localhost. hostmaster.localhost. 1 60 60 60 60",
    "@ IN NS localhost.",
    "; Dry-run APIP RPZ output. Not automatically applied.",
]


def _bundle_hash(fragments: list[str]) -> str:
    return "bundle--" + _hl.sha256(("\n".join(fragments)).encode()).hexdigest()[:24]


def compile_rpz_structured(items: list[tuple[Indicator, Decision]],
                           bundle_id: str = "rpz-bundle-1") -> list[CompiledArtifact]:
    """Compile decisions into structured RPZ fragments (audit P1-26/P1-27).

    One CompiledArtifact per decision that ACTUALLY emitted a zone line; a
    decision with no applicable zone action compiles to NOTHING (so no receipt
    downstream). Each fragment carries its own (zone-owner decision-specific)
    hash AND the bundle hash over the whole combined zone.
    """
    fragments: list[str] = []
    compiled: list[CompiledArtifact] = []
    for ind, dec in items:
        if ind.type == "fqdn" and dec.action == "dns_nxdomain" \
                and dec.disposition in {"AUTO_ENFORCE", "SHADOW_ACTION"}:
            # zone-owner name: re-validated at the artifact boundary
            owner = validate_fqdn(ind.value)
            comment = rpz_comment_safe(f"{dec.id} {dec.disposition} rung={dec.rung}")
            line = f"{owner}. CNAME . ; {comment}"
            fragments.append(line)
            compiled.append(CompiledArtifact(
                decision_id=dec.id, adapter="rpz-file-exporter",
                rule_id=f"owner:{owner}", fragment=line, fragment_hash="",
                bundle_id=bundle_id, bundle_hash="", status="dry_run",
                monitoring_only=False))   # CNAME . is a true NXDOMAIN redirect
    bundle_hash = _bundle_hash(fragments)
    return [
        CompiledArtifact(
            decision_id=a.decision_id, adapter=a.adapter, rule_id=a.rule_id,
            fragment=a.fragment,
            fragment_hash="frag--" + _hl.sha256(a.fragment.encode()).hexdigest()[:24],
            bundle_id=a.bundle_id, bundle_hash=bundle_hash,
            status=a.status, monitoring_only=a.monitoring_only)
        for a in compiled]


def compile_rpz(items: list[tuple[Indicator, Decision]]) -> str:
    """Compile decisions into a dry-run RPZ zone (string form).

    Thin wrapper over `compile_rpz_structured`; keeps the legacy signature.
    """
    arts = compile_rpz_structured(items)
    lines = list(_RPZ_HEADER) + [a.fragment for a in arts]
    return "\n".join(lines) + "\n"
