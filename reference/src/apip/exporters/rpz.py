from __future__ import annotations
from ..models import Indicator, Decision
from ..sanitize import rpz_comment_safe, validate_fqdn


def compile_rpz(items: list[tuple[Indicator, Decision]]) -> str:
    """Compile decisions into a dry-run RPZ zone.

    v2.2 hardening: compile-time validation of every value that reaches the
    zone text (defense in depth behind ingest-time canonicalization). A
    value that cannot be proven zone-safe refuses the compile with a named
    error — an artifact is never emitted with an unvalidated interpolation.
    """
    lines = [
        "$TTL 60",
        "$ORIGIN apip.invalid.",
        "@ IN SOA localhost. hostmaster.localhost. 1 60 60 60 60",
        "@ IN NS localhost.",
        "; Dry-run APIP RPZ output. Not automatically applied.",
    ]
    for ind, dec in items:
        if ind.type == "fqdn" and dec.action == "dns_nxdomain" and dec.disposition in {"AUTO_ENFORCE", "SHADOW_ACTION"}:
            # zone-owner name: re-validated at the artifact boundary
            owner = validate_fqdn(ind.value)
            comment = rpz_comment_safe(f"{dec.id} {dec.disposition} rung={dec.rung}")
            lines.append(f"{owner}. CNAME . ; {comment}")
    return "\n".join(lines) + "\n"
