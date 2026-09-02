from __future__ import annotations
from ..models import Indicator, Decision

def compile_rpz(items: list[tuple[Indicator, Decision]]) -> str:
    lines = [
        "$TTL 60",
        "$ORIGIN apip.invalid.",
        "@ IN SOA localhost. hostmaster.localhost. 1 60 60 60 60",
        "@ IN NS localhost.",
        "; Dry-run APIP RPZ output. Not automatically applied.",
    ]
    for ind, dec in items:
        if ind.type == "fqdn" and dec.action == "dns_nxdomain" and dec.disposition in {"AUTO_ENFORCE", "SHADOW_ACTION"}:
            lines.append(f"{ind.value}. CNAME . ; {dec.id} {dec.disposition} rung={dec.rung}")
    return "\n".join(lines) + "\n"
