from __future__ import annotations
import json, ipaddress
from pathlib import Path
from .models import Indicator, Evidence

def _canonicalize(kind: str, value: str) -> str:
    value = value.strip()
    if kind == "fqdn":
        v = value.rstrip(".").lower()
        if not v or " " in v or "/" in v:
            raise ValueError(f"invalid fqdn: {value!r}")
        return v.encode("idna").decode("ascii")
    if kind == "ipv4":
        return str(ipaddress.IPv4Address(value))
    if kind == "ipv6":
        return str(ipaddress.IPv6Address(value))
    if kind == "cidr":
        return str(ipaddress.ip_network(value, strict=False))
    return value

def load_indicators(path: str | Path) -> list[Indicator]:
    """Load indicators as FACTS (docs/04 v2.1).

    Any client-supplied score fields (points_m, points_s, points_s_ctx,
    points_s_ip) are deliberately IGNORED — scoring authority belongs to
    the policy weight table. Source class and independence are assigned
    server-side by the source registry, never from the payload.
    """
    raw = json.loads(Path(path).read_text())
    out: list[Indicator] = []
    for obj in raw:
        kind = obj["type"]
        evidence: list[Evidence] = []
        for ev in obj.get("evidence", []):
            evidence.append(Evidence(
                kind=str(ev.get("kind", "evidence")),
                source_id=str(ev.get("source_id", "unregistered")),
                source_class="unassigned",   # replaced by registry at policy time
                observed_at=str(ev.get("observed_at", obj.get("last_seen", "")) or ""),
                independent=False,           # replaced by registry at policy time
                detail={k: v for k, v in ev.items()
                        if k not in {"kind", "source_id", "observed_at",
                                     "points_m", "points_s", "points_s_ctx",
                                     "points_s_ip", "independent", "origin",
                                     "family", "corroboration_group"}},
            ))
        out.append(Indicator(
            id=obj["id"],
            type=kind,
            value=_canonicalize(kind, obj["value"]),
            sources=tuple(sorted(set(obj.get("sources", [])))),
            evidence=tuple(evidence),
            tags=tuple(sorted(set(obj.get("tags", [])))),
        ))
    return out
