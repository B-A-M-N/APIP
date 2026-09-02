from __future__ import annotations
from ..models import Indicator, Decision

def compile_rules(items: list[tuple[Indicator, Decision]]) -> str:
    lines = ["# Dry-run APIP Suricata output. Review before any use."]
    sid = 9100000
    for ind, dec in items:
        if ind.type in {"ipv4", "ipv6"} and dec.action in {"firewall_deny", "rate_limit"}:
            sid += 1
            action = "drop" if dec.action == "firewall_deny" else "alert"
            # This is intentionally a simple demonstrator and emits only reserved TEST-NET sample data in the package examples.
            lines.append(
                f'{action} ip $HOME_NET any -> {ind.value} any '
                f'(msg:"APIP {dec.disposition} {ind.value} rung={dec.rung}"; sid:{sid}; rev:1;)'
            )
    return "\n".join(lines) + "\n"
