from __future__ import annotations
from ..models import Indicator, Decision

def compile_rules(items: list[tuple[Indicator, Decision]]) -> str:
    """Compile decisions into a dry-run Suricata ruleset.

    v2.1.1 (audit residual fix): rate_limit rules previously had NO ceiling
    semantics — the rung was selected but the compiled artifact carried no
    rate at all. rate_limit now compiles to alert + rate_filter with the
    decision's drawn ceiling (docs/25), and every rule carries the decision
    id and TTL so an operator can trace the rule back to its recorded draws.
    """
    lines = ["# Dry-run APIP Suricata output. Review before any use."]
    sid = 9100000
    for ind, dec in items:
        # rate_limit requires a ceiling no matter the target type; refuse to
        # compile an intent as a rule.
        ceiling = dec.selector.rate_ceiling_per_min if dec.selector else None
        if dec.action == "rate_limit" and not ceiling:
            raise ValueError(
                f"rate_limit decision {dec.id} has no rate ceiling; "
                "refusing to compile an intent as a rule")
        if ind.type in {"ipv4", "ipv6"} and dec.action in {"firewall_deny", "rate_limit"}:
            sid += 1
            action = "drop" if dec.action == "firewall_deny" else "alert"
            ttl = dec.ttl_seconds or 0
            # This is intentionally a simple demonstrator and emits only reserved TEST-NET sample data in the package examples.
            if action == "alert":
                # Ceiling semantics via real detection_filter (docs/25): the
                # rule fires only once the source exceeds the drawn ceiling
                # within a 60s window — count = ceiling, seconds = 60.
                # Machine-readable metadata carries decision id, ceiling and
                # TTL so the production enforcement compiler (which owns the
                # actual rate_filter/iptables-hashlimit mapping) can consume
                # them without re-deriving anything.
                rule = (
                    f'{action} ip $HOME_NET any -> {ind.value} any '
                    f'(msg:"APIP {dec.disposition} {ind.value} rung={dec.rung}"; '
                    f'metadata:apip_decision {dec.id}, apip_ceiling_per_min {ceiling}, '
                    f'apip_ttl_seconds {max(1, ttl)}; '
                    f'detection_filter:track by_src, count {ceiling}, seconds 60; '
                    f'sid:{sid}; rev:1;)'
                )
            else:
                rule = (
                    f'{action} ip $HOME_NET any -> {ind.value} any '
                    f'(msg:"APIP {dec.disposition} {ind.value} rung={dec.rung}"; '
                    f'metadata:apip_decision {dec.id}, apip_ttl_seconds {max(1, ttl)}; '
                    f'sid:{sid}; rev:1;)'
                )
            lines.append(rule)
        elif (ind.type == "fqdn" and dec.action == "rate_limit"
              and dec.selector is not None
              and dec.selector.scope_type == "client_destination_pair"):
            # v2.1.1: fqdn pair rate-limits previously compiled to NOTHING
            # while receipts still claimed a suricata artifact existed.
            # Compile as an http.host alert gated by the pair's drawn
            # ceiling; metadata carries decision id + ceiling + client so
            # the production enforcement compiler consumes them directly.
            sid += 1
            lines.append(
                f'alert http any any -> any any '
                f'(msg:"APIP {dec.disposition} {ind.value} rung={dec.rung}"; '
                f'http.host; content:"{ind.value}"; nocase; '
                f'metadata:apip_decision {dec.id}, apip_ceiling_per_min {ceiling}, '
                f'apip_client {dec.selector.client or "unknown"}, '
                f'apip_ttl_seconds {max(1, dec.ttl_seconds or 1)}; '
                f'detection_filter:track by_src, count {ceiling}, seconds 60; '
                f'sid:{sid}; rev:1;)')
    return "\n".join(lines) + "\n"
