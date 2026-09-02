from __future__ import annotations
from ..models import Indicator, Decision
from ..sanitize import suricata_safe, validate_fqdn, validate_ip_literal


def compile_rules(items: list[tuple[Indicator, Decision]]) -> str:
    """Compile decisions into a dry-run Suricata ruleset.

    v2.2 hardening: EVERY interpolation into rule text passes a compile-time
    validator/escaper (`suricata_safe`) and address targets are re-validated
    as canonical IP literals. The v2.1.1 audit found `apip_client` carried
    raw, indicator-derived text into metadata — a rule-injection path — and
    the general fix is structural: no value reaches a rule without passing
    the artifact boundary, regardless of what upstream trusted.

    v2.1.1 residual (retained): rate_limit rules carry the decision's drawn
    ceiling and the exporter REFUSES a ceilingless rate_limit — an intent
    is never compiled as a rule.
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
        # artifact-boundary validation of every variable field (fail closed)
        disposition = suricata_safe(dec.disposition, "disposition")
        rung = suricata_safe(dec.rung, "rung")
        dec_id = suricata_safe(dec.id, "decision id")
        if ind.type in {"ipv4", "ipv6"} and dec.action in {"firewall_deny", "rate_limit"}:
            target = validate_ip_literal(ind.value)
            sid += 1
            action = "drop" if dec.action == "firewall_deny" else "alert"
            ttl = max(1, dec.ttl_seconds or 0)
            if action == "alert":
                # Ceiling semantics via real detection_filter (docs/25): the
                # rule fires only once the source exceeds the drawn ceiling
                # within a 60s window — count = ceiling, seconds = 60.
                # Machine-readable metadata carries decision id, ceiling and
                # TTL so the production enforcement compiler (which owns the
                # actual rate_filter/iptables-hashlimit mapping) can consume
                # them without re-deriving anything.
                rule = (
                    f'{action} ip $HOME_NET any -> {target} any '
                    f'(msg:"APIP {disposition} {target} rung={rung}"; '
                    f'metadata:apip_decision {dec_id}, apip_ceiling_per_min {int(ceiling)}, '
                    f'apip_ttl_seconds {ttl}; '
                    f'detection_filter:track by_src, count {int(ceiling)}, seconds 60; '
                    f'sid:{sid}; rev:1;)'
                )
            else:
                rule = (
                    f'{action} ip $HOME_NET any -> {target} any '
                    f'(msg:"APIP {disposition} {target} rung={rung}"; '
                    f'metadata:apip_decision {dec_id}, apip_ttl_seconds {ttl}; '
                    f'sid:{sid}; rev:1;)'
                )
            lines.append(rule)
        elif (ind.type == "fqdn" and dec.action == "rate_limit"
              and dec.selector is not None
              and dec.selector.scope_type == "client_destination_pair"):
            # v2.1.1: fqdn pair rate-limits compile as http.host alerts gated
            # by the pair's drawn ceiling; metadata carries decision id +
            # ceiling + client so the production enforcement compiler
            # consumes them directly. v2.2: the client reference — historically
            # derived from external indicator ids — passes the artifact
            # boundary like every other field.
            host = validate_fqdn(ind.value)
            client = suricata_safe(dec.selector.client or "unknown", "apip_client")
            sid += 1
            lines.append(
                f'alert http any any -> any any '
                f'(msg:"APIP {disposition} {host} rung={rung}"; '
                f'http.host; content:"{host}"; nocase; '
                f'metadata:apip_decision {dec_id}, apip_ceiling_per_min {int(ceiling)}, '
                f'apip_client {client}, '
                f'apip_ttl_seconds {max(1, dec.ttl_seconds or 1)}; '
                f'detection_filter:track by_src, count {int(ceiling)}, seconds 60; '
                f'sid:{sid}; rev:1;)')
    return "\n".join(lines) + "\n"
