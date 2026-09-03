from __future__ import annotations
import hashlib as _hl
from ..models import Indicator, Decision, CompiledArtifact
from ..sanitize import suricata_safe, validate_fqdn, validate_ip_literal

_SURICATA_RULE_START_SID = 9100000


def _bundle_hash(fragments: list[str]) -> str:
    return "bundle--" + _hl.sha256(("\n".join(fragments)).encode()).hexdigest()[:24]


def compile_rules_structured(items: list[tuple[Indicator, Decision]],
                             bundle_id: str = "suricata-bundle-1") -> list[CompiledArtifact]:
    """Compile decisions into structured Suricata artifacts (audit P1-26).

    Returns one CompiledArtifact per decision that ACTUALLY rendered a rule —
    a decision that produced nothing compiles to NOTHING, so no downstream
    caller can claim a receipt for a nonexistent artifact. audit P1-25: rules
    that a cluster-policy mapping has not turned into an enforcement actuator
    are explicitly marked `monitoring_only` (an `alert + detection_filter`
    rule is a monitoring/intent artifact, NOT a real rate-limit actuator).

    v2.2 hardening: EVERY interpolation passes a compile-time
    validator/escaper and address targets are re-validated as canonical IP
    literals. A pair-scoped selector whose client cannot be bounded as an
    address REFUSES the IP compile (raising) rather than broadening a typed
    pair into a destination-global rule (docs/25: adapters must refuse to
    broaden).
    """
    fragments: list[str] = []
    compiled: list[CompiledArtifact] = []
    sid = _SURICATA_RULE_START_SID
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
        rule: str | None = None
        monitoring = False
        if ind.type in {"ipv4", "ipv6"} and dec.action in {"firewall_deny", "rate_limit"}:
            # audit P1-25: an IP pair-scoped selector cannot be enforced here
            # — the adapter (Suricata file rule) would require the CLIENT as a
            # bounded address source for true pair scope. Without one, the
            # only forms are destination-global, which BROADENS the typed
            # selector; refuse rather than broaden.
            sel = dec.selector
            if (sel is not None
                    and sel.scope_type in {"client_destination_pair", "client_session"}
                    and not sel.client):
                raise ValueError(
                    f"decision {dec.id} is {sel.scope_type} with no boundable "
                    "client; the Suricata adapter cannot faithfully represent "
                    "it and refuses to broaden to destination-global")
            target = validate_ip_literal(ind.value)
            sid += 1
            action = "drop" if dec.action == "firewall_deny" else "alert"
            ttl = max(1, dec.ttl_seconds or 0)
            if action == "alert":
                # Ceiling semantics via detection_filter (docs/25). This is a
                # MONITORING/INTENT rule, not a real enforcement actuator: the
                # firing condition is per-source against the drawn ceiling,
                # not the typed pair/session scope. Flag it explicitly.
                monitoring = True
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
        elif (ind.type == "fqdn" and dec.action == "rate_limit"
              and dec.selector is not None
              and dec.selector.scope_type == "client_destination_pair"):
            # v2.1.1: fqdn pair rate-limits compile as http.host alerts gated
            # by the pair's drawn ceiling; metadata carries decision id +
            # ceiling + client so the production enforcement compiler
            # consumes them directly. The http.host FAST pattern IS the pair
            # bound (host), unlike the IP case, so it can be a genuine intent
            # rule — still flagged monitoring because enforcement mapping is a
            # cluster-policy decision (docs/25).
            monitoring = True
            host = validate_fqdn(ind.value)
            client = suricata_safe(dec.selector.client or "unknown", "apip_client")
            sid += 1
            rule = (
                f'alert http any any -> any any '
                f'(msg:"APIP {disposition} {host} rung={rung}"; '
                f'http.host; content:"{host}"; nocase; '
                f'metadata:apip_decision {dec_id}, apip_ceiling_per_min {int(ceiling)}, '
                f'apip_client {client}, '
                f'apip_ttl_seconds {max(1, dec.ttl_seconds or 1)}; '
                f'detection_filter:track by_src, count {int(ceiling)}, seconds 60; '
                f'sid:{sid}; rev:1;)')
        if rule is None:
            # audit P1-26: a decision that compiled to NO rule yields no
            # artifact and therefore NO receipt downstream.
            continue
        fragments.append(rule)
        compiled.append(CompiledArtifact(
            decision_id=dec.id, adapter="suricata-file-exporter",
            rule_id=f"sid:{sid}", fragment=rule, fragment_hash="",  # set after bundle hash
            bundle_id=bundle_id, bundle_hash="", status="dry_run",
            monitoring_only=monitoring))
    bundle_hash = _bundle_hash(fragments)
    # audit P1-27: fragment hash is decision-specific (over this rule alone),
    # independent of the bundle hash (over the whole combined ruleset).
    return [
        CompiledArtifact(
            decision_id=a.decision_id, adapter=a.adapter, rule_id=a.rule_id,
            fragment=a.fragment,
            fragment_hash="frag--" + _hl.sha256(a.fragment.encode()).hexdigest()[:24],
            bundle_id=a.bundle_id, bundle_hash=bundle_hash,
            status=a.status, monitoring_only=a.monitoring_only)
        for a in compiled]


def compile_rules(items: list[tuple[Indicator, Decision]]) -> str:
    """Compile decisions into a dry-run Suricata ruleset (string form).

    Thin wrapper over `compile_rules_structured`; keeps the legacy signature
    for callers that only need the concatenated text. Because it uses the
    structured path, a decision with no artifact contributes no rule text.
    """
    arts = compile_rules_structured(items)
    header = "# Dry-run APIP Suricata output. Review before any use."
    if not arts:
        return header + "\n"
    return header + "\n" + "\n".join(a.fragment for a in arts) + "\n"
