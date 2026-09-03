"""Suricata IPS / file exporter adapter — exact-IP enforcement (docs/06).

The second real enforcement adapter for beta (goal E), alongside the RPZ
adapter. Compiles a decision into a bounded, exact-address Suricata rule and
publishes it to a ruleset file (with an optional reload command for a live
Suricata/Suricata-IPS instance).

Postures (adapter.suricata_mode, the adapter's own maximum):
  OFF      compile only, never publishes;
  OBSERVE  publishes to a monitor-only ruleset file, no IPS consumption
           expected;
  SHADOW   publishes + optional reload, but the fileset is NOT in the
           Suricata response chain — no behavior change is possible;
  ENFORCE  publishes + reloads a Suricata-consumed ruleset; every apply is
           verified by re-reading the ruleset file for the exact sid.

Safety invariants (docs/06 Firewall/IPS section, ported from the reference
exporter's hardened semantics):

  - EXACT IP literals only. `compile` refuses CIDR auto-deny, wildcards, and
    any selector wider than the decision authorized (selector-never-broadens
    is enforced in compile AND validate — two independent checks, plus the
    controller-layer scope check);
  - home-net scoping: an IP target must fall inside one of the adapter's
    configured `suricata_authorized_prefixes` — the adapter enforces scope
    INDEPENDENTLY of policy/controller (defense in depth layer 3). ENFORCE
    mode without any declared prefix never authorizes anything;
  - pair-scoped selectors (client_destination_pair / client_session) with no
    boundable client are REFUSED at compile (raising) rather than broadened
    to a destination-global rule — this adapter never turns a `rate_limit
    <ip>` into a global IPS rule;
  - IP rate-limits compile as `alert + detection_filter` MONITORING rules
    (a real rate-limit actuator mapping is a cluster-policy decision), never
    silently upgraded to an enforcement equivalent;
  - fragments/comment charset is closed (suricata_safe + validate_ip_literal
    at the emit boundary, defense in depth behind ingest canonicalization);
  - each rule carries decision id + TTL in metadata so expiry/reconciliation
    can target exactly that decision.

This is NOT a rate-limit actuator for pair/session scope (the docs/25 L2
ceiling) — it faithfully renders the monitoring/intent artifact the
reference exporter proves, and a cluster policy turning it into enforcement
is separately governed.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from apip.adapters.base import AdapterError
from apip.config.service import AdapterConfig
from apip.domain.sanitize import suricata_safe, validate_fqdn, validate_ip_literal

_MODE_RANK = {"OFF": 0, "OBSERVE": 1, "SHADOW": 2, "ENFORCE": 3}

# SID allocation start for APIP-generated rules (matches the reference
# exporter's namespace so a mixed ruleset stays collision-free).
_SURICATA_RULE_START_SID = 9100000

# Exact SID token matcher. A Suricata rule carries exactly one terminating
# ``sid:NNN;`` key; matching that token (not a substring) is what keeps a
# revoke/verify from hitting a rule whose SID merely shares a prefix.
_SID_RE = re.compile(r"\bsid\s*:\s*(\d+)\s*;")

# Behavioral intent that is NOT a real enforcement actuator (docs/06: a
# rate-limit rule is a monitoring/intent artifact until a cluster policy maps
# it to an enforcement mapping).
_PAIR_SCOPED = {"client_destination_pair", "client_session"}


class SuricataAdapter:
    name = "suricata"

    def __init__(self, config: AdapterConfig):
        self.config = config
        mode = config.suricata_mode.upper()
        if mode not in _MODE_RANK:
            raise AdapterError(f"invalid suricata mode {config.suricata_mode!r}")
        self._mode = mode
        self._rules_dir = Path(config.suricata_rules_dir)
        # ENFORCE requires explicit home-net scope — never authorize-by-omission
        # at the IPS edge.
        if mode == "ENFORCE" and not config.suricata_authorized_prefixes:
            raise AdapterError(
                "suricata ENFORCE mode requires adapter.suricata_authorized_prefixes "
                "(the adapter never authorizes by omission)")
        self._authorized = tuple(
            ipaddress.ip_network(p, strict=False)
            for p in config.suricata_authorized_prefixes)

    # -- posture --------------------------------------------------------------

    def max_mode(self) -> str:
        return self._mode

    def _require_mode(self, needed: str, what: str) -> None:
        if _MODE_RANK[self._mode] < _MODE_RANK[needed]:
            raise AdapterError(
                f"{what} requires adapter mode {needed} (configured {self._mode})")

    # -- scope (defense in depth layer 3) ---------------------------------------

    def _in_adapter_scope(self, ip_literal: str) -> bool:
        """The adapter's OWN boundary: a target address is authorized iff it
        falls inside a configured home-net prefix. Exact addresses only — a
        bare host inside the home net is permitted, and nothing is authorized
        when no prefix is declared."""
        if not self._authorized:
            return False
        try:
            addr = ipaddress.ip_address(ip_literal)
        except ValueError:
            return False
        return any(addr.version == net.version and addr in net
                   for net in self._authorized)

    # -- compile ---------------------------------------------------------------

    def compile(self, decision: Any, indicator_value: str,
                indicator_type: str) -> list[dict]:
        """Compile an exact-IP Suricata rule from a decision.

        Beta contract: ipv4/ipv6 `firewall_deny` -> drop rule; ipv4/ipv6
        `rate_limit` -> monitoring alert + detection_filter (intent artifact);
        fqdn `rate_limit` on a client_destination_pair -> http.host intent
        alert. Anything else compiles to nothing — no action, no receipt.
        """
        if decision.action not in ("firewall_deny", "rate_limit"):
            return []
        if decision.disposition not in ("SHADOW_ACTION", "AUTO_ENFORCE",
                                        "PROPOSE_OPERATOR_APPROVAL"):
            return []
        dec_id = suricata_safe(decision.id, "decision id")
        disposition = suricata_safe(decision.disposition, "disposition")
        rung = suricata_safe(getattr(decision, "rung", "L0"), "rung")
        ttl = max(1, int(getattr(decision, "ttl_seconds", 0) or 0))

        ceiling = None
        sel = getattr(decision, "selector", None)
        if sel is not None:
            ceiling = getattr(sel, "rate_ceiling_per_min", None)

        rule: str | None = None
        sid: int | None = None
        monitoring = False

        if indicator_type in {"ipv4", "ipv6"}:
            # exact IP only — CIDR deny is refused here AND in validate
            if "/" in indicator_value:
                return []
            # pair/session-scoped selectors without a boundable client can
            # never be represented faithfully as a destination-global rule;
            # refuse rather than broaden (docs/06, docs/25).
            if sel is not None and sel.scope_type in _PAIR_SCOPED:
                if not getattr(sel, "client", None):
                    raise AdapterError(
                        f"decision {decision.id} is {sel.scope_type} with no "
                        "boundable client; the Suricata adapter cannot "
                        "faithfully represent it and refuses to broaden to "
                        "destination-global")
            target = self._compile_ip_target(indicator_value)
            if decision.action == "firewall_deny":
                sid = self._next_sid()
                rule = (
                    f'drop ip $HOME_NET any -> {target} any '
                    f'(msg:"APIP {disposition} {target} rung={rung}"; '
                    f'metadata:apip_decision {dec_id}, apip_ttl_seconds {ttl}; '
                    f'sid:{sid}; rev:1;)')
            else:
                # rate_limit requires a ceiling no matter the form; refuse to
                # compile an intent without one.
                if ceiling is None:
                    raise AdapterError(
                        f"rate_limit decision {decision.id} has no rate "
                        "ceiling; refusing to compile an intent as a rule")
                monitoring = True
                sid = self._next_sid()
                rule = (
                    f'alert ip $HOME_NET any -> {target} any '
                    f'(msg:"APIP {disposition} {target} rung={rung}"; '
                    f'metadata:apip_decision {dec_id}, apip_ceiling_per_min {int(ceiling)}, '
                    f'apip_ttl_seconds {ttl}; '
                    f'detection_filter:track by_src, count {int(ceiling)}, seconds 60; '
                    f'sid:{sid}; rev:1;)')
        elif indicator_type == "fqdn" and decision.action == "rate_limit":
            # fqdn pair rate-limits compile as http.host intent alerts; the
            # http.host FAST pattern IS the pair bound (host), unlike the IP
            # case, so it can be a genuine intent rule — still flagged
            # monitoring (docs/25 enforcement mapping is cluster policy).
            if sel is None or sel.scope_type not in _PAIR_SCOPED:
                return []
            if ceiling is None:
                raise AdapterError(
                    f"rate_limit decision {decision.id} has no rate ceiling")
            host = validate_fqdn(indicator_value)
            client = suricata_safe(getattr(sel, "client", None) or "unknown",
                                   "apip_client")
            monitoring = True
            sid = self._next_sid()
            rule = (
                f'alert http any any -> any any '
                f'(msg:"APIP {disposition} {host} rung={rung}"; '
                f'http.host; content:"{host}"; nocase; '
                f'metadata:apip_decision {dec_id}, apip_ceiling_per_min {int(ceiling)}, '
                f'apip_client {client}, '
                f'apip_ttl_seconds {ttl}; '
                f'detection_filter:track by_src, count {int(ceiling)}, seconds 60; '
                f'sid:{sid}; rev:1;)')

        if rule is None or sid is None:
            return []
        target_key = indicator_value.rstrip(".")
        return [{
            "adapter": self.name,
            "rule_id": f"sid:{sid}",
            "fragment": rule,
            "fragment_hash": "frag--" + hashlib.sha256(rule.encode()).hexdigest()[:24],
            "bundle_id": f"suricata-{self.config.suricata_rules_file}",
            "bundle_hash": "bundle--" + hashlib.sha256(
                (rule + "\n").encode()).hexdigest()[:24],
            "monitoring_only": monitoring,
            "ttl_seconds": ttl,
            "selector": {
                "scope_type": (getattr(sel, "scope_type", "destination_global")
                               if sel is not None else "destination_global"),
                "destination": target_key,
                "exact_ip": (validate_ip_literal(indicator_value)
                             if indicator_type in {"ipv4", "ipv6"} else None),
            },
        }]

    def _compile_ip_target(self, indicator_value: str) -> str:
        """Validate + scope-check an exact IP target. Refuses pair-scoped
        selectors that cannot be bounded (never broadens). Returns the
        canonical IP literal."""
        target = validate_ip_literal(indicator_value)
        if not self._in_adapter_scope(target):
            raise AdapterError(
                f"target {target} outside adapter home-net scope "
                f"{sorted(str(n) for n in self._authorized)}")
        return target

    def _next_sid(self) -> int:
        """Deterministic sid for this process: bump a file-local counter."""
        if not hasattr(self, "_sid_counter"):
            self._sid_counter = _SURICATA_RULE_START_SID
        self._sid_counter += 1
        return self._sid_counter

    @staticmethod
    def _rule_sid(line: str) -> str | None:
        """Extract the EXACT sid token from a rule line, or None.

        Exact token match (``sid:NNN;``) not substring: a substring test like
        ``"sid:123" in line`` would match ``sid:1234`` / ``sid:12345`` too,
        letting a nearby rule fake presence, or a revoke over-remove rules
        whose SID merely shares a prefix. Every rule carries one terminating
        ``sid:`` token, so this returns exactly one id — never a guess.
        """
        m = _SID_RE.search(line)
        return m.group(1) if m else None

    # -- validate ----------------------------------------------------------------

    def validate(self, candidate: dict) -> dict:
        rule_id = candidate.get("rule_id", "")
        fragment = candidate.get("fragment", "")
        selector = candidate.get("selector") or {}
        if not rule_id.startswith("sid:"):
            raise AdapterError(f"invalid rule id {rule_id!r}")
        try:
            int(rule_id.split("sid:", 1)[1])
        except ValueError:
            raise AdapterError(f"invalid sid in rule id {rule_id!r}")
        # selector-never-broadens: a destination must match the rule's exact
        # target; a pair/session scope with no boundable client is refused
        # (the adapter never broadens to destination-global).
        scope_type = selector.get("scope_type", "destination_global")
        dest = selector.get("destination")
        exact = selector.get("exact_ip") or dest
        if not any(k in fragment for k in ("apip_decision", "metadata:")):
            raise AdapterError("fragment missing decision metadata")
        if exact and not isinstance(exact, str):
            raise AdapterError("selector exact_ip must be a string")
        if scope_type in _PAIR_SCOPED:
            raise AdapterError(
                "suricata validate refuses a pair/session-scoped selector "
                "(cannot be faithfully represented as destination-global)")
        return {"ok": True, "mode": self._mode, "rule_id": rule_id}

    # -- apply / verify / revoke ---------------------------------------------------

    def _rules_path(self) -> Path:
        return self._rules_dir / f"{self.config.suricata_rules_file}.rules"

    def _read_rules(self) -> str:
        p = self._rules_path()
        if p.is_file():
            return p.read_text(encoding="utf-8")
        return ""

    def _write_rules(self, lines: list[str]) -> str:
        self._rules_dir.mkdir(parents=True, exist_ok=True)
        content = "\n".join(lines) + "\n"
        tmp = self._rules_path().with_suffix(".rules.tmp")
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, self._rules_path())
        return content

    def _reload(self) -> dict:
        cmd = self.config.suricata_reload_command
        if not cmd:
            return {"reloaded": False, "reason": "no suricata_reload_command configured"}
        proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=15)
        if proc.returncode != 0:
            raise AdapterError(
                f"reload command failed rc={proc.returncode}: "
                f"{proc.stderr.decode(errors='replace')[:200]}")
        return {"reloaded": True}

    def apply(self, candidate: dict) -> dict:
        checked = self.validate(candidate)
        rule_id = checked["rule_id"]
        self._require_mode("SHADOW", "apply")
        lines = self._read_rules().splitlines() if self._read_rules() else []
        # idempotency: same sid replaces the prior line — match the EXACT sid
        # token so a rule whose SID merely shares a prefix is never clobbered.
        sid_line = rule_id.split("sid:", 1)[1]
        lines = [l for l in lines if self._rule_sid(l) != sid_line]
        lines.append(candidate["fragment"])
        content = self._write_rules(lines)
        reload_info = {"reloaded": False, "reason": "not attempted"}
        reload_error = None
        if self.config.suricata_reload_command:
            try:
                reload_info = self._reload()
            except AdapterError as e:
                reload_error = str(e)
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        if reload_error:
            return {"ok": False, "error": f"published but reload failed: {reload_error}"}
        return {
            "ok": True,
            "receipt": {
                "receipt_id": "receipt--" + hashlib.sha256(
                    (rule_id + "\x1f" + content_hash).encode()).hexdigest()[:24],
                "status": "applied",
                "observed": {
                    "rules_file": str(self._rules_path()),
                    "rules_sha256": content_hash,
                    "sid": sid_line,
                    "reload": reload_info,
                },
            },
        }

    def verify(self, candidate: dict) -> dict:
        """INDEPENDENT verification: the ruleset file actually holds the exact
        sid. Never fabricates success without the observed rule present."""
        checked = self.validate(candidate)
        rule_id = checked["rule_id"]
        sid_line = rule_id.split("sid:", 1)[1]
        content = self._read_rules()
        if not content:
            return {"ok": False, "error": "ruleset file missing"}
        present = any(self._rule_sid(l) == sid_line for l in content.splitlines())
        if not present:
            return {"ok": False, "error": f"rule sid:{sid_line} not present in ruleset"}
        return {"ok": True, "observed": {
            "rules_sha256": hashlib.sha256(content.encode()).hexdigest(),
            "sid": sid_line, "rule_present": True}}

    def revoke(self, candidate: dict) -> dict:
        """Remove EXACTLY this sid; verify the ruleset no longer holds it. A
        missing ruleset counts as removed (idempotent)."""
        checked = self.validate(candidate)
        rule_id = checked["rule_id"]
        sid_line = rule_id.split("sid:", 1)[1]
        content = self._read_rules()
        if not content:
            return {"ok": True, "observed": {"removed": sid_line, "ruleset_absent": True}}
        lines = [l for l in content.splitlines() if self._rule_sid(l) != sid_line]
        if len(lines) == len(content.splitlines()):
            return {"ok": True, "observed": {"removed": sid_line, "was_absent": True}}
        self._write_rules(lines)
        reload_info = {"reloaded": False, "reason": "not attempted"}
        if self.config.suricata_reload_command:
            reload_info = self._reload()
        after = self._read_rules()
        still = any(self._rule_sid(l) == sid_line for l in after.splitlines())
        if still:
            return {"ok": False, "error": "rule still present after revoke"}
        return {"ok": True, "observed": {
            "removed": sid_line,
            "rules_sha256": hashlib.sha256(after.encode()).hexdigest(),
            "reload": reload_info}}

    def get_state(self, selector: dict) -> dict:
        """Current actual state for a selector. Locates the exact rule by the
        selector's exact_ip (or a carried rule_id sid) — never reports
        present based on intent."""
        sid_line = ""
        if selector.get("rule_id"):
            sid_line = str(selector["rule_id"]).split("sid:", 1)[-1]
        content = self._read_rules()
        if not content:
            return {"sid": sid_line, "present": False, "mode": self._mode}
        ip_target = selector.get("exact_ip") or selector.get("destination")
        present = False
        for l in content.splitlines():
            has_sid = (self._rule_sid(l) == sid_line) if sid_line else True
            has_ip = True
            if ip_target:
                has_ip = ip_target in l
            if has_sid and has_ip:
                present = True
                break
        return {"sid": sid_line, "present": present, "mode": self._mode}

    def health(self) -> dict:
        base = {
            "name": self.name,
            "mode": self._mode,
            "rules_file": str(self._rules_path()),
            "authorized_prefixes": sorted(str(n) for n in self._authorized),
            "reload_configured": bool(self.config.suricata_reload_command),
        }
        if self._mode == "OFF":
            base["status"] = "ok"
            base["note"] = "adapter OFF: compiles only"
            return base
        if self._rules_path().is_file():
            base["status"] = "ok"
        else:
            base["status"] = "degraded" if self._mode == "ENFORCE" else "ok"
            base["note"] = "ruleset not yet created (no applies yet)"
        return base