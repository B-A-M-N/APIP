"""Suricata IDS ruleset exporter — exact-IP monitoring artifacts (docs/06).

The second real adapter for beta, alongside the RPZ adapter. Compiles a
decision into a bounded, exact-address Suricata rule and publishes it to a
ruleset file. THIS IS AN IDS/EXPORT SURFACE ONLY (review P0 #4, option A):
the beta Suricata surface is downgraded to OFF / OBSERVE / SHADOW file
export. It cannot drop, reject, or rate-limit any traffic because:

  - ``suricata_mode = "ENFORCE"`` is REFUSED at construction — there is no
    live reload path, no engine-parser validation, and no independent
    confirmation that a Suricata engine has the rule loaded, so claiming
    enforcement would be fabricated;
  - every emitted rule is ``alert`` (never ``drop``/``reject``) — even if an
    operator attaches the exported ruleset to an inline IPS, the rules can
    alert but cannot change traffic;
  - there is deliberately NO reload command wiring at all: nothing in this
    adapter executes a process, so publication cannot reach an engine.

ENFORCE for this adapter becomes constructible again only with: a mandatory
live reload/update path, real Suricata parser validation, independent
confirmation that the engine holds the exact SID, and inline-IPS capability
verification where ``drop`` is claimed.

Safety invariants (docs/06 Firewall/IPS section, ported from the reference
exporter's hardened semantics):

  - EXACT IP literals only. `compile` refuses CIDR auto-deny, wildcards, and
    any selector wider than the decision authorized (selector-never-broadens
    is enforced in compile AND validate — two independent checks, plus the
    controller-layer scope check);
  - home-net scoping: an IP target must fall inside one of the adapter's
    configured `suricata_authorized_prefixes` — the adapter enforces scope
    INDEPENDENTLY of policy/controller (defense in depth layer 3);
  - pair-scoped selectors (client_destination_pair / client_session) with no
    boundable client are REFUSED at compile (raising) rather than broadened
    to a destination-global rule;
  - rate-limits compile as `alert + detection_filter` MONITORING artifacts;
  - fragments/comment charset is closed (suricata_safe + validate_ip_literal
    at the emit boundary, defense in depth behind ingest canonicalization);
  - each rule carries decision id + TTL in metadata so expiry/reconciliation
    can target exactly that decision.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path
from typing import Any

from apip.adapters.base import AdapterError, MODE_RANK, effective_mode
from apip.config.service import AdapterConfig
from apip.domain.sanitize import suricata_safe, validate_fqdn, validate_ip_literal

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
        from apip.adapters.base import validate_adapter_config
        self.config = config
        mode = config.suricata_mode.upper()
        if mode not in MODE_RANK:
            raise AdapterError(f"invalid suricata mode {config.suricata_mode!r}")
        # P1 #37: same artifact boundary as RPZ — rules dir traversal and a
        # rules filename that is not a bare filename are refused here.
        problems = [p for p in validate_adapter_config(config)
                    if "zone_name" not in p and "verify_query" not in p
                    and "zone_dir" not in p]
        if problems:
            raise AdapterError("; ".join(problems))
        # Truthfulness (review P0 #4): ENFORCE is not offered on this adapter
        # in beta — no engine reload, no parser validation, no independent
        # engine-loaded confirmation exists. Refuse rather than fabricate.
        if mode == "ENFORCE":
            raise AdapterError(
                'suricata_mode = "ENFORCE" is not supported in beta: this '
                "adapter is an IDS/export surface (OFF/OBSERVE/SHADOW) with "
                "no live reload, no engine parser validation, and no "
                "independent engine-loaded confirmation. Configure SHADOW.")
        self._mode = mode
        self._rules_dir = Path(config.suricata_rules_dir)

    # -- posture --------------------------------------------------------------

    def max_mode(self) -> str:
        return self._mode

    def _effective(self, candidate: dict) -> str:
        """min(persisted action mode, adapter maximum) — the persisted mode is
        the authority; configuration can only weaken. Missing mode = OFF."""
        return effective_mode(candidate.get("mode"), self._mode)

    # -- scope (defense in depth layer 3) ---------------------------------------

    def _in_adapter_scope(self, ip_literal: str) -> bool:
        """The adapter's OWN boundary: a target address is authorized iff it
        falls inside a configured home-net prefix. Exact addresses only — a
        bare host inside the home net is permitted, and nothing is authorized
        when no prefix is declared."""
        if not self.config.suricata_authorized_prefixes:
            return False
        try:
            addr = ipaddress.ip_address(ip_literal)
        except ValueError:
            return False
        return any(
            addr.version == net.version and addr in net
            for net in (ipaddress.ip_network(p, strict=False)
                        for p in self.config.suricata_authorized_prefixes))

    # -- compile ---------------------------------------------------------------

    def compile(self, decision: Any, indicator_value: str,
                indicator_type: str) -> list[dict]:
        """Compile an exact-IP Suricata rule from a decision.

        Beta contract: ipv4/ipv6 `firewall_deny` -> alert rule (IDS export —
        the beta adapter cannot drop); ipv4/ipv6 `rate_limit` -> monitoring
        alert + detection_filter; fqdn `rate_limit` on a client_destination_pair
        -> http.host intent alert. Anything else compiles to nothing — no
        action, no receipt.
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
            # IDS-export surface: even a firewall_deny decision renders as
            # `alert` — the beta adapter cannot drop traffic (truthfulness).
            sid = self._next_sid(decision.id, self._read_rules())
            if decision.action == "firewall_deny":
                rule = (
                    f'alert ip $HOME_NET any -> {target} any '
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
            sid = self._next_sid(decision.id, self._read_rules())
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
            "monitoring_only": True,   # every beta artifact is alert-only
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
                f"{sorted(str(n) for n in self.config.suricata_authorized_prefixes)}")
        return target

    def _next_sid(self, decision_id: str, rules_text: str | None = None) -> int:
        """Deterministic, restart-safe SID allocation (review P0 #5).

        The SID is derived from the DECISION ID — a globally unique ledger
        identity — not a process-local counter, so two APIP restarts (or two
        controllers) compiling the same decision derive the SAME sid and two
        different decisions can never collide by construction. The derivation
        is a counter: hash(decision_id) -> start, then scan forward past any
        sid already claimed by a DIFFERENT decision (from the ruleset text and
        this process's allocation cache), guaranteeing a free slot and stable
        recompiles.
        """
        base = int.from_bytes(
            hashlib.sha256(f"{decision_id}".encode()).digest()[:4], "big")
        candidate = _SURICATA_RULE_START_SID + (base % 900_000)   # 9100000..9999999
        claimed: dict[str, str] = {}   # sid -> owning line
        if rules_text:
            for line in rules_text.splitlines():
                sid = self._rule_sid(line)
                if sid is not None:
                    claimed[sid] = line
        if not hasattr(self, "_claimed_sids"):
            self._claimed_sids: dict[str, str] = {}   # decision_id -> sid
        prior = self._claimed_sids.get(decision_id)
        if prior is not None:
            line = claimed.get(prior)
            # this decision's own installed rule: recompiling to the same sid
            # is correct (apply replaces its own rule; crash-recovery path)
            if line is None or f"apip_decision {decision_id}" in line:
                if int(prior) >= _SURICATA_RULE_START_SID:
                    return int(prior)
        # scan wins: never allocate a sid occupied by a DIFFERENT rule
        while str(candidate) in claimed:
            candidate += 1
        self._claimed_sids[decision_id] = str(candidate)
        return candidate

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

    def validate(self, candidate: dict, *, check_scope: bool = True) -> dict:
        rule_id = candidate.get("rule_id", "")
        fragment = candidate.get("fragment", "")
        selector = candidate.get("selector") or {}
        if not rule_id.startswith("sid:"):
            raise AdapterError(f"invalid rule id {rule_id!r}")
        try:
            int(rule_id.split("sid:", 1)[1])
        except ValueError:
            raise AdapterError(f"invalid sid in rule id {rule_id!r}")
        # ruleset-injection guard: the fragment must be a SINGLE rule line.
        if "\n" in fragment or "\r" in fragment:
            raise AdapterError("fragment may not contain a newline (ruleset injection)")
        # selector-never-broadens: a destination must match the rule's exact
        # target. A pair/session-scoped IP selector with no boundable client
        # is refused (the adapter never broadens to destination-global); but an
        # fqdn pair-scoped http.host intent rule IS bound by its host field,
        # so it validates as long as the fragment carries that exact host.
        scope_type = selector.get("scope_type", "destination_global")
        dest = selector.get("destination")
        exact_ip = selector.get("exact_ip")
        if not any(k in fragment for k in ("apip_decision", "metadata:")):
            raise AdapterError("fragment missing decision metadata")
        # truthfulness: this adapter never emits an enforcing verb. A candidate
        # whose fragment carries drop/reject is refused — an IDS export cannot
        # be secretly upgraded to inline enforcement.
        first_word = fragment.split()[0].lower() if fragment.split() else ""
        if first_word in ("drop", "reject", "rejectboth", "rejectsrc", "rejectdst"):
            raise AdapterError(
                "suricata beta surface is IDS/export only: drop/reject rules "
                "are not published (ENFORCE unsupported)")
        if exact_ip is not None and not isinstance(exact_ip, str):
            raise AdapterError("selector exact_ip must be a string")
        if scope_type in _PAIR_SCOPED:
            if exact_ip is not None:
                raise AdapterError(
                    "suricata validate refuses a pair/session-scoped IP selector "
                    "(no boundable client; would broaden to destination-global)")
            # fqdn http.host intent: the host content field IS the exact pair
            # bound — never a bare `http any -> any any` broadcast.
            if not dest or f'content:"{dest}"' not in fragment:
                raise AdapterError(
                    "fqdn pair-scoped rule must carry http.host content bound "
                    "to the selector destination (never broadens)")
        # defense in depth layer 3 (scope): the adapter enforces its own
        # home-net boundary INDEPENDENTLY of policy/controller even at
        # validate time, so a candidate IP target outside the configured
        # authorized prefixes is refused here too — not only at compile.
        if exact_ip is not None:
            if check_scope and not self._in_adapter_scope(exact_ip):
                raise AdapterError(
                    f"target {exact_ip} outside adapter home-net scope "
                    f"{sorted(str(n) for n in self.config.suricata_authorized_prefixes)}")
            # selector-never-broadens: the exact target must be the single
            # address the rule actually fires on — never a wider parent.
            if f"-> {exact_ip} " not in fragment:
                raise AdapterError(
                    "fragment does not target the selector exact_ip (never broadens)")
        return {"ok": True, "mode": self._effective(candidate), "rule_id": rule_id}

    # -- apply / verify / revoke ---------------------------------------------------

    def _rules_path(self, shadow: bool = True) -> Path:
        name = (f"{self.config.suricata_rules_file}.rules" if shadow
                else f"{self.config.suricata_rules_file}.ips.rules")
        return self._rules_dir / name

    def _read_rules(self) -> str:
        p = self._rules_path()
        if p.is_file():
            return p.read_text(encoding="utf-8")
        return ""

    def _write_rules(self, lines: list[str]) -> str:
        import os
        self._rules_dir.mkdir(parents=True, exist_ok=True)
        content = "\n".join(lines) + "\n"
        tmp = self._rules_path().with_suffix(".rules.tmp")
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, self._rules_path())
        return content

    def apply(self, candidate: dict) -> dict:
        """Publish to the exported (shadow/IDS) ruleset. There is no reload
        step and no enforcement claim — the receipt records file bytes only
        (review P0 #4)."""
        checked = self.validate(candidate)
        rule_id = checked["rule_id"]
        eff = self._effective(candidate)
        if MODE_RANK[eff] < MODE_RANK["SHADOW"]:
            raise AdapterError(
                f"effective posture {eff} below SHADOW: refusing to publish")
        lines = self._read_rules().splitlines() if self._read_rules() else []
        sid_line = rule_id.split("sid:", 1)[1]
        lines = [l for l in lines if self._rule_sid(l) != sid_line]
        lines.append(candidate["fragment"])
        content = self._write_rules(lines)
        content_hash = hashlib.sha256(content.encode()).hexdigest()
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
                    "effective_mode": eff,
                    "monitoring_only": True,
                },
            },
        }

    def verify(self, candidate: dict) -> dict:
        """INDEPENDENT verification: the exported ruleset file actually holds
        the exact sid. This proves FILE STATE ONLY — never engine load state;
        the beta surface makes no enforcement claim (review P0 #4)."""
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
            "sid": sid_line, "rule_present": True,
            "monitoring_only": True}}

    def revoke(self, candidate: dict) -> dict:
        """Remove EXACTLY this sid; verify the ruleset no longer holds it. A
        missing ruleset counts as removed (idempotent). Ownership is
        structural (stored rule_id + exact selector shape) and the adapter's
        CURRENT scope never gates removal (review P0 #8): narrowing
        suricata_authorized_prefixes must not strand APIP's own installed
        rule — apply authorization and removal authorization differ."""
        checked = self.validate(candidate, check_scope=False)
        rule_id = checked["rule_id"]
        sid_line = rule_id.split("sid:", 1)[1]
        content = self._read_rules()
        if not content:
            return {"ok": True, "observed": {"removed": sid_line, "ruleset_absent": True}}
        lines = [l for l in content.splitlines() if self._rule_sid(l) != sid_line]
        if len(lines) == len(content.splitlines()):
            return {"ok": True, "observed": {"removed": sid_line, "was_absent": True}}
        self._write_rules(lines)
        after = self._read_rules()
        still = any(self._rule_sid(l) == sid_line for l in after.splitlines())
        if still:
            return {"ok": False, "error": "rule still present after revoke"}
        return {"ok": True, "observed": {
            "removed": sid_line,
            "rules_sha256": hashlib.sha256(after.encode()).hexdigest()}}

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
            "authorized_prefixes": sorted(str(n) for n in self.config.suricata_authorized_prefixes),
            "reload_configured": False,   # no reload path exists (beta truthfulness)
        }
        if self._mode == "OFF":
            base["status"] = "ok"
            base["note"] = "adapter OFF: compiles only"
            return base
        if self._rules_path().is_file():
            base["status"] = "ok"
        else:
            base["status"] = "ok"
            base["note"] = "ruleset not yet created (no applies yet)"
        return base

    def probe_startup(self) -> None:
        """Startup capability probe (audit P1 #13). SHADOW+ for Suricata is
        ruleset compilation only until a reload path exists (beta
        truthfulness), so the probe exercises exactly what is claimed: the
        artifact directory accepts writes."""
        if self._mode == "OFF":
            return
        from apip.adapters.base import AdapterError
        path = self._rules_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            probe = path.parent / ".apip-capability-probe"
            probe.write_text("probe", encoding="utf-8")
            probe.unlink()
        except OSError as e:
            raise AdapterError(
                f"suricata capability probe failed: rules dir "
                f"{path.parent} is not writable: {e}") from e
