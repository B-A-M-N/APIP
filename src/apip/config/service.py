"""Service configuration (ordinary config — NOT secrets, NOT policy).

Layering, lowest to highest precedence:
  1. built-in defaults (fail-safe: SHADOW, loopback bind, RPZ shadow zone);
  2. TOML config file (``[apip]``-less flat sections);
  3. environment variables (``APIP_`` prefix).

Secrets are NEVER part of this module's file format. Every secret is read
from the environment or a ``_FILE``-conventional file (Docker secrets):
  APIP_DB_PASSWORD / APIP_DB_PASSWORD_FILE
  APIP_OPERATOR_TOKEN / APIP_OPERATOR_TOKEN_FILE
  APIP_SECRET_KEY / APIP_SECRET_KEY_FILE       (credential hashing pepper)

Rule of thumb enforced by review + tests: nothing in a config FILE can
authenticate anything.
"""
from __future__ import annotations

from typing import Any
from dataclasses import dataclass, field
from pathlib import Path
import os
import string
import tomllib


class ConfigError(ValueError):
    pass


def _safe_actor_id(value: str) -> bool:
    """Operator actor ids land in audit rows and logs; keep them to the
    same ASCII-only closed charset as source ids (no homoglyph look-alike
    identities)."""
    return bool(value) and all(
        (c in string.ascii_letters or c in string.digits or c in "_-")
        for c in value) and not value.isdigit()


def _secret(env_key: str, what: str) -> str | None:
    """Read a secret from the environment or its _FILE variant. Never from a
    config file."""
    direct = os.environ.get(env_key)
    if direct:
        return direct
    file_path = os.environ.get(env_key + "_FILE")
    if file_path:
        p = Path(file_path)
        if not p.is_file():
            raise ConfigError(f"{what}: {env_key}_FILE={file_path} is not a file")
        value = p.read_text(encoding="utf-8").strip()
        if value:
            return value
    return None


@dataclass(frozen=True)
class DatabaseConfig:
    host: str = "/var/run/postgresql"   # unix socket dir by default
    port: int = 5432
    dbname: str = "apip"
    user: str = "apip"
    password: str | None = None         # from env only
    connect_timeout_s: int = 5

    def dsn_kwargs(self) -> dict:
        kw = dict(host=self.host, port=self.port, dbname=self.dbname,
                  user=self.user, connect_timeout=self.connect_timeout_s,
                  application_name="apip-controller")
        if self.password:
            kw["password"] = self.password
        return kw


@dataclass(frozen=True)
class ControllerConfig:
    # Reconciliation loop cadence (seconds): expiry sweep, pending dispatch,
    # verification passes.
    reconcile_interval_s: float = 15.0
    # Verify active actions at least this often (seconds).
    verify_interval_s: float = 300.0
    # Default TTL applied to actions whose policy TTL is 0/absent (seconds).
    default_action_ttl_s: int = 3600
    # Maximum TTL the controller will honor (seconds) — hard ceiling.
    max_action_ttl_s: int = 86400
    # Behavioral telemetry (audit #17): a Suricata EVE JSON file to tail as
    # the live behavioral datasource. Empty = no live telemetry source (the
    # detectors stay inert; health says so honestly). When set, the
    # controller runs the checkpointed EVE reader on its lifecycle and
    # attaches emitted detections to ingested indicators each reconcile
    # pass.
    suricata_eve_path: str = ""
    # Behavioral families the live feed may detect (audit #23's twin: the
    # live feed's enabled set must mirror the policy's, not silently exceed
    # it). Empty = derive from the active policy at start.
    behavioral_enabled_families: tuple[str, ...] = ()


@dataclass(frozen=True)
class AdapterConfig:
    """Adapter settings. Each `*_mode` is the ADAPTER's own maximum posture
    for that actuator: the controller may not dispatch an action stronger
    than the adapter it is routed to."""
    # -- DNS RPZ -----------------------------------------------------------
    rpz_mode: str = "SHADOW"            # OFF | OBSERVE | SHADOW | ENFORCE
    zone_dir: str = "/var/lib/apip/rpz"
    zone_name: str = "apip.shadow.invalid"
    # Reload command; empty = file-only publish (verification reads the file).
    reload_command: str = ""
    # Namespaces this deployment is authorized to control (defense in depth
    # layer 3; the policy boundary is layer 1+2). Empty = adapter OFF for
    # enforcement regardless of mode.
    authorized_domains: tuple[str, ...] = ()
    verify_query_server: str = ""       # resolver to query for live verify
    verify_query_port: int = 53
    verify_timeout_s: float = 3.0
    # Total budget for one rollback verification loop (audit P0 #2). Resolvers
    # rate-limit RPZ policy-zone updates against the SOA timers ("zone version
    # came too soon" defers the load), so this must cover a worst-case deferral
    # — several multiples of the zone's refresh timer — not just one query.
    revoke_verify_budget_s: float = 75.0
    # Whole-artifact validation before publication (audit P1 #14): a
    # configurable trusted parser command (argv template; e.g.
    # "named-checkzone {zone} {file}") run against the COMPLETE new
    # generation in its temp file. A non-zero exit refuses the publish —
    # the live artifact is never replaced by a zone the real parser
    # rejects. Empty = structural validation only.
    zone_validate_command: str = ""
    # -- Suricata IPS / file exporter --------------------------------------
    suricata_mode: str = "OFF"          # OFF | OBSERVE | SHADOW | ENFORCE
    suricata_rules_dir: str = "/var/lib/apip/suricata"
    suricata_rules_file: str = "apip.rules"
    suricata_reload_command: str = ""   # empty = file-only publish
    # Home-net scope (defense in depth L3): only IP literals inside one of
    # these prefixes may be denied/limited by the Suricata adapter. Exact
    # /32,/128 only — the adapter never invents a CIDR deny. Empty = adapter
    # OFF for any IP enforcement regardless of mode (authorize-by-omission
    # is impossible at the enforcement edge).
    suricata_authorized_prefixes: tuple[str, ...] = ()


# Audit #30: ONE shared default API port for the server AND the CLI. The
# documented bare-metal sequence `apip serve` then `apip status` must work
# with defaults on both sides.
DEFAULT_API_PORT = 8510


@dataclass(frozen=True)
class ServiceConfig:
    db: DatabaseConfig = field(default_factory=DatabaseConfig)
    controller: ControllerConfig = field(default_factory=ControllerConfig)
    adapter: AdapterConfig = field(default_factory=AdapterConfig)
    api_host: str = "127.0.0.1"
    api_port: int = DEFAULT_API_PORT
    # Ingest caps (mirror the reference ingest boundary).
    # service-level ingest maximum (P1 #28); the parser enforces the
    # non-configurable ABSOLUTE ceiling (512 MiB) on top of this
    max_ingest_bytes: int = 10 * 1024 * 1024
    operator_token: str | None = None   # from env only
    # Audit #33: NAMED operator principals. Mapping of immutable actor id ->
    # bearer token. Empty = single-operator mode (the shared token acts as
    # "operator", and the deployment is documented as strictly
    # single-operator). Populated from APIP_OPERATOR_TOKENS as
    # "actor_id:token" pairs separated by commas/whitespace.
    operator_tokens: dict[str, str] = field(default_factory=dict)
    secret_key: str | None = None       # from env only


def _get(raw: dict[str, Any], path: str, default: Any) -> Any:
    cur = raw
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _env_layered(raw: dict[str, Any], path: str, env: str, default: Any,
                 cast=None) -> Any:
    """Ordinary configuration layering (review P1 #23): TOML value, else the
    documented APIP_* environment override, else the default — the
    precedence the module documents (defaults -> TOML -> env)."""
    import os as _os
    val = _os.environ.get(env)
    if val is not None and val != "":
        return val
    got = _get(raw, path, default)
    if cast is not None and got is not default:
        return cast(got)
    return got


def load_config(path: str | Path | None = None) -> ServiceConfig:
    raw: dict[str, Any] = {}
    if path:
        with open(path, "rb") as f:
            raw = tomllib.load(f)

    db = DatabaseConfig(
        host=str(_env_layered(raw, "database.host", "APIP_DB_HOST",
                              "/var/run/postgresql")),
        port=int(_env_layered(raw, "database.port", "APIP_DB_PORT", 5432,
                              int)),
        dbname=str(_env_layered(raw, "database.dbname", "APIP_DB_NAME",
                                "apip")),
        user=str(_env_layered(raw, "database.user", "APIP_DB_USER", "apip")),
        connect_timeout_s=int(_env_layered(raw, "database.connect_timeout_s",
                                           "APIP_DB_CONNECT_TIMEOUT_S", 5,
                                           int)),
    )
    controller = ControllerConfig(
        reconcile_interval_s=float(_get(raw, "controller.reconcile_interval_s", 15.0)),
        verify_interval_s=float(_get(raw, "controller.verify_interval_s", 300.0)),
        default_action_ttl_s=int(_get(raw, "controller.default_action_ttl_s", 3600)),
        max_action_ttl_s=int(_get(raw, "controller.max_action_ttl_s", 86400)),
        suricata_eve_path=str(_get(raw, "controller.suricata_eve_path", "")),
        behavioral_enabled_families=tuple(
            str(f) for f in
            (_get(raw, "controller.behavioral_enabled_families", None)
             or ())),
    )
    adapter = AdapterConfig(
        rpz_mode=str(_get(raw, "adapter.rpz_mode", "SHADOW")).upper(),
        zone_dir=str(_get(raw, "adapter.zone_dir", "/var/lib/apip/rpz")),
        zone_name=str(_get(raw, "adapter.zone_name", "apip.shadow.invalid")),
        reload_command=str(_get(raw, "adapter.reload_command", "")),
        authorized_domains=tuple(
            str(d).strip().lower().rstrip(".")
            for d in (_get(raw, "adapter.authorized_domains", ()) or ())),
        verify_query_server=str(_get(raw, "adapter.verify_query_server", "")),
        verify_query_port=int(_get(raw, "adapter.verify_query_port", 53)),
        verify_timeout_s=float(_get(raw, "adapter.verify_timeout_s", 3.0)),
        revoke_verify_budget_s=float(
            _get(raw, "adapter.revoke_verify_budget_s", 75.0)),
        zone_validate_command=str(
            _get(raw, "adapter.zone_validate_command", "")),
        suricata_mode=str(_get(raw, "adapter.suricata_mode", "OFF")).upper(),
        suricata_rules_dir=str(_get(raw, "adapter.suricata_rules_dir", "/var/lib/apip/suricata")),
        suricata_rules_file=str(_get(raw, "adapter.suricata_rules_file", "apip.rules")),
        suricata_reload_command=str(_get(raw, "adapter.suricata_reload_command", "")),
        suricata_authorized_prefixes=tuple(
            str(p).strip()
            for p in (_get(raw, "adapter.suricata_authorized_prefixes", ()) or ())),
    )
    cfg = ServiceConfig(
        db=db, controller=controller, adapter=adapter,
        api_host=str(_env_layered(raw, "api.host", "APIP_API_HOST",
                                  "127.0.0.1")),
        api_port=int(_env_layered(raw, "api.port", "APIP_API_PORT",
                                  DEFAULT_API_PORT, int)),
        max_ingest_bytes=int(_env_layered(raw, "ingest.max_bytes",
                                          "APIP_INGEST_MAX_BYTES",
                                          10 * 1024 * 1024, int)),
    )

    modes = {"OFF", "OBSERVE", "SHADOW", "ENFORCE"}
    if cfg.adapter.rpz_mode not in modes:
        raise ConfigError(f"adapter.rpz_mode must be one of OFF/OBSERVE/SHADOW/ENFORCE, "
                          f"got {cfg.adapter.rpz_mode!r}")
    if cfg.adapter.suricata_mode not in modes:
        raise ConfigError(f"adapter.suricata_mode must be one of OFF/OBSERVE/SHADOW/ENFORCE, "
                          f"got {cfg.adapter.suricata_mode!r}")
    # Home-net scope prefixes must parse as networks; refuse garbage config
    # rather than silently authorizing-by-omission at the enforcement edge.
    import ipaddress as _ipa
    for p in cfg.adapter.suricata_authorized_prefixes:
        try:
            _ipa.ip_network(p, strict=False)
        except ValueError:
            raise ConfigError(f"adapter.suricata_authorized_prefixes entry {p!r} "
                              f"is not a valid IP network")
    if cfg.controller.reconcile_interval_s <= 0 or cfg.controller.verify_interval_s <= 0:
        raise ConfigError("controller intervals must be positive")
    if cfg.controller.max_action_ttl_s < cfg.controller.default_action_ttl_s:
        raise ConfigError("controller.max_action_ttl_s must be >= default_action_ttl_s")
    if cfg.controller.max_action_ttl_s <= 0 or cfg.controller.default_action_ttl_s <= 0:
        raise ConfigError("controller TTL values must be positive (P1 #27)")
    if cfg.max_ingest_bytes <= 0:
        raise ConfigError("ingest.max_bytes must be positive")

    # Secrets: environment / secret-file only.
    import dataclasses
    cfg = dataclasses.replace(
        cfg,
        operator_token=_secret("APIP_OPERATOR_TOKEN", "operator token"),
        secret_key=_secret("APIP_SECRET_KEY", "secret key"),
    )
    # Audit #33: named operator principals. APIP_OPERATOR_TOKENS carries
    # "actor_id:token" pairs (comma/whitespace separated), e.g.
    #   APIP_OPERATOR_TOKENS="alice:hex1,bob:hex2"
    # Actor ids are immutable audit identities: every audit event records
    # WHICH principal acted, not just "operator". Tokens are never logged.
    raw_tokens = os.environ.get("APIP_OPERATOR_TOKENS", "").strip()
    if raw_tokens:
        principals: dict[str, str] = {}
        for pair in raw_tokens.replace("\n", ",").replace(" ", ",").split(","):
            pair = pair.strip()
            if not pair:
                continue
            actor_id, sep, token = pair.partition(":")
            actor_id, token = actor_id.strip(), token.strip()
            if not sep or not actor_id or not token:
                raise ConfigError(
                    "APIP_OPERATOR_TOKENS entries must be actor_id:token "
                    f"pairs (got {actor_id!r})")
            if not _safe_actor_id(actor_id):
                raise ConfigError(
                    f"unsafe operator actor id {actor_id!r} in "
                    "APIP_OPERATOR_TOKENS")
            if actor_id in principals:
                raise ConfigError(
                    f"duplicate operator actor id {actor_id!r} in "
                    "APIP_OPERATOR_TOKENS")
            principals[actor_id] = token
        if principals:
            cfg = dataclasses.replace(cfg, operator_tokens=principals)
    db_password = _secret("APIP_DB_PASSWORD", "database password")
    if db_password:
        cfg = dataclasses.replace(cfg, db=DatabaseConfig(
            host=cfg.db.host, port=cfg.db.port, dbname=cfg.db.dbname,
            user=cfg.db.user, password=db_password,
            connect_timeout_s=cfg.db.connect_timeout_s))
    return cfg
