"""Operator CLI (beta).

The CLI is an operator-facing front door to the controller API. It reads
read surfaces and issues state-changing actions through the same HTTP API the
controller exposes, so one authorization + ledger + scope path governs every
command. It never pokes the service internals directly.

Endpoints map ~1:1 to the API (health, source, ingest, indicator, decision,
action, policy, adapter, audit). Secrets/credentials come from the
environment (APIP_OPERATOR_TOKEN, per-source keys) — never from the command
line, so they don't leak into process lists or shell history.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import click
import httpx

DEFAULT_BASE = "http://127.0.0.1:8510"


class Client:
    def __init__(self, base: str | None = None, operator_token: str | None = None):
        self.base = (base or os.environ.get("APIP_BASE", DEFAULT_BASE)).rstrip("/")
        self.token = operator_token or os.environ.get("APIP_OPERATOR_TOKEN", "")
        self._h = httpx.Client(base_url=self.base, timeout=30.0,
                               headers={"Authorization":
                                         f"Bearer {self.token}"} if self.token else {})

    def _request(self, method: str, path: str, **kw) -> dict:
        r = self._h.request(method, path, **kw)
        if r.status_code == 401:
            raise click.ClickException("authentication failed — set APIP_OPERATOR_TOKEN")
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except Exception:
                detail = r.text
            raise click.ClickException(f"{method} {path} -> {r.status_code}: {detail}")
        try:
            return r.json()
        except Exception:
            return {"raw": r.text}

    def get(self, path: str, **kw) -> dict:
        return self._request("GET", path, **kw)

    def post(self, path: str, **kw) -> dict:
        return self._request("POST", path, **kw)


def _client(*, base=None, token=None) -> Client:
    return Client(base=base, operator_token=token)


def _table(rows: list[dict], cols: list[str]) -> None:
    if not rows:
        click.echo("(none)")
        return
    widths = {}
    for c in cols:
        header = c.upper() if False else c
        widths[c] = max(len(str(header)), *(len(str(r.get(c, ""))) for r in rows))
    click.echo("  ".join(str(c).ljust(widths[c]) for c in cols))
    click.echo("  ".join("-" * widths[c] for c in cols))
    for r in rows:
        click.echo("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))


@click.group()
@click.option("--base", envvar="APIP_BASE", default=None, help="controller API base URL")
@click.option("--token", envvar="APIP_OPERATOR_TOKEN", default=None,
              help="operator bearer token (prefer env)")
@click.version_option(package_name="apip-beta", prog_name="apip")
@click.pass_context
def cli(ctx: click.Context, base: str | None, token: str | None) -> None:
    """APIP operator CLI. Deterministic, AI-free defensive control plane."""
    ctx.ensure_object(dict)
    ctx.obj["base"] = base
    ctx.obj["token"] = token


# -- status -----------------------------------------------------------------

@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Overall controller + subsystem health (authenticated rich snapshot).

    Reads GET /status (operator token required); the unauthenticated
    /health is a bare liveness word with no component detail by design."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    h = api.get("/status")
    if not isinstance(h.get("components"), dict):
        click.echo(click.style("unknown status shape: " + str(h), fg="yellow"))
        return
    components = h["components"]
    click.echo(f"APIP {h.get('api_version','?')}")
    click.echo()
    click.echo(f"controller: {h.get('status', '?')}")
    click.echo(f"  database:    {components.get('database', {}).get('status', '?')}")
    pol = components.get("policy", {})
    click.echo(f"  policy:      {'active ' + str(pol.get('current')) if pol.get('loaded') else 'NONE LOADED'}")
    srcs = components.get("sources", {})
    click.echo(f"  sources:     {srcs.get('registered',0)} registered, {srcs.get('enabled',0)} enabled")
    ad = components.get("adapter", {})
    click.echo(f"  adapter:     {ad.get('name','?')} mode={ad.get('mode','?')} status={ad.get('status','?')}")
    q = components.get("queue", {})
    click.echo(f"  queue:       {q.get('pending_actions',0)} pending actions")
    acts = h.get("actions", {})
    click.echo()
    click.echo("actions:")
    for k in ("pending", "active", "failed", "expired", "revoked"):
        click.echo(f"  {k:<10} {acts.get(k, 0)}")
    deg = h.get("degraded", [])
    if deg:
        click.echo()
        click.echo("DEGRADED:")
        for d in deg:
            click.echo(f"  - {d}")
        sys.exit(2)


# -- source -------------------------------------------------------------

@cli.group()
def source() -> None:
    """Manage ingest sources."""


@source.command("list")
@click.pass_context
def source_list(ctx: click.Context) -> None:
    """List registered sources."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    rows = api.get("/sources").get("sources", [])
    _table(rows, ["source_id", "source_class", "independent", "auto_enforcement_allowed",
                  "enabled", "health", "last_success_at"])


@source.command("show")
@click.argument("source_id")
@click.pass_context
def source_show(ctx: click.Context, source_id: str) -> None:
    """Show one source incl. allowed kinds + provenance."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    src = api.get(f"/sources/{source_id}").get("source", {})
    for k, v in src.items():
        click.echo(f"{k:<24} {v}")


@source.command("enable")
@click.argument("source_id")
@click.pass_context
def source_enable(ctx: click.Context, source_id: str) -> None:
    """Enable an ingest source."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    api.post(f"/sources/{source_id}/enable")
    click.echo(f"source {source_id} enabled")


@source.command("disable")
@click.argument("source_id")
@click.pass_context
def source_disable(ctx: click.Context, source_id: str) -> None:
    """Disable an ingest source."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    api.post(f"/sources/{source_id}/disable")
    click.echo(f"source {source_id} disabled")


@source.command("register")
@click.argument("source_id")
@click.option("--class", "source_class", default="local",
              help="source class: local|curated|community|annotation")
@click.option("--independent/--no-independent", default=False,
              help="source is independent for corroboration counting")
@click.option("--no-auto-enforce", is_flag=True, default=False,
              help="this source's evidence may not drive auto-enforcement")
@click.option("--upstream", default=None,
              help="upstream source ids this channel proven to carry (comma-sep)")
@click.option("--provenance-note", default="", help="free-text provenance")
@click.pass_context
def source_register(ctx: click.Context, source_id: str, source_class: str,
                    independent: bool, no_auto_enforce: bool,
                    upstream: str | None, provenance_note: str) -> None:
    """Register an ingest source. Prints the one-time source secret key —
    store it now (it is not retrievable again)."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    r = api.post("/sources/register", json={
        "source_id": source_id,
        "source_class": source_class,
        "independent": independent,
        "auto_enforcement_allowed": not no_auto_enforce,
        "upstream": upstream,
        "provenance_note": provenance_note,
    })
    click.echo(f"registered {r['source_id']}")
    click.echo(f"  source_key (store securely): {r['source_key']}")
    click.echo(f"  {r.get('note','')}")


@source.command("rotate")
@click.argument("source_id")
@click.pass_context
def source_rotate(ctx: click.Context, source_id: str) -> None:
    """Rotate a source's credential (prints the new one-time secret key)."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    r = api.post(f"/sources/{source_id}/rotate")
    click.echo(f"rotated credential for {r['source_id']}")
    click.echo(f"  source_key (store securely): {r['source_key']}")
    click.echo(f"  {r.get('note','')}")


# -- ingest -------------------------------------------------------------

@cli.command("ingest")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--source-key", envvar=None, default=None,
              help="source secret key (prefer the per-source env var)")
@click.option("--source", "source_env", default=None,
              help="configures --source-key from APIP_SOURCE_<ID>_KEY")
@click.pass_context
def ingest_file(ctx: click.Context, path: str, source_key: str | None,
                source_env: str | None) -> None:
    """Ingest an indicator JSON file from an authenticated source.

    Source identity is bound to the presented key, never the payload. Use
    --source <id> to pull the key from APIP_SOURCE_<ID>_KEY.
    """
    if source_env:
        source_key = os.environ.get(f"APIP_SOURCE_{source_env.upper()}_KEY")
        if not source_key:
            raise click.ClickException(
                f"no APIP_SOURCE_{source_env.upper()}_KEY env var set")
    if not source_key:
        raise click.ClickException(
            "a source key is required: --source-key or --source <id> with env")
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    data = Path(path).read_bytes()
    r = api._request("POST", "/ingest",
                     content=data,
                     headers={"x-apip-source-key": source_key})
    click.echo(f"batch {r.get('batch_id')}: {r.get('indicators')} indicators, "
               f"{r.get('demoted_records')} demoted, replay={r.get('replay')}")


# -- indicator -------------------------------------------------------------

@cli.group()
def indicator() -> None:
    """Query indicators."""


@indicator.command("list")
@click.option("--limit", default=50, type=int)
@click.pass_context
def indicator_list(ctx: click.Context, limit: int) -> None:
    """List indicators."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    rows = api.get("/indicators", params={"limit": limit}).get("indicators", [])
    _table(rows, ["indicator_id", "itype", "value", "first_seen", "last_seen"])


@indicator.command("show")
@click.argument("indicator_id")
@click.pass_context
def indicator_show(ctx: click.Context, indicator_id: str) -> None:
    """Show an indicator and its evidence."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    data = api.get(f"/indicators/{indicator_id}")
    ind = data.get("indicator", {})
    click.echo(f"indicator: {ind.get('indicator_id')} ({ind.get('itype')})")
    click.echo(f"  value: {ind.get('value')}")
    click.echo(f"  sources: {ind.get('sources')}")
    click.echo("evidence:")
    for ev in data.get("evidence", []):
        click.echo(f"  - {ev.get('kind')} source={ev.get('source_id')} "
                   f"obs={ev.get('observed_at')} detail={ev.get('detail')}")


# -- decision -------------------------------------------------------------

@cli.group()
def decision() -> None:
    """Inspect decisions and explanations."""


@decision.command("list")
@click.option("--limit", default=50, type=int)
@click.option("--disposition", default=None)
@click.pass_context
def decision_list(ctx: click.Context, limit: int, disposition: str | None) -> None:
    """List decisions (optionally filtered by disposition)."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    params: dict[str, str | int] = {"limit": limit}
    if disposition:
        params["disposition"] = disposition
    rows = api.get("/decisions", params=params).get("decisions", [])
    _table(rows, ["decision_id", "disposition", "maliciousness", "action",
                  "indicator_id", "created_at"])


@decision.command("show")
@click.argument("decision_id")
@click.pass_context
def decision_show(ctx: click.Context, decision_id: str) -> None:
    """Show one decision incl. reason codes + policy binding."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    data = api.get(f"/decisions/{decision_id}")
    d = data.get("decision", {})
    click.echo(f"decision {d.get('decision_id')}")
    click.echo(f"  indicator: {d.get('indicator_id')}")
    click.echo(f"  disposition: {d.get('disposition')}")
    click.echo(f"  maliciousness: {d.get('maliciousness')}  "
               f"action_safety: {d.get('action_safety')}  action: {d.get('action')}")
    click.echo(f"  reason_codes: {d.get('reason_codes')}")
    click.echo(f"  seq: {d.get('seq')}  content_hash: {d.get('content_hash')}")
    click.echo(f"  policy: {d.get('policy_version')} "
               f"content_sha256={d.get('policy_content_sha256')}")
    click.echo("evidence:")
    for ev in data.get("evidence", []):
        click.echo(f"  - {ev.get('kind')} source={ev.get('source_id')} obs={ev.get('observed_at')}")


@decision.command("explain")
@click.argument("decision_id")
@click.pass_context
def decision_explain(ctx: click.Context, decision_id: str) -> None:
    """Human-readable why: disposition, score, reason codes, evidence, policy."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    data = api.get(f"/decisions/{decision_id}")
    d = data.get("decision", {})
    click.echo(f"Why APIP reaches {d.get('disposition')} for {d.get('indicator_id')}:")
    click.echo(f"  composite maliciousness m={d.get('maliciousness')} "
               f"action_safety s={d.get('action_safety')}")
    click.echo(f"  reason codes: {', '.join(d.get('reason_codes') or [])}")
    click.echo(f"  action: {d.get('action')} (ttl_seconds={d.get('ttl_seconds')})")
    click.echo(f"  authorized by policy {d.get('policy_version')} "
               f"({d.get('policy_content_sha256')})")
    click.echo("evidence contributing:")
    for ev in data.get("evidence", []):
        kind, sid = ev.get("kind"), ev.get("source_id")
        click.echo(f"  - {kind} from {sid} observed {ev.get('observed_at')}")
    click.echo()
    click.echo("No AI/ML was involved anywhere on this path (deterministic policy engine).")


@decision.command("approve")
@click.argument("decision_id")
@click.pass_context
def decision_approve(ctx: click.Context, decision_id: str) -> None:
    """Compile a PROPOSE_OPERATOR_APPROVAL decision into action(s).

    The decision is rebuilt from ledger state (never re-decided), re-checked
    against the active policy scope, and compiled through every configured
    adapter. Audited with the operator identity.
    """
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    r = api.post(f"/decisions/{decision_id}/approve")
    click.echo(f"approved {decision_id} -> {len(r.get('action_ids', []))} action(s)")
    for aid in r.get("action_ids", []):
        click.echo(f"  {aid}")


@decision.command("replay")
@click.pass_context
def decision_replay(ctx: click.Context) -> None:
    """Re-run every indicator through the active policy (post-promote
    re-baseline). Appends decisions only; acts happen from the worklist."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    r = api.post("/policy/replay")
    click.echo(f"replayed {r.get('indicators')} indicators "
               f"-> {r.get('recorded')} new decision(s), "
               f"{r.get('changed')} changed verdict(s)")
    click.echo(f"against policy {r.get('policy_version')}")


@decision.command("interop")
@click.argument("decision_id")
@click.option("--format", "fmt", type=click.Choice(["openc2", "cacao", "ocsf", "all"]),
              default="all", show_default=True)
@click.pass_context
def decision_interop(ctx: click.Context, decision_id: str, fmt: str) -> None:
    """Emit a decision as OpenC2 / CACAO / OCSF (interop, write-only)."""
    from apip.domain.models import ActionSelector, Decision
    from apip.interop import decision_to_cacao, decision_to_ocsf, decision_to_openc2

    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    d = api.get(f"/decisions/{decision_id}").get("decision", {})
    if not d:
        raise click.ClickException(f"no such decision {decision_id}")
    sel_row = d.get("selector") or {}
    sel = None
    if sel_row:
        kwargs = {k: sel_row[k] for k in (
            "scope_type", "client", "destination", "protocol_class",
            "host", "rate_ceiling_per_min") if k in sel_row}
        sel = ActionSelector(**kwargs)
    decision = Decision(
        id=d["decision_id"], indicator_id=d.get("indicator_id", ""),
        maliciousness=int(d.get("maliciousness", 0) or 0),
        action_safety=int(d.get("action_safety", 0) or 0),
        disposition=d.get("disposition", ""), action=d.get("action", ""),
        rung=d.get("rung", "NONE"), scope=d.get("scope", ""),
        ttl_seconds=int(d.get("ttl_seconds", 0) or 0),
        policy_version=d.get("policy_version", ""),
        reason_codes=tuple(d.get("reason_codes") or ()),
        explanation=d.get("explanation", ""), selector=sel,
        randomization=d.get("randomization"),
        content_hash=d.get("content_hash") or "")
    emit = {
        "openc2": decision_to_openc2,
        "cacao": decision_to_cacao,
        "ocsf": decision_to_ocsf,
    }
    for name, fn in emit.items():
        if fmt != "all" and fmt != name:
            continue
        click.echo(f"--- {name} ---")
        click.echo(fn(decision))


# -- action -------------------------------------------------------------

@cli.group()
def action() -> None:
    """Inspect and control compiled actions."""


@action.command("list")
@click.option("--limit", default=50, type=int)
@click.option("--state", default=None)
@click.pass_context
def action_list(ctx: click.Context, limit: int, state: str | None) -> None:
    """List actions (optionally filtered by FSM state)."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    params: dict[str, str | int] = {"limit": limit}
    if state:
        params["state"] = state
    rows = api.get("/actions", params=params).get("actions", [])
    _table(rows, ["action_id", "adapter", "mode", "rule_id", "state",
                  "expires_at", "verified_at"])


@action.command("show")
@click.argument("action_id")
@click.pass_context
def action_show(ctx: click.Context, action_id: str) -> None:
    """Show one action + every adapter receipt (no fabricated success)."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    data = api.get(f"/actions/{action_id}")
    a = data.get("action", {})
    click.echo(f"action {a.get('action_id')}  state={a.get('state')}")
    click.echo(f"  adapter={a.get('adapter')} mode={a.get('mode')} type={a.get('action_type')}")
    click.echo(f"  rule_id={a.get('rule_id')}")
    click.echo(f"  decision={a.get('decision_id')} indicator={a.get('indicator_id')}")
    click.echo(f"  requested_by={a.get('requested_by')} created={a.get('created_at')}")
    click.echo(f"  expires={a.get('expires_at')} verified={a.get('verified_at')}")
    click.echo(f"  state_reason={a.get('state_reason')}")
    click.echo("receipts:")
    for rec in data.get("receipts", []):
        click.echo(f"  - {rec.get('status')} {rec.get('receipt_id')} "
                   f"observed={rec.get('observed')} verified={rec.get('verified')}")


@action.command("revoke")
@click.argument("action_id")
@click.pass_context
def action_revoke(ctx: click.Context, action_id: str) -> None:
    """Revoke an action through the SAME controlled path as expiry."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    r = api.post(f"/actions/{action_id}/revoke")
    click.echo(f"revoke -> state={r.get('state')} verified={r.get('verified')} "
               f"already_terminal={r.get('already_terminal', False)}")


# -- policy -------------------------------------------------------------

@cli.group()
def policy() -> None:
    """Respect policy lifecycle: validate -> stage -> promote."""


@policy.command("validate")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.pass_context
def policy_validate(ctx: click.Context, path: str) -> None:
    """Validate a TOML policy file without staging it."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    r = api.post("/policy/validate", json={"text": Path(path).read_text()})
    click.echo(f"ok={r.get('ok')}")
    for p in r.get("problems", []):
        click.echo(f"  - {p}")


@policy.command("show")
@click.pass_context
def policy_show(ctx: click.Context) -> None:
    """Show the currently active policy version."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    current = api.get("/policy").get("current", {})
    if not current:
        click.echo("(no active policy)")
        return
    click.echo(f"policy {current.get('policy_version')}@r{current.get('revision')}")
    click.echo(f"  status={current.get('status')} mode={current.get('mode')}")
    click.echo(f"  staged_by={current.get('staged_by')} staged_at={current.get('staged_at')}")
    click.echo(f"  promoted_by={current.get('promoted_by')} promoted_at={current.get('promoted_at')}")
    click.echo(f"  content_sha256={current.get('content_sha256')}")
    click.echo("--- raw TOML ---")
    click.echo(current.get("raw_text", ""))


@policy.command("stage")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--version", default="beta")
@click.option("--mode", default="SHADOW")
@click.pass_context
def policy_stage(ctx: click.Context, path: str, version: str, mode: str) -> None:
    """Validate + stage a policy. A malformed policy is rejected, never staged usable."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    r = api.post("/policy/stage", json={"text": Path(path).read_text(),
                                        "version": version, "mode": mode})
    for p in r.get("problems", []):
        click.echo(f"  PROBLEM: {p}")
    if r.get("accepted"):
        click.echo(f"staged {version}@r{r.get('revision')} sha256={r.get('content_sha256')}")
        click.echo("now: apip policy promote --version %s --revision %d"
                   % (version, int(r.get("revision", 0))))
    else:
        raise click.ClickException("policy did not validate; not staged")


@policy.command("promote")
@click.option("--version", default="beta")
@click.option("--revision", required=True, type=int)
@click.pass_context
def policy_promote(ctx: click.Context, version: str, revision: int) -> None:
    """Promote a staged policy to active. Retires the prior active version."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    r = api.post("/policy/promote", json={"version": version, "revision": revision})
    click.echo(f"promoted {r.get('version')}@r{r.get('revision')} active={r.get('active')}")


@policy.command("history")
@click.pass_context
def policy_history(ctx: click.Context) -> None:
    """Show the full policy version history."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    rows = api.get("/policy/history").get("history", [])
    _table(rows, ["policy_version", "revision", "status", "mode", "content_sha256",
                  "staged_by", "promoted_by"])


# -- adapter -------------------------------------------------------------

@cli.group()
def adapter() -> None:
    """Query enforcement adapter status."""


@adapter.command("list")
@click.pass_context
def adapter_list(ctx: click.Context) -> None:
    """List every configured enforcement adapter (RPZ, Suricata/IPS, ...)."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    for h in api.get("/adapters").get("adapters", []):
        click.echo(f"{h.get('name','?'):<12} mode={h.get('mode','?')} "
                   f"status={h.get('status','?')} max={h.get('max_mode','?')}")


@adapter.command("status")
@click.argument("name")
@click.pass_context
def adapter_status(ctx: click.Context, name: str) -> None:
    """Show detailed status for one adapter (default policy query)."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    h = api.get(f"/adapters/{name}").get("adapter", {})
    for k, v in h.items():
        click.echo(f"{k:<22} {v}")


# -- audit -------------------------------------------------------------

@cli.command("audit")
@click.option("--limit", default=100, type=int)
@click.pass_context
def audit(ctx: click.Context, limit: int) -> None:
    """Show the append-only audit trail."""
    api = _client(base=ctx.obj["base"], token=ctx.obj["token"])
    rows = api.get("/audit", params={"limit": limit}).get("audit", [])
    _table(rows, ["event_id", "at", "actor", "event_type", "subject", "detail"])


# -- lifecycle ---------------------------------------------------------------

@cli.command()
@click.option("--config", default=None, envvar="APIP_CONFIG",
              help="path to apip.toml (else defaults + env secrets)")
def serve(config: str | None) -> None:
    """Run the long-running controller + operator HTTP API.

    Starts the controller workers (dispatch, reconcile/expiry/verify) and
    serves the operator API that the CLI talks to. Security state lives in
    the durable ledger, not this process, so a restart loses nothing.
    """
    import uvicorn
    from apip.api.app import build_app
    from apip.config.service import load_config
    from apip.controller.service import Controller

    cfg = load_config(config)
    controller = Controller(cfg)
    controller.start()   # brings up DB, migrates, starts worker threads
    try:
        app = build_app(cfg, controller=controller)
        uvicorn.run(app, host=cfg.api_host, port=cfg.api_port, log_level="info")
    finally:
        controller.stop()


@cli.command("migrate")
@click.option("--config", default=None, envvar="APIP_CONFIG")
@click.option("--wait-db", default=30.0, type=float,
              help="seconds to wait for the database before failing")
def migrate(config: str | None, wait_db: float) -> None:
    """Apply database migrations (idempotent) to the durable ledger.

    Safe to run repeatedly; applies any pending schema migration and then
    exits. The controller applies them automatically on start, but running
    this explicitly first is fine.
    """
    from apip.config.service import load_config
    from apip.ledger.db import Database
    from apip.ledger.migrations import apply_migrations

    cfg = load_config(config)
    db = Database(cfg.db.dsn_kwargs())
    db.wait_until_ready(timeout_s=wait_db)
    applied = apply_migrations(db)
    db.close()
    click.echo(f"migrations applied: {applied}")


if __name__ == "__main__":
    cli()