"""FastAPI application for the APIP operator API.

The CLI is the primary client. Everything that changes security state is
audited with the requesting operator identity and routed through the
controller so the same LEDGER + scope + idempotency invariants hold whether
the operator acts from the CLI or directly against the HTTP API.

Auth:
  - operator endpoints require the operator bearer token;
  - the ingest endpoint requires a registered SOURCE key on the channel and
    ignores any payload-declared source_id (channel-bound identity).
"""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status

from apip.auth import constant_time_equals, generate_source_key, hash_credential
from apip.config.service import ServiceConfig
from apip.controller.engine import DecisionPipeline
from apip.controller.service import Controller
from apip.ingest import IngestBatch, IngestChannel, IngestError, parse_indicator_payload
from apip.ledger.db import DatabaseUnavailable

API_VERSION = "0.1.0b1"


def _bearer_from(header: str | None) -> str:
    if not header or not header.startswith("Bearer "):
        return ""
    return header[len("Bearer "):].strip()


def _safe_source_id(value: str) -> bool:
    """Source ids are identifiers we insert into SQL and noise; keep them to
    a closed charset (letters, digits, _, -)."""
    return bool(value) and all(c.isalnum() or c in "_-" for c in value) \
        and not value.isdigit()


# Mirrors the DB CHECK constraint on sources.source_class (migrations.py).
# Validated here so an invalid class is a clean 400, not a Postgres violation.
_SOURCE_CLASSES = frozenset({"curated", "local", "community", "annotation",
                             "attribution"})


def build_app(config: ServiceConfig,
              controller: Controller | None = None) -> FastAPI:
    """Build the operator API. When `controller` is passed it is used as-is
    (caller owns its lifecycle); otherwise a fresh, unstarted controller is
    created for the service to manage."""
    app = FastAPI(title="APIP Operator API", version=API_VERSION,
                  description="Deterministic AI-free defensive control plane (beta).")
    controller = controller or Controller(config)

    # -- auth dependencies -------------------------------------------------------

    def _operator(authorization: str | None = Header(default=None)) -> dict:
        """Operator bearer-token auth for state-changing/read surfaces.

        Uses the *injected* config's operator token (sourced from env/secret
        at config build), never a re-read of os.environ at request time — so
        an explicitly constructed ServiceConfig is honored. A config with no
        token configured fails every operator call closed."""
        expected = config.operator_token or ""
        supplied = _bearer_from(authorization)
        if not expected or not constant_time_equals(expected, supplied):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "valid APIP_OPERATOR_TOKEN required")
        return {"actor": "operator"}

    INGEST_KEY_HEADER = "x-apip-source-key"

    def _ingest_source(x_apip_source_key: str = Header(default="")) -> dict:
        """Channel-bound ingest auth: the presented SOURCE key selects the
        identity. Never trusts a payload-declared source_id."""
        if not x_apip_source_key:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "x-apip-source-key required for ingest")
        row = controller.ledger.source_by_credential(x_apip_source_key)
        if row is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "unknown source key")
        if not row.get("enabled"):
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"source {row['source_id']} disabled")
        return row

    # -- source registration -----------------------------------------------------

    @app.post("/sources/register")
    def register_source(payload: dict, _op: dict = Depends(_operator)) -> dict:
        source_id = str(payload.get("source_id", "")).strip()
        source_class = str(payload.get("source_class", "local")).strip()
        independent = bool(payload.get("independent", False))
        auto_enf = bool(payload.get("auto_enforcement_allowed", True))
        upstream = (payload.get("upstream") or None)
        allowed = tuple(str(x) for x in payload.get("allowed_kinds", []) or [])
        provenance = str(payload.get("provenance_note", "")).strip()
        if source_id not in {"", "unregistered"} and not _safe_source_id(source_id):
            raise HTTPException(400, f"unsafe source_id {source_id!r}")
        if source_class not in _SOURCE_CLASSES:
            raise HTTPException(
                400, f"invalid source_class {source_class!r}; "
                     f"must be one of {sorted(_SOURCE_CLASSES)}")
        # one secret per source; only the hash is persisted
        secret = generate_source_key()
        controller.ledger.register_source(
            source_id=source_id, source_class=source_class,
            independent=independent, key_hash=hash_credential(secret),
            actor=_op["actor"], auto_enforcement_allowed=auto_enf,
            upstream=upstream, enabled=True, allowed_kinds=allowed,
            provenance_note=provenance)
        return {"source_id": source_id, "source_key": secret,
                "note": "store the key now; it is not retrievable again"}

    # -- ingest -------------------------------------------------------------

    @app.post("/ingest")
    async def ingest(request: Request, src: dict = Depends(_ingest_source)) -> dict:
        body = await request.body()
        channel = IngestChannel(
            source_id=src["source_id"],
            allowed_source_ids=frozenset(
                s for s in (src.get("upstream") or "").split(",") if s))
        try:
            batch = parse_indicator_payload(body, channel)
        except IngestError as e:
            raise HTTPException(400, str(e)) from e
        # idempotent batch: same bytes + same source => no-op (a replay).
        replay = controller.ledger.batch_exists(batch.batch_id)
        if not replay:
            controller.ledger.record_batch(
                batch_id=batch.batch_id, source_id=batch.source_id,
                raw_sha256=batch.raw_sha256, actor=src["source_id"],
                indicator_count=len(batch.indicators),
                demoted=batch.demoted_records, channel=src["source_id"])
            decide = DecisionPipeline(controller.ledger)
            for ind in batch.indicators:
                controller.ledger.upsert_indicator(ind, batch.batch_id)
                # decide independently per indicator; create actions for
                # actionable dispositions below
                result = decide.decide_indicator(
                    ind.id, actor=src["source_id"], batch_id=batch.batch_id)
                if result and result["decision"].disposition in (
                        "SHADOW_ACTION", "AUTO_ENFORCE"):
                    controller.create_action_from_decision(
                        result["decision"], ind.value, ind.type,
                        actor=src["source_id"])
            controller.ledger.touch_source_success(src["source_id"])
        return {"batch_id": batch.batch_id, "source_id": batch.source_id,
                "indicators": len(batch.indicators),
                "demoted_records": batch.demoted_records,
                "replay": replay}

    # -- health ---------------------------------------------------------------

    @app.get("/health")
    def health() -> dict:
        try:
            h = controller.health()
        except DatabaseUnavailable:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "database unavailable")
        out = dict(h)
        out["api_version"] = API_VERSION
        return out

    @app.get("/ready")
    def ready() -> dict:
        try:
            h = controller.health()
        except DatabaseUnavailable:
            raise HTTPException(503, "database unavailable")
        ok = h.get("status") == "ok"
        if not ok:
            raise HTTPException(503, {"status": h.get("status"),
                                      "degraded": h.get("degraded", [])})
        return {"status": "ready"}

    # -- operator read surfaces --------------------------------------------------

    @app.get("/sources")
    def list_sources(_op: dict = Depends(_operator)) -> dict:
        return {"sources": controller.ledger.list_sources()}

    @app.get("/sources/{source_id}")
    def get_source(source_id: str, _op: dict = Depends(_operator)) -> dict:
        row = controller.ledger.get_source(source_id)
        if row is None:
            raise HTTPException(404, f"no such source {source_id}")
        return {"source": row}

    @app.post("/sources/{source_id}/enable")
    def enable_source(source_id: str, _op: dict = Depends(_operator)) -> dict:
        ok = controller.ledger.set_source_enabled(source_id, True, _op["actor"])
        if not ok:
            raise HTTPException(404, f"no such source {source_id}")
        return {"source_id": source_id, "enabled": True}

    @app.post("/sources/{source_id}/disable")
    def disable_source(source_id: str, _op: dict = Depends(_operator)) -> dict:
        ok = controller.ledger.set_source_enabled(source_id, False, _op["actor"])
        if not ok:
            raise HTTPException(404, f"no such source {source_id}")
        return {"source_id": source_id, "enabled": False}

    @app.get("/indicators")
    def list_indicators(limit: int = 50, _op: dict = Depends(_operator)) -> dict:
        return {"indicators": controller.ledger.list_indicators(limit)}

    @app.get("/indicators/{indicator_id}")
    def get_indicator(indicator_id: str, _op: dict = Depends(_operator)) -> dict:
        ind = controller.ledger.get_indicator(indicator_id)
        if ind is None:
            raise HTTPException(404, f"no such indicator {indicator_id}")
        ev = controller.ledger.indicator_evidence(indicator_id)
        return {"indicator": ind, "evidence": ev}

    @app.get("/decisions")
    def list_decisions(limit: int = 50, disposition: str | None = None,
                       _op: dict = Depends(_operator)) -> dict:
        return {"decisions": controller.ledger.list_decisions(limit, disposition)}

    @app.get("/decisions/{decision_id}")
    def get_decision(decision_id: str, _op: dict = Depends(_operator)) -> dict:
        d = controller.ledger.get_decision(decision_id)
        if d is None:
            raise HTTPException(404, f"no such decision {decision_id}")
        ev = controller.ledger.get_decision_evidence(decision_id)
        return {"decision": d, "evidence": ev}

    @app.post("/decisions/{decision_id}/approve")
    def approve_decision(decision_id: str, _op: dict = Depends(_operator)) -> dict:
        """Operator approval of a PROPOSE_OPERATOR_APPROVAL decision into one
        or more compiled actions (via the controller scope check — defense in
        depth layer 2). Audited with the operator identity."""
        try:
            result = controller.approve_decision(decision_id, _op["actor"])
        except (LookupError, ValueError) as e:
            raise HTTPException(409, str(e)) from e
        if not result.get("compiled"):
            raise HTTPException(409,
                                f"decision {decision_id} compiles to no action")
        return result

    @app.get("/actions")
    def list_actions(limit: int = 50, state: str | None = None,
                     _op: dict = Depends(_operator)) -> dict:
        return {"actions": controller.ledger.list_actions(limit, state)}

    @app.get("/actions/{action_id}")
    def get_action(action_id: str, _op: dict = Depends(_operator)) -> dict:
        a = controller.ledger.get_action(action_id)
        if a is None:
            raise HTTPException(404, f"no such action {action_id}")
        receipts = controller.ledger.list_receipts(action_id)
        return {"action": a, "receipts": receipts}

    @app.post("/actions/{action_id}/revoke")
    def revoke_action(action_id: str,_op: dict = Depends(_operator)) -> dict:
        result = controller.revoke_action(action_id, _op["actor"])
        return result

    @app.get("/policy")
    def policy_current(_op: dict = Depends(_operator)) -> dict:
        row = controller.ledger.current_policy_row()
        return {"current": row}

    @app.get("/policy/history")
    def policy_history(_op: dict = Depends(_operator)) -> dict:
        return {"history": controller.ledger.policy_history()}

    @app.post("/policy/validate")
    def policy_validate(payload: dict, _op: dict = Depends(_operator)) -> dict:
        from apip.decision.loader import validate_policy
        import json as _json, tomllib
        try:
            raw = tomllib.loads(payload.get("text", ""))
        except tomllib.TOMLDecodeError as e:
            return {"ok": False, "problems": [f"TOML parse error: {e}"]}
        problems = validate_policy(raw)
        return {"ok": not problems, "problems": problems}

    @app.post("/policy/stage")
    def policy_stage(payload: dict, _op: dict = Depends(_operator)) -> dict:
        from apip.decision.loader import validate_policy
        import hashlib as _hash, tomllib
        text = payload.get("text", "")
        version = str(payload.get("version", "")).strip() or "beta"
        try:
            raw = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise HTTPException(400, f"TOML parse error: {e}") from e
        problems = validate_policy(raw)
        sha = _hash.sha256(text.encode()).hexdigest()
        rev = controller.ledger.next_policy_revision(version)
        controller.ledger.stage_policy(
            policy_version=version, revision=rev, content_sha256=sha,
            raw_text=text, mode=str(payload.get("mode", "SHADOW")).upper(),
            staged_by=_op["actor"], problems=problems)
        return {"version": version, "revision": rev, "content_sha256": sha,
                "accepted": not problems, "problems": problems}

    @app.post("/policy/replay")
    def policy_replay(_op: dict = Depends(_operator)) -> dict:
        """Re-run every indicator through the active policy, appending fresh
        decisions (re-baseline after a promote). Decisions only — actions are
        compiled via approve/enforce from the worklist."""
        try:
            result = controller.replay_policy(_op["actor"])
        except RuntimeError as e:
            raise HTTPException(409, str(e)) from e
        return result

    @app.post("/policy/promote")
    def policy_promote(payload: dict, _op: dict = Depends(_operator)) -> dict:
        version = str(payload.get("version", "")).strip()
        revision = int(payload.get("revision", -1))
        try:
            controller.ledger.promote_policy(version, revision, _op["actor"])
        except ValueError as e:
            raise HTTPException(409, str(e)) from e
        return {"version": version, "revision": revision, "active": True}

    @app.get("/adapter")
    def adapter_status(_op: dict = Depends(_operator)) -> dict:
        # backward-compatible: primary RPZ health (fixtures reference it)
        return {"adapter": controller.adapter.health()}

    @app.get("/adapters")
    def adapters_status(_op: dict = Depends(_operator)) -> dict:
        """Health for EVERY configured enforcement adapter, so a degraded
        non-primary (e.g. Suricata/IPS) adapter is never masked by the RPZ."""
        return {"adapters": controller.adapters_status()}

    @app.get("/adapters/{name}")
    def adapter_status_one(name: str, _op: dict = Depends(_operator)) -> dict:
        for h in controller.adapters_status():
            if h.get("name") == name:
                return {"adapter": h}
        raise HTTPException(404, f"no adapter named {name}")

    @app.get("/audit")
    def audit(limit: int = 100, _op: dict = Depends(_operator)) -> dict:
        return {"audit": controller.ledger.list_audit(limit)}

    app.state.controller = controller
    return app