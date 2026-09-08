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

import string
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from typing import Literal

from apip.auth import (
    constant_time_equals,
    generate_source_key,
    hash_credential,
    parse_source_key,
)
from apip.config.service import ServiceConfig
from apip.controller.service import Controller, decision_from_row
from apip.ingest import IngestBatch, IngestChannel, IngestError, parse_indicator_payload
from apip.ledger.db import DatabaseUnavailable

API_VERSION = "0.1.0b1"


def _bearer_from(header: str | None) -> str:
    if not header or not header.startswith("Bearer "):
        return ""
    return header[len("Bearer "):].strip()


def _safe_source_id(value: str) -> bool:
    """Source ids are identifiers we insert into SQL, logs, and artifact
    comments; keep them to an ASCII-ONLY closed charset (letters, digits,
    _, -). ``str.isalnum()`` accepts non-ASCII homoglyphs (review P0 #9) —
    a Cyrillic 'а' in a source id is a different identity from the ASCII
    one while rendering identically, so the canonical form is ASCII."""
    return bool(value) and all(
        (c in string.ascii_letters or c in string.digits or c in "_-")
        for c in value) and not value.isdigit()


# Identity sentinels the registry protocol reserves (review P0 #9):
# "unregistered" is the zero-authority class — registering it as a real
# (possibly curated) source would let deliberately demoted evidence resolve
# through the registry and recover scoring authority. Blank ids are
# likewise refused at every layer.
RESERVED_SOURCE_IDS = frozenset({"unregistered"})


# -- strict request models (review P1 #34) -----------------------------------
# Loose `payload: dict` parsing let JSON/type mistakes through silently
# (e.g. bool("false") is True). Strict Pydantic models validate at the
# boundary: closed enums, bounded lengths, typed booleans.

class SourceRegistrationRequest(BaseModel):
    source_id: str = Field(min_length=1, max_length=128,
                           pattern=r"^[A-Za-z0-9_-]+$")
    source_class: Literal["curated", "local", "community", "annotation",
                          "attribution"] = "local"
    independent: bool = False
    # Audit #34: a NEWLY registered intelligence principal does not get
    # enforcement authority by omission. Auto-enforcement participation is
    # an explicit operator opt-in (--auto-enforce / true in the payload);
    # the default keeps a fresh feed observation-only.
    auto_enforcement_allowed: bool = False
    upstream: str | None = Field(default=None, max_length=4096)
    allowed_kinds: list[str] = Field(default_factory=list, max_length=64)
    # audit P0 #8: the tenants this credential may submit for. Empty = a
    # GLOBAL source (may never claim a tenant via x-apip-tenant).
    allowed_tenants: list[str] = Field(default_factory=list, max_length=64)
    provenance_note: str = Field(default="", max_length=2048)


class PolicyStageRequest(BaseModel):
    version: str = Field(min_length=1, max_length=128)
    mode: Literal["OFF", "OBSERVE", "SHADOW", "ENFORCE", "EMERGENCY"] = "SHADOW"
    text: str = Field(min_length=1, max_length=1_000_000)


class DecisionActionRequest(BaseModel):
    reason: str = Field(default="", max_length=2048)


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

        Uses the *injected* config's operator credentials (sourced from
        env/secret at config build), never a re-read of os.environ at
        request time — so an explicitly constructed ServiceConfig is
        honored. A config with no token configured fails every operator
        call closed.

        Audit #33: when named principals are configured
        (APIP_OPERATOR_TOKENS=actor_id:token,...), the token selects an
        immutable actor id and EVERY audit event records which principal
        acted. Without them the deployment is strictly single-operator and
        the shared token acts as the documented "operator" identity."""
        supplied = _bearer_from(authorization)
        principals = getattr(config, "operator_tokens", None) or {}
        if principals:
            for actor_id, expected in principals.items():
                if constant_time_equals(expected, supplied):
                    return {"actor": actor_id}
            _auth_fail()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "valid operator credential required")
        expected = config.operator_token or ""
        if not expected or not constant_time_equals(expected, supplied):
            _auth_fail()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "valid APIP_OPERATOR_TOKEN required")
        return {"actor": "operator"}

    def _auth_fail() -> None:
        """Audit #37: every failed credential check is a counted event."""
        from apip.ops.metrics import inc
        inc("apip_source_auth_failures_total")

    INGEST_KEY_HEADER = "x-apip-source-key"

    def _ingest_source(x_apip_source_key: str = Header(default="")) -> dict:
        """Channel-bound ingest auth: the presented SOURCE key selects the
        identity. Never trusts a payload-declared source_id."""
        if not x_apip_source_key:
            _auth_fail()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "x-apip-source-key required for ingest")
        row = controller.ledger.source_by_credential(
            x_apip_source_key, pepper=config.secret_key or "")
        if row is None:
            _auth_fail()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "unknown source key")
        if not row.get("enabled"):
            _auth_fail()
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"source {row['source_id']} disabled")
        return row

    # -- source registration -----------------------------------------------------

    @app.post("/sources/register")
    def register_source(payload: SourceRegistrationRequest,
                        _op: dict = Depends(_operator)) -> dict:
        source_id = payload.source_id
        source_class = payload.source_class
        independent = payload.independent
        auto_enf = payload.auto_enforcement_allowed
        upstream = payload.upstream
        allowed = tuple(payload.allowed_kinds)
        allowed_tenants = tuple(payload.allowed_tenants)
        for t in allowed_tenants:
            if not _safe_source_id(t):
                raise HTTPException(400, f"unsafe tenant id {t!r}")
        provenance = payload.provenance_note
        # Reserved identities are refused UNCONDITIONALLY (review P0 #9) —
        # no charset exemption path.
        if not source_id or source_id.lower() in RESERVED_SOURCE_IDS:
            raise HTTPException(
                400, f"source_id {source_id!r} is reserved and cannot be "
                     "registered")
        if not _safe_source_id(source_id):
            raise HTTPException(400, f"unsafe source_id {source_id!r}")
        if source_class not in _SOURCE_CLASSES:
            raise HTTPException(
                400, f"invalid source_class {source_class!r}; "
                     f"must be one of {sorted(_SOURCE_CLASSES)}")
        # one secret per source; only the (peppered) hash + PUBLIC key_id are
        # persisted. Registration FAILS CLOSED without the deployment secret
        # (APIP_SECRET_KEY): an unpeppered hash would make a leaked sources
        # table alone sufficient for channel forgery (review P0 #15).
        pepper = config.secret_key or ""
        if not pepper:
            raise HTTPException(
                503, "APIP_SECRET_KEY is not configured; source registration "
                     "is refused (credential hashes must be peppered)")
        # P1 #34: duplicate registration is EXPLICIT. Rotating a credential
        # is a separate endpoint (/sources/{id}/rotate) — the generic
        # register operation never silently replaces a credential.
        if controller.ledger.get_source(source_id) is not None:
            raise HTTPException(
                409, f"source {source_id!r} already exists; use "
                     "/sources/{source_id}/rotate to replace its credential")
        token, key_id = generate_source_key()
        # only the SECRET component is hashed: the presented token's key_id
        # selects the row and its secret verifies against this hash
        parsed = parse_source_key(token)
        assert parsed is not None and parsed[0] == key_id
        secret = parsed[1]
        controller.ledger.register_source(
            source_id=source_id, source_class=source_class,
            independent=independent, key_hash=hash_credential(secret, pepper),
            actor=_op["actor"], auto_enforcement_allowed=auto_enf,
            upstream=upstream, enabled=True, allowed_kinds=allowed,
            allowed_tenants=allowed_tenants,
            provenance_note=provenance, key_id=key_id)
        return {"source_id": source_id, "source_key": token,
                "note": "store the key now; it is not retrievable again"}

    # -- ingest -------------------------------------------------------------

    @app.post("/ingest")
    async def ingest(request: Request, src: dict = Depends(_ingest_source)) -> dict:
        # Bound the ingest body: an unbounded read lets an authenticated source
        # (or a gateway to it) stream an arbitrarily large payload and exhaust
        # controller memory. Reject oversized bodies up front (DoS guard).
        # ONE service-level ingest maximum shared by the HTTP boundary and
        # the parser (review P1 #28); the parser's ABSOLUTE ceiling always
        # applies regardless of configuration.
        max_ingest = getattr(controller.config, "max_ingest_bytes",
                             10 * 1024 * 1024)
        length_header = request.headers.get("content-length")
        if length_header is not None:
            try:
                if int(length_header) > max_ingest:
                    raise HTTPException(413,
                                        f"ingest body exceeds the "
                                        f"{max_ingest} byte limit")
            except ValueError:
                pass
        body = await request.body()
        if len(body) > max_ingest:
            from apip.ops.metrics import inc
            inc("apip_ingest_rejected_total")
            raise HTTPException(413,
                                f"ingest body exceeds the "
                                f"{max_ingest} byte limit")
        channel = IngestChannel(
            source_id=src["source_id"],
            allowed_source_ids=frozenset(
                s for s in (src.get("upstream") or "").split(",") if s),
            # P1 #29: the source's registry-declared allowed evidence kinds
            # gate ingest — disallowed kinds are demoted to zero authority
            allowed_kinds=frozenset(src.get("allowed_kinds") or ()))
        try:
            batch = parse_indicator_payload(body, channel,
                                            max_bytes=max_ingest)
        except IngestError as e:
            from apip.ops.metrics import inc
            inc("apip_ingest_rejected_total")
            raise HTTPException(400, str(e)) from e
        # The ONE durable ingest unit of work (review P0 #11/#12/#13):
        # begin 'processing' -> upsert/decide/act -> 'complete'. A replay of
        # the SAME bytes is a no-op only once the batch is 'complete'; a
        # crashed run resumes. The blast-radius budget
        # (max_new_auto_actions_per_batch) is enforced here, and actions are
        # minted at most once per decision instance (DB-pinned).
        tenant_header = request.headers.get("x-apip-tenant", "").strip()
        if tenant_header and not _safe_source_id(tenant_header):
            raise HTTPException(400, "invalid x-apip-tenant header")
        # audit P0 #8: tenant is authorized by the CREDENTIAL, not claimed
        # by a header. A source's allowed_tenants (set at registration) is
        # the gate:
        #   - empty set  -> a GLOBAL source: it may not claim any tenant;
        #                   the header must be absent (403 otherwise);
        #   - non-empty  -> a tenant-scoped source: it may submit ONLY for
        #                   tenants in its set; the header (or, when it
        #                   submits without one, its single allowed tenant)
        #                   must resolve inside the set (403 otherwise).
        allowed = tuple(src.get("allowed_tenants") or ())
        if tenant_header and tenant_header not in allowed:
            raise HTTPException(403,
                                f"source {src['source_id']} is not authorized "
                                f"for tenant {tenant_header!r}")
        tenant_id: str | None
        if allowed:
            if tenant_header:
                tenant_id = tenant_header
            elif len(allowed) == 1:
                tenant_id = allowed[0]
            else:
                raise HTTPException(400,
                                    f"source {src['source_id']} may submit "
                                    "for multiple tenants; x-apip-tenant "
                                    "is required")
        else:
            tenant_id = None
        # audit P1 #15: the request DURABLY ACCEPTS the batch (payload
        # persisted, status 'queued') and returns immediately — the
        # pipeline (evaluate -> decide -> compile) runs in the bounded
        # worker, so one HTTP request can no longer tie itself to unbounded
        # evaluation work or fail half-way through durable mutation. The
        # queue IS the backpressure: acceptance is bounded by what can be
        # persisted.
        accepted = controller.ledger.accept_batch(
            batch_id=batch.batch_id, source_id=batch.source_id,
            raw_sha256=batch.raw_sha256, raw_payload=body,
            indicator_count=len(batch.indicators),
            demoted=batch.demoted_records, channel=batch.source_id,
            tenant_id=tenant_id, actor=src["source_id"])
        if not accepted:
            # exact replay of already-accepted bytes: report the recorded
            # status instead of re-queueing
            outcome = controller.ingest_status(batch.batch_id) or {}
            return {"batch_id": batch.batch_id,
                    "source_id": batch.source_id,
                    "status": outcome.get("status", "complete"),
                    "indicators": outcome.get("indicator_count", 0),
                    "demoted_records": batch.demoted_records,
                    "replay": True}
        return {"batch_id": batch.batch_id, "source_id": batch.source_id,
                "status": "queued",
                "indicators": len(batch.indicators),
                "demoted_records": batch.demoted_records}

    @app.get("/ingest/{batch_id}")
    def ingest_status(batch_id: str, src: dict = Depends(_ingest_source)) -> dict:
        """Batch processing status (audit P1 #15): processing / complete /
        failed with counts. Authentication is the same ingest credential —
        a source sees batch status, not other sources'."""
        outcome = controller.ingest_status(batch_id)
        if outcome is None:
            raise HTTPException(404, f"unknown batch {batch_id}")
        if outcome["source_id"] != src["source_id"]:
            raise HTTPException(403, "batch belongs to another source")
        return {"batch_id": outcome["batch_id"],
                "status": outcome["status"],
                "indicator_count": outcome["indicator_count"],
                "demoted_records": outcome["demoted_records"],
                "received_at": str(outcome["received_at"] or ""),
                "started_at": str(outcome["started_at"] or ""),
                "completed_at": str(outcome["completed_at"] or ""),
                "failure": outcome["failure"] or ""}

    # -- health ---------------------------------------------------------------

    @app.get("/health")
    def health() -> dict:
        """Unauthenticated LIVENESS ONLY. Returns a bare status word — not
        degraded-reason strings, which carry adapter names and source ids and
        partially defeat the no-topology-disclosure rule (review P1 #25).
        The rich snapshot is the authenticated GET /status."""
        try:
            h = controller.health()
        except DatabaseUnavailable:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "database unavailable")
        return {"status": h.get("status", "degraded"),
                "api_version": API_VERSION}

    @app.get("/ready")
    def ready() -> dict:
        """Unauthenticated READINESS ONLY: a bare 200/503 with no topology
        detail (review P1 #25)."""
        try:
            h = controller.health()
        except DatabaseUnavailable:
            raise HTTPException(503, "database unavailable")
        if h.get("status") != "ok":
            raise HTTPException(503, "not ready")
        return {"status": "ready"}

    @app.get("/status")
    def rich_status(_op: dict = Depends(_operator)) -> dict:
        """AUTHENTICATED rich snapshot (review P1 #25): components, action
        counts (drifted explicit), reconciliation + leadership state, the
        degraded-reason list. This is what `apip status` reads."""
        try:
            return controller.health()
        except DatabaseUnavailable:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "database unavailable")

    @app.get("/metrics",
             response_class=PlainTextResponse)
    def metrics(_op: dict = Depends(_operator)) -> str:
        """Prometheus text metrics (audit #37), AUTHENTICATED like /status —
        metric labels carry adapter/tenant detail and must not be disclosed
        to an unauthenticated prober."""
        from apip.ops import metrics as ops_metrics
        return ops_metrics.render(controller)

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

    @app.post("/sources/{source_id}/rotate")
    def rotate_source_credential(source_id: str,
                                 _op: dict = Depends(_operator)) -> dict:
        """Explicit credential rotation (review P1 #34): mints a new keyed
        credential for an EXISTING source and updates its hash/key_id.
        Registration of an already-known source_id is a 409, not a silent
        rotation — the two operations are distinct."""
        pepper = config.secret_key or ""
        if not pepper:
            raise HTTPException(503,
                                "APIP_SECRET_KEY is not configured; credential "
                                "rotation is refused")
        row = controller.ledger.get_source(source_id)
        if row is None:
            raise HTTPException(404, f"no such source {source_id}")
        # the credential's tenant scope survives rotation (audit P0 #8);
        # get_source's safe projection omits it, so read it separately
        full = controller.ledger.db.query_one(
            "SELECT allowed_tenants FROM sources WHERE source_id=%s",
            (source_id,))
        token, key_id = generate_source_key()
        parsed = parse_source_key(token)
        assert parsed is not None and parsed[0] == key_id
        secret = parsed[1]
        controller.ledger.register_source(
            source_id=source_id,
            source_class=row["source_class"],
            independent=bool(row["independent"]),
            key_hash=hash_credential(secret, pepper),
            actor=_op["actor"],
            auto_enforcement_allowed=bool(row["auto_enforcement_allowed"]),
            upstream=row.get("upstream"),
            enabled=bool(row["enabled"]),
            allowed_kinds=tuple(row.get("allowed_kinds") or ()),
            allowed_tenants=tuple(full["allowed_tenants"] or ())
            if full else (),
            provenance_note=row.get("provenance_note") or "",
            key_id=key_id)
        controller.ledger.audit(_op["actor"], "source.credential_rotated",
                                source_id, {"key_id": key_id})
        return {"source_id": source_id, "source_key": token,
                "note": "store the key now; it is not retrievable again"}

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
    def list_indicators(limit: int = Query(default=50, ge=1, le=1000),
                        _op: dict = Depends(_operator)) -> dict:
        return {"indicators": controller.ledger.list_indicators(limit)}

    @app.get("/indicators/{indicator_id}")
    def get_indicator(indicator_id: str, _op: dict = Depends(_operator)) -> dict:
        ind = controller.ledger.get_indicator(indicator_id)
        if ind is None:
            raise HTTPException(404, f"no such indicator {indicator_id}")
        ev = controller.ledger.indicator_evidence(indicator_id)
        return {"indicator": ind, "evidence": ev}

    @app.get("/decisions")
    def list_decisions(limit: int = Query(default=50, ge=1, le=1000),
                       disposition: str | None = None,
                       _op: dict = Depends(_operator)) -> dict:
        return {"decisions": controller.ledger.list_decisions(limit, disposition)}

    @app.get("/decisions/{decision_id}")
    def get_decision(decision_id: str, _op: dict = Depends(_operator)) -> dict:
        d = controller.ledger.get_decision(decision_id)
        if d is None:
            raise HTTPException(404, f"no such decision {decision_id}")
        ev = controller.ledger.get_decision_evidence(decision_id)
        out = {"decision": d, "evidence": ev}
        # audit #29: a pending proposal carries its materialization status —
        # `decision valid / materialization unavailable` is visible BEFORE
        # an operator approves something that would compile to zero actions.
        if d.get("disposition") == "PROPOSE_OPERATOR_APPROVAL":
            ind = controller.ledger.get_indicator(d["indicator_id"])
            if ind is not None:
                try:
                    decision = decision_from_row(d)
                    out["materialization"] = controller.materialization_for(
                        decision, ind["value"], ind["itype"])
                except Exception:      # noqa: BLE001 — the surface must not
                    pass               # fail on an unshaped legacy row
        return out

    @app.post("/decisions/{decision_id}/approve")
    def approve_decision(decision_id: str,
                         payload: DecisionActionRequest | None = None,
                         _op: dict = Depends(_operator)) -> dict:
        """ONE-SHOT durable operator approval (review P0 #16): records the
        approval citing the exact decision instance, then compiles actions.
        A second approval of the same instance is refused (409)."""
        reason = payload.reason if payload else ""
        try:
            result = controller.approve_decision(decision_id, _op["actor"],
                                                 reason=reason)
        except (LookupError, ValueError) as e:
            raise HTTPException(409, str(e)) from e
        if not result.get("compiled"):
            raise HTTPException(409,
                                f"decision {decision_id} compiles to no action")
        return result

    @app.post("/decisions/{decision_id}/reject")
    def reject_decision(decision_id: str,
                        payload: DecisionActionRequest | None = None,
                        _op: dict = Depends(_operator)) -> dict:
        """Durably reject a proposal: the decision instance can never be
        approved afterwards (review P0 #16)."""
        reason = (payload.reason if payload and payload.reason
                  else "operator_rejected")
        try:
            return controller.reject_decision(decision_id, _op["actor"],
                                              reason=reason)
        except (LookupError, ValueError) as e:
            raise HTTPException(409, str(e)) from e

    @app.get("/approvals")
    def list_approvals(limit: int = Query(default=100, ge=1, le=1000),
                       _op: dict = Depends(_operator)) -> dict:
        return {"approvals": controller.ledger.list_approvals(limit)}

    @app.get("/actions")
    def list_actions(limit: int = Query(default=50, ge=1, le=1000),
                     state: str | None = None,
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
        try:
            result = controller.revoke_action(action_id, _op["actor"])
        except LookupError as e:
            raise HTTPException(404, str(e)) from e
        except ValueError as e:
            raise HTTPException(409, str(e)) from e
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
    def policy_stage(payload: PolicyStageRequest,
                     _op: dict = Depends(_operator)) -> dict:
        from apip.decision.loader import validate_policy
        import hashlib as _hash, tomllib
        # the closed mode set is enforced by the request model (P1 #34)
        mode = payload.mode
        text = payload.text
        version = payload.version
        try:
            raw = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise HTTPException(400, f"TOML parse error: {e}") from e
        problems = validate_policy(raw)
        # P0 #20: the staged row's mode column MUST equal the mode inside
        # the policy text (the runtime truth). A history saying ENFORCE while
        # the loaded policy says SHADOW is exactly the drift this closes.
        text_mode = str(raw.get("mode", "")).upper()
        if text_mode != mode:
            raise HTTPException(
                400, f"mode {mode!r} does not match the policy text's "
                f"mode {text_mode!r}; they must agree")
        sha = _hash.sha256(text.encode()).hexdigest()
        rev = controller.ledger.next_policy_revision(version)
        controller.ledger.stage_policy(
            policy_version=version, revision=rev, content_sha256=sha,
            raw_text=text, mode=mode,
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
        try:
            revision = int(payload.get("revision", -1))
        except (TypeError, ValueError):
            raise HTTPException(400,
                                "revision must be an integer") from None
        try:
            controller.ledger.promote_policy(version, revision, _op["actor"])
        except ValueError as e:
            raise HTTPException(409, str(e)) from e
        return {"version": version, "revision": revision, "active": True}

    # -- tenant overlays (review P1 #31: real operator surface) --------------

    @app.post("/tenants/{tenant_id}/overlay")
    def stage_tenant_overlay(tenant_id: str, payload: dict,
                             _op: dict = Depends(_operator)) -> dict:
        """Stage (or replace) a tenant's tighten-only policy overlay. The
        overlay is VALIDATED at stage time (TOML parse + policy validation);
        problems are stored and returned — a problematic overlay stays
        visible but flagged (the merge() clamp still enforces tighten-only
        at decision time)."""
        from apip.decision.loader import validate_policy
        import hashlib as _hash, tomllib
        text = str(payload.get("text", ""))
        if not text.strip():
            raise HTTPException(400, "overlay text is required")
        try:
            raw = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise HTTPException(400, f"TOML parse error: {e}") from e
        problems = validate_policy(raw)
        sha = _hash.sha256(text.encode()).hexdigest()
        controller.ledger.upsert_tenant_overlay(
            tenant_id=tenant_id, raw_text=text, overlay_sha256=sha,
            created_by=_op["actor"], problems=problems)
        return {"tenant_id": tenant_id, "overlay_sha256": sha,
                "accepted": not problems, "problems": problems}

    @app.get("/tenants/{tenant_id}/overlay")
    def show_tenant_overlay(tenant_id: str,
                            _op: dict = Depends(_operator)) -> dict:
        row = controller.ledger.get_tenant_overlay(tenant_id)
        if row is None:
            raise HTTPException(404, f"no overlay for tenant {tenant_id}")
        return {"overlay": row}

    @app.get("/tenants/overlays")
    def list_tenant_overlays(_op: dict = Depends(_operator)) -> dict:
        return {"overlays": controller.ledger.list_tenant_overlays()}

    @app.delete("/tenants/{tenant_id}/overlay")
    def delete_tenant_overlay(tenant_id: str,
                              _op: dict = Depends(_operator)) -> dict:
        """Remove the overlay: the tenant reverts to the global policy."""
        n = controller.ledger.delete_tenant_overlay(tenant_id)
        if not n:
            raise HTTPException(404, f"no overlay for tenant {tenant_id}")
        return {"tenant_id": tenant_id, "removed": True}

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
    def audit(limit: int = Query(default=100, ge=1, le=5000),
              _op: dict = Depends(_operator)) -> dict:
        return {"audit": controller.ledger.list_audit(limit)}

    app.state.controller = controller
    return app