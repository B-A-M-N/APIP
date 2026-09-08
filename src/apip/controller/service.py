"""The controller: long-running service with explicit lifecycle.

Workers:
  - dispatch:   pending actions -> adapter prepare/validate/apply (with the
                controller-layer scope check) -> verify;
  - verify:     re-verify active actions against the adapter's actual state;
  - reconcile:  expiry sweep (TTL), drift detection, removal verification.

Every worker is restart-safe: work is selected from the ledger, results are
written to the ledger, and a crashed pass loses nothing.
"""
from __future__ import annotations

import hashlib
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import psycopg2.extras

from apip.adapters.base import AdapterError, EnforcementAdapter, MODE_RANK
from apip.adapters import build_adapters
from apip.adapters.rpz import RpzAdapter
from apip.config.service import ServiceConfig
from apip.controller.engine import DecisionPipeline, now_iso_utc
from apip.decision.policy import in_scope
from apip.decision.policy import Policy
from apip.decision.policy import policy_allows_presence
from apip.domain.models import ActionSelector, Decision
from apip.ingest import IngestBatch
from apip.ledger.db import Database, DatabaseUnavailable
from apip.ledger.repo import Ledger

CONTROLLER_ACTOR = "controller"


_SELECTOR_FIELDS = ("scope_type", "client", "destination", "protocol_class",
                    "host", "rate_ceiling_per_min")


def decision_from_row(row: dict) -> Decision:
    """Rebuild an immutable ``Decision`` from a ledger row so stored decisions
    can be re-compiled into actions (operator approve) or reasoned about as a
    domain object. The row is the durable source of truth; nothing is
    re-decided here."""
    sel_row = row.get("selector") or {}
    selector = None
    if sel_row:
        # only forward the selector fields the row actually carries; the
        # stored JSONB snapshot already recorded the authorized scope
        kwargs = {k: sel_row[k] for k in _SELECTOR_FIELDS if k in sel_row}
        selector = ActionSelector(**kwargs)
    return Decision(
        id=row["decision_id"],
        indicator_id=row["indicator_id"],
        maliciousness=int(row["maliciousness"]),
        action_safety=int(row["action_safety"]),
        disposition=row["disposition"],
        action=row["action"],
        rung=row["rung"],
        scope=row["scope"],
        ttl_seconds=int(row["ttl_seconds"] or 0),
        policy_version=row["policy_version"],
        reason_codes=tuple(row.get("reason_codes") or ()),
        explanation=row["explanation"],
        selector=selector,
        randomization=row.get("randomization"),
        content_hash=row.get("content_hash") or "",
    )


def _adapter_health(adapter: EnforcementAdapter) -> dict:
    """One adapter's health, normalized with its max posture surfaced."""
    h = adapter.health()
    h.setdefault("name", adapter.name)
    h.setdefault("max_mode", adapter.max_mode())
    return h


class ControllerState:
    """Component-level health: no single generic healthy=true."""

    def __init__(self):
        self.started_at: datetime | None = None
        self.last_reconcile_at: datetime | None = None
        self.last_reconcile_ok: bool = False
        self.last_reconcile_error: str | None = None
        self.degraded_reasons: list[str] = []
        self.policy_loaded: bool = False
        self.policy_version: str | None = None
        # HA leadership (local view; the DB lease is the authoritative state)
        self.is_leader: bool = False
        self.leader_id: str | None = None
        self.lease_s: int | None = None
        self.lock = threading.Lock()

    def snapshot(self, *, db_health: dict, ledger: Ledger | None,
                 adapter_health: dict, adapters_health: list[dict],
                 registry_rows: list[dict], pipeline_ok: bool) -> dict:
        with self.lock:
            counts = ledger.action_counts() if ledger else {}
            pending = counts.get("pending", 0)
            failed = counts.get("failed", 0)
            active = sum(counts.get(k, 0) for k in ("applied", "verified", "drifted"))
            expired = counts.get("expired", 0)
            revoked = counts.get("revoked", 0)

            degraded = list(self.degraded_reasons)
            if db_health.get("status") != "up":
                degraded.append("database_" + db_health.get("status", "unknown"))
            if not pipeline_ok:
                degraded.append("no_active_policy")
            # P1 #26: drift and failed applies ARE degraded states — an
            # unverified or failed control is exactly what health must surface.
            drifted = counts.get("drifted", 0)
            if drifted:
                degraded.append(f"actions_drifted:{drifted}")
            if failed:
                degraded.append(f"actions_failed:{failed}")
            # a failed/stale reconciliation pass degrades readiness
            if self.last_reconcile_at is not None and not self.last_reconcile_ok:
                degraded.append("reconciliation_failed")
            # every configured adapter is surfaced; ANY unhealthy adapter degrades
            # the overall status (defense in depth: no silent single-adapter gap)
            for ah in (adapters_health or [adapter_health]):
                if ah.get("status") != "ok":
                    degraded.append("adapter_" + ah.get("name", "?") + "_"
                                    + ah.get("status", "unknown"))
            for src in registry_rows:
                if src.get("health") not in ("ok", "unknown") and src.get("enabled"):
                    degraded.append(f"source_{src['source_id']}_{src['health']}")

            overall = "ok"
            if "database_down" in degraded or "database_degraded" in degraded:
                overall = "degraded"
            elif degraded:
                overall = "degraded"
            return {
                "status": overall,
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "components": {
                    "database": db_health,
                    "policy": {
                        "loaded": self.policy_loaded,
                        "current": self.policy_version,
                    },
                    "sources": {
                        "registered": len(registry_rows),
                        "enabled": sum(1 for s in registry_rows if s.get("enabled")),
                    },
                    "adapter": adapter_health,
                    "adapters": adapters_health or [adapter_health],
                    "queue": {"pending_actions": pending},
                },
                "actions": {
                    "pending": pending,
                    "active": active,
                    # drifted is EXPLICIT, not folded into "active" (P1 #26)
                    "drifted": drifted,
                    "failed": failed,
                    "expired": expired,
                    "revoked": revoked,
                },
                "reconciliation": {
                    "last_run_at": self.last_reconcile_at.isoformat() if self.last_reconcile_at else None,
                    "last_ok": self.last_reconcile_ok,
                    "last_error": self.last_reconcile_error,
                },
                "leadership": {
                    "is_leader": self.is_leader,
                    "leader_id": self.leader_id,
                    "lease_s": self.lease_s,
                },
                "degraded": degraded,
            }


class Controller:
    """Owns storage, policy, registry view, adapters, and the worker loops."""

    def __init__(self, config: ServiceConfig):
        self.config = config
        self.db = Database(config.db.dsn_kwargs())
        self.ledger = Ledger(self.db)
        self.pipeline = DecisionPipeline(self.ledger)
        self.state = ControllerState()
        self._adapters = build_adapters(config)
        # Primary RPZ adapter retained for backward compatibility (health
        # surfaces / fixtures that reference self.adapter directly).
        self.adapter = self._adapters[RpzAdapter.name]
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        # HA leader identity + lease window (config-derived; correctness rests
        # on the DB compare-and-set, not this local value).
        self._leader_id = "controller--" + uuid.uuid4().hex[:12]
        self._lease_s = int(2 * max(1, self.config.controller.reconcile_interval_s))
        self._lease_lock = threading.Lock()
        # audit #17: the live behavioral frontier. The feed is always owned
        # (health honestly reports an inert feed when no datasource is
        # configured); the EVE reader exists only when configured.
        from apip.telemetry.feed import LiveBehavioralFeed
        families = self.config.controller.behavioral_enabled_families or None
        self.behavioral_feed = LiveBehavioralFeed(enabled_families=families)
        self.eve_source = None
        if self.config.controller.suricata_eve_path:
            from apip.telemetry.sources.suricata_eve import SuricataEveSource
            self.eve_source = SuricataEveSource(
                self.behavioral_feed, self.config.controller.suricata_eve_path)

    def _acquire_or_renew_lease(self) -> bool:
        """Refresh the worker lease atomically; True only for the live leader.
        Safe to call from any worker (guarded here in-process; the DB guard is
        authoritative)."""
        with self._lease_lock:
            now = datetime.now(timezone.utc)
            holder = self.ledger.claim_leadership(
                self._leader_id, self._lease_s, now)
            self.state.leader_id = self._leader_id
            self.state.lease_s = self._lease_s
            self.state.is_leader = holder
            return holder

    def _adapter_for(self, fragment: dict) -> EnforcementAdapter:
        """Route a fragment to the adapter that compiled it. Unknown adapter
        names fail closed rather than silently disappearing."""
        name = fragment.get("adapter")
        if not isinstance(name, str):
            raise AdapterError(f"fragment carries no adapter name: {name!r}")
        adapter = self._adapters.get(name)
        if adapter is None:
            raise AdapterError(f"no adapter named {name!r} for dispatch")
        return adapter

    # -- lifecycle -------------------------------------------------------------

    def start(self, *, wait_db_s: float = 30.0) -> None:
        self.db.wait_until_ready(timeout_s=wait_db_s)
        from apip.ledger.migrations import apply_migrations
        apply_migrations(self.db)
        # audit P1 #13: before any worker accepts work, every adapter that
        # claims an actuator posture PROVES its physical prerequisites — a
        # refusing controller is visible; a silently unenforcing one is not.
        for adapter in self._adapters.values():
            probe = getattr(adapter, "probe_startup", None)
            if callable(probe):
                probe()
        # audit #22: the local behavioral feed's evidence identity is a
        # GOVERNED, server-derived principal — registered at startup so
        # detections written to the ledger never land under an unregistered
        # id (zero silent authority). Deterministic local detectors only:
        # allowed_kinds pins exactly the behavioral_* families the runtime
        # implements.
        from apip.telemetry.behavioral import (
            LOCAL_BEHAVIORAL_SOURCE_ID, BEACON_KIND, NOVELTY_KIND,
            DGA_KIND, TUNNEL_KIND, FASTFLUX_KIND, VOLUME_KIND, TLS_KIND,
            SYNC_KIND,
        )
        self.ledger.register_source(
            source_id=LOCAL_BEHAVIORAL_SOURCE_ID, source_class="local",
            independent=False,
            auto_enforcement_allowed=False,
            key_hash=hashlib.sha256(
                b"server-derived:local-behavioral").hexdigest(),
            actor=CONTROLLER_ACTOR,
            allowed_kinds=(BEACON_KIND, NOVELTY_KIND, DGA_KIND, TUNNEL_KIND,
                           FASTFLUX_KIND, VOLUME_KIND, TLS_KIND, SYNC_KIND),
            provenance_note=(
                "server-derived local behavioral detectors (deterministic, "
                "AI-free); no external key — not independently corroborative "
                "by construction"))
        self.ledger.audit(CONTROLLER_ACTOR, "controller.start", "", {})
        self.state.started_at = datetime.now(timezone.utc)
        self._refresh_policy_state()
        interval = self.config.controller.reconcile_interval_s
        for name, target in (
            ("dispatch", self._dispatch_loop),
            ("reconcile", self._reconcile_loop),
            ("ingest", self._ingest_loop),
        ):
            t = threading.Thread(target=target, name=f"apip-{name}", daemon=True)
            t.start()
            self._threads.append(t)
        # audit #17: the EVE datasource runs under the controller lifecycle
        if self.eve_source is not None:
            self.eve_source.start_thread()
        self.ledger.audit(CONTROLLER_ACTOR, "controller.workers_started",
                          "", {"interval_s": interval})

    def stop(self) -> None:
        self._stop.set()
        if self.eve_source is not None:
            self.eve_source.stop()
        for t in self._threads:
            t.join(timeout=10)
        try:
            self.ledger.release_lease(self._leader_id)
        except Exception:
            pass    # a follower's release is a no-op; never blocks shutdown
        try:
            self.ledger.audit(CONTROLLER_ACTOR, "controller.stop", "", {})
        except Exception:
            pass
        self.db.close()

    def run_forever(self) -> None:
        self.start()
        try:
            while not self._stop.wait(1.0):
                pass
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    # -- policy ------------------------------------------------------------------

    def _refresh_policy_state(self) -> None:
        try:
            row = self.ledger.current_policy_row()
            self.state.policy_loaded = row is not None
            self.state.policy_version = (
                f"{row['policy_version']}@r{row['revision']}" if row else None)
        except DatabaseUnavailable:
            self.state.policy_loaded = False

    def current_policy(self) -> Policy | None:
        return self.effective_policy_for(None)

    def effective_policy_for(self, tenant_id: str | None) -> Policy | None:
        """The policy governing ``tenant_id``: the GLOBAL active policy, or —
        when the tenant has a registered overlay — the deterministic
        merge(global, overlay) that is at least as restrictive as the global.
        ``None`` (global-only) matches ``current_policy`` exactly."""
        registry = self.pipeline.registry_from_sources(self.ledger.list_sources())
        loaded = self.pipeline.load_active_policy_effective(
            registry, tenant_id=tenant_id, now_fn=now_iso_utc)
        return loaded[0] if loaded else None

    def _active_policy_revision(self) -> str | None:
        """'version@rN' for the active policy row, e.g. 'beta@r3'."""
        row = self.ledger.current_policy_row()
        return (f"{row['policy_version']}@r{row['revision']}" if row else None)

    # -- action creation (from a decision) --------------------------------------

    def create_action_from_decision(self, decision: Decision, indicator_value: str,
                                    indicator_type: str, actor: str,
                                    decision_seq: int | None = None) -> list[str]:
        """Compile a decision into actions through EVERY adapter that renders
        a fragment, with the controller-layer scope check (defense in depth
        layer 2; the decision engine checked layer 1, the adapter re-checks
        layer 3). Returns ALL created action ids (review P1 #32 — a
        multi-adapter decision previously reported only its first action).

        ``decision_seq`` is the exact immutable decision instance that
        authorizes these actions (review P0 #17); when omitted the latest
        instance of the decision id is resolved from the ledger. Actions
        already existing for the same (decision instance, adapter, rule) are
        refused at the database (review P0 #12) and skipped here."""
        # defense-in-depth layer 2 uses the TENANT's effective policy (global, or
        # the tighten-only merge with the tenant's overlay) so a narrowed tenant
        # boundary is honored at the controller scope check too, not just at the
        # decision engine.
        ind_row = self.ledger.get_indicator(decision.indicator_id)
        tenant_id = ind_row.get("tenant_id") if ind_row else None
        policy = self.effective_policy_for(tenant_id)
        if policy is None:
            raise RuntimeError("no active policy; refusing to create actions")
        if decision.disposition not in ("SHADOW_ACTION", "AUTO_ENFORCE",
                                        "PROPOSE_OPERATOR_APPROVAL"):
            return []
        if not in_scope(indicator_value, indicator_type, policy):
            self.ledger.audit(actor, "action.rejected_scope", decision.id,
                              {"value": indicator_value, "type": indicator_type})
            return []

        fragments: list[dict] = []
        for adapter in self._adapters.values():
            fragments.extend(adapter.compile(decision, indicator_value, indicator_type))
        if not fragments:
            return []
        # P1 #27: the controller's max_action_ttl_s is a HARD ceiling —
        # expiry is min(requested/default TTL, ceiling), never the raw ask.
        ttl = decision.ttl_seconds or self.config.controller.default_action_ttl_s
        ttl = min(ttl, self.config.controller.max_action_ttl_s)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        expires_at = expires_at.replace(microsecond=0)
        action_ids = []
        for frag in fragments:
            action_id = "action--" + uuid.uuid4().hex[:24]
            # The PERSISTED action mode (review P0 #1) is what the adapter
            # will honor at dispatch time — it must reflect the policy that
            # authorized this decision, not the adapter's current config.
            # Policy posture is the requested ceiling: an ENFORCE policy may
            # request ENFORCE, anything weaker requests SHADOW. The compiling
            # adapter's maximum posture then CAPS it (never strengthens).
            # An operator-approved PROPOSE decision is the operator directly
            # authorizing the action, so it rides the policy's posture the
            # same as AUTO_ENFORCE. SHADOW_ACTION stays SHADOW by definition.
            enforce_requested = (
                policy.mode == "ENFORCE"
                and decision.disposition in ("AUTO_ENFORCE",
                                             "PROPOSE_OPERATOR_APPROVAL"))
            mode = "ENFORCE" if enforce_requested else "SHADOW"
            adapter = self._adapters.get(frag["adapter"])
            if adapter is not None:
                cap = adapter.max_mode()
                if (MODE_RANK.get(mode, 0) > MODE_RANK.get(cap, 0)):
                    mode = "SHADOW" if MODE_RANK.get(cap, 0) >= MODE_RANK["SHADOW"] else "OBSERVE"
            # audit P1 #12: OBSERVE is DECISION-ONLY. An adapter whose
            # maximum posture is below SHADOW has no actuator surface —
            # persisting a dispatchable action row would dispatch into an
            # adapter that must refuse it, manufacturing a bogus `failed`
            # action from an intentionally disabled actuator. The decision
            # (and this audit event) IS the observation; no action row.
            if adapter is not None and MODE_RANK.get(mode, 0) < MODE_RANK["SHADOW"]:
                self.ledger.audit(actor, "action.observe_decision_only",
                                  decision.id,
                                  {"adapter": frag["adapter"],
                                   "cap": adapter.max_mode(),
                                   "value": indicator_value})
                continue
            if decision_seq is None:
                decision_seq = self.ledger.decision_seq_for(
                    decision.id, decision.content_hash)
                if decision_seq is None:
                    # the authorizing decision instance is not durably
                    # recorded — refuse to create an unprovenanced action
                    self.ledger.audit(actor, "action.rejected_no_decision",
                                      decision.id, {"adapter": frag["adapter"]})
                    return []
            if not self.ledger.record_action(
                    action_id=action_id, decision=decision,
                    indicator_id=decision.indicator_id, adapter=frag["adapter"],
                    mode=mode, fragment=frag, expires_at=expires_at,
                    requested_by=actor, decision_seq=decision_seq,
                    monitoring_only=bool(frag.get("monitoring_only", False))):
                continue        # duplicate logical action (P0 #12): skip
            action_ids.append(action_id)
        return action_ids

    def process_batch(self, *, batch: "IngestBatch", actor: str,
                      tenant_id: str | None = None) -> dict:
        """The ONE durable ingest unit of work (review P0 #11/#12/#13).

        Lifecycle: begin_batch claims the raw bytes as 'processing' (a replay
        of the SAME bytes is the only no-op); indicators, decisions and
        pending actions are then recorded; only at the end is the batch
        marked 'complete'. A crash at any point leaves the row 'processing',
        so the retry RESUMES (re-upserting indicators is idempotent by the
        server-derived observable id; decisions are idempotent by content
        hash; actions are idempotent per decision instance + rule at the
        database) instead of being skipped forever as a phantom replay.

        Blast-radius budget (review P0 #13): policy
        ``max_new_auto_actions_per_batch`` caps how many action-bearing
        decisions one batch may mint. Candidates are evaluated in batch
        order (the payload order is the deterministic tiebreak); overflow is
        DEMOTED to OBSERVE with reason blast_radius_budget_exceeded and the
        demoted decision is persisted — never silently acted on.
        """
        results = {"batch_id": batch.batch_id, "indicators": 0,
                   "decisions": 0, "actions": 0, "demoted": 0,
                   "resumed": False}
        status = self.ledger.batch_status(batch.batch_id)
        if status == "complete":
            results["resumed"] = False
            results["replay"] = True
            return results
        if status is None:
            if not self.ledger.begin_batch(
                    batch_id=batch.batch_id, source_id=batch.source_id,
                    raw_sha256=batch.raw_sha256,
                    indicator_count=len(batch.indicators),
                    demoted=batch.demoted_records, channel=batch.source_id,
                    actor=actor):
                results["replay"] = True
                return results
        else:
            # 'processing' (crashed run) or 'failed': resume
            results["resumed"] = True

        granted = 0
        # the blast-radius budget is the batch's EFFECTIVE policy knob,
        # taken UNCONDITIONALLY (audit P0 #7): the tenant's tighten-only
        # merge when an overlay governs, else the global policy. The cap
        # previously applied only on the tenant path, so every shipped
        # example policy's safety control was silently absent for global
        # ingestion — the mainline path.
        eff = self.effective_policy_for(tenant_id)
        budget = (eff.max_new_auto_actions_per_batch
                  if eff is not None else None)
        try:
            decide = DecisionPipeline(self.ledger)
            for ind in batch.indicators:
                durable_id = self.ledger.upsert_indicator(
                    ind, batch.batch_id, tenant_id=tenant_id)
                results["indicators"] += 1
                result = decide.decide_indicator(
                    durable_id, actor=actor, batch_id=batch.batch_id,
                    tenant_id=tenant_id)
                if result is None:
                    continue
                decision = result["decision"]
                if result["recorded"] is not None:
                    results["decisions"] += 1
                # proposals await operator approval (approve_decision);
                # only AUTO dispositions mint actions during ingest
                if decision.disposition not in ("SHADOW_ACTION", "AUTO_ENFORCE"):
                    continue
                if budget is not None and granted >= budget:
                    # budget exhausted: demote + persist the demoted decision
                    # (never act on the enforcement-intent decision)
                    demoted = decision.with_budget_demotion()
                    self.ledger.record_decision(
                        demoted, indicator_id=durable_id,
                        batch_id=batch.batch_id,
                        policy_content_sha256=result["policy_row"]["content_sha256"],
                        actor=actor)
                    results["demoted"] += 1
                    continue
                created = self.create_action_from_decision(
                    decision, ind.value, ind.type, actor=actor)
                if created:
                    granted += 1
                    results["actions"] += len(created)
            self.ledger.complete_batch(batch.batch_id)
            self.ledger.touch_source_success(batch.source_id)
        except Exception as e:
            self.ledger.fail_batch(batch.batch_id, str(e))
            raise
        if results.get("demoted"):
            self.ledger.audit(actor, "policy.blast_radius_budget", batch.batch_id,
                              {"demoted": results["demoted"], "budget": budget})
        return results

    def approve_decision(self, decision_id: str, actor: str,
                         reason: str = "") -> dict:
        """ONE-SHOT durable approval (review P0 #16): the proposal becomes
        an approved decision_approvals row citing the EXACT decision
        instance; a second approval of the same instance is refused at the
        database. Rebuilds the decision from ledger state (never re-decides),
        re-applies the controller scope check, compiles actions, and audits
        the operator identity. Fails closed when the decision is not
        awaiting approval or cannot be compiled."""
        row = self.ledger.get_decision(decision_id)
        if row is None:
            raise LookupError(f"unknown decision {decision_id}")
        if row["disposition"] != "PROPOSE_OPERATOR_APPROVAL":
            raise ValueError(
                f"decision {decision_id} is {row['disposition']!r}; "
                "only PROPOSE_OPERATOR_APPROVAL decisions can be approved")
        seq = int(row["seq"])
        prior = self.ledger.approval_for(decision_id, seq)
        if prior is not None:
            raise ValueError(
                f"decision {decision_id} seq {seq} already has a "
                f"{prior['outcome']} approval ({prior['approval_id']}); "
                "approvals are one-shot")
        ind = self.ledger.get_indicator(row["indicator_id"])
        if ind is None:
            raise LookupError(
                f"indicator {row['indicator_id']} for decision {decision_id} missing")
        decision = decision_from_row(row)
        # audit P0 #6: the proposal was produced under SOME policy revision;
        # approve only under the CURRENT one. A semantic policy change
        # invalidates pending proposals — they must be regenerated (the
        # safer of the two allowed rules) rather than re-validated.
        active_row = self.ledger.current_policy_row()
        bound = row.get("policy_content_sha256")
        current = active_row["content_sha256"] if active_row else None
        if bound and current and bound != current:
            raise ValueError(
                f"decision {decision_id} was proposed under a different "
                f"policy revision (content {bound[:12]}…; active "
                f"{current[:12]}…); re-propose under the current policy")
        # claim the approval FIRST (atomic at the database): a concurrent
        # duplicate approve can never double-compile actions. If action
        # compilation then fails, the approval stands (durable operator
        # intent) and compilation is retried via actions/approve retry.
        approval_id = "approval--" + uuid.uuid4().hex[:24]
        if not self.ledger.record_approval(
                approval_id=approval_id, decision_id=decision_id,
                decision_seq=seq, outcome="approved", actor=actor, reason=reason,
                policy_version=row["policy_version"],
                policy_content_sha256=row["policy_content_sha256"]):
            raise ValueError(
                f"decision {decision_id} seq {seq} was just approved or "
                "rejected by another operator; approvals are one-shot")
        # a decision may render fragments for MULTIPLE adapters: every
        # created action id is propagated into the approval row and the API
        # response (review P1 #32)
        action_ids: list[str] = self.create_action_from_decision(
            decision, ind["value"], ind["itype"], actor=actor, decision_seq=seq)
        if action_ids:
            self.ledger.set_approval_actions(
                approval_id, tuple(action_ids))
        # audit #29: an approval that compiles to ZERO fragments is reported
        # honestly as `decision valid / materialization unavailable` — the
        # capability registry says which configured adapter could have
        # executed it and why none did. An operator is never left inviting
        # an approval that silently creates nothing.
        result = {"decision_id": decision_id, "approval_id": approval_id,
                  "action_ids": action_ids,
                  "compiled": bool(action_ids)}
        if not action_ids:
            result["materialization"] = {
                "available": False,
                "reason": "no configured adapter compiles this decision "
                          "(decision valid / materialization unavailable)",
                "adapters": self.capability_matrix(),
            }
        return result

    def capability_matrix(self) -> list[dict]:
        """The truthful feature matrix (audit #29): every configured
        adapter's advertised capabilities. UI/CLI surface for what this
        deployment can actually materialize."""
        rows: list[dict] = []
        for adapter in self._adapters.values():
            cap = getattr(adapter, "capabilities", None)
            row: dict = dict(cap()) if callable(cap) else {}   # type: ignore[arg-type]
            if not callable(cap):
                row = {"max_posture": adapter.max_mode()}
            row["name"] = adapter.name
            rows.append(row)
        return rows

    def materialization_for(self, decision: Decision,
                            indicator_value: str,
                            indicator_type: str) -> dict:
        """Whether THIS decision (action/type/selector) is materializable by
        the configured deployment — without compiling or persisting
        anything. `available=False` carries the gap: which capability the
        configured adapters lack (audit #25/#26/#27/#28 honesty)."""
        fragments: list[dict] = []
        for adapter in self._adapters.values():
            try:
                fragments.extend(adapter.compile(
                    decision, indicator_value, indicator_type))
            except AdapterError:
                pass    # a refuse-to-broaden compile is "not materializable"
        if fragments:
            return {"available": True, "action_ids": [], "adapters":
                    sorted({f["adapter"] for f in fragments})}
        action = decision.action
        sel = getattr(decision, "selector", None)
        scope = getattr(sel, "scope_type", None) if sel is not None else None
        itype = indicator_type
        gaps: list[str] = []
        if action in ("proxy_challenge",):
            gaps.append(f"no proxy/WAF actuator exists for {action} "
                        "(NOT MATERIALIZABLE in beta)")
        elif action == "rate_limit":
            gaps.append("no enforcing rate-limit actuator exists "
                        "(Suricata exports detection-filter INTENT only; "
                        "NOT MATERIALIZABLE as enforcement in beta)")
        elif action == "firewall_deny":
            gaps.append("no firewall actuator exists (Suricata renders "
                        "alert/IDS only; NOT MATERIALIZABLE as enforcement "
                        "in beta)")
        if itype == "cidr":
            gaps.append("cidr targets have no supported adapter (audit #28: "
                        "materializable=false, reason=no_supported_adapter)")
        if scope and scope != "destination_global":
            gaps.append(f"selector shape {scope} is not materializable by "
                        "any configured adapter")
        if not gaps:
            gaps.append("no configured adapter accepts this action/type "
                        "combination")
        return {"available": False, "action_ids": [], "gaps": gaps,
                "adapters": self.capability_matrix()}

    def reject_decision(self, decision_id: str, actor: str,
                        reason: str = "operator_rejected") -> dict:
        """Reject a proposal durably: the decision instance can never be
        approved afterwards (review P0 #16)."""
        row = self.ledger.get_decision(decision_id)
        if row is None:
            raise LookupError(f"unknown decision {decision_id}")
        if row["disposition"] != "PROPOSE_OPERATOR_APPROVAL":
            raise ValueError(
                f"decision {decision_id} is {row['disposition']!r}; "
                "only PROPOSE_OPERATOR_APPROVAL decisions can be rejected")
        seq = int(row["seq"])
        prior = self.ledger.approval_for(decision_id, seq)
        if prior is not None:
            raise ValueError(
                f"decision {decision_id} seq {seq} already has a "
                f"{prior['outcome']} approval ({prior['approval_id']})")
        approval_id = "approval--" + uuid.uuid4().hex[:24]
        self.ledger.record_approval(
            approval_id=approval_id, decision_id=decision_id,
            decision_seq=seq, outcome="rejected", actor=actor, reason=reason,
            policy_version=row["policy_version"],
            policy_content_sha256=row["policy_content_sha256"])
        return {"decision_id": decision_id, "approval_id": approval_id,
                "outcome": "rejected"}

    def replay_policy(self, actor: str) -> dict:
        """Re-run every existing indicator through the ACTIVE policy version,
        appending fresh decisions. Re-baselines against a newly promoted
        policy: idempotent by decision content hash, so an unchanged indicator
        records nothing new, while a changed verdict appends a new decision.
        Pre-existing actionable decisions are NOT auto-compiled — replay only
        produces decisions; operators act (approve/enforce) from the worklist.
        """
        indicators = self.ledger.list_indicators(limit=100000)
        new_policy = self.current_policy()
        if new_policy is None:
            raise RuntimeError("no active policy; refusing to replay")
        recorded = 0
        changed = 0
        for ind in indicators:
            before = self.ledger.get_decision(ind["indicator_id"])
            result = self.pipeline.decide_indicator(ind["indicator_id"], actor=actor)
            if result is None or not result["recorded"]:
                continue
            recorded += 1
            # a disposition change means the policy semantics shifted a verdict
            if before and before.get("disposition") != result["decision"].disposition:
                changed += 1
        self.ledger.audit(actor, "policy.replay", "",
                          {"policy_version": new_policy.version,
                           "active_revision": self._active_policy_revision(),
                           "indicators": len(indicators), "recorded": recorded,
                           "changed": changed})
        return {"indicators": len(indicators), "recorded": recorded,
                "changed": changed,
                "policy_version": self._active_policy_revision() or new_policy.version}

    def revoke_action(self, action_id: str, actor: str, reason: str = "operator_revoke") -> dict:
        """Manual revoke uses the SAME controlled path as expiry (goal G),
        SERIALIZED against every other removal path by the same CAS claim
        the lease-holding worker uses (review P0 #21): no operator call can
        mutate the adapter concurrently with a worker expiry/reconcile, and
        two operators revoking on different controllers cannot double-remove.

        HA actuation contract (audit P0 #9): this API-served path NEVER
        mutates infrastructure unless THIS controller holds the worker
        lease. A follower only commits the durable ABSENT intent and
        defers the physical removal to the lease-owning reconciler (step
        0b converges desired-ABSENT rows) — in a real HA deployment
        controller B's local adapter is not the actuator just because the
        API request landed there."""
        action = self.ledger.get_action(action_id)
        if action is None:
            raise LookupError(f"unknown action {action_id}")
        if action["state"] in ("revoked", "expired"):
            return {"action_id": action_id, "state": action["state"],
                    "already_terminal": True}
        if action["state"] in ("pending", "cancelled_policy_changed"):
            # nothing was ever applied: terminal without touching the adapter
            self.ledger.set_action_state(action_id, "revoked", reason, actor)
            self.db.execute(
                "UPDATE actions SET revoked_by=%s, revoked_at=now() "
                "WHERE action_id=%s", (actor, action_id))
            return {"action_id": action_id, "state": "revoked",
                    "verified": True, "not_applied": True}
        # Commit the durable ABSENT intent FIRST (audit P0 #4/#9): the
        # request itself only mutates desired state. A crash after this
        # commit converges to removal, never re-apply.
        if not self.ledger.request_removal(
                action_id, ("applied", "verified", "drifted", "dispatching")):
            return {"action_id": action_id, "state": action["state"],
                    "already_removing": True}
        if not self._acquire_or_renew_lease():
            # follower: intent is durable; the LEADER's reconciler performs
            # the physical removal (audit P0 #9)
            self.ledger.audit(actor, "action.revoke_intent_deferred",
                              action_id, {"reason": reason,
                                          "by": "follower_no_lease"})
            return {"action_id": action_id, "state": "removing",
                    "verified": False, "deferred_to_leader": True}
        result = self._remove_action(action, actor, reason,
                                     terminal_state="revoked", revoked_by=actor)
        if result["state"] == "drifted":
            # unverified removal: the reconcile sweep retries as a REMOVAL
            # (desired stays ABSENT) rather than stranding the claim
            self.ledger.retry_removal(action_id)
        return result

    # -- worker: dispatch ---------------------------------------------------------

    def _dispatch_loop(self) -> None:
        while not self._stop.wait(self.config.controller.reconcile_interval_s):
            try:
                # HA: only the live lease holder dispatches pending actions.
                # A follower attempts takeover each loop and otherwise observes.
                if self._acquire_or_renew_lease():
                    self._dispatch_pending()
            except DatabaseUnavailable as e:
                self.state.last_reconcile_error = f"dispatch: {e}"
            except Exception as e:   # worker must never die silently
                self.state.last_reconcile_error = f"dispatch: {e!r}"

    def _dispatch_pending(self) -> None:
        for action in self.ledger.actions_needing_dispatch():
            # Atomic claim: exactly one leader dispatches each pending action.
            # If another controller already claimed it (lease handoff race /
            # crash between SELECT and apply), skip — the loser never applies.
            if not self.ledger.claim_pending_action(action["action_id"]):
                continue
            self._dispatch_one(action)

    # -- worker: decoupled ingest (audit P1 #15) --------------------------------

    def _ingest_loop(self) -> None:
        """Bounded queue drain: one worker claims ONE accepted batch at a
        time (FOR UPDATE SKIP LOCKED) and runs the pipeline. Bounded by
        construction — never more batches in flight than workers (one) —
        and the durable queue itself is the backpressure: the API only
        accepts what it can persist. Poll cadence is short (1s): the queue
        is the decoupling boundary, not a scheduler."""
        # first poll promptly after start
        while not self._stop.wait(1.0):
            break
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                claimed = self.ledger.claim_queued_batch()
                if claimed is not None:
                    self._process_queued(claimed)
            except DatabaseUnavailable as e:
                self.state.last_reconcile_error = f"ingest: {e}"
            except Exception as e:   # worker must never die silently
                self.state.last_reconcile_error = f"ingest: {e!r}"
            elapsed = time.monotonic() - started
            self._stop.wait(max(1.0, 1.0 - elapsed))

    def _process_queued(self, claimed: dict) -> None:
        """Resume-or-run one claimed batch. The payload is re-parsed from
        the persisted bytes with the SAME channel binding, so a crash at
        any point resumes instead of losing work; a payload that no longer
        parses (registry drift) fails the batch loudly."""
        from apip.ingest import IngestChannel, parse_indicator_payload
        src = self.ledger.get_source(claimed["source_id"]) or {}
        channel = IngestChannel(
            source_id=claimed["source_id"],
            allowed_source_ids=frozenset(
                s for s in (src.get("upstream") or "").split(",") if s),
            allowed_kinds=frozenset(src.get("allowed_kinds") or ()))
        try:
            payload = claimed["raw_payload"]
            if isinstance(payload, memoryview):
                payload = payload.tobytes()
            batch = parse_indicator_payload(
                bytes(payload), channel)
        except Exception as e:   # noqa: BLE001
            self.ledger.fail_batch(claimed["batch_id"], f"reparse failed: {e}")
            return
        self.process_batch(batch=batch, actor=claimed["source_id"],
                           tenant_id=claimed.get("tenant_id"))

    def ingest_status(self, batch_id: str) -> dict | None:
        """Public batch processing status (audit P1 #15)."""
        return self.ledger.batch_outcome(batch_id)

    def _stale_authorization(self, action: dict, *,
                             require_current_revision: bool = True) -> str | None:
        """None when the action may still be applied (or may remain
        applied); a reason string when its authorization no longer holds
        under the CURRENT effective policy (review P0 #7, audit P0 #5/#6).
        Checks, in order:
          1. an effective policy still exists;
          2. (require_current_revision — the DISPATCH path, audit P0 #6)
             the persisted policy-content hash still matches the current
             effective authorization revision: a pending action authorized
             by an OLDER revision does not survive a policy promotion —
             it must be regenerated under the new policy. The periodic
             RECONCILE of already-applied controls deliberately does NOT
             bind to the hash (a promotion would churn every control
             regardless of semantics); it re-checks semantics only;
          3. the shared presence predicate (audit P0 #5): posture gate,
             allowlist gate, scope gate — exactly the evaluate() gates
             that decide whether the policy would still issue this
             control today.
        """
        ind_row = self.ledger.get_indicator(action["indicator_id"])
        if ind_row is None:
            return "indicator_missing"
        tenant_id = ind_row.get("tenant_id")
        policy = self.effective_policy_for(tenant_id)
        if policy is None:
            return "no_active_policy"
        if require_current_revision:
            revision_row = self.ledger.current_policy_row()
            decision = (self.ledger.get_decision(action["decision_id"])
                        if action.get("decision_id") else None)
            if decision is None:
                return "authorizing_decision_missing"
            bound = decision.get("policy_content_sha256")
            current = revision_row["content_sha256"] if revision_row else None
            if bound and current and bound != current:
                return ("policy_revision_changed: decision was authorized "
                        f"by policy content {bound[:12]}…; the active "
                        f"revision is {current[:12]}… (audit P0 #6: "
                        "regenerate under the current policy)")
        reason = policy_allows_presence(ind_row["value"], ind_row["itype"],
                                        action["mode"], policy)
        if reason:
            return reason
        return None

    def _dispatch_one(self, action: dict) -> None:
        action_id = action["action_id"]
        # Re-authorize at DISPATCH time (review P0 #7): creation-time
        # authorization can go stale — a policy promotion may narrow scope,
        # retire the authorizing posture, or invalidate the approval between
        # action creation and worker dispatch. Re-check the CURRENT effective
        # policy before every external apply; cancel rather than apply.
        cancel = self._stale_authorization(action)
        if cancel:
            self.ledger.record_attempt(
                action_id=action_id, phase="prepare", ok=False,
                detail={"cancelled": cancel}, actor=CONTROLLER_ACTOR)
            self.ledger.set_action_state(
                action_id, "cancelled_policy_changed", cancel,
                CONTROLLER_ACTOR)
            return
        try:
            self.ledger.record_attempt(action_id=action_id, phase="prepare",
                                       ok=True, detail={"mode": action["mode"]},
                                       actor=CONTROLLER_ACTOR)
            result = self._adapter_for(action).apply(
                {"rule_id": action["rule_id"], "fragment": action["fragment"],
                 "mode": action["mode"], "selector": action["selector"]})
            self.ledger.record_attempt(
                action_id=action_id, phase="apply", ok=result.get("ok", False),
                detail=result, actor=CONTROLLER_ACTOR)
            if not result.get("ok"):
                self.ledger.set_action_state(
                    action_id, "failed", result.get("error", "apply_failed"),
                    CONTROLLER_ACTOR)
                return
            receipt = result.get("receipt") or {}
            self.ledger.record_receipt(
                receipt_id=receipt.get("receipt_id", f"receipt--{action_id}"),
                action_id=action_id, adapter=action["adapter"],
                rule_id=action["rule_id"],
                fragment_hash=action["fragment_hash"],
                bundle_id=action["bundle_id"], bundle_hash=action["bundle_hash"],
                observed=receipt.get("observed", {}),
                status=receipt.get("status", "applied"),
                verified=False)
            # audit P1 #11: apply is immediately followed by independent
            # verification — an "applied" declaration without observed
            # effect is exactly the file-state != enforcement-state gap.
            # Success -> 'verified'; failure -> 'applied' (the reconcile
            # sweep keeps verifying on cadence and can still converge).
            try:
                v = self._adapter_for(action).verify(
                    {"rule_id": action["rule_id"],
                     "fragment": action["fragment"],
                     "mode": action["mode"],
                     "selector": action["selector"]})
                self.ledger.record_attempt(
                    action_id=action_id, phase="verify",
                    ok=bool(v.get("ok")), detail=v, actor=CONTROLLER_ACTOR)
                if v.get("ok"):
                    self.ledger.set_action_state(
                        action_id, "verified", "verified_on_apply",
                        CONTROLLER_ACTOR,
                        verified_at=datetime.now(timezone.utc))
                    self.ledger.record_receipt(
                        receipt_id=f"receipt--{action_id}--verify-on-apply",
                        action_id=action_id, adapter=action["adapter"],
                        rule_id=action["rule_id"],
                        fragment_hash=action["fragment_hash"],
                        bundle_id=action["bundle_id"],
                        bundle_hash=action["bundle_hash"],
                        observed=v.get("observed", {}),
                        status="verified", verified=True)
                    return
                verify_error = v.get("error", "verification_failed")
            except AdapterError as e:
                verify_error = str(e)
                self.ledger.record_attempt(
                    action_id=action_id, phase="verify", ok=False,
                    detail={"error": verify_error}, actor=CONTROLLER_ACTOR)
            self.ledger.set_action_state(
                action_id, "applied", f"dispatched_unverified: {verify_error}",
                CONTROLLER_ACTOR)
        except AdapterError as e:
            self.ledger.record_attempt(action_id=action_id, phase="apply",
                                       ok=False, detail={"error": str(e)},
                                       actor=CONTROLLER_ACTOR)
            self.ledger.set_action_state(action_id, "failed", str(e),
                                         CONTROLLER_ACTOR)

    # -- worker: reconcile (verify + expiry) --------------------------------------

    def _reconcile_loop(self) -> None:
        # first pass promptly after start
        while not self._stop.wait(1.0):
            break
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                # HA: expiry/verify sweeps run ONLY while holding the worker
                # lease — a second controller on the same ledger can't double-
                # remove or double-verify a rule. A follower still refreshes
                # health and attempts takeover on the next loop.
                if self._acquire_or_renew_lease():
                    self._reconcile_pass()
                    self.state.last_reconcile_ok = True
                    self.state.last_reconcile_error = None
                else:
                    self.state.last_reconcile_ok = False
                    self.state.last_reconcile_error = "follower (not lease leader)"
            except DatabaseUnavailable as e:
                self.state.last_reconcile_ok = False
                self.state.last_reconcile_error = f"reconcile: {e}"
            except Exception as e:
                self.state.last_reconcile_ok = False
                self.state.last_reconcile_error = f"reconcile: {e!r}"
            finally:
                self.state.last_reconcile_at = datetime.now(timezone.utc)
                self._refresh_policy_state()
            elapsed = time.monotonic() - started
            self._stop.wait(max(1.0, self.config.controller.reconcile_interval_s - elapsed))

    def _reconcile_pass(self) -> None:
        now = datetime.now(timezone.utc)
        # 0. crash-recovery of claimed-but-unfinished operations (audit P0 #4).
        #    The durable desired_state disambiguates intent: an APPLY claim
        #    ('dispatching', desired PRESENT) returns to pending so the next
        #    leader re-applies; a REMOVAL claim ('removing', desired ABSENT)
        #    is requeued AS A REMOVAL — it can never become an apply.
        stale = now - timedelta(seconds=max(
            10, 3 * self.config.controller.reconcile_interval_s))
        for action in self.ledger.actions_stuck_dispatching(stale):
            self.ledger.unclaim_action(action["action_id"])
        # a 'removing' row never reconciled at all is a follower-deferred
        # removal intent (audit P0 #9): the leader adopts it immediately.
        # Rows wedged past the stale window are crash recovery.
        for action in self.ledger.actions_stuck_removing(
                stale, include_unreconciled=True):
            self.ledger.retry_removal(action["action_id"])
        # 0b. any action whose desired_state is ABSENT but which still sits
        #     in an active state (a removal interrupted before the adapter
        #     call) re-enters the removal phase — converge toward ABSENT.
        for action in self.ledger.actions_desired_absent_active():
            if self.ledger.request_removal(
                    action["action_id"],
                    ("applied", "verified", "drifted", "removing")):
                self._remove_action(action, CONTROLLER_ACTOR,
                                    "desired_absent_reconcile",
                                    terminal_state="revoked", revoked_by=None)
        # 0c. policy-promotion reconciliation (audit P0 #5): an already-
        #     applied/verified control is re-authorized against the CURRENT
        #     effective policy. Verification alone would happily keep an
        #     obsolete control healthy — backwards. A stale control commits
        #     durable desired ABSENT and leaves through the SAME reconciler
        #     path as expiry/revoke.
        for action in self.ledger.actions_active_state():
            cancel = self._stale_authorization(
                action, require_current_revision=False)
            if not cancel:
                continue
            if self.ledger.request_removal(
                    action["action_id"],
                    ("applied", "verified", "drifted")):
                self.ledger.audit(CONTROLLER_ACTOR,
                                  "action.policy_reconcile_invalidated",
                                  action["action_id"], {"reason": cancel})
                result = self._remove_action(
                    action, CONTROLLER_ACTOR,
                    f"policy_reconcile: {cancel}",
                    terminal_state="revoked", revoked_by=None)
                if result["state"] == "drifted":
                    self.ledger.retry_removal(action["action_id"])
        # 1. expiry sweep: TTL reached -> remove via controlled path.
        # Commit the ABSENT intent FIRST (audit P0 #4), then remove: a crash
        # anywhere after the intent commit converges to removal, never apply.
        for action in self.ledger.actions_due_for_expiry(now):
            if not self.ledger.request_removal(
                    action["action_id"], ("applied", "verified", "drifted")):
                continue
            result = self._remove_action(action, CONTROLLER_ACTOR, "ttl_expired",
                                         terminal_state="expired",
                                         revoked_by=None)
            if result["state"] == "drifted":
                # removal unverified: requeue as removal (desired stays ABSENT)
                self.ledger.retry_removal(action["action_id"])
        # 2. verification sweep: applied/verified actions re-checked
        older_than = now - timedelta(seconds=self.config.controller.verify_interval_s)
        for action in self.ledger.actions_needing_verification(older_than):
            self._verify_action(action)
        # 3. behavioral attachment (audit #17/#19/#20): the leader folds the
        #    live feed's retained detections onto KNOWN indicators only —
        #    a detection for a value nobody ingested stays dormant in the
        #    feed's bounded pending cache (no authority from thin air).
        #    Evidence lands under the governed local-behavioral principal
        #    (audit #22) through the normal observation-identity path, and
        #    the indicator is RE-DECIDED so fresh behavioral facts can move
        #    a decision — policy gates (incl. enabled families, audit #23)
        #    apply exactly as to any other evidence.
        self._attach_behavioral_evidence(now)

    def _attach_behavioral_evidence(self, now) -> None:
        feed = self.behavioral_feed
        known: dict[str, str] = {}
        for row in self.ledger.all_indicator_values():
            known[row["value"]] = row["indicator_id"]
        if not known and not feed.pending_unknown:
            return
        records = feed.attach_to_indicators(known,
                                            now_epoch=int(now.timestamp()))
        attached = 0
        for rec in records:
            ind_id = rec.get("indicator_id")
            if not ind_id:
                continue
            try:
                durable = self.ledger.attach_evidence_fields(
                    indicator_id=ind_id, kind=rec["kind"],
                    source_id=rec["source_id"],
                    observed_at=rec.get("observed_at"),
                    detail=rec.get("detail") or {})
            except Exception:      # noqa: BLE001 — one bad record must not
                continue           # stop the sweep; counted upstream
            if durable:
                attached += 1
                self.ledger.audit(CONTROLLER_ACTOR,
                                  "behavioral.evidence_attached",
                                  ind_id, {"kind": rec["kind"],
                                           "target": rec.get("target")})
                self.pipeline.decide_indicator(
                    ind_id, CONTROLLER_ACTOR,
                    tenant_id=(self.ledger.get_indicator(ind_id) or {})
                    .get("tenant_id"))

    def _verify_action(self, action: dict) -> None:
        action_id = action["action_id"]
        try:
            result = self._adapter_for(action).verify(
                {"rule_id": action["rule_id"], "fragment": action["fragment"],
                 "mode": action["mode"], "selector": action["selector"]})
            self.ledger.record_attempt(action_id=action_id, phase="verify",
                                       ok=bool(result.get("ok")),
                                       detail=result, actor=CONTROLLER_ACTOR)
            if result.get("ok"):
                self.ledger.set_action_state(
                    action_id, "verified", "verified_against_infra",
                    CONTROLLER_ACTOR,
                    verified_at=datetime.now(timezone.utc))
                self.ledger.record_receipt(
                    receipt_id=f"receipt--{action_id}--verify",
                    action_id=action_id, adapter=action["adapter"],
                    rule_id=action["rule_id"],
                    fragment_hash=action["fragment_hash"],
                    bundle_id=action["bundle_id"], bundle_hash=action["bundle_hash"],
                    observed=result.get("observed", {}),
                    status="verified", verified=True)
            else:
                self.ledger.set_action_state(
                    action_id, "drifted", result.get("error", "verification_failed"),
                    CONTROLLER_ACTOR)
        except AdapterError as e:
            self.ledger.record_attempt(action_id=action_id, phase="verify",
                                       ok=False, detail={"error": str(e)},
                                       actor=CONTROLLER_ACTOR)
            self.ledger.set_action_state(action_id, "drifted", f"adapter_error: {e}",
                                         CONTROLLER_ACTOR)

    def _remove_action(self, action: dict, actor: str, reason: str, *,
                       terminal_state: str, revoked_by: str | None) -> dict:
        """Remove a control through the adapter, VERIFY the removal, then
        record the terminal state. If removal cannot be verified the action
        stays `drifted` — never silently marked gone.

        Multi-action ownership (review P0 #6): the adapter's physical rule
        (RPZ owner / Suricata sid) may be shared by several active actions
        (e.g. two decisions denying the same FQDN). While ANY other active
        action still requires the rule, this action reaches its terminal
        state WITHOUT removing the shared physical rule — desired state stays
        while any justification remains."""
        action_id = action["action_id"]
        co_owners = self.ledger.active_co_owners(
            adapter=action["adapter"], rule_id=action["rule_id"],
            exclude_action_id=action_id, mode=action.get("mode"))
        if co_owners:
            self.ledger.record_attempt(
                action_id=action_id, phase="revoke", ok=True,
                detail={"deferred_removal": True,
                        "co_owners": [c["action_id"] for c in co_owners]},
                actor=actor)
            self.ledger.set_action_state(action_id, terminal_state, reason, actor)
            if revoked_by:
                self.db.execute(
                    "UPDATE actions SET revoked_by=%s, revoked_at=now() "
                    "WHERE action_id=%s", (revoked_by, action_id))
            return {"action_id": action_id, "state": terminal_state,
                    "verified": True, "shared_rule": True,
                    "co_owners": [c["action_id"] for c in co_owners]}
        try:
            result = self._adapter_for(action).revoke(
                {"rule_id": action["rule_id"], "fragment": action["fragment"],
                 "mode": action["mode"], "selector": action["selector"]})
            self.ledger.record_attempt(action_id=action_id, phase="revoke",
                                       ok=bool(result.get("ok")),
                                       detail=result, actor=actor)
            if result.get("ok"):
                self.ledger.set_action_state(action_id, terminal_state, reason,
                                             actor)
                if revoked_by:
                    self.db.execute(
                        "UPDATE actions SET revoked_by=%s, revoked_at=now() WHERE action_id=%s",
                        (revoked_by, action_id))
                return {"action_id": action_id, "state": terminal_state,
                        "verified": True}
            self.ledger.set_action_state(action_id, "drifted",
                                         f"revoke_unverified: {result.get('error', '')}",
                                         actor)
            return {"action_id": action_id, "state": "drifted", "verified": False}
        except AdapterError as e:
            self.ledger.record_attempt(action_id=action_id, phase="revoke",
                                       ok=False, detail={"error": str(e)},
                                       actor=actor)
            self.ledger.set_action_state(action_id, "drifted",
                                         f"revoke_adapter_error: {e}", actor)
            return {"action_id": action_id, "state": "drifted", "verified": False}

    # -- health ---------------------------------------------------------------------

    def health(self) -> dict:
        db_health = self.db.health()
        try:
            registry_rows = self.ledger.list_sources()
            pipeline_ok = self.state.policy_loaded
        except DatabaseUnavailable:
            registry_rows = []
            pipeline_ok = False
        adapter_health = self.adapter.health()
        adapters_health = self.adapters_status()
        snap = self.state.snapshot(
            db_health=db_health, ledger=self.ledger if db_health.get("status") == "up" else None,
            adapter_health=adapter_health, adapters_health=adapters_health,
            registry_rows=registry_rows, pipeline_ok=pipeline_ok)
        # audit #17: the live behavioral frontier is a health surface — an
        # inert feed (no datasource) says so; a configured source reports
        # its own lag/drop counters.
        snap["behavioral"] = self.behavioral_status()
        return snap

    def behavioral_status(self) -> dict:
        feed = self.behavioral_feed.health()
        feed["source"] = (self.eve_source.stats()
                          if self.eve_source is not None else
                          {"configured": False,
                           "note": "no telemetry datasource configured "
                                   "(controller.suricata_eve_path empty); "
                                   "live detectors are inert"})
        return feed

    def adapters_status(self) -> list[dict]:
        """Health for every configured enforcement adapter (defense in depth —
        a degraded non-primary adapter must not be masked by the primary RPZ)."""
        return [_adapter_health(a) for a in self._adapters.values()]
