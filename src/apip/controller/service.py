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

import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from apip.adapters.base import AdapterError, EnforcementAdapter, MODE_RANK
from apip.adapters import build_adapters
from apip.adapters.rpz import RpzAdapter
from apip.config.service import ServiceConfig
from apip.controller.engine import DecisionPipeline, now_iso_utc
from apip.decision.policy import in_scope
from apip.decision.policy import Policy
from apip.domain.models import ActionSelector, Decision
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
        self.ledger.audit(CONTROLLER_ACTOR, "controller.start", "", {})
        self.state.started_at = datetime.now(timezone.utc)
        self._refresh_policy_state()
        interval = self.config.controller.reconcile_interval_s
        for name, target in (
            ("dispatch", self._dispatch_loop),
            ("reconcile", self._reconcile_loop),
        ):
            t = threading.Thread(target=target, name=f"apip-{name}", daemon=True)
            t.start()
            self._threads.append(t)
        self.ledger.audit(CONTROLLER_ACTOR, "controller.workers_started",
                          "", {"interval_s": interval})

    def stop(self) -> None:
        self._stop.set()
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
                                    indicator_type: str, actor: str) -> str | None:
        """Compile a decision into an action through the adapter, with the
        controller-layer scope check (defense in depth layer 2; the decision
        engine checked layer 1, the adapter re-checks layer 3)."""
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
            return None
        if not in_scope(indicator_value, indicator_type, policy):
            self.ledger.audit(actor, "action.rejected_scope", decision.id,
                              {"value": indicator_value, "type": indicator_type})
            return None

        fragments: list[dict] = []
        for adapter in self._adapters.values():
            fragments.extend(adapter.compile(decision, indicator_value, indicator_type))
        if not fragments:
            return None
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=decision.ttl_seconds or self.config.controller.default_action_ttl_s)
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
            self.ledger.record_action(
                action_id=action_id, decision=decision,
                indicator_id=decision.indicator_id, adapter=frag["adapter"],
                mode=mode, fragment=frag, expires_at=expires_at,
                requested_by=actor)
            action_ids.append(action_id)
        return action_ids[0] if action_ids else None

    def approve_decision(self, decision_id: str, actor: str) -> dict:
        """Operator approval of a decision awaiting it (PROPOSE_OPERATOR_APPROVAL).

        Rebuilds the decision from ledger state (never re-decides), re-applies
        the controller scope check, compiles actions at the approvals rating,
        and audits the operator identity. Fails closed when the decision is
        not awaiting approval or cannot be compiled.
        """
        row = self.ledger.get_decision(decision_id)
        if row is None:
            raise LookupError(f"unknown decision {decision_id}")
        if row["disposition"] != "PROPOSE_OPERATOR_APPROVAL":
            raise ValueError(
                f"decision {decision_id} is {row['disposition']!r}; "
                "only PROPOSE_OPERATOR_APPROVAL decisions can be approved")
        ind = self.ledger.get_indicator(row["indicator_id"])
        if ind is None:
            raise LookupError(
                f"indicator {row['indicator_id']} for decision {decision_id} missing")
        decision = decision_from_row(row)
        action_ids: list[str] = []
        # a decision may render fragments for multiple adapters
        result = self.create_action_from_decision(
            decision, ind["value"], ind["itype"], actor=actor)
        if result:
            action_ids.append(result)
        self.ledger.audit(
            actor, "decision.approved", decision_id,
            {"disposition": row["disposition"], "indicator_id": ind["indicator_id"],
             "value": ind["value"], "type": ind["itype"], "action_ids": action_ids})
        return {"decision_id": decision_id, "action_ids": action_ids,
                "compiled": bool(action_ids)}

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
        """Manual revoke uses the SAME controlled path as expiry (goal G)."""
        action = self.ledger.get_action(action_id)
        if action is None:
            raise LookupError(f"unknown action {action_id}")
        if action["state"] in ("revoked", "expired"):
            return {"action_id": action_id, "state": action["state"],
                    "already_terminal": True}
        return self._remove_action(action, actor, reason,
                                   terminal_state="revoked", revoked_by=actor)

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

    def _dispatch_one(self, action: dict) -> None:
        action_id = action["action_id"]
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
            self.ledger.set_action_state(action_id, "applied", "dispatched",
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
        # 0. crash-recovery of a claimed-but-never-applied dispatch: a leader
        #    that was mid-apply when it died leaves the action 'dispatching'.
        #    Return any such action (untouched for a full reconcile window,
        #    so we never yank an actually in-flight apply) to pending so the
        #    next leader re-claims and applies it.
        stale = now - timedelta(seconds=max(
            10, 3 * self.config.controller.reconcile_interval_s))
        for action in self.ledger.actions_stuck_dispatching(stale):
            self.ledger.unclaim_action(action["action_id"])
        # 1. expiry sweep: TTL reached -> remove via controlled path
        for action in self.ledger.actions_due_for_expiry(now):
            self._remove_action(action, CONTROLLER_ACTOR, "ttl_expired",
                                terminal_state="expired", revoked_by=None)
        # 2. verification sweep: applied/verified actions re-checked
        older_than = now - timedelta(seconds=self.config.controller.verify_interval_s)
        for action in self.ledger.actions_needing_verification(older_than):
            self._verify_action(action)

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
        stays `drifted` — never silently marked gone."""
        action_id = action["action_id"]
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
        return self.state.snapshot(
            db_health=db_health, ledger=self.ledger if db_health.get("status") == "up" else None,
            adapter_health=adapter_health, adapters_health=adapters_health,
            registry_rows=registry_rows, pipeline_ok=pipeline_ok)

    def adapters_status(self) -> list[dict]:
        """Health for every configured enforcement adapter (defense in depth —
        a degraded non-primary adapter must not be masked by the primary RPZ)."""
        return [_adapter_health(a) for a in self._adapters.values()]
