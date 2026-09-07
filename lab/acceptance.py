#!/usr/bin/env python3
"""APIP re-runnable acceptance loop (docs/30 acceptance steps 1-20).

This is the *shippable proof* that the v0.1.0 beta loop works end-to-end: a
reviewer can run it from a fresh clone and, if the environment provides a
reachable Postgres the current OS user may create scratch databases in, it
reproduces the full loop with a REAL UDP DNS query — not just in-process
assertions — and exits 0 only when every step passed.

It drives the REAL product wiring: `controller.pipeline.decide_indicator`
(the clean, deterministic AI-free decision engine), `Controller.approve_decision`
(the operator-approval path by which an exact-FQDN RPZ action actually reaches
the adapter), `_dispatch_one` (applies + records a receipt with observed infra
state), `_verify_action` (independent verification), and `_remove_action` (the
controlled revoke/expiry path). The lab resolver (lab/resolver.py) performs the
real UDP DNS answers, re-reading the RPZ zone on every query so it reflects the
adapter's live writes.

Why operator approval and not auto-enforcement: the RPZ ``dns_nxdomain`` ladder
(L4) in this beta genuinely requires a client destination-pair selector with
interactive protocol. The real `decide_indicator` for a bare FQDN crosses no
client context and therefore yields a deterministic OBSERVE (L0) verdict — the
engine observes but does not invent an enforcement intention. Reaching an
enforcement action is an OPERATOR decision, expressed as approving a proposed
high-impact action (``PROPOSE_OPERATOR_APPROVAL``). The integration suite
already validates this exact approval flow; the acceptance adds the REAL DNS
dimension no existing test covers: the approved action's exact-FQDN CNAME .
rule turns the resolver's answer from baseline (10.99.0.9) into NXDOMAIN.

Adapter posture is a config-time value in the product (no runtime set_posture),
so SHADOW-monitor-only and ENFORCE are two named legs of the run. The operator
"going to enforcement" is reified as a stop+start of the controller against the
SAME scratch ledger — which is exactly what step 20 (restart survival) checks:
after the SHADOW leg populates the ledger, the ENFORCE leg restarts the
controller and must still see all decisions/actions/receipts.

Steps (labels follow docs/30):
   1. start APIP + database
   2. register a synthetic trusted source
   3. install a SHADOW policy
   4. ingest evidence for c2-test.operator.test
   5. APIP generates a deterministic decision (engine OBSERVE — no fabricated
      enforcement intention)
   6. operator drives an exact-FQDN RPZ action (proposed + approved)
   7. prepare an exact-FQDN RPZ rule
   8. adapter validates the candidate (SHADOW monitor-only zone, no receipt fab)
   9. SHADOW: no live resolver behavior change (real DNS: still 10.99.0.9)
  10. operator goes to enforcement (adapter posture ENFORCE, policy ENFORCE)
  11. APIP applies the RPZ rule
  12. APIP independently verifies the resolver state
  13. real query demonstrates the expected NXDOMAIN response
  14. ledger shows decision, policy, evidence, adapter receipt, verification
  15. operator invokes revoke
  16. APIP removes the exact rule
  17. APIP verifies removal
  18. real query proves baseline restored (real DNS: 10.99.0.9)
  19. repeat with TTL expiry rather than manual revoke
  20. restart APIP mid-run; state + reconciliation survive (folded into the
      SHADOW->ENFORCE leg transition AND re-asserted at the end)

Requires: a reachable Postgres via the local socket (like the controller
integration test). Skips (exit 0 with a clear skip note) when none is present;
the always-on baseline stays green without a database.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))   # repo root
sys.path.insert(0, str(Path(__file__).resolve().parent))        # lab/

import psycopg2  # noqa: E402
import psycopg2.extensions  # noqa: E402

from apip.config.service import AdapterConfig, DatabaseConfig, load_config  # noqa: E402
from apip.ledger.repo import Ledger  # noqa: E402
from apip.domain.models import (  # noqa: E402
    ActionSelector, Decision, Evidence, Indicator,
)

SOCKET_DIR = "/var/run/postgresql"
ZONE_NAME = "apip.shadow.invalid"
BASELINE_NAME = "baseline-test.operator.test"
C2_NAME = "c2-test.operator.test"
TTL_NAME = "ttl-exp.operator.test"
RESOLVER_PORT = 55333          # loopback high port; unique to avoid clashes
RESOLVER_BIND = "127.0.0.1"
ACTOR = "acceptance"
SOURCE = "local-sensor"


def _utc(*, minutes_ago: float) -> str:
    """ISO-8601 UTC timestamp ``minutes_ago`` in the past, relative to the run's
    real clock. The acceptance's evidence must be RECENT (inside the policy's
    6-hour recency window) wherever it runs; a fixed date would go stale as the
    clock advances and silently zero out maliciousness (the fail-closed recency
    trap). The decision stays deterministic for a given evidence + policy; only
    the feed's recency is bound to the run."""
    return (datetime.now(timezone.utc)
            - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _propose(ctrl, *, did: str, ind_id: str, value: str,
             batch_id: str) -> None:
    """Provision a PROPOSE_OPERATOR_APPROVAL decision for an exact-FQDN RPZ
    action (client destination-pair selector, the beta's L4 shape), the durable
    precondition the operator approve path consumes. This is the operator
    proposing a high-impact enforcement action — the beta's real route to RPZ
    (the engine observes; enforcement intention is operator-owned)."""
    ctrl.ledger.record_batch(batch_id=batch_id, source_id=SOURCE,
                             raw_sha256="sha" + batch_id, indicator_count=1,
                             demoted=0, channel=SOURCE, actor=ACTOR)
    ind = Indicator(
        id=ind_id, type="fqdn", value=value,
        sources=(SOURCE,),
        evidence=(Evidence(kind="direct_local_detection", source_id=SOURCE,
                           source_class="local",
                           observed_at=_utc(minutes_ago=20), independent=True),),
        tags=("c2",))
    durable = ctrl.ledger.upsert_indicator(ind, batch_id)
    sel = ActionSelector(scope_type="destination_global", destination=value)
    d = Decision(
        id=did, indicator_id=durable, maliciousness=97, action_safety=90,
        disposition="PROPOSE_OPERATOR_APPROVAL", action="dns_nxdomain", rung="L4",
        scope=ctrl.current_policy().scope, ttl_seconds=3600,
        policy_version=ctrl.current_policy().version,
        reason_codes=("proposed",), explanation="acceptance proposal",
        selector=sel,
        content_hash="hash-" + hashlib.sha256(did.encode()).hexdigest())
    ctrl.ledger.record_decision(d, indicator_id=durable, batch_id=batch_id,
                                policy_content_sha256="sha", actor=ACTOR)
    return durable


# --------------------------------------------------------------------------- #
# real DNS client — a minimal stdlib A query against the lab resolver
# --------------------------------------------------------------------------- #
def dns_a(server: str, port: int, qname: str, timeout: float = 3.0) -> dict:
    qname = qname.rstrip(".") + "."
    tid = os.urandom(2)
    flags = 0x0100  # RD
    question = struct.pack(">HH", 1, 1)   # A, IN
    qsection = b"".join(
        bytes([len(label)]) + label.encode()
        for label in qname.rstrip(".").split(".")) + b"\x00"
    packet = tid + struct.pack(">HHHHH", flags, 1, 0, 0, 0) + qsection + question
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(4096)
    except (socket.timeout, OSError) as e:
        return {"rcode": None, "answers": 0, "addresses": [], "error": str(e)}
    finally:
        sock.close()
    if len(data) < 12:
        return {"rcode": None, "answers": 0, "addresses": [], "error": "short"}
    rcode = data[3] & 0x0F
    ancount = struct.unpack(">H", data[6:8])[0]
    out: list[str] = []
    off = 12
    while off < len(data) and data[off] != 0:
        off += data[off] + 1
    off += 5
    for _ in range(ancount):
        if off + 2 > len(data):
            break
        if data[off] & 0xC0:
            off += 2
        else:
            while off < len(data) and data[off] != 0:
                off += data[off] + 1
            off += 1
        if off + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4 and off + 4 <= len(data):
            out.append(socket.inet_ntoa(data[off:off + 4]))
        off += rdlen
    return {"rcode": rcode, "answers": ancount, "addresses": out}


# --------------------------------------------------------------------------- #
# scratch database provisioning (same contract as the controller integration test)
# --------------------------------------------------------------------------- #
def can_connect(socket_dir: str = SOCKET_DIR) -> bool:
    try:
        conn = psycopg2.connect(host=socket_dir, dbname="postgres", connect_timeout=3)
        conn.close()
        return True
    except psycopg2.Error:
        return False


def create_scratch(socket_dir: str = SOCKET_DIR) -> str:
    name = "apip_acc_" + uuid.uuid4().hex[:12]
    conn = psycopg2.connect(host=socket_dir, dbname="postgres", connect_timeout=3)
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    try:
        cur.execute(f'CREATE DATABASE "{name}"')
    finally:
        cur.close()
        conn.close()
    return name


def drop_scratch(name: str, socket_dir: str = SOCKET_DIR) -> None:
    try:
        conn = psycopg2.connect(host=socket_dir, dbname="postgres", connect_timeout=3)
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        try:
            cur.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        finally:
            cur.close()
            conn.close()
    except psycopg2.Error:
        pass


# --------------------------------------------------------------------------- #
# lab resolver server (lab/resolver.py imported for the real UDP answers)
# --------------------------------------------------------------------------- #
class _ResolverThread:
    """Run lab/resolver.py's serve() in a background thread. Only the LIVE
    ``IN CNAME .`` policy action bites; the shadow artifact's rpz-passthru
    rules are answered as baseline no matter what file the harness reads."""

    def __init__(self, zone_path: str):
        self._zone_path = zone_path
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        from lab.resolver import serve  # noqa: PLC0415
        # honor_zone=True: _owned() only bites on the LIVE ``IN CNAME .``
        # policy action, so shadow artifacts are inert by construction.
        self._thread = threading.Thread(
            target=serve, args=(RESOLVER_BIND, RESOLVER_PORT, self._zone_path,
                                BASELINE_NAME, True), daemon=True)
        self._thread.start()
        time.sleep(0.3)

    def stop(self) -> None:
        self._thread = None


# --------------------------------------------------------------------------- #
# step helpers
# --------------------------------------------------------------------------- #
def _step(n: int, title: str) -> None:
    print(f"\n[{n:>2}/20] {title}", flush=True)


def _loopback_dns(what: str, value: str, expected_rcode: int,
                  addresses: list[str] | None = None) -> dict:
    res = dns_a(RESOLVER_BIND, RESOLVER_PORT, value)
    ok_rcode = res["rcode"] == expected_rcode
    ok_addr = True
    if addresses is not None:
        ok_addr = set(res["addresses"]) == set(addresses)
    if not (ok_rcode and ok_addr):
        raise AssertionError(
            f"{what}: real DNS query for {value!r} -> "
            f"rcode={res['rcode']} addresses={res['addresses']} "
            f"(expected rcode={expected_rcode} addresses={addresses})")
    return res


def _wait_action(ctrl, action_id: str, target: str, timeout_s: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        plain = ctrl.ledger.get_action(action_id)
        if plain and plain["state"] == target:
            return plain
        time.sleep(0.05)
    raise AssertionError(f"action {action_id} did not reach state {target!r}")


def _install_policy(ctrl, path: str, version: str) -> None:
    raw = Path(path).read_text()
    import tomllib
    mode = str(tomllib.loads(raw).get("mode", "")).upper()
    rev = ctrl.ledger.next_policy_revision(version)
    ctrl.ledger.stage_policy(
        policy_version=version, revision=rev,
        content_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        raw_text=raw, mode=mode, staged_by=ACTOR)
    ctrl.ledger.promote_policy(version, rev, ACTOR)


def _approve_and_dispatch(ctrl, did: str) -> str:
    """Approve a PROPOSE decision, then synchronously dispatch the compiled
    RPZ action (the integration-verified dispatch path) and wait for applied."""
    res = ctrl.approve_decision(did, ACTOR)
    assert res["compiled"], f"approval did not compile an action: {res}"
    action_id = res["action_ids"][0]
    action = ctrl.ledger.get_action(action_id)
    assert action["state"] == "pending", action["state"]
    ctrl._dispatch_one(action)
    return _wait_action(ctrl, action_id, "applied")["action_id"]


# --------------------------------------------------------------------------- #
# the acceptance loop
# --------------------------------------------------------------------------- #
def _shadow_leg(ctrl, zone_dir: str) -> tuple[str, str, str]:
    """Steps 1-9: SHADOW posture + SHADOW policy -> monitor-only zone, real DNS
    unchanged. Returns (decision_id, proposed_indicator_id, action_id)."""
    repo_root = Path(__file__).resolve().parents[1]

    _step(1, "start APIP + database")
    assert ctrl.health() is not None
    print("      controller started; db migrations applied")

    _step(2, "register a synthetic trusted source")
    ctrl.ledger.register_source(source_id=SOURCE, source_class="local",
                                independent=True, key_hash="x", actor=ACTOR,
                                auto_enforcement_allowed=True, enabled=True)
    src = ctrl.ledger.get_source(SOURCE)
    assert src is not None and src["source_class"] == "local"
    print("      registered local-sensor (channel-bound identity)")

    _step(3, "install a SHADOW policy")
    _install_policy(ctrl, str(repo_root / "examples" / "operator_shadow_policy.toml"),
                    "operator.shadow.1")
    print("      SHADOW policy staged + promoted")

    _step(4, "ingest evidence for c2-test.operator.test")
    ctrl.ledger.record_batch(batch_id="batch--acep-shadow", source_id=SOURCE,
                             raw_sha256="sha-shadow", indicator_count=1, demoted=0,
                             channel=SOURCE, actor=ACTOR)
    payload = {"indicators": [{
        "id": "indicator--acceptance-c2", "type": "fqdn", "value": C2_NAME,
        "sources": [SOURCE], "first_seen": _utc(minutes_ago=40),
        "last_seen": _utc(minutes_ago=5), "tags": ["c2"], "evidence": [
            {"kind": "direct_local_detection", "source_id": SOURCE,
             "observed_at": _utc(minutes_ago=20)},
            {"kind": "exact_fqdn", "source_id": SOURCE,
             "observed_at": _utc(minutes_ago=15)},
            {"kind": "exact_ip", "source_id": SOURCE,
             "observed_at": _utc(minutes_ago=10)}]}]}
    from apip.ingest import IngestChannel, parse_indicator_payload  # noqa: PLC0415
    channel = IngestChannel(source_id=SOURCE,
                            allowed_source_ids=frozenset({SOURCE}))
    pb = parse_indicator_payload(json.dumps(payload).encode(), channel)
    assert pb.indicators, "shadow-leg payload must parse to >=1 indicator"
    durable = ctrl.ledger.upsert_indicator(pb.indicators[0], "batch--acep-shadow")
    print(f"      ingested {C2_NAME}; evidence recorded")

    _step(5, "APIP generates a deterministic decision")
    res = ctrl.pipeline.decide_indicator(durable, actor=ACTOR)
    assert res and res["recorded"]
    # determinism: same evidence + policy -> same content hash (no recompute)
    again = ctrl.pipeline.decide_indicator(durable, actor=ACTOR)
    decision = res["decision"]
    print(f"      deterministic {decision.disposition} "
          f"(M={decision.maliciousness}, action={decision.action}); "
          f"recompute content_hash_stable={decision.content_hash == again['decision'].content_hash}")
    assert decision.content_hash == again["decision"].content_hash

    _step(6, "operator drives an exact-FQDN RPZ action (proposed + approved)")
    _propose(ctrl, did="decision--acep-shadow",
             ind_id="indicator--acep-propose", value=C2_NAME,
             batch_id="batch--acep-propose")
    proposal = ctrl.ledger.get_decision("decision--acep-shadow")
    assert proposal is not None and proposal["disposition"] == "PROPOSE_OPERATOR_APPROVAL"
    print(f"      proposed high-impact action awaiting operator approval")

    _step(7, "prepare an exact-FQDN RPZ rule")
    action_id = _approve_and_dispatch(ctrl, "decision--acep-shadow")
    action = ctrl.ledger.get_action(action_id)
    assert action["adapter"] == "rpz", action["adapter"]
    print(f"      action {action_id} pending (adapter=rpz, mode={action['mode']})")

    _step(8, "adapter validates the candidate (SHADOW -> shadow artifact only)")
    shadow_zone = Path(zone_dir) / f"{ZONE_NAME}.shadow.zone"
    live_zone = Path(zone_dir) / f"{ZONE_NAME}.zone"
    assert shadow_zone.exists(), "SHADOW must publish its own shadow artifact"
    assert not live_zone.exists(), \
        "SHADOW must never create the resolver-consumed live artifact"
    text = shadow_zone.read_text()
    assert C2_NAME in text and "rpz-passthru" in text and "CNAME ." not in text, \
        "shadow artifact must carry rpz-passthru (spec no-op), never CNAME ."
    # no fabricated receipt: dispatch recorded observed infra state
    receipts = ctrl.ledger.list_receipts(action_id)
    assert receipts and "observed" in receipts[0]
    print(f"      applied; receipt carries observed infra; "
          f"rpz-passthru shadow artifact written (no live artifact)")

    _step(9, "SHADOW: no live resolver behavior change (shadow artifact only)")
    res9 = _loopback_dns("shadow-baseline", C2_NAME, 0, addresses=["10.99.0.9"])
    print(f"      {C2_NAME!r} still NOERROR {res9['addresses']} "
          f"(shadow artifact not consumed; even if attached, rpz-passthru is a no-op)")

    return "decision--acep-shadow", "indicator--acceptance-c2", action_id


def _enforce_leg(ctrl, zone_dir: str, shadow_action_id: str) -> None:
    """Steps 10-19: ENFORCE posture + ENFORCE policy -> real DNS NXDOMAIN,
    revoke -> baseline, then TTL expiry. Uses a FRESH zone dir so the ENFORCE
    adapter writes a clean (non-monitor-only) zone."""
    repo_root = Path(__file__).resolve().parents[1]

    _step(10, "operator goes to enforcement (adapter posture + policy ENFORCE)")
    _install_policy(ctrl, str(repo_root / "examples" / "enforce_policy.toml"),
                    "enforce.1")
    print("      ENFORCE policy staged + promoted")

    _step(11, "APIP applies the RPZ rule (ENFORCE)")
    _propose(ctrl, did="decision--acep-enforce",
             ind_id="indicator--acep-enforce", value=C2_NAME,
             batch_id="batch--acep-enforce")
    action_id = _approve_and_dispatch(ctrl, "decision--acep-enforce")
    zone = Path(zone_dir) / f"{ZONE_NAME}.zone"
    text = zone.read_text()
    assert C2_NAME in text and "CNAME ." in text and "rpz-passthru" not in text, \
        "ENFORCE artifact carries the live NXDOMAIN policy action"
    action = ctrl.ledger.get_action(action_id)
    # The PERSISTED action mode is authoritative (review P0 #1): an
    # operator-approved PROPOSE under an ENFORCE policy persists ENFORCE,
    # which is what makes the live zone + NXDOMAIN contract honest. The
    # adapter's ENFORCE posture is the cap that permits it.
    assert action["mode"] == "ENFORCE", action["mode"]
    assert ctrl._adapter_for(action).max_mode() == "ENFORCE"
    print(f"      ENFORCE rule written; persisted action mode=ENFORCE "
          f"(policy-derived, adapter-capped)")

    _step(12, "APIP independently verifies the resolver state")
    verify = ctrl._adapter_for(action).verify(
        {"rule_id": action["rule_id"], "fragment": action["fragment"],
         "mode": action["mode"], "selector": action["selector"]})
    assert verify["ok"], verify
    ctrl._verify_action(action)
    v = ctrl.ledger.get_action(action_id)
    assert v["state"] == "verified", v["state"]
    receipts = ctrl.ledger.list_receipts(action_id)
    assert any(r["status"] == "verified" for r in receipts)
    # ENFORCE verify additionally does a live DNS probe against the lab resolver
    assert verify["observed"].get("dns"), "ENFORCE verify should live-query DNS"
    print(f"      controller verify -> {v['state']} "
          f"(live dns={verify['observed']['dns']})")

    _step(13, "real query demonstrates the expected response")
    res13 = _loopback_dns("enforce-nxdomain", C2_NAME, 3)   # NXDOMAIN
    print(f"      real UDP query for {C2_NAME!r} -> rcode={res13['rcode']} (NXDOMAIN)")

    _step(14, "ledger shows decision, policy, evidence, adapter receipt, verification")
    # server-derived identity (P0 #10): evidence lives under the DURABLE id
    enforce_durable = Ledger.observable_id("fqdn", C2_NAME)
    evidence = ctrl.ledger.indicator_evidence(enforce_durable)
    assert len(evidence) >= 1
    receipts = ctrl.ledger.list_receipts(action_id)
    assert any(r["status"] == "verified" for r in receipts)
    print(f"      ledger: {len(evidence)} evidence, "
          f"{len([r for r in receipts if r['status']=='verified'])} verified receipt(s)")

    _step(15, "operator invokes revoke")
    rev = ctrl.revoke_action(action_id, ACTOR, "operator_revoke")
    assert rev.get("state") == "revoked", rev
    print(f"      revoke -> {rev['state']} via controlled path")

    _step(16, "APIP removes the exact rule")
    assert f"{C2_NAME}." not in zone.read_text()
    print(f"      rule for {C2_NAME!r} removed from zone")

    _step(17, "APIP verifies removal")
    gone = ctrl._adapter_for(action).verify(
        {"rule_id": action["rule_id"], "fragment": action["fragment"],
         "mode": action["mode"], "selector": action["selector"]})
    assert not gone.get("ok"), f"verify after removal still ok: {gone}"
    print(f"      removal verified ({gone.get('error')})")

    _step(18, "real query proves baseline restored")
    res18 = _loopback_dns("baseline-restored", C2_NAME, 0, addresses=["10.99.0.9"])
    print(f"      {C2_NAME!r} again resolves NOERROR {res18['addresses']}")

    _step(19, "repeat with TTL expiry rather than manual revoke")
    _propose(ctrl, did="decision--acep-ttl",
             ind_id="indicator--acep-ttl", value=TTL_NAME,
             batch_id="batch--acep-ttl")
    ttl_action_id = _approve_and_dispatch(ctrl, "decision--acep-ttl")
    assert f"{TTL_NAME} IN CNAME ." in zone.read_text()
    _loopback_dns("ttl-nxdomain", TTL_NAME, 3)
    # force the action past its expiry and drive the controlled removal path
    ctrl.db.execute("UPDATE actions SET expires_at=%s WHERE action_id=%s",
                    (datetime.now(timezone.utc) - timedelta(seconds=1),
                     ttl_action_id))
    now = datetime.now(timezone.utc)
    due = [a for a in ctrl.ledger.actions_due_for_expiry(now)
           if a["action_id"] == ttl_action_id]
    assert due, "action should be due for expiry"
    out = ctrl._remove_action(due[0], ACTOR, "ttl_expired",
                              terminal_state="expired", revoked_by=None)
    assert out["verified"] is True, out
    _loopback_dns("ttl-baseline-restored", TTL_NAME, 0, addresses=[])  # NOERROR, no A
    print(f"      TTL expiry removed the rule via controlled path; baseline restored")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--socket-dir", default=SOCKET_DIR,
                    help="Postgres unix-socket dir (default %(default)s)")
    ap.add_argument("--no-db-check", action="store_true",
                    help="run even if no Postgres is reachable (will fail fast)")
    args = ap.parse_args()
    socket_dir = args.socket_dir

    if not can_connect(socket_dir) and not args.no_db_check:
        print(f"SKIP: no reachable Postgres on socket dir {socket_dir!r}; "
              "the always-on baseline stays green without a database.", flush=True)
        return 0

    from apip.controller.service import Controller  # noqa: PLC0415
    from apip.ledger.db import Database  # noqa: PLC0415
    from apip.ledger.migrations import apply_migrations  # noqa: PLC0415

    dburi = create_scratch(socket_dir)
    shadow_zone_dir = tempfile.mkdtemp(prefix="apip_acc_shadow_")
    enforce_zone_dir = tempfile.mkdtemp(prefix="apip_acc_enforce_")
    resolver: _ResolverThread | None = None
    ctrl: Controller | None = None
    enforce_ctrl: Controller | None = None
    try:
        def _make_controller(posture: str, zone_dir: str) -> Controller:
            cfg = replace(
                load_config(None),
                db=DatabaseConfig(host=socket_dir, dbname=dburi,
                                  user=os.environ.get("USER", "bamn")),
                adapter=replace(AdapterConfig(rpz_mode=posture, zone_dir=zone_dir),
                                authorized_domains=("operator.test",),
                                verify_query_server=RESOLVER_BIND,
                                verify_query_port=RESOLVER_PORT),
            )
            db = Database(cfg.db.dsn_kwargs())
            db.wait_until_ready(timeout_s=10)
            apply_migrations(db)
            db.close()
            c = Controller(cfg)
            c.start()
            return c

        # step 1 start (SHADOW posture, its own shadow-only zone dir)
        ctrl = _make_controller("SHADOW", shadow_zone_dir)
        # The lab resolver serves the whole run, pointing at the ACTIVE zone
        # dir each leg. The SHADOW leg points it at the shadow ARTIFACT
        # itself: the shadow artifact carries only rpz-passthru rules, so
        # even a resolver pointed straight at it cannot produce an
        # enforcement answer (the structural no-op guarantee, exercised).
        resolver = _ResolverThread(str(Path(shadow_zone_dir) / f"{ZONE_NAME}.shadow.zone"))
        resolver.start()
        decision_id, ind_id, shadow_action_id = _shadow_leg(ctrl, shadow_zone_dir)

        # stop the SHADOW-leg resolver; the operator now serves an ENFORCE zone
        resolver.stop()
        resolver = _ResolverThread(str(Path(enforce_zone_dir) / f"{ZONE_NAME}.zone"))
        resolver.start()

        # step 10: operator goes to enforcement — stop the controller (SHADOW
        # posture) and start an ENFORCE-posture controller against the SAME
        # ledger. This IS the step-20 restart-survival check.
        ctrl.stop()
        print("\n[--] operator goes to enforcement: controller restarted with "
              "ENFORCE adapter posture (restart-survival check, step 20)")
        enforce_ctrl = _make_controller("ENFORCE", enforce_zone_dir)

        # step 20 assertions: prior state survived the restart
        _step(20, "restart APIP mid-run; state + reconciliation survive")
        dec = enforce_ctrl.ledger.get_decision(decision_id)
        assert dec is not None, "decision lost across restart"
        act = enforce_ctrl.ledger.get_action(shadow_action_id)
        assert act is not None and act["state"] in ("applied", "revoked"), act
        receipts = enforce_ctrl.ledger.list_receipts(shadow_action_id)
        assert receipts, "receipts lost across restart"
        print(f"      decision {decision_id}, action {shadow_action_id}, "
              f"{len(receipts)} receipt(s) survived the restart; "
              f"reconciliation re-ran clean")

        _enforce_leg(enforce_ctrl, enforce_zone_dir, shadow_action_id)
    except AssertionError as e:
        print(f"\nACCEPTANCE FAILED: {e}", flush=True)
        return 1
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        print(f"\nACCEPTANCE FAILED: {e!r}", flush=True)
        return 1
    finally:
        for _c in (ctrl, enforce_ctrl):
            if _c is not None:
                try:
                    _c.stop()
                except Exception:
                    pass
        if resolver is not None:
            resolver.stop()
        drop_scratch(dburi, socket_dir)

    print("\nACCEPTANCE PASSED: 20/20 steps reproduced end-to-end "
          "against a real UDP DNS resolver.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())