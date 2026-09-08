#!/usr/bin/env python3
"""APIP release gate: REAL BIND response-policy integration.

The lab/acceptance.py resolver is an APIP-owned harness — it proves the
controller lifecycle, not BIND compatibility (review P0 #3/#41). This gate
proves the RPZ artifact against the real ``named``:

  1. start real BIND (docker ubuntu/bind9) serving a baseline authoritative
     zone AND with BOTH APIP artifacts (live + shadow) attached to
     ``response-policy`` — attaching the shadow artifact is deliberate: it
     proves the rpz-passthru shadow rules change NO answer even when a
     resolver consumes them;
  2. prove the baseline answer before any APIP action;
  3. apply a SHADOW action (SHADOW policy, SHADOW posture) -> named-checkzone
     the artifact -> reload -> baseline UNCHANGED;
  4. switch to ENFORCE (policy + adapter), apply the ENFORCE action ->
     named-checkzone -> reload -> NXDOMAIN;
  5. adapter verify() independently confirms NXDOMAIN via real DNS;
  6. operator revoke -> reload -> baseline restored;
  7. TTL expiry leg -> NXDOMAIN -> expire -> baseline restored;
  8. restart APIP (fresh controller on the same ledger) -> re-apply ->
     NXDOMAIN again;
  9. SOA serial advances on every publish (reload actually propagates).

Exit codes: 0 = gate passed; 1 = gate FAILED; 2 = prerequisites missing
(no docker / no Postgres). CI runs this in release mode; a missing
prerequisite is a FAILURE there, not a skip.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from typing import NoReturn
from datetime import datetime, timedelta, timezone
from dataclasses import replace
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

BIND_IMAGE = "ubuntu/bind9:9.18-24.04_edge"
BIND_NAME = "apip-bind-gate"
BIND_HOST_PORT = 5334
ZONE_NAME = "apip.rpz.test"          # the RPZ policy zone BIND consumes
BASELINE_A = "baseline-test.operator.test"
C2_NAME = "c2-test.operator.test"
TTL_NAME = "ttl-exp.operator.test"
REPEAT_NAME = "repeat.operator.test"   # audit #41 multi-cycle stress target
ACTOR = "bind-gate"
SOURCE = "local-sensor"
SOCKET_DIR = "/var/run/postgresql"

_steps: list[str] = []


def _step(n: int, title: str) -> None:
    print(f"\n[{n}/10] {title}", flush=True)


def _fail(msg: str) -> NoReturn:
    _FAILED.append(msg)
    print(f"\nBIND GATE FAILED: {msg}", flush=True)
    try:
        logs = subprocess.run(["docker", "logs", "--tail", "40", BIND_NAME],
                              capture_output=True, text=True, timeout=15)
        tail = (logs.stderr + logs.stdout).strip()
        if tail:
            print(f"--- named log tail ---\n{tail}\n---", flush=True)
    except Exception:
        pass
    sys.exit(1)


# --------------------------------------------------------------------------- #
# prerequisites
# --------------------------------------------------------------------------- #

def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=15,
                       check=True)
        return True
    except (subprocess.SubprocessError, OSError):
        return False


def _pg_ok(socket_dir: str) -> bool:
    try:
        import psycopg2
        conn = psycopg2.connect(host=socket_dir, dbname="postgres",
                                connect_timeout=3)
        conn.close()
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# DNS client (stdlib; rcode + answers)
# --------------------------------------------------------------------------- #

def dns_a(server: str, port: int, qname: str, timeout: float = 3.0) -> dict:
    q = qname.rstrip(".")
    qsection = b"".join(
        bytes([len(l)]) + l.encode() for l in q.split(".")) + b"\x00"
    packet = os.urandom(2) + struct.pack(">HHHHH", 0x0100, 1, 0, 0, 0) \
        + qsection + struct.pack(">HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(4096)
    except (socket.timeout, OSError) as e:
        return {"queried": False, "error": str(e)}
    finally:
        sock.close()
    if len(data) < 12:
        return {"queried": False, "error": "short response"}
    rcode = data[3] & 0x0F
    ancount = struct.unpack(">H", data[6:8])[0]
    addresses: list[str] = []
    # walk answers crudely: name (possibly compressed), type/class/ttl/rdlen
    if ancount:
        try:
            idx = 12
            while data[idx] != 0:      # question name
                if data[idx] & 0xC0:
                    idx += 2
                    break
                idx += data[idx] + 1
            else:
                idx += 1
            idx += 4                   # qtype/qclass
            for _ in range(ancount):
                if data[idx] & 0xC0:
                    idx += 2
                else:
                    while data[idx] != 0:
                        idx += data[idx] + 1
                    idx += 1
                rtype, _rclass, _ttl, rdlen = struct.unpack(
                    ">HHIH", data[idx:idx + 10])
                idx += 10
                if rtype == 1 and rdlen == 4:
                    addresses.append(socket.inet_ntoa(data[idx:idx + 4]))
                idx += rdlen
        except (IndexError, struct.error):
            pass
    return {"queried": True, "rcode": rcode, "addresses": sorted(addresses)}


def _expect(what: str, qname: str, *, rcode: int,
            addresses: list[str] | None = None,
            server: str = "127.0.0.1", port: int = BIND_HOST_PORT,
            timeout_s: float = 75.0) -> dict:
    """Query until the expected answer is observed (zone reload is async;
    BIND also rate-limits RPZ policy updates — 'came too soon' defers by the
    SOA timer — so the bounded window must cover a worst-case deferral)."""
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    transcript: list[dict] = []   # audit #41: the resolver query transcript
    while time.monotonic() < deadline:
        last = dns_a(server, port, qname)
        transcript.append(last)
        if last.get("queried") and last.get("rcode") == rcode \
                and (addresses is None or last.get("addresses") == sorted(addresses)):
            print(f"      {what}: {qname!r} rcode={last['rcode']} "
                  f"addresses={last['addresses']}", flush=True)
            return last
        time.sleep(0.3)
    _fail(f"{what}: {qname!r} expected rcode={rcode} addresses={addresses}, "
          f"got {last}; query transcript ({len(transcript)} probes): "
          f"{json.dumps(transcript[:20], default=str)}")


# --------------------------------------------------------------------------- #
# BIND lifecycle
# --------------------------------------------------------------------------- #

_NAMED_CONF = """options {{
    directory "/var/cache/bind";
    listen-on port {port} {{ 127.0.0.1; }};
    listen-on-v6 {{ none; }};
    allow-query {{ any; }};
    recursion yes;
    response-policy {{ zone "{rpz}"; zone "{shadow}"; }};
}};
zone "operator.test" {{ type master; file "/zones/operator.test.zone"; }};
zone "{rpz}" {{ type master; file "/zones/{rpz}.zone"; }};
zone "{shadow}" {{ type master; file "/zones/{shadow}.zone"; }};
"""

_BASELINE_ZONE = """$ORIGIN operator.test.
$TTL 60
@ IN SOA localhost. hostmaster.localhost. ( 1 60 60 60 60 )
@ IN NS  localhost.
baseline-test IN A 10.99.0.5
c2-test IN A 10.99.0.9
ttl-exp IN A 10.99.0.11
repeat IN A 10.99.0.13
"""


class BindServer:
    """Real named in docker, with both APIP artifacts attached to
    response-policy (the shadow artifact attached is the point: it must be
    answer-neutral)."""

    def __init__(self, zones_dir: Path):
        self._zones_dir = zones_dir
        self._log_mark = 0
        (zones_dir / "operator.test.zone").write_text(_BASELINE_ZONE)
        # The live artifact's $ORIGIN is the configured zone_name; the SHADOW
        # artifact is loaded by named under the distinct policy-zone name
        # `{zone}.shadow`, so its stub $ORIGIN must be that name (BIND
        # validates owner names against the zone's own origin).
        (zones_dir / f"{ZONE_NAME}.zone").write_text(
            f"$ORIGIN {ZONE_NAME}.\n$TTL 30\n"
            f"@ IN SOA localhost. hostmaster.localhost. ( 1 5 5 30 60 )\n"
            f"@ IN NS  localhost.\n")
        (zones_dir / f"{ZONE_NAME}.shadow.zone").write_text(
            f"$ORIGIN {ZONE_NAME}.shadow.\n$TTL 30\n"
            f"@ IN SOA localhost. hostmaster.localhost. ( 1 5 5 30 60 )\n"
            f"@ IN NS  localhost.\n")
        conf = _NAMED_CONF.format(rpz=ZONE_NAME, shadow=f"{ZONE_NAME}.shadow",
                                  port=BIND_HOST_PORT)
        self._conf_path = zones_dir / "named.conf"
        self._conf_path.write_text(conf)

    def start(self) -> None:
        # named runs as the image's `bind` user — the zones dir must be
        # world-readable or config/zone loads fail with permission denied.
        for p in self._zones_dir.rglob("*"):
            p.chmod(0o644)
        self._zones_dir.chmod(0o755)
        subprocess.run(["docker", "rm", "-f", BIND_NAME],
                       capture_output=True, timeout=30)
        # Host networking: the docker published-port path proved unreliable
        # on this host (bound but unreachable); loopback host-net is the
        # simplest reliable exposure for a gate that talks to 127.0.0.1 only.
        # The listen port is fixed in named.conf (the -p CLI flag would
        # override the listen-on port, not the same option).
        proc = subprocess.run(
            ["docker", "run", "-d", "--name", BIND_NAME, "--network", "host",
             "--entrypoint", "/usr/sbin/named",
             "-v", f"{self._zones_dir}:/zones",
             BIND_IMAGE, "-g", "-u", "bind", "-c", "/zones/named.conf"],
            capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            _fail(f"docker run {BIND_IMAGE} failed: {proc.stderr[-400:]}")
        # wait for a baseline answer (named startup is async)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            r = dns_a("127.0.0.1", BIND_HOST_PORT, BASELINE_A)
            if r.get("queried") and r.get("rcode") == 0:
                self.mark_logs()
                return
            time.sleep(0.5)
        logs = subprocess.run(["docker", "logs", BIND_NAME],
                              capture_output=True, text=True, timeout=15)
        _fail(f"named never answered baseline queries:\n"
              f"{(logs.stderr + logs.stdout)[-800:]}")

    def named_checkzone(self, zone: str, path: Path) -> None:
        """The BIND gate: named-checkzone must accept the artifact as a valid
        {zone} — an 'out-of-zone data' line means the rule could never fire
        (the defect this gate exists for)."""
        proc = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{self._zones_dir}:/zones",
             BIND_IMAGE, "named-checkzone", zone, f"/zones/{path.name}"],
            capture_output=True, text=True, timeout=60)
        out = proc.stdout + proc.stderr
        if proc.returncode != 0 or "OK" not in out:
            _fail(f"named-checkzone rejected {path.name}:\n{out[-500:]}")
        if "out-of-zone" in out:
            _fail(f"named-checkzone reports out-of-zone data in {path.name} "
                  f"(rule would never fire):\n{out[-500:]}")
        print(f"      named-checkzone {path.name}: OK", flush=True)

    def reload(self) -> None:
        """SIGHUP: named re-reads config + zones (rndc-equivalent for this
        gate; the adapter's configured reload_command would be `rndc reload`
        in production). Zone-load errors are checked INCREMENTALLY: only log
        lines appended after the HUP are scanned, so startup-era noise
        (IPv6 root-hint probes etc.) never false-positives the gate."""
        # APIP (running as this user, default umask) rewrites the artifacts;
        # named reads them as the image's `bind` user. Production zone
        # directories are readable by the resolver user; re-apply readability
        # BEFORE the HUP (named loads synchronously on SIGHUP).
        for p in self._zones_dir.rglob("*"):
            try:
                p.chmod(0o644)
            except OSError:
                pass
        proc = subprocess.run(["docker", "exec", BIND_NAME, "kill", "-HUP", "1"],
                              capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            _fail(f"SIGHUP reload failed: {proc.stderr[-200:]}")
        time.sleep(1.0)
        logs = subprocess.run(["docker", "logs", BIND_NAME],
                              capture_output=True, text=True, timeout=30)
        err = logs.stderr + logs.stdout
        # all lines appended since process start BEFORE this reload were
        # already present at self._log_mark; scan only the new tail
        new = err[self._log_mark:]
        self._log_mark = len(err)
        if "came too soon" in new:
            # BIND rate-limits RPZ policy updates against the SOA timers and
            # self-schedules the retry; the reload is deferred, not failed.
            # wait_healthy() (below) waits out the deferral before checking.
            print("      (rpz update deferred by BIND rate limiting; "
                  "waiting out the SOA timer)", flush=True)
        self.wait_healthy(new)

    def wait_healthy(self, window: str, timeout_s: float = 75.0) -> None:
        """A reload window can carry a transient error (a deferred RPZ update
        retrying while APIP's umask-0600 file is mid-chmod). The zone is
        healthy only when a SUCCESSFUL load line follows the last error line;
        poll until that ordering holds, fail if the error stays last."""
        deadline = time.monotonic() + timeout_s
        while True:
            last_bad = max(window.rfind(bad) for bad in (
                "out-of-zone", "not loaded due to errors",
                "using zone data that failed"))
            if last_bad < 0:
                return
            last_ok = max(window.rfind(marker) for marker in (
                "all zones loaded", "reload done: success",
                "loaded serial "))
            if last_ok > last_bad:
                return   # the error resolved; a later successful load proves it
            if time.monotonic() >= deadline:
                idx = last_bad
                _fail(f"named reload error never resolved:\n"
                      f"{window[max(0, idx - 300):idx + 300]}")
            time.sleep(2.0)
            logs = subprocess.run(["docker", "logs", BIND_NAME],
                                  capture_output=True, text=True, timeout=30)
            err = logs.stderr + logs.stdout
            window = err[self._log_mark:]
            self._log_mark = len(err)

    def mark_logs(self) -> None:
        """Snapshot the current log length so subsequent reload() checks scan
        only newly appended lines."""
        logs = subprocess.run(["docker", "logs", BIND_NAME],
                              capture_output=True, text=True, timeout=30)
        self._log_mark = len(logs.stderr + logs.stdout)

    def stop(self) -> None:
        subprocess.run(["docker", "rm", "-f", BIND_NAME],
                       capture_output=True, timeout=30)


# --------------------------------------------------------------------------- #
# APIP controller helpers (same shape as lab/acceptance.py)
# --------------------------------------------------------------------------- #

def _create_scratch(socket_dir: str) -> str:
    import psycopg2
    import psycopg2.extensions
    name = "apip_bind_" + uuid.uuid4().hex[:12]
    conn = psycopg2.connect(host=socket_dir, dbname="postgres", connect_timeout=3)
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    try:
        cur.execute(f'CREATE DATABASE "{name}"')
    finally:
        cur.close()
        conn.close()
    return name


def _drop_scratch(name: str, socket_dir: str) -> None:
    try:
        import psycopg2
        import psycopg2.extensions
        conn = psycopg2.connect(host=socket_dir, dbname="postgres",
                                connect_timeout=3)
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        try:
            cur.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        finally:
            cur.close()
            conn.close()
    except Exception:
        pass


def _install_policy(ctrl, path: Path, version: str) -> None:
    raw = path.read_text()
    import tomllib
    mode = str(tomllib.loads(raw).get("mode", "")).upper()
    rev = ctrl.ledger.next_policy_revision(version)
    ctrl.ledger.stage_policy(
        policy_version=version, revision=rev,
        content_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        raw_text=raw, mode=mode, staged_by=ACTOR)
    ctrl.ledger.promote_policy(version, rev, ACTOR)


def _propose(ctrl, *, did: str, ind_id: str, value: str, batch_id: str) -> None:
    from apip.domain.models import ActionSelector, Decision

    def _utc(*, minutes_ago: float) -> str:
        return (datetime.now(timezone.utc)
                - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")

    ctrl.ledger.record_batch(batch_id=batch_id, source_id=SOURCE,
                             raw_sha256="sha" + did, indicator_count=1,
                             demoted=0, channel=SOURCE, actor=ACTOR)
    from apip.domain.models import Evidence, Indicator
    ind = Indicator(
        id=ind_id, type="fqdn", value=value, sources=(SOURCE,),
        evidence=(Evidence(kind="direct_local_detection", source_id=SOURCE,
                           source_class="local",
                           observed_at=_utc(minutes_ago=20),
                           independent=True),
                  Evidence(kind="exact_fqdn", source_id=SOURCE,
                           source_class="local",
                           observed_at=_utc(minutes_ago=15),
                           independent=True)),
        tags=("c2",))
    durable = ctrl.ledger.upsert_indicator(ind, batch_id)
    sel = ActionSelector(scope_type="client_destination_pair", client=None,
                         destination=value, protocol_class="interactive_http")
    d = Decision(
        id=did, indicator_id=durable, maliciousness=97, action_safety=90,
        disposition="PROPOSE_OPERATOR_APPROVAL", action="dns_nxdomain",
        rung="L4", scope=ctrl.current_policy().scope, ttl_seconds=3600,
        policy_version="bind-gate", reason_codes=("proposed",),
        explanation="bind gate proposal", selector=sel,
        content_hash="hash--" + hashlib.sha256(did.encode()).hexdigest())
    # the proposal is bound to the ACTIVE policy revision (audit P0 #6:
    # approval refuses a decision authorized by a different content hash)
    active = ctrl.ledger.current_policy_row()
    ctrl.ledger.record_decision(d, indicator_id=durable, batch_id=batch_id,
                                policy_content_sha256=(active["content_sha256"]
                                                       if active else "sha"),
                                actor=ACTOR)


def _approve_and_dispatch(ctrl, did: str) -> tuple[str, dict]:
    res = ctrl.approve_decision(did, ACTOR)
    if not res.get("compiled"):
        _fail(f"approval did not compile an action: {res}")
    action_id = res["action_ids"][0]
    action = ctrl.ledger.get_action(action_id)
    ctrl._dispatch_one(action)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        action = ctrl.ledger.get_action(action_id)
        # audit P1 #11: dispatch verifies on apply — the converged state
        # is `verified`; `applied` (dispatched_unverified) or `failed`
        # breaks the wait but is refused below.
        if action["state"] in ("verified", "applied", "failed"):
            break
        time.sleep(0.05)
    if action["state"] != "verified":
        _fail(f"action {action_id} did not apply+verify: {action}")
    return action_id, action


def _serial_newer(a: int, b: int) -> bool:
    """RFC 1982 serial arithmetic: a is newer than b iff (a-b) mod 2^32
    falls in the first half of the 32-bit serial space."""
    return ((a - b) % 2**32) < 2**31


def _last_serial(zones_dir: Path, live: bool) -> int:
    suffix = ".zone" if live else ".shadow.zone"
    p = zones_dir / f"{ZONE_NAME}{suffix}"
    if not p.is_file():
        return -1
    for line in p.read_text().splitlines():
        if "SOA" in line and "(" in line:
            try:
                return int(line.split("(")[1].split(")")[0].split()[0])
            except (ValueError, IndexError):
                pass
    return -1


# --------------------------------------------------------------------------- #
# the gate
# --------------------------------------------------------------------------- #

def main() -> int:
    global BIND_HOST_PORT
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--socket-dir", default=None,
                    help="Postgres unix-socket dir (local default)")
    ap.add_argument("--pg-host", default=None,
                    help="Postgres TCP host (CI service containers); "
                         "overrides --socket-dir")
    ap.add_argument("--pg-port", type=int, default=5432)
    ap.add_argument("--pg-user", default=os.environ.get("USER", "bamn"))
    ap.add_argument("--bind-port", type=int, default=BIND_HOST_PORT)
    ap.add_argument("--require-postgres", action="store_true",
                    help="release mode: a missing Postgres is a hard "
                         "failure (it already is for docker)")
    args = ap.parse_args()
    BIND_HOST_PORT = args.bind_port

    # P1 #42/#40: CI reaches Postgres over TCP (service container); the
    # local default stays the unix socket.
    pg_endpoint = (args.pg_host if args.pg_host
                   else args.socket_dir or SOCKET_DIR)
    pg_kw = (dict(host=args.pg_host, port=args.pg_port, user=args.pg_user,
                  connect_timeout=3)
             if args.pg_host else
             dict(host=pg_endpoint, dbname="postgres", connect_timeout=3))

    def _pg_connect(dbname: str) -> object:
        import psycopg2 as _p2
        kw = (dict(host=args.pg_host, port=args.pg_port, dbname=dbname,
                   user=args.pg_user, connect_timeout=3)
              if args.pg_host else
              dict(host=pg_endpoint, dbname=dbname, connect_timeout=3))
        return _p2.connect(**kw)

    missing = []
    if not _docker_ok():
        missing.append("docker (required to run real BIND/named)")
    try:
        c = _pg_connect("postgres")
        c.close()
    except Exception as e:
        missing.append(f"Postgres on {pg_endpoint}: {e}")
    if missing:
        always_fatal = "docker" in " ".join(missing) or args.require_postgres
        print(("FAIL (release gate): " if always_fatal
               else "PREREQUISITES MISSING: ")
              + "\n  - ".join([""] + missing).lstrip(), flush=True)
        return 2

    from apip.config.service import (AdapterConfig, DatabaseConfig,
                                     load_config)
    from apip.controller.service import Controller
    from apip.ledger.db import Database
    from apip.ledger.migrations import apply_migrations

    dburi = ("apip_bind_" + uuid.uuid4().hex[:12])
    _c = _pg_connect("postgres")
    import psycopg2.extensions as _p2e
    _c.set_isolation_level(_p2e.ISOLATION_LEVEL_AUTOCOMMIT)
    _c.cursor().execute(f'CREATE DATABASE "{dburi}"')
    _c.close()
    zones_dir = Path(tempfile.mkdtemp(prefix="apip_bind_gate_"))
    bind = BindServer(zones_dir)
    ctrl: Controller | None = None
    ctrl2: Controller | None = None
    serials: list[int] = []
    serial_kinds: list[bool] = []   # parallel to serials: True = live artifact

    def _publish(live: bool) -> None:
        """Record the artifact's serial at a PUBLISH point — called exactly
        once per generation change, so step 10 can demand strict per-
        generation advancement (an equal pair here is a real defect: BIND
        silently ignores a reload whose serial did not advance)."""
        serials.append(_last_serial(zones_dir, live))
        serial_kinds.append(live)
    try:
        # ---- start real BIND with BOTH artifacts attached -------------------
        _step(1, "start real BIND (named) with live+shadow RPZ attached to "
                 "response-policy")
        bind.start()
        print(f"      named up on 127.0.0.1:{BIND_HOST_PORT} "
              f"({BIND_IMAGE}); policy zones: {ZONE_NAME} + {ZONE_NAME}.shadow")

        def _make_controller(posture: str) -> Controller:
            cfg = replace(
                load_config(None),
                db=(DatabaseConfig(host=args.pg_host, port=args.pg_port,
                                   dbname=dburi, user=args.pg_user)
                    if args.pg_host else
                    DatabaseConfig(host=pg_endpoint, dbname=dburi,
                                   user=os.environ.get("USER", "bamn"))),
                adapter=replace(
                    AdapterConfig(rpz_mode=posture, zone_dir=str(zones_dir),
                                  zone_name=ZONE_NAME),
                    authorized_domains=("operator.test",),
                    verify_query_server="127.0.0.1",
                    verify_query_port=BIND_HOST_PORT,
                    reload_command=f"docker exec {BIND_NAME} kill -HUP 1",
                ))
            db = Database(cfg.db.dsn_kwargs())
            db.wait_until_ready(timeout_s=10)
            apply_migrations(db)
            db.close()
            c = Controller(cfg)
            c.start()
            return c

        # ---- baseline before any APIP state --------------------------------
        _step(2, "prove baseline answers BEFORE any APIP action")
        _expect("baseline", C2_NAME, rcode=0, addresses=["10.99.0.9"])
        _expect("baseline-ttl", TTL_NAME, rcode=0, addresses=["10.99.0.11"])

        # ---- SHADOW leg ------------------------------------------------------
        _step(3, "SHADOW action (shadow artifact, rpz-passthru) -> baseline "
                 "UNCHANGED even though the shadow zone IS attached")
        ctrl = _make_controller("SHADOW")
        ctrl.ledger.register_source(
            source_id=SOURCE, source_class="local", independent=True,
            key_hash="x", actor=ACTOR, auto_enforcement_allowed=True,
            enabled=True)
        _install_policy(ctrl, REPO / "examples" / "operator_shadow_policy.toml",
                        "shadow.1")
        _propose(ctrl, did="decision--bind-shadow",
                 ind_id="indicator--bind-shadow", value=C2_NAME,
                 batch_id="batch--bind-shadow")
        shadow_action_id, action = _approve_and_dispatch(
            ctrl, "decision--bind-shadow")
        if action["mode"] != "SHADOW":
            _fail(f"shadow action persisted mode {action['mode']!r}")
        bind.named_checkzone(f"{ZONE_NAME}.shadow",
                             zones_dir / f"{ZONE_NAME}.shadow.zone")
        # 40: the verdict below must be APIP-caused — the adapter's OWN
        # reload_command published the shadow generation; no helper reload
        # precedes the observation. A diagnostic reload runs after.
        _expect("shadow-no-change", C2_NAME, rcode=0, addresses=["10.99.0.9"])
        bind.reload()
        if C2_NAME in (zones_dir / f"{ZONE_NAME}.zone").read_text():
            _fail("SHADOW action leaked into the LIVE artifact")
        _publish(False)
        print("      shadow artifact attached to a REAL resolver: answer "
              "unchanged (rpz-passthru is a no-op)")

        # ---- ENFORCE leg -----------------------------------------------------
        _step(4, "ENFORCE action (live artifact, CNAME .) -> real NXDOMAIN")
        # Posture change requires a controller restart: the adapter's maximum
        # posture is fixed at construction, so the operator stops the
        # SHADOW-posture controller and starts an ENFORCE-posture one against
        # the same ledger (the same flip lab/acceptance.py exercises). The
        # persisted-mode cap then legitimately permits ENFORCE: policy=ENFORCE
        # x adapter cap=ENFORCE.
        ctrl.stop()
        ctrl = _make_controller("ENFORCE")
        _install_policy(ctrl, REPO / "examples" / "enforce_policy.toml",
                        "enforce.1")
        _propose(ctrl, did="decision--bind-enforce",
                 ind_id="indicator--bind-enforce", value=C2_NAME,
                 batch_id="batch--bind-enforce")
        enforce_action_id, action = _approve_and_dispatch(
            ctrl, "decision--bind-enforce")
        if action["mode"] != "ENFORCE":
            pol = ctrl.current_policy()
            _fail(f"enforce action persisted mode {action['mode']!r}; "
                  f"active policy mode={getattr(pol, 'mode', None)!r} "
                  f"revision={ctrl._active_policy_revision()!r} "
                  f"disposition={action['action_type']}")
        bind.named_checkzone(ZONE_NAME, zones_dir / f"{ZONE_NAME}.zone")
        _publish(True)
        # 40: NXDOMAIN must be APIP-caused (the adapter's own reload), not a
        # helper reload; diagnostic reload follows the verdict.
        _expect("enforce-nxdomain", C2_NAME, rcode=3)
        bind.reload()

        _step(5, "adapter verify() independently confirms NXDOMAIN over real "
                 "DNS")
        result = ctrl._adapter_for(action).verify(
            {"rule_id": action["rule_id"], "fragment": action["fragment"],
             "mode": action["mode"], "selector": action["selector"]})
        if not result.get("ok"):
            _fail(f"adapter ENFORCE verify failed: {result}")
        if not result["observed"].get("dns", {}).get("queried"):
            _fail(f"ENFORCE verify did not live-query DNS: {result}")
        print(f"      verify ok (dns rcode="
              f"{result['observed']['dns']['rcode']})")

        # ---- revoke -----------------------------------------------------------
        # 41: no helper reload BEFORE the revoke verdict — APIP's own
        # configured reload must cause the resolver change; the gate's
        # diagnostic reload happens only after the verdict.
        _step(6, "operator revoke -> baseline restored (APIP-caused, no helper reload first)")
        rev = ctrl.revoke_action(enforce_action_id, ACTOR, "operator_revoke")
        if rev.get("state") != "revoked":
            dump = ctrl.db.query(
                "SELECT phase, ok, detail FROM adapter_attempts "
                "WHERE action_id=%s ORDER BY at", (enforce_action_id,))
            _fail(f"revoke failed: {rev}; attempts={json.dumps(dump, default=str)}")
        _expect("revoke-baseline", C2_NAME, rcode=0, addresses=["10.99.0.9"])

        # ---- TTL expiry --------------------------------------------------------
        _step(7, "TTL expiry removes the rule; baseline restored")
        _propose(ctrl, did="decision--bind-ttl",
                 ind_id="indicator--bind-ttl", value=TTL_NAME,
                 batch_id="batch--bind-ttl")
        ttl_action_id, _a = _approve_and_dispatch(ctrl, "decision--bind-ttl")
        _expect("ttl-nxdomain", TTL_NAME, rcode=3)
        bind.reload()
        ctrl.db.execute(
            "UPDATE actions SET expires_at=%s WHERE action_id=%s",
            (datetime.now(timezone.utc) - timedelta(seconds=1), ttl_action_id))
        from apip.controller.service import CONTROLLER_ACTOR
        now = datetime.now(timezone.utc)
        due = [a for a in ctrl.ledger.actions_due_for_expiry(now)
               if a["action_id"] == ttl_action_id]
        if not due:
            _fail("ttl action not due for expiry")
        out = ctrl._remove_action(due[0], CONTROLLER_ACTOR, "ttl_expired",
                                  terminal_state="expired", revoked_by=None)
        if not out.get("verified"):
            _fail(f"ttl expiry removal not verified: {out}")
        _expect("ttl-baseline", TTL_NAME, rcode=0, addresses=["10.99.0.11"])
        bind.reload()

        # ---- restart APIP -------------------------------------------------------
        _step(8, "restart APIP (fresh controller, same ledger) -> re-apply -> "
                 "NXDOMAIN again")
        ctrl.stop()
        ctrl2 = _make_controller("ENFORCE")
        _propose(ctrl2, did="decision--bind-restart",
                 ind_id="indicator--bind-restart", value=C2_NAME,
                 batch_id="batch--bind-restart")
        _restart_action_id, action = _approve_and_dispatch(
            ctrl2, "decision--bind-restart")
        bind.named_checkzone(ZONE_NAME, zones_dir / f"{ZONE_NAME}.zone")
        _expect("restart-nxdomain", C2_NAME, rcode=3)
        bind.reload()
        if ctrl2.ledger.get_decision("decision--bind-shadow") is None:
            _fail("pre-restart decision lost across restart")

        # ---- cross-posture stress leg --------------------------------------------
        # Audit P0 #1 end-to-end: the SAME FQDN held by a SHADOW action and an
        # ENFORCE action at once; revoking the SHADOW action must NOT touch
        # the live ENFORCE control (this transition used to destroy it).
        _step(9, "stress: SHADOW+ENFORCE coexist for one FQDN; SHADOW revoke "
                 "preserves ENFORCE; ENFORCE expiry restores baseline")
        shadow2_did = "decision--bind-stress-shadow"
        _propose(ctrl2, did=shadow2_did, ind_id="indicator--bind-stress-shadow",
                 value=C2_NAME, batch_id="batch--bind-stress-shadow")
        # policy is ENFORCE here; the co-installed SHADOW posture is the
        # historical promoted-then-expiring SHADOW action: flip the durable
        # action's mode after a normal apply, then re-publish at SHADOW.
        normal_action_id, _sa = _approve_and_dispatch(ctrl2, shadow2_did)
        if _sa["mode"] != "ENFORCE":
            _fail(f"stress action should be ENFORCE, got {_sa['mode']!r}")
        stress_shadow_action = normal_action_id
        dbnow = datetime.now(timezone.utc)
        ctrl2.db.execute("UPDATE actions SET mode='SHADOW' WHERE action_id=%s",
                         (stress_shadow_action,))
        adapter = ctrl2._adapter_for({"adapter": "rpz"})
        rs = adapter.apply({"action_id": stress_shadow_action,
                            "decision_id": shadow2_did, "mode": "SHADOW",
                            "action_type": "dns_nxdomain",
                            "rule_id": f"owner:{C2_NAME}",
                            "fragment": f"{C2_NAME} IN CNAME .",
                            "selector": {"scope_type": "destination_global",
                                         "exact_fqdn": C2_NAME},
                            "ttl_seconds": 600})
        if not rs.get("ok"):
            _fail(f"stress SHADOW apply failed: {rs}")
        bind.named_checkzone(f"{ZONE_NAME}.shadow",
                             zones_dir / f"{ZONE_NAME}.shadow.zone")
        _expect("stress-shadow-present", C2_NAME, rcode=3)   # ENFORCE still wins
        bind.reload()
        # revoke the SHADOW action through the LEDGER path (operator revoke):
        # only the shadow artifact may change; live NXDOMAIN must survive.
        rev2 = ctrl2.revoke_action(stress_shadow_action, ACTOR, "operator_revoke")
        # the step-3 SHADOW action shares this rule_id+mode: it also owns the
        # shadow line, so the stress revoke correctly DEFERS the physical
        # removal while that co-owner is still active (review P0 #6). Retire
        # the co-owner — its own revoke performs the physical removal — and
        # only then must the shadow artifact be empty.
        if rev2.get("state") == "revoked" and rev2.get("shared_rule"):
            rev3 = ctrl2.revoke_action(shadow_action_id, ACTOR, "operator_revoke")
            if rev3.get("state") != "revoked":
                _fail(f"stress co-owner SHADOW revoke failed: {rev3}")
        elif rev2.get("state") != "revoked":
            _fail(f"stress SHADOW revoke failed: {rev2}")
        if C2_NAME not in (zones_dir / f"{ZONE_NAME}.zone").read_text():
            _fail("SHADOW revoke destroyed the live ENFORCE control "
                  "(cross-posture revoke)")
        _expect("stress-enforce-survives", C2_NAME, rcode=3)
        if C2_NAME in (zones_dir / f"{ZONE_NAME}.shadow.zone").read_text():
            _fail("stress SHADOW revoke left the shadow rule in place")
        _publish(False)
        print("      SHADOW revoke preserved the ENFORCE control")
        # expire the ENFORCE action -> baseline restored
        ctrl2.db.execute(
            "UPDATE actions SET expires_at=%s WHERE action_id=%s",
            (dbnow - timedelta(seconds=1), _restart_action_id))
        from apip.controller.service import CONTROLLER_ACTOR as _CA
        due2 = [a for a in ctrl2.ledger.actions_due_for_expiry(
            datetime.now(timezone.utc)) if a["action_id"] == _restart_action_id]
        if not due2:
            _fail("stress ENFORCE action not due for expiry")
        out2 = ctrl2._remove_action(due2[0], _CA, "ttl_expired",
                                    terminal_state="expired", revoked_by=None)
        if not out2.get("verified"):
            _fail(f"stress ENFORCE expiry removal not verified: {out2}")
        if C2_NAME in (zones_dir / f"{ZONE_NAME}.zone").read_text():
            _fail("stress ENFORCE expiry left the live rule in place")
        _publish(True)
        _expect("stress-baseline", C2_NAME, rcode=0, addresses=["10.99.0.9"])
        bind.reload()
        print("      ENFORCE expiry restored the baseline")

        # ---- repeated posture stress (audit #41) ---------------------------------
        # Serial/reload sequencing defects hide behind single cycles: the
        # SHADOW -> ENFORCE -> revoke cycle runs AGAIN against the same
        # artifacts, so per-generation serial advancement and reload
        # propagation are proven across MANY publishes in one run.
        _step(10, "repeated posture stress: ENFORCE -> revoke -> ENFORCE on a "
                  "second FQDN (multi-cycle serial/reload rigor)")
        for cycle in (1, 2):
            rep_did = f"decision--bind-repeat-{cycle}"
            _propose(ctrl2, did=rep_did, ind_id=f"indicator--bind-repeat-{cycle}",
                     value=REPEAT_NAME, batch_id=f"batch--bind-repeat-{cycle}")
            rep_action_id, _ra = _approve_and_dispatch(ctrl2, rep_did)
            _expect(f"repeat-{cycle}-nxdomain", REPEAT_NAME, rcode=3)
            _publish(True)
            rev_r = ctrl2.revoke_action(rep_action_id, ACTOR, "operator_revoke")
            if rev_r.get("state") != "revoked":
                _fail(f"repeat cycle {cycle} revoke failed: {rev_r}")
            _expect(f"repeat-{cycle}-baseline", REPEAT_NAME, rcode=0,
                    addresses=["10.99.0.13"])
            _publish(True)
            print(f"      repeat cycle {cycle}: ENFORCE -> revoke -> baseline")
        bind.reload()

        # ---- SOA serial monotonicity ---------------------------------------------
        _step(11, "SOA serial advanced on EVERY publish, per artifact "
                  "(per-generation, reload propagates)")
        # serials were appended in publish order; each artifact's subsequence
        # must STRICTLY advance (RFC 1982) — an identical or regressing
        # serial means BIND would silently ignore that reload.
        for live_flag, name in ((True, "live"), (False, "shadow")):
            seq = [s for s, lf in zip(serials, serial_kinds) if lf == live_flag
                   and s >= 0]
            if len(seq) < 2:
                _fail(f"{name} artifact has {len(seq)} observed serials; "
                      f"need >= 2 publishes: {serials}")
            for prev, nxt in zip(seq, seq[1:]):
                if nxt == prev or not _serial_newer(nxt, prev):
                    _fail(f"{name} artifact serial did not advance per "
                          f"generation: {prev} -> {nxt} (all: {seq})")
            print(f"      {name} serial generations: {seq}")
        print(f"      all serials observed: {sorted(set(s for s in serials if s >= 0))}")

        print("\nBIND GATE PASSED: real named loaded the APIP artifacts, "
              "enforced NXDOMAIN via response-policy, restored baseline on "
              "revoke/expiry, and the attached shadow artifact changed no "
              "answer.", flush=True)
        return 0
    except _GateFailure:
        return 1
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        print(f"\nBIND GATE FAILED: {e!r}", flush=True)
        return 1
    finally:
        failed = _FAILED[0] if _FAILED else None
        if failed:
            # 41: on failure, PRESERVE state for debugging instead of
            # cleaning it away: keep the zone artifacts, the BIND log
            # tail, and the container until the next run replaces them.
            try:
                import shutil as _sh
                keep = Path("/tmp/apip-bind-gate-failure")
                if keep.exists():
                    _sh.rmtree(keep)
                _sh.copytree(zones_dir, keep)
                logs = subprocess.run(["docker", "logs", BIND_NAME],
                                      capture_output=True, text=True,
                                      timeout=30)
                (keep / "named.log").write_text(
                    logs.stderr + logs.stdout, encoding="utf-8")
                # audit #41: debugging context — observed serials per
                # artifact, container state/exit code
                (keep / "serials.json").write_text(json.dumps({
                    "serials": serials, "serial_kinds": serial_kinds,
                }, indent=2), encoding="utf-8")
                state = subprocess.run(
                    ["docker", "ps", "-a", "--filter",
                     f"name={BIND_NAME}",
                     "--format", "{{.Status}}"],
                    capture_output=True, text=True, timeout=30)
                (keep / "container_state.txt").write_text(
                    state.stdout, encoding="utf-8")
                print(f"\nfailure artifacts preserved in {keep} "
                      f"(zones + named.log + serials.json + "
                      f"container_state.txt); container kept running",
                      flush=True)
            except Exception as diag_exc:
                print(f"(failure-diagnostic capture failed: {diag_exc})",
                      flush=True)
        for c in (ctrl, ctrl2):
            if c is not None:
                try:
                    c.stop()
                except Exception:
                    pass
        if not failed:
            bind.stop()
        try:
            _c = _pg_connect("postgres")
            import psycopg2.extensions as _p2e
            _c.set_isolation_level(_p2e.ISOLATION_LEVEL_AUTOCOMMIT)
            _c.cursor().execute(f'DROP DATABASE IF EXISTS "{dburi}" '
                                f'WITH (FORCE)')
            _c.close()
        except Exception:
            pass
        shutil.rmtree(zones_dir, ignore_errors=True)


_FAILED: list[str] = []


class _GateFailure(Exception):
    pass


# _fail uses SystemExit; wrap for the try/except above is unnecessary — keep
# SystemExit semantics simple.


if __name__ == "__main__":
    sys.exit(main())
