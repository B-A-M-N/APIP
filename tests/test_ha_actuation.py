"""Leader-owned actuation (audit P0 #9).

In an HA deployment the API request can land on ANY controller, but the
actuator state is LOCAL to each (separate zone directories). The durable
record is the shared thing. Therefore: an API-served revoke on a
FOLLOWER commits durable intent (desired ABSENT) and never touches that
follower's adapter — the lease-owning leader's reconciler performs the
physical removal, converging from the shared ledger.

Proven against real Postgres with two controllers, two DIFFERENT zone
directories, one ledger:
  - B (follower) revoke -> ledger intent committed, B's zone untouched,
    A's zone converges to the removal;
  - lease takeover: after A stops, B takes the lease and continues the
    committed removal from durable state.
"""
from __future__ import annotations

import sys
import tempfile
import time
import uuid
from dataclasses import replace
from pathlib import Path

import psycopg2
import psycopg2.extensions
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pg  # noqa: E402  (shared Postgres test endpoints)

from apip.config.service import (  # noqa: E402
    AdapterConfig,
    ControllerConfig,
    DatabaseConfig,
    load_config,
)
from apip.controller.service import Controller  # noqa: E402
from apip.ledger.db import Database  # noqa: E402
from apip.ledger.migrations import apply_migrations  # noqa: E402
from apip.ledger.repo import Ledger  # noqa: E402


def _can_connect() -> bool:
    try:
        conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
        conn.close()
        return True
    except psycopg2.Error:
        return False


pytestmark = pytest.mark.skipif(
    not _can_connect(), reason="no reachable Postgres for HA actuation tests")


POLICY = """
policy_version = "ha"
mode = "ENFORCE"
scope = "*"
allowlist = []
[thresholds]
observe_m = 40
fqdn_auto_m = 90
fqdn_auto_s = 85
ip_rate_m = 90
ip_rate_s = 85
ip_deny_m = 98
ip_deny_s = 95
[thresholds.rungs.L4]
m = 95
s = 75
[limits]
max_auto_ttl_seconds = 600
max_evidence_per_indicator = 64
nominal_rate_ceiling_per_min = 1000
[authorization]
authorized_domains = ["corp.test"]
[safety]
allowlist_precedence = true
no_ai_components = true
[behavioral]
enabled_families = []
max_behavioral_m_contribution = 60
[behavioral.corroboration]
distinct_families_for_rate_limit = 2
distinct_families_for_deny = 3
deny_also_requires_external = true
"""


def _activate(led: Ledger) -> None:
    import hashlib
    rev = led.next_policy_revision("ha")
    led.stage_policy(policy_version="ha", revision=rev,
                     content_sha256=hashlib.sha256(POLICY.encode()).hexdigest(),
                     raw_text=POLICY, mode="ENFORCE", staged_by="test")
    led.promote_policy("ha", rev, "test")


def _wait_for(condition, timeout_s: float = 10.0, poll_s: float = 0.05):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(poll_s)
    return False


class HACluster:
    """Two controllers over one ledger with SEPARATE local artifacts."""

    def __init__(self, name: str, zone_a: str, zone_b: str,
                 ctrl_a: Controller, ctrl_b: Controller, db: Database):
        self.name = name
        self.zone_a = zone_a
        self.zone_b = zone_b
        self.a = ctrl_a
        self.b = ctrl_b
        self.db = db

    @property
    def led(self) -> Ledger:
        return self.a.ledger

    def install_rule_everywhere(self, tag: str) -> tuple[str, dict]:
        """Seed an applied action citing the active policy and physically
        install its rule into BOTH controllers' local artifacts (the
        replicated edge state an HA deploy would have)."""
        _activate(self.led)
        ind = f"{tag}.evil.corp.test"
        sha = self.led.current_policy_row()["content_sha256"]
        self.db.execute(
            "INSERT INTO indicators (indicator_id, itype, value) VALUES "
            "(%s, 'fqdn', %s) ON CONFLICT DO NOTHING",
            (f"indicator--{tag}", ind))
        self.db.execute("""
INSERT INTO decisions (decision_id, seq, indicator_id, batch_id, maliciousness,
    action_safety, disposition, action, rung, scope, ttl_seconds,
    policy_version, policy_content_sha256, reason_codes, explanation,
    content_hash)
VALUES (%s, 1, %s, NULL, 95, 95, 'AUTO_ENFORCE', 'dns_nxdomain', 'L4', '*',
        600, 'ha', %s, '{}', 'x', 'h--' || %s)
""", (f"decision--{tag}", f"indicator--{tag}", sha, tag))
        action_id = f"action--{tag}"
        self.db.execute("""
INSERT INTO actions (action_id, decision_id, decision_seq, indicator_id,
    adapter, action_type, mode, selector, rule_id, fragment, fragment_hash,
    bundle_id, bundle_hash, requested_by, state)
VALUES (%s, %s, 1, %s, 'rpz', 'dns_nxdomain', 'ENFORCE', %s, %s, %s, 'h',
        'b', 'bh', 'test', 'applied')
""", (action_id, f"decision--{tag}", f"indicator--{tag}",
      f'{{"scope_type": "destination_global", "exact_fqdn": "{ind}"}}',
      f"owner:{ind}", f"{ind} IN CNAME ."))
        candidate = {"action_id": action_id,
                     "decision_id": f"decision--{tag}", "mode": "ENFORCE",
                     "action_type": "dns_nxdomain",
                     "rule_id": f"owner:{ind}",
                     "fragment": f"{ind} IN CNAME .",
                     "selector": {"scope_type": "destination_global",
                                  "exact_fqdn": ind},
                     "ttl_seconds": 600}
        for ctrl in (self.a, self.b):
            r = ctrl._adapter_for({"adapter": "rpz"}).apply(dict(candidate))
            assert r["ok"], (ctrl is self.a, r)
        return action_id, candidate

    def rule_in_zone(self, zone: str, fqdn: str) -> bool:
        p = Path(zone) / "apip.ha.test.zone"
        if not p.is_file():
            return False
        return any(l.split(";")[0].strip().startswith(f"{fqdn} ")
                   for l in p.read_text().splitlines())


@pytest.fixture()
def ha():
    name = "apip_ha_" + uuid.uuid4().hex[:12]
    conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    conn.cursor().execute(f'CREATE DATABASE "{name}"')
    conn.close()
    zone_a = tempfile.mkdtemp(prefix="ha_zone_a_")
    zone_b = tempfile.mkdtemp(prefix="ha_zone_b_")

    def make(zone_dir: str) -> Controller:
        cfg = replace(
            load_config(None),
            db=DatabaseConfig(host=pg.HOST, port=pg.PORT, dbname=name,
                              user=pg.USER),
            controller=replace(ControllerConfig(),
                               reconcile_interval_s=0.2,
                               verify_interval_s=3600),
            adapter=replace(
                # audit #31: operator-owned zone name (the unedited example
                # value is refused at ENFORCE startup)
                AdapterConfig(rpz_mode="ENFORCE", zone_dir=zone_dir,
                              zone_name="apip.ha.test",
                              reload_command="true",
                              verify_query_server="127.0.0.1",
                              verify_query_port=5333),
                authorized_domains=("corp.test",)),
        )
        return Controller(cfg)

    ctrl_a = make(zone_a)
    ctrl_a.start()
    time.sleep(0.5)          # A takes the lease
    ctrl_b = make(zone_b)
    ctrl_b.start()
    db = Database(ctrl_a.config.db.dsn_kwargs())
    db.connect()
    cluster = HACluster(name, zone_a, zone_b, ctrl_a, ctrl_b, db)
    try:
        yield cluster
    finally:
        db.close()
        ctrl_a.stop()
        ctrl_b.stop()
        conn = psycopg2.connect(**pg.dsn_kwargs("postgres"))
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        conn.cursor().execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        conn.close()


def test_follower_revoke_commits_intent_never_touches_own_adapter(ha):
    """The core P0 #9 property: the revoke request lands on B (a
    follower). B's local artifact must be untouched; A (leader) converges
    the shared durable intent and removes the rule from ITS artifact."""
    action_id, cand = ha.install_rule_everywhere("lead1")
    fqdn = "lead1.evil.corp.test"
    assert ha.rule_in_zone(ha.zone_a, fqdn)
    assert ha.rule_in_zone(ha.zone_b, fqdn)
    zone_b_before = (Path(ha.zone_b) / "apip.ha.test.zone").read_text()
    # revoke served by B — the follower
    assert ha.b.state.is_leader is False
    out = ha.b.revoke_action(action_id, "operator", "operator_revoke")
    assert out["deferred_to_leader"] is True, out
    # durable intent was committed on the shared ledger
    row = ha.db.query_one(
        "SELECT state, desired_state FROM actions WHERE action_id=%s",
        (action_id,))
    assert row["desired_state"] == "ABSENT", row
    # B's artifact must be untouched by the follower
    assert (Path(ha.zone_b) / "apip.ha.test.zone").read_text() == \
        zone_b_before, "follower mutated its local adapter"
    # the LEADER's reconciler converges: A's artifact loses the rule and
    # the action reaches its terminal state
    assert _wait_for(lambda: ha.rule_in_zone(ha.zone_a, fqdn) is False), \
        "leader never removed the rule from its artifact"
    assert _wait_for(lambda: ha.db.query_one(
        "SELECT state FROM actions WHERE action_id=%s",
        (action_id,))["state"] == "revoked")


def test_lease_takeover_continues_committed_removal(ha):
    """A commits the removal intent and dies before actuating; B takes
    the lease and completes the removal from durable state — the removal
    can never become an apply."""
    action_id, cand = ha.install_rule_everywhere("take1")
    fqdn = "take1.evil.corp.test"
    # A commits intent only (no actuation): direct request_removal
    assert ha.led.request_removal(
        action_id, ("applied", "verified", "drifted", "dispatching"))
    ha.a.stop()               # leader gone
    # B must take the lease and converge the committed intent
    assert _wait_for(lambda: ha.b.state.is_leader is True, timeout_s=15), \
        "B never took over the lease"
    assert _wait_for(lambda: ha.rule_in_zone(ha.zone_b, fqdn) is False), \
        "B (new leader) never removed the rule"
    assert _wait_for(lambda: ha.db.query_one(
        "SELECT state, desired_state FROM actions WHERE action_id=%s",
        (action_id,))["state"] == "revoked")
    row = ha.db.query_one(
        "SELECT desired_state FROM actions WHERE action_id=%s", (action_id,))
    assert row["desired_state"] == "ABSENT"
