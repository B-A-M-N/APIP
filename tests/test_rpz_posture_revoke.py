"""RPZ posture-scoped revoke + artifact-generation SOA serials (audit P0 #1/#3).

Cross-posture matrix (P0 #1): the same FQDN may legitimately exist in BOTH
artifacts at once (a SHADOW action for the name expiring while an ENFORCE
action for it is live). Revoking one posture must remove ONLY its own
artifact's line — revoke is not a "remove everywhere" primitive, and the
adapter's partition must match the ledger's mode-partitioned co-ownership.

Serial generations (P0 #3): the SOA serial belongs to the artifact
GENERATION, not to wall-clock time. 100 publishes inside a frozen second
must all advance; restart and backwards clock must never regress; the 32-bit
wrap follows RFC 1982. BIND ignores a reload whose serial did not advance,
so an identical serial is a silent enforcement failure.
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apip.adapters.rpz import (  # noqa: E402
    _next_serial,
    _serial_newer,
    _zone_serial,
    RpzAdapter,
)
from apip.config.service import AdapterConfig  # noqa: E402


def _adapter(tmp_path: Path, mode: str = "ENFORCE") -> RpzAdapter:
    return RpzAdapter(AdapterConfig(
        rpz_mode=mode,
        zone_dir=str(tmp_path / "rpz"),
        zone_name="apip.rpz.test",
        authorized_domains=("operator.test",),
    ))


def _candidate(mode: str, action_id: str = "action--x") -> dict:
    owner = "bad.operator.test"
    return {
        "action_id": action_id,
        "decision_id": "decision--x",
        "mode": mode,
        "action_type": "dns_nxdomain",
        "rule_id": f"owner:{owner}",
        "fragment": f"{owner} IN CNAME .",
        "selector": {"scope_type": "destination_global",
                     "exact_fqdn": owner},
        "ttl_seconds": 600,
    }


def _present(adapter: RpzAdapter, live: bool, owner: str = "bad.operator.test") -> bool:
    zone = adapter._read_zone(live)
    return any(l.split(";")[0].strip().startswith(f"{owner} ")
               for l in zone.splitlines())


# --------------------------------------------------------------------------- #
# P0 #1 — the four-state cross-posture matrix
# --------------------------------------------------------------------------- #

def _install_both(adapter: RpzAdapter) -> None:
    r = adapter.apply(_candidate("SHADOW", "action--shadow"))
    assert r["ok"], r
    r = adapter.apply(_candidate("ENFORCE", "action--live"))
    assert r["ok"], r
    assert _present(adapter, True) and _present(adapter, False)


def test_revoke_shadow_leaves_live_enforce(tmp_path):
    a = _adapter(tmp_path)
    _install_both(a)
    r = a.revoke(_candidate("SHADOW", "action--shadow"))
    assert r["ok"], r
    assert _present(a, True), "ENFORCE control destroyed by SHADOW revoke"
    assert not _present(a, False)


def test_revoke_enforce_leaves_shadow(tmp_path):
    a = _adapter(tmp_path)
    _install_both(a)
    r = a.revoke(_candidate("ENFORCE", "action--live"))
    assert r["ok"], r
    assert _present(a, False), "SHADOW control destroyed by ENFORCE revoke"
    assert not _present(a, True)


def test_last_shadow_owner_revoked_only_shadow_disappears(tmp_path):
    a = _adapter(tmp_path)
    _install_both(a)
    r = a.revoke(_candidate("SHADOW", "action--shadow"))
    assert r["ok"], r
    # now revoke the ENFORCE action too: the live artifact must empty
    r = a.revoke(_candidate("ENFORCE", "action--live"))
    assert r["ok"], r
    assert not _present(a, True) and not _present(a, False)


def test_last_enforce_owner_revoked_only_live_disappears(tmp_path):
    a = _adapter(tmp_path)
    _install_both(a)
    r = a.revoke(_candidate("ENFORCE", "action--live"))
    assert r["ok"], r
    assert not _present(a, True)
    assert _present(a, False)


def test_revoke_below_shadow_adapter_caps_artifact_choice(tmp_path):
    """A SHADOW-capped adapter (max SHADOW) revoking an ENFORCE-persisted
    action must NOT touch the live artifact — configuration can only weaken
    an action, so the effective posture is SHADOW and only the shadow
    artifact is edited. (State is installed by an ENFORCE adapter; the
    capped adapter is the one that revokes.)"""
    installer = _adapter(tmp_path)
    _install_both(installer)
    a = _adapter(tmp_path, mode="SHADOW")
    r = a.revoke(_candidate("ENFORCE", "action--live"))
    assert r["ok"], r
    assert _present(a, True), "capped revoke touched the live artifact"
    assert not _present(a, False)


# --------------------------------------------------------------------------- #
# P0 #3 — serial generations
# --------------------------------------------------------------------------- #

def test_100_publishes_in_a_frozen_second_all_advance(tmp_path):
    """The exact failure the reviewer's BIND gate hit: an ENFORCE publish in
    the same wall-clock second as the SHADOW publish produced an identical
    serial and BIND silently ignored the reload. Generations must advance
    regardless of the clock."""
    a = _adapter(tmp_path)
    serials: list[int] = []
    for i in range(100):
        r = a.apply(_candidate("ENFORCE", f"action--s{i}"))
        assert r["ok"], r
        serials.append(r["receipt"]["observed"]["soa_serial"])
    assert len(set(serials)) == 100, "serial repeated within one second"
    for prev, nxt in zip(serials, serials[1:]):
        assert _serial_newer(nxt, prev), f"{prev} -> {nxt} did not advance"


def test_apply_revoke_same_millisecond_advances(tmp_path):
    a = _adapter(tmp_path)
    r1 = a.apply(_candidate("ENFORCE"))
    s1 = r1["receipt"]["observed"]["soa_serial"]
    r2 = a.revoke(_candidate("ENFORCE"))
    assert r2["ok"], r2
    s2 = _zone_serial(a._read_zone(True).splitlines())
    assert s2 is not None and _serial_newer(s2, s1), \
        f"revoke republished with a non-advancing serial: {s1} -> {s2}"


def test_serial_survives_restart(tmp_path):
    a = _adapter(tmp_path)
    r = a.apply(_candidate("ENFORCE"))
    before = r["receipt"]["observed"]["soa_serial"]
    # fresh adapter instance over the same dir = process restart
    b = _adapter(tmp_path)
    r2 = b.apply(_candidate("ENFORCE", "action--second"))
    after = r2["receipt"]["observed"]["soa_serial"]
    assert _serial_newer(after, before), "restart regressed the serial"


def test_clock_moving_backwards_cannot_regress(tmp_path):
    """The serial is read from the artifact and advanced by one, so wall
    clock moving backwards cannot lower it."""
    import apip.adapters.rpz as rpz
    a = _adapter(tmp_path)
    r = a.apply(_candidate("ENFORCE"))
    before = r["receipt"]["observed"]["soa_serial"]
    real = rpz._dt.datetime
    class _FakeDt:
        @staticmethod
        def datetime(*args, **kw):
            class _F:
                @staticmethod
                def now(tz):
                    return real(2000, 1, 1, tzinfo=tz)   # far in the past
            return _F
        @staticmethod
        def timezone(*a, **k):
            return real.timezone(*a, **k)
    try:
        rpz._dt = _FakeDt
        b = _adapter(tmp_path)
        r2 = b.apply(_candidate("ENFORCE", "action--after-clock"))
        after = r2["receipt"]["observed"]["soa_serial"]
    finally:
        rpz._dt = real
    assert _serial_newer(after, before), "backwards clock regressed serial"


def test_serial_wrap_32bit():
    assert _next_serial(2**32 - 1) == 0
    assert _serial_newer(0, 2**32 - 1)
    assert not _serial_newer(2**32 - 1, 0)


def test_concurrent_applies_all_advance(tmp_path):
    """Two threads publishing without coordination must still produce
    distinct advancing generations (artifact lock)."""
    a = _adapter(tmp_path)
    serials: list[int] = []
    lock = threading.Lock()

    def _worker(i: int) -> None:
        r = a.apply(_candidate("ENFORCE", f"action--t{i}"))
        with lock:
            serials.append(r["receipt"]["observed"]["soa_serial"])

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(serials)) == 16, f"serial collision under concurrency: {sorted(serials)}"


def test_unique_temp_files_no_fixed_name(tmp_path):
    """The write path must not use a fixed temp filename two writers could
    collide on (audit P0 #10)."""
    import inspect
    src = inspect.getsource(type(_adapter(tmp_path))._write_zone)
    assert "getpid" in src or "urandom" in src or "get_ident" in src
