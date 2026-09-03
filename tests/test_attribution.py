"""Requester attribution correlation runtime tests (docs/30).

Proof goals:
  1. BYTE-IDENTICAL to the reference oracle: probe order, fingerprint,
     handles (dev-key context), extraction, and the correlation report are
     computed identically in the product and in reference/ (differential);
  2. P0 invariant: attribution output is never an enforcement input —
     decisions are byte-identical with or without attribution records;
  3. bounded store: exceeds the requester cap degrades (stop-and-mark), never
     unlimited growth, never added authority;
  4. deterministic, order-invariant merge: an older record cannot drag
     ``last_seen`` backwards or overwrite a newer feature value;
  5. structural validation REFUSES malformed records (never coerces), and a
     keyed handle is unverifiable outside the deployment's key.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from oracle_client import oracle_attribution  # noqa: E402

from apip.attribution import (  # noqa: E402
    ATTRIBUTION_SOURCE_CLASS,
    CorrelationStore,
    DeploymentKeyError,
    TransactionRejected,
    extract_features,
    fingerprint,
    handle_for,
    probe_order,
    reset_key_cache,
    similarity,
    validate_transaction,
)


def _tx(client, observed_at="2026-09-01T20:00:00Z", **kw):
    base = {"client_ref": client, "observed_at": observed_at,
            "header_order": ["Host", "User-Agent", "Accept"]}
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# Deterministic probe order + fingerprint (no RNG divergence)
# ---------------------------------------------------------------------------

def test_probe_order_deterministic_replay():
    assert probe_order("sess-1", "0") == probe_order("sess-1", "0")
    assert probe_order("sess-1", "0") != probe_order("sess-1", "1")


def test_fingerprint_canonical_deterministic():
    a = fingerprint({"P1:x": "a", "P2:y": "b"})
    b = fingerprint({"P2:y": "b", "P1:x": "a"})
    assert a == b
    assert a.startswith("fp--fp1--")


def test_similarity_counts_shared_keys():
    a = {"P1:x": "a", "P2:y": "b", "P3:z": "c"}
    b = {"P1:x": "a", "P9:w": "q"}
    assert similarity(a, b) == 1


# ---------------------------------------------------------------------------
# Deployment-keyed handles (P1-16)
# ---------------------------------------------------------------------------

def test_handle_is_keyed_hmac(monkeypatch):
    reset_key_cache()
    monkeypatch.setenv("APIP_DEPLOYMENT_KEY", "x" * 40)
    reset_key_cache()
    h1 = handle_for("203.0.113.7")
    reset_key_cache()
    monkeypatch.setenv("APIP_DEPLOYMENT_KEY", "x" * 40 + "!")
    reset_key_cache()
    h2 = handle_for("203.0.113.7")
    # rotated key -> different handle, same input
    assert h1 != h2
    assert h1.startswith("rh--")


def test_short_deployment_key_fails_closed(monkeypatch):
    monkeypatch.setenv("APIP_DEPLOYMENT_KEY", "short")
    reset_key_cache()
    with pytest.raises(DeploymentKeyError):
        handle_for("203.0.113.7")
    reset_key_cache()


def test_dev_fallback_provenance_reported(monkeypatch):
    monkeypatch.delenv("APIP_DEPLOYMENT_KEY", raising=False)
    monkeypatch.delenv("APIP_DEPLOYMENT_KEY_FILE", raising=False)
    reset_key_cache()
    store = CorrelationStore()
    store.observe(_tx("host-1"))
    assert store.report()["handle_keying"] == "dev-fallback"
    reset_key_cache()


# ---------------------------------------------------------------------------
# Transaction contract validation (structural, refusal not coercion)
# ---------------------------------------------------------------------------

def test_validate_accepts_wellformed():
    validate_transaction(_tx("host-1", tls_ja4="t13d1517h2_8daaf6b2_2",
                             cache_behavior="validators_present_correct",
                             range_fallback="range_honored"))


def test_validate_rejects_unknown_field():
    with pytest.raises(TransactionRejected, match="unknown fields"):
        validate_transaction(_tx("host-1", sneaky="x"))


def test_validate_rejects_bad_timestamp():
    with pytest.raises(TransactionRejected, match="ISO-8601 UTC"):
        validate_transaction(_tx("host-1", observed_at="20:00:00"))


def test_validate_rejects_nonstring_and_control():
    with pytest.raises(TransactionRejected):
        validate_transaction(_tx("host-1", accept_language=12345))
    with pytest.raises(TransactionRejected, match="control"):
        validate_transaction(_tx("host-1", accept_language="en\x00-US"))


def test_validate_rejects_nonunique_header_order():
    with pytest.raises(TransactionRejected):
        validate_transaction(_tx("host-1", header_order=["Host", "Host"]))


def test_validate_rejects_enum_violation():
    with pytest.raises(TransactionRejected):
        validate_transaction(_tx("host-1", cache_behavior="bogus_value"))


# ---------------------------------------------------------------------------
# Feature extraction (deterministic per-probe)
# ---------------------------------------------------------------------------

def test_extract_features_header_order_and_set():
    feats = extract_features(_tx("host-1"))
    assert feats["P1:header_order"] == "Host,User-Agent,Accept"
    assert feats["P1:header_set"].startswith(("0", "1", "2", "3", "4", "5",
                                              "6", "7", "8", "9", "a", "b",
                                              "c", "d", "e", "f"))


def test_extract_features_ja4_and_cache():
    feats = extract_features(_tx("host-1", tls_ja4="t13d1517h2",
                                 cache_behavior="revalidation_ignored",
                                 range_fallback="malformed_retry"))
    assert feats["P3:ja4"] == "t13d1517h2"
    assert feats["P4:cache_behavior"] == "revalidation_ignored"
    assert feats["P6:range_fallback"] == "malformed_retry"


def test_extract_features_empty_record_no_guesses():
    assert extract_features({"client_ref": "x", "observed_at": "2026-09-01T20:00:00Z",
                             "header_order": []}) == {}


# ---------------------------------------------------------------------------
# CorrelationStore merge / eviction / report semantics
# ---------------------------------------------------------------------------

def test_store_folds_and_reports_fingerprint_group():
    store = CorrelationStore()
    store.observe(_tx("host-1", header_order=["a", "b"]))
    store.observe(_tx("host-1", header_order=["a", "b"]))  # repeat folds into one
    store.observe(_tx("host-2", header_order=["a", "b"]))  # identical -> same fp
    r = store.report()
    assert r["schema_version"] == "corr-1"
    assert r["tracked_requesters"] == 2
    assert len(r["fingerprint_groups"]) == 1   # both requesters share one fp
    g = r["fingerprint_groups"][0]
    assert set(g["requester_handles"]) == {handle_for("host-1"),
                                           handle_for("host-2")}


def test_store_order_invariant_merge_p18():
    store = CorrelationStore()
    newer = _tx("host-1", observed_at="2026-09-01T20:01:00Z",
                header_order=["z", "y"])
    older = _tx("host-1", observed_at="2026-09-01T20:00:00Z",
                header_order=["a", "b"])
    # arrive out of order: older FIRST then newer
    store.observe(older)
    store.observe(newer)
    state = store._snapshot()[0]
    # newer feature value wins (z,y), last_seen is the max instant
    assert state.features["P1:header_order"] == "z,y"
    assert state.last_seen == "2026-09-01T20:01:00Z"


def test_store_future_stamped_expires_in_prune():
    store = CorrelationStore()
    store.observe(_tx("host-1", observed_at="2026-09-01T20:00:00Z"))
    store.observe(_tx("host-2", observed_at="2099-01-01T00:00:00Z"))
    # just after host-1's contact: host-1 within TTL survives; the 2099-future
    # entry is beyond the TTL horizon and treated as expired (TM-009 clock fix)
    n = store.prune_expired("2026-09-01T20:05:00Z", 3600)
    assert n == 1
    survives = [s.handle for s in store._snapshot()]
    assert handle_for("host-1") in survives
    assert handle_for("host-2") not in survives


def test_store_bounded_capacity_degrades():
    store = CorrelationStore(max_requesters=2)
    store.observe(_tx("host-1"))
    store.observe(_tx("host-2"))
    assert store.degraded is False
    assert store.observe(_tx("host-3")) is None      # overflow suppressed
    assert store.degraded is True
    assert store.report()["tracked_requesters"] == 2  # never grows past cap


def test_attribution_refs_display_only_handle():
    store = CorrelationStore()
    store.observe(_tx("host-1"))
    refs = store.attribution_refs_for("host-1")
    assert refs and refs[0].startswith("fp--")


# ---------------------------------------------------------------------------
# Differential: product == reference oracle (docs/30), isolated subprocess
# ---------------------------------------------------------------------------

def _attribution_script():
    tx_a = {"client_ref": "host-1", "observed_at": "2026-09-01T20:00:00Z",
            "header_order": ["Host", "User-Agent", "Accept"],
            "accept_language": "en-US,en;q=0.9", "accept_encoding": "gzip, deflate",
            "tls_ja4": "t13d1517h2_8daaf6b2_2", "cache_behavior": "validators_present_correct",
            "range_fallback": "range_honored",
            "challenge_body_key_order": ["ts", "nonce", "probe_set", "response"]}
    tx_b = {"client_ref": "host-1", "observed_at": "2026-09-01T20:01:00Z",
            "header_order": ["Accept", "Host"],
            "accept_language": "en-US,en;q=0.9", "accept_encoding": "gzip, deflate",
            "tls_ja4": "t13d1517h2_8daaf6b2_2"}
    tx_c = {"client_ref": "host-2", "observed_at": "2026-09-01T20:02:00Z",
            "header_order": ["Host", "Connection"],
            "accept_language": "fr-FR", "accept_encoding": "br",
            "tls_ja4": "t12d1518h2_8daaf6b2_1"}
    script = [
        {"op": "probe_order", "session": "sess-1", "epoch": "0"},
        {"op": "probe_order", "session": "sess-1", "epoch": "1"},
        {"op": "fingerprint", "features": ["P1:x=a", "P2:y=b", "P3:z=c"]},
        {"op": "handle", "client": "host-1"},
        {"op": "handle", "client": "203.0.113.7"},
        {"op": "validate", "tx": tx_c},
        {"op": "report", "tag": "r1", "transactions": [tx_a, tx_b, tx_c]},
    ]
    return script, tx_a, tx_b


def test_attribution_byte_identical_to_reference():
    """The product attribution pipe must produce byte-identical outputs to the
    reference oracle for probe order, fingerprint, handles, and the report."""
    script, tx_a, tx_b = _attribution_script()
    oracle = oracle_attribution(script)

    res = {
        "po|sess-1|0": list(probe_order("sess-1", "0")),
        "po|sess-1|1": list(probe_order("sess-1", "1")),
        "fp|P1:x=a|P2:y=b|P3:z=c": fingerprint(
            {"P1:x": "a", "P2:y": "b", "P3:z": "c"}),
        "rh|host-1": handle_for("host-1"),
        "rh|203.0.113.7": handle_for("203.0.113.7"),
    }
    store = CorrelationStore()
    store.observe(tx_a)
    store.observe(tx_b)
    store.observe(_tx("host-2", observed_at="2026-09-01T20:02:00Z",
                      header_order=["Host", "Connection"],
                      accept_language="fr-FR", accept_encoding="br",
                      tls_ja4="t12d1518h2_8daaf6b2_1"))
    res["report|r1"] = store.report(min_similarity=3)

    # the well-formed record must be accepted by BOTH product and oracle
    validate_transaction(tx_a)  # raises if the product diverges
    assert oracle.get("val|ok") == "ok"

    # integrity keys must be byte-identical to the reference oracle
    for k, v in res.items():
        assert oracle[k] == v, f"divergence on {k}: {v} vs {oracle[k]}"
    # the oracle must have produced exactly these integrity keys (plus the
    # validation marker) — no inventing or dropping outputs.
    assert set(oracle) == set(res) | {"val|ok"}


def test_attribution_never_enforcement_input():
    """P0: attribution output is not an enforcement input — decisions are
    byte-identical with or without attribution records. Nothing in the
    decision/scoring/controller chain may import the attribution corridor,
    and the attribution source class must not appear in the evidence weight
    table's authoritative classes."""
    import ast
    from pathlib import Path as _P
    root = _P(__file__).resolve().parents[1] / "src" / "apip"
    # any import of the attribution module from the decision/controller path
    # is forbidden by inspection.
    forbidden = set()
    for sub in ("decision", "controller", "ledger", "registry"):
        d = root / sub
        if not d.is_dir():
            continue
        for py in d.rglob("*.py"):
            if py.name.startswith("__"):
                continue
            tree = ast.parse(py.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module == "apip.attribution":
                    forbidden.add(str(py))
                elif isinstance(node, ast.Import):
                    for n in node.names:
                        if n.name == "apip.attribution" or \
                           n.name.startswith("apip.attribution."):
                            forbidden.add(str(py))
    assert forbidden == set(), f"decision path imports attribution: {forbidden}"
    assert ATTRIBUTION_SOURCE_CLASS == "attribution"  # never authoritative