"""Subprocess oracle client for differential testing.

The production package (``src/apip``, distribution ``apip-beta``) and the
reference oracle (``reference/src``, distribution ``apip-reference``) are
NEVER imported into one process — both install a top-level ``apip`` package.
The oracle runs as a subprocess with PYTHONPATH pointing at reference/src,
receives a normalized case on stdin, and returns its decision as JSON.

The oracle NEVER gains production imports and the product NEVER gains oracle
imports; the JSON contract in between is the compatibility surface.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REFERENCE_SRC = REPO_ROOT / "reference" / "src"

_ORACLE_DRIVER = r'''
import json, sys, tempfile, os
sys.path.insert(0, "reference/src")
from apip.config import load_policy
from apip.policy import evaluate
from apip.registry import SourceRegistry, SourceProfile
from apip.models import Evidence, Indicator

case = json.load(sys.stdin)

profiles = tuple(SourceProfile(
    source_id=p["source_id"], source_class=p["source_class"],
    independent=p["independent"],
    auto_enforcement_allowed=p.get("auto_enforcement_allowed", True),
    upstream=p.get("upstream"),
) for p in case["registry"])
registry = SourceRegistry(profiles)

# The oracle pins its clock via replay.reference_now in the policy text and
# loads from a file (its loader contract).
with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
    f.write(case["policy_text"])
    policy_path = f.name
try:
    policy = load_policy(policy_path)
finally:
    os.unlink(policy_path)
# Bind the loaded policy to the case registry (server-side authority).
object.__setattr__(policy, "source_registry", registry)

evidence = tuple(Evidence(
    kind=e["kind"], source_id=e["source_id"], source_class="unassigned",
    observed_at=e["observed_at"], independent=False, detail=e.get("detail", {}),
) for e in case["evidence"])
indicator = Indicator(
    id=case["id"], type=case["type"], value=case["value"],
    sources=tuple(case.get("sources", [])), evidence=evidence,
    tags=tuple(case.get("tags", [])))

ctx = case.get("context") or {}
d = evaluate(indicator, policy, ctx)
sel = d.selector.to_dict() if d.selector is not None else None
rand = d.randomization
if isinstance(rand, list):
    rand = list(rand)
out = {
    "id": d.id, "indicator_id": d.indicator_id,
    "maliciousness": d.maliciousness, "action_safety": d.action_safety,
    "disposition": d.disposition, "action": d.action, "rung": d.rung,
    "scope": d.scope, "ttl_seconds": d.ttl_seconds,
    "policy_version": d.policy_version, "reason_codes": list(d.reason_codes),
    "explanation": d.explanation, "selector": sel, "randomization": rand,
    "content_hash": getattr(d, "content_hash", ""),
    "nominal_ttl_seconds": getattr(d, "nominal_ttl_seconds", 0),
}
json.dump(out, sys.stdout)
'''


def oracle_decide(case: dict) -> dict:
    """Run one normalized case through the reference oracle; return its
    decision as a JSON-compatible dict."""
    proc = subprocess.run(
        [sys.executable, "-c", _ORACLE_DRIVER],
        input=json.dumps(case).encode(),
        capture_output=True, timeout=60, cwd=str(REPO_ROOT))
    if proc.returncode != 0:
        raise RuntimeError(
            f"oracle failed: {proc.stderr.decode(errors='replace')[:2000]}")
    return json.loads(proc.stdout)


def normalize_case(*, policy_text: str, registry: list[dict], ind_id: str,
                   itype: str, value: str, evidence: list[dict],
                   sources: list[str] | None = None, tags: list[str] | None = None,
                   context: dict | None = None) -> dict:
    """Build the shared JSON case shape both engines consume."""
    return {
        "policy_text": policy_text,
        "registry": registry,
        "id": ind_id, "type": itype, "value": value,
        "evidence": evidence,
        "sources": sources or [],
        "tags": tags or [],
        "context": context or {},
    }


# --- requester-attribution oracle (docs/30) ---------------------------------

_ATTRIBUTION_ORACLE_DRIVER = r'''
import json, sys
sys.path.insert(0, "reference/src")
from apip.attribution import (
    probe_order, fingerprint, similarity, handle_for, extract_features,
    CorrelationStore, validate_transaction, reset_key_cache)
# The oracle and product both run in the dev-key context for differential
# pinning: handles keyed on the same public dev key are byte-comparable.
reset_key_cache()
script = json.load(sys.stdin)
out = {}
for step in script:
    op = step["op"]
    if op == "probe_order":
        out[f"po|{step['session']}|{step['epoch']}"] = \
            list(probe_order(step["session"], step["epoch"]))
    elif op == "fingerprint":
        out[f"fp|{'|'.join(step['features'])}"] = \
            fingerprint({k: v for k, v in (p.split("=", 1) for p in step["features"])})
    elif op == "handle":
        out[f"rh|{step['client']}"] = handle_for(step["client"])
    elif op == "validate":
        try:
            validate_transaction(step["tx"])
            out[f"val|ok"] = "ok"
        except Exception as e:
            out[f"val|err"] = str(e)
    elif op == "report":
        store = CorrelationStore(max_requesters=step.get("max_requesters", 10000))
        for tx in step["transactions"]:
            store.observe(tx)
        if step.get("prune"):
            store.prune_expired(step["prune"]["now"], step["prune"]["ttl"])
        out[f"report|{step['tag']}"] = store.report(min_similarity=3)
json.dump(out, sys.stdout)
'''


def oracle_attribution(script: list[dict]) -> dict:
    """Run an attribution script through the reference oracle (docs/30).

    This isolates the oracle in a subprocess (the product and reference both
    install a top-level ``apip`` package), matching the differential
    discipline used elsewhere. Only integrity-relevant outputs are compared:
    probe order, fingerprint, handles (under the shared dev key), extract,
    and the correlation report.
    """
    proc = subprocess.run(
        [sys.executable, "-c", _ATTRIBUTION_ORACLE_DRIVER],
        input=json.dumps(script).encode(),
        capture_output=True, timeout=60, cwd=str(REPO_ROOT))
    if proc.returncode != 0:
        raise RuntimeError(
            f"attribution oracle failed: {proc.stderr.decode(errors='replace')[:2000]}")
    return json.loads(proc.stdout)


# --- terminator-log adapter oracle (docs/30, WP-30) --------------------------

_ADAPTER_ORACLE_DRIVER = r'''
import json, sys
sys.path.insert(0, "reference/src")
from apip.live.adapters import recognize, _safe_client, _norm_ts
script = json.load(sys.stdin)
out = {}
for step in script:
    if step["op"] == "recognize":
        try:
            out[f"rec|{step['tag']}"] = recognize(step["line"])
        except Exception as e:
            out[f"rec|{step['tag']}"] = {"__err__": type(e).__name__}
    elif step["op"] == "safe_client":
        out[f"sc|{step['ref']}"] = _safe_client(step["ref"])
    elif step["op"] == "norm_ts":
        out[f"ts|{step['ts']}"] = _norm_ts(step["ts"])
json.dump(out, sys.stdout)
'''


def oracle_adapters(script: list[dict]) -> dict:
    """Run terminator-log adapter cases through the reference oracle."""

    proc = subprocess.run(
        [sys.executable, "-c", _ADAPTER_ORACLE_DRIVER],
        input=json.dumps(script).encode(),
        capture_output=True, timeout=60, cwd=str(REPO_ROOT))
    if proc.returncode != 0:
        raise RuntimeError(
            f"adapter oracle failed: {proc.stderr.decode(errors='replace')[:2000]}")
    return json.loads(proc.stdout)
