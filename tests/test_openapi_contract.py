"""The checked-in beta OpenAPI contract IS the product's contract (#44).

``api/openapi.beta.json`` is generated from the live FastAPI app by
``scripts/generate_openapi.py``. This test fails when the app's real route
surface or schemas drift from the checked-in contract, so an API change
without a contract update cannot merge. (``api/openapi.future.yaml`` is
deliberately NOT tested — it is the forward design artifact, explicitly not
implemented.)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

CONTRACT = (Path(__file__).resolve().parents[1] / "api"
            / "openapi.beta.json")


def _live_contract() -> dict:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from generate_openapi import build_contract
    return build_contract()


def test_checked_in_contract_matches_the_app():
    assert CONTRACT.is_file(), (
        "api/openapi.beta.json is missing — run "
        "scripts/generate_openapi.py after any API change")
    checked_in = json.loads(CONTRACT.read_text(encoding="utf-8"))
    live = _live_contract()
    assert checked_in["paths"] == live["paths"], (
        "route surface drifted from api/openapi.beta.json — regenerate via "
        "scripts/generate_openapi.py")
    assert checked_in["openapi"] == live["openapi"]
    assert checked_in["info"] == live["info"]
    assert checked_in["components"]["schemas"] == \
        live["components"]["schemas"]


def test_contract_declares_beta_not_future():
    doc = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert "beta" in doc["info"]["version"].lower() or \
        doc["info"]["version"].startswith("0.1"), doc["info"]
    # the future contract must never be mistaken for the live one
    assert doc["info"]["title"] == "APIP Operator API"


def test_future_contract_says_it_is_not_implemented():
    future = (Path(__file__).resolve().parents[1] / "api"
              / "openapi.future.yaml").read_text(encoding="utf-8")
    assert "NOT IMPLEMENTED" in future
