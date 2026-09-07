#!/usr/bin/env python3
"""Generate the beta OpenAPI contract from the real FastAPI app (#44).

``api/openapi.future.yaml`` stays what it says — a forward design artifact
NOT implemented by this repo (its own header says so; it was renamed from
``openapi.yaml`` because a file named "openapi" that no server implements
misleads integrators).

``api/openapi.beta.json`` IS the product's actual contract, generated here
from the live app. ``tests/test_openapi_contract.py`` fails when the
checked-in file drifts from the app, so a route change without a contract
update cannot land.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

OUT = REPO / "api" / "openapi.beta.json"


def build_contract() -> dict:
    import tempfile
    from dataclasses import replace

    from fastapi.testclient import TestClient

    from apip.api.app import build_app
    from apip.config.service import AdapterConfig, load_config

    # A throwaway zone dir: build_app constructs a real controller, and the
    # RPZ adapter validates its artifact directories at construction (#37).
    with tempfile.TemporaryDirectory(prefix="apip_oas_") as tmp:
        cfg = replace(
            load_config(None),
            adapter=replace(AdapterConfig(rpz_mode="SHADOW",
                                          zone_dir=str(Path(tmp) / "rpz")),
                            authorized_domains=("operator.test",)),
            operator_token="apipt_contract-gen",
        )
        app = build_app(cfg, controller=None)
    return app.openapi()


def main() -> int:
    doc = build_contract()
    OUT.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n",
                   encoding="utf-8")
    routes = sorted({f"{m.upper()} {p}"
                     for p, ops in doc["paths"].items() for m in ops})
    print(f"wrote {OUT} ({len(routes)} routes):")
    for r in routes:
        print(f"  {r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
