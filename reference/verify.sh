#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PYTHONPATH=src python -m unittest discover -s tests -v
# No-AI conformance gate (docs/28, WP-27) — machine-enforced, not asserted.
PYTHONPATH=src python -m unittest tests.test_no_ai_conformance -v
rm -rf ../examples/generated
PYTHONPATH=src python -m apip.cli evaluate ../examples/indicators.json --policy ../examples/policy.toml --out ../examples/generated
python -m json.tool ../examples/generated/decisions.json >/dev/null
python -m json.tool ../examples/generated/receipts.json >/dev/null
echo "APIP reference verification passed (incl. no-AI conformance)"
