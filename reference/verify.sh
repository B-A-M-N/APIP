#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# 1. Full unit suite (includes schema-conformance, audit regressions,
#    adversarial-audit residuals, policy/scoring/attribution/live tests).
PYTHONPATH=src python -m unittest discover -s tests -v
# 2. No-AI conformance gate (docs/28, WP-27) — machine-enforced, not asserted.
PYTHONPATH=src python -m unittest tests.test_no_ai_conformance -v

# 3. Regenerate artifacts and validate them against the shipped schemas.
rm -rf ../examples/generated
PYTHONPATH=src python -m apip.cli evaluate ../examples/indicators.json --policy ../examples/policy.toml --out ../examples/generated
python -m json.tool ../examples/generated/decisions.json >/dev/null
python -m json.tool ../examples/generated/receipts.json >/dev/null
# Schema conformance of the ACTUAL emitted artifacts (stdlib validator; the
# unit suite covers this too — repeated here so a failure names the step).
PYTHONPATH=src python -m unittest tests.test_schema_conformance -v

# 4. Optional cross-check with the reference jsonschema implementation when
#    available (never required — the scaffold stays dependency-free).
if python -c "import jsonschema" >/dev/null 2>&1; then
    python - "$PWD/.." <<'EOF'
import json, sys, pathlib
from jsonschema import Draft202012Validator
pkg = pathlib.Path(sys.argv[1])
for schema_name, artifact in (("decision.schema.json", "decisions.json"),
                              ("action_receipt.schema.json", "receipts.json")):
    schema = json.loads((pkg / "schemas" / schema_name).read_text())
    validator = Draft202012Validator(schema)
    instances = json.loads((pkg / "examples" / "generated" / artifact).read_text())
    for inst in instances:
        errors = list(validator.iter_errors(inst))
        assert not errors, f"{artifact}: {errors[0].message}"
print("jsonschema cross-check: PASS")
EOF
else
    echo "jsonschema not installed — skipping optional cross-check (stdlib validator already enforced)"
fi

echo "APIP reference verification passed (incl. no-AI conformance + schema conformance)"
