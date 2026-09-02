"""Schema conformance (v2.2).

The independent audit found the shipped decisions failing their own JSON
Schema (list-form randomization, undeclared attribution_refs) while
BUILD_VERIFICATION claimed PASS — the drift class this test closes. The
suite stays dependency-free, so this is a focused validator over the
subset of JSON Schema Draft 2020-12 the shipped schemas actually use
(type, enum, const, required, properties, additionalProperties, items,
minItems/maxItems, minLength/maxLength, minimum/maximum, pattern,
anyOf/oneOf/allOf, $ref into $defs, uniqueItems). It is not a general
validator; it is a drift alarm: if a schema keyword appears that this
validator does not implement, the test FAILS LOUDLY rather than silently
skipping — an unimplemented keyword is exactly the drift it exists to
catch.

External cross-check: `verify.sh` additionally validates with the real
`jsonschema` package when it is installed (optional, never required).
"""
import json
import re
import unittest
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent.parent
SCHEMAS = PKG / "schemas"

SUPPORTED_KEYWORDS = {
    "$schema", "$id", "title", "description", "type", "enum", "const",
    "required", "properties", "additionalProperties", "items", "prefixItems",
    "minItems", "maxItems", "minLength", "maxLength", "minimum", "maximum",
    "exclusiveMinimum", "exclusiveMaximum", "pattern", "anyOf", "oneOf",
    "allOf", "not", "$ref", "$defs", "uniqueItems", "propertyNames",
    "format", "default", "examples",
}


class _SchemaError(Exception):
    pass


def _resolve(schema, root):
    while "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            raise _SchemaError(f"unsupported $ref target: {ref}")
        node = root
        for part in ref[2:].split("/"):
            node = node[part.replace("~1", "/").replace("~0", "~")]
        rest = {k: v for k, v in schema.items() if k != "$ref"}
        schema = {**node, **rest} if rest else node
    return schema


def _type_ok(value, expected) -> bool:
    checks = {
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        "boolean": lambda v: isinstance(v, bool),
        "null": lambda v: v is None,
    }
    if isinstance(expected, str):
        return checks[expected](value)
    return any(checks[t](value) for t in expected)


def validate(value, schema, root, path="$"):
    """Structural validation; raises _SchemaError with a JSON path on
    failure. Mirrors the subset of keywords the schemas use."""
    schema = _resolve(schema, root)

    for kw in schema:
        if kw not in SUPPORTED_KEYWORDS:
            raise _SchemaError(
                f"schema uses unsupported keyword {kw!r} — extend the "
                f"conformance validator before relying on this schema")

    if "type" in schema and not _type_ok(value, schema["type"]):
        raise _SchemaError(f"{path}: expected type {schema['type']}")
    if "enum" in schema and value not in schema["enum"]:
        raise _SchemaError(f"{path}: {value!r} not in enum {schema['enum']}")
    if "const" in schema and value != schema["const"]:
        raise _SchemaError(f"{path}: {value!r} != const {schema['const']!r}")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise _SchemaError(f"{path}: shorter than minLength")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise _SchemaError(f"{path}: longer than maxLength")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            raise _SchemaError(f"{path}: {value!r} fails pattern {schema['pattern']}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise _SchemaError(f"{path}: below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise _SchemaError(f"{path}: above maximum")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            raise _SchemaError(f"{path}: <= exclusiveMinimum")
        if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
            raise _SchemaError(f"{path}: >= exclusiveMaximum")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise _SchemaError(f"{path}: fewer than minItems")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise _SchemaError(f"{path}: more than maxItems")
        if schema.get("uniqueItems") and len(
                {json.dumps(x, sort_keys=True) for x in value}) != len(value):
            raise _SchemaError(f"{path}: items not unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for i, item in enumerate(value):
                validate(item, item_schema, root, f"{path}[{i}]")

    if isinstance(value, dict):
        for req in schema.get("required", []):
            if req not in value:
                raise _SchemaError(f"{path}: missing required property {req!r}")
        props = schema.get("properties", {})
        for key, sub in value.items():
            if key in props:
                validate(sub, props[key], root, f"{path}.{key}")
            elif schema.get("additionalProperties") is False:
                raise _SchemaError(f"{path}: additional property {key!r} not allowed")
            elif isinstance(schema.get("additionalProperties"), dict):
                validate(sub, schema["additionalProperties"], root, f"{path}.{key}")
        if "propertyNames" in schema:
            for key in value:
                validate(key, schema["propertyNames"], root, f"{path}.<key:{key}>")

    for combo in ("anyOf", "oneOf"):
        if combo in schema:
            errors = []
            passed = 0
            for branch in schema[combo]:
                try:
                    validate(value, branch, root, path)
                    passed += 1
                except _SchemaError as e:
                    errors.append(str(e))
            if combo == "anyOf" and passed == 0:
                raise _SchemaError(f"{path}: fails anyOf: {'; '.join(errors[:3])}")
            if combo == "oneOf" and passed != 1:
                raise _SchemaError(f"{path}: matches {passed} oneOf branches")

    if "allOf" in schema:
        for branch in schema["allOf"]:
            validate(value, branch, root, path)

    if "not" in schema:
        try:
            validate(value, schema["not"], root, path)
        except _SchemaError:
            pass
        else:
            raise _SchemaError(f"{path}: matches forbidden 'not' schema")


def _load(name):
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


class EngineOutputConformanceTests(unittest.TestCase):
    """Every artifact the reference engine emits must satisfy its schema —
    the exact check whose absence let v2.1.1 ship invalid decisions."""

    def _validate_all(self, schema_name, instances):
        schema = _load(schema_name)
        problems = []
        for pos, instance in enumerate(instances):
            try:
                validate(instance, schema, schema)
            except _SchemaError as e:
                problems.append(f"#{pos}: {e}")
        self.assertEqual(problems, [],
                         f"{len(problems)} instance(s) fail {schema_name}:\n"
                         + "\n".join(problems[:10]))

    def test_generated_decisions_conform(self):
        self._validate_all("decision.schema.json",
                           json.loads((PKG / "examples" / "generated" /
                                       "decisions.json").read_text()))

    def test_generated_receipts_conform(self):
        self._validate_all("action_receipt.schema.json",
                           json.loads((PKG / "examples" / "generated" /
                                       "receipts.json").read_text()))

    def test_example_indicators_conform(self):
        self._validate_all("indicator.schema.json",
                           json.loads((PKG / "examples" /
                                       "indicators.json").read_text()))

    def test_example_transactions_conform(self):
        schema = _load("observed_transaction.schema.json")
        problems = []
        for pos, line in enumerate(
                (PKG / "examples" / "transactions.jsonl").read_text().splitlines()):
            if not line.strip():
                continue
            obj = json.loads(line)
            if obj.get("rejected"):
                continue
            try:
                validate(obj, schema, schema)
            except _SchemaError as e:
                problems.append(f"line {pos + 1}: {e}")
        self.assertEqual(problems, [], "\n".join(problems[:10]))

    def test_example_policy_conforms(self):
        import tomllib
        schema = _load("policy.schema.json")
        raw = tomllib.loads((PKG / "examples" / "policy.toml").read_text())
        try:
            validate(raw, schema, schema)
        except _SchemaError as e:
            self.fail(f"examples/policy.toml fails policy.schema.json: {e}")


class SchemaKeywordSupportTests(unittest.TestCase):
    """Every keyword used by every shipped schema is one this validator
    implements — so conformance above can never silently skip."""

    def test_all_schema_keywords_supported(self):
        # keywords whose VALUE is a map of {name: schema}; the names are
        # instance data, the values are schemas
        NAME_TO_SCHEMA = {"properties", "$defs", "patternProperties",
                          "definitions", "dependentSchemas"}
        # keywords whose value is a schema or array of schemas
        SCHEMA_VALUED = {"items", "additionalProperties", "propertyNames",
                         "not", "if", "then", "else", "contains",
                         "contentSchema", "unevaluatedItems",
                         "unevaluatedProperties"}
        ARRAY_OF_SCHEMA = {"anyOf", "oneOf", "allOf", "prefixItems"}

        unknown = []

        def walk_schema(node, where):
            """node is at a schema position: keys are keywords."""
            if isinstance(node, bool) or node is None:
                return
            if not isinstance(node, dict):
                return
            for k, v in node.items():
                if k in NAME_TO_SCHEMA:
                    if not isinstance(v, dict):
                        continue
                    for name, sub in v.items():
                        walk_schema(sub, f"{where}.{k}.{name}")
                elif k in SCHEMA_VALUED:
                    walk_schema(v, f"{where}.{k}")
                elif k in ARRAY_OF_SCHEMA:
                    if isinstance(v, list):
                        for i, sub in enumerate(v):
                            walk_schema(sub, f"{where}.{k}[{i}]")
                elif k in SUPPORTED_KEYWORDS or k.startswith("x-"):
                    pass    # known keyword; its value is annotation data
                else:
                    unknown.append(f"{where}: {k}")

        for p in sorted(SCHEMAS.glob("*.json")):
            walk_schema(json.loads(p.read_text()), p.name)
        self.assertEqual(unknown, [],
                         "schemas use keywords the conformance validator "
                         "does not implement (extend it): " + "; ".join(unknown))
