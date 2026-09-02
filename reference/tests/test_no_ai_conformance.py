"""CI-enforced no-AI conformance (docs/28, WP-27).

These tests make the no-AI invariant machine-checked rather than asserted:
the security-bearing modules of the reference scaffold must (a) depend on
nothing outside a small deterministic standard-library allowlist, (b) import
no AI/ML package from a ban list, (c) contain no model-inference call shapes,
and (d) contain no nondeterministic `random` usage — and the whole suite
must pass with network access disabled.
"""
import ast
import re
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "apip"

# Security-bearing modules: every module that participates in scoring, gating,
# rung selection, artifact compilation, or attribution derivation must stay
# dependency-free.
SECURITY_BEARING = {
    "models", "registry", "scoring", "policy", "randomize",
    "config", "io", "exporters", "attribution",
}

# Deterministic standard-library allowlist for security-bearing modules.
# Anything outside this set (socket, http, subprocess, ctypes, ...) is a
# supply-chain escape and fails the build.
STDLIB_ALLOWLIST = {
    "__future__", "argparse", "dataclasses", "datetime", "hashlib",
    "ipaddress", "itertools", "json", "math", "pathlib", "re",
    "typing", "tomllib", "unittest",
}

# AI/ML package ban list (docs/28 conformance: no model SDK may be present).
AI_PACKAGE_BANLIST = {
    "openai", "anthropic", "cohere", "google.generativeai", "gemini",
    "transformers", "torch", "tensorflow", "keras", "sklearn", "scipy",
    "numpy", "pandas", "onnx", "onnxruntime", "xgboost", "lightgbm",
    "langchain", "llama_index", "llama_cpp", "huggingface_hub", "spacy",
    "nltk", "gensim", "sentence_transformers", "accelerate", "diffusers",
    "mlflow", "dspy", "guidance", "outlines", "vllm", "ollama",
}

# Call shapes that indicate model inference. None may appear in any module.
INFERENCE_CALL_SHAPES = (
    "complete", "chat", "chat_completions", "completions", "generate",
    "embed", "embeddings", "infer", "inference", "predict", "predict_proba",
    "transform", "encode_query", "invoke_model", "query_model", "run_model",
)


def _py_files():
    return sorted(SRC.rglob("*.py"))


def _module_name(path: Path) -> str:
    rel = path.relative_to(SRC)
    if rel.name == "__init__.py":
        return rel.parent.name
    return rel.stem


def _tree(path: Path):
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(tree):
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            out.add(node.module.split(".")[0])
    return out


class DependencyAllowlistTests(unittest.TestCase):
    """WP-27: dependency allowlist review, enforced per module."""

    def test_security_bearing_modules_are_dependency_free(self):
        for path in _py_files():
            mod = _module_name(path)
            if mod not in SECURITY_BEARING:
                continue
            for imp in _imports(_tree(path)):
                if imp == "apip":
                    continue
                self.assertIn(
                    imp, STDLIB_ALLOWLIST,
                    f"{path.relative_to(SRC.parent)} imports '{imp}' — "
                    f"outside the deterministic stdlib allowlist")

    def test_no_ai_package_imported_anywhere(self):
        for path in _py_files():
            for imp in _imports(_tree(path)):
                self.assertNotIn(
                    imp, AI_PACKAGE_BANLIST,
                    f"{path.relative_to(SRC.parent)} imports banned AI package '{imp}'")

    def test_declared_dependencies_are_empty(self):
        # pyproject must declare zero runtime dependencies.
        text = (SRC.parent.parent / "pyproject.toml").read_text(encoding="utf-8")
        self.assertNotIn("dependencies =", text)
        self.assertNotRegex(text, r"^dependencies\s*=", re.MULTILINE)


class InferenceCallShapeTests(unittest.TestCase):
    """WP-27: static check — no inference calls in scoring/policy paths."""

    def test_no_inference_call_shapes(self):
        for path in _py_files():
            tree = _tree(path)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = ""
                fn = node.func
                if isinstance(fn, ast.Attribute):
                    name = fn.attr
                elif isinstance(fn, ast.Name):
                    name = fn.id
                self.assertNotIn(
                    name, INFERENCE_CALL_SHAPES,
                    f"{path.relative_to(SRC.parent)}:{node.lineno} "
                    f"calls '{name}()' — inference call shape forbidden")


class DeterminismTests(unittest.TestCase):
    """docs/28: every draw flows through the recorded ApipRng abstraction."""

    def test_no_random_module_usage(self):
        for path in _py_files():
            imports = _imports(_tree(path))
            self.assertNotIn(
                "random", imports,
                f"{path.relative_to(SRC.parent)} imports 'random' — all "
                f"randomization must flow through apip.randomize.ApipRng")

    def test_apiprng_is_the_only_entropy_source(self):
        randomize = (SRC / "randomize.py").read_text(encoding="utf-8")
        self.assertIn("hashlib", randomize)          # SHA-256 DRBG
        self.assertNotIn("os.urandom", randomize)    # no OS entropy in draws
        self.assertNotIn("secrets", randomize)


class OfflineExecutionTest(unittest.TestCase):
    """WP-27: the decision path must work with no network. Sockets are
    blocked at the socket level for the duration of one full evaluation."""

    def test_evaluate_runs_with_sockets_disabled(self):
        import socket
        import json
        import tempfile

        from apip.config import load_policy
        from apip.io import load_indicators
        from apip.policy import evaluate

        examples = SRC.parent.parent.parent / "examples"
        policy = load_policy(examples / "policy.toml")
        indicators = load_indicators(examples / "indicators.json")

        class _Blocked(socket.socket):
            def __init__(self, *a, **k):
                raise OSError("network disabled by no-AI conformance test")

        real = socket.socket
        socket.socket = _Blocked
        try:
            for ind in indicators:
                d = evaluate(ind, policy, context={
                    "client": "conformance-host", "protocol_class": "interactive_http"})
                self.assertTrue(d.id.startswith("decision--"))
        finally:
            socket.socket = real


if __name__ == "__main__":
    unittest.main()
