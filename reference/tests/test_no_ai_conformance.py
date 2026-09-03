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
# The strict dependency-free decision/compile path. Every module here must
# import nothing outside STDLIB_ALLOWLIST — this is the surface that turns
# evidence into decisions/rules/receipts and must be a deterministic, closed
# computation (audit P1-41: behavioral + sanitize were previously omitted).
STRICT_DEPENDENCY_FREE_PREFIXES = {
    "models", "registry", "scoring", "policy", "randomize", "config", "io",
    "sanitize", "behavioral", "exporters", "attribution",
}

# The loopback LIVE-CAPTURE challenge channel (apip/live/*). This is a test
# harness that MUST be deterministic and AI-free (covered by the global AI ban,
# inference-shape, and no-`random` tests) but legitimately uses http.server +
# sockets on loopback — it is a unit-testable channel, not an API (audit
# P1-31). It is therefore held to determinism/AI-freedom, not to the strict
# dependency-free allowlist.
LIVE_CAPTURE_PREFIXES = ("live", "live.adapters", "live.server")

# audit P1-41: keys on *relative package path* prefix rather than bare filename
# stems, because cli.py/uireport.py share the tree and several live/exporters
# modules share stems with top-level ones.
def _is_strict_dependency_free(rel_module: str) -> bool:
    return any(rel_module == p or rel_module.startswith(p + ".")
               for p in STRICT_DEPENDENCY_FREE_PREFIXES)

def _is_live_capture(rel_module: str) -> bool:
    return any(rel_module == p or rel_module.startswith(p + ".")
               for p in LIVE_CAPTURE_PREFIXES)

def _is_security_bearing(rel_module: str) -> bool:
    """Any module that participates in the decision/compile path or the live
    capture channel. (Both are security-relevant; they differ only in whether
    they may touch network stdlib.)"""
    return _is_strict_dependency_free(rel_module) or _is_live_capture(rel_module)

# Deterministic standard-library allowlist for security-bearing modules.
# Anything outside this set (socket, http, subprocess, ctypes, ...) is a
# supply-chain escape and fails the build. `os` is restricted to env/file
# access for the deployment key (v2.1.1); `hmac` provides keyed
# pseudonymization; both are deterministic, side-effect-free uses.
# v2.2: `threading` added — synchronization primitives (locks) only, for the
# thread-safe bounded writer / correlation store / capture counters; no
# timers, no I/O, no scheduling. Determinism is unaffected: locks order
# concurrent access but introduce no entropy into any decision path.
STDLIB_ALLOWLIST = {
    "__future__", "argparse", "dataclasses", "datetime", "hashlib", "hmac",
    "ipaddress", "itertools", "json", "math", "os", "pathlib", "re",
    "threading", "typing", "tomllib", "unittest",
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
    """Dotted package path of a module relative to the apip package, e.g.
    'models', 'exporters.suricata', 'live.server'. `__init__.py` maps to its
    enclosing package. Matches against SECURITY_BEARING_PREFIXES by prefix."""
    rel = path.relative_to(SRC)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        parts.pop()
    else:
        parts[-1] = parts[-1][:-3]   # strip ".py"
    return ".".join(parts) if parts else ""


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
        # Strictly the decision/compile path — NOT live capture, which
        # legitimately needs http.server for the loopback test channel.
        for path in _py_files():
            mod = _module_name(path)
            if not _is_strict_dependency_free(mod):
                continue
            for imp in _imports(_tree(path)):
                if imp == "apip":
                    continue
                self.assertIn(
                    imp, STDLIB_ALLOWLIST,
                    f"{path.relative_to(SRC.parent)} imports '{imp}' — "
                    f"outside the deterministic stdlib allowlist")

    def test_live_capture_is_loopback_only(self):
        # audit P1-41/P1-31: the live capture channel may use http.server/
        # sockets ONLY as the bounded loopback challenge origin — it must not
        # pull in arbitrary networking (urllib, xmlrpc, ftplib, smtplib, ...).
        bounded_net = {"http", "socketserver", "time"}
        for path in SRC.rglob("live/*.py"):
            if path.name == "__init__.py":
                continue
            for imp in _imports(_tree(path)):
                if imp == "apip":
                    continue
                if imp in bounded_net:
                    continue
                # everything else must be the deterministic allowlist + the
                # thread/io primitives the capture channel legitimately uses
                self.assertIn(
                    imp, STDLIB_ALLOWLIST | {"socket"},
                    f"{path.relative_to(SRC.parent)} imports '{imp}' — "
                    f"not a bounded loopback-capture primitive")

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


class SecurityBearingCoverageTests(unittest.TestCase):
    """audit P1-41: the no-AI dependency restriction must APPLY to every
    security-bearing package path. This test pins the coverage itself, so a
    future module that participates in scoring/gating/compilation/attribution
    but was left out of SECURITY_BEARING_PREFIXES fails loudly instead of
    silently escaping the dependency-free check."""

    def test_named_security_areas_are_in_scope(self):
        # The modules the audit explicitly called out as previously omitted.
        for dotted in ("behavioral", "sanitize", "exporters.rpz",
                       "exporters.suricata", "live", "live.adapters",
                       "live.server", "models", "scoring", "policy",
                       "randomize", "config", "io", "attribution", "registry"):
            self.assertTrue(
                _is_security_bearing(dotted),
                f"{dotted} is security-bearing but not matched by "
                f"SECURITY_BEARING_PREFIXES — the dependency-free invariant "
                f"would NOT apply to it (audit P1-41)")

    def test_every_existing_py_module_is_declared_in_or_out(self):
        # Every actual module must be either security-bearing or explicitly an
        # output/CLI helper (which the global AI ban + call-shape tests still
        # cover). This prevents an unrecognized path from slipping through.
        # The package-root __init__.py (empty dotted path) is only the version
        # marker and carries no decision/compile code, so it is exempt.
        explicitly_non_bearing = {"cli", "uireport"}
        for path in _py_files():
            dotted = _module_name(path)
            if dotted == "":      # package-root __init__.py (version marker)
                continue
            in_scope = _is_security_bearing(dotted)
            if in_scope:
                continue
            self.assertIn(
                dotted, explicitly_non_bearing,
                f"{path.relative_to(SRC.parent)} ({dotted!r}) is neither "
                f"security-bearing nor an explicit output/CLI helper — its "
                f"dependency freedom is not enforced by any allowlist test "
                f"(audit P1-41)")


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
