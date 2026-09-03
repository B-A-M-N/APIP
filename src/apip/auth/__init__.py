"""Authentication primitives: source API keys and the operator token.

Design (docs/09):
  - source credentials are RANDOM 32-byte values shown once at registration,
    stored only as salted PBKDF2/SHA-256 hashes (+ an optional deployment
    pepper from APIP_SECRET_KEY);
  - the ingest channel authenticates the SOURCE, and source identity is
    DERIVED from the credential — a request body can never name a different
    trusted source (reference audit P0-2, carried into the product);
  - the operator token authenticates control-plane mutations; comparison is
    constant-time;
  - nothing here ever touches the decision path: credentials gate INGEST and
    OPERATIONS, never scoring.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

_PBKDF2_ITERATIONS = 240_000


def generate_source_key() -> str:
    """New source API key: ``apipk_<43 base62 chars>`` (32 bytes entropy).
    Returned in clear exactly once at registration."""
    return "apipk_" + secrets.token_urlsafe(32)


def generate_operator_token() -> str:
    return "apipt_" + secrets.token_urlsafe(32)


def hash_credential(secret: str, pepper: str | None = None) -> str:
    """PBKDF2-SHA256, salt embedded, ``pbkdf2$iters$salt$hash`` encoding."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", (pepper or "").encode() + secret.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_credential(secret: str, stored: str, pepper: str | None = None) -> bool:
    """Constant-time credential check; False on any malformed stored value."""
    try:
        scheme, iters, salt_hex, hash_hex = stored.split("$")
        if scheme != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", (pepper or "").encode() + secret.encode(),
            bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def constant_time_equals(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())
