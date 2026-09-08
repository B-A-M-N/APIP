"""Authentication primitives: source API keys and the operator token.

Design (docs/09):
  - source credentials are RANDOM 32-byte values shown once at registration,
    stored only as salted PBKDF2/SHA-256 hashes (+ the deployment pepper
    from APIP_SECRET_KEY — review P0 #15);
  - the key's PUBLIC identifier travels inside the token
    (``apipk_<key_id>.<secret>``) so channel lookup is ONE indexed row + ONE
    PBKDF2 verification, never a scan of every source (review P0 #14);
  - the ingest channel authenticates the SOURCE, and source identity is
    DERIVED from the credential — a request body can never name a different
    trusted source (reference audit P0-2, carried into the product);
  - the operator token authenticates control-plane mutations; comparison is
    constant-time;
  - nothing here ever touches the decision path: credentials gate INGEST and
    OPERATIONS, never scoring.

Credential-hash scheme versions (review P0 #15): ``pbkdf2$...`` is the
UNPEPPERED prerelease scheme (accepted for verification only, so rolling
regeneration works); ``pbkdf2p$...`` is peppered with the deployment secret
and is what registration writes. A deployment without APIP_SECRET_KEY set
fails registration closed — an unpeppered hash would make a leaked
``sources`` table alone sufficient for channel forgery.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

_PBKDF2_ITERATIONS = 240_000
KEY_PREFIX = "apipk_"


class CredentialError(ValueError):
    pass


def generate_source_key() -> tuple[str, str]:
    """New source API key: ``(token, key_id)`` where token is
    ``apipk_<key_id>.<secret>`` (32-byte secret entropy). The token is
    returned in clear exactly once at registration; key_id is the public
    lookup identifier stored alongside the hash."""
    key_id = secrets.token_hex(8)          # 16 hex chars, public
    secret = secrets.token_urlsafe(32)     # 32 bytes entropy
    return f"{KEY_PREFIX}{key_id}.{secret}", key_id


def parse_source_key(token: str) -> tuple[str, str] | None:
    """Split a presented token into ``(key_id, secret)``; None when it is
    not in the ``apipk_<key_id>.<secret>`` form (default-deny)."""
    if not token.startswith(KEY_PREFIX):
        return None
    body = token[len(KEY_PREFIX):]
    key_id, sep, secret = body.partition(".")
    if not sep or not key_id or not secret:
        return None
    if not all(c in "0123456789abcdef" for c in key_id):
        return None
    return key_id, secret


def generate_operator_token() -> str:
    return "apipt_" + secrets.token_urlsafe(32)


def _pbkdf2(secret: str, pepper: str | None, salt: bytes, iters: int) -> bytes:
    # pepper is PREPENDED so the derived key binds to the deployment secret
    material = (pepper or "").encode() + secret.encode()
    return hashlib.pbkdf2_hmac("sha256", material, salt, iters)


def hash_credential(secret: str, pepper: str | None = None) -> str:
    """PBKDF2-SHA256, salt embedded. Peppered scheme ``pbkdf2p$`` when a
    pepper is supplied (the deployment default via APIP_SECRET_KEY);
    ``pbkdf2$`` (legacy, unpeppered) only when explicitly called without
    one — the API layer refuses that path at registration."""
    scheme = "pbkdf2p" if pepper else "pbkdf2"
    salt = secrets.token_bytes(16)
    dk = _pbkdf2(secret, pepper, salt, _PBKDF2_ITERATIONS)
    return f"{scheme}${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_credential(secret: str, stored: str,
                      pepper: str | None = None) -> bool:
    """Constant-time credential check; False on any malformed stored value.
    A legacy ``pbkdf2$`` hash verifies only UNPEPPERED (legacy hashes were
    made without the pepper); ``pbkdf2p$`` verifies WITH the configured
    pepper. Constant-time comparison throughout."""
    try:
        scheme, iters, salt_hex, hash_hex = stored.split("$")
        if scheme not in ("pbkdf2", "pbkdf2p"):
            return False
        use_pepper = pepper if scheme == "pbkdf2p" else None
        dk = _pbkdf2(secret, use_pepper, bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def constant_time_equals(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())
