"""PKCE (RFC 7636) code verifier / challenge generation for the authorization code grant.

The verifier never leaves this server — it's presented in the Token Request (§4.5) to prove
the party redeeming the authorization code is the same one that started the Authorization
Request, without any secret ever appearing in a browser-visible URL.
"""

import base64
import hashlib
import secrets

CODE_CHALLENGE_METHOD = "S256"

_VERIFIER_ENTROPY_BYTES = 64  # -> 86 base64url chars, within RFC 7636's 43-128 char range.


def generate_code_verifier() -> str:
    """A high-entropy, URL-safe code verifier (RFC 7636 §4.1)."""
    return _base64url(secrets.token_bytes(_VERIFIER_ENTROPY_BYTES))


def code_challenge(verifier: str) -> str:
    """The S256 code_challenge for a verifier (RFC 7636 §4.2): BASE64URL(SHA256(verifier))."""
    return _base64url(hashlib.sha256(verifier.encode("ascii")).digest())


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
