"""Shared HTTP POST helper for requests authenticated with an issuance session's existing
access token.

Used by anywhere a session's access token is presented again after the original Token
Request: the Credential Endpoint, the Deferred Credential Endpoint (both in
`credential_request.py`), and the Notification Endpoint (`notification.py`).
"""

import logging
from collections.abc import Awaitable, Callable

from mcp_oidc4vci.issuance import IssuanceSession

logger = logging.getLogger(__name__)

# (url, json_body, headers) -> (status_code, response_headers, body). Response header keys
# are lowercased, matching HTTP's case-insensitive header names.
SessionPoster = Callable[
    [str, dict[str, object], dict[str, str]], Awaitable[tuple[int, dict[str, str], str]]
]

_DPOP_NONCE_ERROR = 'error="use_dpop_nonce"'


class AuthenticatedRequestError(Exception):
    """The HTTP request could not be completed, or kept being challenged for a fresh
    DPoP nonce."""


async def post_with_session_auth(
    poster: SessionPoster,
    url: str,
    body: dict[str, object],
    session: IssuanceSession,
) -> tuple[int, str]:
    """POST to `url`, attaching Authorization (Bearer or DPoP, per whether the session's
    access token ended up DPoP-bound -- RFC 9449 §7.1) and, for a DPoP-bound token, a DPoP
    proof over this request. Retries once with a server-supplied nonce if the endpoint
    demands one (RFC 9449 §8).
    """
    assert session.access_token is not None
    scheme = "DPoP" if session.dpop_bound else "Bearer"
    dpop_nonce: str | None = None

    for attempt in range(2):
        headers = {"Authorization": f"{scheme} {session.access_token}"}
        if session.dpop_bound:
            assert session.dpop_key is not None
            headers["DPoP"] = session.dpop_key.create_proof(
                http_method="POST",
                http_uri=url,
                nonce=dpop_nonce,
                access_token=session.access_token,
            )

        try:
            status_code, response_headers, response_body = await poster(url, body, headers)
        except Exception as exc:
            raise AuthenticatedRequestError(f"Failed to reach {url!r}: {exc}") from exc

        needs_retry = (
            status_code == 401
            and session.dpop_bound
            and attempt == 0
            and _DPOP_NONCE_ERROR in (response_headers.get("www-authenticate") or "")
        )
        new_nonce = response_headers.get("dpop-nonce")
        if needs_retry and new_nonce:
            logger.info("%r demanded a DPoP nonce; retrying with the supplied nonce.", url)
            dpop_nonce = new_nonce
            continue
        return status_code, response_body

    raise AuthenticatedRequestError(f"{url!r} kept demanding a new DPoP nonce.")
