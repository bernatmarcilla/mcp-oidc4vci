"""RFC 9126 Pushed Authorization Requests (PAR).

When the Authorization Server advertises a `pushed_authorization_request_endpoint`, the
Authorization Request's parameters are POSTed there first; the returned `request_uri`
replaces them in the (much shorter) URL a human actually opens, and the Authorization Server
gets to validate everything before any browser redirect happens.
"""

import json
import logging
from collections.abc import Awaitable, Callable

import httpx
from pydantic import ValidationError

from mcp_oidc4vci.models import (
    PushedAuthorizationRequestErrorResponse,
    PushedAuthorizationRequestResponse,
)

logger = logging.getLogger(__name__)

# (url, form_data, extra_headers) -> (status_code, response_headers, body), matching the
# TokenRequester/CredentialRequester shape used elsewhere.
PushedAuthorizationRequester = Callable[
    [str, dict[str, str], dict[str, str]], Awaitable[tuple[int, dict[str, str], str]]
]

_HTTP_TIMEOUT_SECONDS = 10.0


class PushedAuthorizationRequestError(Exception):
    """Base error for problems performing a Pushed Authorization Request."""


class PushedAuthorizationRequestRejectedError(PushedAuthorizationRequestError):
    """The Authorization Server rejected the Pushed Authorization Request with a well-formed
    OAuth error."""

    def __init__(self, error: str, error_description: str | None) -> None:
        self.error = error
        self.error_description = error_description
        super().__init__(error_description or error)


class InvalidPushedAuthorizationRequestResponseError(PushedAuthorizationRequestError):
    """The Authorization Server's response could not be understood."""


async def push_authorization_request(
    pushed_authorization_request_endpoint: str,
    params: dict[str, str],
    *,
    post: PushedAuthorizationRequester | None = None,
) -> PushedAuthorizationRequestResponse:
    """Push the Authorization Request's parameters (RFC 9126 §3) and return the resulting
    `request_uri`/`expires_in`.

    `post` sends the form-encoded request and returns (status_code, response_headers, body);
    it defaults to an HTTPS POST and can be replaced with a fake in tests.
    """
    poster = post or _post_par

    try:
        status_code, _response_headers, body = await poster(
            pushed_authorization_request_endpoint, params, {}
        )
    except Exception as exc:
        raise InvalidPushedAuthorizationRequestResponseError(
            f"Failed to reach pushed authorization request endpoint "
            f"{pushed_authorization_request_endpoint!r}: {exc}"
        ) from exc

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise InvalidPushedAuthorizationRequestResponseError(
            f"Pushed authorization request response is not valid JSON: {exc}"
        ) from exc

    if 200 <= status_code < 300:
        try:
            return PushedAuthorizationRequestResponse.model_validate(payload)
        except ValidationError as exc:
            raise InvalidPushedAuthorizationRequestResponseError(
                "Pushed authorization request success response does not match the expected "
                f"structure: {exc}"
            ) from exc

    try:
        error = PushedAuthorizationRequestErrorResponse.model_validate(payload)
    except ValidationError as exc:
        raise InvalidPushedAuthorizationRequestResponseError(
            f"Pushed authorization request endpoint returned HTTP {status_code} with a body "
            f"that does not match the expected error structure: {exc}"
        ) from exc
    logger.warning(
        "Pushed Authorization Request to %r rejected: %s",
        pushed_authorization_request_endpoint,
        error.error,
    )
    raise PushedAuthorizationRequestRejectedError(error.error, error.error_description)


async def _post_par(
    url: str, data: dict[str, str], headers: dict[str, str]
) -> tuple[int, dict[str, str], str]:
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
        response = await client.post(url, data=data, headers=headers)
        return (
            response.status_code,
            {k.lower(): v for k, v in response.headers.items()},
            response.text,
        )
