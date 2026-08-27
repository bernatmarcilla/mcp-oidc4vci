"""OIDC4VCI Nonce Endpoint client (spec "Nonce Endpoint")."""

import json
from collections.abc import Awaitable, Callable

import httpx
from pydantic import ValidationError

from mcp_oidc4vci.models import NonceResponse

NoncePoster = Callable[[str], Awaitable[tuple[int, str]]]

_HTTP_TIMEOUT_SECONDS = 10.0


class NonceRequestError(Exception):
    """Base error for problems requesting a fresh c_nonce."""


class InvalidNonceResponseError(NonceRequestError):
    """The Nonce Endpoint's response could not be understood."""


async def request_nonce(nonce_endpoint: str, *, post: NoncePoster | None = None) -> str:
    """Request a fresh c_nonce (spec "Nonce Request").

    The Nonce Endpoint is unprotected — no access token is sent. `post` defaults to an HTTPS
    POST and can be replaced with a fake in tests to avoid real network calls.
    """
    try:
        status_code, body = await (post or _post_nonce_request)(nonce_endpoint)
    except Exception as exc:
        raise InvalidNonceResponseError(
            f"Failed to reach nonce endpoint {nonce_endpoint!r}: {exc}"
        ) from exc

    if not 200 <= status_code < 300:
        raise InvalidNonceResponseError(f"Nonce endpoint returned HTTP {status_code}.")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise InvalidNonceResponseError(
            f"Nonce endpoint response is not valid JSON: {exc}"
        ) from exc
    try:
        return NonceResponse.model_validate(payload).c_nonce
    except ValidationError as exc:
        raise InvalidNonceResponseError(
            f"Nonce endpoint response does not match the expected structure: {exc}"
        ) from exc


async def _post_nonce_request(url: str) -> tuple[int, str]:
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
        response = await client.post(url)
        return response.status_code, response.text
