"""OAuth 2.0 Token Request for the pre-authorized code grant (spec "Token Request")."""

import json
from collections.abc import Awaitable, Callable

import httpx
from pydantic import ValidationError

from mcp_oidc4vci.models import (
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
    TokenErrorResponse,
    TokenSuccessResponse,
)

TokenRequester = Callable[[str, dict[str, str]], Awaitable[tuple[int, str]]]

_HTTP_TIMEOUT_SECONDS = 10.0


class TokenRequestError(Exception):
    """Base error for problems performing a Token Request."""


class TokenRequestRejectedError(TokenRequestError):
    """The Authorization Server rejected the Token Request with a well-formed OAuth error."""

    def __init__(self, error: str, error_description: str | None) -> None:
        self.error = error
        self.error_description = error_description
        super().__init__(error_description or error)


class InvalidTokenResponseError(TokenRequestError):
    """The Authorization Server's response could not be understood."""


async def request_token_with_pre_authorized_code(
    token_endpoint: str,
    pre_authorized_code: str,
    *,
    tx_code: str | None = None,
    post: TokenRequester | None = None,
) -> TokenSuccessResponse:
    """Exchange a pre-authorized code for an access token (spec "Token Request").

    `post` sends the form-encoded request and returns (status_code, body); it defaults to an
    HTTPS POST and can be replaced with a fake in tests to avoid real network calls.
    """
    data = {
        "grant_type": PRE_AUTHORIZED_CODE_GRANT_TYPE,
        "pre-authorized_code": pre_authorized_code,
    }
    if tx_code is not None:
        data["tx_code"] = tx_code

    try:
        status_code, body = await (post or _post_token_request)(token_endpoint, data)
    except Exception as exc:
        raise InvalidTokenResponseError(
            f"Failed to reach token endpoint {token_endpoint!r}: {exc}"
        ) from exc

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise InvalidTokenResponseError(
            f"Token endpoint response is not valid JSON: {exc}"
        ) from exc

    if status_code == 200:
        try:
            return TokenSuccessResponse.model_validate(payload)
        except ValidationError as exc:
            raise InvalidTokenResponseError(
                f"Token endpoint success response does not match the expected structure: {exc}"
            ) from exc

    try:
        error = TokenErrorResponse.model_validate(payload)
    except ValidationError as exc:
        raise InvalidTokenResponseError(
            f"Token endpoint error response does not match the expected structure: {exc}"
        ) from exc
    raise TokenRequestRejectedError(error.error, error.error_description)


async def _post_token_request(url: str, data: dict[str, str]) -> tuple[int, str]:
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
        response = await client.post(url, data=data)
        return response.status_code, response.text
