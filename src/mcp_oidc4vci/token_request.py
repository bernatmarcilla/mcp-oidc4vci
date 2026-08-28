"""OAuth 2.0 Token Request for the pre-authorized code grant (spec "Token Request")."""

import json
import logging
from collections.abc import Awaitable, Callable

import httpx
from pydantic import ValidationError

from mcp_oidc4vci.dpop import DPoPKey
from mcp_oidc4vci.models import (
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
    TokenErrorResponse,
    TokenSuccessResponse,
)

logger = logging.getLogger(__name__)

# (url, form_data, extra_headers) -> (status_code, response_headers, body). Response header
# keys are lowercased, matching HTTP's case-insensitive header names.
TokenRequester = Callable[
    [str, dict[str, str], dict[str, str]], Awaitable[tuple[int, dict[str, str], str]]
]

_HTTP_TIMEOUT_SECONDS = 10.0
_DPOP_NONCE_ERROR = "use_dpop_nonce"


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
    dpop_key: DPoPKey | None = None,
    post: TokenRequester | None = None,
) -> TokenSuccessResponse:
    """Exchange a pre-authorized code for an access token (spec "Token Request").

    When `dpop_key` is given, attaches a DPoP proof (RFC 9449 §5) to the request and retries
    once with a server-supplied nonce if the Authorization Server demands one (§8) — the
    response's `token_type` tells the caller whether the issued token ended up DPoP-bound.

    `post` sends the form-encoded request and returns (status_code, response_headers, body);
    it defaults to an HTTPS POST and can be replaced with a fake in tests.
    """
    data = {
        "grant_type": PRE_AUTHORIZED_CODE_GRANT_TYPE,
        "pre-authorized_code": pre_authorized_code,
    }
    if tx_code is not None:
        data["tx_code"] = tx_code
    poster = post or _post_token_request

    dpop_nonce: str | None = None
    for attempt in range(2):
        headers = {}
        if dpop_key is not None:
            headers["DPoP"] = dpop_key.create_proof(
                http_method="POST", http_uri=token_endpoint, nonce=dpop_nonce
            )

        try:
            status_code, response_headers, body = await poster(token_endpoint, data, headers)
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

        new_nonce = response_headers.get("dpop-nonce")
        if error.error == _DPOP_NONCE_ERROR and dpop_key is not None and attempt == 0 and new_nonce:
            logger.info(
                "Token endpoint %r demanded a DPoP nonce; retrying with the supplied nonce.",
                token_endpoint,
            )
            dpop_nonce = new_nonce
            continue
        logger.warning("Token Request to %r rejected: %s", token_endpoint, error.error)
        raise TokenRequestRejectedError(error.error, error.error_description)

    raise InvalidTokenResponseError("Token endpoint kept demanding a new DPoP nonce.")


async def _post_token_request(
    url: str, data: dict[str, str], headers: dict[str, str]
) -> tuple[int, dict[str, str], str]:
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
        response = await client.post(url, data=data, headers=headers)
        return (
            response.status_code,
            {k.lower(): v for k, v in response.headers.items()},
            response.text,
        )
