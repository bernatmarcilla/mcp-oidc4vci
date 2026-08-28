import httpx
import jwt
import pytest

from mcp_oidc4vci import token_request
from mcp_oidc4vci.dpop import DPoPKey
from mcp_oidc4vci.token_request import (
    InvalidTokenResponseError,
    TokenRequestRejectedError,
    request_token_with_pre_authorized_code,
)
from support import mock_async_client

_SUCCESS_BODY = '{"access_token": "abc123", "token_type": "Bearer"}'


async def test_returns_the_access_token_on_success() -> None:
    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return (
            200,
            {},
            '{"access_token": "abc123", "token_type": "Bearer", "expires_in": 86400}',
        )

    token = await request_token_with_pre_authorized_code(
        "https://as.example.com/token", "SplxlOBeZQQYbYS6WxSbIA", post=fake_post
    )

    assert token.access_token == "abc123"
    assert token.expires_in == 86400


async def test_sends_the_expected_form_parameters() -> None:
    captured: dict[str, str] = {}

    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured.update(data)
        captured["__url__"] = url
        return 200, {}, _SUCCESS_BODY

    await request_token_with_pre_authorized_code(
        "https://as.example.com/token", "SplxlOBeZQQYbYS6WxSbIA", tx_code="493536", post=fake_post
    )

    assert captured == {
        "__url__": "https://as.example.com/token",
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": "SplxlOBeZQQYbYS6WxSbIA",
        "tx_code": "493536",
    }


async def test_omits_tx_code_when_not_provided() -> None:
    captured: dict[str, str] = {}

    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured.update(data)
        return 200, {}, _SUCCESS_BODY

    await request_token_with_pre_authorized_code(
        "https://as.example.com/token", "SplxlOBeZQQYbYS6WxSbIA", post=fake_post
    )

    assert "tx_code" not in captured


async def test_raises_token_request_rejected_for_an_oauth_error_response() -> None:
    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 400, {}, '{"error": "invalid_grant", "error_description": "code expired"}'

    with pytest.raises(TokenRequestRejectedError) as excinfo:
        await request_token_with_pre_authorized_code(
            "https://as.example.com/token", "expired-code", post=fake_post
        )

    assert excinfo.value.error == "invalid_grant"
    assert excinfo.value.error_description == "code expired"


async def test_wraps_a_transport_failure() -> None:
    async def broken_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        raise ConnectionError("boom")

    with pytest.raises(InvalidTokenResponseError, match="boom"):
        await request_token_with_pre_authorized_code(
            "https://as.example.com/token", "code", post=broken_post
        )


async def test_rejects_a_response_that_is_not_valid_json() -> None:
    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 200, {}, "not-json"

    with pytest.raises(InvalidTokenResponseError):
        await request_token_with_pre_authorized_code(
            "https://as.example.com/token", "code", post=fake_post
        )


async def test_rejects_a_success_response_missing_required_fields() -> None:
    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 200, {}, "{}"

    with pytest.raises(InvalidTokenResponseError):
        await request_token_with_pre_authorized_code(
            "https://as.example.com/token", "code", post=fake_post
        )


async def test_rejects_an_error_response_missing_required_fields() -> None:
    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 400, {}, "{}"

    with pytest.raises(InvalidTokenResponseError):
        await request_token_with_pre_authorized_code(
            "https://as.example.com/token", "code", post=fake_post
        )


async def test_default_poster_performs_an_https_post(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json={"access_token": "abc123", "token_type": "Bearer"})

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

    status_code, _headers, body = await token_request._post_token_request(
        "https://as.example.com/token", {"grant_type": "x"}, {}
    )

    assert status_code == 200
    assert "access_token" in body
    assert captured_requests[0].method == "POST"
    assert captured_requests[0].read() == b"grant_type=x"


# -- DPoP (RFC 9449) ----------------------------------------------------------


async def test_omits_the_dpop_header_when_no_dpop_key_is_given() -> None:
    captured_headers: dict[str, str] = {}

    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured_headers.update(headers)
        return 200, {}, _SUCCESS_BODY

    await request_token_with_pre_authorized_code(
        "https://as.example.com/token", "code", post=fake_post
    )

    assert "DPoP" not in captured_headers


async def test_attaches_a_dpop_proof_over_the_token_endpoint_when_a_key_is_given() -> None:
    captured_headers: dict[str, str] = {}

    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured_headers.update(headers)
        return 200, {}, _SUCCESS_BODY

    await request_token_with_pre_authorized_code(
        "https://as.example.com/token", "code", dpop_key=DPoPKey(), post=fake_post
    )

    proof = captured_headers["DPoP"]
    header = jwt.get_unverified_header(proof)
    claims = jwt.decode(proof, options={"verify_signature": False})
    assert header["typ"] == "dpop+jwt"
    assert claims["htm"] == "POST"
    assert claims["htu"] == "https://as.example.com/token"
    assert "ath" not in claims  # no access token exists yet at this point


async def test_retries_once_with_the_servers_nonce_after_a_use_dpop_nonce_error() -> None:
    seen_nonces: list[str | None] = []

    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        claims = jwt.decode(headers["DPoP"], options={"verify_signature": False})
        seen_nonces.append(claims.get("nonce"))
        if len(seen_nonces) == 1:
            return (
                400,
                {"dpop-nonce": "server-nonce"},
                '{"error": "use_dpop_nonce", "error_description": "nonce required"}',
            )
        return 200, {}, _SUCCESS_BODY

    token = await request_token_with_pre_authorized_code(
        "https://as.example.com/token", "code", dpop_key=DPoPKey(), post=fake_post
    )

    assert token.access_token == "abc123"
    assert seen_nonces == [None, "server-nonce"]


async def test_gives_up_after_a_second_use_dpop_nonce_error() -> None:
    async def always_wants_a_new_nonce(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return (
            400,
            {"dpop-nonce": "another-nonce"},
            '{"error": "use_dpop_nonce", "error_description": "nonce required"}',
        )

    with pytest.raises(TokenRequestRejectedError, match="nonce required"):
        await request_token_with_pre_authorized_code(
            "https://as.example.com/token",
            "code",
            dpop_key=DPoPKey(),
            post=always_wants_a_new_nonce,
        )


async def test_does_not_retry_a_use_dpop_nonce_error_without_a_dpop_key() -> None:
    call_count = 0

    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        nonlocal call_count
        call_count += 1
        return (
            400,
            {"dpop-nonce": "server-nonce"},
            '{"error": "use_dpop_nonce", "error_description": "nonce required"}',
        )

    with pytest.raises(TokenRequestRejectedError):
        await request_token_with_pre_authorized_code(
            "https://as.example.com/token", "code", post=fake_post
        )

    assert call_count == 1
