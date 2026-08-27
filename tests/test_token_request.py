import httpx
import pytest

from mcp_oidc4vci import token_request
from mcp_oidc4vci.token_request import (
    InvalidTokenResponseError,
    TokenRequestRejectedError,
    request_token_with_pre_authorized_code,
)
from support import mock_async_client


async def test_returns_the_access_token_on_success() -> None:
    async def fake_post(url: str, data: dict[str, str]) -> tuple[int, str]:
        return 200, '{"access_token": "abc123", "token_type": "Bearer", "expires_in": 86400}'

    token = await request_token_with_pre_authorized_code(
        "https://as.example.com/token", "SplxlOBeZQQYbYS6WxSbIA", post=fake_post
    )

    assert token.access_token == "abc123"
    assert token.expires_in == 86400


async def test_sends_the_expected_form_parameters() -> None:
    captured: dict[str, str] = {}

    async def fake_post(url: str, data: dict[str, str]) -> tuple[int, str]:
        captured.update(data)
        captured["__url__"] = url
        return 200, '{"access_token": "abc123", "token_type": "Bearer"}'

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

    async def fake_post(url: str, data: dict[str, str]) -> tuple[int, str]:
        captured.update(data)
        return 200, '{"access_token": "abc123", "token_type": "Bearer"}'

    await request_token_with_pre_authorized_code(
        "https://as.example.com/token", "SplxlOBeZQQYbYS6WxSbIA", post=fake_post
    )

    assert "tx_code" not in captured


async def test_raises_token_request_rejected_for_an_oauth_error_response() -> None:
    async def fake_post(url: str, data: dict[str, str]) -> tuple[int, str]:
        return 400, '{"error": "invalid_grant", "error_description": "code expired"}'

    with pytest.raises(TokenRequestRejectedError) as excinfo:
        await request_token_with_pre_authorized_code(
            "https://as.example.com/token", "expired-code", post=fake_post
        )

    assert excinfo.value.error == "invalid_grant"
    assert excinfo.value.error_description == "code expired"


async def test_wraps_a_transport_failure() -> None:
    async def broken_post(url: str, data: dict[str, str]) -> tuple[int, str]:
        raise ConnectionError("boom")

    with pytest.raises(InvalidTokenResponseError, match="boom"):
        await request_token_with_pre_authorized_code(
            "https://as.example.com/token", "code", post=broken_post
        )


async def test_rejects_a_response_that_is_not_valid_json() -> None:
    async def fake_post(url: str, data: dict[str, str]) -> tuple[int, str]:
        return 200, "not-json"

    with pytest.raises(InvalidTokenResponseError):
        await request_token_with_pre_authorized_code(
            "https://as.example.com/token", "code", post=fake_post
        )


async def test_rejects_a_success_response_missing_required_fields() -> None:
    async def fake_post(url: str, data: dict[str, str]) -> tuple[int, str]:
        return 200, "{}"

    with pytest.raises(InvalidTokenResponseError):
        await request_token_with_pre_authorized_code(
            "https://as.example.com/token", "code", post=fake_post
        )


async def test_rejects_an_error_response_missing_required_fields() -> None:
    async def fake_post(url: str, data: dict[str, str]) -> tuple[int, str]:
        return 400, "{}"

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

    status_code, body = await token_request._post_token_request(
        "https://as.example.com/token", {"grant_type": "x"}
    )

    assert status_code == 200
    assert "access_token" in body
    assert captured_requests[0].method == "POST"
    assert captured_requests[0].read() == b"grant_type=x"
