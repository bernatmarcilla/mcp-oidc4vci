import httpx
import pytest

from mcp_oidc4vci import nonce
from mcp_oidc4vci.nonce import InvalidNonceResponseError, request_nonce
from support import mock_async_client


async def test_returns_the_c_nonce_on_success() -> None:
    async def fake_post(url: str) -> tuple[int, str]:
        return 200, '{"c_nonce": "wKI4LT17ac15ES9bw8ac4"}'

    result = await request_nonce("https://issuer.example.com/nonce", post=fake_post)

    assert result == "wKI4LT17ac15ES9bw8ac4"


async def test_requests_the_given_nonce_endpoint() -> None:
    requested_urls: list[str] = []

    async def fake_post(url: str) -> tuple[int, str]:
        requested_urls.append(url)
        return 200, '{"c_nonce": "abc"}'

    await request_nonce("https://issuer.example.com/nonce", post=fake_post)

    assert requested_urls == ["https://issuer.example.com/nonce"]


async def test_raises_for_a_non_2xx_status() -> None:
    async def fake_post(url: str) -> tuple[int, str]:
        return 500, "internal error"

    with pytest.raises(InvalidNonceResponseError, match="500"):
        await request_nonce("https://issuer.example.com/nonce", post=fake_post)


async def test_rejects_a_response_that_is_not_valid_json() -> None:
    async def fake_post(url: str) -> tuple[int, str]:
        return 200, "not-json"

    with pytest.raises(InvalidNonceResponseError):
        await request_nonce("https://issuer.example.com/nonce", post=fake_post)


async def test_rejects_a_response_missing_c_nonce() -> None:
    async def fake_post(url: str) -> tuple[int, str]:
        return 200, "{}"

    with pytest.raises(InvalidNonceResponseError):
        await request_nonce("https://issuer.example.com/nonce", post=fake_post)


async def test_wraps_a_transport_failure() -> None:
    async def broken_post(url: str) -> tuple[int, str]:
        raise ConnectionError("boom")

    with pytest.raises(InvalidNonceResponseError, match="boom"):
        await request_nonce("https://issuer.example.com/nonce", post=broken_post)


async def test_default_poster_performs_an_https_post(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json={"c_nonce": "abc"})

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

    status_code, body = await nonce._post_nonce_request("https://issuer.example.com/nonce")

    assert status_code == 200
    assert "abc" in body
    assert captured_requests[0].method == "POST"
