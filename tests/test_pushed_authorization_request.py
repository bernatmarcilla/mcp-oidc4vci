import httpx
import pytest

from mcp_oidc4vci import pushed_authorization_request
from mcp_oidc4vci.pushed_authorization_request import (
    InvalidPushedAuthorizationRequestResponseError,
    PushedAuthorizationRequestRejectedError,
    push_authorization_request,
)
from support import mock_async_client

_ENDPOINT = "https://as.example.com/as/par"
_SUCCESS_BODY = '{"request_uri": "urn:ietf:params:oauth:request_uri:abc123", "expires_in": 60}'


async def test_returns_the_request_uri_and_expires_in_on_success() -> None:
    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 201, {}, _SUCCESS_BODY

    response = await push_authorization_request(_ENDPOINT, {"client_id": "abc"}, post=fake_post)

    assert response.request_uri == "urn:ietf:params:oauth:request_uri:abc123"
    assert response.expires_in == 60


async def test_sends_the_given_params_as_form_data() -> None:
    captured: dict[str, str] = {}

    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured.update(data)
        captured["__url__"] = url
        return 201, {}, _SUCCESS_BODY

    await push_authorization_request(
        _ENDPOINT, {"client_id": "abc", "response_type": "code"}, post=fake_post
    )

    assert captured == {"__url__": _ENDPOINT, "client_id": "abc", "response_type": "code"}


async def test_raises_rejected_for_an_oauth_error_response() -> None:
    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 400, {}, '{"error": "invalid_request", "error_description": "missing client_id"}'

    with pytest.raises(PushedAuthorizationRequestRejectedError) as excinfo:
        await push_authorization_request(_ENDPOINT, {}, post=fake_post)

    assert excinfo.value.error == "invalid_request"
    assert str(excinfo.value) == "missing client_id"


async def test_wraps_a_transport_failure() -> None:
    async def broken_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        raise ConnectionError("boom")

    with pytest.raises(InvalidPushedAuthorizationRequestResponseError, match="boom"):
        await push_authorization_request(_ENDPOINT, {}, post=broken_post)


async def test_rejects_a_response_that_is_not_valid_json() -> None:
    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 201, {}, "not-json"

    with pytest.raises(InvalidPushedAuthorizationRequestResponseError):
        await push_authorization_request(_ENDPOINT, {}, post=fake_post)


async def test_rejects_a_success_response_missing_required_fields() -> None:
    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 201, {}, "{}"

    with pytest.raises(InvalidPushedAuthorizationRequestResponseError):
        await push_authorization_request(_ENDPOINT, {}, post=fake_post)


async def test_rejects_an_error_response_missing_required_fields() -> None:
    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 400, {}, "{}"

    with pytest.raises(InvalidPushedAuthorizationRequestResponseError):
        await push_authorization_request(_ENDPOINT, {}, post=fake_post)


async def test_default_poster_performs_an_https_post(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(201, text=_SUCCESS_BODY)

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

    status_code, _headers, body = await pushed_authorization_request._post_par(
        _ENDPOINT, {"client_id": "abc"}, {}
    )

    assert status_code == 201
    assert "request_uri" in body
    assert captured_requests[0].method == "POST"
    assert captured_requests[0].read() == b"client_id=abc"
