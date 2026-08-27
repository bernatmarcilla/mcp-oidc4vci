import httpx
import pytest

from mcp_oidc4vci import authorization_server_metadata
from mcp_oidc4vci.authorization_server_metadata import (
    InvalidAuthorizationServerMetadataError,
    get_authorization_server_metadata,
)
from support import mock_async_client


def _metadata_json(issuer: str) -> str:
    return f'{{"issuer": "{issuer}", "token_endpoint": "{issuer}/token"}}'


async def test_requests_the_well_known_url_when_the_issuer_has_no_path() -> None:
    requested_urls: list[str] = []

    async def fake_fetch(url: str) -> str:
        requested_urls.append(url)
        return _metadata_json("https://as.example.com")

    await get_authorization_server_metadata("https://as.example.com", fetch=fake_fetch)

    assert requested_urls == ["https://as.example.com/.well-known/oauth-authorization-server"]


async def test_inserts_the_well_known_segment_before_an_existing_path_component() -> None:
    requested_urls: list[str] = []

    async def fake_fetch(url: str) -> str:
        requested_urls.append(url)
        return _metadata_json("https://as.example.com/tenant")

    await get_authorization_server_metadata("https://as.example.com/tenant", fetch=fake_fetch)

    assert requested_urls == [
        "https://as.example.com/.well-known/oauth-authorization-server/tenant"
    ]


@pytest.mark.parametrize(
    "issuer",
    [
        "http://as.example.com",
        "https://as.example.com?tenant=1",
        "https://as.example.com#fragment",
    ],
    ids=["not_https", "has_query", "has_fragment"],
)
async def test_rejects_a_malformed_issuer_identifier(issuer: str) -> None:
    async def fail_if_called(url: str) -> str:
        raise AssertionError("a malformed identifier must not trigger a fetch")

    with pytest.raises(InvalidAuthorizationServerMetadataError):
        await get_authorization_server_metadata(issuer, fetch=fail_if_called)


async def test_returns_the_parsed_metadata() -> None:
    async def fake_fetch(url: str) -> str:
        return _metadata_json("https://as.example.com")

    metadata = await get_authorization_server_metadata("https://as.example.com", fetch=fake_fetch)

    assert metadata.token_endpoint == "https://as.example.com/token"


async def test_rejects_a_metadata_document_whose_issuer_does_not_match() -> None:
    async def fake_fetch(url: str) -> str:
        return _metadata_json("https://impostor.example.com")

    with pytest.raises(InvalidAuthorizationServerMetadataError, match="does not match"):
        await get_authorization_server_metadata("https://as.example.com", fetch=fake_fetch)


async def test_rejects_a_payload_that_is_not_valid_json() -> None:
    async def fake_fetch(url: str) -> str:
        return "not-json"

    with pytest.raises(InvalidAuthorizationServerMetadataError):
        await get_authorization_server_metadata("https://as.example.com", fetch=fake_fetch)


async def test_rejects_a_payload_missing_required_fields() -> None:
    async def fake_fetch(url: str) -> str:
        return "{}"

    with pytest.raises(InvalidAuthorizationServerMetadataError):
        await get_authorization_server_metadata("https://as.example.com", fetch=fake_fetch)


async def test_wraps_a_fetch_failure_as_an_invalid_metadata_error() -> None:
    async def broken_fetch(url: str) -> str:
        raise ConnectionError("boom")

    with pytest.raises(InvalidAuthorizationServerMetadataError, match="boom"):
        await get_authorization_server_metadata("https://as.example.com", fetch=broken_fetch)


async def test_does_not_double_wrap_an_invalid_metadata_error_raised_by_the_fetcher() -> None:
    async def fetch_raising_domain_error(url: str) -> str:
        raise InvalidAuthorizationServerMetadataError("authorization server is unreachable")

    with pytest.raises(InvalidAuthorizationServerMetadataError) as excinfo:
        await get_authorization_server_metadata(
            "https://as.example.com", fetch=fetch_raising_domain_error
        )

    assert str(excinfo.value) == "authorization server is unreachable"


async def test_default_fetcher_performs_an_https_get(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(200, text=_metadata_json("https://as.example.com"))

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

    body = await authorization_server_metadata._fetch_metadata_url(
        "https://as.example.com/.well-known/oauth-authorization-server"
    )

    assert requested_urls == ["https://as.example.com/.well-known/oauth-authorization-server"]
    assert body == _metadata_json("https://as.example.com")


async def test_default_fetcher_raises_for_an_http_error_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        httpx, "AsyncClient", mock_async_client(lambda request: httpx.Response(404))
    )

    with pytest.raises(httpx.HTTPStatusError):
        await authorization_server_metadata._fetch_metadata_url(
            "https://as.example.com/.well-known/oauth-authorization-server"
        )
