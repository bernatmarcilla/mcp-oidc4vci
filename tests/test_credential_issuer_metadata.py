import httpx
import pytest

from mcp_oidc4vci import credential_issuer_metadata
from mcp_oidc4vci.credential_issuer_metadata import (
    InvalidCredentialIssuerMetadataError,
    get_credential_issuer_metadata,
)
from support import mock_async_client


def _metadata_json(issuer: str) -> str:
    return (
        f'{{"credential_issuer": "{issuer}", '
        f'"credential_endpoint": "{issuer}/credential", '
        '"credential_configurations_supported": '
        '{"UniversityDegreeCredential": {"format": "vc+sd-jwt"}}}'
    )


async def test_requests_the_well_known_url_when_the_issuer_has_no_path() -> None:
    requested_urls: list[str] = []

    async def fake_fetch(url: str) -> str:
        requested_urls.append(url)
        return _metadata_json("https://issuer.example.com")

    await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)

    assert requested_urls == ["https://issuer.example.com/.well-known/openid-credential-issuer"]


async def test_inserts_the_well_known_segment_before_an_existing_path_component() -> None:
    requested_urls: list[str] = []

    async def fake_fetch(url: str) -> str:
        requested_urls.append(url)
        return _metadata_json("https://issuer.example.com/tenant")

    await get_credential_issuer_metadata("https://issuer.example.com/tenant", fetch=fake_fetch)

    assert requested_urls == [
        "https://issuer.example.com/.well-known/openid-credential-issuer/tenant"
    ]


@pytest.mark.parametrize(
    "credential_issuer",
    [
        "http://issuer.example.com",
        "https://issuer.example.com?tenant=1",
        "https://issuer.example.com#fragment",
    ],
    ids=["not_https", "has_query", "has_fragment"],
)
async def test_rejects_a_malformed_credential_issuer_identifier(credential_issuer: str) -> None:
    async def fail_if_called(url: str) -> str:
        raise AssertionError("a malformed identifier must not trigger a fetch")

    with pytest.raises(InvalidCredentialIssuerMetadataError):
        await get_credential_issuer_metadata(credential_issuer, fetch=fail_if_called)


async def test_returns_the_parsed_metadata() -> None:
    async def fake_fetch(url: str) -> str:
        return _metadata_json("https://issuer.example.com")

    metadata = await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)

    assert metadata.credential_endpoint == "https://issuer.example.com/credential"
    config = metadata.credential_configurations_supported["UniversityDegreeCredential"]
    assert config.format == "vc+sd-jwt"


async def test_parses_the_nested_credential_metadata_display_name() -> None:
    payload = (
        '{"credential_issuer": "https://issuer.example.com", '
        '"credential_endpoint": "https://issuer.example.com/credential", '
        '"credential_configurations_supported": {"UniversityDegreeCredential": {'
        '"format": "vc+sd-jwt", '
        '"credential_metadata": {"display": [{"name": "University Degree", "locale": "en-US"}]}'
        "}}}"
    )

    async def fake_fetch(url: str) -> str:
        return payload

    metadata = await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)

    config = metadata.credential_configurations_supported["UniversityDegreeCredential"]
    assert config.credential_metadata is not None
    assert config.credential_metadata.display is not None
    assert config.credential_metadata.display[0].name == "University Degree"


async def test_rejects_a_metadata_document_whose_credential_issuer_does_not_match() -> None:
    async def fake_fetch(url: str) -> str:
        return _metadata_json("https://impostor.example.com")

    with pytest.raises(InvalidCredentialIssuerMetadataError, match="does not match"):
        await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)


async def test_rejects_a_payload_that_is_not_valid_json() -> None:
    async def fake_fetch(url: str) -> str:
        return "not-json"

    with pytest.raises(InvalidCredentialIssuerMetadataError):
        await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)


async def test_rejects_a_payload_missing_required_fields() -> None:
    async def fake_fetch(url: str) -> str:
        return "{}"

    with pytest.raises(InvalidCredentialIssuerMetadataError):
        await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)


async def test_wraps_a_fetch_failure_as_an_invalid_metadata_error() -> None:
    async def broken_fetch(url: str) -> str:
        raise ConnectionError("boom")

    with pytest.raises(InvalidCredentialIssuerMetadataError, match="boom"):
        await get_credential_issuer_metadata("https://issuer.example.com", fetch=broken_fetch)


async def test_does_not_double_wrap_an_invalid_metadata_error_raised_by_the_fetcher() -> None:
    async def fetch_raising_domain_error(url: str) -> str:
        raise InvalidCredentialIssuerMetadataError("issuer is temporarily unavailable")

    with pytest.raises(InvalidCredentialIssuerMetadataError) as excinfo:
        await get_credential_issuer_metadata(
            "https://issuer.example.com", fetch=fetch_raising_domain_error
        )

    assert str(excinfo.value) == "issuer is temporarily unavailable"


async def test_default_fetcher_performs_an_https_get(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(200, text=_metadata_json("https://issuer.example.com"))

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

    body = await credential_issuer_metadata._fetch_metadata_url(
        "https://issuer.example.com/.well-known/openid-credential-issuer"
    )

    assert requested_urls == ["https://issuer.example.com/.well-known/openid-credential-issuer"]
    assert body == _metadata_json("https://issuer.example.com")


async def test_default_fetcher_raises_for_an_http_error_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        httpx, "AsyncClient", mock_async_client(lambda request: httpx.Response(404))
    )

    with pytest.raises(httpx.HTTPStatusError):
        await credential_issuer_metadata._fetch_metadata_url(
            "https://issuer.example.com/.well-known/x"
        )
