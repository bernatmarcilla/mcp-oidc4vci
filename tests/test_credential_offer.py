from collections.abc import Callable
from urllib.parse import quote

import httpx
import pytest

from mcp_oidc4vci import credential_offer
from mcp_oidc4vci.credential_offer import InvalidCredentialOfferError, resolve_credential_offer

BY_VALUE_OFFER_JSON = (
    '{"credential_issuer": "https://issuer.example.com", '
    '"credential_configuration_ids": ["UniversityDegreeCredential"]}'
)


def _offer_uri(payload: str) -> str:
    return f"openid-credential-offer://?credential_offer={quote(payload, safe='')}"


async def test_resolves_a_by_value_offer_without_fetching() -> None:
    async def fail_if_called(url: str) -> str:
        raise AssertionError("by-value offers must not trigger a fetch")

    offer = await resolve_credential_offer(_offer_uri(BY_VALUE_OFFER_JSON), fetch=fail_if_called)

    assert offer.credential_issuer == "https://issuer.example.com"
    assert offer.credential_configuration_ids == ["UniversityDegreeCredential"]
    assert offer.grants is None


async def test_resolves_a_by_reference_offer_via_the_injected_fetcher() -> None:
    uri = "openid-credential-offer://?credential_offer_uri=" + quote(
        "https://issuer.example.com/offers/1", safe=""
    )
    requested_urls: list[str] = []

    async def fake_fetch(url: str) -> str:
        requested_urls.append(url)
        return BY_VALUE_OFFER_JSON

    offer = await resolve_credential_offer(uri, fetch=fake_fetch)

    assert requested_urls == ["https://issuer.example.com/offers/1"]
    assert offer.credential_issuer == "https://issuer.example.com"


async def test_parses_the_pre_authorized_code_grant_with_its_tx_code() -> None:
    payload = (
        '{"credential_issuer": "https://issuer.example.com", '
        '"credential_configuration_ids": ["UniversityDegreeCredential"], '
        '"grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": '
        '{"pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5", '
        '"tx_code": {"input_mode": "numeric", "length": 4}}}}'
    )

    offer = await resolve_credential_offer(_offer_uri(payload))

    assert offer.grants is not None
    grant = offer.grants.pre_authorized_code
    assert grant is not None
    assert grant.pre_authorized_code == "oaKazRN8I0IbtZ0C7JuMn5"
    assert grant.tx_code is not None
    assert grant.tx_code.length == 4


async def test_parses_the_authorization_code_grant() -> None:
    payload = (
        '{"credential_issuer": "https://issuer.example.com", '
        '"credential_configuration_ids": ["UniversityDegreeCredential"], '
        '"grants": {"authorization_code": {"issuer_state": "abc"}}}'
    )

    offer = await resolve_credential_offer(_offer_uri(payload))

    assert offer.grants is not None
    assert offer.grants.authorization_code is not None
    assert offer.grants.authorization_code.issuer_state == "abc"


@pytest.mark.parametrize(
    "uri",
    [
        "openid-credential-offer://",
        _offer_uri("{}") + "&credential_offer_uri=https://issuer.example.com/offers/1",
    ],
    ids=["neither_parameter_present", "both_parameters_present"],
)
async def test_rejects_a_uri_without_exactly_one_offer_parameter(uri: str) -> None:
    with pytest.raises(InvalidCredentialOfferError):
        await resolve_credential_offer(uri)


async def test_rejects_a_payload_that_is_not_valid_json() -> None:
    uri = "openid-credential-offer://?credential_offer=not-json"

    with pytest.raises(InvalidCredentialOfferError):
        await resolve_credential_offer(uri)


async def test_rejects_a_payload_missing_required_fields() -> None:
    with pytest.raises(InvalidCredentialOfferError):
        await resolve_credential_offer(_offer_uri("{}"))


async def test_wraps_a_fetch_failure_as_an_invalid_offer_error() -> None:
    uri = "openid-credential-offer://?credential_offer_uri=" + quote(
        "https://issuer.example.com/offers/1", safe=""
    )

    async def broken_fetch(url: str) -> str:
        raise ConnectionError("boom")

    with pytest.raises(InvalidCredentialOfferError, match="boom"):
        await resolve_credential_offer(uri, fetch=broken_fetch)


async def test_does_not_double_wrap_an_invalid_offer_error_raised_by_the_fetcher() -> None:
    uri = "openid-credential-offer://?credential_offer_uri=" + quote(
        "https://issuer.example.com/offers/1", safe=""
    )

    async def fetch_raising_domain_error(url: str) -> str:
        raise InvalidCredentialOfferError("the referenced offer has expired")

    with pytest.raises(InvalidCredentialOfferError) as excinfo:
        await resolve_credential_offer(uri, fetch=fetch_raising_domain_error)

    assert str(excinfo.value) == "the referenced offer has expired"


def _mock_async_client(
    handler: Callable[[httpx.Request], httpx.Response],
) -> Callable[..., httpx.AsyncClient]:
    """Patch target for `httpx.AsyncClient` that routes requests through a MockTransport."""
    original_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return original_async_client(*args, **kwargs)  # type: ignore[arg-type]

    return factory


async def test_default_fetcher_performs_an_https_get(monkeypatch: pytest.MonkeyPatch) -> None:
    requested_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(200, text=BY_VALUE_OFFER_JSON)

    monkeypatch.setattr(httpx, "AsyncClient", _mock_async_client(handler))

    body = await credential_offer._fetch_offer_uri("https://issuer.example.com/offers/1")

    assert requested_urls == ["https://issuer.example.com/offers/1"]
    assert body == BY_VALUE_OFFER_JSON


async def test_default_fetcher_raises_for_an_http_error_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        httpx, "AsyncClient", _mock_async_client(lambda request: httpx.Response(404))
    )

    with pytest.raises(httpx.HTTPStatusError):
        await credential_offer._fetch_offer_uri("https://issuer.example.com/offers/1")
