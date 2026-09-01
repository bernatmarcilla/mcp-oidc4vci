import base64
import datetime
from collections.abc import Mapping

import httpx
import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509.oid import NameOID

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


def _self_signed_certificate(private_key: EllipticCurvePrivateKey) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issuer.example.com")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


def _signed_metadata(
    issuer: str,
    *,
    claims: Mapping[str, object] | None = None,
    header: Mapping[str, object] | None = None,
    private_key: EllipticCurvePrivateKey | None = None,
) -> str:
    """Build a signed Credential Issuer Metadata JWT (spec "Signed Metadata", §12.2.3),
    signed with a fresh self-signed EC keypair unless told to sign with a different one."""
    signing_key = private_key or ec.generate_private_key(ec.SECP256R1())
    x5c = base64.b64encode(_self_signed_certificate(signing_key)).decode()
    default_claims = {
        "sub": issuer,
        "iat": 1_700_000_000,
        "credential_issuer": issuer,
        "credential_endpoint": f"{issuer}/credential",
        "credential_configurations_supported": {
            "UniversityDegreeCredential": {"format": "vc+sd-jwt"}
        },
    }
    default_header = {"typ": "openidvci-issuer-metadata+jwt", "x5c": [x5c]}
    return jwt.encode(
        {**default_claims, **(claims or {})},
        signing_key,
        algorithm="ES256",
        headers={**default_header, **(header or {})},
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
    requested_accept_headers: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        requested_accept_headers.append(request.headers.get("accept"))
        return httpx.Response(200, text=_metadata_json("https://issuer.example.com"))

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

    body = await credential_issuer_metadata._fetch_metadata_url(
        "https://issuer.example.com/.well-known/openid-credential-issuer"
    )

    assert requested_urls == ["https://issuer.example.com/.well-known/openid-credential-issuer"]
    assert body == _metadata_json("https://issuer.example.com")
    # spec "Credential Issuer Metadata Retrieval" (§12.2.2): the Wallet is RECOMMENDED to
    # signal, via Accept, whether it supports signed metadata -- this implementation accepts
    # either representation.
    assert requested_accept_headers == ["application/json, application/jwt"]


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


async def test_accepts_valid_signed_metadata() -> None:
    async def fake_fetch(url: str) -> str:
        return _signed_metadata("https://issuer.example.com")

    metadata = await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)

    assert metadata.credential_issuer == "https://issuer.example.com"
    assert metadata.credential_endpoint == "https://issuer.example.com/credential"


async def test_rejects_signed_metadata_with_the_wrong_typ_header() -> None:
    async def fake_fetch(url: str) -> str:
        return _signed_metadata("https://issuer.example.com", header={"typ": "JWT"})

    with pytest.raises(InvalidCredentialIssuerMetadataError, match="typ"):
        await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)


@pytest.mark.parametrize("alg", ["none", "HS256"])
async def test_rejects_signed_metadata_using_a_disallowed_algorithm(alg: str) -> None:
    signing_key = ec.generate_private_key(ec.SECP256R1())
    x5c = base64.b64encode(_self_signed_certificate(signing_key)).decode()
    # jwt.encode refuses to sign with "none"/HS* using an EC key, so the disallowed-algorithm
    # check has to be exercised via a hand-built unverified header instead.
    token = _signed_metadata("https://issuer.example.com", private_key=signing_key)
    _header_b64, payload_b64, signature_b64 = token.split(".")
    tampered_header = base64.urlsafe_b64encode(
        f'{{"typ": "openidvci-issuer-metadata+jwt", "alg": "{alg}", "x5c": ["{x5c}"]}}'.encode()
    ).rstrip(b"=")

    async def fake_fetch(url: str) -> str:
        return f"{tampered_header.decode()}.{payload_b64}.{signature_b64}"

    with pytest.raises(InvalidCredentialIssuerMetadataError, match="disallowed algorithm"):
        await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)


async def test_rejects_signed_metadata_with_a_malformed_x5c_certificate() -> None:
    async def fake_fetch(url: str) -> str:
        return _signed_metadata(
            "https://issuer.example.com", header={"x5c": [base64.b64encode(b"not-a-cert").decode()]}
        )

    with pytest.raises(InvalidCredentialIssuerMetadataError, match="x5c leaf certificate"):
        await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)


async def test_rejects_signed_metadata_without_an_x5c_header() -> None:
    async def fake_fetch(url: str) -> str:
        return _signed_metadata("https://issuer.example.com", header={"x5c": None})

    with pytest.raises(InvalidCredentialIssuerMetadataError, match="x5c"):
        await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)


async def test_rejects_signed_metadata_signed_by_a_different_key_than_its_x5c_certificate() -> (
    None
):
    signing_key = ec.generate_private_key(ec.SECP256R1())
    other_key = ec.generate_private_key(ec.SECP256R1())
    x5c = base64.b64encode(_self_signed_certificate(other_key)).decode()
    token = jwt.encode(
        {
            "sub": "https://issuer.example.com",
            "iat": 1_700_000_000,
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {},
        },
        signing_key,
        algorithm="ES256",
        headers={"typ": "openidvci-issuer-metadata+jwt", "x5c": [x5c]},
    )

    async def fake_fetch(url: str) -> str:
        return token

    with pytest.raises(InvalidCredentialIssuerMetadataError, match="verification"):
        await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)


async def test_rejects_signed_metadata_whose_sub_does_not_match_the_requested_issuer() -> None:
    async def fake_fetch(url: str) -> str:
        return _signed_metadata("https://impostor.example.com")

    with pytest.raises(InvalidCredentialIssuerMetadataError, match="verification"):
        await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)


async def test_rejects_signed_metadata_missing_the_sub_claim() -> None:
    signing_key = ec.generate_private_key(ec.SECP256R1())
    x5c = base64.b64encode(_self_signed_certificate(signing_key)).decode()
    token = jwt.encode(
        {
            "iat": 1_700_000_000,
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {},
        },
        signing_key,
        algorithm="ES256",
        headers={"typ": "openidvci-issuer-metadata+jwt", "x5c": [x5c]},
    )

    async def fake_fetch(url: str) -> str:
        return token

    with pytest.raises(InvalidCredentialIssuerMetadataError, match="verification"):
        await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)


async def test_rejects_expired_signed_metadata() -> None:
    async def fake_fetch(url: str) -> str:
        return _signed_metadata("https://issuer.example.com", claims={"exp": 1})

    with pytest.raises(InvalidCredentialIssuerMetadataError, match="verification"):
        await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)


async def test_rejects_signed_metadata_that_is_not_a_valid_jwt() -> None:
    async def fake_fetch(url: str) -> str:
        return "not.a.jwt"

    with pytest.raises(InvalidCredentialIssuerMetadataError):
        await get_credential_issuer_metadata("https://issuer.example.com", fetch=fake_fetch)
