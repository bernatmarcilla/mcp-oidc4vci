"""Retrieval of OIDC4VCI Credential Issuer Metadata (spec "Credential Issuer Metadata")."""

import base64
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

import httpx
import jwt
from cryptography import x509
from pydantic import ValidationError

from mcp_oidc4vci.models import CredentialIssuerMetadata

logger = logging.getLogger(__name__)

MetadataFetcher = Callable[[str], Awaitable[str]]

_HTTP_TIMEOUT_SECONDS = 10.0
_WELL_KNOWN_SEGMENT = "/.well-known/openid-credential-issuer"

# spec "Signed Metadata" (§12.2.3): the required JOSE header `typ` for signed metadata.
_SIGNED_METADATA_TYPE = "openidvci-issuer-metadata+jwt"
# Algorithms the spec forbids for signed metadata: none, and any symmetric (MAC) algorithm.
_DISALLOWED_SIGNED_METADATA_ALGS = {"none", "HS256", "HS384", "HS512"}


class CredentialIssuerMetadataError(Exception):
    """Base error for problems retrieving Credential Issuer Metadata."""


class InvalidCredentialIssuerMetadataError(CredentialIssuerMetadataError):
    """The Credential Issuer identifier, or the metadata document it resolves to, is invalid."""


async def get_credential_issuer_metadata(
    credential_issuer: str, *, fetch: MetadataFetcher | None = None
) -> CredentialIssuerMetadata:
    """Fetch and validate a Credential Issuer's metadata from its well-known endpoint.

    `fetch` retrieves the raw response body and defaults to an HTTPS GET; tests can inject a
    fake to avoid real network calls. The body may be plain JSON or signed metadata (spec
    "Signed Metadata", §12.2.3) -- see `_parse_metadata_payload`.
    """
    url = _well_known_metadata_url(credential_issuer)
    payload = await _fetch_metadata(url, fetch or _fetch_metadata_url)
    metadata = _parse_metadata_payload(payload, credential_issuer)
    _verify_issuer_identity(metadata, credential_issuer)
    return metadata


def _well_known_metadata_url(credential_issuer: str) -> str:
    """Insert the well-known segment between the host and path components (spec: Credential
    Issuer Metadata Retrieval), e.g. https://issuer.example.com/tenant becomes
    https://issuer.example.com/.well-known/openid-credential-issuer/tenant.
    """
    parts = urlsplit(credential_issuer)
    if parts.scheme != "https" or parts.query or parts.fragment:
        raise InvalidCredentialIssuerMetadataError(
            "credential_issuer must be an https URL with no query or fragment: "
            f"{credential_issuer!r}"
        )
    return urlunsplit(
        SplitResult(parts.scheme, parts.netloc, _WELL_KNOWN_SEGMENT + parts.path, "", "")
    )


def _parse_metadata_payload(payload: str, credential_issuer: str) -> CredentialIssuerMetadata:
    stripped = payload.strip()
    data = (
        _parse_signed_metadata(stripped, credential_issuer)
        if _looks_like_jwt(stripped)
        else _parse_json(stripped)
    )
    try:
        return CredentialIssuerMetadata.model_validate(data)
    except ValidationError as exc:
        raise InvalidCredentialIssuerMetadataError(
            f"Credential Issuer Metadata does not match the expected structure: {exc}"
        ) from exc


def _looks_like_jwt(payload: str) -> bool:
    # A compact JWS is three dot-separated base64url segments; JSON never starts with
    # anything but whitespace, '{', or '[', and a JSON object/array body doesn't contain
    # exactly two top-level dots. Sniffing the body (rather than trusting the response's
    # Content-Type) matches how this project already treats real issuers' HTTP behavior as
    # unreliable (see docs/ROADMAP.md Phase 8).
    return not payload.startswith("{") and payload.count(".") == 2


def _parse_json(payload: str) -> Any:
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise InvalidCredentialIssuerMetadataError(
            f"Credential Issuer Metadata is not valid JSON: {exc}"
        ) from exc


def _parse_signed_metadata(token: str, credential_issuer: str) -> Any:
    """Verify and decode signed Credential Issuer Metadata (spec "Signed Metadata", §12.2.3).

    Verifies the JWS signature using the public key conveyed by the JOSE header's `x5c`
    certificate chain (its leaf certificate) -- the only key-conveyance mechanism this
    implementation supports, of the three the spec allows (`x5c`, `kid`, `trust_chain`); a
    token using one of the others is rejected rather than silently trusted. This proves the
    response has not been altered since signing. It does NOT establish that the signer is who
    they claim to be -- no certificate chain-of-trust validation is performed, a deliberate
    scope decision (see docs/ARCHITECTURE.md).
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.exceptions.DecodeError as exc:
        raise InvalidCredentialIssuerMetadataError(
            f"Signed Credential Issuer Metadata is not a valid JWT: {exc}"
        ) from exc

    if header.get("typ") != _SIGNED_METADATA_TYPE:
        raise InvalidCredentialIssuerMetadataError(
            f"Signed Credential Issuer Metadata has typ {header.get('typ')!r}, expected "
            f"{_SIGNED_METADATA_TYPE!r}."
        )
    alg = header.get("alg")
    if not alg or alg in _DISALLOWED_SIGNED_METADATA_ALGS:
        raise InvalidCredentialIssuerMetadataError(
            f"Signed Credential Issuer Metadata uses a disallowed algorithm {alg!r} (must "
            "not be 'none' or a symmetric/MAC algorithm)."
        )
    x5c = header.get("x5c")
    if not x5c:
        raise InvalidCredentialIssuerMetadataError(
            "Signed Credential Issuer Metadata has no 'x5c' in its JOSE header; this "
            "implementation only supports x5c for conveying the signer's public key."
        )
    try:
        leaf_certificate = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))
        public_key = leaf_certificate.public_key()
    except (ValueError, TypeError) as exc:
        raise InvalidCredentialIssuerMetadataError(
            f"Signed Credential Issuer Metadata's x5c leaf certificate is invalid: {exc}"
        ) from exc

    try:
        return jwt.decode(
            token,
            key=public_key,  # type: ignore[arg-type]
            algorithms=[alg],
            subject=credential_issuer,
            options={"require": ["sub", "iat"]},
        )
    except jwt.exceptions.PyJWTError as exc:
        raise InvalidCredentialIssuerMetadataError(
            f"Signed Credential Issuer Metadata failed verification: {exc}"
        ) from exc


def _verify_issuer_identity(metadata: CredentialIssuerMetadata, requested_issuer: str) -> None:
    # Spec: the returned credential_issuer MUST be identical (exact string match) to the
    # identifier the well-known URL was built from, or the response MUST NOT be used.
    if metadata.credential_issuer != requested_issuer:
        raise InvalidCredentialIssuerMetadataError(
            f"Credential Issuer Metadata's credential_issuer {metadata.credential_issuer!r} does "
            f"not match the requested identifier {requested_issuer!r}."
        )


async def _fetch_metadata(url: str, fetch: MetadataFetcher) -> str:
    # Normalize failures from *any* fetcher (default or caller-supplied) to one error type,
    # so callers only ever need to handle InvalidCredentialIssuerMetadataError.
    logger.debug("Fetching Credential Issuer Metadata from %r.", url)
    try:
        return await fetch(url)
    except InvalidCredentialIssuerMetadataError:
        logger.warning("Credential Issuer Metadata at %r is invalid.", url)
        raise
    except Exception as exc:
        logger.warning("Failed to fetch Credential Issuer Metadata from %r: %s", url, exc)
        raise InvalidCredentialIssuerMetadataError(
            f"Failed to fetch metadata from {url!r}: {exc}"
        ) from exc


async def _fetch_metadata_url(url: str) -> str:
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
        # Accept either representation (spec "Credential Issuer Metadata Retrieval", §12.2.2:
        # the Wallet is RECOMMENDED to send Accept, signaling whether it supports signed
        # metadata) -- _parse_metadata_payload sniffs which one actually came back, since some
        # issuers don't honor Accept consistently (see docs/ROADMAP.md Phase 8).
        response = await client.get(
            url, headers={"Accept": "application/json, application/jwt"}
        )
        response.raise_for_status()
        return response.text
