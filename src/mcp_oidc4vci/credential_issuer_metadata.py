"""Retrieval of OIDC4VCI Credential Issuer Metadata (spec "Credential Issuer Metadata")."""

import json
import logging
from collections.abc import Awaitable, Callable
from urllib.parse import SplitResult, urlsplit, urlunsplit

import httpx
from pydantic import ValidationError

from mcp_oidc4vci.models import CredentialIssuerMetadata

logger = logging.getLogger(__name__)

MetadataFetcher = Callable[[str], Awaitable[str]]

_HTTP_TIMEOUT_SECONDS = 10.0
_WELL_KNOWN_SEGMENT = "/.well-known/openid-credential-issuer"


class CredentialIssuerMetadataError(Exception):
    """Base error for problems retrieving Credential Issuer Metadata."""


class InvalidCredentialIssuerMetadataError(CredentialIssuerMetadataError):
    """The Credential Issuer identifier, or the metadata document it resolves to, is invalid."""


async def get_credential_issuer_metadata(
    credential_issuer: str, *, fetch: MetadataFetcher | None = None
) -> CredentialIssuerMetadata:
    """Fetch and validate a Credential Issuer's metadata from its well-known endpoint.

    `fetch` retrieves the JSON body and defaults to an HTTPS GET; tests can inject a fake
    to avoid real network calls.
    """
    url = _well_known_metadata_url(credential_issuer)
    payload = await _fetch_metadata(url, fetch or _fetch_metadata_url)
    metadata = _parse_metadata_payload(payload)
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


def _parse_metadata_payload(payload: str) -> CredentialIssuerMetadata:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise InvalidCredentialIssuerMetadataError(
            f"Credential Issuer Metadata is not valid JSON: {exc}"
        ) from exc
    try:
        return CredentialIssuerMetadata.model_validate(data)
    except ValidationError as exc:
        raise InvalidCredentialIssuerMetadataError(
            f"Credential Issuer Metadata does not match the expected structure: {exc}"
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
        response = await client.get(url)
        response.raise_for_status()
        return response.text
