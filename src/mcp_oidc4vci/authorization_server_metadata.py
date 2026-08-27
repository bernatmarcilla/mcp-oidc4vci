"""Retrieval of OAuth 2.0 Authorization Server Metadata (RFC 8414).

Used to discover the token endpoint of the Authorization Server a Credential Issuer relies
on, per OIDC4VCI's `authorization_servers` Credential Issuer Metadata parameter.
"""

import json
from collections.abc import Awaitable, Callable
from urllib.parse import SplitResult, urlsplit, urlunsplit

import httpx
from pydantic import ValidationError

from mcp_oidc4vci.models import AuthorizationServerMetadata

MetadataFetcher = Callable[[str], Awaitable[str]]

_HTTP_TIMEOUT_SECONDS = 10.0
_WELL_KNOWN_SEGMENT = "/.well-known/oauth-authorization-server"


class AuthorizationServerMetadataError(Exception):
    """Base error for problems retrieving OAuth Authorization Server Metadata."""


class InvalidAuthorizationServerMetadataError(AuthorizationServerMetadataError):
    """The Authorization Server identifier, or the metadata document it resolves to, is invalid."""


async def get_authorization_server_metadata(
    issuer: str, *, fetch: MetadataFetcher | None = None
) -> AuthorizationServerMetadata:
    """Fetch and validate OAuth Authorization Server metadata from its well-known endpoint.

    Uses the same well-known insertion rule as Credential Issuer Metadata (RFC 8414 §3.1).
    `fetch` retrieves the JSON body and defaults to an HTTPS GET; tests can inject a fake to
    avoid real network calls.
    """
    url = _well_known_metadata_url(issuer)
    payload = await _fetch_metadata(url, fetch or _fetch_metadata_url)
    metadata = _parse_metadata_payload(payload)
    _verify_issuer_identity(metadata, issuer)
    return metadata


def _well_known_metadata_url(issuer: str) -> str:
    """Insert the well-known segment between the host and path components (RFC 8414 §3.1),
    e.g. https://as.example.com/tenant becomes
    https://as.example.com/.well-known/oauth-authorization-server/tenant.
    """
    parts = urlsplit(issuer)
    if parts.scheme != "https" or parts.query or parts.fragment:
        raise InvalidAuthorizationServerMetadataError(
            f"authorization server identifier must be an https URL with no query or "
            f"fragment: {issuer!r}"
        )
    return urlunsplit(
        SplitResult(parts.scheme, parts.netloc, _WELL_KNOWN_SEGMENT + parts.path, "", "")
    )


def _parse_metadata_payload(payload: str) -> AuthorizationServerMetadata:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise InvalidAuthorizationServerMetadataError(
            f"Authorization Server Metadata is not valid JSON: {exc}"
        ) from exc
    try:
        return AuthorizationServerMetadata.model_validate(data)
    except ValidationError as exc:
        raise InvalidAuthorizationServerMetadataError(
            f"Authorization Server Metadata does not match the expected structure: {exc}"
        ) from exc


def _verify_issuer_identity(metadata: AuthorizationServerMetadata, requested_issuer: str) -> None:
    # Mirrors the identity check RFC 8414-based discovery relies on: the returned issuer
    # must match the identifier the well-known URL was built from.
    if metadata.issuer != requested_issuer:
        raise InvalidAuthorizationServerMetadataError(
            f"Authorization Server Metadata's issuer {metadata.issuer!r} does not match the "
            f"requested identifier {requested_issuer!r}."
        )


async def _fetch_metadata(url: str, fetch: MetadataFetcher) -> str:
    # Normalize failures from *any* fetcher (default or caller-supplied) to one error type,
    # so callers only ever need to handle InvalidAuthorizationServerMetadataError.
    try:
        return await fetch(url)
    except InvalidAuthorizationServerMetadataError:
        raise
    except Exception as exc:
        raise InvalidAuthorizationServerMetadataError(
            f"Failed to fetch metadata from {url!r}: {exc}"
        ) from exc


async def _fetch_metadata_url(url: str) -> str:
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.text
