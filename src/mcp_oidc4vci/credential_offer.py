"""Parsing and resolution of OIDC4VCI Credential Offers (spec §4.1)."""

import json
import logging
from collections.abc import Awaitable, Callable
from urllib.parse import parse_qs, urlsplit

import httpx
from pydantic import ValidationError

from mcp_oidc4vci.models import CredentialOffer

logger = logging.getLogger(__name__)

CredentialOfferFetcher = Callable[[str], Awaitable[str]]

_HTTP_TIMEOUT_SECONDS = 10.0


class CredentialOfferError(Exception):
    """Base error for problems resolving a Credential Offer."""


class InvalidCredentialOfferError(CredentialOfferError):
    """The offer URI, or the document it resolves to, is malformed or violates the spec."""


async def resolve_credential_offer(
    offer_uri: str, *, fetch: CredentialOfferFetcher | None = None
) -> CredentialOffer:
    """Resolve a Credential Offer URI, by value or by reference, into a `CredentialOffer`.

    `fetch` retrieves the JSON body for a by-reference offer (`credential_offer_uri`) and
    defaults to an HTTPS GET; tests can inject a fake to avoid real network calls.
    """
    param_name, value = _extract_offer_query_param(offer_uri)
    if param_name == "credential_offer":
        payload = value
    else:
        payload = await _fetch_offer(value, fetch or _fetch_offer_uri)
    return _parse_credential_offer_payload(payload)


def _extract_offer_query_param(offer_uri: str) -> tuple[str, str]:
    """Return the (name, value) of whichever offer parameter is present.

    `credential_offer` and `credential_offer_uri` are mutually exclusive and exactly one
    is required (spec §4.1).
    """
    params = parse_qs(urlsplit(offer_uri).query)
    has_value = "credential_offer" in params
    has_reference = "credential_offer_uri" in params
    if has_value == has_reference:
        raise InvalidCredentialOfferError(
            "Exactly one of 'credential_offer' or 'credential_offer_uri' must be present."
        )
    param_name = "credential_offer" if has_value else "credential_offer_uri"
    return param_name, params[param_name][0]


def _parse_credential_offer_payload(payload: str) -> CredentialOffer:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise InvalidCredentialOfferError(
            f"Credential Offer payload is not valid JSON: {exc}"
        ) from exc
    try:
        return CredentialOffer.model_validate(data)
    except ValidationError as exc:
        raise InvalidCredentialOfferError(
            f"Credential Offer does not match the expected structure: {exc}"
        ) from exc


async def _fetch_offer(url: str, fetch: CredentialOfferFetcher) -> str:
    # Normalize failures from *any* fetcher (default or caller-supplied) to one error type,
    # so callers only ever need to handle InvalidCredentialOfferError.
    logger.debug("Fetching Credential Offer from %r.", url)
    try:
        return await fetch(url)
    except InvalidCredentialOfferError:
        logger.warning("Credential Offer at %r is invalid.", url)
        raise
    except Exception as exc:
        logger.warning("Failed to fetch credential_offer_uri %r: %s", url, exc)
        raise InvalidCredentialOfferError(
            f"Failed to fetch credential_offer_uri {url!r}: {exc}"
        ) from exc


async def _fetch_offer_uri(url: str) -> str:
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.text
