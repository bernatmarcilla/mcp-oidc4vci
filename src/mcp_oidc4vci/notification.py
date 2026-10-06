"""OIDC4VCI Notification Endpoint client (spec "Notification Endpoint", §11).

Lets the Wallet (this server) tell the Credential Issuer whether a previously issued
Credential was actually accepted, failed to be stored, or was deleted by the user --
support for this endpoint is OPTIONAL for the issuer, and sending a notification is itself
optional for the Wallet and best-effort (the spec gives no delivery guarantee).
"""

import json
import logging
import re

import httpx
from pydantic import ValidationError

from mcp_oidc4vci.credential_issuer_metadata import MetadataFetcher, get_credential_issuer_metadata
from mcp_oidc4vci.issuance import IssuanceSession, IssuanceSessionStore
from mcp_oidc4vci.models import NotificationErrorResponse, NotificationEvent
from mcp_oidc4vci.session_request import (
    AuthenticatedRequestError,
    SessionPoster,
    post_with_session_auth,
)

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT_SECONDS = 10.0

# spec §11.1: event_description, if present, is restricted to this ASCII range.
_EVENT_DESCRIPTION_PATTERN = re.compile(r"^[\x20-\x21\x23-\x5b\x5d-\x7e]*$")


class NotificationRequestError(Exception):
    """Base error for problems sending a Notification Request."""


class NotificationNotAvailableError(NotificationRequestError):
    """There is nothing to notify the issuer about right now: the session has no pending
    `notification_id`, or the Credential Issuer doesn't advertise a `notification_endpoint`
    (both legitimate outcomes -- support for this endpoint is OPTIONAL on both sides)."""


class NotificationRejectedError(NotificationRequestError):
    """The Credential Issuer responded with a non-2xx status.

    `error` carries the `error` field from a parseable JSON error body (spec §11.3's 400
    case); it's `None` when the response had no such body -- e.g. an RFC 6750-style
    Authorization Error Response for a missing/invalid Access Token, which defines no
    required JSON shape. Either way, the response is never forced into a shape it doesn't
    have.
    """

    def __init__(self, status_code: int, error: str | None) -> None:
        self.status_code = status_code
        self.error = error
        super().__init__(error or f"HTTP {status_code}")


async def send_credential_notification(
    notification_endpoint: str,
    notification_id: str,
    event: NotificationEvent,
    event_description: str | None = None,
    *,
    session: IssuanceSession,
    post_notification_request: SessionPoster | None = None,
) -> None:
    """Send a Notification Request (spec §11.1) to `notification_endpoint`.

    Authenticated exactly like a Credential Request -- the same Bearer-or-DPoP access token
    issued at the Token Endpoint. Raises `NotificationRejectedError` on anything other than
    a 2xx response; a 2xx response (204 recommended, but any 2xx counts) carries no defined
    body to parse.
    """
    if event_description is not None and not _EVENT_DESCRIPTION_PATTERN.match(event_description):
        raise NotificationRequestError(
            f"event_description {event_description!r} contains characters outside the "
            "spec-allowed ASCII range (%x20-21 / %x23-5B / %x5D-7E)."
        )

    body: dict[str, object] = {"notification_id": notification_id, "event": event}
    if event_description is not None:
        body["event_description"] = event_description

    try:
        status_code, response_body = await post_with_session_auth(
            post_notification_request or _post_notification_request,
            notification_endpoint,
            body,
            session,
        )
    except AuthenticatedRequestError as exc:
        raise NotificationRequestError(str(exc)) from exc

    if 200 <= status_code < 300:
        return
    raise NotificationRejectedError(status_code, _try_parse_error(response_body))


def _try_parse_error(body: str) -> str | None:
    stripped = body.strip()
    if not stripped:
        return None
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    try:
        return NotificationErrorResponse.model_validate(payload).error
    except ValidationError:
        return None


async def notify_credential_issuer(
    session_id: str,
    event: NotificationEvent,
    event_description: str | None = None,
    *,
    sessions: IssuanceSessionStore,
    fetch_issuer_metadata: MetadataFetcher | None = None,
    post_notification_request: SessionPoster | None = None,
) -> None:
    """Report an issuance outcome back to the Credential Issuer for a session's most
    recently issued credential (spec "Notification Endpoint").

    This is a side-channel courtesy to the issuer, not a step in the issuance state
    machine: unlike every other function in this server, it never calls
    `IssuanceSessionStore.update()` and so never changes `session.status` or `session.error`
    -- a rejected or failed notification does not fail the session. It's also, specifically
    *because* it's read-only, safe to call concurrently with a `request_credential` call
    already in flight for the session's next credential configuration (`get()` returns a
    live, shared `IssuanceSession`, so a *mutating* concurrent call would not be safe).

    Raises `IssuanceSessionNotFoundError` if the session doesn't exist,
    `NotificationNotAvailableError` if there's nothing to notify about yet (no
    `notification_id`) or the issuer doesn't support this endpoint (no
    `notification_endpoint`), `InvalidCredentialIssuerMetadataError` if the issuer's metadata
    can't be fetched/validated, and `NotificationRejectedError` if the issuer rejects the
    notification.
    """
    session = await sessions.get(session_id)
    if session.notification_id is None:
        raise NotificationNotAvailableError(
            f"Session {session_id!r} has no pending notification_id to report."
        )

    issuer_metadata = await get_credential_issuer_metadata(
        session.credential_issuer, fetch=fetch_issuer_metadata
    )
    if issuer_metadata.notification_endpoint is None:
        raise NotificationNotAvailableError(
            f"Credential Issuer {session.credential_issuer!r} does not advertise a "
            "notification_endpoint."
        )

    try:
        await send_credential_notification(
            issuer_metadata.notification_endpoint,
            session.notification_id,
            event,
            event_description,
            session=session,
            post_notification_request=post_notification_request,
        )
    except NotificationRejectedError as exc:
        logger.warning(
            "Session %s: Credential Issuer rejected the notification (status=%d, error=%s).",
            session.session_id,
            exc.status_code,
            exc.error,
        )
        raise
    logger.info(
        "Session %s: notified Credential Issuer of event %r for notification_id %r.",
        session.session_id,
        event,
        session.notification_id,
    )


async def _post_notification_request(
    url: str, body: dict[str, object], headers: dict[str, str]
) -> tuple[int, dict[str, str], str]:
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
        response = await client.post(url, json=body, headers=headers)
        return (
            response.status_code,
            {k.lower(): v for k, v in response.headers.items()},
            response.text,
        )
