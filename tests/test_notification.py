import httpx
import jwt
import pytest

from mcp_oidc4vci import notification
from mcp_oidc4vci.credential_issuer_metadata import InvalidCredentialIssuerMetadataError
from mcp_oidc4vci.dpop import DPoPKey
from mcp_oidc4vci.issuance import (
    AUTHORIZATION_CODE_FLOW,
    IssuanceSessionNotFoundError,
    IssuanceSessionStore,
)
from mcp_oidc4vci.notification import (
    NotificationNotAvailableError,
    NotificationRejectedError,
    NotificationRequestError,
    notify_credential_issuer,
    send_credential_notification,
)
from support import mock_async_client

ISSUER = "https://issuer.example.com"
NOTIFICATION_ENDPOINT = f"{ISSUER}/notification"


async def _session_with_notification(
    sessions: IssuanceSessionStore, *, dpop_bound: bool = False
) -> str:
    session = await sessions.create(
        credential_issuer=ISSUER,
        credential_configuration_ids=["UniversityDegreeCredential"],
        flow_type=AUTHORIZATION_CODE_FLOW,
    )
    await sessions.update(
        session.session_id,
        status="completed",
        access_token="secret-token",
        dpop_key=DPoPKey() if dpop_bound else None,
        dpop_bound=dpop_bound,
        notification_id="3fwe98js",
    )
    return session.session_id


def _issuer_metadata_json(*, notification_endpoint: str | None = NOTIFICATION_ENDPOINT) -> str:
    field = f', "notification_endpoint": "{notification_endpoint}"' if notification_endpoint else ""
    return (
        f'{{"credential_issuer": "{ISSUER}", '
        f'"credential_endpoint": "{ISSUER}/credential"{field}, '
        '"credential_configurations_supported": {}}'
    )


async def _fetch_metadata_with_notification_endpoint(url: str) -> str:
    return _issuer_metadata_json()


async def _fetch_metadata_without_notification_endpoint(url: str) -> str:
    return _issuer_metadata_json(notification_endpoint=None)


# -- send_credential_notification (low-level client) ---------------------------


async def test_send_credential_notification_succeeds_on_204() -> None:
    sessions = IssuanceSessionStore()
    session = await sessions.get(await _session_with_notification(sessions))
    captured: list[tuple[str, dict[str, object], dict[str, str]]] = []

    async def fake_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured.append((url, body, headers))
        return 204, {}, ""

    await send_credential_notification(
        NOTIFICATION_ENDPOINT,
        "3fwe98js",
        "credential_accepted",
        session=session,
        post_notification_request=fake_post,
    )

    assert len(captured) == 1
    url, body, headers = captured[0]
    assert url == NOTIFICATION_ENDPOINT
    assert body == {"notification_id": "3fwe98js", "event": "credential_accepted"}
    assert headers["Authorization"] == "Bearer secret-token"


async def test_send_credential_notification_includes_event_description_when_given() -> None:
    sessions = IssuanceSessionStore()
    session = await sessions.get(await _session_with_notification(sessions))
    captured: dict[str, object] = {}

    async def fake_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured.update(body)
        return 200, {}, ""

    await send_credential_notification(
        NOTIFICATION_ENDPOINT,
        "3fwe98js",
        "credential_failure",
        "Could not store the Credential. Out of storage.",
        session=session,
        post_notification_request=fake_post,
    )

    assert captured == {
        "notification_id": "3fwe98js",
        "event": "credential_failure",
        "event_description": "Could not store the Credential. Out of storage.",
    }


async def test_send_credential_notification_rejects_an_out_of_charset_event_description() -> None:
    sessions = IssuanceSessionStore()
    session = await sessions.get(await _session_with_notification(sessions))

    async def fail_if_posted(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        raise AssertionError("must not send a notification with an invalid event_description")

    with pytest.raises(NotificationRequestError):
        await send_credential_notification(
            NOTIFICATION_ENDPOINT,
            "3fwe98js",
            "credential_failure",
            "disallowed control char: \x01",
            session=session,
            post_notification_request=fail_if_posted,
        )


async def test_send_credential_notification_raises_with_the_parsed_error_on_400() -> None:
    sessions = IssuanceSessionStore()
    session = await sessions.get(await _session_with_notification(sessions))

    async def rejecting_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 400, {}, '{"error": "invalid_notification_id"}'

    with pytest.raises(NotificationRejectedError) as exc_info:
        await send_credential_notification(
            NOTIFICATION_ENDPOINT,
            "3fwe98js",
            "credential_accepted",
            session=session,
            post_notification_request=rejecting_post,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.error == "invalid_notification_id"


async def test_send_credential_notification_raises_with_no_error_on_an_empty_401_body() -> None:
    # RFC 6750-style Authorization Error Response (spec §11.3): no JSON body is required for
    # a missing/invalid Access Token, unlike the 400 invalid_notification_id case. The empty
    # body must not be treated as a parse failure or forced into the error-response shape.
    sessions = IssuanceSessionStore()
    session = await sessions.get(await _session_with_notification(sessions))

    async def unauthorized_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 401, {"www-authenticate": 'Bearer error="invalid_token"'}, ""

    with pytest.raises(NotificationRejectedError) as exc_info:
        await send_credential_notification(
            NOTIFICATION_ENDPOINT,
            "3fwe98js",
            "credential_accepted",
            session=session,
            post_notification_request=unauthorized_post,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.error is None


async def test_send_credential_notification_raises_with_no_error_on_a_non_json_body() -> None:
    sessions = IssuanceSessionStore()
    session = await sessions.get(await _session_with_notification(sessions))

    async def rejecting_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 500, {}, "Internal Server Error"

    with pytest.raises(NotificationRejectedError) as exc_info:
        await send_credential_notification(
            NOTIFICATION_ENDPOINT,
            "3fwe98js",
            "credential_accepted",
            session=session,
            post_notification_request=rejecting_post,
        )

    assert exc_info.value.status_code == 500
    assert exc_info.value.error is None


async def test_send_credential_notification_raises_with_no_error_on_a_malformed_error_body() -> (
    None
):
    sessions = IssuanceSessionStore()
    session = await sessions.get(await _session_with_notification(sessions))

    async def rejecting_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 400, {}, '{"unexpected": "shape"}'

    with pytest.raises(NotificationRejectedError) as exc_info:
        await send_credential_notification(
            NOTIFICATION_ENDPOINT,
            "3fwe98js",
            "credential_accepted",
            session=session,
            post_notification_request=rejecting_post,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.error is None


async def test_send_credential_notification_raises_when_the_transport_fails() -> None:
    sessions = IssuanceSessionStore()
    session = await sessions.get(await _session_with_notification(sessions))

    async def broken_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        raise ConnectionError("boom")

    with pytest.raises(NotificationRequestError, match="boom"):
        await send_credential_notification(
            NOTIFICATION_ENDPOINT,
            "3fwe98js",
            "credential_accepted",
            session=session,
            post_notification_request=broken_post,
        )


async def test_send_credential_notification_uses_dpop_when_the_session_is_dpop_bound() -> None:
    sessions = IssuanceSessionStore()
    session = await sessions.get(
        await _session_with_notification(sessions, dpop_bound=True)
    )
    captured_headers: list[dict[str, str]] = []

    async def fake_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured_headers.append(headers)
        return 204, {}, ""

    await send_credential_notification(
        NOTIFICATION_ENDPOINT,
        "3fwe98js",
        "credential_accepted",
        session=session,
        post_notification_request=fake_post,
    )

    headers = captured_headers[0]
    assert headers["Authorization"] == "DPoP secret-token"
    proof_claims = jwt.decode(headers["DPoP"], options={"verify_signature": False})
    assert proof_claims["htm"] == "POST"
    assert proof_claims["htu"] == NOTIFICATION_ENDPOINT


async def test_send_credential_notification_retries_once_on_a_dpop_nonce_challenge() -> None:
    sessions = IssuanceSessionStore()
    session = await sessions.get(
        await _session_with_notification(sessions, dpop_bound=True)
    )
    seen_nonces: list[str | None] = []

    async def fake_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        claims = jwt.decode(headers["DPoP"], options={"verify_signature": False})
        seen_nonces.append(claims.get("nonce"))
        if len(seen_nonces) == 1:
            return (
                401,
                {"www-authenticate": 'DPoP error="use_dpop_nonce"', "dpop-nonce": "rs-nonce"},
                "",
            )
        return 204, {}, ""

    await send_credential_notification(
        NOTIFICATION_ENDPOINT,
        "3fwe98js",
        "credential_accepted",
        session=session,
        post_notification_request=fake_post,
    )

    assert seen_nonces == [None, "rs-nonce"]


async def test_default_poster_sends_a_bearer_token_and_json_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(204)

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

    status_code, _headers, _body = await notification._post_notification_request(
        NOTIFICATION_ENDPOINT,
        {"notification_id": "3fwe98js", "event": "credential_accepted"},
        {"Authorization": "Bearer secret-token"},
    )

    assert status_code == 204
    request = captured_requests[0]
    assert request.method == "POST"
    assert request.headers["authorization"] == "Bearer secret-token"


# -- notify_credential_issuer (session-aware orchestration) --------------------


async def test_notify_credential_issuer_sends_the_sessions_notification_id() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _session_with_notification(sessions)
    captured: dict[str, object] = {}

    async def fake_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured.update(body)
        return 204, {}, ""

    await notify_credential_issuer(
        session_id,
        "credential_accepted",
        sessions=sessions,
        fetch_issuer_metadata=_fetch_metadata_with_notification_endpoint,
        post_notification_request=fake_post,
    )

    assert captured == {"notification_id": "3fwe98js", "event": "credential_accepted"}


async def _succeed(
    url: str, body: dict[str, object], headers: dict[str, str]
) -> tuple[int, dict[str, str], str]:
    return 204, {}, ""


async def test_notify_credential_issuer_does_not_change_session_status_on_success() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _session_with_notification(sessions)

    await notify_credential_issuer(
        session_id,
        "credential_accepted",
        sessions=sessions,
        fetch_issuer_metadata=_fetch_metadata_with_notification_endpoint,
        post_notification_request=_succeed,
    )

    session = await sessions.get(session_id)
    assert session.status == "completed"


async def test_notify_credential_issuer_does_not_change_session_status_on_rejection() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _session_with_notification(sessions)

    async def rejecting_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 400, {}, '{"error": "invalid_notification_id"}'

    with pytest.raises(NotificationRejectedError):
        await notify_credential_issuer(
            session_id,
            "credential_accepted",
            sessions=sessions,
            fetch_issuer_metadata=_fetch_metadata_with_notification_endpoint,
            post_notification_request=rejecting_post,
        )

    session = await sessions.get(session_id)
    assert session.status == "completed"
    assert session.error is None


async def test_notify_credential_issuer_raises_for_an_unknown_session() -> None:
    with pytest.raises(IssuanceSessionNotFoundError):
        await notify_credential_issuer(
            "does-not-exist", "credential_accepted", sessions=IssuanceSessionStore()
        )


async def test_notify_credential_issuer_raises_when_there_is_no_notification_id() -> None:
    sessions = IssuanceSessionStore()
    session = await sessions.create(
        credential_issuer=ISSUER,
        credential_configuration_ids=["UniversityDegreeCredential"],
        flow_type=AUTHORIZATION_CODE_FLOW,
    )
    await sessions.update(session.session_id, status="completed")

    with pytest.raises(NotificationNotAvailableError):
        await notify_credential_issuer(
            session.session_id, "credential_accepted", sessions=sessions
        )


async def test_notify_credential_issuer_raises_when_the_issuer_has_no_notification_endpoint() -> (
    None
):
    sessions = IssuanceSessionStore()
    session_id = await _session_with_notification(sessions)

    with pytest.raises(NotificationNotAvailableError):
        await notify_credential_issuer(
            session_id,
            "credential_accepted",
            sessions=sessions,
            fetch_issuer_metadata=_fetch_metadata_without_notification_endpoint,
        )


async def test_notify_credential_issuer_propagates_invalid_issuer_metadata() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _session_with_notification(sessions)

    async def broken_metadata(url: str) -> str:
        return "not-json"

    with pytest.raises(InvalidCredentialIssuerMetadataError):
        await notify_credential_issuer(
            session_id,
            "credential_accepted",
            sessions=sessions,
            fetch_issuer_metadata=broken_metadata,
        )
