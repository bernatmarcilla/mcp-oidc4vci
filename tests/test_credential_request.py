import httpx
import pytest

from mcp_oidc4vci import credential_request
from mcp_oidc4vci.credential_request import (
    CredentialRequestRejectedError,
    SessionNotReadyError,
    request_credential,
)
from mcp_oidc4vci.issuance import (
    AUTHORIZATION_CODE_FLOW,
    IssuanceSessionNotFoundError,
    IssuanceSessionStore,
)
from mcp_oidc4vci.models import PRE_AUTHORIZED_CODE_GRANT_TYPE
from mcp_oidc4vci.wallet import MockWalletAdapter
from support import mock_async_client

ISSUER = "https://issuer.example.com"


def _issuer_metadata_json(*, nonce_endpoint: str | None = None) -> str:
    nonce_field = f', "nonce_endpoint": "{nonce_endpoint}"' if nonce_endpoint else ""
    return (
        f'{{"credential_issuer": "{ISSUER}", '
        f'"credential_endpoint": "{ISSUER}/credential"{nonce_field}, '
        '"credential_configurations_supported": '
        '{"UniversityDegreeCredential": {"format": "vc+sd-jwt"}}}'
    )


async def _fetch_default_issuer_metadata(url: str) -> str:
    return _issuer_metadata_json()


async def _fail_if_nonce_posted(url: str) -> tuple[int, str]:
    raise AssertionError(f"unexpected nonce request to {url!r}")


async def _fail_if_credential_posted(
    url: str, body: dict[str, object], access_token: str
) -> tuple[int, str]:
    raise AssertionError(f"unexpected credential request to {url!r}")


async def _ready_session(
    sessions: IssuanceSessionStore, *, access_token: str = "secret-token"
) -> str:
    session = await sessions.create(
        credential_issuer=ISSUER,
        credential_configuration_ids=["UniversityDegreeCredential"],
        flow_type=PRE_AUTHORIZED_CODE_GRANT_TYPE,
    )
    await sessions.update(
        session.session_id, status="ready_for_credential_request", access_token=access_token
    )
    return session.session_id


# -- guard checks --------------------------------------------------------------


async def test_raises_when_the_session_does_not_exist() -> None:
    with pytest.raises(IssuanceSessionNotFoundError):
        await request_credential(
            "does-not-exist", sessions=IssuanceSessionStore(), wallet=MockWalletAdapter()
        )


async def test_raises_when_the_session_is_not_ready() -> None:
    sessions = IssuanceSessionStore()
    session = await sessions.create(
        credential_issuer=ISSUER,
        credential_configuration_ids=["UniversityDegreeCredential"],
        flow_type=AUTHORIZATION_CODE_FLOW,
    )
    await sessions.update(session.session_id, status="waiting_for_user_authorization")

    with pytest.raises(SessionNotReadyError):
        await request_credential(session.session_id, sessions=sessions, wallet=MockWalletAdapter())


async def test_raises_when_the_session_has_no_access_token() -> None:
    sessions = IssuanceSessionStore()
    session = await sessions.create(
        credential_issuer=ISSUER,
        credential_configuration_ids=["UniversityDegreeCredential"],
        flow_type=AUTHORIZATION_CODE_FLOW,
    )
    await sessions.update(session.session_id, status="ready_for_credential_request")

    with pytest.raises(SessionNotReadyError):
        await request_credential(session.session_id, sessions=sessions, wallet=MockWalletAdapter())


# -- happy paths ----------------------------------------------------------------


async def test_completes_without_a_nonce_when_the_issuer_has_no_nonce_endpoint() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)
    captured_proof_calls: list[dict[str, object]] = []
    captured_requests: list[tuple[str, dict[str, object], str]] = []

    async def fake_issuer_metadata(url: str) -> str:
        return _issuer_metadata_json()

    class RecordingWallet(MockWalletAdapter):
        async def generate_proof(self, *, audience: str, nonce: str | None) -> str:
            captured_proof_calls.append({"audience": audience, "nonce": nonce})
            return await super().generate_proof(audience=audience, nonce=nonce)

    async def fake_post(url: str, body: dict[str, object], access_token: str) -> tuple[int, str]:
        captured_requests.append((url, body, access_token))
        return 200, '{"credentials": [{"credential": "opaque-jwt-vc"}]}'

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=RecordingWallet(),
        fetch_issuer_metadata=fake_issuer_metadata,
        fetch_nonce=_fail_if_nonce_posted,
        post_credential_request=fake_post,
    )

    assert session.status == "completed"
    assert captured_proof_calls == [{"audience": ISSUER, "nonce": None}]
    assert len(captured_requests) == 1
    url, body, access_token = captured_requests[0]
    assert url == f"{ISSUER}/credential"
    assert access_token == "secret-token"
    assert body["credential_configuration_id"] == "UniversityDegreeCredential"
    proofs = body["proofs"]
    assert isinstance(proofs, dict)
    assert len(proofs["jwt"]) == 1
    assert isinstance(proofs["jwt"][0], str)


async def test_requests_a_nonce_and_binds_it_into_the_proof_when_available() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)
    captured_proof_calls: list[dict[str, object]] = []
    requested_nonce_urls: list[str] = []

    async def fake_issuer_metadata(url: str) -> str:
        return _issuer_metadata_json(nonce_endpoint=f"{ISSUER}/nonce")

    async def fake_nonce(url: str) -> tuple[int, str]:
        requested_nonce_urls.append(url)
        return 200, '{"c_nonce": "fresh-nonce"}'

    class RecordingWallet(MockWalletAdapter):
        async def generate_proof(self, *, audience: str, nonce: str | None) -> str:
            captured_proof_calls.append({"audience": audience, "nonce": nonce})
            return await super().generate_proof(audience=audience, nonce=nonce)

    async def fake_post(url: str, body: dict[str, object], access_token: str) -> tuple[int, str]:
        return 200, '{"credentials": [{"credential": "opaque-jwt-vc"}]}'

    await request_credential(
        session_id,
        sessions=sessions,
        wallet=RecordingWallet(),
        fetch_issuer_metadata=fake_issuer_metadata,
        fetch_nonce=fake_nonce,
        post_credential_request=fake_post,
    )

    assert requested_nonce_urls == [f"{ISSUER}/nonce"]
    assert captured_proof_calls == [{"audience": ISSUER, "nonce": "fresh-nonce"}]


async def test_hands_each_issued_credential_to_the_wallet() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)
    wallet = MockWalletAdapter()

    async def fake_post(url: str, body: dict[str, object], access_token: str) -> tuple[int, str]:
        return 200, (
            '{"credentials": [{"credential": "vc-one"}, {"credential": {"nested": "vc-two"}}]}'
        )

    await request_credential(
        session_id,
        sessions=sessions,
        wallet=wallet,
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=fake_post,
    )

    assert wallet.received_credentials == [
        {"credential_configuration_id": "UniversityDegreeCredential", "credential": "vc-one"},
        {
            "credential_configuration_id": "UniversityDegreeCredential",
            "credential": {"nested": "vc-two"},
        },
    ]


# -- failure paths ----------------------------------------------------------------


async def test_fails_the_session_when_issuer_metadata_is_invalid() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)

    async def broken_metadata(url: str) -> str:
        return "not-json"

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=broken_metadata,
        fetch_nonce=_fail_if_nonce_posted,
        post_credential_request=_fail_if_credential_posted,
    )

    assert session.status == "failed"
    assert session.error is not None


async def test_fails_the_session_when_the_nonce_request_fails() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)

    async def fake_issuer_metadata(url: str) -> str:
        return _issuer_metadata_json(nonce_endpoint=f"{ISSUER}/nonce")

    async def broken_nonce(url: str) -> tuple[int, str]:
        return 500, "boom"

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=fake_issuer_metadata,
        fetch_nonce=broken_nonce,
        post_credential_request=_fail_if_credential_posted,
    )

    assert session.status == "failed"
    assert session.error is not None


async def test_fails_the_session_when_the_credential_request_is_rejected() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)

    async def rejecting_post(
        url: str, body: dict[str, object], access_token: str
    ) -> tuple[int, str]:
        return 400, '{"error": "invalid_proof", "error_description": "proof nonce expired"}'

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=rejecting_post,
    )

    assert session.status == "failed"
    assert session.error == "proof nonce expired"


async def test_fails_the_session_for_a_deferred_response_without_calling_the_wallet() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)
    wallet = MockWalletAdapter()

    async def deferred_post(
        url: str, body: dict[str, object], access_token: str
    ) -> tuple[int, str]:
        return 202, '{"transaction_id": "8xLOxBtZp8", "interval": 5}'

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=wallet,
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=deferred_post,
    )

    assert session.status == "failed"
    assert session.error is not None
    assert "deferred" in session.error.lower()
    assert wallet.received_credentials == []


async def test_fails_the_session_for_a_success_response_with_neither_field_present() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)

    async def empty_post(url: str, body: dict[str, object], access_token: str) -> tuple[int, str]:
        return 200, "{}"

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=empty_post,
    )

    assert session.status == "failed"
    assert session.error is not None


async def test_fails_the_session_when_the_response_body_is_not_valid_json() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)

    async def not_json_post(
        url: str, body: dict[str, object], access_token: str
    ) -> tuple[int, str]:
        return 200, "not-json"

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=not_json_post,
    )

    assert session.status == "failed"
    assert session.error is not None


async def test_fails_the_session_for_a_malformed_success_response() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)

    async def malformed_post(
        url: str, body: dict[str, object], access_token: str
    ) -> tuple[int, str]:
        return 200, '{"credentials": "not-a-list"}'

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=malformed_post,
    )

    assert session.status == "failed"
    assert session.error is not None


async def test_fails_the_session_for_a_malformed_error_response() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)

    async def malformed_error_post(
        url: str, body: dict[str, object], access_token: str
    ) -> tuple[int, str]:
        return 400, '{"unexpected": "shape"}'

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=malformed_error_post,
    )

    assert session.status == "failed"
    assert session.error is not None


async def test_default_poster_sends_a_bearer_token_and_json_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json={"credentials": [{"credential": "opaque-jwt-vc"}]})

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

    status_code, body = await credential_request._post_credential_request(
        f"{ISSUER}/credential",
        {"credential_configuration_id": "UniversityDegreeCredential", "proofs": {"jwt": ["x"]}},
        "secret-token",
    )

    assert status_code == 200
    assert "opaque-jwt-vc" in body
    request = captured_requests[0]
    assert request.method == "POST"
    assert request.headers["authorization"] == "Bearer secret-token"


async def test_raises_credential_request_rejected_error_directly_for_a_well_formed_error() -> None:
    # Exercises CredentialRequestRejectedError's own attributes, independent of how
    # request_credential happens to report the failure on the session.
    exc = CredentialRequestRejectedError("invalid_proof", "proof nonce expired")

    assert exc.error == "invalid_proof"
    assert exc.error_description == "proof nonce expired"
    assert str(exc) == "proof nonce expired"
