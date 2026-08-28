import httpx
import jwt
import pytest

from mcp_oidc4vci import credential_request
from mcp_oidc4vci.credential_request import (
    CredentialRequestRejectedError,
    SessionNotReadyError,
    request_credential,
    request_wallet_proof,
    submit_wallet_proof,
)
from mcp_oidc4vci.dpop import DPoPKey
from mcp_oidc4vci.issuance import (
    AUTHORIZATION_CODE_FLOW,
    IssuanceSessionNotFoundError,
    IssuanceSessionStore,
)
from mcp_oidc4vci.models import PRE_AUTHORIZED_CODE_GRANT_TYPE
from mcp_oidc4vci.wallet import MockWalletAdapter
from support import mock_async_client

ISSUER = "https://issuer.example.com"
_SUCCESS_BODY = '{"credentials": [{"credential": "opaque-jwt-vc"}]}'


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
    url: str, body: dict[str, object], headers: dict[str, str]
) -> tuple[int, dict[str, str], str]:
    raise AssertionError(f"unexpected credential request to {url!r}")


async def _success_post(
    url: str, body: dict[str, object], headers: dict[str, str]
) -> tuple[int, dict[str, str], str]:
    return 200, {}, _SUCCESS_BODY


async def _ready_session(
    sessions: IssuanceSessionStore,
    *,
    access_token: str = "secret-token",
    dpop_bound: bool = False,
) -> str:
    session = await sessions.create(
        credential_issuer=ISSUER,
        credential_configuration_ids=["UniversityDegreeCredential"],
        flow_type=PRE_AUTHORIZED_CODE_GRANT_TYPE,
    )
    await sessions.update(
        session.session_id,
        status="ready_for_credential_request",
        access_token=access_token,
        dpop_key=DPoPKey() if dpop_bound else None,
        dpop_bound=dpop_bound,
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
    captured_requests: list[tuple[str, dict[str, object], dict[str, str]]] = []

    async def fake_issuer_metadata(url: str) -> str:
        return _issuer_metadata_json()

    class RecordingWallet(MockWalletAdapter):
        async def generate_proof(self, *, audience: str, nonce: str | None) -> str:
            captured_proof_calls.append({"audience": audience, "nonce": nonce})
            return await super().generate_proof(audience=audience, nonce=nonce)

    async def fake_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured_requests.append((url, body, headers))
        return 200, {}, _SUCCESS_BODY

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
    url, body, headers = captured_requests[0]
    assert url == f"{ISSUER}/credential"
    assert headers["Authorization"] == "Bearer secret-token"
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

    await request_credential(
        session_id,
        sessions=sessions,
        wallet=RecordingWallet(),
        fetch_issuer_metadata=fake_issuer_metadata,
        fetch_nonce=fake_nonce,
        post_credential_request=_success_post,
    )

    assert requested_nonce_urls == [f"{ISSUER}/nonce"]
    assert captured_proof_calls == [{"audience": ISSUER, "nonce": "fresh-nonce"}]


async def test_hands_each_issued_credential_to_the_wallet() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)
    wallet = MockWalletAdapter()

    async def fake_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return (
            200,
            {},
            '{"credentials": [{"credential": "vc-one"}, {"credential": {"nested": "vc-two"}}]}',
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


async def test_rejects_the_pre_final_singular_credential_shape() -> None:
    # This project targets v1.0 strictly (see docs/ARCHITECTURE.md). Some issuers (e.g.
    # Namirial's dev gateway) still return this pre-final draft shape instead of the v1.0
    # `credentials` array — it must be reported clearly as non-conformant, not accepted.
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)
    wallet = MockWalletAdapter()

    async def fake_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 200, {}, '{"credential": "vc-jwt", "notification_id": "abc"}'

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=wallet,
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=fake_post,
    )

    assert session.status == "failed"
    assert session.error is not None
    assert "['credential', 'notification_id']" in session.error
    assert wallet.received_credentials == []


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
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 400, {}, '{"error": "invalid_proof", "error_description": "proof nonce expired"}'

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
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 202, {}, '{"transaction_id": "8xLOxBtZp8", "interval": 5}'

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

    async def unexpected_shape_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        # Neither the v1.0 'credentials' array nor the pre-final 'credential' field we also
        # accept — field *names* only, chosen to be obviously not real credential data, since
        # the point of this test is that they end up in the error message, not their content.
        return 200, {}, '{"totally_unexpected_field": "not-a-real-shape"}'

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=unexpected_shape_post,
    )

    assert session.status == "failed"
    assert session.error is not None
    assert "['totally_unexpected_field']" in session.error


async def test_fails_the_session_when_the_response_body_is_not_valid_json() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)

    async def not_json_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 200, {}, "not-json"

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
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 200, {}, '{"credentials": "not-a-list"}'

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
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 400, {}, '{"unexpected": "shape"}'

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=malformed_error_post,
    )

    assert session.status == "failed"
    assert session.error is not None


async def test_fails_the_session_when_the_transport_fails() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)

    async def broken_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        raise ConnectionError("boom")

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=broken_post,
    )

    assert session.status == "failed"
    assert session.error is not None
    assert "boom" in session.error


async def test_default_poster_sends_a_bearer_token_and_json_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json={"credentials": [{"credential": "opaque-jwt-vc"}]})

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

    status_code, _headers, body = await credential_request._post_credential_request(
        f"{ISSUER}/credential",
        {"credential_configuration_id": "UniversityDegreeCredential", "proofs": {"jwt": ["x"]}},
        {"Authorization": "Bearer secret-token"},
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


# -- DPoP (RFC 9449): the access token is DPoP-bound ---------------------------


async def test_uses_the_dpop_scheme_and_attaches_a_proof_with_ath_when_dpop_bound() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions, dpop_bound=True)
    captured_requests: list[tuple[str, dict[str, str]]] = []

    async def fake_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured_requests.append((url, headers))
        return 200, {}, _SUCCESS_BODY

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=fake_post,
    )

    assert session.status == "completed"
    assert len(captured_requests) == 1
    url, headers = captured_requests[0]
    assert headers["Authorization"] == "DPoP secret-token"
    proof_claims = jwt.decode(headers["DPoP"], options={"verify_signature": False})
    assert proof_claims["htm"] == "POST"
    assert proof_claims["htu"] == url
    assert "ath" in proof_claims


async def test_retries_once_with_the_servers_nonce_after_a_resource_server_challenge() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions, dpop_bound=True)
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
        return 200, {}, _SUCCESS_BODY

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=fake_post,
    )

    assert session.status == "completed"
    assert seen_nonces == [None, "rs-nonce"]


async def test_fails_the_session_if_the_resource_server_keeps_demanding_a_new_nonce() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions, dpop_bound=True)

    async def always_challenges(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return (
            401,
            {"www-authenticate": 'DPoP error="use_dpop_nonce"', "dpop-nonce": "rs-nonce"},
            "",
        )

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=always_challenges,
    )

    assert session.status == "failed"
    assert session.error is not None


async def test_does_not_treat_a_plain_401_as_a_nonce_challenge() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions, dpop_bound=True)
    call_count = 0

    async def unauthorized_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        nonlocal call_count
        call_count += 1
        return 401, {}, '{"error": "invalid_token", "error_description": "token expired"}'

    session = await request_credential(
        session_id,
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=unauthorized_post,
    )

    assert call_count == 1
    assert session.status == "failed"
    assert session.error == "token expired"


# -- request_wallet_proof / submit_wallet_proof: the manual two-step path -----


async def _awaiting_proof_session(sessions: IssuanceSessionStore) -> str:
    session_id = await _ready_session(sessions)
    await request_wallet_proof(
        session_id, sessions=sessions, fetch_issuer_metadata=_fetch_default_issuer_metadata
    )
    return session_id


async def test_request_wallet_proof_moves_the_session_to_awaiting_without_signing_anything() -> (
    None
):
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)

    session = await request_wallet_proof(
        session_id, sessions=sessions, fetch_issuer_metadata=_fetch_default_issuer_metadata
    )

    assert session.status == "awaiting_wallet_proof"
    assert session.proof_nonce is None


async def test_request_wallet_proof_records_the_nonce_when_the_issuer_has_one() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)

    async def fake_issuer_metadata(url: str) -> str:
        return _issuer_metadata_json(nonce_endpoint=f"{ISSUER}/nonce")

    async def fake_nonce(url: str) -> tuple[int, str]:
        return 200, '{"c_nonce": "fresh-nonce"}'

    session = await request_wallet_proof(
        session_id,
        sessions=sessions,
        fetch_issuer_metadata=fake_issuer_metadata,
        fetch_nonce=fake_nonce,
    )

    assert session.status == "awaiting_wallet_proof"
    assert session.proof_nonce == "fresh-nonce"


async def test_request_wallet_proof_raises_when_the_session_is_not_ready() -> None:
    sessions = IssuanceSessionStore()
    session = await sessions.create(
        credential_issuer=ISSUER,
        credential_configuration_ids=["UniversityDegreeCredential"],
        flow_type=AUTHORIZATION_CODE_FLOW,
    )
    await sessions.update(session.session_id, status="waiting_for_user_authorization")

    with pytest.raises(SessionNotReadyError):
        await request_wallet_proof(session.session_id, sessions=sessions)


async def test_request_wallet_proof_fails_the_session_when_issuer_metadata_is_invalid() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)

    async def broken_metadata(url: str) -> str:
        return "not-json"

    session = await request_wallet_proof(
        session_id, sessions=sessions, fetch_issuer_metadata=broken_metadata
    )

    assert session.status == "failed"
    assert session.error is not None


async def test_submit_wallet_proof_raises_when_the_session_is_not_awaiting_a_proof() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _ready_session(sessions)

    with pytest.raises(SessionNotReadyError):
        await submit_wallet_proof(
            session_id, "externally-signed-jwt", sessions=sessions, wallet=MockWalletAdapter()
        )


async def test_submit_wallet_proof_completes_the_request_without_asking_the_wallet_to_sign() -> (
    None
):
    sessions = IssuanceSessionStore()
    session_id = await _awaiting_proof_session(sessions)
    captured_requests: list[tuple[str, dict[str, object], dict[str, str]]] = []

    class RefusesToSignWallet(MockWalletAdapter):
        async def generate_proof(self, *, audience: str, nonce: str | None) -> str:
            raise AssertionError("submit_wallet_proof must not ask the wallet to sign")

    async def fake_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured_requests.append((url, body, headers))
        return 200, {}, _SUCCESS_BODY

    session = await submit_wallet_proof(
        session_id,
        "externally-signed-jwt",
        sessions=sessions,
        wallet=RefusesToSignWallet(),
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=fake_post,
    )

    assert session.status == "completed"
    assert session.proof_nonce is None
    assert len(captured_requests) == 1
    _url, body, _headers = captured_requests[0]
    assert body["proofs"] == {"jwt": ["externally-signed-jwt"]}


async def test_submit_wallet_proof_hands_the_credential_to_the_wallet() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _awaiting_proof_session(sessions)
    wallet = MockWalletAdapter()

    await submit_wallet_proof(
        session_id,
        "externally-signed-jwt",
        sessions=sessions,
        wallet=wallet,
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=_success_post,
    )

    assert wallet.received_credentials == [
        {
            "credential_configuration_id": "UniversityDegreeCredential",
            "credential": "opaque-jwt-vc",
        }
    ]


async def test_submit_wallet_proof_fails_the_session_when_issuer_metadata_is_invalid() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _awaiting_proof_session(sessions)

    async def broken_metadata(url: str) -> str:
        return "not-json"

    session = await submit_wallet_proof(
        session_id,
        "externally-signed-jwt",
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=broken_metadata,
    )

    assert session.status == "failed"
    assert session.error is not None


async def test_submit_wallet_proof_fails_the_session_when_the_request_is_rejected() -> None:
    sessions = IssuanceSessionStore()
    session_id = await _awaiting_proof_session(sessions)

    async def rejecting_post(
        url: str, body: dict[str, object], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return (
            400,
            {},
            '{"error": "invalid_proof", "error_description": "signature did not verify"}',
        )

    session = await submit_wallet_proof(
        session_id,
        "externally-signed-jwt",
        sessions=sessions,
        wallet=MockWalletAdapter(),
        fetch_issuer_metadata=_fetch_default_issuer_metadata,
        post_credential_request=rejecting_post,
    )

    assert session.status == "failed"
    assert session.error == "signature did not verify"
