import json
from urllib.parse import quote

import pytest

from mcp_oidc4vci.credential_offer import InvalidCredentialOfferError
from mcp_oidc4vci.issuance import (
    AUTHORIZATION_CODE_FLOW,
    IssuanceSessionNotFoundError,
    IssuanceSessionStore,
    UndeterminedIssuanceFlowError,
    describe_issuance_flow,
    initiate_issuance,
    select_flow_type,
)
from mcp_oidc4vci.models import (
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
    AuthorizationCodeGrant,
    CredentialOffer,
    CredentialOfferGrants,
)

ISSUER = "https://issuer.example.com"


def _offer(**kwargs: object) -> CredentialOffer:
    return CredentialOffer.model_validate(
        {
            "credential_issuer": ISSUER,
            "credential_configuration_ids": ["UniversityDegreeCredential"],
            **kwargs,
        }
    )


def _offer_uri(payload: str) -> str:
    return f"openid-credential-offer://?credential_offer={quote(payload, safe='')}"


async def _fail_if_fetched(url: str) -> str:
    raise AssertionError(f"unexpected metadata fetch for {url!r}")


async def _fail_if_posted(
    url: str, data: dict[str, str], headers: dict[str, str]
) -> tuple[int, dict[str, str], str]:
    raise AssertionError(f"unexpected token request to {url!r}")


def _pre_authorized_offer_json(
    *, authorization_server: str | None = None, tx_code: bool = False
) -> str:
    grant: dict[str, object] = {"pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5"}
    if authorization_server is not None:
        grant["authorization_server"] = authorization_server
    if tx_code:
        grant["tx_code"] = {"length": 4}
    return (
        f'{{"credential_issuer": "{ISSUER}", '
        '"credential_configuration_ids": ["UniversityDegreeCredential"], '
        f'"grants": {{"{PRE_AUTHORIZED_CODE_GRANT_TYPE}": {json.dumps(grant)}}}}}'
    )


# -- select_flow_type -------------------------------------------------------


def test_select_flow_type_prefers_pre_authorized_code_when_both_are_present() -> None:
    offer = _offer(
        grants=CredentialOfferGrants.model_validate(
            {
                "authorization_code": {},
                PRE_AUTHORIZED_CODE_GRANT_TYPE: {"pre-authorized_code": "abc"},
            }
        )
    )

    assert select_flow_type(offer) == PRE_AUTHORIZED_CODE_GRANT_TYPE


def test_select_flow_type_picks_authorization_code_when_that_is_all_thats_offered() -> None:
    offer = _offer(grants=CredentialOfferGrants(authorization_code=AuthorizationCodeGrant()))

    assert select_flow_type(offer) == AUTHORIZATION_CODE_FLOW


def test_select_flow_type_raises_when_grants_is_absent() -> None:
    with pytest.raises(UndeterminedIssuanceFlowError):
        select_flow_type(_offer())


def test_select_flow_type_raises_when_grants_is_present_but_empty() -> None:
    with pytest.raises(UndeterminedIssuanceFlowError):
        select_flow_type(_offer(grants=CredentialOfferGrants()))


# -- describe_issuance_flow ---------------------------------------------------


async def test_describe_issuance_flow_for_the_pre_authorized_code_grant() -> None:
    description = await describe_issuance_flow(_offer_uri(_pre_authorized_offer_json()))

    assert description.flow_type == PRE_AUTHORIZED_CODE_GRANT_TYPE
    assert [step.action for step in description.steps] == [
        "token_request",
        "wallet_proof",
        "credential_request",
    ]


async def test_describe_issuance_flow_for_the_authorization_code_grant() -> None:
    payload = (
        f'{{"credential_issuer": "{ISSUER}", '
        '"credential_configuration_ids": ["UniversityDegreeCredential"], '
        '"grants": {"authorization_code": {}}}'
    )

    description = await describe_issuance_flow(_offer_uri(payload))

    assert description.flow_type == AUTHORIZATION_CODE_FLOW
    assert [step.action for step in description.steps] == [
        "user_authorization",
        "wallet_proof",
        "credential_request",
    ]


async def test_describe_issuance_flow_propagates_an_invalid_offer() -> None:
    with pytest.raises(InvalidCredentialOfferError):
        await describe_issuance_flow("openid-credential-offer://")


async def test_describe_issuance_flow_propagates_an_undetermined_flow() -> None:
    payload = (
        f'{{"credential_issuer": "{ISSUER}", '
        '"credential_configuration_ids": ["UniversityDegreeCredential"]}'
    )

    with pytest.raises(UndeterminedIssuanceFlowError):
        await describe_issuance_flow(_offer_uri(payload))


# -- IssuanceSessionStore -----------------------------------------------------


async def test_session_store_create_then_get_round_trips() -> None:
    store = IssuanceSessionStore()

    created = await store.create(
        credential_issuer=ISSUER,
        credential_configuration_ids=["UniversityDegreeCredential"],
        flow_type=AUTHORIZATION_CODE_FLOW,
    )
    fetched = await store.get(created.session_id)

    assert fetched is created
    assert fetched.status == "created"


async def test_session_store_update_changes_status_and_error() -> None:
    store = IssuanceSessionStore()
    session = await store.create(
        credential_issuer=ISSUER,
        credential_configuration_ids=["x"],
        flow_type=AUTHORIZATION_CODE_FLOW,
    )

    updated = await store.update(session.session_id, status="failed", error="boom")

    assert updated.status == "failed"
    assert updated.error == "boom"


async def test_session_store_update_sets_and_clears_proof_nonce() -> None:
    store = IssuanceSessionStore()
    session = await store.create(
        credential_issuer=ISSUER,
        credential_configuration_ids=["x"],
        flow_type=AUTHORIZATION_CODE_FLOW,
    )

    awaiting = await store.update(
        session.session_id, status="awaiting_wallet_proof", proof_nonce="fresh-nonce"
    )
    assert awaiting.proof_nonce == "fresh-nonce"

    completed = await store.update(session.session_id, status="completed")
    assert completed.proof_nonce is None


async def test_session_store_get_raises_for_an_unknown_session() -> None:
    with pytest.raises(IssuanceSessionNotFoundError):
        await IssuanceSessionStore().get("does-not-exist")


async def test_session_store_update_raises_for_an_unknown_session() -> None:
    with pytest.raises(IssuanceSessionNotFoundError):
        await IssuanceSessionStore().update("does-not-exist", status="failed")


# -- initiate_issuance: authorization_code grant ------------------------------


async def test_initiate_issuance_for_authorization_code_needs_no_network_calls() -> None:
    payload = (
        f'{{"credential_issuer": "{ISSUER}", '
        '"credential_configuration_ids": ["UniversityDegreeCredential"], '
        '"grants": {"authorization_code": {}}}'
    )

    session = await initiate_issuance(
        _offer_uri(payload),
        sessions=IssuanceSessionStore(),
        fetch_as_metadata=_fail_if_fetched,
        post_token_request=_fail_if_posted,
    )

    assert session.status == "waiting_for_user_authorization"
    assert session.flow_type == AUTHORIZATION_CODE_FLOW


# -- initiate_issuance: pre-authorized_code grant -----------------------------


async def test_initiate_issuance_completes_the_token_exchange_on_success() -> None:
    requested_as_issuer: list[str] = []

    async def fake_as_metadata(url: str) -> str:
        requested_as_issuer.append(url)
        return '{"issuer": "https://issuer.example.com", "token_endpoint": "https://issuer.example.com/token"}'

    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        assert url == "https://issuer.example.com/token"
        return 200, {}, '{"access_token": "secret-token", "token_type": "Bearer"}'

    session = await initiate_issuance(
        _offer_uri(_pre_authorized_offer_json()),
        sessions=IssuanceSessionStore(),
        fetch_as_metadata=fake_as_metadata,
        post_token_request=fake_post,
    )

    assert session.status == "ready_for_credential_request"
    assert session.access_token == "secret-token"
    assert requested_as_issuer == [
        "https://issuer.example.com/.well-known/oauth-authorization-server"
    ]
    # AS metadata here doesn't advertise DPoP support, so no key should be generated.
    assert session.dpop_key is None
    assert session.dpop_bound is False


async def test_initiate_issuance_uses_the_grants_authorization_server_hint_when_present() -> None:
    requested_urls: list[str] = []

    async def fake_as_metadata(url: str) -> str:
        requested_urls.append(url)
        return (
            '{"issuer": "https://as.example.com", "token_endpoint": "https://as.example.com/token"}'
        )

    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 200, {}, '{"access_token": "secret-token", "token_type": "Bearer"}'

    await initiate_issuance(
        _offer_uri(_pre_authorized_offer_json(authorization_server="https://as.example.com")),
        sessions=IssuanceSessionStore(),
        fetch_as_metadata=fake_as_metadata,
        post_token_request=fake_post,
    )

    assert requested_urls == ["https://as.example.com/.well-known/oauth-authorization-server"]


async def test_initiate_issuance_sends_the_provided_tx_code() -> None:
    captured: dict[str, str] = {}

    async def fake_as_metadata(url: str) -> str:
        return '{"issuer": "https://issuer.example.com", "token_endpoint": "https://issuer.example.com/token"}'

    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured.update(data)
        return 200, {}, '{"access_token": "secret-token", "token_type": "Bearer"}'

    await initiate_issuance(
        _offer_uri(_pre_authorized_offer_json(tx_code=True)),
        sessions=IssuanceSessionStore(),
        tx_code="493536",
        fetch_as_metadata=fake_as_metadata,
        post_token_request=fake_post,
    )

    assert captured["tx_code"] == "493536"


async def test_initiate_issuance_fails_fast_when_a_required_tx_code_is_missing() -> None:
    session = await initiate_issuance(
        _offer_uri(_pre_authorized_offer_json(tx_code=True)),
        sessions=IssuanceSessionStore(),
        fetch_as_metadata=_fail_if_fetched,
        post_token_request=_fail_if_posted,
    )

    assert session.status == "failed"
    assert session.error is not None
    assert "transaction code" in session.error.lower()


async def test_initiate_issuance_fails_the_session_when_as_metadata_is_invalid() -> None:
    async def broken_as_metadata(url: str) -> str:
        return "not-json"

    session = await initiate_issuance(
        _offer_uri(_pre_authorized_offer_json()),
        sessions=IssuanceSessionStore(),
        fetch_as_metadata=broken_as_metadata,
        post_token_request=_fail_if_posted,
    )

    assert session.status == "failed"
    assert session.error is not None


async def test_initiate_issuance_fails_the_session_when_the_token_request_is_rejected() -> None:
    async def fake_as_metadata(url: str) -> str:
        return '{"issuer": "https://issuer.example.com", "token_endpoint": "https://issuer.example.com/token"}'

    async def rejecting_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        return 400, {}, '{"error": "invalid_grant", "error_description": "code expired"}'

    session = await initiate_issuance(
        _offer_uri(_pre_authorized_offer_json()),
        sessions=IssuanceSessionStore(),
        fetch_as_metadata=fake_as_metadata,
        post_token_request=rejecting_post,
    )

    assert session.status == "failed"
    assert session.error == "code expired"


# -- initiate_issuance: DPoP (RFC 9449) ---------------------------------------


async def test_initiate_issuance_attaches_dpop_and_marks_session_bound() -> None:
    captured_headers: list[dict[str, str]] = []

    async def fake_as_metadata(url: str) -> str:
        return (
            '{"issuer": "https://issuer.example.com", '
            '"token_endpoint": "https://issuer.example.com/token", '
            '"dpop_signing_alg_values_supported": ["ES256"]}'
        )

    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured_headers.append(headers)
        return 200, {}, '{"access_token": "secret-token", "token_type": "DPoP"}'

    session = await initiate_issuance(
        _offer_uri(_pre_authorized_offer_json()),
        sessions=IssuanceSessionStore(),
        fetch_as_metadata=fake_as_metadata,
        post_token_request=fake_post,
    )

    assert session.status == "ready_for_credential_request"
    assert session.dpop_bound is True
    assert session.dpop_key is not None
    assert "DPoP" in captured_headers[0]


async def test_initiate_issuance_keeps_session_unbound_when_as_returns_bearer() -> None:
    async def fake_as_metadata(url: str) -> str:
        return (
            '{"issuer": "https://issuer.example.com", '
            '"token_endpoint": "https://issuer.example.com/token", '
            '"dpop_signing_alg_values_supported": ["ES256"]}'
        )

    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        # The AS advertised DPoP, so a proof is still offered, but it chose not to bind.
        return 200, {}, '{"access_token": "secret-token", "token_type": "Bearer"}'

    session = await initiate_issuance(
        _offer_uri(_pre_authorized_offer_json()),
        sessions=IssuanceSessionStore(),
        fetch_as_metadata=fake_as_metadata,
        post_token_request=fake_post,
    )

    assert session.dpop_bound is False


async def test_initiate_issuance_skips_dpop_when_as_only_advertises_an_unsupported_alg() -> None:
    captured_headers: list[dict[str, str]] = []

    async def fake_as_metadata(url: str) -> str:
        return (
            '{"issuer": "https://issuer.example.com", '
            '"token_endpoint": "https://issuer.example.com/token", '
            '"dpop_signing_alg_values_supported": ["RS256"]}'
        )

    async def fake_post(
        url: str, data: dict[str, str], headers: dict[str, str]
    ) -> tuple[int, dict[str, str], str]:
        captured_headers.append(headers)
        return 200, {}, '{"access_token": "secret-token", "token_type": "Bearer"}'

    session = await initiate_issuance(
        _offer_uri(_pre_authorized_offer_json()),
        sessions=IssuanceSessionStore(),
        fetch_as_metadata=fake_as_metadata,
        post_token_request=fake_post,
    )

    assert session.dpop_key is None
    assert "DPoP" not in captured_headers[0]


# -- initiate_issuance: upfront failures create no session --------------------


async def test_initiate_issuance_propagates_an_invalid_offer_without_creating_a_session() -> None:
    store = IssuanceSessionStore()

    with pytest.raises(InvalidCredentialOfferError):
        await initiate_issuance("openid-credential-offer://", sessions=store)

    assert store._sessions == {}


async def test_initiate_issuance_propagates_an_undetermined_flow_without_creating_a_session() -> (
    None
):
    store = IssuanceSessionStore()
    payload = (
        f'{{"credential_issuer": "{ISSUER}", '
        '"credential_configuration_ids": ["UniversityDegreeCredential"]}'
    )

    with pytest.raises(UndeterminedIssuanceFlowError):
        await initiate_issuance(_offer_uri(payload), sessions=store)

    assert store._sessions == {}
