"""Credential Request orchestration (spec "Credential Endpoint" / "Credential Request").

Ties together Credential Issuer Metadata, the Nonce Endpoint, and a WalletAdapter to obtain
one issued credential for a session that has already completed a Token Request.
"""

import json
from collections.abc import Awaitable, Callable

import httpx
from pydantic import ValidationError

from mcp_oidc4vci.credential_issuer_metadata import (
    InvalidCredentialIssuerMetadataError,
    MetadataFetcher,
    get_credential_issuer_metadata,
)
from mcp_oidc4vci.issuance import IssuanceSession, IssuanceSessionStore
from mcp_oidc4vci.models import (
    CredentialErrorResponse,
    CredentialIssuerMetadata,
    CredentialResponse,
)
from mcp_oidc4vci.nonce import InvalidNonceResponseError, NoncePoster, request_nonce
from mcp_oidc4vci.wallet import WalletAdapter

CredentialRequester = Callable[[str, dict[str, object], str], Awaitable[tuple[int, str]]]

_HTTP_TIMEOUT_SECONDS = 10.0


class CredentialRequestError(Exception):
    """Base error for problems performing a Credential Request."""


class SessionNotReadyError(CredentialRequestError):
    """The session is not in a state that allows a Credential Request."""


class CredentialRequestRejectedError(CredentialRequestError):
    """The Credential Issuer rejected the Credential Request with a well-formed error."""

    def __init__(self, error: str, error_description: str | None) -> None:
        self.error = error
        self.error_description = error_description
        super().__init__(error_description or error)


class InvalidCredentialResponseError(CredentialRequestError):
    """The Credential Issuer's response could not be understood."""


async def request_credential(
    session_id: str,
    *,
    sessions: IssuanceSessionStore,
    wallet: WalletAdapter,
    fetch_issuer_metadata: MetadataFetcher | None = None,
    fetch_nonce: NoncePoster | None = None,
    post_credential_request: CredentialRequester | None = None,
) -> IssuanceSession:
    """Complete the Credential Request for a session that already has an access token,
    automatically, using the configured `WalletAdapter` to produce the proof.

    Requests a fresh `c_nonce` when the issuer has a Nonce Endpoint, asks the wallet to
    generate a proof of possession over it, sends the Credential Request, and hands each
    issued credential to the wallet. The session ends `completed` or `failed` — the
    credential's content is never returned to the caller.

    Use `request_wallet_proof` / `submit_wallet_proof` instead when the proof must be
    produced by something outside this process (e.g. a real wallet) rather than
    synchronously by an in-process `WalletAdapter`.
    """
    session = await sessions.get(session_id)
    _require_status(session, "ready_for_credential_request", need_access_token=True)

    try:
        issuer_metadata, c_nonce = await _prepare_proof_request(
            session, fetch_issuer_metadata=fetch_issuer_metadata, fetch_nonce=fetch_nonce
        )
        proof = await wallet.generate_proof(audience=session.credential_issuer, nonce=c_nonce)
    except (InvalidCredentialIssuerMetadataError, InvalidNonceResponseError) as exc:
        return await sessions.update(session.session_id, status="failed", error=str(exc))

    return await _send_credential_request(
        session,
        issuer_metadata.credential_endpoint,
        proof,
        wallet,
        sessions,
        post_credential_request=post_credential_request,
    )


async def request_wallet_proof(
    session_id: str,
    *,
    sessions: IssuanceSessionStore,
    fetch_issuer_metadata: MetadataFetcher | None = None,
    fetch_nonce: NoncePoster | None = None,
) -> IssuanceSession:
    """Manual path, step 1 of 2: describe what needs signing, without asking a
    `WalletAdapter` to sign it automatically.

    Moves the session to `awaiting_wallet_proof` and records the audience/nonce to sign
    (surfaced by the caller alongside `session_id`/`status`). Pairs with
    `submit_wallet_proof`, which completes the Credential Request once a proof produced
    outside this process — by a real wallet, or by hand for testing — is available.
    """
    session = await sessions.get(session_id)
    _require_status(session, "ready_for_credential_request", need_access_token=True)

    try:
        _issuer_metadata, c_nonce = await _prepare_proof_request(
            session, fetch_issuer_metadata=fetch_issuer_metadata, fetch_nonce=fetch_nonce
        )
    except (InvalidCredentialIssuerMetadataError, InvalidNonceResponseError) as exc:
        return await sessions.update(session.session_id, status="failed", error=str(exc))

    return await sessions.update(
        session.session_id, status="awaiting_wallet_proof", proof_nonce=c_nonce
    )


async def submit_wallet_proof(
    session_id: str,
    proof_jwt: str,
    *,
    sessions: IssuanceSessionStore,
    wallet: WalletAdapter,
    fetch_issuer_metadata: MetadataFetcher | None = None,
    post_credential_request: CredentialRequester | None = None,
) -> IssuanceSession:
    """Manual path, step 2 of 2: complete the Credential Request with a proof produced
    outside this server, in response to `request_wallet_proof`.

    Still hands the issued credential to `wallet.receive_credential` — that part of the
    boundary applies regardless of who signed the proof.
    """
    session = await sessions.get(session_id)
    _require_status(session, "awaiting_wallet_proof")

    try:
        issuer_metadata = await get_credential_issuer_metadata(
            session.credential_issuer, fetch=fetch_issuer_metadata
        )
    except InvalidCredentialIssuerMetadataError as exc:
        return await sessions.update(session.session_id, status="failed", error=str(exc))

    return await _send_credential_request(
        session,
        issuer_metadata.credential_endpoint,
        proof_jwt,
        wallet,
        sessions,
        post_credential_request=post_credential_request,
    )


def _require_status(
    session: IssuanceSession, expected_status: str, *, need_access_token: bool = False
) -> None:
    if session.status != expected_status or (need_access_token and session.access_token is None):
        raise SessionNotReadyError(
            f"Session {session.session_id!r} is not ready (expected status "
            f"{expected_status!r}, has {session.status!r})."
        )


async def _prepare_proof_request(
    session: IssuanceSession,
    *,
    fetch_issuer_metadata: MetadataFetcher | None,
    fetch_nonce: NoncePoster | None,
) -> tuple[CredentialIssuerMetadata, str | None]:
    issuer_metadata = await get_credential_issuer_metadata(
        session.credential_issuer, fetch=fetch_issuer_metadata
    )
    c_nonce = None
    if issuer_metadata.nonce_endpoint is not None:
        c_nonce = await request_nonce(issuer_metadata.nonce_endpoint, post=fetch_nonce)
    return issuer_metadata, c_nonce


async def _send_credential_request(
    session: IssuanceSession,
    credential_endpoint: str,
    proof: str,
    wallet: WalletAdapter,
    sessions: IssuanceSessionStore,
    *,
    post_credential_request: CredentialRequester | None,
) -> IssuanceSession:
    assert session.access_token is not None
    credential_configuration_id = session.credential_configuration_ids[0]

    try:
        status_code, body = await (post_credential_request or _post_credential_request)(
            credential_endpoint,
            {
                "credential_configuration_id": credential_configuration_id,
                "proofs": {"jwt": [proof]},
            },
            session.access_token,
        )
        response = _parse_credential_response(status_code, body)
    except (CredentialRequestRejectedError, InvalidCredentialResponseError) as exc:
        return await sessions.update(session.session_id, status="failed", error=str(exc))

    if response.transaction_id is not None:
        return await sessions.update(
            session.session_id,
            status="failed",
            error="Credential issuance was deferred; deferred issuance is not yet supported.",
        )

    # _parse_credential_response guarantees credentials is set whenever transaction_id isn't.
    assert response.credentials is not None
    for issued in response.credentials:
        await wallet.receive_credential(
            credential_configuration_id=credential_configuration_id, credential=issued.credential
        )

    return await sessions.update(session.session_id, status="completed")


def _parse_credential_response(status_code: int, body: str) -> CredentialResponse:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise InvalidCredentialResponseError(
            f"Credential endpoint response is not valid JSON: {exc}"
        ) from exc

    if 200 <= status_code < 300:
        try:
            response = CredentialResponse.model_validate(payload)
        except ValidationError as exc:
            raise InvalidCredentialResponseError(
                f"Credential endpoint success response does not match the expected structure: {exc}"
            ) from exc
        if response.credentials is None and response.transaction_id is None:
            raise InvalidCredentialResponseError(
                "Credential endpoint success response contains neither 'credentials' nor "
                "'transaction_id'."
            )
        return response

    try:
        error = CredentialErrorResponse.model_validate(payload)
    except ValidationError as exc:
        raise InvalidCredentialResponseError(
            f"Credential endpoint error response does not match the expected structure: {exc}"
        ) from exc
    raise CredentialRequestRejectedError(error.error, error.error_description)


async def _post_credential_request(
    url: str, body: dict[str, object], access_token: str
) -> tuple[int, str]:
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
        response = await client.post(
            url, json=body, headers={"Authorization": f"Bearer {access_token}"}
        )
        return response.status_code, response.text
