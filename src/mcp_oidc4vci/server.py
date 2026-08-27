from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from mcp_oidc4vci.credential_issuer_metadata import (
    InvalidCredentialIssuerMetadataError,
)
from mcp_oidc4vci.credential_issuer_metadata import (
    get_credential_issuer_metadata as fetch_credential_issuer_metadata,
)
from mcp_oidc4vci.credential_offer import InvalidCredentialOfferError, resolve_credential_offer
from mcp_oidc4vci.credential_request import SessionNotReadyError
from mcp_oidc4vci.credential_request import request_credential as fetch_credential
from mcp_oidc4vci.credential_request import request_wallet_proof as begin_wallet_proof
from mcp_oidc4vci.credential_request import submit_wallet_proof as finish_wallet_proof
from mcp_oidc4vci.issuance import (
    IssuanceSession,
    IssuanceSessionNotFoundError,
    IssuanceSessionStore,
    UndeterminedIssuanceFlowError,
)
from mcp_oidc4vci.issuance import describe_issuance_flow as build_issuance_flow_description
from mcp_oidc4vci.issuance import initiate_issuance as start_issuance
from mcp_oidc4vci.wallet import MockWalletAdapter

mcp = FastMCP(name="oidc4vci")
_sessions = IssuanceSessionStore()
_wallet = MockWalletAdapter()


@mcp.tool
async def inspect_credential_offer(credential_offer: str) -> dict[str, Any]:
    """Parse and validate an OIDC4VCI Credential Offer URI.

    Resolves the offer (by value or by reference) and returns its Credential Issuer,
    requested credential configuration IDs, and available grants.
    """
    try:
        offer = await resolve_credential_offer(credential_offer)
    except InvalidCredentialOfferError as exc:
        raise ToolError(str(exc)) from exc
    return offer.model_dump(mode="json", exclude_none=True, by_alias=True)


@mcp.tool
async def get_credential_issuer_metadata(credential_issuer: str) -> dict[str, Any]:
    """Fetch and validate a Credential Issuer's metadata from its well-known endpoint.

    Returns the issuer's credential endpoint, authorization servers, and the credential
    configurations it supports.
    """
    try:
        metadata = await fetch_credential_issuer_metadata(credential_issuer)
    except InvalidCredentialIssuerMetadataError as exc:
        raise ToolError(str(exc)) from exc
    return metadata.model_dump(mode="json", exclude_none=True, by_alias=True)


@mcp.tool
async def describe_issuance_flow(credential_offer: str) -> dict[str, Any]:
    """Describe the steps required to obtain the credential(s) offered by a Credential Offer.

    Resolves the offer and returns which grant-based flow applies and its ordered steps.
    """
    try:
        description = await build_issuance_flow_description(credential_offer)
    except (InvalidCredentialOfferError, UndeterminedIssuanceFlowError) as exc:
        raise ToolError(str(exc)) from exc
    return description.model_dump(mode="json")


@mcp.tool
async def initiate_issuance(credential_offer: str, tx_code: str | None = None) -> dict[str, Any]:
    """Start an issuance session for a Credential Offer.

    For the pre-authorized code grant, completes the token exchange immediately and the
    session ends `ready_for_credential_request` or `failed`. For the authorization code
    grant, the session is left `waiting_for_user_authorization`, since completing it requires
    a wallet-driven redirect not yet implemented. `tx_code` is the transaction code obtained
    from the user out-of-band, if the offer requires one.
    """
    try:
        session = await start_issuance(credential_offer, sessions=_sessions, tx_code=tx_code)
    except (InvalidCredentialOfferError, UndeterminedIssuanceFlowError) as exc:
        raise ToolError(str(exc)) from exc
    return _issuance_session_output(session)


@mcp.tool
async def get_issuance_status(session_id: str) -> dict[str, Any]:
    """Return the current state of a previously started issuance session."""
    try:
        session = await _sessions.get(session_id)
    except IssuanceSessionNotFoundError as exc:
        raise ToolError(str(exc)) from exc
    return _issuance_session_output(session)


@mcp.tool
async def request_credential(session_id: str) -> dict[str, Any]:
    """Complete the Credential Request for a session that has an access token.

    Generates a key proof of possession through the wallet adapter — this server never
    signs anything itself — and hands the issued credential to the wallet for safekeeping.
    Its contents are never returned to the agent.
    """
    try:
        session = await fetch_credential(session_id, sessions=_sessions, wallet=_wallet)
    except (IssuanceSessionNotFoundError, SessionNotReadyError) as exc:
        raise ToolError(str(exc)) from exc
    return _issuance_session_output(session)


@mcp.tool
async def request_wallet_proof(session_id: str) -> dict[str, Any]:
    """Ask what needs to be signed to complete a Credential Request, without asking any
    wallet adapter to sign it automatically.

    Use this instead of request_credential when the proof must be produced by something
    outside this server — a real wallet, or a human signing by hand. Returns the audience
    and (if the issuer requires one) nonce to sign; the session moves to
    `awaiting_wallet_proof`. Call submit_wallet_proof with the result once you have it.
    """
    try:
        session = await begin_wallet_proof(session_id, sessions=_sessions)
    except (IssuanceSessionNotFoundError, SessionNotReadyError) as exc:
        raise ToolError(str(exc)) from exc
    return _issuance_session_output(session)


@mcp.tool
async def submit_wallet_proof(session_id: str, proof_jwt: str) -> dict[str, Any]:
    """Complete a Credential Request using a proof produced outside this server, in
    response to request_wallet_proof.

    Hands the issued credential to the wallet adapter for safekeeping, same as
    request_credential — its contents are never returned to the agent.
    """
    try:
        session = await finish_wallet_proof(
            session_id, proof_jwt, sessions=_sessions, wallet=_wallet
        )
    except (IssuanceSessionNotFoundError, SessionNotReadyError) as exc:
        raise ToolError(str(exc)) from exc
    return _issuance_session_output(session)


def _issuance_session_output(session: IssuanceSession) -> dict[str, Any]:
    output: dict[str, Any] = {"session_id": session.session_id, "status": session.status}
    if session.error is not None:
        output["error"] = session.error
    if session.status == "awaiting_wallet_proof":
        proof_request: dict[str, Any] = {"audience": session.credential_issuer}
        if session.proof_nonce is not None:
            proof_request["nonce"] = session.proof_nonce
        output["proof_request"] = proof_request
    return output


def main() -> None:
    mcp.run()
