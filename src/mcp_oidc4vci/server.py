import logging
import os
import sys
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
from mcp_oidc4vci.credential_request import (
    poll_deferred_credential as poll_deferred_credential_flow,
)
from mcp_oidc4vci.credential_request import request_credential as fetch_credential
from mcp_oidc4vci.credential_request import request_wallet_proof as begin_wallet_proof
from mcp_oidc4vci.credential_request import submit_wallet_proof as finish_wallet_proof
from mcp_oidc4vci.issuance import (
    IssuanceSession,
    IssuanceSessionNotFoundError,
    IssuanceSessionStore,
    SessionNotReadyError,
    UndeterminedIssuanceFlowError,
)
from mcp_oidc4vci.issuance import begin_authorization as begin_authorization_flow
from mcp_oidc4vci.issuance import describe_issuance_flow as build_issuance_flow_description
from mcp_oidc4vci.issuance import initiate_issuance as start_issuance
from mcp_oidc4vci.issuance import submit_authorization_result as finish_authorization
from mcp_oidc4vci.wallet import MockWalletAdapter

logger = logging.getLogger(__name__)

_DEBUG_TOOLS_ENV_VAR = "MCP_OIDC4VCI_DEBUG_TOOLS"
_TRUTHY_VALUES = {"1", "true", "yes"}

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
    grant, this resolves the Authorization Server's metadata and leaves the session
    `waiting_for_user_authorization`; call `begin_authorization` next. `tx_code` is the
    transaction code obtained from the user out-of-band, if the offer requires one.
    """
    try:
        session = await start_issuance(credential_offer, sessions=_sessions, tx_code=tx_code)
    except (InvalidCredentialOfferError, UndeterminedIssuanceFlowError) as exc:
        raise ToolError(str(exc)) from exc
    return _issuance_session_output(session)


@mcp.tool
async def begin_authorization(session_id: str, client_id: str, redirect_uri: str) -> dict[str, Any]:
    """Build the Authorization Request URL for a session waiting on the authorization code
    grant (`status == "waiting_for_user_authorization"`).

    `client_id` and `redirect_uri` must be whatever you've registered (or otherwise arranged)
    with the Authorization Server — this server has no client registration of its own to
    supply them for you. Returns the URL for a human to open and complete; the session moves
    to `awaiting_authorization_result`. This server cannot receive the resulting redirect
    itself, so once it completes, call submit_authorization_result with the `code` and
    `state` query parameters the redirect target ends up carrying.

    Hand the URL to the human immediately, and ask them to open it right away: when the
    Authorization Server requires Pushed Authorization Requests (RFC 9126), the URL embeds a
    `request_uri` that can expire in well under a minute — a real Authorization Server has
    been observed expiring one in about 60 seconds. If authorization fails with something
    like "invalid request" before the human even reaches a login page, the `request_uri` most
    likely expired; just call begin_authorization again for a fresh one rather than retrying
    the same URL.
    """
    try:
        session = await begin_authorization_flow(
            session_id, client_id=client_id, redirect_uri=redirect_uri, sessions=_sessions
        )
    except (IssuanceSessionNotFoundError, SessionNotReadyError) as exc:
        raise ToolError(str(exc)) from exc
    return _issuance_session_output(session)


@mcp.tool
async def submit_authorization_result(session_id: str, code: str, state: str) -> dict[str, Any]:
    """Complete the authorization code grant using the `code` and `state` obtained by opening
    the URL from `begin_authorization` and completing the redirect.

    A `state` that doesn't match what `begin_authorization` issued fails the session without
    making a Token Request. On success, the session ends `ready_for_credential_request` or
    `failed`, exactly like the pre-authorized code grant.
    """
    try:
        session = await finish_authorization(session_id, code, state, sessions=_sessions)
    except (IssuanceSessionNotFoundError, SessionNotReadyError) as exc:
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
    Its contents are never returned to the agent. If the Credential Issuer defers issuance
    instead of responding immediately, the session ends `awaiting_deferred_credential`
    instead of `completed`/`failed` — call poll_deferred_credential to check back later.
    """
    try:
        session = await fetch_credential(session_id, sessions=_sessions, wallet=_wallet)
    except (IssuanceSessionNotFoundError, SessionNotReadyError) as exc:
        raise ToolError(str(exc)) from exc
    return _issuance_session_output(session)


@mcp.tool
async def poll_deferred_credential(session_id: str) -> dict[str, Any]:
    """Check back on a session left `awaiting_deferred_credential` by request_credential or
    submit_wallet_proof.

    The session's status carries how long to wait: `deferred_interval`, in seconds, is the
    Credential Issuer's own suggested wait before polling again — this tool doesn't wait or
    retry on its own, so call it again no sooner than that. Ends `completed` once the
    credential is ready (handed straight to the wallet, same as request_credential) or
    `failed` if the issuer gives up on the pending request; otherwise stays
    `awaiting_deferred_credential`, possibly with an updated `deferred_interval`.
    """
    try:
        session = await poll_deferred_credential_flow(
            session_id, sessions=_sessions, wallet=_wallet
        )
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


def debug_inspect_mock_wallet_credentials() -> list[dict[str, Any]]:
    """DEBUG ONLY: list credentials the in-process MockWalletAdapter has received.

    Exists purely to inspect what a mock-wallet test run actually issued. This bypasses the
    wallet boundary on purpose, and only works because this server's wallet happens to be a
    MockWalletAdapter today — a real WalletAdapter would never expose this, since credential
    content is meant to stay with the wallet and never return through this server to the
    agent. Remove this tool once a real (non-mock) wallet is wired in.

    Only registered as an MCP tool when MCP_OIDC4VCI_DEBUG_TOOLS is set to a truthy value
    ("1", "true", or "yes") — otherwise it isn't even discoverable by a connected client.
    """
    return _wallet.received_credentials


def _debug_tools_enabled() -> bool:
    return os.environ.get(_DEBUG_TOOLS_ENV_VAR, "").strip().lower() in _TRUTHY_VALUES


if _debug_tools_enabled():  # pragma: no cover -- exercised via mcp.add_tool in tests, not env
    mcp.tool(debug_inspect_mock_wallet_credentials)
    logger.warning(
        "%s is enabled: debug_inspect_mock_wallet_credentials bypasses the wallet boundary "
        "and should only be used for local testing.",
        _DEBUG_TOOLS_ENV_VAR,
    )


def _issuance_session_output(session: IssuanceSession) -> dict[str, Any]:
    output: dict[str, Any] = {"session_id": session.session_id, "status": session.status}
    if session.error is not None:
        output["error"] = session.error
    if session.status == "awaiting_wallet_proof":
        proof_request: dict[str, Any] = {"audience": session.credential_issuer}
        if session.proof_nonce is not None:
            proof_request["nonce"] = session.proof_nonce
        output["proof_request"] = proof_request
    if session.status == "awaiting_authorization_result" and session.authorization_url is not None:
        output["authorization_url"] = session.authorization_url
    if session.status == "awaiting_deferred_credential" and session.deferred_interval is not None:
        output["deferred_interval"] = session.deferred_interval
    return output


def _configure_logging() -> None:
    # MCP servers typically talk to their client over stdio, so logs must go to stderr —
    # anything on stdout would corrupt the JSON-RPC stream.
    level_name = os.environ.get("MCP_OIDC4VCI_LOG_LEVEL", "INFO").strip().upper()
    level = logging.getLevelNamesMapping().get(level_name, logging.INFO)
    logging.basicConfig(
        level=level, stream=sys.stderr, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )


def main() -> None:
    _configure_logging()
    mcp.run()
