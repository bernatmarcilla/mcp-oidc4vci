"""Issuance flow determination and orchestration.

Covers the "Authorization Code Flow" and "Pre-Authorized Code Flow" sections of the spec,
plus in-memory tracking of issuance sessions across the separate MCP tool calls that make up
one issuance (`initiate_issuance` followed by one or more `get_issuance_status` calls).
"""

import asyncio
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from mcp_oidc4vci.authorization_server_metadata import (
    InvalidAuthorizationServerMetadataError,
    MetadataFetcher,
    get_authorization_server_metadata,
)
from mcp_oidc4vci.credential_offer import CredentialOfferFetcher, resolve_credential_offer
from mcp_oidc4vci.dpop import SUPPORTED_DPOP_SIGNING_ALG, DPoPKey
from mcp_oidc4vci.models import (
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
    AuthorizationServerMetadata,
    CredentialOffer,
    IssuanceFlowDescription,
    IssuanceFlowStep,
)
from mcp_oidc4vci.token_request import (
    InvalidTokenResponseError,
    TokenRequester,
    TokenRequestRejectedError,
    request_token_with_pre_authorized_code,
)

logger = logging.getLogger(__name__)

AUTHORIZATION_CODE_FLOW = "authorization_code"
DEFAULT_SESSION_TTL_SECONDS = 3600.0

_FLOW_STEPS: dict[str, list[IssuanceFlowStep]] = {
    AUTHORIZATION_CODE_FLOW: [
        IssuanceFlowStep(
            step=1,
            action="user_authorization",
            description="The user must authorize credential issuance.",
        ),
        IssuanceFlowStep(
            step=2,
            action="wallet_proof",
            description="A proof may be required during the credential request.",
        ),
        IssuanceFlowStep(
            step=3,
            action="credential_request",
            description="The credential can be requested from the issuer.",
        ),
    ],
    PRE_AUTHORIZED_CODE_GRANT_TYPE: [
        IssuanceFlowStep(
            step=1,
            action="token_request",
            description="Exchange the pre-authorized code (and transaction code, if "
            "required) for an access token.",
        ),
        IssuanceFlowStep(
            step=2,
            action="wallet_proof",
            description="A proof may be required during the credential request.",
        ),
        IssuanceFlowStep(
            step=3,
            action="credential_request",
            description="The credential can be requested from the issuer.",
        ),
    ],
}


class IssuanceError(Exception):
    """Base error for problems determining or orchestrating an issuance flow."""


class UndeterminedIssuanceFlowError(IssuanceError):
    """The flow to use cannot be determined from the offer alone."""


class IssuanceSessionNotFoundError(IssuanceError):
    """No issuance session exists for the given session_id."""


def select_flow_type(offer: CredentialOffer) -> str:
    """Pick which declared grant to use (spec: "at the Wallet's discretion" when more than
    one is present). Prefers the pre-authorized code grant, since it needs no interactive
    redirect to an external Authorization Server.
    """
    if offer.grants is None:
        raise UndeterminedIssuanceFlowError(
            "The offer does not declare 'grants'; determining the flow from Authorization "
            "Server metadata alone is not yet supported."
        )
    if offer.grants.pre_authorized_code is not None:
        return PRE_AUTHORIZED_CODE_GRANT_TYPE
    if offer.grants.authorization_code is not None:
        return AUTHORIZATION_CODE_FLOW
    raise UndeterminedIssuanceFlowError(
        "The offer's 'grants' object declares no supported grant type."
    )


async def describe_issuance_flow(
    credential_offer: str, *, fetch: CredentialOfferFetcher | None = None
) -> IssuanceFlowDescription:
    """Resolve the offer and describe the steps required to obtain the offered credential."""
    offer = await resolve_credential_offer(credential_offer, fetch=fetch)
    flow_type = select_flow_type(offer)
    return IssuanceFlowDescription(flow_type=flow_type, steps=_FLOW_STEPS[flow_type])


@dataclass
class IssuanceSession:
    """Server-side issuance session state.

    `access_token` is intentionally never surfaced by `get_issuance_status` — it stays
    server-side per the "MCP exposes capabilities, not raw secrets" design principle.
    `proof_nonce` only has a value while `status == "awaiting_wallet_proof"` — the manual
    proof handoff between `request_wallet_proof` and `submit_wallet_proof`. `dpop_key` and
    `dpop_bound` carry the RFC 9449 DPoP key generated for this session (when the
    Authorization Server advertises support) and whether the resulting access token ended
    up DPoP-bound, so a later `request_credential` call can present it the same way.
    """

    session_id: str
    credential_issuer: str
    credential_configuration_ids: list[str]
    flow_type: str
    status: str
    error: str | None = None
    access_token: str | None = None
    proof_nonce: str | None = None
    dpop_key: DPoPKey | None = None
    dpop_bound: bool = False
    created_at: float = field(default_factory=time.monotonic)


class IssuanceSessionStore:
    """In-memory issuance session store, keyed by session_id.

    Process-local: sessions do not survive a server restart and are not shared across
    server instances. Sufficient for the current single-process MVP. Sessions older than
    `ttl_seconds` (measured from creation, not last access) are evicted lazily on the next
    store operation rather than by a background sweep — a session's natural lifetime is one
    issuance flow, so there's no need to poll for expiry between calls. An expired
    session_id behaves exactly like an unknown one.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_SESSION_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._sessions: dict[str, IssuanceSession] = {}
        self._lock = asyncio.Lock()
        self._ttl_seconds = ttl_seconds
        self._clock = clock

    def _evict_expired_locked(self) -> None:
        now = self._clock()
        expired = [
            session_id
            for session_id, session in self._sessions.items()
            if now - session.created_at > self._ttl_seconds
        ]
        for session_id in expired:
            del self._sessions[session_id]
        if expired:
            logger.info("Evicted %d expired issuance session(s).", len(expired))

    async def create(
        self, *, credential_issuer: str, credential_configuration_ids: list[str], flow_type: str
    ) -> IssuanceSession:
        session = IssuanceSession(
            session_id=str(uuid.uuid4()),
            credential_issuer=credential_issuer,
            credential_configuration_ids=credential_configuration_ids,
            flow_type=flow_type,
            status="created",
            created_at=self._clock(),
        )
        async with self._lock:
            self._evict_expired_locked()
            self._sessions[session.session_id] = session
        logger.info(
            "Created issuance session %s for issuer %r (flow=%r).",
            session.session_id,
            credential_issuer,
            flow_type,
        )
        return session

    async def update(
        self,
        session_id: str,
        *,
        status: str,
        error: str | None = None,
        access_token: str | None = None,
        proof_nonce: str | None = None,
        dpop_key: DPoPKey | None = None,
        dpop_bound: bool | None = None,
    ) -> IssuanceSession:
        async with self._lock:
            self._evict_expired_locked()
            session = self._sessions.get(session_id)
            if session is None:
                raise IssuanceSessionNotFoundError(f"No issuance session found for {session_id!r}.")
            session.status = status
            session.error = error
            session.proof_nonce = proof_nonce
            if access_token is not None:
                session.access_token = access_token
            if dpop_key is not None:
                session.dpop_key = dpop_key
            if dpop_bound is not None:
                session.dpop_bound = dpop_bound
            return session

    async def get(self, session_id: str) -> IssuanceSession:
        async with self._lock:
            self._evict_expired_locked()
            session = self._sessions.get(session_id)
        if session is None:
            raise IssuanceSessionNotFoundError(f"No issuance session found for {session_id!r}.")
        return session


async def initiate_issuance(
    credential_offer: str,
    *,
    sessions: IssuanceSessionStore,
    tx_code: str | None = None,
    fetch_offer: CredentialOfferFetcher | None = None,
    fetch_as_metadata: MetadataFetcher | None = None,
    post_token_request: TokenRequester | None = None,
) -> IssuanceSession:
    """Start an issuance session for the offer's chosen flow.

    For the pre-authorized code grant, completes the token exchange immediately (it needs no
    user interaction); the session ends "ready_for_credential_request" or "failed". For the
    authorization code grant, the session is left "waiting_for_user_authorization" — that flow
    requires a wallet-driven redirect, which is out of scope until the wallet boundary
    (roadmap Phase 4) exists.
    """
    offer = await resolve_credential_offer(credential_offer, fetch=fetch_offer)
    flow_type = select_flow_type(offer)
    session = await sessions.create(
        credential_issuer=offer.credential_issuer,
        credential_configuration_ids=offer.credential_configuration_ids,
        flow_type=flow_type,
    )

    if flow_type == AUTHORIZATION_CODE_FLOW:
        return await sessions.update(session.session_id, status="waiting_for_user_authorization")

    return await _complete_pre_authorized_code_flow(
        offer,
        session,
        sessions,
        tx_code=tx_code,
        fetch_as_metadata=fetch_as_metadata,
        post_token_request=post_token_request,
    )


async def _complete_pre_authorized_code_flow(
    offer: CredentialOffer,
    session: IssuanceSession,
    sessions: IssuanceSessionStore,
    *,
    tx_code: str | None,
    fetch_as_metadata: MetadataFetcher | None,
    post_token_request: TokenRequester | None,
) -> IssuanceSession:
    assert offer.grants is not None
    grant = offer.grants.pre_authorized_code
    assert grant is not None

    if grant.tx_code is not None and tx_code is None:
        return await sessions.update(
            session.session_id,
            status="failed",
            error="A transaction code (tx_code) is required but was not provided.",
        )

    # Spec default when the grant omits its own hint: the Credential Issuer's identifier is
    # also the Authorization Server's identifier.
    authorization_server = grant.authorization_server or offer.credential_issuer

    try:
        as_metadata = await get_authorization_server_metadata(
            authorization_server, fetch=fetch_as_metadata
        )
        dpop_key = DPoPKey() if _dpop_signing_alg_supported(as_metadata) else None
        token = await request_token_with_pre_authorized_code(
            as_metadata.token_endpoint,
            grant.pre_authorized_code,
            tx_code=tx_code,
            dpop_key=dpop_key,
            post=post_token_request,
        )
    except (
        InvalidAuthorizationServerMetadataError,
        TokenRequestRejectedError,
        InvalidTokenResponseError,
    ) as exc:
        logger.warning("Session %s failed during token exchange: %s", session.session_id, exc)
        return await sessions.update(session.session_id, status="failed", error=str(exc))

    logger.info(
        "Session %s obtained an access token (dpop_bound=%s).",
        session.session_id,
        token.token_type == "DPoP",
    )
    return await sessions.update(
        session.session_id,
        status="ready_for_credential_request",
        access_token=token.access_token,
        dpop_key=dpop_key,
        dpop_bound=(token.token_type == "DPoP"),
    )


def _dpop_signing_alg_supported(as_metadata: AuthorizationServerMetadata) -> bool:
    # RFC 9449 §5.1: presence of this field, with an algorithm we can sign with, is the
    # spec-defined signal to proactively attach a DPoP proof rather than wait for a rejection.
    algs = as_metadata.dpop_signing_alg_values_supported
    return algs is not None and SUPPORTED_DPOP_SIGNING_ALG in algs
