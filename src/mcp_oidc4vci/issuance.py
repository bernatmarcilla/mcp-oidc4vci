"""Issuance flow determination and orchestration.

Covers the "Authorization Code Flow" and "Pre-Authorized Code Flow" sections of the spec,
plus in-memory tracking of issuance sessions across the separate MCP tool calls that make up
one issuance (`initiate_issuance` followed by one or more `get_issuance_status` calls).
"""

import asyncio
import logging
import secrets
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from mcp_oidc4vci.authorization_request import (
    authorization_request_params,
    build_authorization_url,
    build_pushed_authorization_url,
)
from mcp_oidc4vci.authorization_server_metadata import (
    InvalidAuthorizationServerMetadataError,
    MetadataFetcher,
    get_authorization_server_metadata,
)
from mcp_oidc4vci.credential_issuer_metadata import (
    InvalidCredentialIssuerMetadataError,
    get_credential_issuer_metadata,
)
from mcp_oidc4vci.credential_issuer_metadata import (
    MetadataFetcher as CredentialIssuerMetadataFetcher,
)
from mcp_oidc4vci.credential_offer import CredentialOfferFetcher, resolve_credential_offer
from mcp_oidc4vci.dpop import SUPPORTED_DPOP_SIGNING_ALG, DPoPKey
from mcp_oidc4vci.models import (
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
    AuthorizationServerMetadata,
    CredentialIssuerMetadata,
    CredentialOffer,
    IssuanceFlowDescription,
    IssuanceFlowStep,
)
from mcp_oidc4vci.pkce import code_challenge, generate_code_verifier
from mcp_oidc4vci.pushed_authorization_request import (
    InvalidPushedAuthorizationRequestResponseError,
    PushedAuthorizationRequester,
    PushedAuthorizationRequestRejectedError,
    push_authorization_request,
)
from mcp_oidc4vci.token_request import (
    InvalidTokenResponseError,
    TokenRequester,
    TokenRequestRejectedError,
    request_token_with_authorization_code,
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


class SessionNotReadyError(IssuanceError):
    """The session is not in a state that allows the requested operation."""


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

    The following fields exist only for the `authorization_code` grant, which — unlike the
    pre-authorized code grant — spans three separate tool calls (`initiate_issuance` ->
    `begin_authorization` -> `submit_authorization_result`) and so needs somewhere to keep
    state between them: `authorization_endpoint`/`token_endpoint`/`issuer_state` are resolved
    from Authorization Server metadata up front; `pushed_authorization_request_endpoint`,
    when the Authorization Server advertises one (RFC 9126), is also resolved up front, and
    is what tells `begin_authorization` whether to push the Authorization Request instead of
    putting its parameters directly in the URL; `scope`, resolved from the requested credential
    configurations' own declared `scope` (Credential Issuer Metadata), is the backward-
    compatible alternative to `authorization_details` sent alongside it, for an Authorization
    Server that doesn't support Rich Authorization Requests; `client_id`/`redirect_uri`/
    `code_verifier` are chosen by `begin_authorization` and must be replayed identically in the
    later Token Request; `authorization_state` is compared against what
    `submit_authorization_result` receives back, to guard against cross-session mixups;
    `authorization_url` is surfaced to the caller while `status == "awaiting_authorization_result"`,
    the same way `proof_nonce` is surfaced for `awaiting_wallet_proof`.

    `transaction_id` and `deferred_interval` apply to either grant: when the Credential Issuer
    defers issuance (spec "Deferred Credential Response"), `status` becomes
    `awaiting_deferred_credential` and these carry what `poll_deferred_credential` needs to
    check back later — `transaction_id` to identify the pending request, `deferred_interval`
    as the issuer's suggested wait (in seconds) before polling again.
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
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    issuer_state: str | None = None
    pushed_authorization_request_endpoint: str | None = None
    scope: str | None = None
    client_id: str | None = None
    redirect_uri: str | None = None
    code_verifier: str | None = None
    authorization_state: str | None = None
    authorization_url: str | None = None
    transaction_id: str | None = None
    deferred_interval: int | None = None


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
        authorization_endpoint: str | None = None,
        token_endpoint: str | None = None,
        issuer_state: str | None = None,
        pushed_authorization_request_endpoint: str | None = None,
        scope: str | None = None,
        client_id: str | None = None,
        redirect_uri: str | None = None,
        code_verifier: str | None = None,
        authorization_state: str | None = None,
        authorization_url: str | None = None,
        transaction_id: str | None = None,
        deferred_interval: int | None = None,
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
            if authorization_endpoint is not None:
                session.authorization_endpoint = authorization_endpoint
            if token_endpoint is not None:
                session.token_endpoint = token_endpoint
            if issuer_state is not None:
                session.issuer_state = issuer_state
            if pushed_authorization_request_endpoint is not None:
                session.pushed_authorization_request_endpoint = (
                    pushed_authorization_request_endpoint
                )
            if scope is not None:
                session.scope = scope
            if client_id is not None:
                session.client_id = client_id
            if redirect_uri is not None:
                session.redirect_uri = redirect_uri
            if code_verifier is not None:
                session.code_verifier = code_verifier
            if authorization_state is not None:
                session.authorization_state = authorization_state
            if authorization_url is not None:
                session.authorization_url = authorization_url
            if transaction_id is not None:
                session.transaction_id = transaction_id
            if deferred_interval is not None:
                session.deferred_interval = deferred_interval
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
    fetch_issuer_metadata: CredentialIssuerMetadataFetcher | None = None,
    post_token_request: TokenRequester | None = None,
) -> IssuanceSession:
    """Start an issuance session for the offer's chosen flow.

    For the pre-authorized code grant, completes the token exchange immediately (it needs no
    user interaction); the session ends "ready_for_credential_request" or "failed". For the
    authorization code grant, this resolves the Authorization Server's metadata (so a bad
    `authorization_server` hint or a missing `authorization_endpoint` fails fast) and leaves
    the session "waiting_for_user_authorization" — completing it needs `begin_authorization`
    followed by `submit_authorization_result`, since a wallet-driven browser redirect can't
    happen inside a single tool call.
    """
    offer = await resolve_credential_offer(credential_offer, fetch=fetch_offer)
    flow_type = select_flow_type(offer)
    session = await sessions.create(
        credential_issuer=offer.credential_issuer,
        credential_configuration_ids=offer.credential_configuration_ids,
        flow_type=flow_type,
    )

    if flow_type == AUTHORIZATION_CODE_FLOW:
        return await _prepare_authorization_code_flow(
            offer,
            session,
            sessions,
            fetch_as_metadata=fetch_as_metadata,
            fetch_issuer_metadata=fetch_issuer_metadata,
        )

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


async def _prepare_authorization_code_flow(
    offer: CredentialOffer,
    session: IssuanceSession,
    sessions: IssuanceSessionStore,
    *,
    fetch_as_metadata: MetadataFetcher | None,
    fetch_issuer_metadata: CredentialIssuerMetadataFetcher | None,
) -> IssuanceSession:
    assert offer.grants is not None
    grant = offer.grants.authorization_code
    assert grant is not None

    # Same spec default as the pre-authorized code grant: absent its own hint, the Credential
    # Issuer's identifier is also the Authorization Server's identifier.
    authorization_server = grant.authorization_server or offer.credential_issuer

    try:
        as_metadata = await get_authorization_server_metadata(
            authorization_server, fetch=fetch_as_metadata
        )
    except InvalidAuthorizationServerMetadataError as exc:
        logger.warning(
            "Session %s failed resolving Authorization Server metadata: %s",
            session.session_id,
            exc,
        )
        return await sessions.update(session.session_id, status="failed", error=str(exc))

    if as_metadata.authorization_endpoint is None:
        error = (
            f"Authorization Server {authorization_server!r} does not advertise an "
            "authorization_endpoint; the authorization_code grant cannot proceed."
        )
        return await sessions.update(session.session_id, status="failed", error=error)

    # Needed to resolve `scope` below — the Authorization Request's backward-compatible
    # alternative to `authorization_details` — and, since it's fetched anyway, validated
    # up front rather than only when `request_credential` needs it later.
    try:
        issuer_metadata = await get_credential_issuer_metadata(
            offer.credential_issuer, fetch=fetch_issuer_metadata
        )
    except InvalidCredentialIssuerMetadataError as exc:
        logger.warning(
            "Session %s failed resolving Credential Issuer Metadata: %s",
            session.session_id,
            exc,
        )
        return await sessions.update(session.session_id, status="failed", error=str(exc))

    dpop_key = DPoPKey() if _dpop_signing_alg_supported(as_metadata) else None
    return await sessions.update(
        session.session_id,
        status="waiting_for_user_authorization",
        authorization_endpoint=as_metadata.authorization_endpoint,
        token_endpoint=as_metadata.token_endpoint,
        issuer_state=grant.issuer_state,
        pushed_authorization_request_endpoint=as_metadata.pushed_authorization_request_endpoint,
        scope=_resolve_scope(issuer_metadata, offer.credential_configuration_ids),
        dpop_key=dpop_key,
    )


def _resolve_scope(
    issuer_metadata: CredentialIssuerMetadata, credential_configuration_ids: list[str]
) -> str | None:
    # Spec's backward-compatible alternative to `authorization_details` (RFC 9396), for an
    # Authorization Server that doesn't support Rich Authorization Requests. Only meaningful
    # when every requested credential configuration declares one — a partial scope list would
    # silently drop whichever credentials didn't, with no other way for a scope-only
    # Authorization Server to learn about them.
    scopes: list[str] = []
    for credential_configuration_id in credential_configuration_ids:
        configuration = issuer_metadata.credential_configurations_supported.get(
            credential_configuration_id
        )
        if configuration is None or configuration.scope is None:
            return None
        scopes.append(configuration.scope)
    return " ".join(scopes)


async def begin_authorization(
    session_id: str,
    *,
    client_id: str,
    redirect_uri: str,
    sessions: IssuanceSessionStore,
    post_par_request: PushedAuthorizationRequester | None = None,
) -> IssuanceSession:
    """Build the Authorization Request URL for a session left `waiting_for_user_authorization`
    by `initiate_issuance`.

    `client_id` and `redirect_uri` are whatever this caller has registered (or otherwise been
    given) with the Authorization Server — this server has no dynamic client registration of
    its own, so it can't choose them for you. Generates a fresh PKCE pair and `state` value,
    and stores them server-side.

    When the Authorization Server advertised a `pushed_authorization_request_endpoint`
    (RFC 9126), the parameters are pushed there first and the URL carries only the resulting
    `request_uri`; otherwise they go directly in the URL's query string, as before — a caller
    never needs to know or care which one happened. Either way the session moves to
    `awaiting_authorization_result`; once a human has opened the returned URL and authorized
    issuance, call `submit_authorization_result` with the `code`/`state` the redirect carried.

    A pushed `request_uri` can be short-lived — well under a minute against at least one real
    Authorization Server — so the URL should be handed off and opened with as little delay as
    possible; calling this again produces a fresh one if the caller suspects it expired.
    """
    session = await sessions.get(session_id)
    if session.status != "waiting_for_user_authorization" or session.authorization_endpoint is None:
        raise SessionNotReadyError(
            f"Session {session.session_id!r} is not ready (expected status "
            f"'waiting_for_user_authorization' with a resolved Authorization Server, has "
            f"status {session.status!r})."
        )

    code_verifier = generate_code_verifier()
    state = secrets.token_urlsafe(24)
    params = authorization_request_params(
        client_id=client_id,
        redirect_uri=redirect_uri,
        credential_configuration_ids=session.credential_configuration_ids,
        code_challenge_value=code_challenge(code_verifier),
        state=state,
        issuer_state=session.issuer_state,
        scope=session.scope,
    )

    if session.pushed_authorization_request_endpoint is not None:
        try:
            par_response = await push_authorization_request(
                session.pushed_authorization_request_endpoint, params, post=post_par_request
            )
        except (
            PushedAuthorizationRequestRejectedError,
            InvalidPushedAuthorizationRequestResponseError,
        ) as exc:
            logger.warning(
                "Session %s failed pushing the Authorization Request: %s", session.session_id, exc
            )
            return await sessions.update(session.session_id, status="failed", error=str(exc))
        authorization_url = build_pushed_authorization_url(
            session.authorization_endpoint,
            client_id=client_id,
            request_uri=par_response.request_uri,
        )
    else:
        authorization_url = build_authorization_url(session.authorization_endpoint, params)

    return await sessions.update(
        session.session_id,
        status="awaiting_authorization_result",
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
        authorization_state=state,
        authorization_url=authorization_url,
    )


async def submit_authorization_result(
    session_id: str,
    code: str,
    state: str,
    *,
    sessions: IssuanceSessionStore,
    post_token_request: TokenRequester | None = None,
) -> IssuanceSession:
    """Complete the authorization code grant with the `code`/`state` a human obtained by
    opening `begin_authorization`'s URL and completing the redirect.

    Rejects a `state` that doesn't match the one `begin_authorization` generated for this
    session, without ever making a Token Request — that mismatch means this isn't the
    redirect this session is waiting for. Otherwise exchanges `code` for an access token
    (PKCE-bound, and DPoP-bound if the Authorization Server requires it) and lands the
    session at `ready_for_credential_request`, same as the pre-authorized code grant.
    """
    session = await sessions.get(session_id)
    if session.status != "awaiting_authorization_result":
        raise SessionNotReadyError(
            f"Session {session.session_id!r} is not ready (expected status "
            f"'awaiting_authorization_result', has {session.status!r})."
        )

    if state != session.authorization_state:
        return await sessions.update(
            session.session_id,
            status="failed",
            error="The returned state does not match the state issued for this session.",
        )

    assert session.token_endpoint is not None
    assert session.redirect_uri is not None
    assert session.client_id is not None
    assert session.code_verifier is not None

    try:
        token = await request_token_with_authorization_code(
            session.token_endpoint,
            code,
            redirect_uri=session.redirect_uri,
            client_id=session.client_id,
            code_verifier=session.code_verifier,
            dpop_key=session.dpop_key,
            post=post_token_request,
        )
    except (TokenRequestRejectedError, InvalidTokenResponseError) as exc:
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
        dpop_bound=(token.token_type == "DPoP"),
    )
