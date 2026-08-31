"""Authorization Request construction for the `authorization_code` grant (spec "Authorization
Request", RFC 9396 `authorization_details`, RFC 7636 PKCE, RFC 9126 Pushed Authorization
Requests).

Building a URL (or, when the Authorization Server requires PAR, pushing to it first) is the
whole job here — this server has no way to receive the resulting redirect itself (see
docs/ARCHITECTURE.md), so the URL is handed to a human to open, and the `code`/`state` it
redirects back with are supplied separately to `submit_authorization_result`.
"""

import json
from urllib.parse import urlencode

from mcp_oidc4vci.pkce import CODE_CHALLENGE_METHOD

_OPENID_CREDENTIAL_AUTHORIZATION_DETAILS_TYPE = "openid_credential"


def authorization_request_params(
    *,
    client_id: str,
    redirect_uri: str,
    credential_configuration_ids: list[str],
    code_challenge_value: str,
    state: str,
    issuer_state: str | None,
    scope: str | None,
) -> dict[str, str]:
    """The Authorization Request's parameters (spec "Authorization Request"). Sent either
    directly in the Authorization Request URL's query string via `build_authorization_url`,
    or as the body of a Pushed Authorization Request (RFC 9126 §3) via
    `pushed_authorization_request.push_authorization_request` — whichever the Authorization
    Server requires. `code_challenge_value` is `pkce.code_challenge(verifier)` — the verifier
    itself never appears here. `issuer_state`, when the offer's grant carried one, lets the
    Authorization Server correlate this request back to the original Credential Offer.

    `scope` is the spec's backward-compatible alternative to `authorization_details`
    (RFC 9396) for an Authorization Server that doesn't support Rich Authorization Requests —
    sent *instead of* `authorization_details`, not alongside it, when available. A real
    Authorization Server (Keycloak) was found to hard-reject an unsupported
    `authorization_details` type even with `scope` also present, so there's no combination
    that's safe to send unconditionally; `authorization_details` is the more precise
    mechanism and is used whenever no `scope` was resolved.
    """
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge_value,
        "code_challenge_method": CODE_CHALLENGE_METHOD,
    }
    if scope is not None:
        params["scope"] = scope
    else:
        authorization_details = [
            {
                "type": _OPENID_CREDENTIAL_AUTHORIZATION_DETAILS_TYPE,
                "credential_configuration_id": credential_configuration_id,
            }
            for credential_configuration_id in credential_configuration_ids
        ]
        # Compact (no whitespace): keeps the URL shorter, and sidesteps any ambiguity in
        # whether a receiving server decodes a query string's "+" back into the space
        # json.dumps would otherwise put after ":" and ",".
        params["authorization_details"] = json.dumps(authorization_details, separators=(",", ":"))
    if issuer_state is not None:
        params["issuer_state"] = issuer_state
    return params


def build_authorization_url(authorization_endpoint: str, params: dict[str, str]) -> str:
    """The URL a human opens to authorize issuance, with `params` directly in the query
    string. Used when the Authorization Server has no `pushed_authorization_request_endpoint`.
    """
    return f"{authorization_endpoint}?{urlencode(params)}"


def build_pushed_authorization_url(
    authorization_endpoint: str, *, client_id: str, request_uri: str
) -> str:
    """The (much shorter) URL a human opens after a successful Pushed Authorization Request
    (RFC 9126 §4) — the Authorization Server looks up the pushed parameters by `request_uri`
    instead of them appearing here.
    """
    params = {"client_id": client_id, "request_uri": request_uri}
    return f"{authorization_endpoint}?{urlencode(params)}"
