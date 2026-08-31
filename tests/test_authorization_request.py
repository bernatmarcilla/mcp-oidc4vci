import json
from urllib.parse import parse_qs, urlsplit

from mcp_oidc4vci.authorization_request import (
    authorization_request_params,
    build_authorization_url,
    build_pushed_authorization_url,
)

_ENDPOINT = "https://as.example.com/authorize"


def _query(url: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(url).query)


def _params(
    *,
    credential_configuration_ids: list[str] | None = None,
    issuer_state: str | None = None,
    scope: str | None = None,
) -> dict[str, str]:
    return authorization_request_params(
        client_id="client-id",
        redirect_uri="https://client.example.com/cb",
        credential_configuration_ids=credential_configuration_ids or ["UniversityDegreeCredential"],
        code_challenge_value="challenge-value",
        state="state-value",
        issuer_state=issuer_state,
        scope=scope,
    )


# -- authorization_request_params ----------------------------------------------


def test_authorization_request_params_includes_the_required_oauth_and_pkce_parameters() -> None:
    params = _params()

    assert params["response_type"] == "code"
    assert params["client_id"] == "client-id"
    assert params["redirect_uri"] == "https://client.example.com/cb"
    assert params["state"] == "state-value"
    assert params["code_challenge"] == "challenge-value"
    assert params["code_challenge_method"] == "S256"


def test_authorization_request_params_encodes_one_authorization_detail_per_credential_config() -> (
    None
):
    params = _params(
        credential_configuration_ids=["UniversityDegreeCredential", "DriversLicense"]
    )

    authorization_details = json.loads(params["authorization_details"])
    assert authorization_details == [
        {"type": "openid_credential", "credential_configuration_id": "UniversityDegreeCredential"},
        {"type": "openid_credential", "credential_configuration_id": "DriversLicense"},
    ]


def test_authorization_request_params_includes_issuer_state_when_given() -> None:
    params = _params(issuer_state="opaque-issuer-state")

    assert params["issuer_state"] == "opaque-issuer-state"


def test_authorization_request_params_omits_issuer_state_when_absent() -> None:
    params = _params(issuer_state=None)

    assert "issuer_state" not in params


def test_authorization_request_params_includes_scope_when_given() -> None:
    params = _params(scope="eu.europa.ec.eudi.pid_mso_mdoc")

    assert params["scope"] == "eu.europa.ec.eudi.pid_mso_mdoc"


def test_authorization_request_params_omits_scope_when_absent() -> None:
    params = _params(scope=None)

    assert "scope" not in params


def test_authorization_request_params_sends_scope_instead_of_authorization_details() -> None:
    # A real Authorization Server (Keycloak) was found to hard-reject an unsupported
    # authorization_details type even with scope also present, so only one is ever sent.
    params = _params(scope="eu.europa.ec.eudi.pid_mso_mdoc")

    assert "scope" in params
    assert "authorization_details" not in params


def test_authorization_request_params_sends_authorization_details_when_no_scope_is_given() -> None:
    params = _params(scope=None)

    assert "authorization_details" in params
    assert "scope" not in params


# -- build_authorization_url ----------------------------------------------------


def test_build_authorization_url_targets_the_authorization_endpoint() -> None:
    url = build_authorization_url(_ENDPOINT, _params())

    assert url.startswith(f"{_ENDPOINT}?")


def test_build_authorization_url_round_trips_every_param_into_the_query_string() -> None:
    params = _params(issuer_state="opaque-issuer-state")

    query = _query(build_authorization_url(_ENDPOINT, params))

    assert {key: values[0] for key, values in query.items()} == params


# -- build_pushed_authorization_url ----------------------------------------------


def test_build_pushed_authorization_url_carries_only_client_id_and_request_uri() -> None:
    url = build_pushed_authorization_url(
        _ENDPOINT, client_id="client-id", request_uri="urn:ietf:params:oauth:request_uri:abc123"
    )

    assert url.startswith(f"{_ENDPOINT}?")
    query = _query(url)
    assert query == {
        "client_id": ["client-id"],
        "request_uri": ["urn:ietf:params:oauth:request_uri:abc123"],
    }
