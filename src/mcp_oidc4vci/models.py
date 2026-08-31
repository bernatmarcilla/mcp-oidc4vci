"""OIDC4VCI 1.0 data models used by the MCP server.

Field names and shapes follow the final specification:
https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PRE_AUTHORIZED_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
AUTHORIZATION_CODE_GRANT_TYPE = "authorization_code"


class TxCode(BaseModel):
    """Transaction Code requirements for the pre-authorized code grant (spec §4.1.1)."""

    input_mode: Literal["numeric", "text"] = "numeric"
    length: int | None = None
    description: str | None = Field(default=None, max_length=300)


class AuthorizationCodeGrant(BaseModel):
    """Parameters for the `authorization_code` grant (spec §4.1.1)."""

    issuer_state: str | None = None
    authorization_server: str | None = None


class PreAuthorizedCodeGrant(BaseModel):
    """Parameters for the pre-authorized code grant (spec §4.1.1)."""

    model_config = ConfigDict(populate_by_name=True)

    pre_authorized_code: str = Field(alias="pre-authorized_code")
    tx_code: TxCode | None = None
    authorization_server: str | None = None


class CredentialOfferGrants(BaseModel):
    """The `grants` object of a Credential Offer, keyed by grant type identifier."""

    model_config = ConfigDict(populate_by_name=True)

    authorization_code: AuthorizationCodeGrant | None = None
    # mypy requires a literal for Field(alias=...); must stay equal to
    # PRE_AUTHORIZED_CODE_GRANT_TYPE above (a test asserts this).
    pre_authorized_code: PreAuthorizedCodeGrant | None = Field(
        default=None, alias="urn:ietf:params:oauth:grant-type:pre-authorized_code"
    )


class CredentialOffer(BaseModel):
    """A Credential Offer (spec §4.1), resolved from either its by-value or by-reference form."""

    credential_issuer: str
    credential_configuration_ids: list[str] = Field(min_length=1)
    grants: CredentialOfferGrants | None = None


class CredentialDisplay(BaseModel):
    """A localized display entry from a credential configuration's `credential_metadata`."""

    name: str
    locale: str | None = None


class CredentialMetadata(BaseModel):
    """The `credential_metadata` object of a credential configuration entry."""

    display: list[CredentialDisplay] | None = None


class CredentialConfiguration(BaseModel):
    """A single entry of `credential_configurations_supported`, describing one issuable
    credential."""

    format: str
    scope: str | None = None
    cryptographic_binding_methods_supported: list[str] | None = None
    # The spec leaves each identifier's type to the credential format: JOSE-based formats use
    # a string alg (e.g. "ES256"), COSE-based formats like mso_mdoc use an integer from the
    # IANA COSE Algorithms registry (e.g. -7, also ES256).
    credential_signing_alg_values_supported: list[str | int] | None = None
    credential_metadata: CredentialMetadata | None = None


class CredentialIssuerMetadata(BaseModel):
    """Credential Issuer Metadata, fetched from the issuer's well-known endpoint."""

    credential_issuer: str
    credential_endpoint: str
    authorization_servers: list[str] | None = None
    nonce_endpoint: str | None = None
    # spec "Deferred Credential Endpoint" (§9). Presence is what a session that received a
    # transaction_id needs to poll for the credential later.
    deferred_credential_endpoint: str | None = None
    credential_configurations_supported: dict[str, CredentialConfiguration]


class AuthorizationServerMetadata(BaseModel):
    """OAuth 2.0 Authorization Server Metadata (RFC 8414), fetched from its well-known
    endpoint to discover the token endpoint used by the pre-authorized code grant."""

    issuer: str
    token_endpoint: str
    # Required for the authorization_code grant (RFC 8414 §2 notes it's optional in general,
    # but an AS that doesn't advertise one can't support that grant here).
    authorization_endpoint: str | None = None
    # RFC 9126 §5. Presence is the signal to push the Authorization Request's parameters
    # instead of putting them directly in its URL — always safe to do when the AS advertises
    # support, whether or not it's mandatory for that AS.
    pushed_authorization_request_endpoint: str | None = None
    # RFC 9449 §5.1. Presence signals DPoP support; used to decide whether to proactively
    # attach a DPoP proof to the Token Request.
    dpop_signing_alg_values_supported: list[str] | None = None


class PushedAuthorizationRequestResponse(BaseModel):
    """A successful Pushed Authorization Request Response (RFC 9126 §2.2)."""

    request_uri: str
    expires_in: int


class PushedAuthorizationRequestErrorResponse(BaseModel):
    """A Pushed Authorization Request Error Response (RFC 9126 §2.3)."""

    error: str
    error_description: str | None = None


class TokenSuccessResponse(BaseModel):
    """A successful Token Response (spec "Successful Token Response")."""

    access_token: str
    token_type: str
    expires_in: int | None = None


class TokenErrorResponse(BaseModel):
    """A Token Error Response (spec "Token Error Response", RFC 6749 §5.2)."""

    error: str
    error_description: str | None = None


class IssuanceFlowStep(BaseModel):
    """A single step in a normalized issuance flow description."""

    step: int
    action: str
    description: str


class IssuanceFlowDescription(BaseModel):
    """A normalized description of the steps required to obtain an offered credential."""

    flow_type: str
    steps: list[IssuanceFlowStep]


class NonceResponse(BaseModel):
    """A Nonce Response (spec "Nonce Response")."""

    c_nonce: str


class IssuedCredential(BaseModel):
    """One element of a Credential Response's `credentials` array."""

    credential: str | dict[str, object]


class CredentialResponse(BaseModel):
    """A Credential Response (spec "Credential Response"), immediate or deferred."""

    credentials: list[IssuedCredential] | None = None
    transaction_id: str | None = None
    interval: int | None = None
    notification_id: str | None = None


class CredentialErrorResponse(BaseModel):
    """A Credential Error Response (spec "Credential Error Response")."""

    error: str
    error_description: str | None = None
