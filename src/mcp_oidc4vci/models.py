"""OIDC4VCI 1.0 data models used by the MCP server.

Field names and shapes follow the final specification:
https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PRE_AUTHORIZED_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"


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
    credential_signing_alg_values_supported: list[str] | None = None
    credential_metadata: CredentialMetadata | None = None


class CredentialIssuerMetadata(BaseModel):
    """Credential Issuer Metadata, fetched from the issuer's well-known endpoint."""

    credential_issuer: str
    credential_endpoint: str
    authorization_servers: list[str] | None = None
    credential_configurations_supported: dict[str, CredentialConfiguration]
