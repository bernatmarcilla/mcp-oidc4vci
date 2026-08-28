import pytest
from pydantic import ValidationError

from mcp_oidc4vci.models import (
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
    AuthorizationServerMetadata,
    CredentialConfiguration,
    CredentialIssuerMetadata,
    CredentialOffer,
    CredentialOfferGrants,
    IssuanceFlowDescription,
    PreAuthorizedCodeGrant,
    TokenErrorResponse,
    TokenSuccessResponse,
)


def test_credential_offer_grants_field_alias_matches_the_exported_grant_type_constant() -> None:
    field = CredentialOfferGrants.model_fields["pre_authorized_code"]

    assert field.alias == PRE_AUTHORIZED_CODE_GRANT_TYPE


def test_pre_authorized_code_grant_accepts_the_specs_hyphenated_field_name() -> None:
    grant = PreAuthorizedCodeGrant.model_validate({"pre-authorized_code": "abc123"})

    assert grant.pre_authorized_code == "abc123"


def test_credential_offer_grants_maps_the_pre_authorized_code_urn_to_its_field() -> None:
    grants = CredentialOfferGrants.model_validate(
        {PRE_AUTHORIZED_CODE_GRANT_TYPE: {"pre-authorized_code": "abc123"}}
    )

    assert grants.pre_authorized_code is not None
    assert grants.pre_authorized_code.pre_authorized_code == "abc123"


def test_credential_offer_requires_at_least_one_credential_configuration_id() -> None:
    with pytest.raises(ValidationError):
        CredentialOffer.model_validate(
            {
                "credential_issuer": "https://issuer.example.com",
                "credential_configuration_ids": [],
            }
        )


def test_credential_offer_requires_credential_issuer() -> None:
    with pytest.raises(ValidationError):
        CredentialOffer.model_validate(
            {"credential_configuration_ids": ["UniversityDegreeCredential"]}
        )


def test_credential_offer_ignores_unknown_fields_instead_of_rejecting_the_offer() -> None:
    offer = CredentialOffer.model_validate(
        {
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["UniversityDegreeCredential"],
            "some_issuer_specific_extension": "opaque",
        }
    )

    assert offer.credential_issuer == "https://issuer.example.com"


def test_credential_offer_dumps_the_pre_authorized_code_grant_under_its_urn_key() -> None:
    offer = CredentialOffer.model_validate(
        {
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["UniversityDegreeCredential"],
            "grants": {PRE_AUTHORIZED_CODE_GRANT_TYPE: {"pre-authorized_code": "abc123"}},
        }
    )

    dumped = offer.model_dump(mode="json", by_alias=True, exclude_none=True)

    assert dumped["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE]["pre-authorized_code"] == "abc123"
    assert "authorization_code" not in dumped["grants"]


def test_credential_configuration_requires_a_format() -> None:
    with pytest.raises(ValidationError):
        CredentialConfiguration.model_validate({})


def test_credential_configuration_parses_its_nested_display_name() -> None:
    config = CredentialConfiguration.model_validate(
        {
            "format": "vc+sd-jwt",
            "credential_metadata": {"display": [{"name": "University Degree"}]},
        }
    )

    assert config.credential_metadata is not None
    assert config.credential_metadata.display is not None
    assert config.credential_metadata.display[0].name == "University Degree"


def test_credential_issuer_metadata_requires_credential_endpoint_and_configurations() -> None:
    with pytest.raises(ValidationError):
        CredentialIssuerMetadata.model_validate({"credential_issuer": "https://issuer.example.com"})


def test_credential_issuer_metadata_keys_configurations_by_id() -> None:
    metadata = CredentialIssuerMetadata.model_validate(
        {
            "credential_issuer": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "credential_configurations_supported": {
                "UniversityDegreeCredential": {"format": "vc+sd-jwt"}
            },
        }
    )

    assert metadata.credential_configurations_supported["UniversityDegreeCredential"].format == (
        "vc+sd-jwt"
    )


def test_authorization_server_metadata_requires_issuer_and_token_endpoint() -> None:
    with pytest.raises(ValidationError):
        AuthorizationServerMetadata.model_validate({"issuer": "https://as.example.com"})


def test_authorization_server_metadata_dpop_signing_algs_default_to_absent() -> None:
    metadata = AuthorizationServerMetadata.model_validate(
        {"issuer": "https://as.example.com", "token_endpoint": "https://as.example.com/token"}
    )

    assert metadata.dpop_signing_alg_values_supported is None


def test_authorization_server_metadata_parses_dpop_signing_algs() -> None:
    metadata = AuthorizationServerMetadata.model_validate(
        {
            "issuer": "https://as.example.com",
            "token_endpoint": "https://as.example.com/token",
            "dpop_signing_alg_values_supported": ["ES256"],
        }
    )

    assert metadata.dpop_signing_alg_values_supported == ["ES256"]


def test_token_success_response_requires_access_token_and_token_type() -> None:
    with pytest.raises(ValidationError):
        TokenSuccessResponse.model_validate({"access_token": "abc"})


def test_token_error_response_requires_error() -> None:
    with pytest.raises(ValidationError):
        TokenErrorResponse.model_validate({"error_description": "no code given"})


def test_issuance_flow_description_dumps_its_ordered_steps() -> None:
    description = IssuanceFlowDescription.model_validate(
        {
            "flow_type": "authorization_code",
            "steps": [{"step": 1, "action": "user_authorization", "description": "..."}],
        }
    )

    dumped = description.model_dump(mode="json")

    assert dumped["steps"][0]["step"] == 1
