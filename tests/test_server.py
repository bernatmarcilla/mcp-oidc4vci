from urllib.parse import quote

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from mcp_oidc4vci.server import mcp

BY_VALUE_OFFER_JSON = (
    '{"credential_issuer": "https://issuer.example.com", '
    '"credential_configuration_ids": ["UniversityDegreeCredential"]}'
)


def _offer_uri(payload: str) -> str:
    return f"openid-credential-offer://?credential_offer={quote(payload, safe='')}"


async def test_inspect_credential_offer_returns_the_parsed_offer() -> None:
    async with Client(mcp) as client:
        result = await client.call_tool(
            "inspect_credential_offer", {"credential_offer": _offer_uri(BY_VALUE_OFFER_JSON)}
        )

    assert result.data == {
        "credential_issuer": "https://issuer.example.com",
        "credential_configuration_ids": ["UniversityDegreeCredential"],
    }


async def test_inspect_credential_offer_surfaces_invalid_offers_as_a_tool_error() -> None:
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="Exactly one of"):
            await client.call_tool(
                "inspect_credential_offer", {"credential_offer": "openid-credential-offer://"}
            )
