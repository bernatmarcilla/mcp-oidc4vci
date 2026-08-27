from urllib.parse import quote

import httpx
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from mcp_oidc4vci.server import mcp
from support import mock_async_client

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


async def test_get_credential_issuer_metadata_returns_the_parsed_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = (
        '{"credential_issuer": "https://issuer.example.com", '
        '"credential_endpoint": "https://issuer.example.com/credential", '
        '"credential_configurations_supported": '
        '{"UniversityDegreeCredential": {"format": "vc+sd-jwt"}}}'
    )
    monkeypatch.setattr(
        httpx, "AsyncClient", mock_async_client(lambda request: httpx.Response(200, text=payload))
    )

    async with Client(mcp) as client:
        result = await client.call_tool(
            "get_credential_issuer_metadata", {"credential_issuer": "https://issuer.example.com"}
        )

    assert result.data["credential_endpoint"] == "https://issuer.example.com/credential"


async def test_get_credential_issuer_metadata_surfaces_invalid_metadata_as_a_tool_error() -> None:
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="https URL"):
            await client.call_tool(
                "get_credential_issuer_metadata", {"credential_issuer": "http://issuer.example.com"}
            )
