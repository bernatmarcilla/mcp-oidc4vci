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


async def test_describe_issuance_flow_returns_the_flow_type_and_steps() -> None:
    payload = (
        '{"credential_issuer": "https://issuer.example.com", '
        '"credential_configuration_ids": ["UniversityDegreeCredential"], '
        '"grants": {"authorization_code": {}}}'
    )

    async with Client(mcp) as client:
        result = await client.call_tool(
            "describe_issuance_flow", {"credential_offer": _offer_uri(payload)}
        )

    assert result.data["flow_type"] == "authorization_code"
    assert [step["action"] for step in result.data["steps"]] == [
        "user_authorization",
        "wallet_proof",
        "credential_request",
    ]


async def test_describe_issuance_flow_surfaces_an_undetermined_flow_as_a_tool_error() -> None:
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="grants"):
            await client.call_tool(
                "describe_issuance_flow", {"credential_offer": _offer_uri(BY_VALUE_OFFER_JSON)}
            )


async def test_initiate_and_check_issuance_status_for_the_pre_authorized_code_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "issuer": "https://issuer.example.com",
                    "token_endpoint": "https://issuer.example.com/token",
                },
            )
        return httpx.Response(200, json={"access_token": "secret-token", "token_type": "Bearer"})

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

    payload = (
        '{"credential_issuer": "https://issuer.example.com", '
        '"credential_configuration_ids": ["UniversityDegreeCredential"], '
        '"grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": '
        '{"pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5"}}}'
    )

    async with Client(mcp) as client:
        initiate_result = await client.call_tool(
            "initiate_issuance", {"credential_offer": _offer_uri(payload)}
        )
        assert initiate_result.data["status"] == "ready_for_credential_request"

        status_result = await client.call_tool(
            "get_issuance_status", {"session_id": initiate_result.data["session_id"]}
        )

    assert status_result.data == initiate_result.data
    assert "access_token" not in status_result.data


async def test_initiate_issuance_reports_a_failed_session_with_its_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "issuer": "https://issuer.example.com",
                    "token_endpoint": "https://issuer.example.com/token",
                },
            )
        return httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "code expired"}
        )

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

    payload = (
        '{"credential_issuer": "https://issuer.example.com", '
        '"credential_configuration_ids": ["UniversityDegreeCredential"], '
        '"grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": '
        '{"pre-authorized_code": "expired-code"}}}'
    )

    async with Client(mcp) as client:
        result = await client.call_tool(
            "initiate_issuance", {"credential_offer": _offer_uri(payload)}
        )

    assert result.data == {
        "session_id": result.data["session_id"],
        "status": "failed",
        "error": "code expired",
    }


async def test_initiate_issuance_surfaces_an_invalid_offer_as_a_tool_error() -> None:
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="Exactly one of"):
            await client.call_tool(
                "initiate_issuance", {"credential_offer": "openid-credential-offer://"}
            )


async def test_get_issuance_status_surfaces_an_unknown_session_as_a_tool_error() -> None:
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="No issuance session"):
            await client.call_tool("get_issuance_status", {"session_id": "does-not-exist"})


async def test_request_credential_completes_the_full_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and "oauth-authorization-server" in path:
            return httpx.Response(
                200,
                json={
                    "issuer": "https://issuer.example.com",
                    "token_endpoint": "https://issuer.example.com/token",
                },
            )
        if request.method == "GET" and "openid-credential-issuer" in path:
            return httpx.Response(
                200,
                json={
                    "credential_issuer": "https://issuer.example.com",
                    "credential_endpoint": "https://issuer.example.com/credential",
                    "credential_configurations_supported": {
                        "UniversityDegreeCredential": {"format": "vc+sd-jwt"}
                    },
                },
            )
        if request.method == "POST" and path == "/token":
            return httpx.Response(
                200, json={"access_token": "secret-token", "token_type": "Bearer"}
            )
        if request.method == "POST" and path == "/credential":
            return httpx.Response(200, json={"credentials": [{"credential": "opaque-jwt-vc"}]})
        raise AssertionError(f"unexpected request {request.method} {request.url}")

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

    payload = (
        '{"credential_issuer": "https://issuer.example.com", '
        '"credential_configuration_ids": ["UniversityDegreeCredential"], '
        '"grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": '
        '{"pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5"}}}'
    )

    async with Client(mcp) as client:
        initiate_result = await client.call_tool(
            "initiate_issuance", {"credential_offer": _offer_uri(payload)}
        )
        assert initiate_result.data["status"] == "ready_for_credential_request"

        request_result = await client.call_tool(
            "request_credential", {"session_id": initiate_result.data["session_id"]}
        )

    assert request_result.data == {
        "session_id": initiate_result.data["session_id"],
        "status": "completed",
    }


async def test_request_credential_surfaces_an_unknown_session_as_a_tool_error() -> None:
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="No issuance session"):
            await client.call_tool("request_credential", {"session_id": "does-not-exist"})


async def test_request_credential_surfaces_a_not_ready_session_as_a_tool_error() -> None:
    payload = (
        '{"credential_issuer": "https://issuer.example.com", '
        '"credential_configuration_ids": ["UniversityDegreeCredential"], '
        '"grants": {"authorization_code": {}}}'
    )

    async with Client(mcp) as client:
        initiate_result = await client.call_tool(
            "initiate_issuance", {"credential_offer": _offer_uri(payload)}
        )
        assert initiate_result.data["status"] == "waiting_for_user_authorization"

        with pytest.raises(ToolError, match="not ready"):
            await client.call_tool(
                "request_credential", {"session_id": initiate_result.data["session_id"]}
            )
