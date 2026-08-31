import json
from urllib.parse import parse_qs, quote, urlsplit

import httpx
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from mcp_oidc4vci.server import _debug_tools_enabled, debug_inspect_mock_wallet_credentials, mcp
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


async def test_request_credential_handles_multiple_configurations_across_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_configuration_ids: list[str] = []

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
                        "UniversityDegreeCredential": {"format": "vc+sd-jwt"},
                        "DriversLicense": {"format": "vc+sd-jwt"},
                    },
                },
            )
        if request.method == "POST" and path == "/token":
            return httpx.Response(
                200, json={"access_token": "secret-token", "token_type": "Bearer"}
            )
        if request.method == "POST" and path == "/credential":
            body = json.loads(request.content)
            requested_configuration_ids.append(body["credential_configuration_id"])
            return httpx.Response(200, json={"credentials": [{"credential": "opaque-jwt-vc"}]})
        raise AssertionError(f"unexpected request {request.method} {request.url}")

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

    payload = (
        '{"credential_issuer": "https://issuer.example.com", '
        '"credential_configuration_ids": ["UniversityDegreeCredential", "DriversLicense"], '
        '"grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": '
        '{"pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5"}}}'
    )

    async with Client(mcp) as client:
        initiate_result = await client.call_tool(
            "initiate_issuance", {"credential_offer": _offer_uri(payload)}
        )
        session_id = initiate_result.data["session_id"]

        first = await client.call_tool("request_credential", {"session_id": session_id})
        assert first.data == {"session_id": session_id, "status": "ready_for_credential_request"}

        second = await client.call_tool("request_credential", {"session_id": session_id})
        assert second.data == {"session_id": session_id, "status": "completed"}

    assert requested_configuration_ids == ["UniversityDegreeCredential", "DriversLicense"]


async def test_poll_deferred_credential_completes_a_deferred_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    poll_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal poll_count
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
                    "deferred_credential_endpoint": "https://issuer.example.com/deferred",
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
            return httpx.Response(
                202, json={"transaction_id": "8xLOxBtZp8", "interval": 5}
            )
        if request.method == "POST" and path == "/deferred":
            poll_count += 1
            if poll_count == 1:
                return httpx.Response(
                    202, json={"transaction_id": "8xLOxBtZp8", "interval": 5}
                )
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
        session_id = initiate_result.data["session_id"]

        request_result = await client.call_tool("request_credential", {"session_id": session_id})
        assert request_result.data == {
            "session_id": session_id,
            "status": "awaiting_deferred_credential",
            "deferred_interval": 5,
        }

        still_pending = await client.call_tool(
            "poll_deferred_credential", {"session_id": session_id}
        )
        assert still_pending.data == {
            "session_id": session_id,
            "status": "awaiting_deferred_credential",
            "deferred_interval": 5,
        }

        ready = await client.call_tool("poll_deferred_credential", {"session_id": session_id})

    assert ready.data == {"session_id": session_id, "status": "completed"}


async def test_poll_deferred_credential_surfaces_an_unknown_session_as_a_tool_error() -> None:
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="No issuance session"):
            await client.call_tool("poll_deferred_credential", {"session_id": "does-not-exist"})


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, False), ("", False), ("0", False), ("false", False), ("1", True), ("True", True)],
)
def test_debug_tools_enabled_reads_the_env_var(
    monkeypatch: pytest.MonkeyPatch, value: str | None, expected: bool
) -> None:
    if value is None:
        monkeypatch.delenv("MCP_OIDC4VCI_DEBUG_TOOLS", raising=False)
    else:
        monkeypatch.setenv("MCP_OIDC4VCI_DEBUG_TOOLS", value)

    assert _debug_tools_enabled() is expected


async def test_debug_inspect_mock_wallet_credentials_is_not_registered_by_default() -> None:
    async with Client(mcp) as client:
        tools = await client.list_tools()

    assert "debug_inspect_mock_wallet_credentials" not in {tool.name for tool in tools}


async def test_debug_inspect_mock_wallet_credentials_reflects_what_request_credential_issued(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> None:
    # This tool is only registered when MCP_OIDC4VCI_DEBUG_TOOLS is set (see server.py); to
    # test its behavior without depending on process-wide env state, register/unregister it
    # on the shared `mcp` instance around just this test.
    mcp.add_tool(debug_inspect_mock_wallet_credentials)
    request.addfinalizer(
        lambda: mcp.local_provider.remove_tool("debug_inspect_mock_wallet_credentials")
    )

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
            return httpx.Response(
                200, json={"credentials": [{"credential": "debug-tool-test-credential"}]}
            )
        raise AssertionError(f"unexpected request {request.method} {request.url}")

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

    payload = (
        '{"credential_issuer": "https://issuer.example.com", '
        '"credential_configuration_ids": ["UniversityDegreeCredential"], '
        '"grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": '
        '{"pre-authorized_code": "another-code"}}}'
    )

    async with Client(mcp) as client:
        before = await client.call_tool("debug_inspect_mock_wallet_credentials", {})
        credentials_before = len(before.data)

        initiate_result = await client.call_tool(
            "initiate_issuance", {"credential_offer": _offer_uri(payload)}
        )
        await client.call_tool(
            "request_credential", {"session_id": initiate_result.data["session_id"]}
        )

        after = await client.call_tool("debug_inspect_mock_wallet_credentials", {})

    assert len(after.data) == credentials_before + 1
    assert after.data[-1] == {
        "credential_configuration_id": "UniversityDegreeCredential",
        "credential": "debug-tool-test-credential",
    }


async def test_request_credential_surfaces_an_unknown_session_as_a_tool_error() -> None:
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="No issuance session"):
            await client.call_tool("request_credential", {"session_id": "does-not-exist"})


async def test_request_credential_surfaces_a_not_ready_session_as_a_tool_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "oauth-authorization-server" in path:
            return httpx.Response(
                200,
                json={
                    "issuer": "https://issuer.example.com",
                    "token_endpoint": "https://issuer.example.com/token",
                    "authorization_endpoint": "https://issuer.example.com/authorize",
                },
            )
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

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

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


async def test_manual_wallet_proof_completes_the_full_flow(monkeypatch: pytest.MonkeyPatch) -> None:
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
                    "nonce_endpoint": "https://issuer.example.com/nonce",
                    "credential_configurations_supported": {
                        "UniversityDegreeCredential": {"format": "vc+sd-jwt"}
                    },
                },
            )
        if request.method == "POST" and path == "/token":
            return httpx.Response(
                200, json={"access_token": "secret-token", "token_type": "Bearer"}
            )
        if request.method == "POST" and path == "/nonce":
            return httpx.Response(200, json={"c_nonce": "fresh-nonce"})
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
        session_id = initiate_result.data["session_id"]

        proof_result = await client.call_tool("request_wallet_proof", {"session_id": session_id})
        assert proof_result.data == {
            "session_id": session_id,
            "status": "awaiting_wallet_proof",
            "proof_request": {
                "audience": "https://issuer.example.com",
                "credential_configuration_id": "UniversityDegreeCredential",
                "nonce": "fresh-nonce",
            },
        }

        submit_result = await client.call_tool(
            "submit_wallet_proof",
            {"session_id": session_id, "proof_jwt": "externally-signed-proof"},
        )

    assert submit_result.data == {"session_id": session_id, "status": "completed"}


async def test_request_wallet_proof_surfaces_a_not_ready_session_as_a_tool_error() -> None:
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="No issuance session"):
            await client.call_tool("request_wallet_proof", {"session_id": "does-not-exist"})


async def test_submit_wallet_proof_surfaces_a_not_awaiting_session_as_a_tool_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "oauth-authorization-server" in path:
            return httpx.Response(
                200,
                json={
                    "issuer": "https://issuer.example.com",
                    "token_endpoint": "https://issuer.example.com/token",
                    "authorization_endpoint": "https://issuer.example.com/authorize",
                },
            )
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

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

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
        session_id = initiate_result.data["session_id"]

        with pytest.raises(ToolError, match="not ready"):
            await client.call_tool(
                "submit_wallet_proof", {"session_id": session_id, "proof_jwt": "x"}
            )


async def test_authorization_code_grant_completes_the_full_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and "oauth-authorization-server" in path:
            return httpx.Response(
                200,
                json={
                    "issuer": "https://issuer.example.com",
                    "token_endpoint": "https://issuer.example.com/token",
                    "authorization_endpoint": "https://issuer.example.com/authorize",
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
        '"grants": {"authorization_code": {}}}'
    )

    async with Client(mcp) as client:
        initiate_result = await client.call_tool(
            "initiate_issuance", {"credential_offer": _offer_uri(payload)}
        )
        assert initiate_result.data["status"] == "waiting_for_user_authorization"
        session_id = initiate_result.data["session_id"]

        begin_result = await client.call_tool(
            "begin_authorization",
            {
                "session_id": session_id,
                "client_id": "test-client",
                "redirect_uri": "https://client.example.com/cb",
            },
        )
        assert begin_result.data["status"] == "awaiting_authorization_result"
        authorization_url = begin_result.data["authorization_url"]
        assert authorization_url.startswith("https://issuer.example.com/authorize?")
        state = parse_qs(urlsplit(authorization_url).query)["state"][0]

        submit_result = await client.call_tool(
            "submit_authorization_result",
            {"session_id": session_id, "code": "auth-code", "state": state},
        )
        assert submit_result.data["status"] == "ready_for_credential_request"

        request_result = await client.call_tool(
            "request_credential", {"session_id": session_id}
        )

    assert request_result.data == {"session_id": session_id, "status": "completed"}


async def test_begin_authorization_surfaces_an_unknown_session_as_a_tool_error() -> None:
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="No issuance session"):
            await client.call_tool(
                "begin_authorization",
                {
                    "session_id": "does-not-exist",
                    "client_id": "test-client",
                    "redirect_uri": "https://client.example.com/cb",
                },
            )


async def test_begin_authorization_surfaces_a_not_ready_session_as_a_tool_error(
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

        with pytest.raises(ToolError, match="not ready"):
            await client.call_tool(
                "begin_authorization",
                {
                    "session_id": initiate_result.data["session_id"],
                    "client_id": "test-client",
                    "redirect_uri": "https://client.example.com/cb",
                },
            )


async def test_submit_authorization_result_surfaces_an_unknown_session_as_a_tool_error() -> None:
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="No issuance session"):
            await client.call_tool(
                "submit_authorization_result",
                {"session_id": "does-not-exist", "code": "auth-code", "state": "x"},
            )


async def test_submit_authorization_result_surfaces_a_not_ready_session_as_a_tool_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "oauth-authorization-server" in path:
            return httpx.Response(
                200,
                json={
                    "issuer": "https://issuer.example.com",
                    "token_endpoint": "https://issuer.example.com/token",
                    "authorization_endpoint": "https://issuer.example.com/authorize",
                },
            )
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

    monkeypatch.setattr(httpx, "AsyncClient", mock_async_client(handler))

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
                "submit_authorization_result",
                {
                    "session_id": initiate_result.data["session_id"],
                    "code": "auth-code",
                    "state": "x",
                },
            )
