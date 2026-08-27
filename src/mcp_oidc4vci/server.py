from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from mcp_oidc4vci.credential_offer import InvalidCredentialOfferError, resolve_credential_offer

mcp = FastMCP(name="oidc4vci")


@mcp.tool
async def inspect_credential_offer(credential_offer: str) -> dict[str, Any]:
    """Parse and validate an OIDC4VCI Credential Offer URI.

    Resolves the offer (by value or by reference) and returns its Credential Issuer,
    requested credential configuration IDs, and available grants.
    """
    try:
        offer = await resolve_credential_offer(credential_offer)
    except InvalidCredentialOfferError as exc:
        raise ToolError(str(exc)) from exc
    return offer.model_dump(mode="json", exclude_none=True, by_alias=True)


def main() -> None:
    mcp.run()
