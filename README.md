# MCP-OIDC4VCI

### AI-Assisted Verifiable Credential Issuance using MCP

This project explores how the **Model Context Protocol (MCP)** can be used to expose capabilities from an **OpenID for Verifiable Credential Issuance (OIDC4VCI)** ecosystem to an AI agent. It targets [OIDC4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) (final specification).

The goal is not to replace a wallet, nor to give an LLM access to private keys or unrestricted credentials. Instead, the project investigates a more constrained architecture:

> **An MCP server acts as an agent-facing orchestration layer for understanding and progressing through an OIDC4VCI credential issuance flow, while security-sensitive operations remain under the control of dedicated components such as the wallet or credential holder.**

The project starts from a concrete scenario:

> A user receives an OIDC4VCI Credential Offer and wants an AI agent to help understand what is being offered and guide or orchestrate the issuance process.

---

## Motivation

OIDC4VCI defines a protocol for issuing Verifiable Credentials to a wallet or credential holder. A typical flow involves a Credential Offer, a Credential Issuer and its metadata, an Authorization Server, authorization or pre-authorized flows, credential requests, proofs and cryptographic key binding, and credential delivery and storage — a significant amount of structured information for a user to parse on their own.

An AI agent can potentially help by understanding a credential offer, explaining what's being offered, discovering supported credential configurations, determining the required issuance flow, identifying what's needed next, and orchestrating non-sensitive protocol interactions.

The central question this project explores is:

> **How can OIDC4VCI capabilities be exposed to an AI agent through MCP without compromising the security boundaries of wallets and cryptographic key material?**

For the full system design, see [Architecture](docs/ARCHITECTURE.md).

---

## Architecture at a glance

```text
   AI Agent ──MCP──▶ OIDC4VCI MCP Server ──▶ Credential Issuer / Authorization Server
                              │
                              ▼
                       Wallet Boundary
                              │
                              ▼
              Key Management / Proofs / User Authorization
```

The MCP server acts as an intermediary between the AI agent and the OIDC4VCI ecosystem — it should not automatically become a wallet. Sensitive operations (keys, proofs, consent) stay behind an explicit wallet boundary, never in the LLM context.

Full details, component responsibilities, data flows, tool contracts, and security requirements live in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Feature support

| Feature | Status |
| --- | --- |
| Credential Offer, by value or by reference | Supported |
| Pre-Authorized Code Grant | Supported |
| Authorization Code Grant | Supported |
| PKCE ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), `S256`) | Supported |
| Pushed Authorization Requests ([RFC 9126](https://www.rfc-editor.org/rfc/rfc9126)) | Supported, auto-detected from Authorization Server metadata |
| DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) | Supported, auto-detected from Authorization Server metadata |
| Rich Authorization Requests / `authorization_details` ([RFC 9396](https://www.rfc-editor.org/rfc/rfc9396)) | Supported, replaced by a `scope` fallback when one is available, for Authorization Servers that don't support RAR |
| Transaction Code (`tx_code`) | Supported |
| Nonce Endpoint / `c_nonce` | Supported |
| `jwt` Proof Type | Supported |
| `attestation` Proof Type / key attestation | Not yet |
| Deferred Credential Issuance | Supported |
| Multiple credential configurations per offer | Supported — one Credential Request per configuration, one per tool call |
| Signed (JWT) Credential Issuer Metadata | Not verified — plain JSON is requested and used instead |
| Credential Request/Response Encryption | Not yet |
| Batch Credential Issuance | Not yet |
| Notification Endpoint | Not yet — `notification_id` is parsed but not acted on |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design reasoning behind each of these.

---

## Current capabilities

This project is under active development. Here's what's implemented today.

**Credential Offer inspection.** `inspect_credential_offer` resolves a Credential Offer by value or by reference (`credential_offer_uri`), validates it against OIDC4VCI 1.0, and returns the issuer, requested credential configuration IDs, and grants. See [src/mcp_oidc4vci/credential_offer.py](src/mcp_oidc4vci/credential_offer.py).

**Credential Issuer metadata discovery.** `get_credential_issuer_metadata` fetches and validates a Credential Issuer's metadata from its well-known endpoint (correctly inserting the well-known path segment ahead of any path component in the issuer identifier, per spec), verifies the returned `credential_issuer` matches what was requested, and returns the credential endpoint, authorization servers, and supported credential configurations. See [src/mcp_oidc4vci/credential_issuer_metadata.py](src/mcp_oidc4vci/credential_issuer_metadata.py).

**Issuance flow orchestration.** `describe_issuance_flow`, `initiate_issuance`, and `get_issuance_status` run on top of an in-memory `IssuanceSessionStore`. For the pre-authorized code grant, `initiate_issuance` completes the full Token Request end to end — OAuth Authorization Server discovery via RFC 8414, then the token exchange, including a [DPoP](https://www.rfc-editor.org/rfc/rfc9449) proof of possession when the Authorization Server requires one. For the authorization code grant, it resolves the Authorization Server's metadata and leaves the session ready for `begin_authorization`. See [src/mcp_oidc4vci/issuance.py](src/mcp_oidc4vci/issuance.py), [src/mcp_oidc4vci/authorization_server_metadata.py](src/mcp_oidc4vci/authorization_server_metadata.py), [src/mcp_oidc4vci/token_request.py](src/mcp_oidc4vci/token_request.py), and [src/mcp_oidc4vci/dpop.py](src/mcp_oidc4vci/dpop.py).

**Authorization code grant.** `begin_authorization` builds the Authorization Request URL (PKCE, RFC 7636, `S256`; `authorization_details` naming the requested credential configurations, RFC 9396 — replaced by each configuration's own `scope`, when one is available, for an Authorization Server that doesn't support Rich Authorization Requests) for a human to open and complete — pushing its parameters first via [Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126) when the Authorization Server requires it, transparently to the caller — and `submit_authorization_result` exchanges the resulting `code`/`state` for an access token, rejecting a mismatched `state` before ever making a Token Request. This server has no HTTP endpoint of its own to receive the browser redirect, so the `code`/`state` are supplied back explicitly rather than captured automatically — see [Architecture](docs/ARCHITECTURE.md#begin_authorization-and-submit_authorization_result) for why. Both grants converge on the same `ready_for_credential_request` state from here. See [src/mcp_oidc4vci/authorization_request.py](src/mcp_oidc4vci/authorization_request.py), [src/mcp_oidc4vci/pushed_authorization_request.py](src/mcp_oidc4vci/pushed_authorization_request.py), and [src/mcp_oidc4vci/pkce.py](src/mcp_oidc4vci/pkce.py).

**Wallet boundary.** `WalletAdapter` (a `Protocol` with `generate_proof` and `receive_credential`) backs `request_credential`, which completes a Credential Request for a `ready_for_credential_request` session: fetch issuer metadata, get a fresh nonce if the issuer needs one, ask the wallet for a signed proof (a real EC-signed `openid4vci-proof+jwt`, never signed by this server), send it — DPoP-bound if the session's access token is — and hand the issued credential to the wallet, whose contents never reach the agent. The spec's Credential Request only ever names one credential configuration, so an offer requesting several gets one Request per configuration: `request_credential` handles one per call and returns to `ready_for_credential_request` (not `completed`) while more remain, for the caller to call it again. If the issuer defers issuance instead of responding immediately, the session moves to `awaiting_deferred_credential` and `poll_deferred_credential` checks back later, reusing the same authentication, response handling, and one-at-a-time rule. The bundled `MockWalletAdapter` makes both grants work end to end for local testing. See [src/mcp_oidc4vci/wallet.py](src/mcp_oidc4vci/wallet.py), [src/mcp_oidc4vci/credential_request.py](src/mcp_oidc4vci/credential_request.py), and [src/mcp_oidc4vci/nonce.py](src/mcp_oidc4vci/nonce.py).

**Manual wallet handoff.** `request_wallet_proof` / `submit_wallet_proof` split the Credential Request into two tool calls for when the proof must come from something other than the in-process `MockWalletAdapter` — a real wallet, or a human signing by hand — without needing any blocking-wait or webhook machinery: the handoff happens through the session, the same way `initiate_issuance` → `get_issuance_status` already does. `request_credential` (the automatic path) is unchanged and still there for fast, fully-automated testing. See [Architecture](docs/ARCHITECTURE.md#request_wallet_proof-and-submit_wallet_proof) for the design reasoning.

Shared data models live in [src/mcp_oidc4vci/models.py](src/mcp_oidc4vci/models.py), with tests in [tests/](tests/) (99% coverage, 262 tests).

---

## Tech Stack

- **[Python](https://www.python.org/)** — implementation language.
- **[uv](https://docs.astral.sh/uv/)** — dependency management, virtual environments, and running the project.
- **[FastMCP](https://github.com/jlowin/fastmcp)** — high-level Python framework for building the MCP server and its tools.
- **[MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)** — the underlying official protocol SDK that FastMCP builds on.
- **[MCP Inspector](https://github.com/modelcontextprotocol/inspector)** — interactive tool for testing and debugging the MCP server's tools during development.

---

## Getting Started

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync

# Run the MCP server through the MCP Inspector for interactive testing
uv run fastmcp dev inspector src/mcp_oidc4vci/server.py:mcp

# Lint, type-check, and run the test suite
uv run ruff check .
uv run mypy src
uv run pytest
```

### Testing the manual wallet-proof path without a real wallet

[scripts/sign_proof.py](scripts/sign_proof.py) signs a spec-shaped proof JWT the same way `MockWalletAdapter` does, but as a separate process — useful for exercising `request_wallet_proof` / `submit_wallet_proof` (see [Architecture](docs/ARCHITECTURE.md#request_wallet_proof-and-submit_wallet_proof)) when there's no real wallet app on hand:

```bash
uv run scripts/sign_proof.py --audience https://issuer.example.com --nonce abc123
```

Pass its output straight to `submit_wallet_proof`'s `proof_jwt` argument.

### Testing the authorization code grant

This server has no HTTP endpoint of its own to receive a browser redirect (see [Architecture](docs/ARCHITECTURE.md#begin_authorization-and-submit_authorization_result)), so completing this grant needs a real Authorization Server, a `client_id`/`redirect_uri` registered with it, and a browser: call `begin_authorization`, open the returned `authorization_url`, authenticate, and copy the `code`/`state` query parameters from wherever the browser lands after the redirect into `submit_authorization_result`.

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — components, design principles, wallet boundary, data flow, MCP tool contracts, security requirements.
