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

For the full system design, see [Architecture](docs/ARCHITECTURE.md). For the planned build-out and current scope, see [Roadmap](docs/ROADMAP.md).

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

## Project status

Early-stage. The architecture and MVP scope are drafted in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

**Phase 1 (MCP Credential Offer Inspector) — in progress.** `inspect_credential_offer` is implemented: it resolves a Credential Offer by value or by reference (`credential_offer_uri`), validates it against OIDC4VCI 1.0, and returns the issuer, requested credential configuration IDs, and grants. See [src/mcp_oidc4vci/credential_offer.py](src/mcp_oidc4vci/credential_offer.py) and [src/mcp_oidc4vci/models.py](src/mcp_oidc4vci/models.py), with tests in [tests/](tests/).

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

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — components, design principles, wallet boundary, data flow, MCP tool contracts, security requirements.
- [Roadmap](docs/ROADMAP.md) — MVP scope, development phases, non-goals, success criteria, future extensions.
