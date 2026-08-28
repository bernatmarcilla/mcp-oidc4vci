# Architecture

This document describes the technical design of the OIDC4VCI MCP server: the components, boundaries, data flow, tool contracts, and security requirements. For the project's motivation and background, see the [README](../README.md).

**Spec version:** this project targets [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) (final specification). Field names and JSON shapes below follow that version.

---

## High-Level Architecture

```text
                            ┌─────────────────┐
                            │                 │
                            │    AI Agent     │
                            │                 │
                            └────────┬────────┘
                                     │
                                     │ MCP
                                     ▼
                            ┌─────────────────┐
                            │                 │
                            │ OIDC4VCI MCP    │
                            │     Server      │
                            │                 │
                            └────────┬────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
                    ▼                ▼                ▼
             Credential Offer    Credential        Authorization
                                 Issuer            Server
                    │
                    │
                    ▼
              Wallet Boundary
                    │
                    ▼
          Key Management / Proofs
          Credential Storage
          User Authorization
```

The MCP server acts as an intermediary between the AI agent and the OIDC4VCI ecosystem. However, the MCP server should not automatically become a wallet.

---

## Core Design Principles

### 1. The AI agent is not the wallet

The AI agent should not be responsible for:

- Managing private keys.
- Storing sensitive credentials.
- Generating cryptographic proofs directly.
- Automatically authorizing credential requests.
- Bypassing user consent.

The AI agent can understand and orchestrate the process, but sensitive operations remain outside of the LLM context.

### 2. MCP exposes capabilities, not raw secrets

A key design principle is to expose high-level capabilities instead of unnecessarily exposing sensitive data.

For example, instead of returning:

```json
{
  "private_key": "...",
  "credential": {
    "name": "John Doe",
    "date_of_birth": "..."
  }
}
```

the MCP interface should expose structured and constrained operations, such as `inspect_credential_offer()` or `get_issuance_requirements()`.

The AI receives the information necessary to reason about the flow without receiving secrets or unnecessary personal data.

### 3. User authorization remains explicit

Whenever an action has security or privacy implications, the architecture should support an explicit handoff to the user or wallet.

```text
Agent
  │
  │ "Credential issuance requires proof of possession"
  │
  ▼
MCP Server
  │
  │ Request wallet operation
  ▼
Wallet
  │
  │ User approval
  │
  │ Key selection / proof generation
  ▼
OIDC4VCI flow continues
```

The agent can explain what is happening but should not silently perform actions that normally require holder authorization.

---

## Architecture Components

### 1. MCP Server

The main component of the project. Responsible for exposing protocol-aware tools to an AI agent.

Responsibilities include:

- Credential Offer parsing.
- Metadata retrieval.
- Issuance flow orchestration.
- Session management.
- Protocol validation.
- Returning structured results.

### 2. OIDC4VCI Client

A protocol-specific component responsible for interacting with Credential Issuers, Authorization Servers, and Credential Endpoints.

This component should contain as much of the actual protocol logic as possible. The MCP layer should ideally remain relatively thin:

```text
MCP Tool
   ↓
Application Service
   ↓
OIDC4VCI Client
   ↓
Remote Issuer
```

This separation makes the project easier to test and potentially allows the OIDC4VCI implementation to be reused without MCP.

### 3. Issuance Session Manager

Responsible for maintaining the state of an issuance process:

```text
IssuanceSession
│
├── session_id
├── credential_offer
├── credential_issuer
├── authorization_server
├── flow_type
├── authorization_state
├── wallet_interaction_state
└── issuance_status
```

This is important because MCP tool calls may not correspond to one continuous protocol transaction. The system needs a way to preserve state between interactions.

### 4. Wallet Adapter

Responsible for interacting with the wallet boundary — implemented as a `typing.Protocol` in [`src/mcp_oidc4vci/wallet.py`](../src/mcp_oidc4vci/wallet.py), with `MockWalletAdapter` as the initial implementation. A production implementation could support different real wallet integrations behind the same interface.

---

## Wallet Boundary

The wallet is deliberately treated as a separate security domain.

```text
┌─────────────────────────────┐
│          MCP Server         │
│                             │
│  - Parse offers             │
│  - Fetch metadata           │
│  - Manage issuance state    │
│  - Initiate protocol flows  │
│  - Explain requirements     │
└──────────────┬──────────────┘
               │
               │ Explicit interaction
               ▼
┌─────────────────────────────┐
│            Wallet           │
│                             │
│  - Manage keys              │
│  - Select holder keys       │
│  - Generate proofs          │
│  - Request user consent     │
│  - Receive credentials      │
│  - Store credentials        │
└─────────────────────────────┘
```

The exact integration mechanism between the MCP server and wallet is intentionally left open in the first version of the project. Possible approaches include:

- A mock wallet.
- A wallet adapter interface.
- A local wallet service.
- A QR/deep-link handoff.
- An external wallet implementation.

For the initial prototype, a mock or reference wallet implementation may be sufficient.

### Wallet Adapter

To avoid coupling the MCP server to a specific wallet implementation, [`src/mcp_oidc4vci/wallet.py`](../src/mcp_oidc4vci/wallet.py) defines an abstract interface — narrowed to exactly what the issuance engine currently calls, not the full surface a real wallet integration will eventually need:

```text
WalletAdapter (Protocol)
│
├── generate_proof(audience, nonce) -> proof JWT
│
└── receive_credential(credential_configuration_id, credential) -> None
```

The MCP server does not need to know how keys are stored or how the wallet implements cryptographic operations. Instead, it requests a capability:

```text
MCP Server:
  "A proof is required for this credential request."

        ↓

Wallet Adapter:
  generate_proof(audience=credential_issuer, nonce=c_nonce)

        ↓

Wallet:
  Cryptographic operation (in a real wallet: after user approval)

        ↓

Proof returned to protocol layer
```

`MockWalletAdapter` implements this by generating an ephemeral EC (P-256) keypair in-process and signing a real `openid4vci-proof+jwt` per spec ("`jwt` Proof Type") — enough to exercise the full protocol round-trip against a real or test issuer. It is explicitly **not** production-safe: a real wallet holds its keys in its own security boundary (hardware-backed keystore, secure enclave, a separate signing service) and is never this MCP server itself. `receive_credential` takes custody of each issued credential; the MCP server does not retain it, and no tool ever returns a credential's contents to the agent.

Two methods from the original sketch of this interface — `requestUserAuthorization()` and `prepareKeyBinding()` / `getCapabilities()` — aren't implemented yet. They become relevant once the authorization code grant is completed (needs user-facing consent) and once proof type / cryptographic binding negotiation matters (multiple proof types, key attestation).

---

## Data Flow

### Phase 1: Credential Offer Inspection

```text
User
 │
 │ Credential Offer
 ▼
AI Agent
 │
 │ inspect_credential_offer()
 ▼
MCP Server
 │
 ▼
Structured Result
 │
 ▼
AI Agent
 │
 ▼
User explanation
```

### Phase 2: Issuer Metadata Retrieval

```text
AI Agent
 │
 │ get_credential_issuer_metadata()
 ▼
MCP Server
 │
 │ HTTP
 ▼
Credential Issuer
 │
 │ Metadata
 ▼
MCP Server
 │
 ▼
Structured Result
```

### Phase 3: Issuance Flow Determination

```text
Credential Offer
        │
        ▼
┌───────────────────┐
│ Available Grants  │
└─────────┬─────────┘
          │
     ┌────┴─────┐
     │          │
     ▼          ▼
Authorization  Pre-authorized
Code Flow      Code Flow
```

The MCP server determines the supported flow and exposes the next required action.

### Phase 4: Wallet Interaction

```text
MCP Server
     │
     │ Wallet operation required
     ▼
Wallet Adapter
     │
     ▼
Wallet
     │
     ├── User consent
     ├── Key selection
     └── Proof generation
```

The result is returned to the protocol layer without exposing private key material.

---

## Proposed MCP Tools

### `inspect_credential_offer`

Parses and validates a Credential Offer, passed either by value (`credential_offer` query parameter, a JSON object) or by reference (`credential_offer_uri`, fetched by the server). See spec §4.1.

**Input**

```json
{
  "credential_offer": "openid-credential-offer://?credential_offer=..."
}
```

**Output**

```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_configuration_ids": ["UniversityDegreeCredential"],
  "grants": {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "oaKazRN8I0IbtZ0C7JuMn5",
      "tx_code": {
        "input_mode": "numeric",
        "length": 4,
        "description": "Please provide the one-time code sent via e-mail"
      }
    }
  }
}
```

`grants` is optional in the spec and, when present, is keyed by grant type identifier — `authorization_code` and/or `urn:ietf:params:oauth:grant-type:pre-authorized_code` — each with its own sub-fields (`issuer_state`, `authorization_server`, `pre-authorized_code`, `tx_code`). When absent, the Wallet is expected to determine the flow itself; `describe_issuance_flow` should surface that as an explicit case rather than defaulting silently.

**Responsibilities**

- Resolve the offer: parse the by-value JSON object, or dereference `credential_offer_uri` over HTTPS.
- Validate the expected structure (`credential_issuer` and non-empty `credential_configuration_ids` are required).
- Extract the Credential Issuer.
- Extract requested credential configuration identifiers.
- Identify the grant type(s) offered and their parameters, without exposing more than the agent needs.
- Avoid exposing unnecessary data.

Implemented in [`src/mcp_oidc4vci/credential_offer.py`](../src/mcp_oidc4vci/credential_offer.py).

### `get_credential_issuer_metadata`

Retrieves metadata for a Credential Issuer from its well-known endpoint. Per spec ("Credential Issuer Metadata Retrieval"), the well-known path segment is *inserted* between the host and path components of the `credential_issuer` identifier, not simply appended — e.g. `https://issuer.example.com/tenant` resolves to `https://issuer.example.com/.well-known/openid-credential-issuer/tenant`. The identifier itself must be an `https` URL with no query or fragment.

**Input**

```json
{
  "credential_issuer": "https://issuer.example.com"
}
```

**Output**

```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_endpoint": "https://issuer.example.com/credential",
  "authorization_servers": ["https://issuer.example.com"],
  "credential_configurations_supported": {
    "UniversityDegreeCredential": {
      "format": "vc+sd-jwt",
      "credential_signing_alg_values_supported": ["ES256"],
      "credential_metadata": {
        "display": [
          { "name": "University Degree", "locale": "en-US" }
        ]
      }
    }
  }
}
```

Note that `credential_configurations_supported` is an object keyed by credential configuration ID — the same IDs referenced in `inspect_credential_offer`'s `credential_configuration_ids` — not an array. `credential_endpoint` and `credential_configurations_supported` are required by the spec; `authorization_servers` is optional. `credential_signing_alg_values_supported` and `cryptographic_binding_methods_supported` are both optional. The human-readable display name for a credential lives under the nested `credential_metadata.display` array, not directly on the configuration entry.

**Responsibilities**

- Construct the well-known metadata URL by inserting the well-known segment between the identifier's host and path.
- Reject a `credential_issuer` that isn't an `https` URL, or that carries a query or fragment.
- Retrieve and validate the metadata document (required fields: `credential_issuer`, `credential_endpoint`, `credential_configurations_supported`).
- Verify the returned `credential_issuer` is an exact string match for the requested identifier — the spec requires discarding the response otherwise, since a mismatch indicates the wrong document was served.
- Identify supported credential configurations, keyed by ID.
- Identify relevant protocol endpoints (`credential_endpoint`, and optionally `authorization_servers`, `deferred_credential_endpoint`, `notification_endpoint`).

Implemented in [`src/mcp_oidc4vci/credential_issuer_metadata.py`](../src/mcp_oidc4vci/credential_issuer_metadata.py).

### `describe_issuance_flow`

Provides a normalized description of the steps required to obtain the offered credential. Takes the same offer URI as `inspect_credential_offer` — no prior session or offer ID is needed, since the flow is fully determined by the offer's `grants`.

**Input**

```json
{
  "credential_offer": "openid-credential-offer://?credential_offer=..."
}
```

**Output**

```json
{
  "flow_type": "authorization_code",
  "steps": [
    {
      "step": 1,
      "action": "user_authorization",
      "description": "The user must authorize credential issuance."
    },
    {
      "step": 2,
      "action": "wallet_proof",
      "description": "A proof may be required during the credential request."
    },
    {
      "step": 3,
      "action": "credential_request",
      "description": "The credential can be requested from the issuer."
    }
  ]
}
```

`flow_type` is the grant type identifier itself (`authorization_code` or `urn:ietf:params:oauth:grant-type:pre-authorized_code`) — when an offer declares both, the pre-authorized code grant is preferred, since it needs no redirect to an external Authorization Server. An offer with no `grants` at all requires discovering supported flows from Authorization Server metadata, which isn't implemented yet; the tool reports that explicitly rather than guessing.

This tool abstracts protocol complexity into something easier for an agent to reason about.

### `initiate_issuance`

Starts an issuance session for the offer's chosen flow, tracked server-side and referenced by `session_id` in every response — no protocol secrets (tokens, codes) are ever returned to the agent.

**Input**

```json
{
  "credential_offer": "openid-credential-offer://?credential_offer=...",
  "tx_code": "493536"
}
```

`tx_code` is the transaction code the user obtained out-of-band (e.g. via email or SMS), required only when the offer's pre-authorized code grant declares a `tx_code` object.

**Output**

```json
{
  "session_id": "9f1c2e40-...-b2a6",
  "status": "ready_for_credential_request"
}
```

or, on failure:

```json
{
  "session_id": "9f1c2e40-...-b2a6",
  "status": "failed",
  "error": "code expired"
}
```

Behavior differs by grant type:

- **Pre-authorized code grant:** completes the Token Request immediately (spec "Token Request") — it needs no user interaction with an external Authorization Server. On success the session becomes `ready_for_credential_request` (the access token is held server-side); on a rejected or malformed exchange it becomes `failed` with a short `error` message.
- **Authorization code grant:** the session is left `waiting_for_user_authorization`. Completing this flow requires a wallet-driven browser redirect and PKCE — that belongs to the Wallet Adapter, not this tool, so `initiate_issuance` deliberately stops short of it rather than fabricating an incomplete authorization URL.

### `get_issuance_status`

Returns the current state of a previously started issuance session, in the same shape `initiate_issuance` returns.

```json
{
  "session_id": "9f1c2e40-...-b2a6",
  "status": "waiting_for_user_authorization"
}
```

Session states currently in use:

```text
created
waiting_for_user_authorization   (authorization_code grant, awaiting the wallet boundary)
ready_for_credential_request     (pre-authorized_code grant, token exchange succeeded)
awaiting_wallet_proof            (request_wallet_proof called; awaiting submit_wallet_proof)
completed                        (request_credential or submit_wallet_proof succeeded)
failed
```

The remaining states from the original design (`authorization_completed`, `waiting_for_wallet_operation`, `credential_requested`) come into play once the authorization code grant is completed and deferred issuance is supported.

Sessions are held in an in-memory, process-local store (`IssuanceSessionStore` in [`src/mcp_oidc4vci/issuance.py`](../src/mcp_oidc4vci/issuance.py)) — they don't survive a server restart and aren't shared across server instances. That's an accepted limitation for the current single-process MVP, not a spec requirement. To bound memory growth in a long-running process, each session carries a `created_at` timestamp and is evicted once it's older than `ttl_seconds` (default one hour); eviction is lazy — swept on the next `create`/`update`/`get` call rather than by a background task — and an expired `session_id` behaves exactly like an unknown one.

`describe_issuance_flow`, `initiate_issuance`, and `get_issuance_status` are implemented in [`src/mcp_oidc4vci/issuance.py`](../src/mcp_oidc4vci/issuance.py), which relies on [`src/mcp_oidc4vci/authorization_server_metadata.py`](../src/mcp_oidc4vci/authorization_server_metadata.py) (RFC 8414 discovery of the token endpoint) and [`src/mcp_oidc4vci/token_request.py`](../src/mcp_oidc4vci/token_request.py) (the pre-authorized code Token Request).

### `request_credential`

Completes the Credential Request for a session that has an access token (`status: "ready_for_credential_request"`), producing an issued credential without ever exposing its contents — or any key material — to the agent.

**Input**

```json
{
  "session_id": "9f1c2e40-...-b2a6"
}
```

**Output**

```json
{
  "session_id": "9f1c2e40-...-b2a6",
  "status": "completed"
}
```

or, on failure:

```json
{
  "session_id": "9f1c2e40-...-b2a6",
  "status": "failed",
  "error": "proof nonce expired"
}
```

**Responsibilities**

- Reject a session that isn't `ready_for_credential_request` (or has no access token) with a `SessionNotReadyError` — a caller mistake, not a normal issuance-flow outcome, so it surfaces as a tool error rather than mutating the session.
- Fetch Credential Issuer Metadata to find `credential_endpoint` and the optional `nonce_endpoint`.
- Request a fresh `c_nonce` from the Nonce Endpoint when the issuer has one (spec "Nonce Endpoint").
- Ask the `WalletAdapter` to generate a key-proof JWT over `{audience: credential_issuer, nonce: c_nonce}` — this server never signs anything itself.
- Send the Credential Request (`credential_configuration_id` + `proofs.jwt`) with the session's access token as a Bearer token.
- Hand each issued credential to `wallet.receive_credential(...)`; the tool's own return value never includes the credential's contents.
- On a rejected or malformed exchange, or a deferred response (`transaction_id` — not yet supported), mark the session `failed` with a short `error` message, mirroring how `initiate_issuance` handles Token Request failures.

Implemented in [`src/mcp_oidc4vci/credential_request.py`](../src/mcp_oidc4vci/credential_request.py), which relies on [`src/mcp_oidc4vci/nonce.py`](../src/mcp_oidc4vci/nonce.py) and the `WalletAdapter` boundary in [`src/mcp_oidc4vci/wallet.py`](../src/mcp_oidc4vci/wallet.py).

**Known simplification:** always requests exactly one credential, for the first ID in `credential_configuration_ids`, and always includes a `jwt` proof — the spec only requires `proofs` when the configuration declares `proof_types_supported`, but sending one unconditionally is harmless and keeps the logic simple.

**Strict v1.0 compliance:** `CredentialResponse` only recognizes the final spec's `credentials` array — a pre-final draft's singular `credential` field (still returned by at least one real issuer's dev/test environment encountered during development) is deliberately *not* accepted as an alias. A non-conformant response is reported clearly (`InvalidCredentialResponseError` naming the actual top-level fields received) rather than silently worked around. Also supports DPoP-bound access tokens end to end (RFC 9449; see [`src/mcp_oidc4vci/dpop.py`](../src/mcp_oidc4vci/dpop.py)) — required by that same environment's Authorization Server.

### `request_wallet_proof` and `submit_wallet_proof`

An alternative, manual two-step path to `request_credential`, for when the proof must be produced by something outside this server — a real wallet, or a human signing by hand — rather than synchronously by an in-process `WalletAdapter`.

A genuinely real wallet takes real-world time to approve a request (a person unlocking a device, tapping approve), which a single blocking tool call can't represent well: MCP tool calls are request/response, and while a server-side await *can* take a while, nothing can resolve it except something outside the current conversation turn — the calling agent cannot make a second tool call while the first is still pending. So this is split into two ordinary, non-blocking tool calls that hand off through the session, the same way `initiate_issuance` and `get_issuance_status` already do — not through a blocking wait.

**`request_wallet_proof`** — same guard and same metadata/nonce lookup as `request_credential`, but stops there: it does not call any `WalletAdapter`. It moves the session to `awaiting_wallet_proof` and returns what needs to be signed.

**Input**

```json
{
  "session_id": "9f1c2e40-...-b2a6"
}
```

**Output**

```json
{
  "session_id": "9f1c2e40-...-b2a6",
  "status": "awaiting_wallet_proof",
  "proof_request": {
    "audience": "https://issuer.example.com",
    "nonce": "fresh-nonce"
  }
}
```

(`nonce` is omitted when the issuer has no Nonce Endpoint.) The agent is expected to get a `jwt` proof JWT signed against exactly this `{audience, nonce}` — spec "`jwt` Proof Type" — from whatever is standing in for the wallet, and pass it to `submit_wallet_proof`.

**`submit_wallet_proof`** — takes that externally-produced proof, re-fetches Credential Issuer Metadata for `credential_endpoint` (the nonce isn't needed again — it's already embedded in the proof), and otherwise does exactly what `request_credential` does after it has a proof: send the Credential Request, hand the result to `wallet.receive_credential(...)`, end the session `completed` or `failed`. It does **not** validate the proof's claims against what was asked for before sending it — the issuer already does that (`invalid_proof` / `invalid_nonce` error codes) and duplicating the check wouldn't catch anything the issuer's own rejection doesn't.

**Input**

```json
{
  "session_id": "9f1c2e40-...-b2a6",
  "proof_jwt": "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIs..."
}
```

Rejects a session that isn't `awaiting_wallet_proof` with `SessionNotReadyError`, same as `request_credential`'s own guard.

Both are implemented in [`src/mcp_oidc4vci/credential_request.py`](../src/mcp_oidc4vci/credential_request.py), sharing the metadata/nonce lookup and the send-and-parse logic with `request_credential` (`_prepare_proof_request` / `_send_credential_request`) so all three paths stay behaviorally identical wherever they overlap.

**Why not a blocking wait with a webhook callback instead?** That's the more capable design — an MCP tool call blocks server-side on an `asyncio.Future`, resolved either by an HTTP callback a real wallet-side service POSTs to, or a concurrent poll, whichever comes first. It's a real, working pattern (a pending-call registry keyed by request ID, resolved by whichever of the callback or the poll arrives first), and it's the right shape once there's an actual external wallet/gateway on the other end capable of calling back. It's deliberately not what's built here yet: without a real wallet counterpart to call back, that machinery would have nothing to resolve it. The two-tool-call version above needs no new infrastructure and is the natural stepping stone — swapping in a real wallet later means adding a QR/deep-link step in front of `request_wallet_proof`, not rebuilding the waiting logic.

---

## Example Interaction

A user says:

> I received this credential offer. Can you help me get the credential?

The agent calls `inspect_credential_offer`:

```json
{
  "credential_issuer": "https://issuer.example.com",
  "credential_configuration_ids": ["UniversityDegreeCredential"],
  "grants": {
    "authorization_code": {}
  }
}
```

The agent then calls `get_credential_issuer_metadata`, then `describe_issuance_flow`:

```json
{
  "flow_type": "authorization_code",
  "steps": [
    { "step": 1, "action": "user_authorization" },
    { "step": 2, "action": "wallet_proof" },
    { "step": 3, "action": "credential_request" }
  ]
}
```

The agent tells the user:

> The offer is for a University Degree Credential issued by Example University. To continue, you need to authorize the issuance process.

If the user agrees, the agent calls `initiate_issuance`:

```json
{
  "session_id": "issuance_123",
  "status": "waiting_for_user_authorization"
}
```

At this point, the application hands control to the appropriate authorization or wallet interaction.

Had the offer instead used the pre-authorized code grant, `initiate_issuance` would complete the token exchange in that same call and return `status: "ready_for_credential_request"` directly. The agent can then call `request_credential`:

```json
{
  "session_id": "issuance_123",
  "status": "completed"
}
```

The issued credential itself never appears in this response — `request_credential` hands it to the `WalletAdapter` (`MockWalletAdapter` today), which is where it's held. This is the one path, end to end, that's fully wired up today: by-value or by-reference offer → issuer metadata → token exchange → wallet-generated proof → credential request → credential in the wallet's custody.

**Debug tool:** `debug_inspect_mock_wallet_credentials` (in [`src/mcp_oidc4vci/server.py`](../src/mcp_oidc4vci/server.py)) lists what the in-process `MockWalletAdapter` has received — the only way to inspect an issued credential without violating the "never returns to the agent" rule above, and only meaningful because today's wallet happens to be a mock. It's registered as an MCP tool only when the `MCP_OIDC4VCI_DEBUG_TOOLS` environment variable is set (`1`/`true`/`yes`); otherwise it isn't discoverable at all. It should be removed once a real (non-mock) wallet is wired in.

---

## Security Requirements

### Private keys

Private keys must never be:

- Returned by MCP tools.
- Added to the LLM context.
- Logged.
- Stored in issuance sessions.

### User consent

Operations that require authorization should not be silently performed by the AI agent. The MCP server should return an explicit state such as:

```json
{
  "status": "user_interaction_required"
}
```

The application can then perform the required interaction.

### Sensitive data minimization

MCP tool responses should return only the information necessary for the agent to perform its task.

The agent may need to know:

```text
Credential type: University Degree
Issuer: Example University
Authorization required: Yes
```

It does not necessarily need to know:

```text
Full personal information
Private keys
Authentication tokens
Raw credentials
```

### Token handling

Access tokens, authorization codes, and pre-authorized codes are treated as sensitive values that never cross the MCP boundary. `initiate_issuance` performs the Token Request server-side and stores the resulting access token only inside the in-memory `IssuanceSession` record (`src/mcp_oidc4vci/issuance.py`) — `get_issuance_status` and `initiate_issuance`'s own return value expose only `session_id`, `status`, and (on failure) a short `error` string:

```text
Agent
  │
  │ initiate_issuance()
  ▼
MCP Server
  │
  ├── Performs the Token Request, stores the access token server-side
  │
  ▼
Returns
{
  "session_id": "abc123",
  "status": "ready_for_credential_request"
}
```

Subsequent calls use the session ID rather than exposing tokens to the agent.

### Logging

Each module logs its own lifecycle and error/retry events (session creation, token/credential request outcomes, DPoP nonce retries, metadata fetch failures) via the standard `logging` module — configured to stream to stderr in `main()`, since stdout carries the MCP JSON-RPC transport and can't be shared with log output. Log messages never include access tokens, DPoP private keys, proof JWTs, or credential content; failures are logged with their error text — already sanitized to field names rather than values, per the "Strict v1.0 compliance" diagnostics in `request_credential` above — rather than raw response bodies. Level defaults to `INFO` and is configurable via `MCP_OIDC4VCI_LOG_LEVEL`.

---

## Interesting Research Questions

This project should not just be an implementation exercise. It can also explore several architectural questions.

**How should sensitive protocol state be represented in MCP?**

Should an agent see `access_token`, `authorization_code`, `c_nonce`? Or should it only see `issuance_session_id`, `status`, `next_action`? The second approach is likely safer and creates a useful abstraction boundary.

**How much protocol knowledge should live in the LLM?**

The agent could understand "this flow requires user authorization." But the actual implementation of authorization request construction, PKCE, token exchange, nonce handling, and credential requests should likely remain deterministic application logic. This suggests:

```text
LLM
=
Intent + explanation + orchestration

MCP Server
=
Capabilities + protocol abstraction

OIDC4VCI Client
=
Protocol implementation
```

**Can MCP tool schemas improve safety?**

Tools can require structured input (e.g. `{ "session_id": "..." }`) rather than allowing an agent to construct arbitrary protocol requests. This can constrain the agent to supported operations and reduce the risk of protocol misuse.

---

## Technology Considerations

The implementation could be divided into:

```text
apps/
  agent-client/

services/
  mcp-server/
  oidc4vci-client/
  wallet-adapter/

packages/
  protocol-models/
  shared-types/

tests/
  fixtures/
  integration/
```

A possible architecture:

```text
┌──────────────────────────────────────┐
│             Agent Client             │
└───────────────────┬──────────────────┘
                    │ MCP
┌───────────────────▼──────────────────┐
│             MCP Server               │
│                                      │
│  inspect_offer                       │
│  get_metadata                        │
│  describe_flow                       │
│  initiate_issuance                   │
│  get_status                          │
└───────────────────┬──────────────────┘
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
┌─────────────────┐   ┌─────────────────┐
│ OIDC4VCI Client │   │ Wallet Adapter  │
└────────┬────────┘   └────────┬────────┘
         │                     │
         ▼                     ▼
  Credential Issuer         Wallet
```

See the [README](../README.md#tech-stack) for the concrete stack chosen for the Python implementation (FastMCP, MCP Python SDK, uv, MCP Inspector).
