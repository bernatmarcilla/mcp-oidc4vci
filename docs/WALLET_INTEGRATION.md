# Integrating a Wallet with This MCP Server

This document is for a team building or operating a wallet (a mobile app, a backend service, a browser extension: whatever holds the user's keys and credentials) that wants to offer OIDC4VCI credential issuance **without implementing the OIDC4VCI protocol itself**. It walks through what this server takes off your plate, what stays your responsibility, how to wire your wallet into it, and the current limitations you should know about before committing to it.

It assumes you've read the [README](../README.md) for the project's motivation. For the full technical design, tool-by-tool contracts, and the reasoning behind every design choice, see [docs/ARCHITECTURE.md](ARCHITECTURE.md) — this document is a narrower, audience-specific entry point into the same system, not a replacement for it.

**You don't need an AI agent to use this.** The rest of this project's documentation talks about "the AI agent" a lot, because that's the scenario that motivated the project. But every MCP tool here is just a structured, typed RPC call — nothing about them requires an LLM in the loop. Your own backend (a plain orchestration service, a workflow engine, whatever drives your wallet's issuance logic today) can be an MCP client and call these tools directly, deterministically, with no model involved. If that's your situation, read "agent" below as "whatever calls the MCP tools" throughout.

---

## 1. What this server does for you, and what it doesn't

**It owns the parts of OIDC4VCI 1.0 that are pure protocol mechanics and don't touch your key material:**

- Parsing and validating a Credential Offer (by value or by reference).
- Fetching and validating Credential Issuer Metadata, including the signed-JWT representation some issuers use, with signature verification.
- Discovering the Authorization Server (RFC 8414) and completing the Token Request for both the pre-authorized code and authorization code grants.
- PKCE (RFC 7636), Pushed Authorization Requests (RFC 9126), and DPoP (RFC 9449) — all auto-detected from issuer/AS metadata, so you never have to decide whether a given issuer needs them.
- Building and sending the actual Credential Request, Deferred Credential Request, and Notification Request, with correct Bearer/DPoP authentication and retry-on-nonce-challenge behavior.
- Tracking where a given issuance is up to via an opaque `session_id`, so your integration doesn't have to re-implement a state machine for "what step are we on."

**It deliberately does *not* do, and never will, without you:**

- Hold or generate private keys.
- Produce a proof-of-possession signature.
- Decide whether the user consents to issuance.
- Store, display, or interpret the credential's content once issued.

That split is the whole point of the project (see [Architecture → Wallet Boundary](ARCHITECTURE.md#wallet-boundary)): this server is a protocol engine, not a wallet. It calls out to *your* code for exactly the two operations that need your key material, through the `WalletAdapter` interface described next, and never sees a private key or a completed credential pass through it either way — on the manual path (§2B below) it doesn't even see the signature, only confirmation that one was produced.

---

## 2. The two ways to plug your wallet in

Every other tool in this server is fixed — you call them the same way regardless of how your wallet works. The one real integration decision is **how your signing/consent logic gets called**, and there are two supported shapes.

### A. In-process `WalletAdapter` — if your signing is synchronous and co-located

Defined in [`src/mcp_oidc4vci/wallet.py`](../src/mcp_oidc4vci/wallet.py) as a `typing.Protocol` with exactly two methods:

```python
class WalletAdapter(Protocol):
    async def generate_proof(self, *, audience: str, nonce: str | None) -> str:
        """Return a signed key-proof JWT (spec "jwt Proof Type")."""
        ...

    async def receive_credential(
        self, *, credential_configuration_id: str, credential: str | dict[str, object]
    ) -> None:
        """Take custody of one issued credential."""
        ...
```

Implement this class, pass an instance of it into the `request_credential` / `poll_deferred_credential` call sites in [`src/mcp_oidc4vci/server.py`](../src/mcp_oidc4vci/server.py) (today those are wired to the bundled `MockWalletAdapter` — swapping it is a one-line change, not an extension point exposed over MCP itself, since signing is never something the calling agent should be able to redirect), and the automatic `request_credential` tool handles everything end to end: nonce fetch, proof generation, sending the request, handing you the result.

This only makes sense if `generate_proof` can actually return synchronously within one call — i.e., your signing key is reachable *from the same process this server runs in* (an embedded HSM client, a local secure-enclave binding, a signing library with no human-approval step in the middle). If approving a signature involves a person unlocking a phone, or a call to a separate service you don't control the latency of, don't use this path — use B.

`receive_credential` is also where you'd persist the issued credential into your own storage. The server does not retain it after this call returns.

### B. Manual two-call handoff — the realistic shape for most wallet companies

This is almost certainly what you want. If your wallet is its own app, its own backend, or anything that can't be called as a synchronous Python function from inside this server's process, use `request_wallet_proof` / `submit_wallet_proof` instead of `request_credential`:

1. Call **`request_wallet_proof(session_id)`**. The server does everything `request_credential` would do up to the point of needing a signature (fetch issuer metadata, get a fresh `c_nonce` if the issuer requires one), then hands you back exactly what needs to be signed:

   ```json
   {
     "session_id": "9f1c2e40-...-b2a6",
     "status": "awaiting_wallet_proof",
     "proof_request": {
       "audience": "https://issuer.example.com",
       "credential_configuration_id": "UniversityDegreeCredential",
       "nonce": "fresh-nonce"
     }
   }
   ```

2. Outside this server, in your own system, produce a `jwt` proof (spec "`jwt` Proof Type") over exactly that `{audience, nonce}` pair, signed by whatever key your wallet actually controls — hardware-backed keystore, secure enclave, a signing microservice, a human tapping "approve" on a phone first. This is real-world time your orchestration needs to tolerate: there's no blocking wait inside this server while you do it.
3. Call **`submit_wallet_proof(session_id, proof_jwt)`** with the result. The server sends the Credential Request, authenticates it, parses the response, and lands the session at `completed`, `failed`, or `awaiting_deferred_credential`, exactly like the automatic path.

No webhook server, no polling loop, and no blocking tool call is needed to make this work — the "wait" for your wallet to produce a signature is just the natural gap between two separate tool calls, the same way a user authorizing in a browser (§5 below) is just the gap between `begin_authorization` and `submit_authorization_result`. Your orchestration decides when to call step 3; this server doesn't need to know how long that took or why.

**If you're integrating a real wallet, start with B.** It's the path every "attach a real signer" effort in this project's own history has used, and it imposes nothing on how your wallet is built — synchronous, asynchronous, human-in-the-loop, hardware-backed, all of it fits.

---

## 3. Running the server

This is a Python 3.12+ package managed with [uv](https://docs.astral.sh/uv/). From a checkout:

```bash
uv run mcp-oidc4vci
```

It speaks MCP over **stdio** — it's a subprocess your orchestrator launches and talks to over stdin/stdout, not a network service you point a URL at. Any MCP-client library (Python, TypeScript, etc.) can drive it; see the [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) or [FastMCP](https://github.com/jlowin/fastmcp) (what this server itself is built on) for the client side.

Two environment variables control runtime behavior:

- `MCP_OIDC4VCI_LOG_LEVEL` — log level (default `INFO`); logs go to stderr, never stdout, so they never collide with the MCP protocol stream.
- `MCP_OIDC4VCI_DEBUG_TOOLS` — set to `1`/`true`/`yes` to register `debug_inspect_mock_wallet_credentials`, a development-only tool that bypasses the wallet boundary to inspect what `MockWalletAdapter` received. **Never enable this in anything resembling production** — it exists purely for local testing against the bundled mock wallet, and the only reason it's safe at all is that it only works when the wallet actually is `MockWalletAdapter`.

---

## 4. The tool catalog

Full request/response contracts, including every JSON field, are in [Architecture → Proposed MCP Tools](ARCHITECTURE.md#proposed-mcp-tools). This is the condensed map — what each tool is for and when you'd call it.

| Tool | Purpose | When you'd call it |
| --- | --- | --- |
| `inspect_credential_offer` | Parse/validate a Credential Offer (by value or `_uri`) | As soon as your wallet receives an offer (QR scan, deep link, …) |
| `get_credential_issuer_metadata` | Fetch and validate issuer metadata | To show the user what's on offer, or any time you need `credential_endpoint`/supported configs directly |
| `describe_issuance_flow` | Explain which grant applies and its steps, without starting a session | Optional — useful for UI/UX, not required to proceed |
| `initiate_issuance` | Start a session; completes the token exchange immediately for the pre-authorized code grant, or resolves AS metadata and pauses for the authorization code grant | Once the user agrees to proceed |
| `begin_authorization` | Build the Authorization Request URL (authorization code grant only) | After `initiate_issuance` leaves a session `waiting_for_user_authorization` |
| `submit_authorization_result` | Exchange the browser redirect's `code`/`state` for a token | After your app/browser captures the redirect from `begin_authorization`'s URL |
| `get_issuance_status` | Re-read a session's current state | Any time you need to check in, or recover after a restart of *your* orchestrator |
| `request_credential` | Automatic path: ask the in-process `WalletAdapter` to sign and complete the request | Only if you're using integration shape A (§2) |
| `request_wallet_proof` | Manual path, step 1: get `{audience, nonce}` to sign | Integration shape B (§2) |
| `submit_wallet_proof` | Manual path, step 2: submit your externally-produced proof | Integration shape B (§2), right after you have a signature |
| `poll_deferred_credential` | Check back on an issuer that deferred issuance | When a session is `awaiting_deferred_credential`, no sooner than `deferred_interval` seconds after the last call |
| `send_credential_notification` | Tell the issuer whether an issued credential was accepted/failed/deleted | After your wallet has actually stored (or failed to store, or the user deleted) a credential — optional, best-effort, never required to proceed |

---

## 5. Session states and the calls that move between them

Every tool above either creates a session or reads/advances one, identified by an opaque `session_id` — your orchestrator should persist this alongside whatever issuance record you keep on your own side, since it's the only handle you get back.

```text
created
  │ (pre-authorized code grant: token exchange happens inline)
  ├──────────────────────────────────────────────► ready_for_credential_request
  │ (authorization code grant: AS metadata resolved)
  ▼
waiting_for_user_authorization
  │ begin_authorization()
  ▼
awaiting_authorization_result
  │ submit_authorization_result()
  ▼
ready_for_credential_request
  │
  ├── request_credential() ─────────────────────────┐
  │                                                   │
  └── request_wallet_proof() ──► awaiting_wallet_proof │
                                   │ submit_wallet_proof()
                                   ▼                   │
                                   ├───────────────────┤
                                                        ▼
                              completed ◄── (all configurations issued)
                                   ▲
                                   │ more configurations remain:
                                   └── back to ready_for_credential_request
                                        (call request_credential /
                                         request_wallet_proof again)

          either path above may instead land on:
                         awaiting_deferred_credential
                                   │ poll_deferred_credential()
                                   │ (repeat no sooner than deferred_interval)
                                   ▼
                    completed / ready_for_credential_request / failed

          any state can transition to:
                                failed   (error field explains why)
```

Two things worth internalizing before you build around this:

- **An offer naming more than one credential configuration takes one Credential Request per configuration.** `request_credential`/`request_wallet_proof`+`submit_wallet_proof`/`poll_deferred_credential` each handle exactly one configuration per call and land back on `ready_for_credential_request`, not `completed`, while more remain. Your orchestrator's loop should be "call again while status comes back `ready_for_credential_request` after a request_credential-family call," not "call once."
- **`failed` is a normal, expected outcome, not an exception.** A rejected Token Request, an issuer that's gone offline, a `state` mismatch on the authorization redirect — all of these land the session on `status: "failed"` with a human-readable `error` string, returned normally, not thrown. Contrast this with calling a tool against a session in the *wrong* state (e.g. `request_credential` on a session that's still `waiting_for_user_authorization`) — that's a caller bug, and it's raised as an MCP tool error (see §6) instead of a session state, so you can tell "the issuer said no" apart from "we called things in the wrong order" programmatically.

Sessions live in an in-memory, per-process store with a one-hour default TTL (see §7) — there is nothing to migrate or persist on your side beyond the `session_id` itself while a session is active.

---

## 6. Error handling: two different kinds of "no"

This server surfaces failure in exactly two ways, and the distinction is deliberate — build your error handling around it rather than catching one generic exception:

1. **A normal protocol-level rejection** (issuer says the proof's nonce expired, the Authorization Server rejects the grant, metadata is malformed, …) comes back as an ordinary tool **result** with `status: "failed"` and an `error` string. Nothing is thrown. This is the outcome you branch your issuance UI on — "tell the user it failed, and why."
2. **A caller-side mistake** (unknown `session_id`, calling a tool against a session that isn't in the state it expects) is raised as an MCP **tool error** (`fastmcp.exceptions.ToolError` server-side; your MCP client library will surface this as whatever it calls a tool-call failure). This is a bug in your orchestration (the session's protocol state didn't actually change), not something to show the user as "issuance failed."

If your client framework collapses both into one generic "the call failed" branch, you will lose this distinction and end up showing users "it failed" for what are actually integration bugs on your end. Keep them separate.

---

## 7. What you're committing to, and what you're not

**Security boundary — what stays entirely outside this server, always:**

- Private keys, in whatever form — software, hardware-backed, HSM-resident. Never generated, held, or seen by this server.
- The proof signature itself, on the manual path (§2B) — the server only ever sees the finished JWT you hand it, never anything it could use to produce one itself.
- User consent / approval UX. The server has no concept of "ask the user" — your wallet decides when and how to get consent before calling `submit_wallet_proof`, `submit_authorization_result`, or (for the authorization code grant) before even opening the authorization URL in a browser.
- Credential storage and display, after issuance. `receive_credential` (shape A) or your own handling of a `completed` status (shape B) is the last point this server touches a credential; everything after that (persistence, rendering, later presentation) is entirely yours.

**Operational limitations to know about before you commit:**

- **Session storage is in-memory and single-process.** `IssuanceSessionStore` doesn't survive a process restart and isn't shared across multiple server instances. If you need to run more than one instance behind a load balancer, or survive restarts mid-issuance, you'll need to either pin a given `session_id` to one instance for its lifetime, or replace the store — it's a small, swappable class (`src/mcp_oidc4vci/issuance.py`), not a hidden implementation detail.
- **Key attestation isn't supported.** If an issuer's metadata declares `key_attestations_required` for the proof type you're using, the Credential Request will be rejected by the issuer — this server has no mechanism to attach attestation evidence today. Check your target issuer(s)' metadata for this before assuming end-to-end issuance will work.
- **No certificate chain-of-trust validation for signed Credential Issuer Metadata.** Signature verification against the `x5c` leaf certificate is performed, but nothing establishes that certificate is trustworthy (see [Architecture](ARCHITECTURE.md#get_credential_issuer_metadata)). If your trust model requires chain validation, you'll need to add it.
- **`notification_id` is a single scalar per session.** For a multi-configuration offer, only the most recently issued configuration's `notification_id` is reachable by the time you call `send_credential_notification` — see [Architecture](ARCHITECTURE.md#send_credential_notification).
- **Not yet implemented at all:** Credential Request/Response Encryption, the `attestation` proof type, batch issuance of multiple credentials of the *same* type in one call. See the [README feature table](../README.md#feature-support) for the current, authoritative list — it's kept up to date as features land.

None of these are secret — they're the same limitations this project's own README and ROADMAP track for its own development. The point of listing them here is so you can check them against your actual target issuer(s) *before* building on top of this, not discover them mid-integration.

---

## 8. Getting started — a checklist

1. **Decide your integration shape (§2).** Can your signing operation run synchronously inside this server's process? Shape A. Otherwise (the common case for an existing wallet product), shape B.
2. **Shape A:** implement `WalletAdapter`, wire it in place of `MockWalletAdapter` in `server.py`. **Shape B:** build the piece of your own system that takes a `{audience, nonce, credential_configuration_id}` proof request and returns a signed `jwt` proof, including wherever your consent UX lives.
3. **Stand up the server as a subprocess your orchestrator launches**, and write (or reuse) an MCP client in your orchestration language of choice to drive it.
4. **Check your target issuer(s) against §7's limitation list**, especially key attestation, before assuming a given credential type will issue end to end.
5. **Build your orchestration loop around the state machine in §5**, including the "call again while more credential configurations remain" case and the `failed`-is-normal / tool-error-is-a-bug distinction in §6.
6. **Decide whether you'll call `send_credential_notification`.** It's optional and best-effort, but if your wallet already knows definitively whether storage succeeded, this is a one-call way to tell the issuer.
7. **Test against a mock or sandbox issuer first.** The bundled `MockWalletAdapter` exists exactly for this — it lets you exercise the full pre-authorized-code flow end to end before any real wallet code is involved.

For anything this document doesn't cover (exact JSON shapes, the reasoning behind a specific design choice, RFC references), [docs/ARCHITECTURE.md](ARCHITECTURE.md) is the complete reference, and [docs/ROADMAP.md](ROADMAP.md) has the history of what's been validated against real issuers versus unit-tested only.
