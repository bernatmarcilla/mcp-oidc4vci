#!/usr/bin/env python3
"""Sign a proof-of-possession JWT for manually testing the wallet-proof handoff.

Stands in for a real wallet: generates a fresh, throwaway EC key and signs a spec-shaped
`openid4vci-proof+jwt`, using the exact same construction `MockWalletAdapter` uses inside
the server. Running it as a *separate* process (instead of importing it in-process) means
the resulting proof genuinely comes from outside the server, exercising
`request_wallet_proof` / `submit_wallet_proof` the way an actual external wallet would.

Usage:
    uv run scripts/sign_proof.py --audience https://issuer.example.com --nonce abc123
    uv run scripts/sign_proof.py --audience https://issuer.example.com   # no nonce endpoint

Prints the proof JWT to stdout; pass it straight to submit_wallet_proof's `proof_jwt` argument.
"""

import argparse
import asyncio

from mcp_oidc4vci.wallet import MockWalletAdapter


async def _main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--audience",
        required=True,
        help="The 'audience' from request_wallet_proof's output (the Credential Issuer id).",
    )
    parser.add_argument(
        "--nonce",
        default=None,
        help="The 'nonce' from request_wallet_proof's output, if the issuer has a Nonce Endpoint.",
    )
    args = parser.parse_args()

    wallet = MockWalletAdapter()
    proof = await wallet.generate_proof(audience=args.audience, nonce=args.nonce)
    print(proof)


if __name__ == "__main__":
    asyncio.run(_main())
