"""The Wallet Adapter boundary (architecture "Proposed Wallet Adapter" / "Wallet Boundary").

Everything that touches private key material or issued credential content lives behind this
interface. The issuance engine orchestrates the protocol; it never signs a proof or retains
a credential itself.
"""

import json
import time
from typing import Protocol

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

PROOF_JWT_TYPE = "openid4vci-proof+jwt"


class WalletAdapter(Protocol):
    """What the issuance engine needs from a wallet to complete a Credential Request."""

    async def generate_proof(self, *, audience: str, nonce: str | None) -> str:
        """Return a signed key-proof JWT (spec "jwt Proof Type") binding the Credential
        Request to a wallet-held key. `nonce` is the c_nonce from the issuer's Nonce
        Endpoint, when the issuer has one."""
        ...  # pragma: no cover

    async def receive_credential(
        self, *, credential_configuration_id: str, credential: str | dict[str, object]
    ) -> None:
        """Take custody of one issued credential. The MCP server does not retain it."""
        ...  # pragma: no cover


class MockWalletAdapter:
    """An in-process `WalletAdapter` backed by an ephemeral EC keypair.

    For development and testing only, to exercise the full protocol round-trip without a
    real wallet. A production wallet holds its keys in its own security boundary
    (hardware-backed keystore, secure enclave, a separate signing service, ...) — never
    inside this MCP server.
    """

    def __init__(self) -> None:
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self.received_credentials: list[dict[str, object]] = []

    async def generate_proof(self, *, audience: str, nonce: str | None) -> str:
        claims: dict[str, object] = {"aud": audience, "iat": int(time.time())}
        if nonce is not None:
            claims["nonce"] = nonce
        public_jwk = json.loads(
            ECAlgorithm(ECAlgorithm.SHA256).to_jwk(self._private_key.public_key())
        )
        return jwt.encode(
            claims,
            self._private_key,
            algorithm="ES256",
            headers={"typ": PROOF_JWT_TYPE, "jwk": public_jwk},
        )

    async def receive_credential(
        self, *, credential_configuration_id: str, credential: str | dict[str, object]
    ) -> None:
        self.received_credentials.append(
            {"credential_configuration_id": credential_configuration_id, "credential": credential}
        )
