import json
import time

import jwt

from mcp_oidc4vci.wallet import PROOF_JWT_TYPE, MockWalletAdapter


async def test_generate_proof_produces_a_verifiable_jwt_bound_to_its_own_key() -> None:
    wallet = MockWalletAdapter()

    proof = await wallet.generate_proof(audience="https://issuer.example.com", nonce="abc123")

    header = jwt.get_unverified_header(proof)
    assert header["typ"] == PROOF_JWT_TYPE
    assert header["alg"] == "ES256"
    public_key = jwt.PyJWK.from_json(json.dumps(header["jwk"])).key

    decoded = jwt.decode(
        proof,
        public_key,
        algorithms=["ES256"],
        audience="https://issuer.example.com",
    )
    assert decoded["nonce"] == "abc123"
    assert abs(decoded["iat"] - int(time.time())) < 5


async def test_generate_proof_omits_the_nonce_claim_when_none_is_given() -> None:
    wallet = MockWalletAdapter()

    proof = await wallet.generate_proof(audience="https://issuer.example.com", nonce=None)

    claims = jwt.decode(proof, options={"verify_signature": False})
    assert "nonce" not in claims


async def test_generate_proof_uses_a_stable_key_across_calls() -> None:
    wallet = MockWalletAdapter()

    first = jwt.get_unverified_header(await wallet.generate_proof(audience="a", nonce=None))
    second = jwt.get_unverified_header(await wallet.generate_proof(audience="b", nonce=None))

    assert first["jwk"] == second["jwk"]


async def test_receive_credential_accumulates_issued_credentials() -> None:
    wallet = MockWalletAdapter()

    await wallet.receive_credential(
        credential_configuration_id="UniversityDegreeCredential", credential="opaque-jwt-vc"
    )
    await wallet.receive_credential(
        credential_configuration_id="UniversityDegreeCredential", credential={"vc": "..."}
    )

    assert wallet.received_credentials == [
        {
            "credential_configuration_id": "UniversityDegreeCredential",
            "credential": "opaque-jwt-vc",
        },
        {"credential_configuration_id": "UniversityDegreeCredential", "credential": {"vc": "..."}},
    ]
