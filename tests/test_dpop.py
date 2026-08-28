import hashlib
import json

import jwt

from mcp_oidc4vci.dpop import DPOP_JWT_TYPE, DPoPKey


def test_create_proof_is_signed_and_verifiable_with_its_own_embedded_key() -> None:
    key = DPoPKey()

    proof = key.create_proof(http_method="POST", http_uri="https://as.example.com/token")

    header = jwt.get_unverified_header(proof)
    public_key = jwt.PyJWK.from_json(json.dumps(header["jwk"])).key
    claims = jwt.decode(proof, public_key, algorithms=["ES256"])
    assert claims["htm"] == "POST"


def test_proof_header_has_the_required_dpop_jwt_shape() -> None:
    key = DPoPKey()

    proof = key.create_proof(http_method="GET", http_uri="https://rs.example.com/credential")

    header = jwt.get_unverified_header(proof)
    assert header["typ"] == DPOP_JWT_TYPE
    assert header["alg"] == "ES256"
    assert "kty" in header["jwk"]
    assert "d" not in header["jwk"]  # public key only, never the private key


def test_proof_strips_query_and_fragment_from_htu() -> None:
    key = DPoPKey()

    proof = key.create_proof(
        http_method="POST", http_uri="https://as.example.com/token?foo=bar#frag"
    )

    claims = jwt.decode(proof, options={"verify_signature": False})
    assert claims["htu"] == "https://as.example.com/token"


def test_proof_omits_nonce_and_ath_when_not_given() -> None:
    key = DPoPKey()

    proof = key.create_proof(http_method="POST", http_uri="https://as.example.com/token")

    claims = jwt.decode(proof, options={"verify_signature": False})
    assert "nonce" not in claims
    assert "ath" not in claims


def test_proof_includes_the_given_nonce() -> None:
    key = DPoPKey()

    proof = key.create_proof(
        http_method="POST", http_uri="https://as.example.com/token", nonce="server-nonce"
    )

    claims = jwt.decode(proof, options={"verify_signature": False})
    assert claims["nonce"] == "server-nonce"


def test_proof_ath_is_the_base64url_sha256_of_the_access_token() -> None:
    key = DPoPKey()

    proof = key.create_proof(
        http_method="POST",
        http_uri="https://rs.example.com/credential",
        access_token="secret-token",
    )

    claims = jwt.decode(proof, options={"verify_signature": False})
    expected = jwt.utils.base64url_encode(hashlib.sha256(b"secret-token").digest()).decode()
    assert claims["ath"] == expected


def test_each_proof_gets_a_unique_jti() -> None:
    key = DPoPKey()

    first = jwt.decode(
        key.create_proof(http_method="POST", http_uri="https://as.example.com/token"),
        options={"verify_signature": False},
    )
    second = jwt.decode(
        key.create_proof(http_method="POST", http_uri="https://as.example.com/token"),
        options={"verify_signature": False},
    )

    assert first["jti"] != second["jti"]


def test_uses_the_same_key_across_multiple_proofs() -> None:
    key = DPoPKey()

    first_jwk = jwt.get_unverified_header(
        key.create_proof(http_method="POST", http_uri="https://a.example.com")
    )["jwk"]
    second_jwk = jwt.get_unverified_header(
        key.create_proof(http_method="GET", http_uri="https://b.example.com")
    )["jwk"]

    assert first_jwk == second_jwk
