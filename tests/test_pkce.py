import base64
import hashlib

from mcp_oidc4vci.pkce import CODE_CHALLENGE_METHOD, code_challenge, generate_code_verifier


def test_generate_code_verifier_is_within_the_rfc7636_length_range() -> None:
    verifier = generate_code_verifier()

    assert 43 <= len(verifier) <= 128


def test_generate_code_verifier_uses_only_unreserved_characters() -> None:
    verifier = generate_code_verifier()

    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    assert set(verifier) <= allowed


def test_generate_code_verifier_is_not_reused_across_calls() -> None:
    assert generate_code_verifier() != generate_code_verifier()


def test_code_challenge_matches_an_independently_computed_s256_digest() -> None:
    verifier = "test-verifier-value"

    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    expected = expected.rstrip(b"=").decode("ascii")

    assert code_challenge(verifier) == expected


def test_code_challenge_is_deterministic_for_the_same_verifier() -> None:
    verifier = generate_code_verifier()

    assert code_challenge(verifier) == code_challenge(verifier)


def test_code_challenge_differs_for_different_verifiers() -> None:
    assert code_challenge(generate_code_verifier()) != code_challenge(generate_code_verifier())


def test_code_challenge_contains_no_padding() -> None:
    assert "=" not in code_challenge(generate_code_verifier())


def test_code_challenge_method_is_s256() -> None:
    assert CODE_CHALLENGE_METHOD == "S256"
