import hashlib
import base64
from identity.tokens import b64url, unb64url, hash_token, generate_raw_token


def test_b64url_roundtrip_no_padding():
    raw = b"\x00\x01\x02hello"
    enc = b64url(raw)
    assert "=" not in enc
    assert unb64url(enc) == raw


def test_hash_token_is_sha256_base64url():
    raw = "mcp_abc"
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(raw.encode()).digest()).decode().rstrip("=")
    assert hash_token(raw) == expected


def test_hash_token_is_deterministic():
    assert hash_token("mcp_abc") == hash_token("mcp_abc")


def test_generate_raw_token_has_prefix_and_entropy():
    a = generate_raw_token("mcp")
    b = generate_raw_token("mcp")
    assert a.startswith("mcp_") and b.startswith("mcp_")
    assert a != b
    assert len(a) > len("mcp_") + 20
