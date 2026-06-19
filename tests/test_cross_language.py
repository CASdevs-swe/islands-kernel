# tests/test_cross_language.py
#
# Cross-language integration proof: a token minted by the Python issuer
# must verify in both Python (here) and Node (libs/node/test/verify.test.ts).
#
# Ordering: this test must run BEFORE the Node suite. It writes the golden
# fixture that the Node test reads. Run: pytest tests/ first, then npx vitest.
#
# SEED NOTE: CROSS_LANG_SEED is a throwaway constant used only in this test.
# It is NOT a production key. The fixture contains only a public JWKS (no
# private key material) and is safe to commit.

import json
import os

from identity.keys import KeyManager
from identity.jwt_issuer import mint
from identity.jwt_verify import verify_island_jwt
from identity.tokens import b64url

# Throwaway fixed seed — test-only constant, never a production key.
CROSS_LANG_SEED = b64url(b"\x07" * 32)

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "cross_lang", "token.json")


def test_python_writes_and_verifies_golden_token():
    km = KeyManager.from_seed("kid-1", CROSS_LANG_SEED)
    token = mint(
        km=km,
        issuer="https://id.x",
        sub="prn_1",
        typ="human",
        audience="https://mcp.x",
        org="org_1",
        roles=["owner"],
        ttl=300,
        now=1000,
        email="a@b.se",
    )
    fixture = {
        "token": token,
        "jwks": km.jwks_document(),
        "audience": "https://mcp.x",
        "issuer": "https://id.x",
        "now": 1100,
    }
    os.makedirs(os.path.dirname(FIX), exist_ok=True)
    with open(FIX, "w") as f:
        json.dump(fixture, f, indent=2)

    claims = verify_island_jwt(
        token,
        jwks=km.jwks_document(),
        audience="https://mcp.x",
        now=1100,
        issuer="https://id.x",
    )
    assert claims["sub"] == "prn_1"
