import os
import tempfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from identity.tokens import b64url
import identity.app as identity_app


def _seed_b64url() -> str:
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes(serialization.Encoding.Raw,
                             serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    return b64url(raw)


def test_missing_seed_raises(monkeypatch):
    monkeypatch.delenv("KERNEL_SIGNING_SEED", raising=False)
    monkeypatch.setenv("KERNEL_ISSUER", "https://id.local")
    with pytest.raises(RuntimeError):
        identity_app._build_identity_app_from_env()


def test_served_identity_publishes_matching_jwks(monkeypatch, tmp_path):
    seed = _seed_b64url()
    monkeypatch.setenv("KERNEL_SIGNING_SEED", seed)
    monkeypatch.setenv("KERNEL_ISSUER", "https://id.local")
    monkeypatch.setenv("KERNEL_KID", "kid-served")
    monkeypatch.setenv("KERNEL_IDENTITY_DB", str(tmp_path / "identity.sqlite"))
    app = identity_app._build_identity_app_from_env()
    r = TestClient(app).get("/.well-known/jwks.json")
    assert r.status_code == 200
    keys = r.json()["keys"]
    assert keys and keys[0]["kid"] == "kid-served" and keys[0]["kty"] == "OKP"
