import base64

import pytest

from identity.tokens import b64url
from identity.app import _build_identity_app_from_env
from vault.app import _build_app_from_env
from bus.app import _build_bus_app_from_env

VALID_SEED = b64url(b"\x00" * 32)          # KeyManager.from_seed expects b64url(32 bytes)
VALID_KEK = base64.b64encode(b"\x00" * 32).decode()  # VAULT_KEK expects base64(32 bytes)


def test_identity_requires_signing_seed(monkeypatch):
    monkeypatch.delenv("KERNEL_SIGNING_SEED", raising=False)
    monkeypatch.setenv("KERNEL_ISSUER", "https://id.example")
    with pytest.raises(RuntimeError, match="KERNEL_SIGNING_SEED"):
        _build_identity_app_from_env()


def test_identity_requires_issuer(monkeypatch, tmp_path):
    monkeypatch.setenv("KERNEL_SIGNING_SEED", VALID_SEED)
    monkeypatch.setenv("KERNEL_IDENTITY_DB", str(tmp_path / "identity.sqlite"))
    monkeypatch.delenv("KERNEL_ISSUER", raising=False)
    with pytest.raises(KeyError, match="KERNEL_ISSUER"):
        _build_identity_app_from_env()


def test_vault_served_requires_kek(monkeypatch):
    monkeypatch.setenv("VAULT_REQUIRE_KERNEL", "1")
    monkeypatch.delenv("VAULT_KEK", raising=False)
    with pytest.raises(RuntimeError, match="VAULT_KEK"):
        _build_app_from_env()


def test_vault_served_requires_audience(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_REQUIRE_KERNEL", "1")
    monkeypatch.setenv("VAULT_KEK", VALID_KEK)
    monkeypatch.setenv("VAULT_DB", f"sqlite:///{tmp_path}/vault.sqlite")
    monkeypatch.setenv("KERNEL_IDENTITY_DB", str(tmp_path / "identity.sqlite"))
    monkeypatch.setenv("KERNEL_JWKS_URL", "https://id.example/.well-known/jwks.json")
    monkeypatch.setenv("KERNEL_ISSUER", "https://id.example")
    monkeypatch.delenv("VAULT_AUDIENCE", raising=False)
    with pytest.raises(KeyError, match="VAULT_AUDIENCE"):
        _build_app_from_env()


def test_vault_served_requires_jwks_url(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_REQUIRE_KERNEL", "1")
    monkeypatch.setenv("VAULT_KEK", VALID_KEK)
    monkeypatch.setenv("VAULT_DB", f"sqlite:///{tmp_path}/vault.sqlite")
    monkeypatch.setenv("KERNEL_IDENTITY_DB", str(tmp_path / "identity.sqlite"))
    monkeypatch.setenv("VAULT_AUDIENCE", "vault")
    monkeypatch.setenv("KERNEL_ISSUER", "https://id.example")
    monkeypatch.delenv("KERNEL_JWKS_URL", raising=False)
    with pytest.raises(KeyError, match="KERNEL_JWKS_URL"):
        _build_app_from_env()


def test_bus_requires_issuer(monkeypatch):
    monkeypatch.delenv("KERNEL_ISSUER", raising=False)
    with pytest.raises(KeyError, match="KERNEL_ISSUER"):
        _build_bus_app_from_env()


def test_bus_requires_audience(monkeypatch):
    monkeypatch.setenv("KERNEL_ISSUER", "https://id.example")
    monkeypatch.delenv("BUS_AUDIENCE", raising=False)
    with pytest.raises(KeyError, match="BUS_AUDIENCE"):
        _build_bus_app_from_env()
