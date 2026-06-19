import base64

import pytest
import nacl.utils

from vault.app import _build_from_env


def test_served_vault_refuses_random_kek(monkeypatch, tmp_path):
    monkeypatch.delenv("VAULT_KEK", raising=False)
    monkeypatch.setenv("VAULT_BACKEND", "server")
    monkeypatch.setenv("VAULT_DB", f"sqlite:///{tmp_path}/vault.sqlite")
    with pytest.raises(RuntimeError):
        _build_from_env()


def test_served_vault_accepts_explicit_kek(monkeypatch, tmp_path):
    monkeypatch.setenv("VAULT_KEK", base64.b64encode(nacl.utils.random(32)).decode())
    monkeypatch.setenv("VAULT_BACKEND", "server")
    monkeypatch.setenv("VAULT_DB", f"sqlite:///{tmp_path}/vault.sqlite")
    svc = _build_from_env()
    assert svc is not None


def test_local_default_still_allows_random_kek(monkeypatch, tmp_path):
    monkeypatch.delenv("VAULT_KEK", raising=False)
    monkeypatch.setenv("VAULT_BACKEND", "local")
    monkeypatch.delenv("VAULT_REQUIRE_KERNEL", raising=False)
    monkeypatch.setenv("VAULT_STORE_DIR", str(tmp_path / "store"))
    assert _build_from_env() is not None
