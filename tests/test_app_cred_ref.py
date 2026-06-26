"""VaultConfig.app_cred_for honors the per-connection app-cred ref.

A connection records app_cred_ref and get_access_token passes it here, so a
connection refreshes with the app that minted it. The default ref equals the
provider (backward compatible: ref='fortnox' resolves the provider's cred).
"""
import pytest

from vault.config import VaultConfig
from vault.providers.base import AppCred


def _cfg(creds):
    return VaultConfig(app_creds=creds, state_hmac_key=b"k")


def test_default_ref_resolves_provider_cred():
    a = AppCred("id_a", "sec_a")
    cfg = _cfg({"fortnox": a})
    assert cfg.app_cred_for("fortnox", "fortnox") is a


def test_named_ref_resolves_its_own_cred():
    a = AppCred("id_a", "sec_a")
    b = AppCred("id_b", "sec_b")
    cfg = _cfg({"fortnox": a, "smartcharge": b})
    assert cfg.app_cred_for("fortnox", "smartcharge") is b
    assert cfg.app_cred_for("fortnox", "fortnox") is a


def test_unknown_ref_falls_back_to_provider():
    a = AppCred("id_a", "sec_a")
    cfg = _cfg({"fortnox": a})
    assert cfg.app_cred_for("fortnox", "nope") is a


def test_raises_when_neither_ref_nor_provider_present():
    cfg = _cfg({})
    with pytest.raises(KeyError):
        cfg.app_cred_for("fortnox", "fortnox")
