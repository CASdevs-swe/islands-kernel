import nacl.utils
from pathlib import Path
from vault.crypto import SecretboxKeyWrapper
from vault.model import Connection, ConnKey, Token
from vault.store.local_file import LocalFileStore


def _store(tmp_path) -> LocalFileStore:
    return LocalFileStore(root=Path(tmp_path), wrapper=SecretboxKeyWrapper(nacl.utils.random(32)))


def _conn():
    return Connection(id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
                      scopes=["s"], app_cred_ref="fortnox", token=Token("a", "r", 1000.0, "s"),
                      rotation="rotating", lease=None, created_by="stub", created_at=0.0, updated_at=0.0)


def test_put_get_token_roundtrip(tmp_path):
    s = _store(tmp_path); s.put_connection(_conn())
    got = s.get_connection(ConnKey("caput-venti", "fortnox", "559401-5157"))
    assert got.token == Token("a", "r", 1000.0, "s")


def test_token_file_is_encrypted_on_disk(tmp_path):
    s = _store(tmp_path); s.put_connection(_conn())
    blob = (Path(tmp_path) / "connections/caput-venti/fortnox/559401-5157.token.age").read_bytes()
    assert b"\"a\"" not in blob and b"refresh" not in blob


def test_lease_is_exclusive(tmp_path):
    s = _store(tmp_path); s.put_connection(_conn())
    k = ConnKey("caput-venti", "fortnox", "559401-5157")
    assert s.acquire_lease(k, "h1", until=2000.0, now=1000.0) is True
    assert s.acquire_lease(k, "h2", until=2000.0, now=1000.0) is False   # h1 holds it
    s.release_lease(k, "h1")
    assert s.acquire_lease(k, "h2", until=2000.0, now=1000.0) is True    # now free


def test_expired_lease_can_be_stolen(tmp_path):
    s = _store(tmp_path); s.put_connection(_conn())
    k = ConnKey("caput-venti", "fortnox", "559401-5157")
    assert s.acquire_lease(k, "h1", until=1500.0, now=1000.0) is True
    assert s.acquire_lease(k, "h2", until=3000.0, now=2000.0) is True    # h1's lease expired at 1500
