import nacl.utils
import pytest
from pathlib import Path
from vault.crypto import SecretboxKeyWrapper
from vault.model import (Connection, ConnKey, Token, ConnectionGrant, ConnectionAccessLog)
from vault.store.local_file import LocalFileStore
from vault.store.server import ServerStore
from vault.store.memory import InMemoryStore


@pytest.fixture(params=["memory", "local", "server"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryStore()
    w = SecretboxKeyWrapper(nacl.utils.random(32))
    if request.param == "local":
        return LocalFileStore(root=Path(tmp_path), wrapper=w)
    return ServerStore(conn_str=f"sqlite:///{tmp_path}/v.sqlite", wrapper=w)


def _conn():
    return Connection(id="conn_1", org="caput-venti", provider="fortnox", account="559401-5157",
                      scopes=["bookkeeping"], app_cred_ref="fortnox", token=Token("a", "r", 1000.0, "s"),
                      rotation="rotating", lease=None, created_by="stub", created_at=0.0, updated_at=0.0)


def test_crud_and_token_write(store):
    store.put_connection(_conn())
    k = ConnKey("caput-venti", "fortnox", "559401-5157")
    assert store.get_connection(k).token.access_token == "a"
    store.write_token(k, Token("a2", "r2", 5000.0, "s"), now=10.0)
    assert store.get_connection(k).token == Token("a2", "r2", 5000.0, "s")
    assert len(store.list_connections("caput-venti", "fortnox")) == 1


def test_grants_and_logs(store):
    store.put_connection(_conn())
    store.add_grant(ConnectionGrant("conn_1", "p2", "use", None, "stub", 0.0))
    assert store.get_grants("conn_1")[0].principal_id == "p2"
    store.append_log(ConnectionAccessLog("conn_1", "p2", "bookkeeping", "access-token", 1.0))
    assert store.read_log("conn_1")[0].op == "access-token"


def test_delete_zeroizes(store):
    store.put_connection(_conn())
    k = ConnKey("caput-venti", "fortnox", "559401-5157")
    store.delete_connection(k)
    assert store.get_connection(k) is None
