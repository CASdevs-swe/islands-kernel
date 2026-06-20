import os
import tempfile

from identity.store.memory import InMemoryIdentityStore
from identity.store.server import ServerIdentityStore
from identity.model import (
    Principal, Org, Membership, Grant, GrantTarget, McpToken, AccessLog,
    OAuthAuthCode, OAuthAccessToken,
)


def _principal(pid="prn_1", email="a@b.se"):
    return Principal(id=pid, type="human", email=email,
                     display_name=None, public_key=None, created_at=0.0)


def _stores():
    mem = InMemoryIdentityStore()
    path = os.path.join(tempfile.mkdtemp(), "identity.sqlite")
    return [mem, ServerIdentityStore(path)]


def test_principal_put_get_and_by_email():
    for s in _stores():
        s.put_principal(_principal())
        assert s.get_principal("prn_1").email == "a@b.se"
        assert s.get_principal_by_email("a@b.se").id == "prn_1"
        assert s.get_principal("nope") is None


def test_membership_lookup():
    for s in _stores():
        s.put_membership(Membership("prn_1", "org_1", ["owner"], True, 0.0))
        assert s.get_membership("prn_1", "org_1").roles == ["owner"]
        assert len(s.list_memberships("prn_1")) == 1


def test_grant_add_list_revoke():
    for s in _stores():
        g = Grant("grant_1", "prn_1", GrantTarget("org", "org_1"),
                  "use", None, "prn_owner", 0.0, None)
        s.add_grant(g)
        assert len(s.list_grants("prn_1")) == 1
        s.revoke_grant("grant_1", at=5.0)
        assert s.list_grants("prn_1")[0].revoked_at == 5.0


def test_mcp_token_lookup_by_hash():
    for s in _stores():
        s.put_mcp_token(McpToken("h", "prn_1", "org_1", "aud", "mcp", None, None))
        assert s.get_mcp_token("h").principal_id == "prn_1"
        assert s.get_mcp_token("missing") is None


def test_log_is_append_only():
    for s in _stores():
        s.append_log(AccessLog("prn_1", "org_1", "bk", "reconcile", 0.0))
        s.append_log(AccessLog("prn_1", "org_1", "bk", "reconcile", 1.0))
        assert len(s.read_log("prn_1")) == 2


def test_consume_auth_code_single_use():
    for s in _stores():
        code = OAuthAuthCode(
            hash="code_h1",
            client_id="client_1",
            principal_id="prn_1",
            org_id="org_1",
            code_challenge="ch",
            audience="aud",
            scope="openid",
            expires_at=9999.0,
            consumed_at=None,
        )
        s.put_auth_code(code)
        assert s.consume_auth_code("code_h1", at=1.0) is True
        assert s.consume_auth_code("code_h1", at=2.0) is False


def test_access_token_json_round_trip_and_rotate():
    for s in _stores():
        tok = OAuthAccessToken(
            hash="at_h1",
            client_id="client_1",
            principal_id="prn_1",
            org_id="org_1",
            audience="aud_1",
            scope="openid profile",
            expires_at=9999.0,
            refresh={"hash": "rh", "expires_at": 9999.0},
        )
        s.put_access_token(tok)
        got = s.get_access_token("at_h1")
        assert got is not None
        assert got.refresh == {"hash": "rh", "expires_at": 9999.0}
        assert got.audience == "aud_1"
        assert got.scope == "openid profile"

        new_tok = OAuthAccessToken(
            hash="at_h2",
            client_id="client_1",
            principal_id="prn_1",
            org_id="org_1",
            audience="aud_1",
            scope="openid profile",
            expires_at=19999.0,
            refresh={"hash": "rh2", "expires_at": 19999.0},
        )
        s.rotate_refresh("at_h1", new_tok)
        assert s.get_access_token("at_h1") is None
        rotated = s.get_access_token("at_h2")
        assert rotated is not None
        assert rotated.refresh == {"hash": "rh2", "expires_at": 19999.0}


def _access_token(h, rh):
    return OAuthAccessToken(
        hash=h, client_id="client_1", principal_id="prn_1", org_id="org_1",
        audience="aud_1", scope="openid", expires_at=9999.0,
        refresh={"hash": rh, "expires_at": 9999.0})


def test_access_token_hashes_parity_after_put_and_rotate():
    # access_token_hashes() backs the O(n) refresh scan; both backends must
    # enumerate the same live hashes after the same put/rotate sequence.
    for s in _stores():
        s.put_access_token(_access_token("at_a", "rh_a"))
        s.put_access_token(_access_token("at_b", "rh_b"))
        assert set(s.access_token_hashes()) == {"at_a", "at_b"}
        s.rotate_refresh("at_a", _access_token("at_c", "rh_c"))
        assert set(s.access_token_hashes()) == {"at_b", "at_c"}
