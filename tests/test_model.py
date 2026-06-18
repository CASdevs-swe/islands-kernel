from vault.model import Token, Connection, ConnKey, ConnectionGrant, new_id


def test_token_expiry_skew():
    t = Token(access_token="a", refresh_token="r", expires_at=1000.0, scope="s")
    assert t.is_expired(skew=60, now=950.0) is True      # 950+60 >= 1000
    assert t.is_expired(skew=60, now=900.0) is False     # 900+60 < 1000


def test_token_roundtrip():
    t = Token("a", "r", 1000.0, "s")
    assert Token.from_dict(t.to_dict()) == t


def test_connection_record_excludes_token():
    c = Connection(
        id="conn_x", org="shop1", provider="fortnox", account="559401-5157",
        scopes=["bookkeeping"], app_cred_ref="fortnox", token=Token("SECRET_A", "SECRET_R", 1.0, "s"),
        rotation="rotating", lease=None, created_by="stub", created_at=0.0, updated_at=0.0,
    )
    rec = c.to_record()
    assert "token" not in rec and "SECRET_A" not in str(rec) and "SECRET_R" not in str(rec)
    assert c.key == ConnKey("shop1", "fortnox", "559401-5157")


def test_new_id_deterministic_no_clock():
    assert new_id("conn", "caput-venti/fortnox/559401-5157") == new_id("conn", "caput-venti/fortnox/559401-5157")
    assert new_id("conn", "a").startswith("conn_")
