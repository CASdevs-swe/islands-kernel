from capture_bridge.principal_map import PrincipalMap


def test_resolves_a_known_sender():
    pm = PrincipalMap([
        {"channel": "telegram", "channelUserId": 111, "principal": "prn_sam", "org": "org_caput"},
    ])
    out = pm.resolve({"channel": "telegram", "channelUserId": 111})
    assert out == {"principal": "prn_sam", "org": "org_caput"}


def test_unknown_sender_returns_none():
    pm = PrincipalMap([])
    assert pm.resolve({"channel": "telegram", "channelUserId": 999}) is None


def test_multi_entry_does_not_cross_resolve():
    pm = PrincipalMap([
        {"channel": "telegram", "channelUserId": 111, "principal": "prn_a", "org": "org_a"},
        {"channel": "telegram", "channelUserId": 222, "principal": "prn_b", "org": "org_b"},
    ])
    assert pm.resolve({"channel": "telegram", "channelUserId": 222}) == {"principal": "prn_b", "org": "org_b"}
    assert pm.resolve({"channel": "discord", "channelUserId": 111}) is None
