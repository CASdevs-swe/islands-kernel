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
