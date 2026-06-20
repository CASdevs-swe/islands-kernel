from capture_bridge.translate import translate


def test_builds_capture_route_input():
    event = {"data": {"text": "kom ihag att kopa mjolk"}}
    out = translate(event, type="personal-task", privacy="private",
                    vault_root="/tmp/vault", today="2025-06-15")
    assert out == {
        "startPath": "/tmp/vault",
        "today": "2025-06-15",
        "thoughts": [
            {"text": "kom ihag att kopa mjolk", "type": "personal-task", "privacy": "private"},
        ],
    }


def test_missing_event_data_falls_back_to_empty_text():
    out = translate({}, type="personal-task", privacy="private",
                    vault_root="/tmp/vault", today="2025-06-15")
    assert out["thoughts"][0]["text"] == ""
