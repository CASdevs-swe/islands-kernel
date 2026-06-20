import pytest
from bus.model import Event, Subscription
from bus.dispatch import HttpPushDelivery


class _FakeResp:
    def __init__(self, status): self.status_code = status


def _ev():
    return Event(id="evt_1", type="a.b.c", schema="s/v1", source="src", org="org_1",
                 principal="prn_a", occurred_at="2026-06-20T10:00:00Z",
                 trace={"store": "x", "ref": "r"}, data={"k": "v"})


def _sub(url="http://consumer.local/events"):
    return Subscription("sub_1", "org_1", "consumer", "a.b.c",
                        {"kind": "http", "url": url, "audience": "consumer"}, "g1")


def test_http_push_posts_envelope_and_audience_header():
    captured = {}
    def post(url, json, headers):
        captured.update(url=url, json=json, headers=headers)
        return _FakeResp(202)
    HttpPushDelivery(http_post=post).deliver(_sub(), _ev())
    assert captured["url"] == "http://consumer.local/events"
    assert captured["json"]["id"] == "evt_1"
    assert captured["headers"]["X-Event-Audience"] == "consumer"


def test_http_push_raises_on_non_2xx():
    HttpPushDelivery(http_post=lambda url, json, headers: _FakeResp(500))
    with pytest.raises(Exception):
        HttpPushDelivery(http_post=lambda url, json, headers: _FakeResp(500)).deliver(_sub(), _ev())
