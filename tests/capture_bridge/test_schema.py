from bus.schema_registry import SchemaRegistry
from capture_bridge.schema import (
    INBOUND_SCHEMA_ID, INBOUND_EVENT_TYPE, INBOUND_MESSAGE_SCHEMA, register_inbound_schema,
)


def test_schema_constants():
    assert INBOUND_SCHEMA_ID == "inbound-message/v1"
    assert INBOUND_EVENT_TYPE == "inbound.message.telegram.received"
    assert INBOUND_MESSAGE_SCHEMA["required"] == ["channel", "text", "sender"]


def test_register_inbound_schema_validates_a_good_payload():
    reg = SchemaRegistry()
    register_inbound_schema(reg)
    # validate() raises on bad data, returns/no-ops on good data
    reg.validate_data(INBOUND_SCHEMA_ID, {
        "channel": "telegram", "text": "hej",
        "sender": {"channel": "telegram", "channelUserId": 111},
    })
