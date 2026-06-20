"""Canonical inbound-message event: schema + identifiers.

This is the contract seam between any channel connector and the capture-bridge.
A connector emits an event of INBOUND_EVENT_TYPE whose data validates against
INBOUND_MESSAGE_SCHEMA. The bridge consumes it. Channel-agnostic by design.
"""

INBOUND_SCHEMA_ID = "inbound-message/v1"
INBOUND_EVENT_TYPE = "inbound.message.telegram.received"

INBOUND_MESSAGE_SCHEMA = {
    "type": "object",
    "required": ["channel", "text", "sender"],
    "properties": {
        "channel": {"type": "string"},
        "text": {"type": "string"},
        "lang": {"type": "string"},
        "channelMsgId": {"type": "integer"},
        "channelChatId": {"type": "integer"},
        "sender": {
            "type": "object",
            "required": ["channel", "channelUserId"],
            "properties": {
                "channel": {"type": "string"},
                "channelUserId": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        "attachments": {"type": "array"},
        "capturedAt": {"type": "string"},
    },
    "additionalProperties": False,
}


def register_inbound_schema(reg) -> None:
    """Register the inbound-message schema on a bus SchemaRegistry."""
    reg.register(INBOUND_SCHEMA_ID, INBOUND_MESSAGE_SCHEMA)
