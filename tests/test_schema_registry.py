import pytest
from bus.schema_registry import SchemaRegistry
from bus.model import EnvelopeError

VOUCHER_V1 = {
    "type": "object",
    "required": ["voucherId"],
    "properties": {"voucherId": {"type": "string"}},
    "additionalProperties": False,
}


def test_validate_data_accepts_matching_payload():
    r = SchemaRegistry()
    r.register("voucher/v1", VOUCHER_V1)
    r.validate_data("voucher/v1", {"voucherId": "V-1"})  # no raise


def test_validate_data_rejects_mismatch():
    r = SchemaRegistry()
    r.register("voucher/v1", VOUCHER_V1)
    with pytest.raises(EnvelopeError):
        r.validate_data("voucher/v1", {"voucherId": 7})


def test_validate_data_rejects_extra_properties():
    r = SchemaRegistry()
    r.register("voucher/v1", VOUCHER_V1)
    with pytest.raises(EnvelopeError):
        r.validate_data("voucher/v1", {"voucherId": "V-1", "amount": 100})


def test_validate_data_unknown_schema_raises():
    r = SchemaRegistry()
    with pytest.raises(EnvelopeError):
        r.validate_data("nope/v9", {"x": 1})
