import pytest
from bus.model import Event, EnvelopeError
from bus.envelope import stamp_envelope, validate_envelope


def _body(**over):
    b = {"type": "bookkeeping.voucher.posted", "schema": "voucher/v1",
         "source": "bookkeeping", "trace": {"store": "bk-audit", "ref": "a1"},
         "data": {"voucherId": "V-1"}, "occurredAt": "2026-06-20T10:00:00Z"}
    b.update(over)
    return b


def test_stamp_sets_principal_org_and_id_from_server_not_body():
    body = _body(principal="prn_EVIL", org="org_EVIL", id=None)
    ev = stamp_envelope(body, principal="prn_real", org="org_real", now_iso="2026-06-20T11:00:00Z")
    assert ev.principal == "prn_real"
    assert ev.org == "org_real"
    assert ev.id.startswith("evt_")
    assert ev.occurred_at == "2026-06-20T10:00:00Z"  # producer-set occurredAt is kept


def test_stamp_defaults_occurred_at_when_absent():
    body = _body()
    del body["occurredAt"]
    ev = stamp_envelope(body, principal="prn_real", org="org_real", now_iso="2026-06-20T11:00:00Z")
    assert ev.occurred_at == "2026-06-20T11:00:00Z"


def test_validate_accepts_well_formed_envelope():
    ev = stamp_envelope(_body(), principal="prn_real", org="org_real", now_iso="2026-06-20T11:00:00Z")
    validate_envelope(ev)  # no raise


def test_validate_rejects_missing_trace_ref():
    ev = stamp_envelope(_body(trace={"store": "bk-audit"}), principal="p", org="o",
                        now_iso="2026-06-20T11:00:00Z")
    with pytest.raises(EnvelopeError):
        validate_envelope(ev)


def test_validate_rejects_non_dotted_type():
    ev = stamp_envelope(_body(type="notdotted"), principal="p", org="o",
                        now_iso="2026-06-20T11:00:00Z")
    with pytest.raises(EnvelopeError):
        validate_envelope(ev)


def test_validate_rejects_non_object_data():
    ev = stamp_envelope(_body(data=["nope"]), principal="p", org="o",
                        now_iso="2026-06-20T11:00:00Z")
    with pytest.raises(EnvelopeError):
        validate_envelope(ev)
