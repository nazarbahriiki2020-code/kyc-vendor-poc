import hashlib
import hmac
import json

import httpx
import pytest
import respx

from kyc_poc.models import Status
from kyc_poc.vendors.veriff import Veriff

BASE = "https://stationapi.veriff.com"


@pytest.fixture
def veriff():
    return Veriff("api-key", "shared-secret", client=httpx.Client())


def _sign(data: bytes) -> str:
    return hmac.new(b"shared-secret", data, hashlib.sha256).hexdigest()


@respx.mock
def test_create_session_signs_body(veriff):
    route = respx.post(f"{BASE}/v1/sessions").mock(
        return_value=httpx.Response(
            201,
            json={"status": "success", "verification": {
                "id": "v-1", "url": "https://alchemy.veriff.com/v/abc", "sessionToken": "tok"}},
        )
    )
    s = veriff.create_session("poc-abc")
    req = route.calls.last.request
    assert req.headers["x-auth-client"] == "api-key"
    assert req.headers["x-hmac-signature"] == _sign(req.content)
    assert json.loads(req.content) == {"verification": {"vendorData": "poc-abc"}}
    assert (s.session_id, s.url) == ("v-1", "https://alchemy.veriff.com/v/abc")


def test_scenarios_are_rejected(veriff):
    with pytest.raises(ValueError):
        veriff.create_session("poc-abc", scenario="approve")


@respx.mock
def test_decision_signs_session_id(veriff):
    route = respx.get(f"{BASE}/v1/sessions/v-1/decision").mock(
        return_value=httpx.Response(200, json={"status": "success", "verification": {
            "id": "v-1", "status": "declined", "code": 9102, "reason": "Physical document not used",
            "person": {"firstName": "JANE"},  # PII must not leak
            "riskLabels": [{"label": "document_integration_level_crosslinked_with_fraud"}],
        }})
    )
    d = veriff.get_decision("v-1")
    assert route.calls.last.request.headers["x-hmac-signature"] == _sign(b"v-1")
    assert d.status is Status.DECLINED
    assert d.reason == "code 9102 Physical document not used"
    assert d.risks == ["document_integration_level_crosslinked_with_fraud"]
    assert "JANE" not in json.dumps(d.to_dict())


def test_no_decision_yet_is_pending():
    d = Veriff.parse_decision({"status": "success", "verification": None}, "v-1")
    assert d.status is Status.PENDING and not d.status.is_terminal


@pytest.mark.parametrize("raw,expected", [
    ("approved", Status.APPROVED), ("resubmission_requested", Status.RESUBMIT),
    ("review", Status.REVIEW), ("abandoned", Status.ABANDONED),
])
def test_status_mapping(raw, expected):
    assert Veriff.parse_decision({"verification": {"id": "v", "status": raw}}).status is expected


def test_webhook_signature(veriff):
    body = b'{"status":"success","verification":{"id":"v-1","status":"approved"}}'
    assert veriff.verify_webhook({"X-HMAC-SIGNATURE": _sign(body), "X-AUTH-CLIENT": "api-key"}, body)
    assert not veriff.verify_webhook({"x-hmac-signature": _sign(body + b" ")}, body)
    assert not veriff.verify_webhook({"x-hmac-signature": _sign(body), "x-auth-client": "other"}, body)


def test_parse_decision_and_event_webhooks(veriff):
    ev = veriff.parse_webhook({"status": "success", "verification": {"id": "v-1", "status": "approved"}})
    assert (ev.kind, ev.status, ev.session_id) == ("decision", Status.APPROVED, "v-1")
    ev = veriff.parse_webhook({"id": "v-1", "action": "submitted", "code": 7002})
    assert (ev.kind, ev.status, ev.raw_status) == ("event", Status.PENDING, "submitted")
