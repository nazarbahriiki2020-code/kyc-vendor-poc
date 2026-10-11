import hashlib
import hmac
import json

import httpx
import pytest
import respx

from kyc_poc.models import Status, VendorError
from kyc_poc.vendors.didit import Didit, canonical_json

BASE = "https://verification.didit.me"
NOW = 1_800_000_000


@pytest.fixture
def didit():
    return Didit("key-123", "wf-1", webhook_secret="whsec", client=httpx.Client(), clock=lambda: NOW)


@respx.mock
def test_create_session_sends_workflow_and_scenario(didit):
    route = respx.post(f"{BASE}/v3/session/").mock(
        return_value=httpx.Response(
            201, json={"session_id": "s-1", "url": "https://verify.didit.me/s-1", "session_token": "tok"}
        )
    )
    s = didit.create_session("poc-abc", scenario="approve")

    req = route.calls.last.request
    assert req.headers["x-api-key"] == "key-123"
    assert json.loads(req.content) == {
        "workflow_id": "wf-1", "vendor_data": "poc-abc", "sandbox_scenario": "approve",
    }
    assert (s.session_id, s.url) == ("s-1", "https://verify.didit.me/s-1")
    assert "session_token" not in s.public()  # tokens never reach the results log


@respx.mock
def test_http_error_becomes_vendor_error(didit):
    respx.post(f"{BASE}/v3/session/").mock(
        return_value=httpx.Response(401, json={"detail": "Invalid or missing API key"})
    )
    with pytest.raises(VendorError) as exc:
        didit.create_session("poc-abc")
    assert exc.value.status_code == 401


DECLINED = {
    "session_id": "s-2",
    "status": "Declined",
    "id_verifications": [
        {
            "node_id": "id_verification_1", "status": "Declined",
            "first_name": "Jane", "date_of_birth": "1990-01-01",  # PII must not leak
            "warnings": [{"risk": "DOCUMENT_EXPIRED"}],
        }
    ],
    "liveness_checks": [{"status": "Approved", "score": 92.0, "warnings": []}],
    "face_matches": [{"status": "Declined", "score": 32, "warnings": [{"risk": "LOW_FACE_MATCH_SIMILARITY"}]}],
}


def test_parse_decision_maps_status_and_checks():
    d = Didit.parse_decision(DECLINED)
    assert d.status is Status.DECLINED
    assert [c.name for c in d.checks] == ["id_verification", "liveness", "face_match"]
    assert d.risks == ["DOCUMENT_EXPIRED", "LOW_FACE_MATCH_SIMILARITY"]
    dumped = json.dumps(d.to_dict())
    assert "Jane" not in dumped and "1990-01-01" not in dumped


@pytest.mark.parametrize(
    "raw,expected",
    [("In Review", Status.REVIEW), ("Kyc Expired", Status.EXPIRED), ("Not Started", Status.PENDING),
     ("Something New", Status.UNKNOWN)],
)
def test_status_mapping(raw, expected):
    assert Didit.parse_decision({"status": raw}, "s").status is expected


@respx.mock
def test_simulate_posts_scenario(didit):
    route = respx.post(f"{BASE}/v3/session/s-1/simulate/").mock(return_value=httpx.Response(200, json={}))
    didit.simulate("s-1", "decline_liveness_attack")
    assert json.loads(route.calls.last.request.content) == {"scenario": "decline_liveness_attack"}


# --- webhook signatures ------------------------------------------------------

PAYLOAD = {
    "event_id": "e-1", "session_id": "s-1", "status": "Approved",
    "webhook_type": "status.updated", "timestamp": NOW, "vendor_data": "José",
    "decision": {"face_matches": [{"score": 96.0}]},
}


def _sign(text: str | bytes, secret: str = "whsec") -> str:
    data = text.encode() if isinstance(text, str) else text
    return hmac.new(secret.encode(), data, hashlib.sha256).hexdigest()


def test_signature_v2_survives_reencoding(didit):
    # Body re-encoded with escaped Unicode and different key order: V2 still verifies.
    body = json.dumps(PAYLOAD, ensure_ascii=True).encode()
    headers = {"X-Signature-V2": _sign(canonical_json(PAYLOAD)), "X-Timestamp": str(NOW)}
    assert didit.verify_webhook(headers, body)


def test_raw_signature_fallback(didit):
    body = json.dumps(PAYLOAD, sort_keys=True, separators=(",", ":")).encode()
    assert didit.verify_webhook({"x-signature": _sign(body), "x-timestamp": str(NOW)}, body)


def test_rejects_wrong_secret_stale_timestamp_and_simple_only(didit):
    body = json.dumps(PAYLOAD).encode()
    good = _sign(canonical_json(PAYLOAD))
    assert not didit.verify_webhook({"x-signature-v2": _sign(canonical_json(PAYLOAD), "other"),
                                     "x-timestamp": str(NOW)}, body)
    assert not didit.verify_webhook({"x-signature-v2": good, "x-timestamp": str(NOW - 301)}, body)
    simple = _sign(f"{NOW}:s-1:Approved:status.updated")
    assert not didit.verify_webhook({"x-signature-simple": simple, "x-timestamp": str(NOW)}, body)


def test_no_secret_means_reject():
    d = Didit("k", "wf", webhook_secret=None, client=httpx.Client(), clock=lambda: NOW)
    assert not d.verify_webhook({"x-signature-v2": "x", "x-timestamp": str(NOW)}, b"{}")


def test_parse_webhook(didit):
    ev = didit.parse_webhook(PAYLOAD)
    assert (ev.session_id, ev.status, ev.kind, ev.event_id) == ("s-1", Status.APPROVED, "status.updated", "e-1")


@respx.mock
def test_error_body_is_reduced_to_allow_listed_fields(didit):
    respx.post(f"{BASE}/v3/session/").mock(
        return_value=httpx.Response(400, json={
            "detail": "Invalid request", "code": "bad_input",
            "expected_details": {"first_name": "Jane", "date_of_birth": "1990-01-01"},
        })
    )
    with pytest.raises(VendorError) as exc:
        didit.create_session("poc-abc")
    text = str(exc.value)
    assert "detail=Invalid request" in text and "code=bad_input" in text
    assert "Jane" not in text and "1990" not in text


@respx.mock
def test_non_json_error_body_is_dropped(didit):
    respx.post(f"{BASE}/v3/session/").mock(return_value=httpx.Response(502, text="<html>Jane Doe</html>"))
    with pytest.raises(VendorError) as exc:
        didit.create_session("poc-abc")
    assert "Jane" not in str(exc.value) and exc.value.status_code == 502
