import hashlib
import hmac
import json

import httpx
from fastapi.testclient import TestClient

from kyc_poc import cli, results
from kyc_poc.models import Decision, Status
from kyc_poc.vendors import Veriff
from kyc_poc.webhooks import create_app


def test_webhook_endpoint_verifies_and_logs(tmp_path):
    v = Veriff("api-key", "shared-secret", client=httpx.Client())
    client = TestClient(create_app({"veriff": v}, str(tmp_path)))
    body = json.dumps({"status": "success", "verification": {"id": "v-1", "status": "approved"}}).encode()
    sig = hmac.new(b"shared-secret", body, hashlib.sha256).hexdigest()

    assert client.post("/webhooks/veriff", content=body, headers={"x-hmac-signature": sig}).status_code == 200
    assert client.post("/webhooks/veriff", content=body, headers={"x-hmac-signature": "bad"}).status_code == 401
    assert client.post("/webhooks/nope", content=body).status_code == 404

    rows = results.load(str(tmp_path))
    assert [r["verified"] for r in rows] == [True, False]
    assert rows[0]["status"] == "approved"


def test_expected_status():
    assert cli.expected_status("approve") is Status.APPROVED
    assert cli.expected_status("decline_liveness_attack") is Status.DECLINED
    assert cli.expected_status("review_face_match_borderline") is Status.REVIEW


class FakeVendor:
    name = "fake"

    def __init__(self, statuses):
        self.statuses = list(statuses)

    def get_decision(self, session_id):
        return Decision("fake", session_id, self.statuses.pop(0), None)


def test_poll_until_terminal_stops_on_final_status(tmp_path):
    v = FakeVendor([Status.PENDING, Status.PENDING, Status.APPROVED, Status.DECLINED])
    d, _ = cli.poll_until_terminal(v, "s", str(tmp_path), timeout=60, interval=0, sleep=lambda _: None)
    assert d.status is Status.APPROVED
    assert len(results.load(str(tmp_path))) == 3


def test_summary_table(tmp_path):
    out = str(tmp_path)
    results.record(out, "session_created", vendor="didit", latency_ms=200)
    results.record(out, "session_created", vendor="didit", latency_ms=400)
    results.record(out, "scenario_run", vendor="didit", scenario="approve", expected="approved",
                   actual="approved", match=True, risks=[])
    results.record(out, "error", vendor="veriff", step="create_session", http_status=401, message="bad | key")
    md = results.summarize(results.load(out))
    assert "| didit | 300 / 390 ms (n=2)" in md
    assert "1/1" in md and "`approve`" in md and "bad \\| key" in md


def test_duplicate_webhook_is_acknowledged_but_not_reprocessed(tmp_path):
    v = Veriff("api-key", "shared-secret", client=httpx.Client())
    client = TestClient(create_app({"veriff": v}, str(tmp_path)))
    body = json.dumps({"status": "success", "verification": {"id": "v-1", "status": "declined"}}).encode()
    sig = hmac.new(b"shared-secret", body, hashlib.sha256).hexdigest()

    first = client.post("/webhooks/veriff", content=body, headers={"x-hmac-signature": sig})
    again = client.post("/webhooks/veriff", content=body, headers={"x-hmac-signature": sig})
    assert first.json() == {"ok": True}
    assert again.status_code == 200 and again.json() == {"ok": True, "duplicate": True}
    assert [r["duplicate"] for r in results.load(str(tmp_path))] == [False, True]


def test_seen_events_is_bounded():
    from kyc_poc.webhooks import SeenEvents

    s = SeenEvents(limit=2)
    assert s.add("a") and s.add("b") and s.add("c")
    assert s.add("a")  # evicted, so treated as new again
    assert not s.add("c")


def test_small_samples_are_flagged(tmp_path):
    results.record(str(tmp_path), "session_created", vendor="veriff", latency_ms=738)
    assert "738 / 738 ms (n=1), too few to compare" in results.summarize(results.load(str(tmp_path)))
