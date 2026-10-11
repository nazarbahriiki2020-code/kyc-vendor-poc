"""Veriff adapter (Public API v1).

Docs used:
- Getting started / integrations: https://veriff.com/developers
- Public API & auth headers:       https://devdocs.veriff.com/apidocs

Auth model: every request carries X-AUTH-CLIENT (API key). Requests whose
payload must be authenticated also carry X-HMAC-SIGNATURE, a hex
HMAC-SHA256 of the payload keyed with the integration's shared secret
(for GET /sessions/{id}/decision the payload is the session id itself).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Mapping

import httpx

from ..models import CheckResult, Decision, Session, Status, WebhookEvent
from .base import KYCVendor

DEFAULT_BASE_URL = "https://stationapi.veriff.com"

STATUS_MAP: dict[str, Status] = {
    "approved": Status.APPROVED,
    "declined": Status.DECLINED,
    "resubmission_requested": Status.RESUBMIT,
    "review": Status.REVIEW,
    "expired": Status.EXPIRED,
    "abandoned": Status.ABANDONED,
}


class Veriff(KYCVendor):
    name = "veriff"

    def __init__(
        self,
        api_key: str,
        shared_secret: str,
        base_url: str = DEFAULT_BASE_URL,
        client: httpx.Client | None = None,
    ):
        super().__init__(client)
        self.api_key = api_key
        self.shared_secret = shared_secret
        self.base_url = base_url.rstrip("/")

    def sign(self, payload: bytes) -> str:
        return hmac.new(self.shared_secret.encode(), payload, hashlib.sha256).hexdigest()

    # --- session lifecycle -------------------------------------------------
    def create_session(
        self, reference: str, scenario: str | None = None, callback: str | None = None
    ) -> Session:
        if scenario:
            raise ValueError(
                "Veriff has no sandbox scenarios. In a Test integration Veriff does not "
                "decide sessions itself: set the decision manually in the Customer Portal."
            )
        verification: dict[str, Any] = {"vendorData": reference}
        if callback:
            verification["callback"] = callback
        raw = json.dumps({"verification": verification}, separators=(",", ":")).encode()
        r = self._client.post(
            f"{self.base_url}/v1/sessions",
            content=raw,
            headers={
                "X-AUTH-CLIENT": self.api_key,
                "X-HMAC-SIGNATURE": self.sign(raw),
                "Content-Type": "application/json",
            },
        )
        data = self._json(r, "create session")
        v = data.get("verification") or {}
        secrets = {"session_token": v["sessionToken"]} if v.get("sessionToken") else {}
        return Session(self.name, str(v["id"]), v.get("url"), secrets)

    def get_decision(self, session_id: str) -> Decision:
        r = self._client.get(
            f"{self.base_url}/v1/sessions/{session_id}/decision",
            headers={
                "X-AUTH-CLIENT": self.api_key,
                "X-HMAC-SIGNATURE": self.sign(session_id.encode()),
                "Content-Type": "application/json",
            },
        )
        return self.parse_decision(self._json(r, "get decision"), session_id)

    @classmethod
    def parse_decision(cls, data: dict[str, Any], session_id: str | None = None) -> Decision:
        v = data.get("verification")
        if not v:
            # No decision yet: the end-user has not finished, or (in a Test
            # integration) nobody has set a decision in the Customer Portal.
            return Decision(cls.name, str(session_id), Status.PENDING, None)
        raw = v.get("status")
        risks = [
            str(rl.get("label")) for rl in v.get("riskLabels") or [] if isinstance(rl, dict)
        ]
        code = v.get("code")
        reason = v.get("reason")
        reason_text = " ".join(p for p in (f"code {code}" if code else "", reason or "") if p)
        return Decision(
            vendor=cls.name,
            session_id=str(v.get("id") or session_id),
            status=STATUS_MAP.get(str(raw), Status.UNKNOWN),
            raw_status=raw,
            checks=[CheckResult("decision", str(raw), None, risks)],
            reason=reason_text or None,
        )

    # --- webhooks ------------------------------------------------------------
    def verify_webhook(self, headers: Mapping[str, str], raw_body: bytes) -> bool:
        h = self._lower(headers)
        client = h.get("x-auth-client")
        if client is not None and not hmac.compare_digest(client, self.api_key):
            return False
        return self._safe_equal(h.get("x-hmac-signature"), self.sign(raw_body))

    def parse_webhook(self, payload: dict[str, Any]) -> WebhookEvent:
        v = payload.get("verification")
        if isinstance(v, dict):  # decision webhook
            raw = v.get("status")
            return WebhookEvent(
                vendor=self.name,
                session_id=v.get("id"),
                status=STATUS_MAP.get(str(raw), Status.UNKNOWN),
                raw_status=raw,
                kind="decision",
            )
        # event webhook: {"id": ..., "action": "started" | "submitted", ...}
        return WebhookEvent(
            vendor=self.name,
            session_id=payload.get("id"),
            status=Status.PENDING,
            raw_status=payload.get("action"),
            kind="event",
        )
