"""Didit adapter (API v3).

Docs used:
- Quick start / sessions: https://docs.didit.me/getting-started/quick-start
- Webhooks & signatures:  https://docs.didit.me/integration/webhooks
- Sandbox scenarios:      https://docs.didit.me/integration/sandbox-testing
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Callable, Mapping

import httpx

from ..models import CheckResult, Decision, Session, Status, WebhookEvent
from .base import KYCVendor

DEFAULT_BASE_URL = "https://verification.didit.me"

# Exact, case-sensitive strings from the Didit docs ("Kyc Expired" included).
STATUS_MAP: dict[str, Status] = {
    "Not Started": Status.PENDING,
    "In Progress": Status.PENDING,
    "Awaiting User": Status.PENDING,
    "Approved": Status.APPROVED,
    "Declined": Status.DECLINED,
    "In Review": Status.REVIEW,
    "Resubmitted": Status.RESUBMIT,
    "Expired": Status.EXPIRED,
    "Kyc Expired": Status.EXPIRED,
    "Abandoned": Status.ABANDONED,
}

# V3 decisions use plural arrays, one item per workflow node.
FEATURE_ARRAYS: dict[str, str] = {
    "id_verifications": "id_verification",
    "liveness_checks": "liveness",
    "face_matches": "face_match",
    "ip_analyses": "ip_analysis",
    "aml_screenings": "aml",
    "nfc_verifications": "nfc",
    "database_validations": "database_validation",
    "poa_verifications": "proof_of_address",
    "phone_verifications": "phone",
    "email_verifications": "email",
}

SIGNATURE_MAX_AGE_SECONDS = 300


def _shorten_floats(data: Any) -> Any:
    """Didit serialises whole-valued floats as ints; mirror that before signing."""
    if isinstance(data, dict):
        return {k: _shorten_floats(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_shorten_floats(x) for x in data]
    if isinstance(data, float) and data.is_integer():
        return int(data)
    return data


def canonical_json(payload: Any) -> str:
    """Canonical form signed by X-Signature-V2: sorted keys, compact, Unicode kept."""
    return json.dumps(
        _shorten_floats(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


class Didit(KYCVendor):
    name = "didit"

    def __init__(
        self,
        api_key: str,
        workflow_id: str,
        webhook_secret: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        client: httpx.Client | None = None,
        clock: Callable[[], float] = time.time,
    ):
        super().__init__(client)
        self.api_key = api_key
        self.workflow_id = workflow_id
        self.webhook_secret = webhook_secret
        self.base_url = base_url.rstrip("/")
        self._clock = clock

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # --- session lifecycle -------------------------------------------------
    def create_session(
        self, reference: str, scenario: str | None = None, callback: str | None = None
    ) -> Session:
        body: dict[str, Any] = {"workflow_id": self.workflow_id, "vendor_data": reference}
        if scenario:
            # Accepted only by sandbox-mode applications; live apps reject it.
            body["sandbox_scenario"] = scenario
        if callback:
            body["callback"] = callback
        r = self._client.post(f"{self.base_url}/v3/session/", json=body, headers=self._headers())
        data = self._json(r, "create session")
        secrets = {"session_token": data["session_token"]} if data.get("session_token") else {}
        return Session(self.name, str(data["session_id"]), data.get("url"), secrets)

    def get_decision(self, session_id: str) -> Decision:
        r = self._client.get(
            f"{self.base_url}/v3/session/{session_id}/decision/", headers=self._headers()
        )
        return self.parse_decision(self._json(r, "get decision"), session_id)

    def simulate(self, session_id: str, scenario: str) -> None:
        """Sandbox only. Needs an API key with the write:sessions privilege."""
        r = self._client.post(
            f"{self.base_url}/v3/session/{session_id}/simulate/",
            json={"scenario": scenario},
            headers=self._headers(),
        )
        self._json(r, "simulate")

    @classmethod
    def parse_decision(cls, data: dict[str, Any], session_id: str | None = None) -> Decision:
        raw = data.get("status")
        checks: list[CheckResult] = []
        for key, label in FEATURE_ARRAYS.items():
            for item in data.get(key) or []:
                if not isinstance(item, dict):
                    continue
                score = item.get("score")
                checks.append(
                    CheckResult(
                        name=label,
                        status=str(item.get("status")),
                        score=float(score) if isinstance(score, (int, float)) else None,
                        risks=[w["risk"] for w in item.get("warnings") or [] if w.get("risk")],
                    )
                )
        return Decision(
            vendor=cls.name,
            session_id=str(data.get("session_id") or session_id),
            status=STATUS_MAP.get(raw, Status.UNKNOWN),
            raw_status=raw,
            checks=checks,
        )

    # --- webhooks ------------------------------------------------------------
    def verify_webhook(self, headers: Mapping[str, str], raw_body: bytes) -> bool:
        """Verify X-Signature-V2, falling back to X-Signature (raw bytes).

        X-Signature-Simple is deliberately NOT accepted: per Didit's docs it
        only covers four envelope fields, not the decision body.
        """
        if not self.webhook_secret:
            return False
        h = self._lower(headers)
        try:
            ts = int(h.get("x-timestamp", ""))
        except ValueError:
            return False
        if abs(self._clock() - ts) > SIGNATURE_MAX_AGE_SECONDS:
            return False

        key = self.webhook_secret.encode()
        sig_v2 = h.get("x-signature-v2")
        if sig_v2:
            try:
                canonical = canonical_json(json.loads(raw_body.decode("utf-8")))
            except (ValueError, UnicodeDecodeError):
                return False
            expected = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
            if self._safe_equal(sig_v2, expected):
                return True

        sig_raw = h.get("x-signature")
        if sig_raw:
            expected = hmac.new(key, raw_body, hashlib.sha256).hexdigest()
            if self._safe_equal(sig_raw, expected):
                return True
        return False

    def parse_webhook(self, payload: dict[str, Any]) -> WebhookEvent:
        raw = payload.get("status")
        return WebhookEvent(
            vendor=self.name,
            session_id=payload.get("session_id"),
            status=STATUS_MAP.get(raw, Status.UNKNOWN),
            raw_status=raw,
            kind=str(payload.get("webhook_type", "unknown")),
            event_id=payload.get("event_id"),
        )
