"""Common interface every vendor adapter implements.

The point of the PoC is that the *same* calling code drives every vendor,
so differences in the results come from the vendors, not from our glue.
"""

from __future__ import annotations

import hmac
from abc import ABC, abstractmethod
from typing import Any, Mapping

import httpx

from ..models import Decision, Session, VendorError, WebhookEvent, safe_error_detail


class KYCVendor(ABC):
    name: str = "base"

    def __init__(self, client: httpx.Client | None = None, timeout: float = 20.0):
        self._client = client or httpx.Client(timeout=timeout)

    # --- session lifecycle -------------------------------------------------
    @abstractmethod
    def create_session(
        self, reference: str, scenario: str | None = None, callback: str | None = None
    ) -> Session:
        """Create a hosted verification session and return its URL."""

    @abstractmethod
    def get_decision(self, session_id: str) -> Decision:
        """Fetch the current decision (polling fallback to webhooks)."""

    def simulate(self, session_id: str, scenario: str) -> None:
        """Force an outcome in sandbox. Only some vendors support this."""
        raise NotImplementedError(f"{self.name} has no API to simulate outcomes")

    # --- webhooks ------------------------------------------------------------
    @abstractmethod
    def verify_webhook(self, headers: Mapping[str, str], raw_body: bytes) -> bool:
        """Authenticate an incoming webhook. Must use constant-time comparison."""

    @abstractmethod
    def parse_webhook(self, payload: dict[str, Any]) -> WebhookEvent:
        """Turn a verified webhook payload into a vendor-neutral event."""

    # --- helpers -------------------------------------------------------------
    @staticmethod
    def _lower(headers: Mapping[str, str]) -> dict[str, str]:
        return {k.lower(): v for k, v in headers.items()}

    @staticmethod
    def _safe_equal(a: str | None, b: str | None) -> bool:
        if not a or not b:
            return False
        return hmac.compare_digest(a.strip().lower(), b.strip().lower())

    def _json(self, response: httpx.Response, action: str) -> dict[str, Any]:
        if response.status_code >= 400:
            raise VendorError(
                self.name, f"{action} failed", response.status_code, safe_error_detail(response.text)
            )
        try:
            return response.json()
        except ValueError as exc:
            raise VendorError(self.name, f"{action} returned non-JSON", response.status_code) from exc
