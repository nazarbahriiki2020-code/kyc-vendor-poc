"""Minimal webhook receiver: POST /webhooks/{vendor}.

Run with `python -m kyc_poc serve`, expose it with ngrok/cloudflared and
register https://<public-host>/webhooks/<vendor> in each vendor console.

Order of checks for every request:
1. signature (and, for Didit, timestamp freshness) on the raw body;
2. de-duplication, so a retried or replayed delivery is acknowledged but
   not processed twice;
3. parse and record a PII-free event.
"""

from __future__ import annotations

import json
import logging
from collections import OrderedDict

from fastapi import FastAPI, HTTPException, Request

from . import results
from .models import WebhookEvent
from .vendors import KYCVendor

log = logging.getLogger("kyc_poc.webhooks")

MAX_REMEMBERED_EVENTS = 10_000


def dedup_key(event: WebhookEvent) -> str:
    """Didit sends a stable event_id (reused on retries). Veriff decision
    webhooks have no event id, so fall back to session + kind + status."""
    if event.event_id:
        return f"{event.vendor}:event:{event.event_id}"
    return f"{event.vendor}:{event.session_id}:{event.kind}:{event.raw_status}"


class SeenEvents:
    """Bounded in-memory set. A restart forgets it; production would use a
    database unique constraint on the same key."""

    def __init__(self, limit: int = MAX_REMEMBERED_EVENTS):
        self._keys: OrderedDict[str, None] = OrderedDict()
        self._limit = limit

    def add(self, key: str) -> bool:
        """Return True if the key is new."""
        if key in self._keys:
            return False
        self._keys[key] = None
        if len(self._keys) > self._limit:
            self._keys.popitem(last=False)
        return True


def create_app(vendors: dict[str, KYCVendor], results_dir: str) -> FastAPI:
    app = FastAPI(title="KYC vendor PoC – webhook receiver")
    seen = SeenEvents()

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "vendors": sorted(vendors)}

    @app.post("/webhooks/{vendor}")
    async def receive(vendor: str, request: Request) -> dict:
        adapter = vendors.get(vendor)
        if adapter is None:
            raise HTTPException(status_code=404, detail="unknown vendor")

        raw = await request.body()  # raw bytes: never re-serialise before verifying
        if not adapter.verify_webhook(request.headers, raw):
            results.record(results_dir, "webhook", vendor=vendor, verified=False)
            log.warning("rejected %s webhook: bad or stale signature", vendor)
            raise HTTPException(status_code=401, detail="invalid signature")

        try:
            payload = json.loads(raw)
        except ValueError:
            raise HTTPException(status_code=400, detail="body is not JSON")

        event = adapter.parse_webhook(payload)
        if not seen.add(dedup_key(event)):
            # 2xx so the vendor stops retrying, but nothing is processed again.
            results.record(results_dir, "webhook", verified=True, duplicate=True, **event.to_dict())
            log.info("duplicate %s webhook ignored: session=%s", vendor, event.session_id)
            return {"ok": True, "duplicate": True}

        results.record(results_dir, "webhook", verified=True, duplicate=False, **event.to_dict())
        log.info("%s webhook: session=%s status=%s", vendor, event.session_id, event.status.value)
        return {"ok": True}

    return app
