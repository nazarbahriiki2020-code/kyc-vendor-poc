"""Vendor-neutral data model.

Everything here is PII-free by construction: we keep statuses, scores and
risk codes only. Names, dates of birth, document numbers and images from
vendor payloads are never copied into these objects, so nothing that is
logged or written to ``results/`` can leak personal data.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DECLINED = "declined"
    REVIEW = "review"
    RESUBMIT = "resubmit"
    EXPIRED = "expired"
    ABANDONED = "abandoned"
    UNKNOWN = "unknown"

    @property
    def is_terminal(self) -> bool:
        return self not in (Status.PENDING, Status.UNKNOWN)


@dataclass
class Session:
    vendor: str
    session_id: str
    url: str | None
    # Client-side tokens (e.g. Didit session_token). Kept in memory only,
    # never serialised to results.
    secrets: dict[str, str] = field(default_factory=dict, repr=False)

    def public(self) -> dict[str, Any]:
        return {"vendor": self.vendor, "session_id": self.session_id, "url": self.url}


@dataclass
class CheckResult:
    """One feature inside a decision: ID check, liveness, face match, ..."""

    name: str
    status: str
    score: float | None = None
    risks: list[str] = field(default_factory=list)


@dataclass
class Decision:
    vendor: str
    session_id: str
    status: Status
    raw_status: str | None
    checks: list[CheckResult] = field(default_factory=list)
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @property
    def risks(self) -> list[str]:
        return sorted({r for c in self.checks for r in c.risks})


@dataclass
class WebhookEvent:
    vendor: str
    session_id: str | None
    status: Status
    raw_status: str | None
    kind: str
    event_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


class VendorError(Exception):
    """An HTTP or protocol error returned by a vendor API.

    The raw response body is deliberately NOT kept: an error body could echo
    request data back. Only ``detail``, a short summary built from a fixed
    allow-list of error fields, is stored and logged.
    """

    def __init__(self, vendor: str, message: str, status_code: int | None = None, detail: str = ""):
        self.vendor = vendor
        self.status_code = status_code
        self.detail = detail
        suffix = f": {detail}" if detail else ""
        super().__init__(f"[{vendor}] {message} (HTTP {status_code}){suffix}")


# Error fields that vendors use for human-readable error descriptions and codes.
SAFE_ERROR_FIELDS = ("detail", "message", "error", "code", "reason", "status")
MAX_ERROR_DETAIL = 200


def safe_error_detail(body: str) -> str:
    """Reduce a vendor error body to allow-listed scalar fields, or nothing."""
    import json

    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return ""  # non-JSON (HTML error pages etc.): keep nothing
    if not isinstance(data, dict):
        return ""
    parts = [
        f"{k}={data[k]}"
        for k in SAFE_ERROR_FIELDS
        if isinstance(data.get(k), (str, int, float, bool))
    ]
    return "; ".join(parts)[:MAX_ERROR_DETAIL]
