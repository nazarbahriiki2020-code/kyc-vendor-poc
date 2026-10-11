"""Build vendor adapters from environment variables (.env)."""

from __future__ import annotations

import os

from dotenv import load_dotenv

from .vendors import Didit, KYCVendor, Veriff
from .vendors.didit import DEFAULT_BASE_URL as DIDIT_URL
from .vendors.veriff import DEFAULT_BASE_URL as VERIFF_URL

VENDORS = ("didit", "veriff")


class ConfigError(RuntimeError):
    pass


def _env(name: str, required: bool = True) -> str | None:
    value = os.getenv(name, "").strip()
    if required and not value:
        raise ConfigError(f"{name} is not set. Copy .env.example to .env and fill it in.")
    return value or None


def build_vendor(name: str) -> KYCVendor:
    load_dotenv()
    if name == "didit":
        return Didit(
            api_key=_env("DIDIT_API_KEY"),
            workflow_id=_env("DIDIT_WORKFLOW_ID"),
            webhook_secret=_env("DIDIT_WEBHOOK_SECRET", required=False),
            base_url=_env("DIDIT_BASE_URL", required=False) or DIDIT_URL,
        )
    if name == "veriff":
        return Veriff(
            api_key=_env("VERIFF_API_KEY"),
            shared_secret=_env("VERIFF_SHARED_SECRET"),
            base_url=_env("VERIFF_BASE_URL", required=False) or VERIFF_URL,
        )
    raise ConfigError(f"Unknown vendor {name!r}. Choose one of: {', '.join(VENDORS)}")


def configured_vendors() -> dict[str, KYCVendor]:
    """Every vendor whose credentials are present; others are skipped silently."""
    out: dict[str, KYCVendor] = {}
    for name in VENDORS:
        try:
            out[name] = build_vendor(name)
        except ConfigError:
            continue
    return out


def results_dir() -> str:
    load_dotenv()
    return os.getenv("RESULTS_DIR", "results")
