"""Append-only JSONL evidence log plus a Markdown summary generator.

Each line in results/runs.jsonl is one observation (a session created, a
decision fetched, a scenario run, a webhook received). Only normalised,
PII-free fields are ever written.
"""

from __future__ import annotations

import json
import os
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable

RUNS_FILE = "runs.jsonl"


def record(results_dir: str, event: str, **fields: Any) -> dict[str, Any]:
    os.makedirs(results_dir, exist_ok=True)
    row = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "event": event, **fields}
    with open(os.path.join(results_dir, RUNS_FILE), "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row


def load(results_dir: str) -> list[dict[str, Any]]:
    path = os.path.join(results_dir, RUNS_FILE)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _pct(values: list[float], q: float) -> float:
    if len(values) == 1:
        return values[0]
    return statistics.quantiles(values, n=100, method="inclusive")[int(q) - 1]


MIN_SAMPLES = 5


def _latency(values: Iterable[float]) -> str:
    v = sorted(x for x in values if x is not None)
    if not v:
        return "–"
    text = f"{statistics.median(v):.0f} / {_pct(v, 95):.0f} ms (n={len(v)})"
    if len(v) < MIN_SAMPLES:
        text += ", too few to compare"
    return text


def summarize(rows: list[dict[str, Any]]) -> str:
    by_vendor: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        if r.get("vendor"):
            by_vendor[r["vendor"]].append(r)

    lines = [
        "# Run summary",
        "",
        "Generated from `results/runs.jsonl`. Figures are **observed API round-trip "
        "latency from one machine (median / p95), not a vendor performance benchmark** "
        "and not end-user verification time. Get-decision figures are polling calls: "
        "many calls can belong to the same session.",
        "",
        "| Vendor | Create session | Get decision: poll calls | Sessions polled | "
        "Scenario runs (match) | Errors | Webhooks ok / duplicate / rejected |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for vendor in sorted(by_vendor):
        rs = by_vendor[vendor]
        create = [r["latency_ms"] for r in rs if r["event"] == "session_created"]
        decision = [r["latency_ms"] for r in rs if r["event"] == "decision_fetched"]
        scen = [r for r in rs if r["event"] == "scenario_run"]
        matched = sum(1 for r in scen if r.get("match"))
        errors = sum(1 for r in rs if r["event"] == "error")
        polled = {r.get("session_id") for r in rs if r["event"] == "decision_fetched"}
        hooks = [r for r in rs if r["event"] == "webhook"]
        wh_ok = sum(1 for r in hooks if r.get("verified") and not r.get("duplicate"))
        wh_dup = sum(1 for r in hooks if r.get("verified") and r.get("duplicate"))
        wh_bad = sum(1 for r in hooks if not r.get("verified"))
        lines.append(
            f"| {vendor} | {_latency(create)} | {_latency(decision)} | {len(polled)} | "
            f"{matched}/{len(scen)} | {errors} | {wh_ok} / {wh_dup} / {wh_bad} |"
        )

    scen_rows = [r for r in rows if r.get("event") == "scenario_run"]
    if scen_rows:
        lines += [
            "",
            "## Scenario matrix",
            "",
            "| Vendor | Scenario | Expected | Actual | Match | Risk codes |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for r in scen_rows:
            lines.append(
                f"| {r['vendor']} | `{r['scenario']}` | {r.get('expected')} | "
                f"{r.get('actual')} | {'✅' if r.get('match') else '❌'} | "
                f"{', '.join(r.get('risks') or []) or '–'} |"
            )

    err_rows = [r for r in rows if r.get("event") == "error"]
    if err_rows:
        lines += ["", "## Errors", "", "| Vendor | Step | HTTP | Message |", "| --- | --- | --- | --- |"]
        for r in err_rows:
            msg = str(r.get("message", "")).replace("|", "\\|").replace("\n", " ")[:160]
            lines.append(f"| {r.get('vendor')} | {r.get('step')} | {r.get('http_status')} | {msg} |")
    return "\n".join(lines) + "\n"
