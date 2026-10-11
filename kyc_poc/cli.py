"""Command-line entry point: `python -m kyc_poc <command> ...`."""

from __future__ import annotations

import argparse
import os
import sys
import time
import uuid
from typing import Callable

from . import results
from .config import VENDORS, ConfigError, build_vendor, configured_vendors, results_dir
from .models import Decision, Status, VendorError
from .vendors import KYCVendor

# Scenarios that exercise the features in a document + liveness + face match
# + IP workflow (Didit's "Free KYC"). decline_aml_hit is included on purpose:
# that workflow has no AML step, so it shows how a scenario for a feature the
# workflow lacks is handled.
DEFAULT_DIDIT_SCENARIOS = [
    "approve",
    "decline_document_expired",
    "decline_mrz_validation",
    "decline_face_match_low_similarity",
    "decline_liveness_attack",
    "decline_ip_blocklist",
    "review_face_match_borderline",
    "decline_aml_hit",
]


def expected_status(scenario: str) -> Status:
    if scenario == "approve":
        return Status.APPROVED
    if scenario.startswith("decline_"):
        return Status.DECLINED
    if scenario.startswith("review_"):
        return Status.REVIEW
    return Status.UNKNOWN


def new_reference() -> str:
    # Opaque, non-personal identifier sent as vendor_data / vendorData.
    return f"poc-{uuid.uuid4().hex[:10]}"


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)


def _print_decision(d: Decision) -> None:
    print(f"status: {d.status.value}  (vendor says: {d.raw_status})")
    if d.reason:
        print(f"reason: {d.reason}")
    for c in d.checks:
        score = f" score={c.score:g}" if c.score is not None else ""
        risks = f" risks={','.join(c.risks)}" if c.risks else ""
        print(f"  - {c.name}: {c.status}{score}{risks}")


def _record_error(out: str, vendor: str, step: str, exc: Exception, **extra) -> None:
    results.record(
        out, "error", vendor=vendor, step=step,
        http_status=getattr(exc, "status_code", None), message=str(exc), **extra,
    )


def poll_until_terminal(
    vendor: KYCVendor,
    session_id: str,
    out: str,
    timeout: float,
    interval: float,
    on_poll: Callable[[Decision], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[Decision | None, float]:
    """Poll the decision endpoint; return (last decision, seconds waited)."""
    started = time.perf_counter()
    last: Decision | None = None
    while True:
        t0 = time.perf_counter()
        last = vendor.get_decision(session_id)
        results.record(
            out, "decision_fetched", vendor=vendor.name, session_id=session_id,
            latency_ms=_ms(t0), status=last.status.value, raw_status=last.raw_status,
        )
        if on_poll:
            on_poll(last)
        waited = time.perf_counter() - started
        if last.status.is_terminal or waited >= timeout:
            return last, waited
        sleep(interval)


# --- commands ---------------------------------------------------------------

def cmd_create(args) -> int:
    vendor = build_vendor(args.vendor)
    out = results_dir()
    ref = args.reference or new_reference()
    t0 = time.perf_counter()
    try:
        s = vendor.create_session(ref, scenario=args.scenario, callback=args.callback)
    except (VendorError, ValueError) as exc:
        _record_error(out, vendor.name, "create_session", exc)
        print(exc, file=sys.stderr)
        return 1
    latency = _ms(t0)
    results.record(out, "session_created", latency_ms=latency, reference=ref,
                   scenario=args.scenario, **s.public())
    print(f"session_id: {s.session_id}\nurl:        {s.url}\nlatency:    {latency} ms")
    print("\nOpen the URL to complete the flow, then run:")
    print(f"  python -m kyc_poc watch {vendor.name} {s.session_id}")
    return 0


def cmd_decision(args) -> int:
    vendor = build_vendor(args.vendor)
    out = results_dir()
    t0 = time.perf_counter()
    try:
        d = vendor.get_decision(args.session_id)
    except VendorError as exc:
        _record_error(out, vendor.name, "get_decision", exc, session_id=args.session_id)
        print(exc, file=sys.stderr)
        return 1
    results.record(out, "decision_fetched", vendor=vendor.name, session_id=args.session_id,
                   latency_ms=_ms(t0), status=d.status.value, raw_status=d.raw_status)
    _print_decision(d)
    return 0


def cmd_watch(args) -> int:
    vendor = build_vendor(args.vendor)
    out = results_dir()
    seen: list[str | None] = []

    def show(d: Decision) -> None:
        if not seen or seen[-1] != d.raw_status:
            print(f"[{time.strftime('%H:%M:%S')}] {d.raw_status or 'no decision yet'}")
            seen.append(d.raw_status)

    try:
        d, waited = poll_until_terminal(vendor, args.session_id, out, args.timeout, args.interval, show)
    except VendorError as exc:
        _record_error(out, vendor.name, "watch", exc, session_id=args.session_id)
        print(exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nstopped")
        return 130
    if d and d.status.is_terminal:
        results.record(out, "decision_final", vendor=vendor.name, session_id=args.session_id,
                       seconds_to_decision=round(waited, 1), status=d.status.value,
                       risks=d.risks)
        print()
        _print_decision(d)
        return 0
    print(f"No final decision after {args.timeout:.0f}s.")
    return 2


def cmd_bench(args) -> int:
    vendor = build_vendor(args.vendor)
    out = results_dir()
    scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    if vendor.name == "veriff":
        print("Veriff has no scenario API; use `create` + `watch` and set decisions in the portal.")
        return 2

    failures = 0
    for scenario in scenarios:
        for _ in range(args.repeat):
            want = expected_status(scenario)
            t0 = time.perf_counter()
            try:
                s = vendor.create_session(new_reference(), scenario=scenario)
                results.record(out, "session_created", latency_ms=_ms(t0), scenario=scenario, **s.public())
                vendor.simulate(s.session_id, scenario)
                d, waited = poll_until_terminal(vendor, s.session_id, out, args.timeout, args.interval)
            except (VendorError, NotImplementedError) as exc:
                failures += 1
                _record_error(out, vendor.name, f"bench:{scenario}", exc)
                print(f"{scenario:38} ERROR  {exc}")
                continue
            got = d.status if d else Status.UNKNOWN
            match = got == want
            failures += not match
            results.record(out, "scenario_run", vendor=vendor.name, scenario=scenario,
                           session_id=s.session_id, expected=want.value, actual=got.value,
                           match=match, risks=d.risks if d else [],
                           seconds_to_decision=round(waited, 1))
            mark = "ok " if match else "MISMATCH"
            print(f"{scenario:38} {mark:8} expected={want.value:9} got={got.value:9} "
                  f"risks={','.join(d.risks) if d else '-'}")
    print(f"\n{failures} problem(s). Run `python -m kyc_poc summary` for the table.")
    return 0 if failures == 0 else 1


def cmd_summary(args) -> int:
    out = results_dir()
    md = results.summarize(results.load(out))
    path = os.path.join(out, "summary.md")
    os.makedirs(out, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
    print(md)
    print(f"written to {path}")
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    from .webhooks import create_app

    vendors = configured_vendors()
    if not vendors:
        print("No vendor credentials found in .env", file=sys.stderr)
        return 1
    for name, v in vendors.items():
        if name == "didit" and not getattr(v, "webhook_secret", None):
            print("warning: DIDIT_WEBHOOK_SECRET is empty, Didit webhooks will be rejected")
    uvicorn.run(create_app(vendors, results_dir()), host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m kyc_poc", description="KYC vendor proof-of-concept")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("create", help="create a hosted verification session")
    c.add_argument("vendor", choices=VENDORS)
    c.add_argument("--scenario", help="sandbox scenario slug (Didit only)")
    c.add_argument("--reference", help="your own opaque reference (default: random)")
    c.add_argument("--callback", help="URL the user returns to after the flow")
    c.set_defaults(func=cmd_create)

    d = sub.add_parser("decision", help="fetch the current decision once")
    d.add_argument("vendor", choices=VENDORS)
    d.add_argument("session_id")
    d.set_defaults(func=cmd_decision)

    w = sub.add_parser("watch", help="poll until a final decision arrives")
    w.add_argument("vendor", choices=VENDORS)
    w.add_argument("session_id")
    w.add_argument("--timeout", type=float, default=900)
    w.add_argument("--interval", type=float, default=5)
    w.set_defaults(func=cmd_watch)

    b = sub.add_parser("bench", help="run a sandbox scenario matrix (Didit)")
    b.add_argument("vendor", choices=VENDORS)
    b.add_argument("--scenarios", default=",".join(DEFAULT_DIDIT_SCENARIOS))
    b.add_argument("--repeat", type=int, default=1)
    b.add_argument("--timeout", type=float, default=60)
    b.add_argument("--interval", type=float, default=2)
    b.set_defaults(func=cmd_bench)

    s = sub.add_parser("summary", help="write results/summary.md from the run log")
    s.set_defaults(func=cmd_summary)

    sv = sub.add_parser("serve", help="run the webhook receiver")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
