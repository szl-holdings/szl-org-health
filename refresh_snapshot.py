#!/usr/bin/env python3
"""Refresh the static org-health snapshot (static/data.json).

Runs the same collectors as the live backend and writes a fresh, timestamped
snapshot so a statically-served dashboard never goes stale. Intended to be run
on a schedule (e.g. once daily) or manually.

Usage:
    python3 refresh_snapshot.py            # writes ./static/data.json
    python3 refresh_snapshot.py --stdout   # also prints the JSON

Needs a GitHub token on the environment for the GitHub source (via the credential
proxy in the SZL sandbox); HF + DNS reads are public. Honesty preserved: any source
that can't be read is written as UNKNOWN, never fabricated.
"""
import json
import os
import signal
import sys

# Reuse the exact collectors from the backend so snapshot == live semantics.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app  # noqa: E402
from app import build_report  # noqa: E402

# Hard overall deadline (seconds). A scheduled refresh must never hang; if the
# GitHub proxy is slow we bound the whole run and write whatever was collected.
DEADLINE_S = int(os.environ.get("REFRESH_DEADLINE_S", "120"))


def _timeout(_sig, _frame):
    raise TimeoutError(f"refresh exceeded {DEADLINE_S}s deadline")


def main() -> int:
    # Tighten per-request timeouts + retries and skip the heavy per-repo
    # protection probe so the scheduled run stays inside the deadline.
    app._GH_TIMEOUT_OVERRIDE = 8.0  # noqa: SLF001
    app.FAST_MODE = True
    app._CACHE = {"data": None, "ts": 0.0}  # force a fresh pull, ignore 60s cache
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(DEADLINE_S)
    try:
        report = build_report()
    except TimeoutError as e:
        print(f"WARN: {e} — writing no snapshot this run (keeping prior)", file=sys.stderr)
        return 2
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "data.json")
    with open(out_path, "w") as f:
        json.dump(report, f, separators=(",", ":"))
    ok = {k: v.get("ok") for k, v in report.get("sources", {}).items()}
    print(f"snapshot written: {out_path}")
    print(f"generated_at: {report.get('generated_at')}  sources_ok: {ok}")
    if "--stdout" in sys.argv:
        print(json.dumps(report, indent=2))
    # Non-zero exit if every source failed — lets a scheduler detect a bad run.
    return 0 if any(ok.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
