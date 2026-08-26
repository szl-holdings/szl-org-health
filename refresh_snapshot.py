#!/usr/bin/env python3
"""Refresh public and internal org-health evidence snapshots.

Runs the same collectors as the live backend once, derives the public projection
from that exact internal report, writes it to ``static/data.json``, and keeps the
full evidence view in ignored ``census-internal.json`` only for the receipt gate.

Usage:
    python3 refresh_snapshot.py            # writes both evidence views
    python3 refresh_snapshot.py --stdout   # also prints public JSON only

Credential-derived private evidence is never printed or written to the public
snapshot. Any source that cannot be read remains UNKNOWN, never fabricated.
"""

import json
import os
import signal
import sys
import tempfile
from pathlib import Path

# Reuse the exact collectors from the backend so snapshot == live semantics.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from census.report import (
    build_report,
    project_public_report,
    serialize_report,
)

# Hard collection deadline (seconds). A scheduled refresh must never hang or
# publish a partial replacement after the deadline.
DEADLINE_S = int(os.environ.get("REFRESH_DEADLINE_S", "120"))
ROOT = Path(__file__).resolve().parent
PUBLIC_SNAPSHOT = ROOT / "static" / "data.json"
INTERNAL_SNAPSHOT = ROOT / "census-internal.json"


def _timeout(_sig, _frame):
    raise TimeoutError(f"refresh exceeded {DEADLINE_S}s deadline")


def _stage_snapshot(path: Path, payload: str) -> Path:
    """Durably stage one payload beside its destination for atomic replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115 - enter after recording path
        mode="w",
        encoding="utf-8",
        newline="\n",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    staged = Path(handle.name)
    try:
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    return staged


def _replace_snapshots(internal_payload: str, public_payload: str) -> None:
    """Stage both serialized views, then atomically replace each destination."""
    staged_internal: Path | None = None
    staged_public: Path | None = None
    try:
        staged_internal = _stage_snapshot(INTERNAL_SNAPSHOT, internal_payload)
        staged_public = _stage_snapshot(PUBLIC_SNAPSHOT, public_payload)
        os.replace(staged_internal, INTERNAL_SNAPSHOT)
        staged_internal = None
        os.replace(staged_public, PUBLIC_SNAPSHOT)
        staged_public = None
    finally:
        if staged_internal is not None:
            staged_internal.unlink(missing_ok=True)
        if staged_public is not None:
            staged_public.unlink(missing_ok=True)


def main() -> int:
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _timeout)
        signal.alarm(DEADLINE_S)
    try:
        # Use real collector parameters rather than mutating no-op module
        # globals. Protection is explicitly UNKNOWN in bounded snapshot mode.
        internal_report = build_report(
            exposure="internal",
            use_cache=False,
            github_timeout=8.0,
            github_retries=1,
            include_branch_protection=False,
        )
        public_report = project_public_report(internal_report)
    except TimeoutError as e:
        print(
            f"WARN: {e} — writing no snapshot this run (keeping prior)", file=sys.stderr
        )
        return 2
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
    serialized_internal = serialize_report(internal_report)
    serialized_public = serialize_report(public_report)
    _replace_snapshots(serialized_internal, serialized_public)

    ok = {
        name: source.get("ok")
        for name, source in internal_report.get("sources", {}).items()
    }
    print(f"public snapshot written: {PUBLIC_SNAPSHOT}")
    print(f"generated_at: {internal_report.get('generated_at')}  sources_ok: {ok}")
    if "--stdout" in sys.argv:
        print(json.dumps(public_report, indent=2))
    # Non-zero exit if every source failed — lets a scheduler detect a bad run.
    return 0 if any(ok.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
