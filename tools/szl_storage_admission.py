# SPDX-License-Identifier: Apache-2.0
"""Fail-closed, read-only local capacity admission for declared SZL build budgets.

Examples:
  python -I tools/szl_storage_admission.py --mode observe --drive C:/
  python -I tools/szl_storage_admission.py --mode admit --drive C:/ --reserve-gib 8

This tool NEVER deletes files, launches jobs, creates reservations, or changes
Windows settings. It is a preflight gate, not an atomic multi-agent scheduler.
Concurrent writers can consume space immediately after a green observation.
"""
from __future__ import annotations

import argparse
import datetime as dt
from decimal import Decimal, ROUND_CEILING
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import time
from typing import Callable

SCHEMA = "szl.local.capacity-admission/v1"
DOMAIN = b"szl.local.capacity-admission/v1\x00"
GIB = 1024**3
_NUMERIC = re.compile(r"(?:0|[1-9][0-9]{0,3})(?:\.[0-9]{1,3})?\Z")
MAX_BUDGET_GIB = Decimal("4096")
MAX_SAMPLE_SECONDS = 10


class AdmissionInputError(ValueError):
    """Reject unknown, unbounded, or ambiguous inputs without assuming safety."""


def gib_bytes(raw: str, *, can_be_zero: bool) -> int:
    """Exact binary GiB budget with <= 3 decimals; no NaN/inf/exponents/signs."""
    if type(raw) is not str or _NUMERIC.fullmatch(raw) is None:
        raise AdmissionInputError("BUDGET_NUMBER_INVALID")
    value = Decimal(raw)
    if value > MAX_BUDGET_GIB or (not can_be_zero and value == 0):
        raise AdmissionInputError("BUDGET_BOUND_INVALID")
    return int((value * GIB).to_integral_value(rounding=ROUND_CEILING))


def _usage_bytes(usage: object) -> tuple[int, int, int]:
    try:
        total, used, free = usage.total, usage.used, usage.free
    except AttributeError as exc:
        raise AdmissionInputError("DISK_OBSERVATION_MALFORMED") from exc
    if any(type(v) is not int or v < 0 for v in (total, used, free)):
        raise AdmissionInputError("DISK_OBSERVATION_MALFORMED")
    # POSIX filesystems can reserve blocks not counted as user-available
    # free space. Accept total > used + free, but never a sum > total.
    if total == 0 or used + free > total:
        raise AdmissionInputError("DISK_GEOMETRY_INCONSISTENT")
    return total, used, free


def _rounded_gib(n: int) -> float:
    return round(n / GIB, 3)


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _receipt(core: dict) -> dict:
    return {**core, "sha256": hashlib.sha256(DOMAIN + _canonical(core)).hexdigest()}


def _source_digest() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _timestamp(now: dt.datetime | None = None) -> str:
    if now is None:
        now = dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise AdmissionInputError("UTC_TIME_REQUIRED")
    return now.astimezone(dt.timezone.utc).isoformat()


def observe(
    *,
    drive: str,
    mode: str,
    reserve_gib: str | None = None,
    floor_gib: str = "50",
    critical_gib: str = "20",
    sample_seconds: int = 2,
    disk_reader: Callable[[str], object] = shutil.disk_usage,
    sleeper: Callable[[float], object] = time.sleep,
    clock: Callable[[], dt.datetime] | None = None,
    source_digest: str | None = None,
) -> dict:
    """Observe twice and gate against the *minimum* measured free space.

    Caller-supplied budget is a declaration, not locked space. Two observations
    detect short-term depletion but cannot predict unknown concurrent writers.
    """
    if type(drive) is not str or not drive.strip() or "\x00" in drive:
        raise AdmissionInputError("DRIVE_INVALID")
    if mode not in ("observe", "admit") or type(mode) is not str:
        raise AdmissionInputError("MODE_INVALID")
    if type(sample_seconds) is not int or not 0 <= sample_seconds <= MAX_SAMPLE_SECONDS:
        raise AdmissionInputError("SAMPLE_WINDOW_INVALID")
    floor_bytes = gib_bytes(floor_gib, can_be_zero=False)
    critical_bytes = gib_bytes(critical_gib, can_be_zero=False)
    if floor_bytes <= critical_bytes:
        raise AdmissionInputError("FLOOR_MUST_EXCEED_CRITICAL")
    if mode == "admit":
        if reserve_gib is None:
            raise AdmissionInputError("DECLARED_JOB_BUDGET_REQUIRED")
        budget_bytes = gib_bytes(reserve_gib, can_be_zero=False)
    else:
        if reserve_gib is not None:
            raise AdmissionInputError("OBSERVATION_MUST_NOT_DECLARE_JOB")
        budget_bytes = 0

    observed = []
    unavailable_reserved = []
    total = None
    for i in range(2 if sample_seconds else 1):
        if i:
            sleeper(sample_seconds)
        try:
            t, _used, free = _usage_bytes(disk_reader(drive))
        except AdmissionInputError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise AdmissionInputError("DISK_OBSERVATION_UNAVAILABLE") from exc
        if total is not None and t != total:
            raise AdmissionInputError("DISK_GEOMETRY_CHANGED")
        total = t
        observed.append(free)
        unavailable_reserved.append(t - _used - free)

    assert total is not None
    minimum = min(observed)
    projected = minimum - budget_bytes
    if minimum < critical_bytes:
        state = "CRITICAL"
    elif minimum < floor_bytes:
        state = "CONSTRAINED"
    else:
        state = "CAPACITY_OK"
    if mode == "observe":
        decision = "NOT_REQUESTED"
        reason = "READ_ONLY_OBSERVATION"
    elif state == "CRITICAL":
        decision, reason = "HOLD", "CRITICAL_FREE_SPACE"
    elif state == "CONSTRAINED":
        decision, reason = "HOLD", "BELOW_REQUIRED_HEADROOM"
    elif projected < floor_bytes:
        decision, reason = "HOLD", "DECLARED_BUDGET_BREACHES_HEADROOM"
    else:
        decision, reason = "ADMIT_PRECHECK_ONLY", "DECLARED_BUDGET_FITS_MEASURED_HEADROOM"

    core = {
        "schema": SCHEMA,
        "timestamp_utc": _timestamp(clock() if clock else None),
        "drive": drive,
        "mode": mode,
        "measurement_source": "LOCAL_OS_SHUTIL_DISK_USAGE",
        "sample_seconds": sample_seconds,
        "observations": len(observed),
        "total_bytes": total,
        "observed_free_bytes": observed,
        "filesystem_unavailable_reserved_bytes": unavailable_reserved,
        "min_free_bytes": minimum,
        "measured_free_gib": _rounded_gib(minimum),
        "floor_bytes": floor_bytes,
        "critical_bytes": critical_bytes,
        "declared_budget_bytes": budget_bytes,
        "min_post_budget_free_bytes": projected,
        "min_post_budget_free_gib": _rounded_gib(projected),
        "observed_drop_bytes": max(0, observed[0] - observed[-1]),
        "capacity_state": state,
        "decision": decision,
        "reason": reason,
        "implementation_sha256": source_digest if source_digest is not None else _source_digest(),
        "automatic_deletion": False,
        "lease_or_reservation_established": False,
        "concurrent_writer_exclusion_established": False,
        "future_capacity_guaranteed": False,
        "remote_production_readiness_established": False,
        "signature_verified": False,
    }
    return _receipt(core)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("observe", "admit"))
    parser.add_argument("--drive", required=True)
    parser.add_argument("--reserve-gib", help="Declared maximum additional job disk consumption; required for admit.")
    parser.add_argument("--floor-gib", default="50", help="Minimum post-job headroom (default: 50 GiB).")
    parser.add_argument("--critical-gib", default="20", help="Critical capacity threshold (default: 20 GiB).")
    parser.add_argument("--sample-seconds", type=int, default=2,
                        help="Time between two samples (default: 2, maximum: 10).")
    args = parser.parse_args(argv)
    try:
        report = observe(
            drive=args.drive,
            mode=args.mode,
            reserve_gib=args.reserve_gib,
            floor_gib=args.floor_gib,
            critical_gib=args.critical_gib,
            sample_seconds=args.sample_seconds,
        )
    except AdmissionInputError as exc:
        print(json.dumps({
            "schema": SCHEMA, "decision": "HOLD",
            "reason": str(exc), "measurement_valid": False,
            "automatic_deletion": False,
            "lease_or_reservation_established": False,
        }, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    if args.mode == "admit" and report["decision"] != "ADMIT_PRECHECK_ONLY":
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
