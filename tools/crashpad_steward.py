# SPDX-License-Identifier: Apache-2.0
"""Read-only, fail-closed SZL Edge Crashpad health monitor.

Crashpad reports may be PENDING or COMPLETED. File name, age and unlocked
state do NOT prove disposal authorization. No dump bytes or metadata contents
are ever opened. This module has NO deletion capability.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import stat
import sys
import time
from pathlib import Path

PROFILE = Path(r"C:\SZL\edge-cdp-profile-ops")
SCHEMA = "szl.crashpad-readonly-health/v2"
UUID_DMP = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\.dmp$")
REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
FREE_FLOOR = 50 * 1024**3
MAX_ENTRIES = 150000


class Hold(Exception):
    pass


def _unsafe(info):
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & REPARSE
    )


def _profile(root):
    if not root.is_absolute():
        raise Hold("PROFILE_NOT_ABSOLUTE")
    folder = root / "Crashpad" / "reports"
    for path in (*reversed(root.parents), root, root / "Crashpad", folder):
        try:
            st = path.lstat()
        except OSError as exc:
            raise Hold("PATH_UNAVAILABLE") from exc
        if _unsafe(st) or not stat.S_ISDIR(st.st_mode):
            raise Hold("REPARSE_OR_INVALID_DIRECTORY")
    for path, expected in ((root / "Default", stat.S_ISDIR),
                           (root / "Local State", stat.S_ISREG),
                           (root / "Crashpad" / "metadata", stat.S_ISREG)):
        try:
            st = path.lstat()
        except OSError as exc:
            raise Hold("PROFILE_OR_DATABASE_UNAVAILABLE") from exc
        if _unsafe(st) or not expected(st.st_mode):
            raise Hold("PROFILE_OR_DATABASE_INVALID")
    if (root / ".git").exists() or (root / ".git").is_symlink():
        raise Hold("GIT_TREE_PROTECTED")
    db = (root / "Crashpad" / "metadata").lstat()
    return folder, db.st_size


def _snapshot(root, folder):
    now_ns = time.time_ns()
    files = 0
    size_bytes = 0
    recent = 0
    unclassified = 0
    scanned = 0
    with os.scandir(folder) as it:
        for row in it:
            scanned += 1
            if scanned > MAX_ENTRIES:
                raise Hold("SCAN_BUDGET_EXCEEDED")
            if not UUID_DMP.fullmatch(row.name):
                unclassified += 1
                continue
            try:
                st = os.lstat(row.path)
            except OSError as exc:
                raise Hold("FILE_STAT_UNAVAILABLE") from exc
            if _unsafe(st) or not stat.S_ISREG(st.st_mode):
                unclassified += 1
                continue
            files += 1
            size_bytes += st.st_size
            if st.st_mtime_ns >= now_ns - 600 * 10**9:
                recent += 1
    disk = shutil.disk_usage(root)
    return {
        "utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "drive_total_bytes": disk.total,
        "drive_free_bytes": disk.free,
        "uuid_dmp_count": files,
        "uuid_dmp_bytes": size_bytes,
        "reports_last_10min": recent,
        "unclassified_entries": unclassified,
        "reports_pending_or_completed_unknown": files,
        "verified_completed_count": 0,
        "disposable_count": 0,
    }


def observe(root=PROFILE, *, sample_count=3, interval_seconds=2):
    result = {
        "schema": SCHEMA,
        "operation": "READ_ONLY",
        "status": "HOLD",
        "deletion_authorized": False,
        "database_states_verified": False,
        "private_dump_contents_read": False,
        "command_lines_read": False,
    }
    try:
        if not 1 <= sample_count <= 5 or not 0 <= interval_seconds <= 10:
            raise Hold("INVALID_SAMPLE_BOUNDS")
        folder, database_bytes = _profile(Path(root))
        result["crashpad_metadata_bytes"] = database_bytes
        readings = []
        for i in range(sample_count):
            readings.append(_snapshot(Path(root), folder))
            if i + 1 < sample_count:
                time.sleep(interval_seconds)
        result["readings"] = readings
        result["drive_free_delta_bytes"] = (
            readings[-1]["drive_free_bytes"] - readings[0]["drive_free_bytes"]
        )
        result["report_count_delta"] = (
            readings[-1]["uuid_dmp_count"] - readings[0]["uuid_dmp_count"]
        )
        result["below_50_gib"] = readings[-1]["drive_free_bytes"] < FREE_FLOOR
        result["rapid_crash_reports"] = (
            readings[-1]["reports_last_10min"] >= 30
            or result["report_count_delta"] > 3
        )
        result["status"] = (
            "ALERT" if result["below_50_gib"] or result["rapid_crash_reports"]
            else "READ_ONLY_OBSERVED"
        )
    except (Hold, OSError) as exc:
        result["reason_code"] = (
            str(exc) if isinstance(exc, Hold) else "FILESYSTEM_UNAVAILABLE"
        )
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Safe read-only Crashpad monitor")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dry-run", action="store_true")
    group.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if args.execute:
        print(json.dumps({
            "schema": SCHEMA, "status": "HOLD", "operation": "NONE",
            "deletion_authorized": False,
            "reason_code": "CRASHPAD_DB_STATE_UNVERIFIED",
        }, sort_keys=True))
        return 2
    data = observe()
    print(json.dumps(data, sort_keys=True, separators=(",", ":")))
    return 2 if data["status"] == "HOLD" else 0


if __name__ == "__main__":
    sys.exit(main())
