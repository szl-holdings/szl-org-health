# SPDX-License-Identifier: Apache-2.0
"""Bounded SZL Edge Crashpad stewardship. Does not touch user/source/model data.

Scope is fixed at a known SZL automation browser profile. Dump bytes are NEVER read.
The tool is intentionally incapable of removing a directory, arbitrary path,
worktree, source revision, model, signed receipt, or non-UUID diagnostic file.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import NamedTuple

PROFILE = Path(r"C:\SZL\edge-cdp-profile-ops")
EVIDENCE = Path(r"C:\SZL\EstateOps\disk-hygiene")
UUID_DMP = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\.dmp$")
MIN_AGE_SECONDS = 30 * 60
MIN_KEEP = 200
MAX_PER_RUN = 2000
MIN_BYTES = 1025
MAX_BYTES = 10 * 1024 * 1024
FREE_FLOOR_BYTES = 50 * 1024**3
REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
SCHEMA = "szl.crashpad-scoped-steward/v1"


class GuardError(Exception):
    """A precondition failure: no cleanup should occur."""


class Candidate(NamedTuple):
    name: str
    size: int
    mtime_ns: int
    inode: int
    device: int


def _is_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & REPARSE
    )


def validate_profile(root: Path) -> Path:
    """Validate each path segment, not just a resolved final path."""
    root = Path(root)
    if not root.is_absolute():
        raise GuardError("PROFILE_NOT_ABSOLUTE")
    for path in (*reversed(root.parents), root, root / "Crashpad", root / "Crashpad" / "reports"):
        try:
            info = path.lstat()
        except OSError as exc:
            raise GuardError("PATH_UNAVAILABLE") from exc
        if _is_reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise GuardError("REPARSE_OR_NON_DIRECTORY")
    if not (root / "Local State").is_file() or not (root / "Default").is_dir():
        raise GuardError("BROWSER_PROFILE_NOT_PROVEN")
    if (root / ".git").exists():
        raise GuardError("GIT_TREE_PROTECTED")
    return root / "Crashpad" / "reports"


def _regular(entry: os.DirEntry[str]) -> os.stat_result | None:
    try:
        # Windows DirEntry.stat may report st_ino=st_dev=0, unlike lstat.
        # Use the same identity source as the pre-unlink recheck.
        info = os.lstat(entry.path)
    except OSError:
        return None
    if _is_reparse(info) or not stat.S_ISREG(info.st_mode):
        return None
    return info


def inventory(reports: Path, *, now_ns: int) -> dict:
    cutoff = now_ns - MIN_AGE_SECONDS * 10**9
    raw = []
    ignored = 0
    recent = 0
    inspected = 0
    for entry in os.scandir(reports):
        inspected += 1
        if not UUID_DMP.fullmatch(entry.name):
            ignored += 1
            continue
        info = _regular(entry)
        if info is None or info.st_size < MIN_BYTES or info.st_size > MAX_BYTES:
            ignored += 1
            continue
        raw.append(Candidate(entry.name, info.st_size, info.st_mtime_ns,
                             info.st_ino, info.st_dev))
        if info.st_mtime_ns > now_ns - (20 * 60 * 10**9):
            recent += 1
    newest = sorted(raw, key=lambda x: (x.mtime_ns, x.name), reverse=True)
    protected = {x.name for x in newest[:MIN_KEEP]}
    eligible = sorted(
        (x for x in raw if x.name not in protected and x.mtime_ns < cutoff),
        key=lambda x: (x.mtime_ns, x.name),
    )[:MAX_PER_RUN]
    return {
        "all_items": inspected,
        "generated_dump_count": len(raw),
        "ignored_items": ignored,
        "last_20m_count": recent,
        "eligible": eligible,
        "eligible_bytes": sum(x.size for x in eligible),
        "oldest_protected_count": min(MIN_KEEP, len(raw)),
        "retention_seconds": MIN_AGE_SECONDS,
    }


def _exclusive_read_attrs(path: Path) -> bool:
    """Probe completed Windows dumps without reading their contents."""
    if os.name != "nt":
        return False
    fn = ctypes.windll.kernel32.CreateFileW
    fn.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                   ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                   ctypes.c_void_p]
    fn.restype = ctypes.c_void_p
    h = fn(str(path), 0x80, 0, None, 3, 0x00200000, None)
    if h in (None, ctypes.c_void_p(-1).value):
        return False
    close = ctypes.windll.kernel32.CloseHandle
    close.argtypes = [ctypes.c_void_p]
    close.restype = ctypes.c_int
    return bool(close(h))


@contextmanager
def _exclusive_steward_lock(path: Path):
    """Windows byte-range lock: lock exits automatically on process failure."""
    if os.name != "nt":
        raise GuardError("WINDOWS_DEVICE_REQUIRED")
    import msvcrt
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_BINARY | os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"0")
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            raise GuardError("CONCURRENT_STEWARD_ALREADY_ACTIVE") from exc
        try:
            yield
        finally:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    finally:
        os.close(fd)


def cleanup_candidate(reports: Path, item: Candidate, *, now_ns: int) -> str:
    """Reverify identity and exclusive access immediately before unlink."""
    if not UUID_DMP.fullmatch(item.name):
        return "INELIGIBLE"
    path = reports / item.name
    try:
        info = path.lstat()
    except OSError:
        return "CHANGED"
    if (_is_reparse(info) or not stat.S_ISREG(info.st_mode) or
            info.st_size != item.size or info.st_mtime_ns != item.mtime_ns or
            info.st_ino != item.inode or info.st_dev != item.device or
            info.st_mtime_ns > now_ns - MIN_AGE_SECONDS * 10**9):
        return "CHANGED"
    if not _exclusive_read_attrs(path):
        return "LOCKED"
    try:
        # No recursive deletion. Never follow directories or junctions.
        path.unlink()
    except OSError:
        return "LOCKED"
    return "REMOVED" if not path.exists() else "FAILED"


def measure_drive(root: Path = PROFILE) -> dict:
    # Production is fixed to C:. Non-Windows unit tests can use a temp root.
    d = shutil.disk_usage("C:\\" if os.name == "nt" else root)
    return {"total_bytes": d.total, "free_bytes": d.free}


def write_receipt(root: Path, body: dict) -> Path:
    """Unsigned telemetry, never replace an existing receipt."""
    day = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    directory = root / day
    directory.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    file = directory / ("crashpad-steward-" + stamp + ".json")
    data = (json.dumps(body, sort_keys=True, indent=2) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(str(file), flags, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return file


def run_once(*, execute: bool, root: Path = PROFILE,
             evidence: Path = EVIDENCE,
             free_floor_bytes: int = FREE_FLOOR_BYTES,
             now_ns: int | None = None) -> tuple[int, dict]:
    start_utc = dt.datetime.now(dt.timezone.utc).isoformat()
    info = {"schema": SCHEMA, "utc": start_utc, "mode": "EXECUTE" if execute else "DRY_RUN",
            "status": "HOLD", "deletion_authorized_for_other_files": False,
            "deleted_source_repos": False, "touched_models": False,
            "touched_user_documents": False, "touched_live_processes": False}
    try:
        reports = validate_profile(root)
        before = measure_drive(root)
        info["free_before_bytes"] = before["free_bytes"]
        info["total_bytes"] = before["total_bytes"]
        now_ns = now_ns if now_ns is not None else time.time_ns()
        scan = inventory(reports, now_ns=now_ns)
        info.update({key: val for key, val in scan.items() if key != "eligible"})
        info["eligible_count"] = len(scan["eligible"])
        info["scope"] = str(reports)
        info["min_keep"] = MIN_KEEP
        info["max_per_run"] = MAX_PER_RUN
        info["capability"] = "GUID_DMP_ONLY"
        info["potential_crash_loop"] = scan["last_20m_count"] >= 30
        if not execute:
            info["status"] = "DRY_RUN_ONLY"
            return 0, info
        if before["free_bytes"] >= free_floor_bytes:
            info["status"] = "NO_CLEANUP_NEEDED"
            return 0, info
        if not scan["eligible"]:
            info["status"] = "NO_ELIGIBLE_GENERATED_REPORTS"
            return 0, info
        removed = 0
        expected = 0
        skipped = {"LOCKED": 0, "CHANGED": 0, "INELIGIBLE": 0, "FAILED": 0}
        with _exclusive_steward_lock(evidence / "crashpad-steward.lock"):
            # Race check: never act on a changed folder, new reparse point, or
            # new admission. Re-inventory after acquiring exclusive steward lock.
            reports = validate_profile(root)
            confirm = inventory(reports, now_ns=time.time_ns())
            keep = {x.name for x in confirm["eligible"]}
            planned = [x for x in scan["eligible"] if x.name in keep]
            plan_digest = hashlib.sha256()
            for item in planned:
                plan_digest.update(f"{item.name}|{item.size}|{item.mtime_ns}\n".encode("ascii"))
            intent = {"schema": SCHEMA, "utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                      "status": "UNSIGNED_PREPARED_INTENT", "scope": str(reports),
                      "candidate_count": len(planned), "candidate_bytes": sum(x.size for x in planned),
                      "candidate_metadata_sha256": plan_digest.hexdigest(),
                      "min_keep": MIN_KEEP, "max_per_run": MAX_PER_RUN,
                      "no_user_source_or_model_deletion": True}
            # Write-ahead receipt: no deletion if preparation cannot be persisted.
            info["prepare_receipt"] = str(write_receipt(evidence, intent))
            for item in scan["eligible"]:
                if item.name not in keep:
                    skipped["CHANGED"] += 1
                    continue
                if measure_drive(root)["free_bytes"] >= free_floor_bytes:
                    break
                state = cleanup_candidate(reports, item, now_ns=time.time_ns())
                if state == "REMOVED":
                    removed += 1
                    expected += item.size
                else:
                    skipped[state] = skipped.get(state, 0) + 1
        after = measure_drive(root)
        info["status"] = "BOUNDED_CLEANUP_COMPLETED" if removed else "NO_SAFE_REMOVAL"
        info["removed_count"] = removed
        info["expected_removed_bytes"] = expected
        info["free_after_bytes"] = after["free_bytes"]
        info["observed_free_delta_bytes"] = after["free_bytes"] - before["free_bytes"]
        info["skipped"] = skipped
        info["remaining_report_count"] = inventory(reports, now_ns=time.time_ns())["generated_dump_count"]
        info["receipt"] = str(write_receipt(evidence, info))
        return 0, info
    except (GuardError, OSError) as exc:
        info["error_code"] = str(exc) if isinstance(exc, GuardError) else "FILESYSTEM_OR_ACCESS_FAILURE"
        return 2, info


def main() -> int:
    parser = argparse.ArgumentParser(description="SZL Crashpad diagnostic-file safety steward")
    flags = parser.add_mutually_exclusive_group()
    flags.add_argument("--execute", action="store_true", help="Delete only eligible generated UUID .dmp")
    flags.add_argument("--dry-run", action="store_true", help="Only inventory")
    opts = parser.parse_args()
    exit_code, result = run_once(execute=opts.execute)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())