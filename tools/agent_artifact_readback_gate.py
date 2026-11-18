# SPDX-License-Identifier: Apache-2.0
"""Bounded, read-only artifact-copy verification. NEVER authorizes deletion.

The input manifest is untrusted. Verifying bytes is not verifying provenance,
retention, ownership, active agent claims, or archive durability.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "szl.agent-artifact-readback/v1"
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_FILES = 1000
DEFAULT_READ_BUDGET = 256 * 1024 * 1024
CHUNK = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PROTECTED_COMPONENTS = frozenset({
    ".git", ".ssh", ".aws", ".cache", "appdata", "onedrive",
    "huggingface", "models", "model_weights", "weights",
    "secrets", "private_keys", "credentials", "tokens",
})


class GateError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _read_json_unique(raw: bytes) -> dict[str, Any]:
    def object_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in pairs:
            if key in obj:
                raise GateError("DUPLICATE_JSON_KEY")
            obj[key] = value
        return obj

    if len(raw) > MAX_MANIFEST_BYTES:
        raise GateError("MANIFEST_TOO_LARGE")
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=object_hook)
    except (UnicodeError, ValueError) as exc:
        raise GateError("INVALID_MANIFEST_JSON") from exc
    if not isinstance(result, dict):
        raise GateError("INVALID_MANIFEST_SHAPE")
    return result


def _relative(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or len(value) > 500:
        raise GateError("INVALID_RELATIVE_PATH")
    if "\\" in value or ":" in value or "\x00" in value or any(ord(c) < 32 for c in value):
        raise GateError("INVALID_RELATIVE_PATH")
    raw_parts = value.split("/")
    if any(p in ("", ".", "..") for p in raw_parts) or value.startswith("/"):
        raise GateError("INVALID_RELATIVE_PATH")
    parts = PurePosixPath(value).parts
    if len(parts) != len(raw_parts):
        raise GateError("INVALID_RELATIVE_PATH")
    if any(p.casefold() in PROTECTED_COMPONENTS for p in parts):
        raise GateError("PROTECTED_PATH")
    return parts


def _check_not_reparse(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise GateError("PATH_UNAVAILABLE") from exc
    flags = getattr(info, "st_file_attributes", 0)
    if stat.S_ISLNK(info.st_mode) or (flags & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
        raise GateError("REPARSE_OR_SYMLINK")
    return info


def _checked_root(root: Path) -> Path:
    if not root.is_absolute():
        raise GateError("ROOT_NOT_ABSOLUTE")
    for entry in (*reversed(root.parents), root):
        _check_not_reparse(entry)
    if not root.is_dir():
        raise GateError("ROOT_NOT_DIRECTORY")
    return root.resolve(strict=True)


def _checked_file(root: Path, parts: tuple[str, ...]) -> tuple[Path, os.stat_result]:
    path = root
    for part in parts:
        path = path / part
        _check_not_reparse(path)
    details = _check_not_reparse(path)
    if not stat.S_ISREG(details.st_mode):
        raise GateError("NOT_REGULAR_FILE")
    return path, details


def _hash_file(path: Path, before: os.stat_result, budget: int) -> tuple[int, str, os.stat_result]:
    if before.st_size < 0 or before.st_size > budget:
        raise GateError("FILE_EXCEEDS_READ_BUDGET")
    hasher = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as file:
            opened = os.fstat(file.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
            ):
                raise GateError("FILE_CHANGED_DURING_READ")
            total = 0
            while True:
                block = file.read(min(CHUNK, budget - total + 1))
                if not block:
                    break
                total += len(block)
                if total > budget:
                    raise GateError("FILE_EXCEEDS_READ_BUDGET")
                hasher.update(block)
            end = os.fstat(file.fileno())
    except OSError as exc:
        raise GateError("FILE_READ_FAILED") from exc
    after = _check_not_reparse(path)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns
    ) or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ) or total != before.st_size:
        raise GateError("FILE_CHANGED_DURING_READ")
    return total, hasher.hexdigest(), after


def evaluate(manifest: dict[str, Any], source_root: Path, copy_root: Path,
             *, read_budget: int = DEFAULT_READ_BUDGET) -> dict[str, Any]:
    """Inspect bytes only. Never changes files, treats age as proof, or permits cleanup."""
    summary: dict[str, Any] = {
        "schema": SCHEMA, "status": "HOLD", "deletion_authorized": False,
        "copy_verified": 0, "item_count": 0, "rows": [],
        "limitations": ["COPY_DURABILITY_UNPROVEN", "SIGNATURE_UNVERIFIED",
                        "LIVE_AGENT_CLAIMS_UNVERIFIED", "RETENTION_APPROVAL_UNVERIFIED"],
    }
    try:
        if not isinstance(read_budget, int) or isinstance(read_budget, bool) or read_budget < 1:
            raise GateError("INVALID_READ_BUDGET")
        if manifest.get("schema") != SCHEMA:
            raise GateError("SCHEMA_MISMATCH")
        items = manifest.get("artifacts")
        if not isinstance(items, list) or not 1 <= len(items) <= MAX_FILES:
            raise GateError("INVALID_ARTIFACT_COUNT")
        source = _checked_root(source_root)
        copy = _checked_root(copy_root)
        if (source == copy or source in copy.parents or copy in source.parents):
            raise GateError("ROOTS_NOT_SEPARATE")
        summary["item_count"] = len(items)
        seen: set[str] = set()
        remaining = read_budget
        for item in items:
            # The entire batch stays on HOLD if ANY row is malformed or missing.
            if not isinstance(item, dict):
                raise GateError("INVALID_ITEM")
            parts = _relative(item.get("relative_path"))
            copy_parts = _relative(item.get("copy_relative_path"))
            identity = "/".join(parts).casefold()
            if identity in seen:
                raise GateError("DUPLICATE_ARTIFACT_PATH")
            seen.add(identity)
            digest = item.get("sha256")
            size = item.get("size_bytes")
            owner = item.get("owner")
            evidence_id = item.get("evidence_id")
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
                raise GateError("INVALID_SHA256")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise GateError("INVALID_SIZE")
            if not isinstance(owner, str) or not owner.strip() or len(owner) > 200:
                raise GateError("OWNERSHIP_UNDECLARED")
            if not isinstance(evidence_id, str) or not evidence_id.strip() or len(evidence_id) > 200:
                raise GateError("EVIDENCE_ID_MISSING")
            fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
            row: dict[str, Any] = {"id": fingerprint, "status": "HOLD"}
            summary["rows"].append(row)
            if size * 2 > remaining:
                row["code"] = "BUDGET_EXHAUSTED"
                continue
            try:
                source_path, source_stat = _checked_file(source, parts)
                copy_path, copy_stat = _checked_file(copy, copy_parts)
                if (source_stat.st_ino and copy_stat.st_ino and
                        source_stat.st_dev == copy_stat.st_dev and
                        source_stat.st_ino == copy_stat.st_ino):
                    raise GateError("SAME_INODE_NOT_COPY")
                if source_stat.st_size != size or copy_stat.st_size != size:
                    raise GateError("SIZE_MISMATCH")
                src_n, src_hash, _ = _hash_file(source_path, source_stat, remaining)
                remaining -= src_n
                cp_n, cp_hash, _ = _hash_file(copy_path, copy_stat, remaining)
                remaining -= cp_n
                if src_hash != digest or cp_hash != digest:
                    raise GateError("DIGEST_MISMATCH")
                row["status"] = "READBACK_MATCH"
                row["code"] = "MATCHED_UNATTESTED"
                summary["copy_verified"] += 1
            except GateError as exc:
                row["code"] = exc.code
        if summary["copy_verified"] == summary["item_count"]:
            summary["status"] = "READBACK_VERIFIED_NOT_RELEASED"
    except GateError as exc:
        summary["error_code"] = exc.code
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only artifact readback; NEVER cleanup")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--copy-root", required=True)
    parser.add_argument("--max-read-mib", type=int, default=256)
    opts = parser.parse_args(argv)
    result: dict[str, Any]
    try:
        raw = Path(opts.manifest).read_bytes()
        parsed = _read_json_unique(raw)
        result = evaluate(parsed, Path(opts.source_root), Path(opts.copy_root),
                          read_budget=opts.max_read_mib * 1024 * 1024)
        result["input_sha256"] = hashlib.sha256(raw).hexdigest()
    except (GateError, OSError) as exc:
        result = {"schema": SCHEMA, "status": "HOLD", "deletion_authorized": False,
                  "error_code": exc.code if isinstance(exc, GateError) else "MANIFEST_UNAVAILABLE"}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "READBACK_VERIFIED_NOT_RELEASED" else 2


if __name__ == "__main__":
    sys.exit(main())