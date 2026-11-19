#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded, read-only recovery locator for previously hashed SZL evidence.

A byte-identical file is a candidate for custody recovery, NOT a trusted
signature, durable archive, restored receipt, or production release admission.
No file is written, moved, deleted, opened for write, or sent over a network.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

SCHEMA = "szl.custody.recovery-locator/v1"
MANIFEST_MAX_BYTES = 128 * 1024
MAX_ARTIFACTS = 64
MAX_ROOTS = 8
MAX_ENTRIES = 250_000
MAX_BYTES_READ = 256 * 1024 * 1024
MAX_SINGLE_FILE = 32 * 1024 * 1024
MAX_SECONDS = 20.0
CHUNK_BYTES = 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z")
SAFE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,119}\Z")
ALLOWED_SUFFIXES = frozenset({".json", ".jsonl", ".ndjson"})
PROTECTED_DIRECTORIES = frozenset({
    ".git", ".ssh", ".gnupg", ".aws", "onedrive", "appdata",
    "secrets", "credentials", "private", "keys", "models", "weights",
    "huggingface", ".cache", "node_modules", ".venv", "venv",
    "__pycache__", ".pytest_cache", "dist", "build",
})
REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class Hold(Exception):
    """A fail-closed validation or observation failure."""


def _is_link(st: os.stat_result) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool(
        getattr(st, "st_file_attributes", 0) & REPARSE
    )


def _pairs_unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise Hold("DUPLICATE_JSON_KEY")
        result[name] = value
    return result


def load_manifest(path: Path) -> tuple[dict, str]:
    try:
        info = path.lstat()
        if _is_link(info) or not stat.S_ISREG(info.st_mode):
            raise Hold("MANIFEST_NOT_REGULAR")
        if info.st_size > MANIFEST_MAX_BYTES:
            raise Hold("MANIFEST_TOO_LARGE")
        with path.open("rb") as file:
            raw = file.read(MANIFEST_MAX_BYTES + 1)
        if len(raw) > MANIFEST_MAX_BYTES:
            raise Hold("MANIFEST_TOO_LARGE")
    except OSError as exc:
        raise Hold("MANIFEST_UNAVAILABLE") from exc
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_unique)
    except (ValueError, UnicodeError) as exc:
        raise Hold("INVALID_MANIFEST_JSON") from exc
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise Hold("MANIFEST_SCHEMA_MISMATCH")
    items = doc.get("artifacts")
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_ARTIFACTS:
        raise Hold("INVALID_ARTIFACT_COUNT")
    identities = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {
            "id", "basename", "size_bytes", "sha256"
        }:
            raise Hold("INVALID_ARTIFACT_FIELDS")
        ident, name = item["id"], item["basename"]
        size, digest = item["size_bytes"], item["sha256"]
        if (not isinstance(ident, str) or not SAFE_NAME.fullmatch(ident)
                or ident.casefold() in identities):
            raise Hold("INVALID_OR_DUPLICATE_ARTIFACT_ID")
        identities.add(ident.casefold())
        if (not isinstance(name, str) or not SAFE_NAME.fullmatch(name)
                or Path(name).suffix.lower() not in ALLOWED_SUFFIXES):
            raise Hold("INVALID_BASENAME")
        if type(size) is not int or not 0 < size <= MAX_SINGLE_FILE:
            raise Hold("INVALID_ARTIFACT_SIZE")
        if not isinstance(digest, str) or not SHA.fullmatch(digest):
            raise Hold("INVALID_SHA256")
    return doc, hashlib.sha256(raw).hexdigest()


def check_root(root: Path) -> Path:
    if not root.is_absolute() or root == Path(root.anchor):
        raise Hold("ROOT_MUST_BE_EXPLICIT_DIRECTORY")
    if any(piece.casefold() in PROTECTED_DIRECTORIES for piece in root.parts):
        raise Hold("PROTECTED_ROOT")
    for path in (*reversed(root.parents), root):
        try:
            info = path.lstat()
        except OSError as exc:
            raise Hold("ROOT_UNAVAILABLE") from exc
        if _is_link(info) or not stat.S_ISDIR(info.st_mode):
            raise Hold("ROOT_REPARSE_OR_NOT_DIRECTORY")
    return root


def file_identity(st: os.stat_result) -> tuple[int, int, int, int]:
    return st.st_size, st.st_mtime_ns, st.st_dev, st.st_ino


def read_digest(path: Path, budget: int) -> tuple[str, int]:
    """Recheck metadata on an exact-basename file; never follow a link."""
    try:
        before = path.lstat()
        if _is_link(before) or not stat.S_ISREG(before.st_mode):
            raise Hold("FILE_REPARSE_OR_NONREGULAR")
        if before.st_size < 1 or before.st_size > budget:
            raise Hold("HASH_BUDGET_EXHAUSTED")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as file:
            opened = os.fstat(file.fileno())
            if file_identity(before) != file_identity(opened):
                raise Hold("FILE_CHANGED_DURING_READ")
            digest = hashlib.sha256()
            observed = 0
            while True:
                block = file.read(min(CHUNK_BYTES, budget - observed + 1))
                if not block:
                    break
                observed += len(block)
                if observed > budget:
                    raise Hold("HASH_BUDGET_EXHAUSTED")
                digest.update(block)
            after_open = os.fstat(file.fileno())
        after = path.lstat()
    except OSError as exc:
        raise Hold("FILE_READ_UNAVAILABLE") from exc
    if (file_identity(before) != file_identity(after)
            or file_identity(before) != file_identity(after_open)
            or observed != before.st_size):
        raise Hold("FILE_CHANGED_DURING_READ")
    return digest.hexdigest(), observed


def inspect(manifest: dict, roots: list[Path], *,
            show_paths: bool = False, max_entries: int = MAX_ENTRIES,
            max_bytes: int = MAX_BYTES_READ, max_seconds: float = MAX_SECONDS) -> dict:
    """No network, deletion, copies, writes, or production admission."""
    if not 1 <= len(roots) <= MAX_ROOTS:
        raise Hold("INVALID_ROOT_COUNT")
    if type(max_entries) is not int or not 1 <= max_entries <= MAX_ENTRIES:
        raise Hold("INVALID_SCAN_BUDGET")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BYTES_READ:
        raise Hold("INVALID_HASH_BUDGET")
    if type(max_seconds) not in (int, float) or not 0 < max_seconds <= MAX_SECONDS:
        raise Hold("INVALID_TIME_BUDGET")
    checked_roots = [check_root(root) for root in roots]
    if len({str(root).casefold() for root in checked_roots}) != len(roots):
        raise Hold("DUPLICATE_SCAN_ROOT")
    targets = {}
    states = {}
    for item in manifest["artifacts"]:
        targets.setdefault(item["basename"].casefold(), []).append(item)
        states[item["id"]] = {
            "id": item["id"], "status": "NOT_FOUND_IN_SCOPED_NONPROTECTED_FILES",
            "matched_count": 0, "independent_archive_verified": False,
            "signature_verified": False, "source_revision_verified": False,
            "locations": [],
        }
    start = time.monotonic()
    count = 0
    hashed = 0
    candidates = 0
    excluded = 0
    inaccessible = 0
    incomplete_reason = None
    for root_index, root in enumerate(checked_roots):
        stack = [root]
        while stack:
            if count >= max_entries or time.monotonic() - start >= max_seconds:
                incomplete_reason = "SCAN_BUDGET_EXHAUSTED"
                break
            folder = stack.pop()
            try:
                # Iterate lazily: never materialize a huge attacker-controlled directory.
                with os.scandir(folder) as iterator:
                    for entry in iterator:
                        count += 1
                        if count > max_entries or time.monotonic() - start >= max_seconds:
                            incomplete_reason = "SCAN_BUDGET_EXHAUSTED"
                            break
                        if entry.name.casefold() in PROTECTED_DIRECTORIES:
                            excluded += 1
                            continue
                        try:
                            info = os.lstat(entry.path)
                        except OSError:
                            inaccessible += 1
                            incomplete_reason = "ENTRY_UNAVAILABLE"
                            continue
                        if _is_link(info):
                            excluded += 1
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            stack.append(Path(entry.path))
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            continue
                        applicable = [
                            item for item in targets.get(entry.name.casefold(), [])
                            if item["size_bytes"] == info.st_size
                        ]
                        if not applicable:
                            continue
                        candidates += 1
                        if info.st_size > max_bytes - hashed:
                            incomplete_reason = "HASH_BUDGET_EXHAUSTED"
                            break
                        try:
                            actual, consumed = read_digest(Path(entry.path), max_bytes - hashed)
                        except Hold as exc:
                            inaccessible += 1
                            incomplete_reason = str(exc)
                            continue
                        hashed += consumed
                        for item in applicable:
                            if actual != item["sha256"]:
                                continue
                            state = states[item["id"]]
                            state["matched_count"] += 1
                            state["status"] = "HASH_MATCH_UNATTESTED"
                            if show_paths:
                                state["locations"].append({
                                    "root_index": root_index,
                                    "relative_path": str(Path(entry.path).relative_to(root)),
                                })
            except OSError:
                inaccessible += 1
                incomplete_reason = "DIRECTORY_UNAVAILABLE"
                continue
            if incomplete_reason in ("SCAN_BUDGET_EXHAUSTED", "HASH_BUDGET_EXHAUSTED"):
                break
        if incomplete_reason in ("SCAN_BUDGET_EXHAUSTED", "HASH_BUDGET_EXHAUSTED"):
            break
    if incomplete_reason:
        for state in states.values():
            if state["matched_count"] == 0:
                state["status"] = "UNKNOWN_INCOMPLETE_SCAN"
    all_matched = all(x["matched_count"] > 0 for x in states.values())
    return {
        "schema": SCHEMA, "observed_utc": datetime.now(timezone.utc).isoformat(),
        "status": "CANDIDATES_FOUND_NOT_ADMITTED" if all_matched
                  else "HOLD", "release_authorized": False,
        "deletion_authorized": False, "archive_durability_verified": False,
        "manifest_authenticity_verified": False, "scan_complete": incomplete_reason is None,
        "scope": "EXPLICIT_ROOTS_EXCLUDING_PROTECTED_AND_REPARSE_PATHS",
        "incomplete_reason": incomplete_reason, "root_count": len(roots),
        "scanned_entries": count, "candidate_files_hashed": candidates,
        "bytes_hashed": hashed, "excluded_entries": excluded,
        "inaccessible_entries": inaccessible,
        "matched_artifacts": sum(x["matched_count"] > 0 for x in states.values()),
        "artifact_count": len(states),
        "artifacts": [states[x["id"]] for x in manifest["artifacts"]],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only, fail-closed evidence locator")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--root", action="append", required=True)
    parser.add_argument("--show-paths", action="store_true",
                        help="Expose matched relative paths locally, not for public CI")
    args = parser.parse_args(argv)
    try:
        manifest, exact_digest = load_manifest(Path(args.manifest))
        outcome = inspect(manifest, [Path(r) for r in args.root],
                          show_paths=args.show_paths)
        outcome["manifest_sha256_unsigned"] = exact_digest
    except Hold as exc:
        outcome = {
            "schema": SCHEMA, "status": "HOLD", "reason": str(exc),
            "release_authorized": False, "deletion_authorized": False,
        }
    print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
    return 0 if outcome["status"] == "CANDIDATES_FOUND_NOT_ADMITTED" else 2


if __name__ == "__main__":
    sys.exit(main())
