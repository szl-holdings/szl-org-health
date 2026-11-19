#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exhaustive, byte-checked source census for the SZL Ouroboros braid v2.

Reads COMMITTED objects from local git checkouts (``git ls-tree`` plus
``git cat-file``), recomputes each blob's git id and an independent SHA-256,
and emits one cord per file that the reviewed policy puts in scope. Every
tracked file is counted: files outside the scope are reported as a number,
never silently dropped, and a repository with no usable checkout is listed
as UNAVAILABLE rather than treated as empty. Each repository row records the
commit's root tree id and a digest of its full file listing, so anyone with
the same commit can re-derive every count.

``validate_census`` checks a report on its own: the file accounting, cord
keys, include and exclude globs, and per-repository cord and unavailable
counts. A file dropped with every count adjusted to match cannot be seen from
the report alone; ``verify_census_checkouts`` (CLI ``--verify``) re-derives
each row from a checkout of the recorded commit and refuses any difference.

No network, no repository code is imported or executed, nothing is written
inside a checkout. A match proves that these bytes are the content of that
commit in that local object store. It does NOT prove the commit is on the
protected remote branch, who authored it, or that any proof in a file was
checked. ``checkout_identity`` only compares the checkout's configured
``origin`` URL with the policy name. Family labels come from the reviewed
policy and map; a file no rule names is UNCLASSIFIED, never guessed.

``export_tree`` writes the committed bytes of one commit into a new directory
so other tools can run committed code without any untracked or ignored file of
the checkout being importable.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from urllib.parse import quote, urlsplit

try:
    from tools.database_braid_common import (
        REPOSITORY, SHA40, SHA64, checkout_root, closed, digest, git_blob_sha1, lean_code_only,
        natural, read_json, require, sha256_hex, write_exclusive,
    )
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_braid_common import (
        REPOSITORY, SHA40, SHA64, checkout_root, closed, digest, git_blob_sha1, lean_code_only,
        natural, read_json, require, sha256_hex, write_exclusive,
    )
    from tools.database_catalog_admission import InputError

SCHEMA = "szl.database-braid-source-census/v1"
FAMILY_MAP_SCHEMA = "szl.database-braid-family-map/v1"
FAMILY = re.compile(r"[A-Z][A-Z0-9_]{1,47}\Z")
GLOB = re.compile(r"[A-Za-z0-9_.*?/+@\[\]-]{1,200}\Z")
UNCLASSIFIED = "UNCLASSIFIED"
IDENTITY_MATCHES = "ORIGIN_MATCHES"
IDENTITY_DIFFERS = "ORIGIN_DIFFERS"
IDENTITY_NO_ORIGIN = "NO_ORIGIN"
IDENTITIES = (IDENTITY_MATCHES, IDENTITY_DIFFERS, IDENTITY_NO_ORIGIN)
UNAVAILABLE_REASONS = ("BLOB_OVER_SIZE_CAP", "LFS_POINTER_CONTENT_ABSENT")
MAX_REPOSITORIES = 32
MAX_RULES = 200
MAX_CENSUS_BYTES = 16777216
MAX_MAP_BYTES = 1048576
MAX_BATCH_BYTES = 67108864
MAX_EXPORT_BYTES = 536870912
GIT_TIMEOUT_SECONDS = 120
LFS_MAGIC = b"version https://git-lfs.github.com/spec/v1"
_FALSE_FLAGS = ("network_used", "source_code_executed", "provider_writes", "secrets_recorded",
                "remote_head_independently_verified", "proofs_checked_by_this_collector")
_ROW_FIELDS = ("repository", "state", "commit", "tree_id", "listing_sha256", "checkout_identity",
               "shallow", "tracked_files", "in_scope_files", "out_of_scope_files",
               "symlink_or_submodule_entries", "cords", "unavailable_cords")
_COUNT_FIELDS = ("tracked_files", "in_scope_files", "out_of_scope_files",
                 "symlink_or_submodule_entries", "cords", "unavailable_cords")


def validate_census_policy(section) -> list:
    """Validate the ``census`` section of the braid v2 policy; return its repositories."""
    closed(section, ("max_cords", "max_blob_bytes", "repositories"), "CENSUS_POLICY_FIELDS_INVALID")
    natural(section["max_cords"], "CENSUS_POLICY_INVALID", maximum=50000)
    natural(section["max_blob_bytes"], "CENSUS_POLICY_INVALID", maximum=67108864)
    require(section["max_cords"] > 0 and section["max_blob_bytes"] > 0, "CENSUS_POLICY_INVALID")
    repos = section["repositories"]
    require(type(repos) is list and 0 < len(repos) <= MAX_REPOSITORIES,
            "CENSUS_POLICY_INVALID")
    names = []
    for repo in repos:
        closed(repo, ("repository", "include", "exclude", "families"),
               "CENSUS_REPOSITORY_FIELDS_INVALID")
        require(type(repo["repository"]) is str and
                REPOSITORY.fullmatch(repo["repository"]) is not None,
                "CENSUS_REPOSITORY_INVALID")
        names.append(repo["repository"])
        for field in ("include", "exclude"):
            globs = repo[field]
            require(type(globs) is list and len(globs) <= MAX_RULES and
                    all(type(g) is str and GLOB.fullmatch(g) for g in globs),
                    "CENSUS_GLOB_INVALID")
        require(len(repo["include"]) > 0, "CENSUS_GLOB_INVALID")
        rules = repo["families"]
        require(type(rules) is list and len(rules) <= MAX_RULES, "CENSUS_FAMILY_RULES_INVALID")
        for rule in rules:
            closed(rule, ("glob", "family"), "CENSUS_FAMILY_RULES_INVALID")
            require(type(rule["glob"]) is str and GLOB.fullmatch(rule["glob"]) and
                    type(rule["family"]) is str and FAMILY.fullmatch(rule["family"]),
                    "CENSUS_FAMILY_RULES_INVALID")
    require(names == sorted(set(names)), "CENSUS_REPOSITORY_ORDER_OR_DUPLICATE")
    short = [name.split("/", 1)[1] for name in names]
    require(len(short) == len(set(short)), "CENSUS_REPOSITORY_ORDER_OR_DUPLICATE")
    return repos


def validate_family_map(value) -> dict:
    """A reviewed explicit ``repository -> path -> family`` map. Optional input."""
    closed(value, ("schema", "review_status", "families"), "CENSUS_FAMILY_MAP_INVALID")
    require(value["schema"] == FAMILY_MAP_SCHEMA and
            value["review_status"] in ("MACHINE_PROPOSED_UNRATIFIED", "OWNER_RATIFIED") and
            type(value["families"]) is dict, "CENSUS_FAMILY_MAP_INVALID")
    for repository, paths in value["families"].items():
        require(type(repository) is str and REPOSITORY.fullmatch(repository) and
                type(paths) is dict, "CENSUS_FAMILY_MAP_INVALID")
        for path, family in paths.items():
            require(type(path) is str and 0 < len(path) <= 400 and
                    type(family) is str and FAMILY.fullmatch(family),
                    "CENSUS_FAMILY_MAP_INVALID")
    return value["families"]


def cord_key(repository: str, path: str) -> str:
    """Stable cord key; unusual path characters are percent-encoded."""
    return repository.split("/", 1)[1] + ":" + quote(path, safe="/._+@-")


def lean_text_sorry_tokens(raw: bytes) -> int:
    """Count ``sorry`` tokens outside Lean comments and literals. Text level, not a kernel check."""
    code = lean_code_only(raw.decode("utf-8", "replace"))
    return len(re.findall(r"(?<![A-Za-z0-9_.'!?])sorry(?![A-Za-z0-9_'!?])", code))


def _git(directory: Path, *args, stdin: bytes | None = None, ok_codes=(0,)) -> bytes:
    """Run one fixed, local, read-only git command with a minimal environment.

    System and global configuration are ignored, hooks that git status-like
    commands could run (fsmonitor, untracked cache) are switched off, and replace
    refs are ignored so a listing or export is always the named commit's own content.
    """
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/"),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C",
           # A planted refs/replace entry must not substitute the commit's own trees or blobs.
           "GIT_NO_REPLACE_OBJECTS": "1"}
    try:
        proc = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c",
                               "core.untrackedCache=false", "-C", str(directory), *args],
                              input=stdin, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env=env, timeout=GIT_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise InputError("CENSUS_GIT_UNAVAILABLE") from None
    require(proc.returncode in ok_codes, "CENSUS_GIT_REFUSED")
    return proc.stdout


def _ls_tree(directory: Path, commit: str) -> list:
    """``[(mode, kind, sha, size_or_None, path)]`` for every entry of ``commit``'s tree."""
    rows = []
    for record in _git(directory, "ls-tree", "-r", "-z", "-l", "--full-tree", commit).split(b"\0"):
        if not record:
            continue
        meta, _, name = record.partition(b"\t")
        fields = meta.split()
        require(len(fields) == 4, "CENSUS_TREE_PARSE_FAILED")
        mode, kind, sha, size = (f.decode("ascii") for f in fields)
        require(SHA40.fullmatch(sha) is not None and (size == "-" or size.isdigit()),
                "CENSUS_TREE_PARSE_FAILED")
        try:
            path = name.decode("utf-8", "strict")
        except UnicodeError:
            raise InputError("CENSUS_PATH_NOT_UTF") from None
        rows.append((mode, kind, sha, None if size == "-" else int(size), path))
    return rows


def list_tree(directory: Path) -> tuple:
    """``(commit, shallow, rows)`` for HEAD of a checkout whose top level is ``directory``."""
    require(isinstance(directory, Path) and directory.is_dir() and not directory.is_symlink(),
            "CENSUS_CHECKOUT_UNAVAILABLE")
    top = _git(directory, "rev-parse", "--show-toplevel").decode("utf-8", "replace").strip()
    # A directory nested inside some other work tree is not that repository's checkout.
    require(top != "" and Path(top).resolve() == directory.resolve(),
            "CENSUS_CHECKOUT_NOT_TOP_LEVEL")
    commit = _git(directory, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    require(SHA40.fullmatch(commit) is not None, "CENSUS_COMMIT_INVALID")
    shallow = _git(directory, "rev-parse", "--is-shallow-repository").strip() == b"true"
    return commit, shallow, _ls_tree(directory, commit)


def tree_identity(directory: Path, commit: str, rows: list) -> tuple:
    """``(root_tree_id, listing_sha256)``: what a verifier with the commit can recompute."""
    tree = _git(directory, "rev-parse", "--verify", commit + "^{tree}").decode("ascii").strip()
    require(SHA40.fullmatch(tree) is not None, "CENSUS_TREE_PARSE_FAILED")
    listing = digest(sorted([path, mode, sha] for mode, _kind, sha, _size, path in rows))
    return tree, listing


def checkout_identity(directory: Path, repository: str) -> str:
    """Compare the checkout's ``origin`` URL with the policy repository name."""
    raw = _git(directory, "config", "--get", "remote.origin.url", ok_codes=(0, 1))
    url = raw.decode("utf-8", "replace").strip()
    if not url:
        return IDENTITY_NO_ORIGIN
    path = urlsplit(url).path if "://" in url else url.split(":", 1)[-1]
    tail = PurePosixPath(path.rstrip("/")).parts[-2:]
    name = "/".join(tail)
    if name.endswith(".git"):
        name = name[:-4]
    return IDENTITY_MATCHES if name.lower() == repository.lower() else IDENTITY_DIFFERS


def iter_blobs(directory: Path, shas, *, max_bytes: int):
    """Yield ``(blob_id, committed bytes)``, or ``(blob_id, None)`` when over ``max_bytes``.

    Sizes are read first, so an over-cap blob is never loaded into memory, and
    the rest are read in batches of at most ``MAX_BATCH_BYTES``, one batch held
    at a time, so the total read never has to fit in memory at once.
    """
    wanted = sorted(set(shas))
    require(all(type(s) is str and SHA40.fullmatch(s) for s in wanted), "CENSUS_BLOB_ID_INVALID")
    if not wanted:
        return
    sizes = {}
    for line in _git(directory, "cat-file", "--batch-check",
                     stdin=("\n".join(wanted) + "\n").encode("ascii")).decode("ascii").splitlines():
        parts = line.split()
        require(len(parts) == 3 and parts[1] == "blob" and parts[2].isdigit(),
                "CENSUS_BLOB_PARSE_FAILED")
        sizes[parts[0]] = int(parts[2])
    require(set(sizes) == set(wanted), "CENSUS_BLOB_PARSE_FAILED")
    for sha in wanted:
        if sizes[sha] > max_bytes:
            yield sha, None
    batch, batch_bytes = [], 0
    for sha in [s for s in wanted if sizes[s] <= max_bytes] + [None]:
        if sha is not None and (not batch or batch_bytes + sizes[sha] <= MAX_BATCH_BYTES):
            batch.append(sha)
            batch_bytes += sizes[sha]
            continue
        if batch:
            raw = _git(directory, "cat-file", "--batch",
                       stdin=("\n".join(batch) + "\n").encode("ascii"))
            offset = 0
            for item in batch:
                end = raw.find(b"\n", offset)
                require(end >= 0, "CENSUS_BLOB_PARSE_FAILED")
                header = raw[offset:end].decode("ascii", "replace").split()
                require(len(header) == 3 and header[0] == item and header[1] == "blob" and
                        header[2] == str(sizes[item]), "CENSUS_BLOB_PARSE_FAILED")
                body = raw[end + 1:end + 1 + sizes[item]]
                require(len(body) == sizes[item], "CENSUS_BLOB_PARSE_FAILED")
                yield item, body
                offset = end + 1 + sizes[item] + 1
        if sha is not None:
            batch, batch_bytes = [sha], sizes[sha]


def read_blobs(directory: Path, shas: list, *, max_bytes: int) -> dict:
    """Committed bytes for each blob id, or ``None`` when over the size cap.

    Every blob read is returned at once; a caller reading many blobs should
    iterate ``iter_blobs`` instead.
    """
    return dict(iter_blobs(directory, shas, max_bytes=max_bytes))


def _export_path(root: Path, path: str) -> Path:
    # Split the raw text: PurePosixPath would quietly collapse "a/./b" and "a//b".
    parts = path.split("/")
    require(all(p not in ("", ".", "..", ".git") for p in parts), "EXPORT_PATH_INVALID")
    target = root.joinpath(*parts)
    require(target.resolve().is_relative_to(root), "EXPORT_PATH_INVALID")
    return target


def export_tree(directory: Path, commit: str, dest: Path, *, max_blob_bytes: int = 67108864,
                max_total_bytes: int = MAX_EXPORT_BYTES) -> dict:
    """Write the committed regular files of ``commit`` into the empty directory ``dest``.

    Bytes come from the object store, not the working tree, and attributes such
    as export-ignore or export-subst play no part. Symlinks and submodules are
    counted and skipped. Every path is checked to stay inside ``dest`` before
    anything is written, and blobs are written batch by batch as they are read.
    """
    require(isinstance(dest, Path) and dest.is_dir() and not dest.is_symlink() and
            not any(dest.iterdir()), "EXPORT_DESTINATION_INVALID")
    rows = _ls_tree(directory, commit)
    files = [(mode, sha, size, path) for mode, kind, sha, size, path in rows
             if kind == "blob" and mode in ("100644", "100755")]
    require(sum(size or 0 for _m, _s, size, _p in files) <= max_total_bytes, "EXPORT_TOO_LARGE")
    root = dest.resolve()
    targets = {}
    for mode, sha, _size, path in files:
        targets.setdefault(sha, []).append((mode, _export_path(root, path)))
    written = 0
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for sha, body in iter_blobs(directory, list(targets), max_bytes=max_blob_bytes):
        require(body is not None and git_blob_sha1(body) == sha, "EXPORT_BLOB_UNAVAILABLE")
        for mode, target in targets[sha]:
            target.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(target), flags, 0o700 if mode == "100755" else 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(body)
            written += len(body)
    return {"files": len(files), "bytes": written, "skipped_entries": len(rows) - len(files)}


def _matches(path, globs) -> bool:
    return any(fnmatchcase(path, g) for g in globs)


def _in_scope(repo_policy, path) -> bool:
    return _matches(path, repo_policy["include"]) and not _matches(path, repo_policy["exclude"])


def _family(repo_policy, explicit, path) -> str:
    if path in explicit:
        return explicit[path]
    for rule in repo_policy["families"]:
        if fnmatchcase(path, rule["glob"]):
            return rule["family"]
    return UNCLASSIFIED


def census_repository(repo_policy, directory: Path, explicit: dict, *, max_blob_bytes: int,
                      max_cords: int, commit: str | None = None) -> tuple:
    """Census one checkout at HEAD, or at ``commit`` when one is named.

    Returns ``(repository_row, cords, unavailable_cords)``.
    """
    repository = repo_policy["repository"]
    head, shallow, rows = list_tree(directory)
    if commit is None:
        commit = head
    elif commit != head:
        require(type(commit) is str and SHA40.fullmatch(commit) is not None,
                "CENSUS_COMMIT_INVALID")
        _git(directory, "cat-file", "-e", commit + "^{commit}")
        rows = _ls_tree(directory, commit)
    tree_id, listing = tree_identity(directory, commit, rows)
    chosen, counts = [], {"tracked": 0, "out_of_scope": 0, "symlink_or_submodule": 0}
    for mode, kind, sha, size, path in rows:
        counts["tracked"] += 1
        if kind != "blob" or mode not in ("100644", "100755"):
            counts["symlink_or_submodule"] += 1
        elif _in_scope(repo_policy, path):
            chosen.append((path, sha, size))
        else:
            counts["out_of_scope"] += 1
    require(len(chosen) <= max_cords, "CENSUS_CORD_BUDGET_EXCEEDED")
    lean_blobs = {sha for path, sha, _size in chosen if path.endswith(".lean")}
    # Only per-blob facts are kept, so memory holds one read batch, never every blob.
    facts = {}
    for sha, body in iter_blobs(directory, [sha for _p, sha, _s in chosen],
                                max_bytes=max_blob_bytes):
        if body is None:
            facts[sha] = None
            continue
        # Git's blob id is recomputed over the bytes actually read from the object store.
        require(git_blob_sha1(body) == sha, "CENSUS_BLOB_ID_MISMATCH")
        facts[sha] = {"sha256": sha256_hex(body), "bytes": len(body),
                      "lfs": body.startswith(LFS_MAGIC),
                      "sorry": lean_text_sorry_tokens(body) if sha in lean_blobs else 0}
    cords, unavailable = [], []
    for path, sha, _size in sorted(chosen):
        fact = facts[sha]
        key = cord_key(repository, path)
        if fact is None or fact["lfs"]:
            unavailable.append({"key": key, "repository": repository, "path": path,
                                "reason": "BLOB_OVER_SIZE_CAP" if fact is None
                                else "LFS_POINTER_CONTENT_ABSENT"})
            continue
        lean = path.endswith(".lean")
        cords.append({
            "key": key, "repository": repository, "path": path, "blob_sha1": sha,
            "sha256": fact["sha256"], "bytes": fact["bytes"],
            "family": _family(repo_policy, explicit, path), "is_lean": lean,
            "lean_text_sorry_tokens": fact["sorry"] if lean else 0,
        })
    row = {"repository": repository, "state": "OBSERVED", "commit": commit, "tree_id": tree_id,
           "listing_sha256": listing,
           "checkout_identity": checkout_identity(directory, repository), "shallow": shallow,
           "tracked_files": counts["tracked"], "in_scope_files": len(chosen),
           "out_of_scope_files": counts["out_of_scope"],
           "symlink_or_submodule_entries": counts["symlink_or_submodule"],
           "cords": len(cords), "unavailable_cords": len(unavailable)}
    return row, cords, unavailable


def observe(section, checkouts: dict, *, family_map: dict | None = None, at=None,
            policy_sha256=None, family_map_sha256=None) -> dict:
    """Census every policy repository from the supplied ``repository -> Path`` checkouts."""
    repos = validate_census_policy(section)
    explicit = family_map or {}
    require(type(checkouts) is dict and set(checkouts) <= {r["repository"] for r in repos},
            "CENSUS_CHECKOUT_NOT_IN_POLICY")
    rows, cords, unavailable = [], [], []
    for repo in repos:
        name = repo["repository"]
        directory = checkouts.get(name)
        if directory is None:
            rows.append({field: None for field in _ROW_FIELDS} |
                        {"repository": name, "state": "UNAVAILABLE"})
            continue
        row, found, missing = census_repository(
            repo, Path(directory), explicit.get(name, {}), max_blob_bytes=section["max_blob_bytes"],
            max_cords=section["max_cords"] - len(cords))
        rows.append(row)
        cords.extend(found)
        unavailable.extend(missing)
    require(len(cords) <= section["max_cords"], "CENSUS_CORD_BUDGET_EXCEEDED")
    observed = [r for r in rows if r["state"] == "OBSERVED"]
    report = {
        "schema": SCHEMA,
        "observed_at": (at or datetime.now(timezone.utc)).isoformat(),
        "state": "COMPLETE" if len(observed) == len(rows) and not unavailable else "PARTIAL",
        "policy_sha256": policy_sha256, "family_map_sha256": family_map_sha256,
        "repositories": rows,
        "repositories_required": len(rows), "repositories_observed": len(observed),
        "cords": sorted(cords, key=lambda c: c["key"]),
        "unavailable_cords": sorted(unavailable, key=lambda c: c["key"]),
        "git_object_bytes_checked_by_this_collector": True,
    }
    report.update({flag: False for flag in _FALSE_FLAGS})
    validate_census(report, section, family_map=family_map)
    return report


def validate_census(value, section, *, family_map: dict | None = None) -> list:
    """Closed-schema check of a census report against the policy. Returns its cords.

    Cord families are re-derived from the policy rules when the report used no
    family map, and from ``family_map`` when one is given.
    """
    repos = validate_census_policy(section)
    by_name = {r["repository"]: r for r in repos}
    if family_map is not None:
        family_map = validate_family_map({"schema": FAMILY_MAP_SCHEMA,
                                          "review_status": "MACHINE_PROPOSED_UNRATIFIED",
                                          "families": family_map})
    closed(value, ("schema", "observed_at", "state", "policy_sha256", "family_map_sha256",
                   "repositories", "repositories_required", "repositories_observed", "cords",
                   "unavailable_cords", "git_object_bytes_checked_by_this_collector",
                   *_FALSE_FLAGS), "CENSUS_FIELDS_INVALID")
    require(value["schema"] == SCHEMA and
            value["git_object_bytes_checked_by_this_collector"] is True and
            all(value[flag] is False for flag in _FALSE_FLAGS), "CENSUS_FALSE_AUTHORITY_CLAIM")
    for field in ("policy_sha256", "family_map_sha256"):
        require(value[field] is None or (type(value[field]) is str and
                                         SHA64.fullmatch(value[field])), "CENSUS_FIELDS_INVALID")
    require(type(value["observed_at"]) is str and len(value["observed_at"]) <= 48,
            "CENSUS_TIMESTAMP_INVALID")
    try:
        stamp = datetime.fromisoformat(value["observed_at"].replace("Z", "+00:00"))
    except ValueError:
        raise InputError("CENSUS_TIMESTAMP_INVALID") from None
    require(stamp.tzinfo is not None and stamp.utcoffset() is not None,
            "CENSUS_TIMESTAMP_INVALID")
    rows = value["repositories"]
    require(type(rows) is list and [r.get("repository") if type(r) is dict else None
                                    for r in rows] == [r["repository"] for r in repos],
            "CENSUS_REPOSITORY_COVERAGE_INVALID")
    counted = {}
    for row in rows:
        closed(row, _ROW_FIELDS, "CENSUS_REPOSITORY_FIELDS_INVALID")
        if row["state"] == "OBSERVED":
            require(type(row["commit"]) is str and SHA40.fullmatch(row["commit"]) and
                    type(row["tree_id"]) is str and SHA40.fullmatch(row["tree_id"]) and
                    type(row["listing_sha256"]) is str and SHA64.fullmatch(row["listing_sha256"])
                    and row["checkout_identity"] in IDENTITIES and type(row["shallow"]) is bool,
                    "CENSUS_REPOSITORY_FIELDS_INVALID")
            for field in _COUNT_FIELDS:
                natural(row[field], "CENSUS_REPOSITORY_FIELDS_INVALID")
            # Every tracked file is accounted for: in scope, out of scope, or not a regular blob.
            require(row["tracked_files"] == row["in_scope_files"] + row["out_of_scope_files"]
                    + row["symlink_or_submodule_entries"] and
                    row["in_scope_files"] == row["cords"] + row["unavailable_cords"],
                    "CENSUS_FILE_ACCOUNTING_BROKEN")
            counted[row["repository"]] = [row["cords"], row["unavailable_cords"]]
        else:
            require(row["state"] == "UNAVAILABLE" and
                    all(row[f] is None for f in row if f not in ("repository", "state")),
                    "CENSUS_UNAVAILABLE_NOT_UNKNOWN")
    cords = value["cords"]
    require(type(cords) is list and len(cords) <= section["max_cords"], "CENSUS_CORDS_INVALID")
    keys, per_repo = [], {}
    for cord in cords:
        closed(cord, ("key", "repository", "path", "blob_sha1", "sha256", "bytes", "family",
                      "is_lean", "lean_text_sorry_tokens"), "CENSUS_CORD_FIELDS_INVALID")
        repository, path = cord["repository"], cord["path"]
        require(type(repository) is str and repository in counted and type(path) is str and
                _in_scope(by_name[repository], path) and cord["key"] == cord_key(repository, path)
                and
                type(cord["blob_sha1"]) is str and SHA40.fullmatch(cord["blob_sha1"]) and
                type(cord["sha256"]) is str and SHA64.fullmatch(cord["sha256"]) and
                type(cord["family"]) is str and FAMILY.fullmatch(cord["family"]) and
                type(cord["is_lean"]) is bool and
                cord["is_lean"] == cord["path"].endswith(".lean"), "CENSUS_CORD_FIELDS_INVALID")
        natural(cord["bytes"], "CENSUS_CORD_FIELDS_INVALID", maximum=section["max_blob_bytes"])
        natural(cord["lean_text_sorry_tokens"], "CENSUS_CORD_FIELDS_INVALID", maximum=10 ** 6)
        require(cord["is_lean"] or cord["lean_text_sorry_tokens"] == 0,
                "CENSUS_CORD_FIELDS_INVALID")
        if family_map is not None or value["family_map_sha256"] is None:
            explicit = (family_map or {}).get(cord["repository"], {})
            require(cord["family"] == _family(by_name[cord["repository"]], explicit, cord["path"]),
                    "CENSUS_CORD_FAMILY_NOT_DERIVED")
        keys.append(cord["key"])
        per_repo[cord["repository"]] = per_repo.get(cord["repository"], 0) + 1
    require(keys == sorted(set(keys)), "CENSUS_CORD_ORDER_OR_DUPLICATE")
    missing = value["unavailable_cords"]
    require(type(missing) is list, "CENSUS_CORDS_INVALID")
    missing_keys, missing_per_repo = [], {}
    for item in missing:
        closed(item, ("key", "repository", "path", "reason"), "CENSUS_CORD_FIELDS_INVALID")
        repository, path = item["repository"], item["path"]
        # An unavailable entry names one in-scope file of one observed policy repository.
        require(type(repository) is str and repository in counted and type(path) is str and
                _in_scope(by_name[repository], path) and item["key"] == cord_key(repository, path)
                and item["reason"] in UNAVAILABLE_REASONS, "CENSUS_CORD_FIELDS_INVALID")
        missing_keys.append(item["key"])
        missing_per_repo[item["repository"]] = missing_per_repo.get(item["repository"], 0) + 1
    require(missing_keys == sorted(set(missing_keys)) and not set(keys) & set(missing_keys),
            "CENSUS_CORD_ORDER_OR_DUPLICATE")
    require(all(per_repo.get(name, 0) == pair[0] and missing_per_repo.get(name, 0) == pair[1]
                for name, pair in counted.items()), "CENSUS_CORD_COUNT_MISMATCH")
    observed = sum(r["state"] == "OBSERVED" for r in rows)
    require(value["repositories_required"] == len(rows) and
            value["repositories_observed"] == observed and
            (value["state"] == "COMPLETE") == (observed == len(rows) and not missing) and
            value["state"] in ("COMPLETE", "PARTIAL"), "CENSUS_STATE_INVALID")
    return cords


def verify_census_checkouts(value, section, checkouts: dict, *,
                            family_map: dict | None = None) -> list:
    """Re-derive census rows from checkouts of the recorded commits. Returns the names checked.

    For every repository with a checkout here, the root tree id, the listing
    digest, every count, every cord and every unavailable entry are recomputed
    from that checkout's object store at the row's commit and must be equal.
    ``checkout_identity`` and ``shallow`` describe a local clone, not the commit,
    and are not compared. Families are compared when they can be re-derived: a
    family map is given, or the census used none.
    """
    validate_census(value, section, family_map=family_map)
    by_name = {r["repository"]: r for r in validate_census_policy(section)}
    require(type(checkouts) is dict and set(checkouts) <= set(by_name),
            "CENSUS_CHECKOUT_NOT_IN_POLICY")
    explicit = family_map or {}
    same_family = family_map is not None or value["family_map_sha256"] is None

    def comparable(cords):
        return [c if same_family else {k: v for k, v in c.items() if k != "family"}
                for c in sorted(cords, key=lambda c: c["key"])]

    checked = []
    for row in value["repositories"]:
        name = row["repository"]
        if name not in checkouts:
            continue
        require(row["state"] == "OBSERVED", "CENSUS_REDERIVATION_ROW_NOT_OBSERVED")
        again, cords, missing = census_repository(
            by_name[name], Path(checkouts[name]), explicit.get(name, {}),
            max_blob_bytes=section["max_blob_bytes"], max_cords=section["max_cords"],
            commit=row["commit"])
        require(again["commit"] == row["commit"] and again["tree_id"] == row["tree_id"] and
                again["listing_sha256"] == row["listing_sha256"], "CENSUS_LISTING_MISMATCH")
        require(all(again[field] == row[field] for field in _COUNT_FIELDS),
                "CENSUS_REDERIVED_COUNTS_MISMATCH")
        recorded = [c for c in value["cords"] if c["repository"] == name]
        require(comparable(recorded) == comparable(cords) and
                [u for u in value["unavailable_cords"] if u["repository"] == name] ==
                sorted(missing, key=lambda u: u["key"]), "CENSUS_REDERIVED_CORDS_MISMATCH")
        checked.append(name)
    return checked


def main(argv=None):
    ap = argparse.ArgumentParser(description="Byte-checked source census from local git checkouts")
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--family-map", type=Path)
    ap.add_argument("--checkout", action="append", default=[], metavar="REPOSITORY=DIRECTORY")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--verify", type=Path, metavar="CENSUS",
                      help="re-derive an existing census from the supplied checkouts")
    args = ap.parse_args(argv)
    try:
        policy, policy_sha = read_json(args.policy, max_bytes=MAX_MAP_BYTES)
        require(type(policy) is dict and "census" in policy, "CENSUS_POLICY_FIELDS_INVALID")
        family_map, map_sha = None, None
        if args.family_map is not None:
            raw_map, map_sha = read_json(args.family_map, max_bytes=MAX_MAP_BYTES)
            family_map = validate_family_map(raw_map)
        checkouts = {}
        for item in args.checkout:
            name, sep, directory = item.partition("=")
            require(sep == "=" and REPOSITORY.fullmatch(name) and directory and
                    name not in checkouts, "CENSUS_CHECKOUT_ARGUMENT_INVALID")
            checkouts[name] = Path(directory)
        if args.verify is not None:
            census, census_sha = read_json(args.verify, max_bytes=MAX_CENSUS_BYTES)
            require(type(census) is dict and census.get("policy_sha256") == policy_sha and
                    census.get("family_map_sha256") == map_sha, "CENSUS_INPUTS_DIFFER")
            checked = verify_census_checkouts(census, policy["census"], checkouts,
                                              family_map=family_map)
            print(json.dumps({"state": "REDERIVED_EQUAL", "census_sha256": census_sha,
                              "census_state": census["state"],
                              "repositories_rederived": len(checked),
                              "repositories_required": census["repositories_required"],
                              "provider_writes": False}))
            return 0
        report = observe(policy["census"], checkouts, family_map=family_map,
                         policy_sha256=policy_sha, family_map_sha256=map_sha)
        write_exclusive(args.output, report, max_bytes=MAX_CENSUS_BYTES, checkout=checkout_root())
        print(json.dumps({"state": report["state"], "cords": len(report["cords"]),
                          "unavailable_cords": len(report["unavailable_cords"]),
                          "repositories_observed": report["repositories_observed"],
                          "repositories_required": report["repositories_required"],
                          "provider_writes": False}))
        return 0 if report["state"] == "COMPLETE" else 2
    except InputError as exc:
        code = exc.code
    except Exception:
        code = "CENSUS_UNAVAILABLE"
    print(json.dumps({"state": "UNAVAILABLE", "code": code, "provider_writes": False}))
    return 3


if __name__ == "__main__":
    sys.exit(main())
