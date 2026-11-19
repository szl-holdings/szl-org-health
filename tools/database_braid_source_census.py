#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exhaustive, byte-checked source census for the SZL Ouroboros braid v2.

Reads COMMITTED objects from local git checkouts (``git ls-tree`` plus
``git cat-file``), recomputes each blob's git id and an independent SHA-256,
and emits one cord per file that the reviewed policy puts in scope. Every
tracked file is counted: files outside the scope are reported as a number,
never silently dropped, and a repository with no usable checkout is listed
as UNAVAILABLE rather than treated as empty.

No network, no repository code is imported or executed, nothing is written
inside a checkout. A match proves that these bytes are the content of that
commit in that local object store. It does NOT prove the checkout equals the
protected remote branch, who authored the commit, or that any proof in the
file was checked. Family labels come from the reviewed policy and map; a file
no rule names is UNCLASSIFIED, never guessed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote

try:
    from tools.database_braid_common import (
        REPOSITORY, SHA40, SHA64, checkout_root, closed, git_blob_sha1, lean_code_only,
        natural, read_json, require, sha256_hex, write_exclusive,
    )
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_braid_common import (
        REPOSITORY, SHA40, SHA64, checkout_root, closed, git_blob_sha1, lean_code_only,
        natural, read_json, require, sha256_hex, write_exclusive,
    )
    from tools.database_catalog_admission import InputError

SCHEMA = "szl.database-braid-source-census/v1"
FAMILY_MAP_SCHEMA = "szl.database-braid-family-map/v1"
FAMILY = re.compile(r"[A-Z][A-Z0-9_]{1,47}\Z")
GLOB = re.compile(r"[A-Za-z0-9_.*?/+@\[\]-]{1,200}\Z")
UNCLASSIFIED = "UNCLASSIFIED"
MAX_REPOSITORIES = 32
MAX_RULES = 200
MAX_CENSUS_BYTES = 16777216
MAX_MAP_BYTES = 1048576
GIT_TIMEOUT_SECONDS = 120
LFS_MAGIC = b"version https://git-lfs.github.com/spec/v1"
_FALSE_FLAGS = ("network_used", "source_code_executed", "provider_writes", "secrets_recorded",
                "remote_head_independently_verified", "proofs_checked_by_this_collector")


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
    """Count ``sorry`` tokens outside Lean comments. Text level only, not a kernel check."""
    code = lean_code_only(raw.decode("utf-8", "replace"))
    return len(re.findall(r"(?<![A-Za-z0-9_.'!?])sorry(?![A-Za-z0-9_'!?])", code))


def _git(directory: Path, *args, stdin: bytes | None = None) -> bytes:
    """Run one fixed, local, read-only git command with a minimal environment."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/"),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
           "LC_ALL": "C"}
    try:
        proc = subprocess.run(["git", "-C", str(directory), *args], input=stdin,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
                              timeout=GIT_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise InputError("CENSUS_GIT_UNAVAILABLE") from None
    require(proc.returncode == 0, "CENSUS_GIT_REFUSED")
    return proc.stdout


def list_tree(directory: Path) -> tuple:
    """``(commit, shallow, [(mode, sha1, size, path)])`` for HEAD of a local checkout."""
    require(directory.is_dir() and not directory.is_symlink(), "CENSUS_CHECKOUT_UNAVAILABLE")
    require(_git(directory, "rev-parse", "--is-inside-work-tree").strip() == b"true",
            "CENSUS_CHECKOUT_UNAVAILABLE")
    commit = _git(directory, "rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip()
    require(SHA40.fullmatch(commit) is not None, "CENSUS_COMMIT_INVALID")
    shallow = _git(directory, "rev-parse", "--is-shallow-repository").strip() == b"true"
    rows = []
    for record in _git(directory, "ls-tree", "-r", "-z", "-l", "--full-tree", commit).split(b"\0"):
        if not record:
            continue
        meta, _, name = record.partition(b"\t")
        fields = meta.split()
        require(len(fields) == 4, "CENSUS_TREE_PARSE_FAILED")
        mode, kind, sha, size = (f.decode("ascii") for f in fields)
        try:
            path = name.decode("utf-8", "strict")
        except UnicodeError:
            raise InputError("CENSUS_PATH_NOT_UTF") from None
        rows.append((mode, kind, sha, size, path))
    return commit, shallow, rows


def read_blobs(directory: Path, shas: list, *, max_bytes: int) -> dict:
    """Committed bytes for each blob id, or ``None`` when over the size cap."""
    if not shas:
        return {}
    raw = _git(directory, "cat-file", "--batch", stdin=("\n".join(shas) + "\n").encode("ascii"))
    out, offset = {}, 0
    for sha in shas:
        end = raw.find(b"\n", offset)
        require(end >= 0, "CENSUS_BLOB_PARSE_FAILED")
        header = raw[offset:end].decode("ascii", "replace").split()
        require(len(header) == 3 and header[0] == sha and header[1] == "blob" and
                header[2].isdigit(), "CENSUS_BLOB_PARSE_FAILED")
        size = int(header[2])
        body = raw[end + 1:end + 1 + size]
        require(len(body) == size, "CENSUS_BLOB_PARSE_FAILED")
        out[sha] = body if size <= max_bytes else None
        offset = end + 1 + size + 1
    return out


def _matches(path, globs) -> bool:
    return any(fnmatchcase(path, g) for g in globs)


def _family(repo_policy, explicit, path) -> str:
    if path in explicit:
        return explicit[path]
    for rule in repo_policy["families"]:
        if fnmatchcase(path, rule["glob"]):
            return rule["family"]
    return UNCLASSIFIED


def census_repository(repo_policy, directory: Path, explicit: dict, *, max_blob_bytes: int) -> tuple:
    """Census one checkout. Returns ``(repository_row, cords, unavailable_cords)``."""
    repository = repo_policy["repository"]
    commit, shallow, rows = list_tree(directory)
    chosen, counts = [], {"tracked": 0, "out_of_scope": 0, "symlink_or_submodule": 0}
    for mode, kind, sha, _size, path in rows:
        counts["tracked"] += 1
        if kind != "blob" or mode not in ("100644", "100755"):
            counts["symlink_or_submodule"] += 1
        elif _matches(path, repo_policy["include"]) and not _matches(path, repo_policy["exclude"]):
            require(SHA40.fullmatch(sha) is not None, "CENSUS_TREE_PARSE_FAILED")
            chosen.append((path, sha))
        else:
            counts["out_of_scope"] += 1
    blobs = read_blobs(directory, sorted({sha for _, sha in chosen}), max_bytes=max_blob_bytes)
    cords, unavailable = [], []
    for path, sha in sorted(chosen):
        body = blobs[sha]
        key = cord_key(repository, path)
        if body is None:
            unavailable.append({"key": key, "reason": "BLOB_OVER_SIZE_CAP"})
            continue
        # Git's blob id is recomputed over the bytes actually read from the object store.
        require(git_blob_sha1(body) == sha, "CENSUS_BLOB_ID_MISMATCH")
        pointer = body.startswith(LFS_MAGIC)
        if pointer:
            unavailable.append({"key": key, "reason": "LFS_POINTER_CONTENT_ABSENT"})
            continue
        lean = path.endswith(".lean")
        cords.append({
            "key": key, "repository": repository, "path": path, "blob_sha1": sha,
            "sha256": sha256_hex(body), "bytes": len(body),
            "family": _family(repo_policy, explicit, path), "is_lean": lean,
            "lean_text_sorry_tokens": lean_text_sorry_tokens(body) if lean else 0,
        })
    row = {"repository": repository, "state": "OBSERVED", "commit": commit, "shallow": shallow,
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
            rows.append({"repository": name, "state": "UNAVAILABLE", "commit": None,
                         "shallow": None, "tracked_files": None, "in_scope_files": None,
                         "out_of_scope_files": None, "symlink_or_submodule_entries": None,
                         "cords": None, "unavailable_cords": None})
            continue
        row, found, missing = census_repository(repo, Path(directory), explicit.get(name, {}),
                                                max_blob_bytes=section["max_blob_bytes"])
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
    validate_census(report, section)
    return report


def validate_census(value, section) -> list:
    """Closed-schema check of a census report against the policy. Returns its cords."""
    repos = validate_census_policy(section)
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
        closed(row, ("repository", "state", "commit", "shallow", "tracked_files",
                     "in_scope_files", "out_of_scope_files", "symlink_or_submodule_entries",
                     "cords", "unavailable_cords"), "CENSUS_REPOSITORY_FIELDS_INVALID")
        if row["state"] == "OBSERVED":
            require(type(row["commit"]) is str and SHA40.fullmatch(row["commit"]) and
                    type(row["shallow"]) is bool, "CENSUS_REPOSITORY_FIELDS_INVALID")
            for field in ("tracked_files", "in_scope_files", "out_of_scope_files",
                          "symlink_or_submodule_entries", "cords", "unavailable_cords"):
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
        require(cord["repository"] in counted and type(cord["path"]) is str and
                cord["key"] == cord_key(cord["repository"], cord["path"]) and
                type(cord["blob_sha1"]) is str and SHA40.fullmatch(cord["blob_sha1"]) and
                type(cord["sha256"]) is str and SHA64.fullmatch(cord["sha256"]) and
                type(cord["family"]) is str and FAMILY.fullmatch(cord["family"]) and
                type(cord["is_lean"]) is bool and
                cord["is_lean"] == cord["path"].endswith(".lean"), "CENSUS_CORD_FIELDS_INVALID")
        natural(cord["bytes"], "CENSUS_CORD_FIELDS_INVALID", maximum=section["max_blob_bytes"])
        natural(cord["lean_text_sorry_tokens"], "CENSUS_CORD_FIELDS_INVALID", maximum=10 ** 6)
        require(cord["is_lean"] or cord["lean_text_sorry_tokens"] == 0,
                "CENSUS_CORD_FIELDS_INVALID")
        keys.append(cord["key"])
        per_repo[cord["repository"]] = per_repo.get(cord["repository"], 0) + 1
    require(keys == sorted(set(keys)), "CENSUS_CORD_ORDER_OR_DUPLICATE")
    missing = value["unavailable_cords"]
    require(type(missing) is list, "CENSUS_CORDS_INVALID")
    missing_keys = []
    for item in missing:
        closed(item, ("key", "reason"), "CENSUS_CORD_FIELDS_INVALID")
        require(type(item["key"]) is str and item["reason"] in (
            "BLOB_OVER_SIZE_CAP", "LFS_POINTER_CONTENT_ABSENT"), "CENSUS_CORD_FIELDS_INVALID")
        missing_keys.append(item["key"])
    require(missing_keys == sorted(set(missing_keys)) and not set(keys) & set(missing_keys),
            "CENSUS_CORD_ORDER_OR_DUPLICATE")
    require(all(per_repo.get(name, 0) == pair[0] for name, pair in counted.items()) and
            sum(pair[1] for pair in counted.values()) == len(missing),
            "CENSUS_CORD_COUNT_MISMATCH")
    observed = sum(r["state"] == "OBSERVED" for r in rows)
    require(value["repositories_required"] == len(rows) and
            value["repositories_observed"] == observed and
            (value["state"] == "COMPLETE") == (observed == len(rows) and not missing) and
            value["state"] in ("COMPLETE", "PARTIAL"), "CENSUS_STATE_INVALID")
    return cords


def main(argv=None):
    ap = argparse.ArgumentParser(description="Byte-checked source census from local git checkouts")
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--family-map", type=Path)
    ap.add_argument("--checkout", action="append", default=[], metavar="REPOSITORY=DIRECTORY")
    ap.add_argument("--output", type=Path, required=True)
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
