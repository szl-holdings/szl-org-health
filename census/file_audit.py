"""Complete default-branch repository and file audit for one GitHub organization.

The audit proves two distinct things without conflating them:

* inventory completeness: every repository visible to the organization reader and
  every entry in each default-branch Git tree is enumerated; and
* byte integrity: every tracked blob is recovered from GitHub's immutable commit
  archive, checked against its Git blob SHA-1, and committed into a SHA-256 evidence
  receipt. CRLF exports are inverted only when the recovered bytes exactly match
  the declared Git object; the original archive member hashes remain recorded.

High-signal UTF-8 source files are additionally inspected for supply-chain and
unfinished-work patterns. Binary and oversized text blobs are still fully hashed;
they are never silently described as source-inspected. Submodules remain explicit
commit pointers and are not recursively trusted or fetched.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import hashlib
import io
import json
import posixpath
import re
import sys
import tarfile
import urllib.parse
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from .common import request_bytes, request_json, token_header
from .github_inventory import discover_repositories

SCHEMA = "szl.repository-file-audit/v2"
PUBLIC_SCHEMA = "szl.repository-file-audit-public/v3"
GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
DEFAULT_ORG = "szl-holdings"
DEFAULT_MAX_WORKERS = 4
DEFAULT_MAX_TEXT_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_REPOSITORY_BYTES = 4 * 1024 * 1024 * 1024
DEFAULT_MINIMUM_REPOSITORIES = 1
MAX_REPOSITORY_PAGES = 20
MAX_TREE_NODES = 2_000_000
MAX_TREE_DEPTH = 256
MAX_FINDINGS_PER_REPOSITORY = 100_000
MAX_REPORT_FILES = 2_000_000
SHA40 = re.compile(r"^[0-9a-f]{40}$")
REMOTE_ACTION = re.compile(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)")
PINNED_ACTION_REF = re.compile(r"^[^/@\s]+/[^@\s]+@[0-9a-fA-F]{40}$")
CODE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".css", ".go", ".h", ".hpp", ".html",
    ".java", ".js", ".jsx", ".kt", ".kts", ".lean", ".lua", ".mjs",
    ".php", ".ps1", ".psm1", ".psd1", ".py", ".rb", ".rs", ".scala", ".sh", ".sql", ".swift",
    ".toml", ".ts", ".tsx", ".vue", ".xml", ".yaml", ".yml",
}
TEXT_EXTENSIONS = CODE_EXTENSIONS | {
    ".cfg", ".conf", ".csv", ".dockerignore", ".env.example", ".gitattributes",
    ".gitignore", ".ini", ".json", ".jsonl", ".lock", ".md", ".properties",
    ".rst", ".svg", ".txt",
}
TEXT_BASENAMES = {
    "CODEOWNERS", "CONTRIBUTING", "Dockerfile", "LICENSE", "Makefile",
    "NOTICE", "README", "SECURITY", "Taskfile", "justfile",
}
SECRET_LIKE_BASENAMES = {
    ".env", ".npmrc", ".pypirc", "credentials", "credentials.json", "id_dsa",
    "id_ed25519", "id_rsa", "secrets.json", "service-account.json",
}
SECRET_LIKE_SUFFIXES = (
    ".key", ".p12", ".pfx", ".pem", ".ppk", ".jks", ".keystore",
)
BAND_AID_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("temporary-repair", re.compile(r"(?i)\btemporary\s+(?:repair|fix|shim|workflow)\b")),
    ("ephemeral-shim", re.compile(r"(?i)\bephemeral\s+(?:compatibility\s+)?shim\b")),
    ("one-shot-controller", re.compile(r"(?i)\bone[- ]shot\s+(?:workflow|controller|repair)\b")),
    ("self-delete", re.compile(r"(?i)(?:git\s+rm|unlink\(|remove\().{0,80}(?:workflow|sitecustomize|self)")),
    ("bandaid-marker", re.compile(r"(?i)\b(?:band[- ]?aid|workaround|hotfix-only)\b")),
)
DANGEROUS_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("remote-shell-pipe", re.compile(r"(?i)(?:curl|wget)[^\n|]{0,240}\|\s*(?:ba)?sh\b"), "critical"),
    ("disabled-tls-verification", re.compile(r"(?i)(?:verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|curl\s+[^\n]*\s-k(?:\s|$))"), "high"),
    ("python-shell-true", re.compile(r"(?i)subprocess\.(?:run|call|Popen|check_output)\([^\n]{0,300}shell\s*=\s*True"), "high"),
    ("yaml-unsafe-load", re.compile(r"(?i)yaml\.load\([^\n]{0,200}(?:Loader\s*=\s*yaml\.Loader|$)"), "high"),
    ("pickle-load", re.compile(r"(?i)\bpickle\.loads?\("), "medium"),
    ("workflow-write-all", re.compile(r"(?mi)^\s*permissions\s*:\s*write-all\s*$"), "high"),
    ("pull-request-target", re.compile(r"(?mi)^\s*pull_request_target\s*:"), "high"),
)
TODO_PATTERN = re.compile(r"(?i)\b(TODO|FIXME|HACK|XXX)\b")
FROM_PATTERN = re.compile(r"(?mi)^\s*FROM\s+([^\s]+)")
IMAGE_PATTERN = re.compile(r"(?mi)^\s*image\s*:\s*['\"]?([^\s'\"]+)")
SPDX_PATTERN = re.compile(r"SPDX-License-Identifier\s*:")


class AuditError(RuntimeError):
    """The collector could not prove a complete bounded audit."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def github_headers() -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        **token_header(("SZL_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")),
    }


def _request_json(
    path: str,
    *,
    timeout: float = 30.0,
    max_bytes: int = 16 * 1024 * 1024,
) -> tuple[Any | None, str | None]:
    value, _, error = request_json(
        f"{GITHUB_API}{path}",
        headers=github_headers(),
        timeout=timeout,
        retries=2,
        max_bytes=max_bytes,
    )
    return value, error


def _encoded_repository(repository: str) -> str:
    parts = repository.split("/", 1)
    if len(parts) != 2 or any(not part for part in parts):
        raise AuditError(f"invalid repository identity: {repository!r}")
    return "/".join(urllib.parse.quote(part, safe="") for part in parts)


def _visibility(repo: Mapping[str, Any]) -> str:
    explicit = repo.get("visibility")
    if explicit in {"public", "private", "internal"}:
        return str(explicit)
    private = repo.get("private")
    return "private" if private is True else "public" if private is False else "unknown"


def list_repositories(org: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    values, org_value, error = discover_repositories(
        org,
        headers=github_headers(),
        timeout=30.0,
        retries=2,
        max_pages=MAX_REPOSITORY_PAGES,
    )
    if error:
        raise AuditError(f"repository pagination incomplete: {error}")
    if not isinstance(values, list):
        raise AuditError("repository pagination did not return an array")
    repositories = [row for row in values if isinstance(row, dict)]
    identities = [str(row.get("full_name") or "") for row in repositories]
    if not repositories or any(not item.startswith(f"{org}/") for item in identities):
        raise AuditError("repository inventory is empty or contains a foreign owner")
    if len(identities) != len(set(identities)):
        raise AuditError("repository inventory contains duplicate identities")

    reconciliation: dict[str, Any] = {
        "observed_repository_count": len(repositories),
        "observed_public_count": sum(_visibility(row) == "public" for row in repositories),
        "observed_private_or_internal_count": sum(
            _visibility(row) in {"private", "internal"} for row in repositories
        ),
        "authoritative_count_available": False,
        "authoritative_expected_count": None,
        "matched": None,
        "error": None,
    }
    reconciliation.update(_reconcile_counts(org_value, len(repositories)))
    return repositories, reconciliation


def _nonneg_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _reconcile_counts(org_value: Any, observed: int) -> dict[str, Any]:
    """Reconcile an owned-repository enumeration against the org's own counters.

    GitHub exposes two private-repository counters that can legitimately disagree:
    ``owned_private_repos`` (repositories the org owns) and ``total_private_repos``
    (plan-quota shaped). A ``type=all`` enumeration returns owned repositories, so
    ``owned_private_repos`` is the apples-to-apples counter and is preferred. The
    other is still evaluated: a match against either counter is a match, so a
    counter-semantics difference alone can no longer manufacture a mismatch, while a
    genuine inventory gap -- an observation matching neither -- still fails closed.
    """
    out: dict[str, Any] = {
        "authoritative_count_available": False,
        "authoritative_expected_count": None,
        "authoritative_expected_counts": None,
        "authoritative_counter_used": None,
        "counters_disagree": None,
        "matched": None,
        "error": None,
    }
    if not isinstance(org_value, dict):
        return out
    public_count = org_value.get("public_repos")
    if not _nonneg_int(public_count):
        return out
    expectations = {
        name: public_count + org_value[name]
        for name in ("owned_private_repos", "total_private_repos")
        if _nonneg_int(org_value.get(name))
    }
    if not expectations:
        return out
    preferred = "owned_private_repos" if "owned_private_repos" in expectations else "total_private_repos"
    matching = [name for name in ("owned_private_repos", "total_private_repos")
                if expectations.get(name) == observed]
    out.update(
        {
            "authoritative_count_available": True,
            "authoritative_expected_count": expectations[matching[0]] if matching else expectations[preferred],
            "authoritative_expected_counts": dict(expectations),
            "authoritative_counter_used": matching[0] if matching else None,
            "counters_disagree": len(set(expectations.values())) > 1,
            "matched": bool(matching),
            "error": None,
        }
    )
    return out


def _validate_tree_entry(entry: Mapping[str, Any], repository: str) -> dict[str, Any]:
    path = str(entry.get("path") or "")
    kind = str(entry.get("type") or "")
    sha = str(entry.get("sha") or "").lower()
    mode = str(entry.get("mode") or "")
    size = entry.get("size")
    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        raise AuditError(f"{repository}: malformed tree path")
    normalized = posixpath.normpath(path)
    if normalized != path or normalized == ".." or normalized.startswith("../"):
        raise AuditError(f"{repository}: traversal-like tree path")
    if kind not in {"blob", "tree", "commit"} or not SHA40.fullmatch(sha):
        raise AuditError(f"{repository}: malformed tree entry for {path}")
    if kind == "blob" and (
        isinstance(size, bool) or not isinstance(size, int) or size < 0
    ):
        raise AuditError(f"{repository}: blob size unavailable for {path}")
    return {"path": path, "type": kind, "sha": sha, "mode": mode, "size": size}


def _root_tree_sha(repository: str, default_branch: str) -> tuple[str, str]:
    encoded_repo = _encoded_repository(repository)
    branch = urllib.parse.quote(default_branch, safe="")
    value, error = _request_json(f"/repos/{encoded_repo}/branches/{branch}")
    if error or not isinstance(value, dict):
        raise AuditError(
            f"{repository}: default branch unresolved ({error or 'invalid response'})"
        )
    commit_sha = str((value.get("commit") or {}).get("sha") or "").lower()
    if not SHA40.fullmatch(commit_sha):
        raise AuditError(f"{repository}: default branch commit SHA unavailable")
    commit, commit_error = _request_json(
        f"/repos/{encoded_repo}/git/commits/{commit_sha}"
    )
    if commit_error or not isinstance(commit, dict):
        raise AuditError(
            f"{repository}: commit tree unresolved ({commit_error or 'invalid response'})"
        )
    tree_sha = str((commit.get("tree") or {}).get("sha") or "").lower()
    if not SHA40.fullmatch(tree_sha):
        raise AuditError(f"{repository}: root tree SHA unavailable")
    return commit_sha, tree_sha


def _tree_request(repository: str, tree_sha: str, *, recursive: bool) -> dict[str, Any]:
    encoded_repo = _encoded_repository(repository)
    suffix = "?recursive=1" if recursive else ""
    value, error = _request_json(
        f"/repos/{encoded_repo}/git/trees/{tree_sha}{suffix}"
    )
    if error or not isinstance(value, dict):
        raise AuditError(
            f"{repository}: tree {tree_sha} unavailable ({error or 'invalid response'})"
        )
    return value


def walk_repository_tree(
    repository: str,
    default_branch: str,
) -> tuple[str, str, list[dict[str, Any]], str]:
    """Return commit SHA, root tree SHA, every entry, and completeness proof."""
    commit_sha, root_sha = _root_tree_sha(repository, default_branch)
    try:
        recursive = _tree_request(repository, root_sha, recursive=True)
    except AuditError:
        recursive = {"truncated": True}
    raw = recursive.get("tree")
    if recursive.get("truncated") is not True and isinstance(raw, list):
        entries = [
            _validate_tree_entry(row, repository)
            for row in raw
            if isinstance(row, dict)
        ]
        if len(entries) != len(raw):
            raise AuditError(f"{repository}: recursive tree contains non-object entries")
        if len(entries) > MAX_TREE_NODES:
            raise AuditError(f"{repository}: recursive tree exceeds node ceiling")
        entries.sort(key=lambda item: item["path"])
        return commit_sha, root_sha, entries, "recursive-tree"

    queue: list[tuple[str, str, int]] = [("", root_sha, 0)]
    entries: list[dict[str, Any]] = []
    seen_trees: set[tuple[str, str]] = set()
    while queue:
        prefix, tree_sha, depth = queue.pop()
        if depth > MAX_TREE_DEPTH:
            raise AuditError(f"{repository}: tree depth exceeds {MAX_TREE_DEPTH}")
        identity = (prefix, tree_sha)
        if identity in seen_trees:
            raise AuditError(f"{repository}: repeated tree identity at {prefix or '.'}")
        seen_trees.add(identity)
        value = _tree_request(repository, tree_sha, recursive=False)
        rows = value.get("tree")
        if value.get("truncated") is True or not isinstance(rows, list):
            raise AuditError(f"{repository}: non-recursive tree is incomplete")
        for row in rows:
            if not isinstance(row, dict):
                raise AuditError(f"{repository}: non-object tree entry")
            item = _validate_tree_entry(row, repository)
            full_path = f"{prefix}/{item['path']}" if prefix else item["path"]
            item = {**item, "path": full_path}
            entries.append(item)
            if item["type"] == "tree":
                queue.append((full_path, item["sha"], depth + 1))
            if len(entries) > MAX_TREE_NODES:
                raise AuditError(f"{repository}: tree exceeds node ceiling")
    entries.sort(key=lambda item: item["path"])
    return commit_sha, root_sha, entries, "explicit-subtree-walk"


def _safe_archive_path(name: str, root_prefix: str) -> str | None:
    if not name or "\\" in name or "\x00" in name or name.startswith("/"):
        raise AuditError("archive contains an invalid absolute or ambiguous path")
    raw = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in raw.parts):
        raise AuditError("archive contains a traversal-like path")
    if not raw.parts or raw.parts[0] != root_prefix:
        raise AuditError("archive root prefix changed")
    if len(raw.parts) == 1:
        return None
    relative = PurePosixPath(*raw.parts[1:]).as_posix()
    if posixpath.normpath(relative) != relative:
        raise AuditError("archive contains a non-canonical path")
    return relative


def _git_blob_sha1(size: int, chunks: Iterable[bytes]) -> tuple[str, str, bytes | None]:
    git_hash = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    git_hash.update(f"blob {size}\0".encode("ascii"))
    collected: list[bytes] = []
    total = 0
    for chunk in chunks:
        total += len(chunk)
        git_hash.update(chunk)
        sha256.update(chunk)
        collected.append(chunk)
    if total != size:
        raise AuditError("archive member ended before its declared size")
    return git_hash.hexdigest(), sha256.hexdigest(), b"".join(collected)


def _member_chunks(stream: Any, size: int, *, normalize_crlf: bool) -> Iterable[bytes]:
    remaining = size
    pending = b""
    while remaining:
        chunk = stream.read(min(1024 * 1024, remaining))
        if not chunk:
            raise AuditError("archive member ended before its declared size")
        remaining -= len(chunk)
        if normalize_crlf:
            chunk = pending + chunk
            # Preserve a CR at the chunk boundary until its following byte arrives.
            pending = b"\r" if chunk.endswith(b"\r") else b""
            if pending:
                chunk = chunk[:-1]
            chunk = chunk.replace(b"\r\n", b"\n")
        yield chunk
    if stream.read(1):
        raise AuditError("archive member exceeds its declared size")
    if pending:
        yield pending


def _stream_member(
    stream: Any,
    *,
    size: int,
    collect: bool,
    archive_size: int | None = None,
) -> tuple[str, str, bytes | None]:
    git_hash = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    git_hash.update(f"blob {size}\0".encode("ascii"))
    collected = bytearray() if collect else None
    total = 0
    for chunk in _member_chunks(
        stream,
        size if archive_size is None else archive_size,
        normalize_crlf=archive_size is not None,
    ):
        total += len(chunk)
        if total > size:
            raise AuditError("archive member exceeds its declared Git blob size")
        git_hash.update(chunk)
        sha256.update(chunk)
        if collected is not None:
            collected.extend(chunk)
    if total != size:
        raise AuditError("archive member does not match its declared Git blob size")
    return git_hash.hexdigest(), sha256.hexdigest(), bytes(collected) if collected is not None else None


def download_commit_archive(
    repository: str,
    commit_sha: str,
    *,
    max_archive_bytes: int,
) -> bytes:
    encoded_repo = _encoded_repository(repository)
    raw, _, error = request_bytes(
        f"{GITHUB_API}/repos/{encoded_repo}/tarball/{commit_sha}",
        headers=github_headers(),
        timeout=120.0,
        retries=2,
        max_bytes=max_archive_bytes,
    )
    if error or raw is None:
        raise AuditError(
            f"{repository}: immutable commit archive unavailable ({error or 'empty'})"
        )
    return raw


def classify_path(path: str) -> str:
    lowered = path.casefold()
    base = posixpath.basename(path)
    suffix = Path(base).suffix.casefold()
    if lowered.startswith(".github/workflows/") and suffix in {".yml", ".yaml"}:
        return "workflow"
    if base.casefold().startswith("dockerfile") or lowered.endswith("/dockerfile"):
        return "container"
    if lowered.startswith("tests/") or "/tests/" in lowered or base.casefold().startswith("test_"):
        return "test"
    if base.casefold().startswith("readme") or lowered.startswith("docs/") or suffix in {".md", ".rst"}:
        return "documentation"
    if base in TEXT_BASENAMES or suffix in TEXT_EXTENSIONS:
        return "source" if suffix in CODE_EXTENSIONS else "text"
    return "artifact"


def is_text_candidate(path: str, size: int, max_text_bytes: int) -> bool:
    if size > max_text_bytes:
        return False
    base = posixpath.basename(path)
    suffix = Path(base).suffix.casefold()
    return (
        base in TEXT_BASENAMES
        or suffix in TEXT_EXTENSIONS
        or base.casefold().startswith("dockerfile")
    )


def _line_number(text: str, index: int) -> int:
    return text.count("\n", 0, max(0, index)) + 1


def _mutable_image(reference: str) -> bool:
    value = reference.strip().rstrip(",")
    if not value or "${{" in value or value.startswith("$"):
        return False
    if "@sha256:" in value:
        return False
    return value.casefold() != "scratch"


def _finding(
    repository: str,
    visibility: str,
    path: str,
    rule: str,
    severity: str,
    *,
    line: int | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "repository": repository,
        "visibility": visibility,
        "path": path,
        "rule": rule,
        "severity": severity,
    }
    if line is not None:
        value["line"] = line
    if detail:
        value["detail"] = detail[:240]
    return value


def inspect_text(
    repository: str,
    visibility: str,
    path: str,
    text: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    role = classify_path(path)

    if role == "workflow":
        for match in REMOTE_ACTION.finditer(text):
            action = match.group(1).strip().strip("'\"")
            if action.startswith("./") or PINNED_ACTION_REF.fullmatch(action):
                continue
            findings.append(
                _finding(
                    repository,
                    visibility,
                    path,
                    "unpinned-github-action",
                    "high",
                    line=_line_number(text, match.start()),
                    detail=action,
                )
            )

    if role in {"workflow", "source", "container"}:
        for rule, pattern in BAND_AID_PATTERNS:
            for match in pattern.finditer(text):
                findings.append(
                    _finding(
                        repository,
                        visibility,
                        path,
                        rule,
                        "high",
                        line=_line_number(text, match.start()),
                    )
                )

    for rule, pattern, severity in DANGEROUS_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(
                _finding(
                    repository,
                    visibility,
                    path,
                    rule,
                    severity,
                    line=_line_number(text, match.start()),
                )
            )

    if role in {"workflow", "source", "container", "test"}:
        for match in TODO_PATTERN.finditer(text):
            findings.append(
                _finding(
                    repository,
                    visibility,
                    path,
                    "unfinished-marker",
                    "low",
                    line=_line_number(text, match.start()),
                    detail=match.group(1).upper(),
                )
            )

    if role in {"workflow", "container"}:
        for pattern in (FROM_PATTERN, IMAGE_PATTERN):
            for match in pattern.finditer(text):
                reference = match.group(1)
                if _mutable_image(reference):
                    findings.append(
                        _finding(
                            repository,
                            visibility,
                            path,
                            "mutable-container-image",
                            "medium",
                            line=_line_number(text, match.start()),
                            detail=reference,
                        )
                    )

    if role in {"source", "test"} and Path(path).suffix.casefold() in CODE_EXTENSIONS:
        head = "\n".join(text.splitlines()[:12])
        if not SPDX_PATTERN.search(head):
            findings.append(
                _finding(
                    repository,
                    visibility,
                    path,
                    "missing-spdx-header",
                    "low",
                )
            )
    return findings


def _archive_file_records(
    repository: str,
    visibility: str,
    archive: bytes,
    tree_entries: Sequence[Mapping[str, Any]],
    *,
    max_text_bytes: int,
    max_repository_bytes: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int], str]:
    blobs = {
        str(item["path"]): item
        for item in tree_entries
        if item.get("type") == "blob"
    }
    if len(blobs) > MAX_REPORT_FILES:
        raise AuditError(f"{repository}: file count exceeds report ceiling")
    expected_bytes = sum(int(item.get("size") or 0) for item in blobs.values())
    if expected_bytes > max_repository_bytes:
        raise AuditError(
            f"{repository}: tracked bytes {expected_bytes} exceed repository ceiling {max_repository_bytes}"
        )

    files: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    role_counts: dict[str, int] = {}
    observed_paths: set[str] = set()
    archive_sha256 = hashlib.sha256(archive).hexdigest()

    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as bundle:
        members = bundle.getmembers()
        if not members:
            if blobs:
                raise AuditError(f"{repository}: non-empty tree has an empty archive")
            return files, findings, role_counts, archive_sha256
        root_prefix = PurePosixPath(members[0].name).parts[0]
        if not root_prefix:
            raise AuditError(f"{repository}: archive root prefix unavailable")

        for member in members:
            relative = _safe_archive_path(member.name.rstrip("/"), root_prefix)
            if relative is None or member.isdir():
                continue
            if member.islnk() or member.ischr() or member.isblk() or member.isfifo():
                raise AuditError(f"{repository}: forbidden archive member type at {relative}")
            if not (member.isfile() or member.issym()):
                raise AuditError(f"{repository}: unsupported archive member type at {relative}")
            if relative in observed_paths:
                raise AuditError(f"{repository}: duplicate archive path {relative}")
            expected = blobs.get(relative)
            if expected is None:
                raise AuditError(f"{repository}: archive contains path absent from Git tree: {relative}")
            observed_paths.add(relative)

            expected_size = int(expected["size"])
            collect = is_text_candidate(relative, expected_size, max_text_bytes)
            export_evidence: dict[str, Any] = {}
            if member.issym():
                raw = member.linkname.encode("utf-8", errors="surrogateescape")
                if expected.get("mode") != "120000":
                    raise AuditError(f"{repository}: unexpected archive symlink for {relative}")
                if len(raw) != expected_size:
                    raise AuditError(f"{repository}: symlink size mismatch for {relative}")
                git_sha1, content_sha256, collected = _git_blob_sha1(
                    expected_size,
                    (raw,),
                )
            else:
                if expected.get("mode") == "120000":
                    raise AuditError(f"{repository}: symlink materialized as a regular file: {relative}")
                if member.size < expected_size or member.size > 2 * expected_size:
                    raise AuditError(f"{repository}: archive size mismatch for {relative}")
                stream = bundle.extractfile(member)
                if stream is None:
                    raise AuditError(f"{repository}: archive content unavailable for {relative}")
                git_sha1, content_sha256, collected = _stream_member(
                    stream,
                    size=member.size,
                    collect=collect and member.size == expected_size,
                )
                if member.size != expected_size:
                    export_evidence = {
                        "archive_transform": "crlf-to-lf",
                        "archive_size": member.size,
                        "archive_git_blob_sha1": git_sha1,
                        "archive_content_sha256": content_sha256,
                    }
                    stream = bundle.extractfile(member)
                    if stream is None:
                        raise AuditError(f"{repository}: archive content unavailable for {relative}")
                    git_sha1, content_sha256, collected = _stream_member(
                        stream,
                        size=expected_size,
                        collect=collect,
                        archive_size=member.size,
                    )

            if git_sha1 != expected.get("sha"):
                raise AuditError(f"{repository}: Git blob digest mismatch for {relative}")

            role = classify_path(relative)
            role_counts[role] = role_counts.get(role, 0) + 1
            inspection = "hashed-binary-or-unclassified"
            if collect and collected is not None:
                if b"\x00" in collected[:8192]:
                    inspection = "hashed-binary"
                else:
                    try:
                        text = collected.decode("utf-8")
                    except UnicodeDecodeError:
                        inspection = "hashed-non-utf8"
                    else:
                        inspection = "hashed-and-source-inspected"
                        findings.extend(
                            inspect_text(repository, visibility, relative, text)
                        )
            elif expected_size > max_text_bytes and (
                Path(relative).suffix.casefold() in TEXT_EXTENSIONS
                or posixpath.basename(relative) in TEXT_BASENAMES
            ):
                inspection = "hashed-text-size-bound"

            base = posixpath.basename(relative).casefold()
            if base in SECRET_LIKE_BASENAMES or base.endswith(SECRET_LIKE_SUFFIXES):
                findings.append(
                    _finding(
                        repository,
                        visibility,
                        relative,
                        "secret-like-tracked-path",
                        "critical",
                    )
                )

            files.append(
                {
                    "path": relative,
                    "mode": expected.get("mode"),
                    "size": expected_size,
                    "role": role,
                    "git_blob_sha1": git_sha1,
                    "content_sha256": content_sha256,
                    "inspection": inspection,
                    **export_evidence,
                }
            )
            if len(findings) > MAX_FINDINGS_PER_REPOSITORY:
                raise AuditError(f"{repository}: finding ceiling exceeded")

    missing = sorted(set(blobs) - observed_paths)
    if missing:
        preview = ", ".join(missing[:3])
        raise AuditError(
            f"{repository}: archive omitted {len(missing)} Git blobs ({preview})"
        )
    files.sort(key=lambda item: item["path"])
    return files, findings, dict(sorted(role_counts.items())), archive_sha256


def audit_repository(
    repo: Mapping[str, Any],
    *,
    max_text_bytes: int,
    max_archive_bytes: int,
    max_repository_bytes: int,
    archive_provider: Callable[..., bytes] = download_commit_archive,
) -> dict[str, Any]:
    repository = str(repo.get("full_name") or "")
    visibility = _visibility(repo)
    default_branch = str(repo.get("default_branch") or "")
    result: dict[str, Any] = {
        "repository": repository,
        "visibility": visibility,
        "private": repo.get("private") if type(repo.get("private")) is bool else None,
        "archived": repo.get("archived") is True,
        "default_branch": default_branch or None,
        "state": "INCOMPLETE",
        "commit_sha": None,
        "tree_sha": None,
        "tree_proof": None,
        "archive_sha256": None,
        "entry_count": 0,
        "file_count": 0,
        "directory_count": 0,
        "submodule_count": 0,
        "bytes_tracked": 0,
        "role_counts": {},
        "files": [],
        "submodules": [],
        "findings": [],
        "errors": [],
    }
    if not repository or "/" not in repository:
        result["errors"].append("repository identity unavailable")
        return result
    if not default_branch:
        result["errors"].append("default branch unavailable")
        return result

    try:
        commit_sha, tree_sha, entries, proof = walk_repository_tree(
            repository,
            default_branch,
        )
        archive = archive_provider(
            repository,
            commit_sha,
            max_archive_bytes=max_archive_bytes,
        )
        files, findings, roles, archive_sha256 = _archive_file_records(
            repository,
            visibility,
            archive,
            entries,
            max_text_bytes=max_text_bytes,
            max_repository_bytes=max_repository_bytes,
        )
    except (AuditError, tarfile.TarError) as exc:
        result["errors"].append(str(exc)[:480])
        return result

    submodules = [
        {
            "path": str(item["path"]),
            "gitlink_commit_sha1": str(item["sha"]),
            "mode": str(item["mode"]),
            "content_audited": False,
        }
        for item in entries
        if item.get("type") == "commit"
    ]
    for item in submodules:
        findings.append(
            _finding(
                repository,
                visibility,
                item["path"],
                "git-submodule-not-recursively-audited",
                "medium",
            )
        )

    result.update(
        {
            "commit_sha": commit_sha,
            "tree_sha": tree_sha,
            "tree_proof": proof,
            "archive_sha256": archive_sha256,
            "entry_count": len(entries),
            "file_count": len(files),
            "directory_count": sum(item.get("type") == "tree" for item in entries),
            "submodule_count": len(submodules),
            "bytes_tracked": sum(int(item["size"]) for item in files),
            "role_counts": roles,
            "files": files,
            "submodules": submodules,
            "findings": findings[:MAX_FINDINGS_PER_REPOSITORY],
            "errors": [],
        }
    )
    severities = {str(item.get("severity")) for item in findings}
    if "critical" in severities or "high" in severities:
        result["state"] = "FAIL"
    elif findings:
        result["state"] = "WARN"
    else:
        result["state"] = "PASS"
    result["repository_receipt_sha256"] = sha256_json(
        {key: value for key, value in result.items() if key != "repository_receipt_sha256"}
    )
    return result


def summarize(repositories: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    state_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    inspection_counts: dict[str, int] = {}
    totals = {
        "repositories": len(repositories),
        "entries": 0,
        "files": 0,
        "directories": 0,
        "submodules": 0,
        "bytes_tracked_and_verified": 0,
        "findings": 0,
    }
    for repo in repositories:
        state = str(repo.get("state") or "INCOMPLETE")
        state_counts[state] = state_counts.get(state, 0) + 1
        totals["entries"] += int(repo.get("entry_count") or 0)
        totals["files"] += int(repo.get("file_count") or 0)
        totals["directories"] += int(repo.get("directory_count") or 0)
        totals["submodules"] += int(repo.get("submodule_count") or 0)
        totals["bytes_tracked_and_verified"] += int(repo.get("bytes_tracked") or 0)
        for file_row in repo.get("files") or []:
            if isinstance(file_row, Mapping):
                inspection = str(file_row.get("inspection") or "unknown")
                inspection_counts[inspection] = inspection_counts.get(inspection, 0) + 1
        for finding in repo.get("findings") or []:
            if not isinstance(finding, Mapping):
                continue
            severity = str(finding.get("severity") or "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            totals["findings"] += 1
    overall = (
        "INCOMPLETE"
        if state_counts.get("INCOMPLETE")
        else "FAIL"
        if state_counts.get("FAIL")
        else "WARN"
        if state_counts.get("WARN")
        else "PASS"
    )
    return {
        "state": overall,
        "state_counts": dict(sorted(state_counts.items())),
        "severity_counts": dict(sorted(severity_counts.items())),
        "inspection_counts": dict(sorted(inspection_counts.items())),
        "totals": totals,
    }


def _public_fields(value: Mapping[str, Any], fields: Sequence[str]) -> dict[str, Any]:
    """Copy only bounded scalar evidence; never arbitrary nested extensions."""
    result = {}
    for field in fields:
        item = value.get(field)
        numeric = field in {"entry_count", "file_count", "directory_count", "submodule_count",
                            "bytes_tracked", "size", "line"}
        if numeric:
            if type(item) is int and item >= 0:
                result[field] = item
        elif item is None or type(item) is bool:
            result[field] = item
        elif type(item) is int and item >= 0:
            result[field] = item
        elif isinstance(item, str) and len(item) <= 4096:
            result[field] = item
    return result


def _public_repository(repo: Mapping[str, Any]) -> dict[str, Any]:
    value = _public_fields(repo, (
        "repository", "visibility", "private", "archived", "default_branch",
        "state", "commit_sha", "tree_sha", "tree_proof", "archive_sha256",
        "entry_count", "file_count", "directory_count", "submodule_count", "bytes_tracked",
    ))
    for name, fields in (
        ("files", ("path", "content_sha256", "git_blob_sha1", "inspection", "mode", "role", "size")),
        ("submodules", ("path", "gitlink_commit_sha1", "mode", "content_audited")),
        ("findings", ("path", "rule", "severity", "line")),
    ):
        value[name] = [
            _public_fields(row, fields)
            for row in repo.get(name) or [] if isinstance(row, Mapping)
        ]
    # Error messages and finding details may contain cross-repository identities.
    value["errors"] = ["SOURCE_UNAVAILABLE"] if repo.get("errors") else []
    if value.get("state") not in {"PASS", "WARN", "FAIL", "INCOMPLETE"} or value["errors"]:
        value["state"] = "INCOMPLETE"
    for field in ("entry_count", "file_count", "directory_count", "submodule_count", "bytes_tracked"):
        if field in repo and (type(repo[field]) is not int or repo[field] < 0):
            value["state"] = "INCOMPLETE"
    roles: dict[str, int] = {}
    for row in value["files"]:
        role = row.get("role")
        if isinstance(role, str):
            roles[role] = roles.get(role, 0) + 1
    value["role_counts"] = dict(sorted(roles.items()))
    # Bind the public fields, rather than disclosing a digest of omitted fields.
    value["repository_receipt_sha256"] = sha256_json(value)
    return value


def public_projection(report: Mapping[str, Any]) -> dict[str, Any]:
    public_repositories: list[dict[str, Any]] = []
    for repo in report.get("repositories") or []:
        if not isinstance(repo, Mapping):
            continue
        if repo.get("private") is not False or repo.get("visibility") != "public":
            continue
        if not isinstance(repo.get("repository"), str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo["repository"]
        ):
            continue
        public_repositories.append(_public_repository(repo))
    summary = summarize(public_repositories)
    if not public_repositories:
        summary["state"] = "INCOMPLETE"
    value: dict[str, Any] = {
        "schema": PUBLIC_SCHEMA,
        "observed_at": report.get("observed_at") if isinstance(report.get("observed_at"), str)
            and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
                             report["observed_at"]) else None,
        "organization": report.get("organization") if isinstance(report.get("organization"), str)
            and re.fullmatch(r"[A-Za-z0-9-]{1,39}", report["organization"]) else None,
        "source": {"scope": "PUBLIC_REPOSITORIES_ONLY", "organization_population": None,
                   "verified_work_counts_are_population": False},
        "inventory_reconciliation": {"authoritative_count_available": False,
                                     "authoritative_expected_count": None, "matched": None},
        "summary": summary,
        "public_repositories": public_repositories,
        "claim_boundary": (
            "Coverage is described by inventory_reconciliation, summary, and per-repository evidence; "
            "this projection does not establish complete enumeration or byte verification. "
            "Missing authoritative inventory or an INCOMPLETE result cannot establish an organization-complete audit. "
            "UTF-8 source inspection remains separately labelled; "
            "submodule targets are external commit pointers and are not recursively trusted."
            " Only literal private=false repositories contribute to this closed public projection; "
            "private-derived counts, states, digests and unknown extensions are excluded. "
            "Pattern findings require source triage and are not verified vulnerabilities."
        ),
    }
    value["receipt_sha256"] = sha256_json(value)
    return value


def run_audit(
    *,
    org: str = DEFAULT_ORG,
    max_workers: int = DEFAULT_MAX_WORKERS,
    max_text_bytes: int = DEFAULT_MAX_TEXT_BYTES,
    max_archive_bytes: int = DEFAULT_MAX_ARCHIVE_BYTES,
    max_repository_bytes: int = DEFAULT_MAX_REPOSITORY_BYTES,
    minimum_repositories: int = DEFAULT_MINIMUM_REPOSITORIES,
    repository_provider: Callable[[str], tuple[list[dict[str, Any]], dict[str, Any]]] = list_repositories,
    repository_auditor: Callable[..., dict[str, Any]] = audit_repository,
) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", org):
        raise AuditError("organization name is invalid")
    for value, label, minimum, maximum in (
        (max_workers, "max_workers", 1, 16),
        (max_text_bytes, "max_text_bytes", 1, 8 * 1024 * 1024),
        (max_archive_bytes, "max_archive_bytes", 1, 2 * 1024 * 1024 * 1024),
        (max_repository_bytes, "max_repository_bytes", 1, 16 * 1024 * 1024 * 1024),
        (minimum_repositories, "minimum_repositories", 1, 100_000),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise AuditError(f"{label} is outside the allowed range")

    inventory, reconciliation = repository_provider(org)
    if len(inventory) < minimum_repositories:
        raise AuditError(
            f"repository inventory {len(inventory)} is below required minimum {minimum_repositories}"
        )
    if reconciliation.get("authoritative_count_available") is True and reconciliation.get("matched") is not True:
        raise AuditError("repository inventory does not match authoritative organization counts")

    results: list[dict[str, Any]] = []
    with cf.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                repository_auditor,
                repo,
                max_text_bytes=max_text_bytes,
                max_archive_bytes=max_archive_bytes,
                max_repository_bytes=max_repository_bytes,
            ): str(repo.get("full_name") or "")
            for repo in inventory
        }
        for future in cf.as_completed(futures):
            identity = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                results.append(
                    {
                        "repository": identity,
                        "visibility": "unknown",
                        "archived": None,
                        "default_branch": None,
                        "state": "INCOMPLETE",
                        "commit_sha": None,
                        "tree_sha": None,
                        "tree_proof": None,
                        "archive_sha256": None,
                        "entry_count": 0,
                        "file_count": 0,
                        "directory_count": 0,
                        "submodule_count": 0,
                        "bytes_tracked": 0,
                        "role_counts": {},
                        "files": [],
                        "submodules": [],
                        "findings": [],
                        "errors": [f"collector exception:{type(exc).__name__}"],
                    }
                )
    results.sort(key=lambda row: str(row.get("repository") or ""))
    observed_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "observed_at": observed_at,
        "organization": org,
        "source": {
            "api": GITHUB_API,
            "credential_present": bool(github_headers().get("Authorization")),
            "repository_pages_max": MAX_REPOSITORY_PAGES,
            "tree_node_ceiling": MAX_TREE_NODES,
            "tree_depth_ceiling": MAX_TREE_DEPTH,
            "max_text_bytes": max_text_bytes,
            "max_archive_bytes": max_archive_bytes,
            "max_repository_bytes": max_repository_bytes,
            "minimum_repositories": minimum_repositories,
            "audit_semantics": "all Git blobs byte-verified; eligible UTF-8 source additionally inspected",
        },
        "inventory_reconciliation": reconciliation,
        "repositories": results,
    }
    report["summary"] = summarize(results)
    report["receipt_sha256"] = sha256_json(
        {key: value for key, value in report.items() if key != "receipt_sha256"}
    )
    return report


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", default=DEFAULT_ORG)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path)
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS)
    parser.add_argument("--max-text-bytes", type=int, default=DEFAULT_MAX_TEXT_BYTES)
    parser.add_argument("--max-archive-bytes", type=int, default=DEFAULT_MAX_ARCHIVE_BYTES)
    parser.add_argument("--max-repository-bytes", type=int, default=DEFAULT_MAX_REPOSITORY_BYTES)
    parser.add_argument("--minimum-repositories", type=int, default=DEFAULT_MINIMUM_REPOSITORIES)
    parser.add_argument(
        "--allow-findings",
        action="store_true",
        help="Exit zero for complete WARN/FAIL receipts; INCOMPLETE still fails.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = run_audit(
            org=args.org,
            max_workers=args.max_workers,
            max_text_bytes=args.max_text_bytes,
            max_archive_bytes=args.max_archive_bytes,
            max_repository_bytes=args.max_repository_bytes,
            minimum_repositories=args.minimum_repositories,
        )
    except AuditError as exc:
        print(
            json.dumps({"state": "INCOMPLETE", "error": str(exc)}),
            file=sys.stderr,
        )
        return 2
    write_json(args.output, report)
    if args.public_output:
        write_json(args.public_output, public_projection(report))
    summary = report["summary"]
    print(
        json.dumps(
            {
                "state": summary["state"],
                "repositories": summary["totals"]["repositories"],
                "files": summary["totals"]["files"],
                "bytes_verified": summary["totals"]["bytes_tracked_and_verified"],
                "findings": summary["totals"]["findings"],
                "receipt_sha256": report["receipt_sha256"],
            },
            sort_keys=True,
        )
    )
    if summary["state"] == "INCOMPLETE":
        return 2
    if summary["state"] in {"FAIL", "WARN"} and not args.allow_findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
