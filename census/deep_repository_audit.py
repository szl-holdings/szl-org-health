#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Recursive, source-bound audit of every tracked file in a GitHub organization.

The collector is deliberately read-only.  It enumerates every accessible
repository, resolves the exact default-branch commit, inventories the recursive
Git tree, downloads that exact source archive, verifies every regular file
against its Git blob object ID, and emits bounded findings without changing a
repository, branch, workflow, provider, secret, or runtime.

Every tracked file receives an inventory row.  Textual first-party files receive
semantic checks; binary, vendored, generated, submodule, and oversized objects
remain explicitly inventoried with a reason when semantic inspection is not
applicable.  Missing evidence is UNKNOWN/INCOMPLETE, never PASS.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import dataclasses
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, Mapping, Sequence

API_VERSION = "2022-11-28"
DEFAULT_ORG = "szl-holdings"
DEFAULT_SHARD_COUNT = 6
DEFAULT_TIMEOUT = 45.0
DEFAULT_RETRIES = 4
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_BYTES = 3 * 1024 * 1024 * 1024
SCHEMA = "szl.deep-repository-audit/v1"
USER_AGENT = "SZL-Deep-Repository-Audit/1.0"

FAILURE_CONCLUSIONS = frozenset(
    {"action_required", "cancelled", "failure", "stale", "startup_failure", "timed_out"}
)
PENDING_STATUSES = frozenset({"in_progress", "pending", "queued", "requested", "waiting"})
GREEN_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})

TEXT_SUFFIXES = frozenset(
    {
        "",
        ".c",
        ".cc",
        ".cfg",
        ".clj",
        ".cljs",
        ".cmake",
        ".conf",
        ".cpp",
        ".css",
        ".csv",
        ".dockerignore",
        ".env.example",
        ".fish",
        ".go",
        ".graphql",
        ".h",
        ".hpp",
        ".htm",
        ".html",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".jsonl",
        ".jsx",
        ".lean",
        ".lock",
        ".lua",
        ".m",
        ".md",
        ".mjs",
        ".nix",
        ".ps1",
        ".py",
        ".pyi",
        ".r",
        ".rego",
        ".rs",
        ".rst",
        ".scss",
        ".sh",
        ".sql",
        ".svg",
        ".swift",
        ".tf",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".vue",
        ".xml",
        ".yaml",
        ".yml",
        ".zsh",
    }
)
BINARY_SUFFIXES = frozenset(
    {
        ".7z",
        ".a",
        ".avif",
        ".bin",
        ".bmp",
        ".bz2",
        ".class",
        ".dll",
        ".dylib",
        ".eot",
        ".exe",
        ".gif",
        ".gz",
        ".ico",
        ".jar",
        ".jpeg",
        ".jpg",
        ".lockb",
        ".mp3",
        ".mp4",
        ".o",
        ".onnx",
        ".otf",
        ".parquet",
        ".pdf",
        ".pickle",
        ".pkl",
        ".png",
        ".pyc",
        ".safetensors",
        ".so",
        ".tar",
        ".tflite",
        ".ttf",
        ".wav",
        ".webm",
        ".webp",
        ".whl",
        ".woff",
        ".woff2",
        ".xz",
        ".zip",
    }
)
VENDOR_SEGMENTS = frozenset(
    {
        ".venv",
        "dist",
        "generated",
        "node_modules",
        "third_party",
        "third-party",
        "vendor",
        "vendored",
    }
)
FIXTURE_SEGMENTS = frozenset(
    {"example", "examples", "fixture", "fixtures", "sample", "samples", "testdata"}
)
DOC_SEGMENTS = frozenset({"doc", "docs", "documentation"})
SOURCE_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".go",
        ".java",
        ".js",
        ".jsx",
        ".lean",
        ".mjs",
        ".py",
        ".rs",
        ".ts",
        ".tsx",
    }
)
LOCKFILES = frozenset(
    {
        "Cargo.lock",
        "Gemfile.lock",
        "Pipfile.lock",
        "bun.lock",
        "bun.lockb",
        "composer.lock",
        "go.sum",
        "package-lock.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "yarn.lock",
    }
)
DEPENDENCY_MANIFESTS = frozenset(
    {
        "Cargo.toml",
        "Gemfile",
        "Pipfile",
        "composer.json",
        "go.mod",
        "package.json",
        "pyproject.toml",
        "requirements.in",
        "requirements.txt",
    }
)
TECH_MARKERS: dict[str, tuple[str, ...]] = {
    "inference.vllm": ("vllm",),
    "inference.sglang": ("sglang",),
    "inference.llama_cpp": ("llama.cpp", "llama_cpp", "llama-cpp"),
    "inference.kserve": ("kserve",),
    "orchestration.ray": ("ray[", "ray==", "kuberay",),
    "orchestration.temporal": ("temporalio", "temporal.io",),
    "observability.opentelemetry": ("opentelemetry", "open-telemetry",),
    "observability.phoenix": ("arize-phoenix", "phoenix.evals",),
    "observability.langfuse": ("langfuse",),
    "security.sigstore": ("sigstore", "cosign",),
    "security.in_toto": ("in-toto", "intoto",),
    "security.slsa": ("slsa",),
    "policy.opa": ("openpolicyagent", "opa ", ".rego",),
    "policy.kyverno": ("kyverno",),
    "identity.spiffe": ("spiffe", "spire",),
    "training.trl": ("trl==", "trl>=", "huggingface/trl",),
    "training.peft": ("peft==", "peft>=", "huggingface/peft",),
    "training.axolotl": ("axolotl",),
    "evaluation.lm_eval": ("lm-eval", "lm_eval",),
    "retrieval.qdrant": ("qdrant",),
    "retrieval.milvus": ("milvus",),
    "retrieval.pgvector": ("pgvector",),
    "data.duckdb": ("duckdb",),
    "data.lance": ("lancedb", "lance.dataset",),
    "protocol.mcp": ("model context protocol", "modelcontextprotocol", "mcp.server",),
}

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("private-key-pem", re.compile(br"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("github-token", re.compile(br"\bgh(?:p|o|u|s|r)_[A-Za-z0-9_]{32,}\b")),
    ("github-fine-grained-token", re.compile(br"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("huggingface-token", re.compile(br"\bhf_[A-Za-z0-9]{30,}\b")),
    ("aws-access-key", re.compile(br"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("slack-token", re.compile(br"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
)
PLACEHOLDER_RE = re.compile(
    r"\b(?:BANDAID|FIXME|HACK|NOT[_ -]?IMPLEMENTED|PLACEHOLDER|STUB|TEMPORARY|"
    r"TODO|WIP|WORKAROUND)\b",
    re.IGNORECASE,
)
GROK_RE = re.compile(r"\b(?:grok(?:[-_ ]?\d+(?:\.\d+)*)?|xai)\b", re.IGNORECASE)
STALL_RE = re.compile(
    r"\b(?:ABANDONED|BLOCKED|BUILD[_ -]?ERROR|EXPIRED|FAILED|INCOMPLETE|"
    r"RUNTIME[_ -]?ERROR|STALLED|STOPPED|TIMED[_ -]?OUT|UNFINISHED)\b",
    re.IGNORECASE,
)
USES_RE = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)")
FROM_RE = re.compile(r"(?im)^\s*FROM\s+([^\s]+)")
PERMISSIONS_WRITE_RE = re.compile(
    r"(?im)^\s*(?:permissions:\s*write-all|(?:actions|checks|contents|deployments|"
    r"id-token|issues|packages|pull-requests|security-events|statuses):\s*write)\s*$"
)
SELF_MUTATION_RE = re.compile(
    r"(?is)(?:persist-credentials:\s*true|contents:\s*write|permissions:\s*write-all)"
    r".{0,12000}?\bgit\s+push\b"
)
SHELL_TRUE_RE = re.compile(
    r"(?:subprocess\.(?:call|check_call|check_output|Popen|run)\s*\([^)]*shell\s*=\s*True|"
    r"os\.system\s*\()"
)
CURL_PIPE_RE = re.compile(r"(?:curl|wget)[^\n|]{0,500}\|\s*(?:ba)?sh\b", re.IGNORECASE)
PULL_REQUEST_TARGET_RE = re.compile(r"(?m)^\s*pull_request_target\s*:")
UNSAFE_CHECKOUT_RE = re.compile(
    r"(?is)pull_request_target.{0,20000}?uses:\s*actions/checkout@"
    r".{0,3000}?(?:github\.event\.pull_request\.head|refs/pull/)"
)


class AuditError(RuntimeError):
    """Fail-closed audit error."""


@dataclasses.dataclass(frozen=True)
class Finding:
    repository: str
    severity: str
    category: str
    rule_id: str
    path: str | None
    line: int | None
    message: str
    evidence: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class ApiResponse:
    data: Any
    headers: Mapping[str, str]
    url: str


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()  # noqa: S324 - Git object identity


def redact(text: str, token: str | None = None) -> str:
    value = text
    if token:
        value = value.replace(token, "[REDACTED]")
    value = re.sub(r"(?i)(authorization:\s*(?:bearer|token)\s+)[^\s]+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)([?&](?:access_token|token)=)[^&\s]+", r"\1[REDACTED]", value)
    return value[:4000]


def _next_link(link_header: str | None) -> str | None:
    if not link_header:
        return None
    for part in link_header.split(","):
        section = part.strip()
        if 'rel="next"' not in section:
            continue
        match = re.match(r"<([^>]+)>", section)
        if match:
            return match.group(1)
    return None


class GitHubClient:
    def __init__(
        self,
        token: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        api_base: str = "https://api.github.com",
    ) -> None:
        if not token:
            raise AuditError("GITHUB_TOKEN is required for the organization audit")
        self.token = token
        self.timeout = timeout
        self.retries = retries
        self.api_base = api_base.rstrip("/")

    def _headers(self, accept: str = "application/vnd.github+json") -> dict[str, str]:
        return {
            "Accept": accept,
            "Authorization": f"Bearer {self.token}",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": API_VERSION,
        }

    def request(
        self,
        url_or_path: str,
        *,
        accept: str = "application/vnd.github+json",
        stream_to: Path | None = None,
        max_bytes: int | None = None,
    ) -> ApiResponse:
        url = (
            url_or_path
            if url_or_path.startswith(("https://", "http://"))
            else f"{self.api_base}{url_or_path}"
        )
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(url, headers=self._headers(accept), method="GET")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    if stream_to is not None:
                        total = 0
                        with stream_to.open("wb") as handle:
                            while True:
                                chunk = response.read(1024 * 1024)
                                if not chunk:
                                    break
                                total += len(chunk)
                                if max_bytes is not None and total > max_bytes:
                                    raise AuditError(
                                        f"archive exceeded configured byte ceiling ({max_bytes})"
                                    )
                                handle.write(chunk)
                        return ApiResponse({"bytes": total}, headers, response.geturl())
                    raw = response.read()
                    if not raw:
                        data: Any = None
                    else:
                        data = json.loads(raw.decode("utf-8"))
                    return ApiResponse(data, headers, response.geturl())
            except urllib.error.HTTPError as exc:
                raw = exc.read(65536)
                detail = raw.decode("utf-8", "replace")
                retry_after = exc.headers.get("Retry-After")
                remaining = exc.headers.get("X-RateLimit-Remaining")
                reset = exc.headers.get("X-RateLimit-Reset")
                retryable = exc.code in {429, 500, 502, 503, 504}
                if exc.code == 403 and remaining == "0":
                    retryable = True
                last_error = AuditError(
                    f"GitHub HTTP {exc.code} for {url}: {redact(detail, self.token)}"
                )
                if not retryable or attempt >= self.retries:
                    raise last_error
                delay = min(60.0, 2.0**attempt)
                if retry_after and retry_after.isdigit():
                    delay = min(120.0, float(retry_after))
                elif remaining == "0" and reset and reset.isdigit():
                    delay = min(120.0, max(1.0, int(reset) - time.time()))
                time.sleep(delay)
            except (OSError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt >= self.retries:
                    raise AuditError(
                        f"GitHub request failed for {url}: {redact(str(exc), self.token)}"
                    ) from exc
                time.sleep(min(30.0, 2.0**attempt))
        raise AuditError(f"GitHub request failed: {last_error}")

    def paginate(self, path: str, *, max_pages: int = 100) -> list[Any]:
        url: str | None = path
        results: list[Any] = []
        pages = 0
        while url:
            pages += 1
            if pages > max_pages:
                raise AuditError(f"pagination exceeded {max_pages} pages for {path}")
            response = self.request(url)
            data = response.data
            if not isinstance(data, list):
                raise AuditError(f"expected list response while paginating {path}")
            results.extend(data)
            url = _next_link(response.headers.get("link"))
        return results

    def download_archive(self, full_name: str, revision: str, target: Path, max_bytes: int) -> int:
        encoded_repo = "/".join(urllib.parse.quote(part, safe="") for part in full_name.split("/", 1))
        response = self.request(
            f"/repos/{encoded_repo}/tarball/{urllib.parse.quote(revision, safe='')}",
            accept="application/vnd.github+json",
            stream_to=target,
            max_bytes=max_bytes,
        )
        return int((response.data or {}).get("bytes") or 0)


def classify_path(path: str) -> str:
    pure = PurePosixPath(path)
    parts = {part.lower() for part in pure.parts}
    suffix = pure.suffix.lower()
    name = pure.name
    lower = path.lower()
    if ".github/workflows/" in lower:
        return "workflow"
    if parts & VENDOR_SEGMENTS:
        return "vendored-or-generated"
    if parts & FIXTURE_SEGMENTS:
        return "fixture-or-sample"
    if parts & DOC_SEGMENTS or suffix in {".md", ".rst"}:
        return "documentation"
    if name in DEPENDENCY_MANIFESTS or name in LOCKFILES:
        return "dependency"
    if name.lower().startswith("dockerfile") or suffix in {".dockerfile", ".tf", ".rego"}:
        return "infrastructure"
    if suffix in SOURCE_SUFFIXES:
        return "source"
    if suffix in BINARY_SUFFIXES:
        return "binary"
    if any(part.lower() in {"test", "tests", "__tests__"} for part in pure.parts):
        return "test"
    return "other"


def is_probably_text(path: str, data: bytes) -> bool:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in BINARY_SUFFIXES:
        return False
    if b"\x00" in data[:8192]:
        return False
    if suffix in TEXT_SUFFIXES:
        return True
    if not data:
        return True
    sample = data[:8192]
    printable = sum(byte in b"\t\n\r\f\b" or 32 <= byte <= 126 or byte >= 128 for byte in sample)
    return printable / len(sample) >= 0.90


def line_number(data: bytes, offset: int) -> int:
    return data.count(b"\n", 0, max(0, offset)) + 1


def _finding(
    findings: list[Finding],
    *,
    repo: str,
    severity: str,
    category: str,
    rule_id: str,
    path: str | None,
    line: int | None,
    message: str,
    evidence: str | None = None,
) -> None:
    findings.append(
        Finding(
            repository=repo,
            severity=severity,
            category=category,
            rule_id=rule_id,
            path=path,
            line=line,
            message=message,
            evidence=evidence,
        )
    )


def scan_file(
    repository: str,
    path: str,
    data: bytes,
    *,
    classification: str,
    findings: list[Finding],
    technology_hits: set[str],
) -> dict[str, Any]:
    lower_path = path.lower()
    text = data.decode("utf-8", "replace")
    lower_text = text.lower()
    semantic_state = "SCANNED"

    for tech, markers in TECH_MARKERS.items():
        if any(marker.lower() in lower_path or marker.lower() in lower_text for marker in markers):
            technology_hits.add(tech)

    secret_scope_reduced = classification in {
        "documentation",
        "fixture-or-sample",
        "test",
        "vendored-or-generated",
    }
    for rule_id, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(data):
            _finding(
                findings,
                repo=repository,
                severity="P1" if secret_scope_reduced else "P0",
                category="secrets",
                rule_id=rule_id,
                path=path,
                line=line_number(data, match.start()),
                message=(
                    "Credential-like material appears in a reduced-trust example/test scope."
                    if secret_scope_reduced
                    else "High-confidence credential material appears in first-party tracked source."
                ),
                evidence=match.group(0)[:12].decode("ascii", "replace") + "…",
            )

    if PurePosixPath(path).name == "sitecustomize.py":
        _finding(
            findings,
            repo=repository,
            severity="P1",
            category="runtime-integrity",
            rule_id="python-sitecustomize",
            path=path,
            line=1,
            message=(
                "sitecustomize.py is imported implicitly by Python and can mutate every process; "
                "require an explicit, reviewed runtime module instead."
            ),
        )

    if classification == "workflow":
        for match in USES_RE.finditer(text):
            ref = match.group(1)
            if ref.startswith("./"):
                continue
            if "@sha256:" in ref:
                continue
            if "@" not in ref or not re.fullmatch(r"[^@]+@[0-9a-fA-F]{40}", ref):
                _finding(
                    findings,
                    repo=repository,
                    severity="P1",
                    category="supply-chain",
                    rule_id="workflow-action-unpinned",
                    path=path,
                    line=text.count("\n", 0, match.start()) + 1,
                    message=f"GitHub Action is not pinned to an exact 40-character commit SHA: {ref}",
                )
        if PERMISSIONS_WRITE_RE.search(text):
            _finding(
                findings,
                repo=repository,
                severity="P1",
                category="workflow-authority",
                rule_id="workflow-write-permission",
                path=path,
                line=None,
                message="Workflow receives write authority; verify the scope is minimal and gated.",
            )
        if SELF_MUTATION_RE.search(text):
            ephemeral = (
                "once" in PurePosixPath(path).name.lower()
                or re.search(
                    r"(?i)\b(?:ephemeral|one[- ]?shot|self[- ]?remov(?:e|ing)|"
                    r"temporary repair|compatibility shim)\b",
                    text,
                )
                is not None
            )
            _finding(
                findings,
                repo=repository,
                severity="P0" if ephemeral else "P1",
                category="workflow-authority",
                rule_id=(
                    "ephemeral-self-mutating-workflow"
                    if ephemeral
                    else "repository-writing-workflow"
                ),
                path=path,
                line=None,
                message=(
                    "One-shot/self-removing workflow combines repository write authority "
                    "with git push; replace it with permanent source and reviewed PRs."
                    if ephemeral
                    else "Workflow combines repository write authority with git push; "
                    "verify the mutation is a permanent, bounded release controller."
                ),
            )
        if PULL_REQUEST_TARGET_RE.search(text) and UNSAFE_CHECKOUT_RE.search(text):
            _finding(
                findings,
                repo=repository,
                severity="P0",
                category="workflow-authority",
                rule_id="pull-request-target-untrusted-checkout",
                path=path,
                line=None,
                message="pull_request_target workflow appears to execute or check out untrusted PR-head content.",
            )

    if PurePosixPath(path).name.lower().startswith("dockerfile"):
        for match in FROM_RE.finditer(text):
            image = match.group(1)
            if image.lower() == "scratch":
                continue
            if "@sha256:" not in image:
                _finding(
                    findings,
                    repo=repository,
                    severity="P1",
                    category="supply-chain",
                    rule_id="docker-base-unpinned",
                    path=path,
                    line=text.count("\n", 0, match.start()) + 1,
                    message=f"Container base image is not digest-pinned: {image}",
                )

    for regex, rule_id, message in (
        (
            SHELL_TRUE_RE,
            "shell-execution",
            "Dynamic shell execution primitive requires a bounded argv-based replacement or explicit proof.",
        ),
        (
            CURL_PIPE_RE,
            "network-pipe-shell",
            "Remote network content is piped directly to a shell.",
        ),
    ):
        for match in regex.finditer(text):
            _finding(
                findings,
                repo=repository,
                severity="P1",
                category="code-execution",
                rule_id=rule_id,
                path=path,
                line=text.count("\n", 0, match.start()) + 1,
                message=message,
                evidence=text[match.start() : match.end()][:160],
            )

    placeholder_count = len(PLACEHOLDER_RE.findall(text))
    grok_count = len(GROK_RE.findall(text))
    stall_count = len(STALL_RE.findall(text))
    if placeholder_count and classification not in {"documentation", "fixture-or-sample", "test"}:
        _finding(
            findings,
            repo=repository,
            severity="P2",
            category="completion",
            rule_id="unfinished-marker",
            path=path,
            line=None,
            message=f"First-party file contains {placeholder_count} unfinished-work marker(s).",
        )
    if grok_count and stall_count:
        _finding(
            findings,
            repo=repository,
            severity="P1",
            category="grok-recovery",
            rule_id="grok-stall-marker",
            path=path,
            line=None,
            message=(
                f"Grok/xAI references and {stall_count} stall/error marker(s) coexist; "
                "review for abandoned executable work rather than payload-only placement."
            ),
        )

    return {
        "semantic_state": semantic_state,
        "placeholder_markers": placeholder_count,
        "grok_markers": grok_count,
        "stall_markers": stall_count,
    }


def aggregate_workflow_runs(runs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    latest: dict[str, Mapping[str, Any]] = {}
    for run in runs:
        key = str(run.get("workflow_id") or run.get("name") or run.get("id") or "unknown")
        stamp = str(run.get("created_at") or run.get("run_started_at") or "")
        old = latest.get(key)
        old_stamp = str(
            (old or {}).get("created_at") or (old or {}).get("run_started_at") or ""
        )
        if old is None or stamp > old_stamp:
            latest[key] = run
    failing: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    if not latest:
        return {
            "state": "UNKNOWN",
            "workflow_count": 0,
            "failing": [],
            "pending": [],
            "unknown": [],
        }
    for run in latest.values():
        row = {
            "id": run.get("id"),
            "name": run.get("name"),
            "status": run.get("status"),
            "conclusion": run.get("conclusion"),
            "head_sha": run.get("head_sha"),
            "created_at": run.get("created_at"),
            "html_url": run.get("html_url"),
        }
        status = run.get("status")
        conclusion = run.get("conclusion")
        if status == "completed" and conclusion in FAILURE_CONCLUSIONS:
            failing.append(row)
        elif status in PENDING_STATUSES and conclusion is None:
            pending.append(row)
        elif status == "completed" and conclusion in GREEN_CONCLUSIONS:
            continue
        else:
            unknown.append(row)
    state = "FAILURE" if failing else "UNKNOWN" if unknown else "PENDING" if pending else "SUCCESS"
    return {
        "state": state,
        "workflow_count": len(latest),
        "failing": sorted(failing, key=lambda row: str(row.get("name"))),
        "pending": sorted(pending, key=lambda row: str(row.get("name"))),
        "unknown": sorted(unknown, key=lambda row: str(row.get("name"))),
    }


def safe_member_path(name: str) -> PurePosixPath:
    pure = PurePosixPath(name)
    if (
        pure.is_absolute()
        or "//" in name
        or "\\" in name
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise AuditError(f"unsafe archive path: {name!r}")
    return pure


def extract_archive(archive: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, mode="r:*") as tf:
        members = tf.getmembers()
        roots: set[str] = set()
        for member in members:
            pure = safe_member_path(member.name)
            roots.add(pure.parts[0])
            if member.ischr() or member.isblk() or member.isfifo():
                raise AuditError(f"unsupported special archive member: {member.name}")
            target = destination.joinpath(*pure.parts)
            target_parent = target.parent.resolve()
            if destination.resolve() not in {target_parent, *target_parent.parents}:
                raise AuditError(f"archive path escapes destination: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if member.islnk():
                raise AuditError(f"hard-linked archive member is unsupported: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                # A Git symlink blob contains its target path as bytes.  Materialize
                # those bytes as a regular audit file instead of creating a link.
                target.write_bytes(member.linkname.encode("utf-8", "surrogateescape"))
            elif member.isfile():
                source = tf.extractfile(member)
                if source is None:
                    raise AuditError(f"archive member has no readable payload: {member.name}")
                with source, target.open("wb") as out:
                    shutil.copyfileobj(source, out)
            else:
                continue
            os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
    if len(roots) != 1:
        raise AuditError(f"source archive must contain one root directory, found {sorted(roots)}")
    root_name = next(iter(roots))
    root = destination / root_name
    if not root.is_dir():
        raise AuditError("source archive root is not a directory")
    return root


def _repo_path(full_name: str) -> str:
    owner, repo = full_name.split("/", 1)
    return f"/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}"


def _write_json(path: Path, value: Any) -> None:
    raw = canonical_json_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def _write_ndjson_gzip(path: Path, rows: Iterable[Mapping[str, Any]]) -> tuple[int, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    digest = hashlib.sha256()
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            for row in rows:
                line = canonical_json_bytes(row) + b"\n"
                digest.update(line)
                gz.write(line)
                count += 1
    return count, digest.hexdigest()


def _load_repo_metadata(client: GitHubClient, org: str) -> list[dict[str, Any]]:
    encoded = urllib.parse.quote(org, safe="")
    repos = client.paginate(
        f"/orgs/{encoded}/repos?type=all&sort=full_name&direction=asc&per_page=100",
        max_pages=100,
    )
    cleaned: list[dict[str, Any]] = []
    for repo in repos:
        if not isinstance(repo, dict) or not isinstance(repo.get("full_name"), str):
            raise AuditError("organization repository inventory contains malformed entries")
        cleaned.append(repo)
    return sorted(cleaned, key=lambda item: item["full_name"].lower())


def select_shard(
    repos: Sequence[Mapping[str, Any]], shard_index: int, shard_count: int
) -> list[Mapping[str, Any]]:
    if shard_count <= 0 or not 0 <= shard_index < shard_count:
        raise AuditError("invalid shard coordinates")
    return [repo for position, repo in enumerate(repos) if position % shard_count == shard_index]


def _branch_candidates(branches: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for branch in branches:
        name = str(branch.get("name") or "")
        lower = name.lower()
        if any(marker in lower for marker in ("grok", "xai", "stall", "perplexity", "codex")):
            candidates.append(
                {
                    "name": name,
                    "sha": ((branch.get("commit") or {}).get("sha")),
                    "protected": branch.get("protected"),
                }
            )
    return sorted(candidates, key=lambda row: row["name"].lower())


def _manifest_lock_findings(
    repository: str, file_paths: set[str], findings: list[Finding]
) -> None:
    package_managers = {
        "package.json": {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"},
        "pyproject.toml": {"poetry.lock", "uv.lock", "Pipfile.lock"},
        "Cargo.toml": {"Cargo.lock"},
        "go.mod": {"go.sum"},
    }
    names = {PurePosixPath(path).name for path in file_paths}
    for manifest, locks in package_managers.items():
        if manifest in names and not names.intersection(locks):
            _finding(
                findings,
                repo=repository,
                severity="P1",
                category="reproducibility",
                rule_id="dependency-lockfile-missing",
                path=None,
                line=None,
                message=f"{manifest} is present but no recognized lockfile was observed.",
            )


def audit_repository(
    client: GitHubClient,
    repo: Mapping[str, Any],
    *,
    archive_dir: Path,
    max_file_bytes: int,
    max_archive_bytes: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[Finding]]:
    full_name = str(repo["full_name"])
    default_branch = str(repo.get("default_branch") or "")
    repo_api = _repo_path(full_name)
    findings: list[Finding] = []
    file_rows: list[dict[str, Any]] = []
    technology_hits: set[str] = set()
    repo_started = time.monotonic()
    archived = bool(repo.get("archived"))

    if not default_branch:
        _finding(
            findings,
            repo=full_name,
            severity="P1",
            category="source-integrity",
            rule_id="default-branch-missing",
            path=None,
            line=None,
            message="Repository has no observable default branch.",
        )
        return (
            {
                "repository": full_name,
                "archived": archived,
                "visibility": repo.get("visibility"),
                "state": "INCOMPLETE",
                "error": "default branch missing",
                "file_count": 0,
                "finding_count": len(findings),
            },
            file_rows,
            findings,
        )

    branch = client.request(
        f"{repo_api}/branches/{urllib.parse.quote(default_branch, safe='')}"
    ).data
    if not isinstance(branch, dict):
        raise AuditError(f"{full_name}: default branch response is malformed")
    revision = str(((branch.get("commit") or {}).get("sha")) or "")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise AuditError(f"{full_name}: default branch has no exact commit SHA")
    commit = client.request(f"{repo_api}/git/commits/{revision}").data
    if not isinstance(commit, dict):
        raise AuditError(f"{full_name}: commit response is malformed")
    tree_sha = str(((commit.get("tree") or {}).get("sha")) or "")
    if not re.fullmatch(r"[0-9a-f]{40}", tree_sha):
        raise AuditError(f"{full_name}: commit has no exact tree SHA")
    tree = client.request(f"{repo_api}/git/trees/{tree_sha}?recursive=1").data
    if not isinstance(tree, dict) or not isinstance(tree.get("tree"), list):
        raise AuditError(f"{full_name}: recursive tree response is malformed")
    if tree.get("truncated") is True:
        _finding(
            findings,
            repo=full_name,
            severity="P0",
            category="source-integrity",
            rule_id="recursive-tree-truncated",
            path=None,
            line=None,
            message="GitHub recursive tree was truncated; complete file coverage is not proven.",
        )

    tree_blobs: dict[str, dict[str, Any]] = {}
    submodules: list[dict[str, Any]] = []
    for entry in tree["tree"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise AuditError(f"{full_name}: recursive tree contains a malformed entry")
        path = entry["path"]
        entry_type = entry.get("type")
        if entry_type == "blob":
            tree_blobs[path] = entry
        elif entry_type == "commit":
            submodules.append(
                {"path": path, "sha": entry.get("sha"), "mode": entry.get("mode")}
            )

    pulls = client.paginate(f"{repo_api}/pulls?state=open&per_page=100", max_pages=20)
    branches = client.paginate(f"{repo_api}/branches?per_page=100", max_pages=100)
    runs_response = client.request(
        f"{repo_api}/actions/runs?branch={urllib.parse.quote(default_branch, safe='')}"
        "&event=push&per_page=100"
    ).data
    runs = (
        runs_response.get("workflow_runs")
        if isinstance(runs_response, dict)
        and isinstance(runs_response.get("workflow_runs"), list)
        else []
    )
    ci = aggregate_workflow_runs(runs)
    for failure in ci["failing"]:
        _finding(
            findings,
            repo=full_name,
            severity="P1",
            category="build-health",
            rule_id="default-branch-workflow-failure",
            path=None,
            line=None,
            message=f"Latest observed default-branch run is failing: {failure.get('name')}",
            evidence=str(failure.get("html_url") or ""),
        )
    if ci["pending"] or ci["unknown"]:
        _finding(
            findings,
            repo=full_name,
            severity="P2",
            category="build-health",
            rule_id="default-branch-workflow-nonterminal",
            path=None,
            line=None,
            message="At least one latest default-branch workflow is pending or unknown.",
        )

    for pr in pulls:
        title = str(pr.get("title") or "")
        body = str(pr.get("body") or "")
        if GROK_RE.search(title + "\n" + body):
            _finding(
                findings,
                repo=full_name,
                severity="P1",
                category="grok-recovery",
                rule_id="open-grok-pr",
                path=None,
                line=None,
                message=f"Open pull request references Grok/xAI: #{pr.get('number')} {title}",
                evidence=str(pr.get("html_url") or ""),
            )

    archive_path = archive_dir / (full_name.replace("/", "__") + ".tar.gz")
    extract_path = archive_dir / (full_name.replace("/", "__") + ".src")
    archive_bytes = 0
    archive_state = "NOT_ATTEMPTED"
    archive_error: str | None = None
    extracted_root: Path | None = None
    try:
        archive_bytes = client.download_archive(
            full_name, revision, archive_path, max_archive_bytes
        )
        archive_state = "DOWNLOADED"
        extracted_root = extract_archive(archive_path, extract_path)
        archive_state = "VERIFIED"
    except Exception as exc:  # fail closed per repository; the shard still produces evidence
        archive_state = "INCOMPLETE"
        archive_error = redact(str(exc), client.token)
        _finding(
            findings,
            repo=full_name,
            severity="P0",
            category="source-integrity",
            rule_id="source-archive-unavailable",
            path=None,
            line=None,
            message="Exact source archive could not be fully downloaded and extracted.",
            evidence=archive_error,
        )

    observed_paths: set[str] = set()
    content_scanned = 0
    binary_count = 0
    oversized_count = 0
    blob_mismatches = 0
    symlink_count = 0
    missing_archive_paths: list[str] = []
    extra_archive_paths: list[str] = []

    if extracted_root is not None:
        for local in sorted(extracted_root.rglob("*")):
            if local.is_symlink():
                symlink_count += 1
                continue
            if not local.is_file():
                continue
            rel = local.relative_to(extracted_root).as_posix()
            observed_paths.add(rel)
            entry = tree_blobs.get(rel)
            data = local.read_bytes()
            digest = sha256_bytes(data)
            classification = classify_path(rel)
            git_sha = git_blob_sha(data)
            expected_sha = str((entry or {}).get("sha") or "")
            blob_verified = bool(entry) and git_sha == expected_sha
            if not blob_verified:
                blob_mismatches += 1
                _finding(
                    findings,
                    repo=full_name,
                    severity="P0",
                    category="source-integrity",
                    rule_id="git-blob-mismatch",
                    path=rel,
                    line=None,
                    message="Archive file bytes do not match the recursive Git tree blob identity.",
                    evidence=f"expected={expected_sha or 'absent'} observed={git_sha}",
                )

            semantic = {
                "semantic_state": "NOT_APPLICABLE",
                "placeholder_markers": 0,
                "grok_markers": 0,
                "stall_markers": 0,
            }
            if len(data) > max_file_bytes:
                oversized_count += 1
                semantic["semantic_state"] = "OVERSIZED"
            elif not is_probably_text(rel, data):
                binary_count += 1
                semantic["semantic_state"] = "BINARY"
            elif classification == "vendored-or-generated":
                semantic["semantic_state"] = "VENDORED_OR_GENERATED"
            else:
                semantic = scan_file(
                    full_name,
                    rel,
                    data,
                    classification=classification,
                    findings=findings,
                    technology_hits=technology_hits,
                )
                content_scanned += 1

            file_rows.append(
                {
                    "repository": full_name,
                    "revision": revision,
                    "path": rel,
                    "mode": (entry or {}).get("mode"),
                    "git_blob_sha1": expected_sha or None,
                    "git_blob_verified": blob_verified,
                    "size": len(data),
                    "sha256": digest,
                    "classification": classification,
                    **semantic,
                }
            )

        missing_archive_paths = sorted(set(tree_blobs) - observed_paths)
        extra_archive_paths = sorted(observed_paths - set(tree_blobs))
        for path in missing_archive_paths[:200]:
            _finding(
                findings,
                repo=full_name,
                severity="P0",
                category="source-integrity",
                rule_id="archive-file-missing",
                path=path,
                line=None,
                message="Tracked Git blob is missing from the exact source archive.",
            )
        for path in extra_archive_paths[:200]:
            _finding(
                findings,
                repo=full_name,
                severity="P0",
                category="source-integrity",
                rule_id="archive-file-extra",
                path=path,
                line=None,
                message="Exact source archive contains an unexpected regular file.",
            )
    else:
        for rel, entry in sorted(tree_blobs.items()):
            file_rows.append(
                {
                    "repository": full_name,
                    "revision": revision,
                    "path": rel,
                    "mode": entry.get("mode"),
                    "git_blob_sha1": entry.get("sha"),
                    "git_blob_verified": None,
                    "size": entry.get("size"),
                    "sha256": None,
                    "classification": classify_path(rel),
                    "semantic_state": "ARCHIVE_UNAVAILABLE",
                    "placeholder_markers": None,
                    "grok_markers": None,
                    "stall_markers": None,
                }
            )

    file_paths = set(tree_blobs)
    _manifest_lock_findings(full_name, file_paths, findings)
    names = {PurePosixPath(path).name for path in file_paths}
    for required, severity in (("README.md", "P1"), ("LICENSE", "P2"), ("SECURITY.md", "P2")):
        if required not in names and not any(name.startswith(required + ".") for name in names):
            _finding(
                findings,
                repo=full_name,
                severity=severity,
                category="governance",
                rule_id=f"missing-{required.lower().replace('.', '-')}",
                path=None,
                line=None,
                message=f"Repository does not expose a tracked {required} governance artifact.",
            )

    grok_files = sorted(
        row["path"]
        for row in file_rows
        if (row.get("grok_markers") or 0) > 0 or GROK_RE.search(str(row["path"]))
    )
    stalled_grok_files = sorted(
        row["path"]
        for row in file_rows
        if (row.get("grok_markers") or 0) > 0 and (row.get("stall_markers") or 0) > 0
    )
    severity_counts = Counter(finding.severity for finding in findings)
    state = (
        "FAILED_CLOSED"
        if severity_counts["P0"] or archive_state != "VERIFIED" or blob_mismatches
        else "ACTION_REQUIRED"
        if severity_counts["P1"]
        else "OBSERVED"
    )

    repo_summary = {
        "schema": SCHEMA,
        "repository": full_name,
        "repository_id": repo.get("id"),
        "archived": archived,
        "visibility": repo.get("visibility"),
        "default_branch": default_branch,
        "revision": revision,
        "tree_sha": tree_sha,
        "state": state,
        "archive_state": archive_state,
        "archive_bytes": archive_bytes,
        "archive_error": archive_error,
        "recursive_tree_truncated": tree.get("truncated") is True,
        "file_count": len(tree_blobs),
        "archive_file_count": len(observed_paths),
        "content_scanned_count": content_scanned,
        "binary_count": binary_count,
        "oversized_count": oversized_count,
        "symlink_count": symlink_count,
        "submodules": submodules,
        "git_blob_mismatch_count": blob_mismatches,
        "missing_archive_path_count": len(missing_archive_paths),
        "extra_archive_path_count": len(extra_archive_paths),
        "open_pull_requests": [
            {
                "number": pr.get("number"),
                "title": pr.get("title"),
                "draft": pr.get("draft"),
                "head_sha": ((pr.get("head") or {}).get("sha")),
                "base_sha": ((pr.get("base") or {}).get("sha")),
                "html_url": pr.get("html_url"),
            }
            for pr in pulls
        ],
        "branch_count": len(branches),
        "grok_branch_candidates": _branch_candidates(branches),
        "ci": ci,
        "technology_hits": sorted(technology_hits),
        "grok_files": grok_files,
        "stalled_grok_files": stalled_grok_files,
        "finding_counts": dict(sorted(severity_counts.items())),
        "duration_seconds": round(time.monotonic() - repo_started, 3),
    }

    archive_path.unlink(missing_ok=True)
    shutil.rmtree(extract_path, ignore_errors=True)
    return repo_summary, file_rows, findings


def run_shard(args: argparse.Namespace) -> int:
    token = args.token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    client = GitHubClient(
        token or "",
        timeout=args.timeout,
        retries=args.retries,
        api_base=args.api_base,
    )
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    repos = _load_repo_metadata(client, args.org)
    selected = select_shard(repos, args.shard_index, args.shard_count)
    archive_dir = Path(tempfile.mkdtemp(prefix=f"szl-deep-audit-{args.shard_index}-"))

    repo_summaries: list[dict[str, Any]] = []
    inventory_rows: list[dict[str, Any]] = []
    findings: list[Finding] = []
    errors: list[dict[str, str]] = []

    try:
        for repo in selected:
            full_name = str(repo["full_name"])
            try:
                summary, rows, repo_findings = audit_repository(
                    client,
                    repo,
                    archive_dir=archive_dir,
                    max_file_bytes=args.max_file_bytes,
                    max_archive_bytes=args.max_archive_bytes,
                )
                repo_summaries.append(summary)
                inventory_rows.extend(rows)
                findings.extend(repo_findings)
            except Exception as exc:
                message = redact(str(exc), client.token)
                errors.append({"repository": full_name, "error": message})
                findings.append(
                    Finding(
                        repository=full_name,
                        severity="P0",
                        category="collector",
                        rule_id="repository-audit-failed",
                        path=None,
                        line=None,
                        message="Repository audit failed before complete evidence was emitted.",
                        evidence=message,
                    )
                )
                repo_summaries.append(
                    {
                        "schema": SCHEMA,
                        "repository": full_name,
                        "state": "INCOMPLETE",
                        "error": message,
                        "file_count": None,
                        "finding_counts": {"P0": 1},
                    }
                )
    finally:
        shutil.rmtree(archive_dir, ignore_errors=True)

    repo_summaries.sort(key=lambda row: str(row["repository"]).lower())
    inventory_rows.sort(key=lambda row: (str(row["repository"]).lower(), str(row["path"])))
    finding_dicts = sorted(
        (finding.as_dict() for finding in findings),
        key=lambda row: (
            {"P0": 0, "P1": 1, "P2": 2, "P3": 3}.get(str(row["severity"]), 9),
            str(row["repository"]).lower(),
            str(row.get("path") or ""),
            str(row["rule_id"]),
        ),
    )

    inventory_path = output / f"file-inventory-shard-{args.shard_index}.ndjson.gz"
    inventory_count, inventory_digest = _write_ndjson_gzip(
        inventory_path, inventory_rows
    )
    findings_path = output / f"findings-shard-{args.shard_index}.json"
    _write_json(findings_path, finding_dicts)
    repos_path = output / f"repositories-shard-{args.shard_index}.json"
    _write_json(repos_path, repo_summaries)

    severity_counts = Counter(row["severity"] for row in finding_dicts)
    state = (
        "INCOMPLETE"
        if errors
        else "FAILED_CLOSED"
        if severity_counts["P0"]
        else "ACTION_REQUIRED"
        if severity_counts["P1"]
        else "OBSERVED"
    )
    receipt = {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "organization": args.org,
        "state": state,
        "shard_index": args.shard_index,
        "shard_count": args.shard_count,
        "organization_repository_count": len(repos),
        "selected_repository_count": len(selected),
        "audited_repository_count": len(repo_summaries),
        "inventory_row_count": inventory_count,
        "inventory_uncompressed_sha256": inventory_digest,
        "inventory_archive_sha256": sha256_bytes(inventory_path.read_bytes()),
        "repositories_sha256": sha256_bytes(repos_path.read_bytes()),
        "findings_sha256": sha256_bytes(findings_path.read_bytes()),
        "finding_counts": dict(sorted(severity_counts.items())),
        "errors": errors,
        "source": {
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "workflow_sha": os.environ.get("GITHUB_SHA"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        },
        "authority": {
            "read_only": True,
            "external_effectors": [],
            "production_authorization": False,
            "secret_values_emitted": False,
        },
    }
    _write_json(output / f"receipt-shard-{args.shard_index}.json", receipt)
    print(json.dumps({"state": state, "receipt": receipt}, sort_keys=True))
    return 2 if errors else 0


def merge_shards(args: argparse.Namespace) -> int:
    source = Path(args.input_dir)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    receipts: list[dict[str, Any]] = []
    repositories: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    inventory_files: list[dict[str, Any]] = []

    for index in range(args.shard_count):
        receipt_path = source / f"receipt-shard-{index}.json"
        repo_path = source / f"repositories-shard-{index}.json"
        finding_path = source / f"findings-shard-{index}.json"
        inventory_path = source / f"file-inventory-shard-{index}.ndjson.gz"
        missing = [
            str(path)
            for path in (receipt_path, repo_path, finding_path, inventory_path)
            if not path.is_file()
        ]
        if missing:
            raise AuditError(f"missing shard artifacts: {missing}")
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if receipt.get("shard_index") != index or receipt.get("shard_count") != args.shard_count:
            raise AuditError(f"shard {index} receipt coordinates mismatch")
        if sha256_bytes(inventory_path.read_bytes()) != receipt.get(
            "inventory_archive_sha256"
        ):
            raise AuditError(f"shard {index} inventory digest mismatch")
        receipts.append(receipt)
        repositories.extend(json.loads(repo_path.read_text(encoding="utf-8")))
        findings.extend(json.loads(finding_path.read_text(encoding="utf-8")))
        inventory_files.append(
            {
                "shard_index": index,
                "path": inventory_path.name,
                "sha256": receipt["inventory_archive_sha256"],
                "uncompressed_sha256": receipt["inventory_uncompressed_sha256"],
                "row_count": receipt["inventory_row_count"],
            }
        )

    repositories.sort(key=lambda row: str(row["repository"]).lower())
    if len({row["repository"] for row in repositories}) != len(repositories):
        raise AuditError("repository appeared in more than one shard")
    organization_counts = {receipt["organization_repository_count"] for receipt in receipts}
    if len(organization_counts) != 1:
        raise AuditError("shards disagree on organization repository count")
    expected_repo_count = next(iter(organization_counts))
    if len(repositories) != expected_repo_count:
        raise AuditError(
            f"merged repository count mismatch: expected {expected_repo_count}, found {len(repositories)}"
        )

    severity_counts = Counter(str(row.get("severity")) for row in findings)
    incomplete = any(receipt.get("state") == "INCOMPLETE" for receipt in receipts)
    state = (
        "INCOMPLETE"
        if incomplete
        else "FAILED_CLOSED"
        if severity_counts["P0"]
        else "ACTION_REQUIRED"
        if severity_counts["P1"]
        else "OBSERVED"
    )
    tech_repos: dict[str, list[str]] = defaultdict(list)
    grok_rows: list[dict[str, Any]] = []
    for repo in repositories:
        for tech in repo.get("technology_hits") or []:
            tech_repos[str(tech)].append(str(repo["repository"]))
        if repo.get("grok_files") or repo.get("grok_branch_candidates"):
            grok_rows.append(
                {
                    "repository": repo["repository"],
                    "revision": repo.get("revision"),
                    "files": repo.get("grok_files") or [],
                    "stalled_files": repo.get("stalled_grok_files") or [],
                    "branches": repo.get("grok_branch_candidates") or [],
                    "open_pull_requests": [
                        pr
                        for pr in repo.get("open_pull_requests") or []
                        if GROK_RE.search(str(pr.get("title") or ""))
                    ],
                }
            )

    finding_path = output / "findings.json"
    repository_path = output / "repositories.json"
    grok_path = output / "grok-recovery-index.json"
    technology_path = output / "technology-capability-index.json"
    _write_json(finding_path, findings)
    _write_json(repository_path, repositories)
    _write_json(grok_path, grok_rows)
    _write_json(
        technology_path,
        {
            "schema": "szl.technology-capability-index/v1",
            "technologies": {
                tech: sorted(repos) for tech, repos in sorted(tech_repos.items())
            },
        },
    )

    p0 = [row for row in findings if row.get("severity") == "P0"]
    p1 = [row for row in findings if row.get("severity") == "P1"]
    ci_failures = [
        {
            "repository": repo["repository"],
            "failures": (repo.get("ci") or {}).get("failing") or [],
        }
        for repo in repositories
        if (repo.get("ci") or {}).get("failing")
    ]
    report_lines = [
        "# SZL deep repository audit",
        "",
        f"- State: **{state}**",
        f"- Organization: `{args.org}`",
        f"- Repositories: **{len(repositories)}**",
        f"- Tracked file inventory rows: **{sum(item['row_count'] for item in inventory_files)}**",
        f"- P0 findings: **{len(p0)}**",
        f"- P1 findings: **{len(p1)}**",
        f"- Repositories with latest default-branch workflow failures: **{len(ci_failures)}**",
        f"- Repositories with Grok/xAI recovery evidence: **{len(grok_rows)}**",
        "",
        "## Authority boundary",
        "",
        "Read-only observation only. No branch, pull request, workflow, provider, "
        "runtime, secret, visibility, hardware, DNS, or production authority was changed.",
        "",
        "## P0 findings",
        "",
    ]
    if p0:
        for row in p0[:200]:
            location = (
                f"`{row['repository']}:{row.get('path') or '<repository>'}`"
            )
            report_lines.append(
                f"- **{row['rule_id']}** {location} — {row['message']}"
            )
    else:
        report_lines.append("- None observed.")
    report_lines.extend(["", "## P1 findings", ""])
    if p1:
        for row in p1[:300]:
            location = (
                f"`{row['repository']}:{row.get('path') or '<repository>'}`"
            )
            report_lines.append(
                f"- **{row['rule_id']}** {location} — {row['message']}"
            )
    else:
        report_lines.append("- None observed.")
    report_lines.extend(["", "## Grok recovery index", ""])
    if grok_rows:
        for row in grok_rows:
            report_lines.append(
                f"- `{row['repository']}` — files {len(row['files'])}; "
                f"stalled markers {len(row['stalled_files'])}; branches {len(row['branches'])}"
            )
    else:
        report_lines.append("- No Grok/xAI-tagged tracked files or branch candidates observed.")

    report_path = output / "report.md"
    report_path.write_text("\n".join(report_lines).rstrip() + "\n", encoding="utf-8")

    final_receipt = {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "organization": args.org,
        "state": state,
        "repository_count": len(repositories),
        "active_repository_count": sum(1 for repo in repositories if not repo.get("archived")),
        "archived_repository_count": sum(1 for repo in repositories if repo.get("archived")),
        "file_inventory_row_count": sum(item["row_count"] for item in inventory_files),
        "finding_counts": dict(sorted(severity_counts.items())),
        "default_branch_failure_repository_count": len(ci_failures),
        "grok_recovery_repository_count": len(grok_rows),
        "inventory_shards": inventory_files,
        "artifacts": {
            path.name: sha256_bytes(path.read_bytes())
            for path in (
                finding_path,
                repository_path,
                grok_path,
                technology_path,
                report_path,
            )
        },
        "source": {
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "workflow_sha": os.environ.get("GITHUB_SHA"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        },
        "authority": {
            "read_only": True,
            "external_effectors": [],
            "production_authorization": False,
            "secret_values_emitted": False,
        },
    }
    _write_json(output / "receipt.json", final_receipt)
    print(json.dumps(final_receipt, sort_keys=True))
    return 2 if state == "INCOMPLETE" else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    shard = subparsers.add_parser("shard", help="audit one deterministic repository shard")
    shard.add_argument("--org", default=DEFAULT_ORG)
    shard.add_argument("--shard-index", type=int, required=True)
    shard.add_argument("--shard-count", type=int, default=DEFAULT_SHARD_COUNT)
    shard.add_argument("--output-dir", required=True)
    shard.add_argument("--token", default=None)
    shard.add_argument("--api-base", default="https://api.github.com")
    shard.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    shard.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    shard.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    shard.add_argument("--max-archive-bytes", type=int, default=DEFAULT_MAX_ARCHIVE_BYTES)
    shard.set_defaults(handler=run_shard)

    merge = subparsers.add_parser("merge", help="merge and verify all shard evidence")
    merge.add_argument("--org", default=DEFAULT_ORG)
    merge.add_argument("--shard-count", type=int, default=DEFAULT_SHARD_COUNT)
    merge.add_argument("--input-dir", required=True)
    merge.add_argument("--output-dir", required=True)
    merge.set_defaults(handler=merge_shards)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except AuditError as exc:
        print(json.dumps({"state": "INCOMPLETE", "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
