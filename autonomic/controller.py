#!/usr/bin/env python3
"""Closed-loop, fail-closed SRE controller for the declared SZL public estate.

The controller reads one signed GitHub source manifest, probes only fixed HTTPS
origins declared there, applies a small state machine, and may request a bounded
Hugging Face Space restart. It does not execute product code, accept caller
supplied URLs, edit DNS, change hardware, alter visibility, delete assets, or
run arbitrary shell commands.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

POLICY_SCHEMA = "szl.autonomic-sre-policy/v1"
MANIFEST_SCHEMA = "szl.public-estate/v1"
STATE_SCHEMA = "szl.autonomic-sre-state/v1"
RECEIPT_SCHEMA = "szl.autonomic-sre-receipt/v1"
OFFLINE_SCHEMA = "szl.autonomic-sre-contract/v1"
STATE_BEGIN = "<!-- SZL_AUTONOMIC_STATE_BEGIN\n"
STATE_END = "\nSZL_AUTONOMIC_STATE_END -->"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SURFACE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
USER_AGENT = "SZLHOLDINGS-AutonomicSRE/1.0"
REDACTED_ERROR = "request failed"


class ContractError(RuntimeError):
    """Raised when a repository-owned contract is malformed or unverifiable."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject every redirect; each probe is pinned to one manifest origin."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Mapping[str, str],
        newurl: str,
    ) -> urllib.request.Request | None:
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "redirect rejected by fixed-origin policy",
            headers,
            fp,
        )


@dataclasses.dataclass(frozen=True)
class PathObservation:
    path: str
    status: int | None
    elapsed_ms: int
    content_type: str
    body_sha256: str | None
    body_bytes: int | None
    ok: bool
    error_kind: str | None = None

    def receipt(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class SurfaceObservation:
    surface_id: str
    hf_repository: str
    base_url: str
    availability_ok: bool
    source_ok: bool
    source_status: str
    source_revision: str | None
    expected_revision: str | None
    paths: tuple[PathObservation, ...]
    failures: tuple[str, ...]

    @property
    def healthy(self) -> bool:
        return self.availability_ok and self.source_ok

    def receipt(self) -> dict[str, Any]:
        return {
            "id": self.surface_id,
            "hf_repository": self.hf_repository,
            "base_url": self.base_url,
            "availability_ok": self.availability_ok,
            "source_ok": self.source_ok,
            "source_status": self.source_status,
            "source_revision": self.source_revision,
            "expected_revision": self.expected_revision,
            "paths": [item.receipt() for item in self.paths],
            "failures": list(self.failures),
        }


@dataclasses.dataclass(frozen=True)
class RecoveryPlan:
    state: str
    consecutive_failures: int
    recovery_attempts: int
    action: str | None
    reason: str
    last_action_at: str | None


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def require_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"{label} must be a string")
    return value.strip()


def require_positive_int(value: Any, label: str, *, maximum: int) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer")
    require(1 <= value <= maximum, f"{label} must be between 1 and {maximum}")
    return value


def require_repo(value: Any, label: str) -> str:
    repo = require_string(value, label)
    require(bool(REPO.fullmatch(repo)), f"{label} must be owner/repository")
    return repo


def safe_error_kind(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP_{int(exc.code)}"
    if isinstance(exc, urllib.error.URLError):
        return "URL_ERROR"
    if isinstance(exc, TimeoutError):
        return "TIMEOUT"
    if isinstance(exc, ssl.SSLError):
        return "TLS_ERROR"
    return type(exc).__name__.upper()[:64]


def write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    data = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    temp.write_text(data, encoding="utf-8")
    temp.replace(path)


def validate_policy(raw: Any) -> dict[str, Any]:
    require(isinstance(raw, dict), "policy must be an object")
    policy = dict(raw)
    require(policy.get("schema") == POLICY_SCHEMA, "unexpected policy schema")
    controller_repository = require_repo(
        policy.get("controller_repository"), "controller_repository"
    )
    controller_branch = require_string(
        policy.get("controller_branch"), "controller_branch"
    )
    require(
        re.fullmatch(r"[A-Za-z0-9._/-]+", controller_branch) is not None
        and ".." not in controller_branch,
        "controller_branch is invalid",
    )
    source = policy.get("source_manifest")
    require(isinstance(source, dict), "source_manifest must be an object")
    source_repository = require_repo(source.get("repository"), "source_manifest.repository")
    branch = require_string(source.get("branch"), "source_manifest.branch")
    require(
        re.fullmatch(r"[A-Za-z0-9._/-]+", branch) is not None and ".." not in branch,
        "source_manifest.branch is invalid",
    )
    source_path = require_string(source.get("path"), "source_manifest.path")
    require(
        not source_path.startswith("/") and ".." not in Path(source_path).parts,
        "source_manifest.path must be repository-relative",
    )
    require(source.get("require_verified_commit") is True, "source commit verification must be required")

    probe = policy.get("probe")
    require(isinstance(probe, dict), "probe must be an object")
    probe_out = {
        "interval_minutes": require_positive_int(
            probe.get("interval_minutes"), "probe.interval_minutes", maximum=60
        ),
        "timeout_seconds": require_positive_int(
            probe.get("timeout_seconds"), "probe.timeout_seconds", maximum=60
        ),
        "max_response_bytes": require_positive_int(
            probe.get("max_response_bytes"), "probe.max_response_bytes", maximum=2_097_152
        ),
        "parallelism": require_positive_int(
            probe.get("parallelism"), "probe.parallelism", maximum=32
        ),
        "failure_threshold": require_positive_int(
            probe.get("failure_threshold"), "probe.failure_threshold", maximum=10
        ),
    }

    recovery = policy.get("recovery")
    require(isinstance(recovery, dict), "recovery must be an object")
    require(isinstance(recovery.get("enabled"), bool), "recovery.enabled must be boolean")
    recovery_out = {
        "enabled": recovery["enabled"],
        "max_actions_per_cycle": require_positive_int(
            recovery.get("max_actions_per_cycle"),
            "recovery.max_actions_per_cycle",
            maximum=4,
        ),
        "cooldown_minutes": require_positive_int(
            recovery.get("cooldown_minutes"), "recovery.cooldown_minutes", maximum=1440
        ),
        "max_attempts_before_incident": require_positive_int(
            recovery.get("max_attempts_before_incident"),
            "recovery.max_attempts_before_incident",
            maximum=10,
        ),
        "paused_stages": sorted(
            {
                require_string(value, "recovery.paused_stages[]").upper()
                for value in recovery.get("paused_stages", [])
            }
        ),
        "transitional_stages": sorted(
            {
                require_string(value, "recovery.transitional_stages[]").upper()
                for value in recovery.get("transitional_stages", [])
            }
        ),
        "terminal_stages": sorted(
            {
                require_string(value, "recovery.terminal_stages[]").upper()
                for value in recovery.get("terminal_stages", [])
            }
        ),
    }
    require(recovery_out["paused_stages"], "recovery.paused_stages cannot be empty")
    require(recovery_out["terminal_stages"], "recovery.terminal_stages cannot be empty")
    require(
        not set(recovery_out["paused_stages"]).intersection(recovery_out["terminal_stages"]),
        "paused and terminal stages overlap",
    )

    issue = policy.get("state_issue")
    require(isinstance(issue, dict), "state_issue must be an object")
    issue_title = require_string(issue.get("title"), "state_issue.title")
    require(len(issue_title) <= 120, "state_issue.title is too long")
    heartbeat_minutes = require_positive_int(
        issue.get("heartbeat_minutes"), "state_issue.heartbeat_minutes", maximum=1440
    )

    allowed_raw = policy.get("allowed_hf_repositories")
    require(isinstance(allowed_raw, list) and allowed_raw, "allowed_hf_repositories must be non-empty")
    allowed = [require_repo(value, "allowed_hf_repositories[]") for value in allowed_raw]
    require(len(allowed) == len(set(allowed)), "allowed_hf_repositories contains duplicates")
    require(
        all(value.startswith("SZLHOLDINGS/") for value in allowed),
        "every HF repository must be in SZLHOLDINGS",
    )

    return {
        "schema": POLICY_SCHEMA,
        "controller_repository": controller_repository,
        "controller_branch": controller_branch,
        "source_manifest": {
            "repository": source_repository,
            "branch": branch,
            "path": source_path,
            "require_verified_commit": True,
        },
        "probe": probe_out,
        "recovery": recovery_out,
        "state_issue": {
            "title": issue_title,
            "heartbeat_minutes": heartbeat_minutes,
        },
        "allowed_hf_repositories": sorted(allowed),
    }


def load_policy(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw_bytes = path.read_bytes()
        raw = json.loads(raw_bytes)
    except OSError as exc:
        raise ContractError(f"cannot read policy: {safe_error_kind(exc)}") from exc
    except json.JSONDecodeError as exc:
        raise ContractError("policy is not valid JSON") from exc
    return validate_policy(raw), sha256_hex(canonical_json(raw))


class GitHubApi:
    """Minimal same-provider GitHub client with bounded JSON responses."""

    def __init__(
        self,
        *,
        token: str | None,
        controller_repository: str,
        timeout: int,
        max_response_bytes: int,
    ) -> None:
        self._token = token
        self.controller_repository = controller_repository
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        context = ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), NoRedirectHandler()
        )
        self._branch_cache: dict[tuple[str, str], dict[str, Any]] = {}

    def _request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> Any:
        require(path.startswith("/"), "GitHub API path must begin with /")
        url = f"https://api.github.com{path}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        data = None
        if payload is not None:
            data = canonical_json(payload)
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        with self._opener.open(request, timeout=self.timeout) as response:
            body = response.read(self.max_response_bytes + 1)
            if len(body) > self.max_response_bytes:
                raise ContractError("GitHub response exceeded the controller limit")
            if not body:
                return None
            try:
                return json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ContractError("GitHub returned non-JSON data") from exc

    def branch(self, repository: str, branch: str) -> dict[str, Any]:
        key = (repository, branch)
        if key not in self._branch_cache:
            quoted = urllib.parse.quote(branch, safe="")
            payload = self._request("GET", f"/repos/{repository}/branches/{quoted}")
            require(isinstance(payload, dict), "GitHub branch response must be an object")
            self._branch_cache[key] = payload
        return dict(self._branch_cache[key])

    def verified_tip(self, repository: str, branch: str) -> str:
        payload = self.branch(repository, branch)
        commit = payload.get("commit")
        require(isinstance(commit, dict), f"{repository}:{branch} is missing a commit")
        sha = require_string(commit.get("sha"), f"{repository}:{branch}.sha")
        require(bool(SHA40.fullmatch(sha)), f"{repository}:{branch} has an invalid SHA")
        detail = commit.get("commit")
        require(isinstance(detail, dict), f"{repository}:{branch} is missing commit detail")
        verification = detail.get("verification")
        require(
            isinstance(verification, dict) and verification.get("verified") is True,
            f"{repository}:{branch} tip is not cryptographically verified",
        )
        return sha

    def file_at(self, repository: str, path: str, ref: str) -> bytes:
        quoted_path = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
        quoted_ref = urllib.parse.quote(ref, safe="")
        payload = self._request(
            "GET", f"/repos/{repository}/contents/{quoted_path}?ref={quoted_ref}"
        )
        require(isinstance(payload, dict), "GitHub contents response must be an object")
        require(payload.get("encoding") == "base64", "GitHub contents encoding is not base64")
        content = require_string(payload.get("content"), "GitHub contents.content")
        try:
            decoded = base64.b64decode(content, validate=False)
        except ValueError as exc:
            raise ContractError("GitHub contents base64 is invalid") from exc
        require(
            len(decoded) <= self.max_response_bytes,
            "repository file exceeded the controller limit",
        )
        return decoded

    def find_state_issue(self, title: str) -> dict[str, Any] | None:
        query = urllib.parse.urlencode(
            {
                "q": (
                    f'repo:{self.controller_repository} is:issue is:open '
                    f'in:title "{title}"'
                ),
                "per_page": "100",
            }
        )
        payload = self._request("GET", f"/search/issues?{query}")
        require(isinstance(payload, dict), "GitHub issue search response must be an object")
        items = payload.get("items")
        require(isinstance(items, list), "GitHub issue search items must be a list")
        matches = [
            item
            for item in items
            if isinstance(item, dict)
            and "pull_request" not in item
            and item.get("title") == title
        ]
        require(len(matches) <= 1, "multiple autonomic state issues exist")
        return dict(matches[0]) if matches else None

    def upsert_state_issue(
        self,
        *,
        title: str,
        body: str,
        existing: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        require(bool(self._token), "GITHUB_TOKEN is required to persist controller state")
        if existing is None:
            payload = self._request(
                "POST",
                f"/repos/{self.controller_repository}/issues",
                {"title": title, "body": body},
            )
        else:
            number = existing.get("number")
            require(isinstance(number, int), "state issue number is invalid")
            payload = self._request(
                "PATCH",
                f"/repos/{self.controller_repository}/issues/{number}",
                {"title": title, "body": body, "state": "open"},
            )
        require(isinstance(payload, dict), "state issue write did not return an object")
        return payload


def expected_hf_host(repo_id: str) -> str:
    return repo_id.replace("/", "-").lower() + ".hf.space"


def validate_path(path: Any, label: str) -> str:
    value = require_string(path, label)
    parsed = urllib.parse.urlsplit(value)
    require(value.startswith("/"), f"{label} must begin with /")
    require(not parsed.scheme and not parsed.netloc, f"{label} must not contain an origin")
    require(not parsed.query and not parsed.fragment, f"{label} cannot contain query or fragment")
    require("//" not in value, f"{label} cannot contain an empty path segment")
    return value


def validate_manifest(
    raw: Any,
    *,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    require(isinstance(raw, dict), "manifest must be an object")
    manifest = dict(raw)
    require(manifest.get("schema") == MANIFEST_SCHEMA, "unexpected estate manifest schema")
    require(
        manifest.get("source_repository")
        == policy["source_manifest"]["repository"],
        "manifest source repository drift",
    )
    require(
        manifest.get("truth_policy") == "exact-source-or-unverified",
        "manifest truth policy drift",
    )
    allowed_hosts_raw = manifest.get("allowed_hosts")
    require(isinstance(allowed_hosts_raw, list), "manifest allowed_hosts must be a list")
    allowed_hosts = {require_string(item, "manifest.allowed_hosts[]") for item in allowed_hosts_raw}
    require("api.github.com" in allowed_hosts, "GitHub API host is not allowed")
    require("huggingface.co" in allowed_hosts, "Hugging Face host is not allowed")

    raw_surfaces = list(manifest.get("platforms") or []) + list(
        manifest.get("public_products") or []
    )
    require(raw_surfaces, "manifest contains no public surfaces")
    require(len(raw_surfaces) <= 32, "manifest contains too many public surfaces")
    allowed_repositories = set(policy["allowed_hf_repositories"])
    surfaces: list[dict[str, Any]] = []
    ids: set[str] = set()
    repos: set[str] = set()
    origins: set[str] = set()
    for index, item in enumerate(raw_surfaces):
        require(isinstance(item, dict), f"surface[{index}] must be an object")
        surface = dict(item)
        surface_id = require_string(surface.get("id"), f"surface[{index}].id")
        require(bool(SURFACE_ID.fullmatch(surface_id)), f"{surface_id} has an invalid id")
        require(surface_id not in ids, f"duplicate surface id: {surface_id}")
        require(surface.get("public") is True, f"{surface_id} is not explicitly public")
        repo_id = require_repo(surface.get("hf_repository"), f"{surface_id}.hf_repository")
        require(repo_id in allowed_repositories, f"{surface_id} HF repository is not allowlisted")
        require(repo_id not in repos, f"duplicate HF repository: {repo_id}")
        base_url = require_string(surface.get("base_url"), f"{surface_id}.base_url").rstrip("/")
        parsed = urllib.parse.urlsplit(base_url)
        require(parsed.scheme == "https", f"{surface_id} must use HTTPS")
        require(parsed.hostname == expected_hf_host(repo_id), f"{surface_id} host/repository mismatch")
        require(parsed.hostname in allowed_hosts, f"{surface_id} host is not manifest-allowlisted")
        require(parsed.port in (None, 443), f"{surface_id} uses a non-standard port")
        require(parsed.path in ("", "/"), f"{surface_id} base URL contains a path")
        require(not parsed.query and not parsed.fragment, f"{surface_id} base URL is not fixed")
        require(base_url not in origins, f"duplicate surface origin: {base_url}")
        source_repo = require_repo(
            surface.get("deployment_source_repository"),
            f"{surface_id}.deployment_source_repository",
        )
        require(
            source_repo.startswith("szl-holdings/"),
            f"{surface_id} deployment source escaped the organization",
        )
        policy_name = require_string(
            surface.get("revision_policy"), f"{surface_id}.revision_policy"
        )
        require(
            policy_name in {"exact-default-branch", "declared-commit"},
            f"{surface_id} revision policy is unknown",
        )
        default_branch = surface.get("default_branch")
        if policy_name == "exact-default-branch":
            default_branch = require_string(default_branch, f"{surface_id}.default_branch")
        required_raw = surface.get("required_paths")
        require(
            isinstance(required_raw, list) and required_raw,
            f"{surface_id}.required_paths must be non-empty",
        )
        require(len(required_raw) <= 32, f"{surface_id} has too many paths")
        required_paths = [
            validate_path(value, f"{surface_id}.required_paths[]") for value in required_raw
        ]
        require(
            len(required_paths) == len(set(required_paths)),
            f"{surface_id} required paths contain duplicates",
        )
        build_path = validate_path(
            surface.get("build_info_path"), f"{surface_id}.build_info_path"
        )
        require(build_path in required_paths, f"{surface_id} build path is not required")
        ids.add(surface_id)
        repos.add(repo_id)
        origins.add(base_url)
        surfaces.append(
            {
                "id": surface_id,
                "title": require_string(surface.get("title"), f"{surface_id}.title"),
                "hf_repository": repo_id,
                "base_url": base_url,
                "deployment_source_repository": source_repo,
                "revision_policy": policy_name,
                "default_branch": default_branch,
                "build_info_path": build_path,
                "required_paths": required_paths,
            }
        )
    require(
        repos == allowed_repositories,
        "policy and manifest public HF repository sets differ",
    )
    result = dict(manifest)
    result["surfaces"] = surfaces
    result["allowed_hosts"] = sorted(allowed_hosts)
    return result


def load_signed_manifest(
    github: GitHubApi,
    policy: Mapping[str, Any],
) -> tuple[dict[str, Any], str, str]:
    source = policy["source_manifest"]
    tip = github.verified_tip(source["repository"], source["branch"])
    raw_bytes = github.file_at(source["repository"], source["path"], tip)
    try:
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("estate manifest is not valid UTF-8 JSON") from exc
    manifest = validate_manifest(raw, policy=policy)
    return manifest, tip, sha256_hex(canonical_json(raw))


def build_probe_opener() -> urllib.request.OpenerDirector:
    context = ssl.create_default_context()
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), NoRedirectHandler()
    )


def fixed_url(base_url: str, path: str) -> str:
    parsed = urllib.parse.urlsplit(path)
    require(
        path.startswith("/")
        and not parsed.scheme
        and not parsed.netloc
        and not parsed.query
        and not parsed.fragment,
        "probe path escaped fixed origin",
    )
    return f"{base_url}{path}"


def probe_path(
    opener: urllib.request.OpenerDirector,
    *,
    base_url: str,
    path: str,
    timeout: int,
    max_response_bytes: int,
) -> tuple[PathObservation, bytes | None]:
    url = fixed_url(base_url, path)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json, text/html;q=0.9, */*;q=0.1",
            "User-Agent": USER_AGENT,
            "Cache-Control": "no-cache",
        },
        method="GET",
    )
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(max_response_bytes + 1)
            if len(body) > max_response_bytes:
                raise ContractError("response exceeded the probe byte limit")
            status = int(response.status)
            elapsed_ms = int((time.monotonic() - started) * 1000)
            content_type = (
                response.headers.get("content-type", "")
                .split(";", 1)[0]
                .strip()
                .lower()
            )
            ok = 200 <= status < 300
            return (
                PathObservation(
                    path=path,
                    status=status,
                    elapsed_ms=elapsed_ms,
                    content_type=content_type,
                    body_sha256=sha256_hex(body),
                    body_bytes=len(body),
                    ok=ok,
                    error_kind=None if ok else f"HTTP_{status}",
                ),
                body,
            )
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return (
            PathObservation(
                path=path,
                status=int(exc.code) if isinstance(exc, urllib.error.HTTPError) else None,
                elapsed_ms=elapsed_ms,
                content_type="",
                body_sha256=None,
                body_bytes=None,
                ok=False,
                error_kind=safe_error_kind(exc),
            ),
            None,
        )


def selected_build_fields(payload: Mapping[str, Any]) -> dict[str, Any]:
    candidates: list[Mapping[str, Any]] = [payload]
    for key in ("build", "source", "deployment", "data"):
        value = payload.get(key)
        if isinstance(value, dict):
            candidates.append(value)
    aliases = {
        "source_repository": ("source_repository", "repository", "repo"),
        "source_revision": ("source_revision", "git_sha", "commit_sha", "sha"),
    }
    result: dict[str, Any] = {}
    for target, names in aliases.items():
        for candidate in candidates:
            for name in names:
                value = candidate.get(name)
                if value not in (None, ""):
                    result[target] = value
                    break
            if target in result:
                break
    return result


def probe_surface(
    surface: Mapping[str, Any],
    *,
    opener: urllib.request.OpenerDirector,
    github: GitHubApi,
    timeout: int,
    max_response_bytes: int,
    parallelism: int,
) -> SurfaceObservation:
    paths = list(surface["required_paths"])
    rows: dict[str, tuple[PathObservation, bytes | None]] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(parallelism, len(paths)),
        thread_name_prefix=f"probe-{surface['id']}",
    ) as pool:
        futures = {
            pool.submit(
                probe_path,
                opener,
                base_url=surface["base_url"],
                path=path,
                timeout=timeout,
                max_response_bytes=max_response_bytes,
            ): path
            for path in paths
        }
        for future in concurrent.futures.as_completed(futures):
            path = futures[future]
            try:
                rows[path] = future.result()
            except Exception as exc:
                rows[path] = (
                    PathObservation(
                        path=path,
                        status=None,
                        elapsed_ms=0,
                        content_type="",
                        body_sha256=None,
                        body_bytes=None,
                        ok=False,
                        error_kind=safe_error_kind(exc),
                    ),
                    None,
                )

    observations = tuple(rows[path][0] for path in paths)
    failures = [
        f"path:{item.path}:{item.error_kind or 'UNHEALTHY'}"
        for item in observations
        if not item.ok
    ]
    availability_ok = not failures

    source_status = "UNVERIFIED"
    source_ok = False
    source_revision: str | None = None
    expected_revision: str | None = None
    build_body = rows[surface["build_info_path"]][1]
    build_observation = rows[surface["build_info_path"]][0]
    if build_body is None or not build_observation.ok:
        failures.append("source:build-info-unavailable")
    else:
        try:
            payload = json.loads(build_body.decode("utf-8"))
            require(isinstance(payload, dict), "build info must be an object")
            fields = selected_build_fields(payload)
            source_repository = fields.get("source_repository")
            source_revision_raw = fields.get("source_revision")
            require(
                source_repository == surface["deployment_source_repository"],
                "build-info source repository mismatch",
            )
            source_revision = require_string(
                source_revision_raw, "build-info source revision"
            ).lower()
            require(bool(SHA40.fullmatch(source_revision)), "build-info source revision is invalid")
            if surface["revision_policy"] == "exact-default-branch":
                expected_revision = github.verified_tip(
                    surface["deployment_source_repository"],
                    surface["default_branch"],
                )
                source_ok = source_revision == expected_revision
                source_status = "EXACT" if source_ok else "DRIFT"
                if not source_ok:
                    failures.append("source:revision-drift")
            else:
                source_ok = True
                source_status = "DECLARED_COMMIT"
        except Exception as exc:
            source_status = "INVALID"
            failures.append(f"source:{safe_error_kind(exc)}")

    return SurfaceObservation(
        surface_id=surface["id"],
        hf_repository=surface["hf_repository"],
        base_url=surface["base_url"],
        availability_ok=availability_ok,
        source_ok=source_ok,
        source_status=source_status,
        source_revision=source_revision,
        expected_revision=expected_revision,
        paths=observations,
        failures=tuple(sorted(set(failures))),
    )


def default_surface_state() -> dict[str, Any]:
    return {
        "state": "UNKNOWN",
        "consecutive_failures": 0,
        "recovery_attempts": 0,
        "last_success_at": None,
        "last_failure_at": None,
        "last_action_at": None,
        "last_action": None,
        "last_action_result": None,
        "last_hf_stage": None,
        "last_reason": "no prior state",
    }


def plan_recovery(
    *,
    observation: SurfaceObservation,
    previous: Mapping[str, Any] | None,
    hf_stage: str,
    policy: Mapping[str, Any],
    now: dt.datetime,
    action_budget_available: bool,
) -> RecoveryPlan:
    old = {**default_surface_state(), **dict(previous or {})}
    recovery = policy["recovery"]
    now_text = now.isoformat().replace("+00:00", "Z")
    if observation.healthy:
        return RecoveryPlan(
            state="HEALTHY",
            consecutive_failures=0,
            recovery_attempts=0,
            action=None,
            reason="all required routes and source checks passed",
            last_action_at=old.get("last_action_at"),
        )
    if observation.availability_ok and not observation.source_ok:
        return RecoveryPlan(
            state="INCIDENT",
            consecutive_failures=int(old.get("consecutive_failures") or 0) + 1,
            recovery_attempts=int(old.get("recovery_attempts") or 0),
            action=None,
            reason="source integrity drift cannot be repaired by a runtime restart",
            last_action_at=old.get("last_action_at"),
        )

    failures = int(old.get("consecutive_failures") or 0) + 1
    attempts = int(old.get("recovery_attempts") or 0)
    if failures < policy["probe"]["failure_threshold"]:
        return RecoveryPlan(
            state="SUSPECT",
            consecutive_failures=failures,
            recovery_attempts=attempts,
            action=None,
            reason="failure threshold not yet reached",
            last_action_at=old.get("last_action_at"),
        )

    stage = (hf_stage or "UNKNOWN").upper()
    if stage in recovery["transitional_stages"]:
        return RecoveryPlan(
            state="RECOVERING",
            consecutive_failures=failures,
            recovery_attempts=attempts,
            action=None,
            reason=f"Hugging Face runtime is already transitional ({stage})",
            last_action_at=old.get("last_action_at"),
        )
    if attempts >= recovery["max_attempts_before_incident"]:
        return RecoveryPlan(
            state="INCIDENT",
            consecutive_failures=failures,
            recovery_attempts=attempts,
            action=None,
            reason="bounded automatic recovery budget exhausted",
            last_action_at=old.get("last_action_at"),
        )
    last_action = parse_time(old.get("last_action_at"))
    if last_action is not None:
        age = now - last_action
        if age < dt.timedelta(minutes=recovery["cooldown_minutes"]):
            return RecoveryPlan(
                state="DEGRADED",
                consecutive_failures=failures,
                recovery_attempts=attempts,
                action=None,
                reason="restart cooldown is active",
                last_action_at=old.get("last_action_at"),
            )
    if not recovery["enabled"]:
        return RecoveryPlan(
            state="DEGRADED",
            consecutive_failures=failures,
            recovery_attempts=attempts,
            action=None,
            reason="automatic recovery is disabled by policy",
            last_action_at=old.get("last_action_at"),
        )
    if not action_budget_available:
        return RecoveryPlan(
            state="DEGRADED",
            consecutive_failures=failures,
            recovery_attempts=attempts,
            action=None,
            reason="per-cycle recovery action budget is exhausted",
            last_action_at=old.get("last_action_at"),
        )

    if stage in recovery["paused_stages"]:
        action = "resume"
    elif stage in recovery["terminal_stages"]:
        action = "factory-restart"
    else:
        action = "soft-restart"
    return RecoveryPlan(
        state="RECOVERING",
        consecutive_failures=failures,
        recovery_attempts=attempts + 1,
        action=action,
        reason=f"bounded {action} admitted after {failures} consecutive failures",
        last_action_at=now_text,
    )


class HuggingFaceControl:
    """Narrow Space runtime controller; only restart_space is admitted."""

    def __init__(self, token: str | None) -> None:
        self._token = token
        self._api: Any | None = None

    def _client(self) -> Any:
        if self._api is None:
            try:
                from huggingface_hub import HfApi
            except ImportError as exc:
                raise ContractError("huggingface_hub is not installed") from exc
            self._api = HfApi(token=self._token or None)
        return self._api

    def stage(self, repo_id: str) -> str:
        try:
            runtime = self._client().get_space_runtime(repo_id=repo_id)
            return str(getattr(runtime, "stage", "") or "UNKNOWN").upper()
        except Exception:
            return "UNAVAILABLE"

    def recover(self, repo_id: str, action: str) -> dict[str, Any]:
        require(action in {"resume", "soft-restart", "factory-restart"}, "unknown recovery action")
        if not self._token:
            return {
                "ok": False,
                "status": "BLOCKED",
                "reason": "HF_TOKEN_MISSING",
                "secret_values_recorded": False,
            }
        try:
            self._client().restart_space(
                repo_id=repo_id,
                factory_reboot=(action == "factory-restart"),
            )
            return {
                "ok": True,
                "status": "REQUESTED",
                "action": action,
                "secret_values_recorded": False,
            }
        except Exception as exc:
            return {
                "ok": False,
                "status": "FAILED",
                "action": action,
                "error_kind": safe_error_kind(exc),
                "secret_values_recorded": False,
            }


def extract_state(body: Any) -> dict[str, Any]:
    if not isinstance(body, str):
        return {"schema": STATE_SCHEMA, "surfaces": {}}
    start = body.find(STATE_BEGIN)
    end = body.find(STATE_END)
    if start < 0 or end < 0 or end <= start:
        return {"schema": STATE_SCHEMA, "surfaces": {}}
    raw = body[start + len(STATE_BEGIN) : end].strip()
    try:
        state = json.loads(raw)
    except json.JSONDecodeError:
        return {"schema": STATE_SCHEMA, "surfaces": {}}
    if not isinstance(state, dict) or state.get("schema") != STATE_SCHEMA:
        return {"schema": STATE_SCHEMA, "surfaces": {}}
    if not isinstance(state.get("surfaces"), dict):
        state["surfaces"] = {}
    return state


def issue_body(state: Mapping[str, Any]) -> str:
    surfaces = state.get("surfaces") if isinstance(state.get("surfaces"), dict) else {}
    counts: dict[str, int] = {}
    for item in surfaces.values():
        label = str((item or {}).get("state") or "UNKNOWN")
        counts[label] = counts.get(label, 0) + 1
    lines = [
        "# SZL Autonomic SRE State",
        "",
        "Machine-managed closed-loop state for the declared public estate.",
        "The controller may perform only bounded Hugging Face Space restarts.",
        "",
        f"- Updated: `{state.get('updated_at', 'UNAVAILABLE')}`",
        f"- Manifest revision: `{state.get('manifest_revision', 'UNAVAILABLE')}`",
        f"- Controller revision: `{state.get('controller_revision', 'UNAVAILABLE')}`",
        f"- State counts: `{json.dumps(counts, sort_keys=True)}`",
        "",
        "| Surface | State | Failures | Attempts | Last action |",
        "|---|---|---:|---:|---|",
    ]
    for surface_id in sorted(surfaces):
        item = surfaces[surface_id]
        lines.append(
            "| {id} | {state} | {failures} | {attempts} | {action} |".format(
                id=surface_id,
                state=item.get("state", "UNKNOWN"),
                failures=item.get("consecutive_failures", 0),
                attempts=item.get("recovery_attempts", 0),
                action=item.get("last_action") or "—",
            )
        )
    lines.extend(
        [
            "",
            "Do not edit the machine state between the markers.",
            "",
            STATE_BEGIN + json.dumps(state, sort_keys=True, separators=(",", ":")) + STATE_END,
            "",
        ]
    )
    return "\n".join(lines)


def state_requires_write(
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
    *,
    heartbeat_minutes: int,
    now: dt.datetime,
) -> bool:
    if previous.get("surfaces") != current.get("surfaces"):
        return True
    last = parse_time(previous.get("updated_at"))
    return last is None or now - last >= dt.timedelta(minutes=heartbeat_minutes)


def make_surface_state(
    *,
    previous: Mapping[str, Any] | None,
    observation: SurfaceObservation,
    plan: RecoveryPlan,
    stage: str,
    action_result: Mapping[str, Any] | None,
    now_text: str,
) -> dict[str, Any]:
    old = {**default_surface_state(), **dict(previous or {})}
    result = dict(old)
    result.update(
        {
            "state": plan.state,
            "consecutive_failures": plan.consecutive_failures,
            "recovery_attempts": plan.recovery_attempts,
            "last_hf_stage": stage,
            "last_reason": plan.reason,
            "source_status": observation.source_status,
            "last_probe_ok": observation.healthy,
        }
    )
    if observation.healthy:
        if old.get("state") != "HEALTHY" or not old.get("last_success_at"):
            result["last_success_at"] = now_text
        result["last_failure_at"] = old.get("last_failure_at")
    else:
        result["last_failure_at"] = now_text
    if plan.action:
        result["last_action"] = plan.action
        result["last_action_at"] = plan.last_action_at
        result["last_action_result"] = dict(action_result or {})
        if not action_result or action_result.get("ok") is not True:
            result["state"] = "DEGRADED"
    return result


def offline_contract(policy: Mapping[str, Any], policy_sha256: str) -> dict[str, Any]:
    return {
        "schema": OFFLINE_SCHEMA,
        "valid": True,
        "policy_sha256": policy_sha256,
        "controller_repository": policy["controller_repository"],
        "controller_branch": policy["controller_branch"],
        "source_manifest": policy["source_manifest"],
        "allowed_hf_repositories": policy["allowed_hf_repositories"],
        "authority": {
            "fixed_manifest": True,
            "fixed_https_origins": True,
            "arbitrary_shell": False,
            "dns_mutation": False,
            "asset_deletion": False,
            "visibility_mutation": False,
            "hardware_mutation": False,
            "max_actions_per_cycle": policy["recovery"]["max_actions_per_cycle"],
        },
        "secret_values_recorded": False,
    }


def run_live(
    *,
    policy: Mapping[str, Any],
    policy_sha256: str,
    output: Path,
    dry_run: bool,
) -> int:
    repository = os.getenv("GITHUB_REPOSITORY", "").strip()
    if repository:
        require(
            repository == policy["controller_repository"],
            "workflow repository does not match policy authority",
        )
    token = (os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or "").strip() or None
    github = GitHubApi(
        token=token,
        controller_repository=policy["controller_repository"],
        timeout=policy["probe"]["timeout_seconds"],
        max_response_bytes=max(policy["probe"]["max_response_bytes"], 1_048_576),
    )
    controller_tip = github.verified_tip(
        policy["controller_repository"], policy["controller_branch"]
    )
    workflow_sha = os.getenv("GITHUB_SHA", "").strip()
    if workflow_sha:
        require(
            workflow_sha == controller_tip,
            "controller workflow is not running from the exact verified default-branch tip",
        )
    manifest, manifest_revision, manifest_sha256 = load_signed_manifest(github, policy)
    state_issue = github.find_state_issue(policy["state_issue"]["title"]) if token else None
    previous_state = extract_state(state_issue.get("body") if state_issue else None)
    previous_surfaces = previous_state.get("surfaces") or {}
    now = dt.datetime.now(dt.timezone.utc)
    now_text = now.isoformat().replace("+00:00", "Z")
    opener = build_probe_opener()

    observations: dict[str, SurfaceObservation] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(
            policy["probe"]["parallelism"],
            len(manifest["surfaces"]),
        ),
        thread_name_prefix="estate",
    ) as pool:
        futures = {
            pool.submit(
                probe_surface,
                surface,
                opener=opener,
                github=github,
                timeout=policy["probe"]["timeout_seconds"],
                max_response_bytes=policy["probe"]["max_response_bytes"],
                parallelism=max(1, policy["probe"]["parallelism"] // 2),
            ): surface
            for surface in manifest["surfaces"]
        }
        for future in concurrent.futures.as_completed(futures):
            surface = futures[future]
            try:
                observations[surface["id"]] = future.result()
            except Exception as exc:
                observations[surface["id"]] = SurfaceObservation(
                    surface_id=surface["id"],
                    hf_repository=surface["hf_repository"],
                    base_url=surface["base_url"],
                    availability_ok=False,
                    source_ok=False,
                    source_status="UNAVAILABLE",
                    source_revision=None,
                    expected_revision=None,
                    paths=(),
                    failures=(f"controller:{safe_error_kind(exc)}",),
                )

    hf = HuggingFaceControl(
        (os.getenv("HF_TOKEN") or os.getenv("HUGGING_FACE_HUB_TOKEN") or "").strip()
        or None
    )
    actions_left = 0 if dry_run else policy["recovery"]["max_actions_per_cycle"]
    surface_states: dict[str, Any] = {}
    actions: list[dict[str, Any]] = []
    report_surfaces: list[dict[str, Any]] = []

    for surface in manifest["surfaces"]:
        observation = observations[surface["id"]]
        previous = previous_surfaces.get(surface["id"])
        stage = hf.stage(surface["hf_repository"])
        plan = plan_recovery(
            observation=observation,
            previous=previous if isinstance(previous, dict) else None,
            hf_stage=stage,
            policy=policy,
            now=now,
            action_budget_available=actions_left > 0,
        )
        action_result: dict[str, Any] | None = None
        if plan.action:
            if dry_run:
                action_result = {
                    "ok": False,
                    "status": "DRY_RUN",
                    "action": plan.action,
                    "secret_values_recorded": False,
                }
            else:
                action_result = hf.recover(surface["hf_repository"], plan.action)
                actions_left -= 1
                actions.append(
                    {
                        "surface": surface["id"],
                        "hf_repository": surface["hf_repository"],
                        "action": plan.action,
                        "result": action_result,
                    }
                )
        current = make_surface_state(
            previous=previous if isinstance(previous, dict) else None,
            observation=observation,
            plan=plan,
            stage=stage,
            action_result=action_result,
            now_text=now_text,
        )
        surface_states[surface["id"]] = current
        row = observation.receipt()
        row.update(
            {
                "hf_stage": stage,
                "state_before": (
                    previous.get("state", "UNKNOWN")
                    if isinstance(previous, dict)
                    else "UNKNOWN"
                ),
                "state_after": current["state"],
                "consecutive_failures": current["consecutive_failures"],
                "recovery_attempts": current["recovery_attempts"],
                "planned_action": plan.action,
                "action_result": action_result,
                "reason": current["last_reason"],
            }
        )
        report_surfaces.append(row)

    current_state = {
        "schema": STATE_SCHEMA,
        "updated_at": now_text,
        "controller_revision": controller_tip,
        "manifest_revision": manifest_revision,
        "manifest_sha256": manifest_sha256,
        "policy_sha256": policy_sha256,
        "surfaces": surface_states,
        "secret_values_recorded": False,
    }
    healthy_count = sum(item["state"] == "HEALTHY" for item in surface_states.values())
    report = {
        "schema": RECEIPT_SCHEMA,
        "cycle_id": f"sre_{uuid.uuid4().hex}",
        "generated_at": now_text,
        "controller_repository": policy["controller_repository"],
        "controller_revision": controller_tip,
        "manifest_repository": policy["source_manifest"]["repository"],
        "manifest_revision": manifest_revision,
        "manifest_sha256": manifest_sha256,
        "policy_sha256": policy_sha256,
        "dry_run": dry_run,
        "public_surface_count": len(surface_states),
        "healthy_surface_count": healthy_count,
        "all_healthy": healthy_count == len(surface_states),
        "actions": actions,
        "surfaces": report_surfaces,
        "authority": {
            "fixed_manifest": True,
            "fixed_https_origins": True,
            "hf_restart_only": True,
            "arbitrary_shell": False,
            "dns_mutation": False,
            "asset_deletion": False,
            "visibility_mutation": False,
            "max_actions_per_cycle": policy["recovery"]["max_actions_per_cycle"],
        },
        "secret_values_recorded": False,
    }
    report["receipt_sha256"] = sha256_hex(canonical_json(report))
    write_json_atomic(output, report)
    output.with_suffix(output.suffix + ".sha256").write_text(
        report["receipt_sha256"] + "\n", encoding="ascii"
    )

    if not dry_run:
        require(bool(token), "GITHUB_TOKEN is required for durable controller state")
        if state_requires_write(
            previous_state,
            current_state,
            heartbeat_minutes=policy["state_issue"]["heartbeat_minutes"],
            now=now,
        ):
            github.upsert_state_issue(
                title=policy["state_issue"]["title"],
                body=issue_body(current_state),
                existing=state_issue,
            )
    return 0


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument(
        "--policy",
        type=Path,
        default=Path("autonomic/policy.json"),
    )
    command.add_argument(
        "--output",
        type=Path,
        default=Path("reports/autonomic-sre.json"),
    )
    command.add_argument("--dry-run", action="store_true")
    command.add_argument("--offline-contract-only", action="store_true")
    return command


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        policy, policy_sha256 = load_policy(args.policy)
        if args.offline_contract_only:
            receipt = offline_contract(policy, policy_sha256)
            write_json_atomic(args.output, receipt)
            print(json.dumps(receipt, indent=2, sort_keys=True))
            return 0
        return run_live(
            policy=policy,
            policy_sha256=policy_sha256,
            output=args.output,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        failure = {
            "schema": RECEIPT_SCHEMA,
            "generated_at": utc_now(),
            "ok": False,
            "error_kind": safe_error_kind(exc),
            "error": REDACTED_ERROR,
            "secret_values_recorded": False,
        }
        try:
            write_json_atomic(args.output, failure)
        except Exception:
            pass
        print(json.dumps(failure, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
