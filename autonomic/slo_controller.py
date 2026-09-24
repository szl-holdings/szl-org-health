#!/usr/bin/env python3
"""Independent SLO, burn-rate, and deadman controller for the SZL public estate.

This plane is intentionally observational. It reads one signed repository-owned
manifest, probes only its fixed HTTPS origins, checks the freshness of the
bounded recovery workflow, persists compact public reliability history, and
maintains one deduplicated incident. It cannot restart services, dispatch
workflows, edit source, change DNS, alter hardware, or execute product actions.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import dataclasses
import datetime as dt
import hashlib
import json
import math
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

POLICY_SCHEMA = "szl.autonomic-slo-policy/v1"
MANIFEST_SCHEMA = "szl.public-estate/v1"
STATE_SCHEMA = "szl.autonomic-slo-state/v1"
RECEIPT_SCHEMA = "szl.autonomic-slo-receipt/v1"
CONTRACT_SCHEMA = "szl.autonomic-slo-contract/v1"
STATE_BEGIN = "<!-- SZL_AUTONOMIC_SLO_STATE_BEGIN\n"
STATE_END = "\nSZL_AUTONOMIC_SLO_STATE_END -->"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SURFACE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
USER_AGENT = "SZLHOLDINGS-AutonomicSLO/1.0"
MAX_GITHUB_BYTES = 2_097_152
MAX_STATE_BYTES = 1_572_864
MAX_ISSUE_BODY_BYTES = 60_000
BUCKET_MINUTES = 15
ACTIVE_RUN_STATES = {"queued", "in_progress", "waiting", "requested", "pending"}


class ContractError(RuntimeError):
    """Raised when repository-owned authority or evidence is malformed."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects so a probe never escapes its manifest origin."""

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
class PathProbe:
    path: str
    ok: bool
    status: int | None
    latency_ms: int
    content_type: str
    body_sha256: str | None
    body_bytes: int | None
    error_kind: str | None

    def receipt(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class SurfaceProbe:
    surface_id: str
    hf_repository: str
    base_url: str
    ok: bool
    maximum_latency_ms: int
    provider_blocker: str | None
    paths: tuple[PathProbe, ...]

    def receipt(self) -> dict[str, Any]:
        return {
            "id": self.surface_id,
            "hf_repository": self.hf_repository,
            "base_url": self.base_url,
            "ok": self.ok,
            "maximum_latency_ms": self.maximum_latency_ms,
            "provider_blocker": self.provider_blocker,
            "paths": [item.receipt() for item in self.paths],
        }


@dataclasses.dataclass(frozen=True)
class WindowResult:
    name: str
    minutes: int
    expected_samples: int
    observed_samples: int
    coverage_percent: float
    availability_percent: float | None
    error_budget_burn: float | None
    latency_breach_percent: float | None
    sufficient_coverage: bool

    def receipt(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


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


def observation_digest(report: Mapping[str, Any]) -> str:
    """Bind the measured result independently of subsequent incident mutations."""
    return sha256_hex(canonical_json({
        key: value
        for key, value in report.items()
        if key not in {"incident", "receipt_sha256", "observation_sha256"}
    }))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def require_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"{label} must be a string")
    return value.strip()


def require_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer")
    require(minimum <= value <= maximum, f"{label} must be between {minimum} and {maximum}")
    return value


def require_number(
    value: Any,
    label: str,
    *,
    minimum: float,
    maximum: float,
) -> float:
    require(
        isinstance(value, (int, float)) and not isinstance(value, bool),
        f"{label} must be numeric",
    )
    result = float(value)
    require(math.isfinite(result), f"{label} must be finite")
    require(minimum <= result <= maximum, f"{label} is outside its bounds")
    return result


def require_repository(value: Any, label: str) -> str:
    repository = require_string(value, label)
    require(bool(REPOSITORY.fullmatch(repository)), f"{label} must be owner/repository")
    return repository


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
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def validate_policy(raw: Any) -> dict[str, Any]:
    require(isinstance(raw, dict), "policy must be an object")
    policy = dict(raw)
    require(policy.get("schema") == POLICY_SCHEMA, "unexpected policy schema")
    controller_repository = require_repository(
        policy.get("controller_repository"), "controller_repository"
    )
    controller_branch = require_string(policy.get("controller_branch"), "controller_branch")
    source = policy.get("source_manifest")
    require(isinstance(source, dict), "source_manifest must be an object")
    source_repository = require_repository(source.get("repository"), "source_manifest.repository")
    source_branch = require_string(source.get("branch"), "source_manifest.branch")
    source_path = require_string(source.get("path"), "source_manifest.path")
    require(not source_path.startswith("/"), "source_manifest.path must be repository-relative")
    require(".." not in Path(source_path).parts, "source_manifest.path escapes the repository")
    require(source.get("require_verified_commit") is True, "signed source tip must be required")

    cadence = require_int(policy.get("cadence_minutes"), "cadence_minutes", minimum=5, maximum=60)
    retention = require_int(
        policy.get("history_retention_minutes"),
        "history_retention_minutes",
        minimum=1440,
        maximum=43200,
    )
    availability = require_number(
        policy.get("availability_objective_percent"),
        "availability_objective_percent",
        minimum=90.0,
        maximum=99.9999,
    )
    latency = require_int(policy.get("latency_objective_ms"), "latency_objective_ms", minimum=100, maximum=60000)
    recovery = require_int(
        policy.get("recovery_objective_minutes"),
        "recovery_objective_minutes",
        minimum=cadence,
        maximum=1440,
    )
    coverage = require_number(
        policy.get("minimum_window_coverage_percent"),
        "minimum_window_coverage_percent",
        minimum=10.0,
        maximum=100.0,
    )

    probe = policy.get("probe")
    require(isinstance(probe, dict), "probe must be an object")
    probe_out = {
        "timeout_seconds": require_int(
            probe.get("timeout_seconds"), "probe.timeout_seconds", minimum=1, maximum=60
        ),
        "max_response_bytes": require_int(
            probe.get("max_response_bytes"),
            "probe.max_response_bytes",
            minimum=1024,
            maximum=2_097_152,
        ),
        "parallelism": require_int(
            probe.get("parallelism"), "probe.parallelism", minimum=1, maximum=32
        ),
    }

    windows_raw = policy.get("burn_windows")
    require(isinstance(windows_raw, list) and len(windows_raw) == 3, "exactly three burn windows are required")
    windows: list[dict[str, Any]] = []
    names: set[str] = set()
    previous_minutes = 0
    for index, value in enumerate(windows_raw):
        require(isinstance(value, dict), f"burn_windows[{index}] must be an object")
        name = require_string(value.get("name"), f"burn_windows[{index}].name")
        require(name not in names, "burn window names must be unique")
        minutes = require_int(
            value.get("minutes"), f"burn_windows[{index}].minutes", minimum=cadence, maximum=retention
        )
        require(minutes > previous_minutes, "burn windows must be strictly increasing")
        threshold = require_number(
            value.get("burn_threshold"),
            f"burn_windows[{index}].burn_threshold",
            minimum=1.0,
            maximum=1000.0,
        )
        names.add(name)
        previous_minutes = minutes
        windows.append({"name": name, "minutes": minutes, "burn_threshold": threshold})
    require(retention >= windows[-1]["minutes"], "history retention must cover the slow window")

    deadman = policy.get("deadman")
    require(isinstance(deadman, dict), "deadman must be an object")
    workflow_file = require_string(deadman.get("workflow_file"), "deadman.workflow_file")
    require(
        workflow_file.endswith((".yml", ".yaml")) and "/" not in workflow_file and "\\" not in workflow_file,
        "deadman.workflow_file must be a workflow filename",
    )
    maximum_age = require_int(
        deadman.get("maximum_age_minutes"),
        "deadman.maximum_age_minutes",
        minimum=cadence * 2,
        maximum=1440,
    )
    accepted_raw = deadman.get("accepted_conclusions")
    require(isinstance(accepted_raw, list) and accepted_raw, "deadman.accepted_conclusions must be non-empty")
    accepted = sorted({require_string(item, "deadman.accepted_conclusions[]").lower() for item in accepted_raw})

    incident = policy.get("incident")
    state_issue = policy.get("state_issue")
    require(isinstance(incident, dict), "incident must be an object")
    require(isinstance(state_issue, dict), "state_issue must be an object")
    incident_out = {
        "label": require_string(incident.get("label"), "incident.label"),
        "title": require_string(incident.get("title"), "incident.title"),
        "healthy_cycles_before_close": require_int(
            incident.get("healthy_cycles_before_close"),
            "incident.healthy_cycles_before_close",
            minimum=1,
            maximum=24,
        ),
        "refresh_minutes": require_int(
            incident.get("refresh_minutes"),
            "incident.refresh_minutes",
            minimum=cadence,
            maximum=1440,
        ),
    }
    state_out = {
        "title": require_string(state_issue.get("title"), "state_issue.title"),
        "heartbeat_minutes": require_int(
            state_issue.get("heartbeat_minutes"),
            "state_issue.heartbeat_minutes",
            minimum=cadence,
            maximum=1440,
        ),
    }
    require(incident_out["title"] != state_out["title"], "incident and state issue titles must differ")

    allowed_raw = policy.get("allowed_hf_repositories")
    require(isinstance(allowed_raw, list) and allowed_raw, "allowed_hf_repositories must be non-empty")
    allowed = [require_repository(item, "allowed_hf_repositories[]") for item in allowed_raw]
    require(len(allowed) == len(set(allowed)), "allowed_hf_repositories contains duplicates")
    require(all(item.startswith("SZLHOLDINGS/") for item in allowed), "HF repositories escaped SZLHOLDINGS")

    return {
        "schema": POLICY_SCHEMA,
        "controller_repository": controller_repository,
        "controller_branch": controller_branch,
        "source_manifest": {
            "repository": source_repository,
            "branch": source_branch,
            "path": source_path,
            "require_verified_commit": True,
        },
        "cadence_minutes": cadence,
        "history_retention_minutes": retention,
        "availability_objective_percent": availability,
        "latency_objective_ms": latency,
        "recovery_objective_minutes": recovery,
        "minimum_window_coverage_percent": coverage,
        "probe": probe_out,
        "burn_windows": windows,
        "deadman": {
            "workflow_file": workflow_file,
            "maximum_age_minutes": maximum_age,
            "accepted_conclusions": accepted,
        },
        "incident": incident_out,
        "state_issue": state_out,
        "allowed_hf_repositories": sorted(allowed),
    }


def load_policy(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ContractError(f"policy unavailable: {safe_error_kind(exc)}") from exc
    except json.JSONDecodeError as exc:
        raise ContractError("policy is not valid JSON") from exc
    return validate_policy(raw), sha256_hex(canonical_json(raw))


class GitHubApi:
    """Small fixed-provider GitHub client with bounded responses."""

    def __init__(self, *, token: str | None, repository: str, timeout: int) -> None:
        self.token = token
        self.repository = repository
        self.timeout = timeout
        context = ssl.create_default_context()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), NoRedirectHandler()
        )
        self.branch_cache: dict[tuple[str, str], dict[str, Any]] = {}

    def request(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> Any:
        require(path.startswith("/"), "GitHub API path must begin with /")
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = None
        if payload is not None:
            data = canonical_json(payload)
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"https://api.github.com{path}",
            data=data,
            headers=headers,
            method=method,
        )
        with self.opener.open(request, timeout=self.timeout) as response:
            body = response.read(MAX_GITHUB_BYTES + 1)
            require(len(body) <= MAX_GITHUB_BYTES, "GitHub response exceeded the byte limit")
            if not body:
                return None
            try:
                return json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ContractError("GitHub returned non-JSON data") from exc

    def branch(self, repository: str, branch: str) -> dict[str, Any]:
        key = (repository, branch)
        if key not in self.branch_cache:
            quoted = urllib.parse.quote(branch, safe="")
            value = self.request("GET", f"/repos/{repository}/branches/{quoted}")
            require(isinstance(value, dict), "branch response must be an object")
            self.branch_cache[key] = value
        return dict(self.branch_cache[key])

    def verified_tip(self, repository: str, branch: str) -> str:
        value = self.branch(repository, branch)
        commit = value.get("commit")
        require(isinstance(commit, dict), "branch response is missing commit")
        sha = require_string(commit.get("sha"), "branch commit sha").lower()
        require(bool(SHA40.fullmatch(sha)), "branch commit sha is invalid")
        detail = commit.get("commit")
        verification = detail.get("verification") if isinstance(detail, dict) else None
        require(
            isinstance(verification, dict) and verification.get("verified") is True,
            f"{repository}:{branch} tip is not cryptographically verified",
        )
        return sha

    def file_at(self, repository: str, path: str, ref: str) -> bytes:
        quoted_path = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
        quoted_ref = urllib.parse.quote(ref, safe="")
        value = self.request("GET", f"/repos/{repository}/contents/{quoted_path}?ref={quoted_ref}")
        require(isinstance(value, dict), "contents response must be an object")
        require(value.get("encoding") == "base64", "contents response is not base64")
        encoded = require_string(value.get("content"), "contents.content")
        try:
            decoded = base64.b64decode(encoded, validate=False)
        except ValueError as exc:
            raise ContractError("contents base64 is invalid") from exc
        require(len(decoded) <= MAX_GITHUB_BYTES, "repository file exceeded the byte limit")
        return decoded

    def workflow_deadman(self, workflow_file: str, *, now: dt.datetime, policy: Mapping[str, Any]) -> dict[str, Any]:
        encoded = urllib.parse.quote(workflow_file, safe="")
        value = self.request(
            "GET",
            f"/repos/{self.repository}/actions/workflows/{encoded}/runs?event=schedule&per_page=20",
        )
        require(isinstance(value, dict), "workflow runs response must be an object")
        runs = value.get("workflow_runs")
        require(isinstance(runs, list), "workflow runs must be a list")
        candidates = [item for item in runs if isinstance(item, dict)]
        if not candidates:
            return {
                "ok": False,
                "state": "MISSING",
                "age_minutes": None,
                "run_id": None,
                "reason": "no scheduled recovery run was observed",
            }
        candidates.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        latest = candidates[0]
        observed = parse_time(latest.get("updated_at") or latest.get("created_at"))
        if observed is None:
            return {
                "ok": False,
                "state": "INVALID_TIMESTAMP",
                "age_minutes": None,
                "run_id": latest.get("id"),
                "reason": "latest recovery run has no valid timestamp",
            }
        age = max(0.0, (now - observed).total_seconds() / 60.0)
        status = str(latest.get("status") or "unknown").lower()
        conclusion = str(latest.get("conclusion") or "").lower() or None
        alive = status in ACTIVE_RUN_STATES or (
            status == "completed" and conclusion in policy["deadman"]["accepted_conclusions"]
        )
        fresh = age <= policy["deadman"]["maximum_age_minutes"]
        return {
            "ok": alive and fresh,
            "state": "FRESH" if alive and fresh else ("STALE" if not fresh else "INVALID_CONCLUSION"),
            "age_minutes": round(age, 3),
            "run_id": latest.get("id"),
            "status": status,
            "conclusion": conclusion,
            "created_at": latest.get("created_at"),
            "updated_at": latest.get("updated_at"),
            "reason": "latest scheduled recovery heartbeat is current" if alive and fresh else "scheduled recovery heartbeat is stale or invalid",
        }

    def find_open_issue(self, title: str) -> dict[str, Any] | None:
        query = urllib.parse.urlencode(
            {"q": f'repo:{self.repository} is:issue is:open in:title "{title}"', "per_page": "100"}
        )
        value = self.request("GET", f"/search/issues?{query}")
        require(isinstance(value, dict), "issue search response must be an object")
        items = value.get("items")
        require(isinstance(items, list), "issue search items must be a list")
        matches = [
            item
            for item in items
            if isinstance(item, dict)
            and "pull_request" not in item
            and item.get("title") == title
        ]
        require(len(matches) <= 1, f"multiple open issues exist for {title}")
        return dict(matches[0]) if matches else None

    def ensure_label(self, label: str) -> None:
        require(bool(self.token), "GITHUB_TOKEN is required for issue writes")
        try:
            self.request(
                "POST",
                f"/repos/{self.repository}/labels",
                {
                    "name": label,
                    "color": "B60205",
                    "description": "Autonomic SLO, error-budget, or deadman incident",
                },
            )
        except urllib.error.HTTPError as exc:
            if int(exc.code) != 422:
                raise

    def create_issue(self, *, title: str, body: str, labels: Sequence[str] = ()) -> dict[str, Any]:
        require(bool(self.token), "GITHUB_TOKEN is required for issue writes")
        value = self.request(
            "POST",
            f"/repos/{self.repository}/issues",
            {"title": title, "body": body, "labels": list(labels)},
        )
        require(isinstance(value, dict), "issue creation response must be an object")
        return value

    def update_issue(self, issue: Mapping[str, Any], *, body: str, state: str = "open") -> dict[str, Any]:
        require(bool(self.token), "GITHUB_TOKEN is required for issue writes")
        number = issue.get("number")
        require(isinstance(number, int), "issue number is invalid")
        value = self.request(
            "PATCH",
            f"/repos/{self.repository}/issues/{number}",
            {"body": body, "state": state, "state_reason": "completed" if state == "closed" else None},
        )
        require(isinstance(value, dict), "issue update response must be an object")
        return value


def expected_hf_host(repository: str) -> str:
    return repository.replace("/", "-").lower() + ".hf.space"


def validate_relative_path(value: Any, label: str) -> str:
    path = require_string(value, label)
    parsed = urllib.parse.urlsplit(path)
    require(path.startswith("/"), f"{label} must begin with /")
    require(not parsed.scheme and not parsed.netloc, f"{label} contains an origin")
    require(not parsed.query and not parsed.fragment, f"{label} contains query or fragment")
    require("//" not in path, f"{label} contains an empty segment")
    return path


def validate_manifest(raw: Any, *, policy: Mapping[str, Any]) -> dict[str, Any]:
    require(isinstance(raw, dict), "manifest must be an object")
    manifest = dict(raw)
    require(manifest.get("schema") == MANIFEST_SCHEMA, "unexpected manifest schema")
    require(
        manifest.get("source_repository") == policy["source_manifest"]["repository"],
        "manifest source repository drift",
    )
    require(manifest.get("truth_policy") == "exact-source-or-unverified", "manifest truth policy drift")
    hosts_raw = manifest.get("allowed_hosts")
    require(isinstance(hosts_raw, list), "manifest allowed_hosts must be a list")
    hosts = {require_string(item, "manifest.allowed_hosts[]") for item in hosts_raw}
    require("api.github.com" in hosts and "huggingface.co" in hosts, "manifest provider hosts are incomplete")

    raw_surfaces = list(manifest.get("platforms") or []) + list(manifest.get("public_products") or [])
    require(1 <= len(raw_surfaces) <= 32, "manifest public surface count is outside bounds")
    allowed = set(policy["allowed_hf_repositories"])
    identifiers: set[str] = set()
    repositories: set[str] = set()
    origins: set[str] = set()
    surfaces: list[dict[str, Any]] = []
    for index, raw_surface in enumerate(raw_surfaces):
        require(isinstance(raw_surface, dict), f"surface[{index}] must be an object")
        surface = dict(raw_surface)
        identifier = require_string(surface.get("id"), f"surface[{index}].id")
        require(bool(SURFACE_ID.fullmatch(identifier)), f"{identifier} has an invalid id")
        require(identifier not in identifiers, f"duplicate surface id: {identifier}")
        require(surface.get("public") is True, f"{identifier} is not explicitly public")
        hf_repository = require_repository(surface.get("hf_repository"), f"{identifier}.hf_repository")
        require(hf_repository in allowed, f"{identifier} is not policy-allowlisted")
        require(hf_repository not in repositories, f"duplicate HF repository: {hf_repository}")
        base_url = require_string(surface.get("base_url"), f"{identifier}.base_url").rstrip("/")
        parsed = urllib.parse.urlsplit(base_url)
        require(parsed.scheme == "https", f"{identifier} must use HTTPS")
        require(parsed.hostname == expected_hf_host(hf_repository), f"{identifier} host/repository mismatch")
        require(parsed.hostname in hosts, f"{identifier} host is not manifest-allowlisted")
        require(parsed.port in (None, 443), f"{identifier} uses a nonstandard port")
        require(parsed.path in ("", "/") and not parsed.query and not parsed.fragment, f"{identifier} origin is not fixed")
        require(base_url not in origins, f"duplicate public origin: {base_url}")
        paths_raw = surface.get("required_paths")
        require(isinstance(paths_raw, list) and paths_raw, f"{identifier}.required_paths must be non-empty")
        require(len(paths_raw) <= 32, f"{identifier} has too many required paths")
        paths = [validate_relative_path(item, f"{identifier}.required_paths[]") for item in paths_raw]
        require(len(paths) == len(set(paths)), f"{identifier} required paths contain duplicates")
        build_info_path = validate_relative_path(surface.get("build_info_path"), f"{identifier}.build_info_path")
        require(build_info_path in paths, f"{identifier} build-info path is not required")
        identifiers.add(identifier)
        repositories.add(hf_repository)
        origins.add(base_url)
        surfaces.append(
            {
                "id": identifier,
                "title": require_string(surface.get("title"), f"{identifier}.title"),
                "hf_repository": hf_repository,
                "base_url": base_url,
                "required_paths": paths,
                "build_info_path": build_info_path,
            }
        )
    require(repositories == allowed, "manifest and policy HF repository sets differ")
    result = dict(manifest)
    result["surfaces"] = surfaces
    return result


def load_signed_manifest(github: GitHubApi, policy: Mapping[str, Any]) -> tuple[dict[str, Any], str, str]:
    source = policy["source_manifest"]
    revision = github.verified_tip(source["repository"], source["branch"])
    raw_bytes = github.file_at(source["repository"], source["path"], revision)
    try:
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError("manifest is not valid UTF-8 JSON") from exc
    return validate_manifest(raw, policy=policy), revision, sha256_hex(canonical_json(raw))


def fixed_url(base_url: str, path: str) -> str:
    parsed = urllib.parse.urlsplit(path)
    require(path.startswith("/") and not parsed.scheme and not parsed.netloc, "probe path escaped its origin")
    require(not parsed.query and not parsed.fragment, "probe path contains query or fragment")
    return f"{base_url}{path}"


def probe_path(
    *,
    base_url: str,
    path: str,
    timeout_seconds: int,
    max_response_bytes: int,
) -> PathProbe:
    url = fixed_url(base_url, path)
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), NoRedirectHandler()
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json, text/html;q=0.9, */*;q=0.1",
            "Cache-Control": "no-cache",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            body = response.read(max_response_bytes + 1)
            require(len(body) <= max_response_bytes, "probe response exceeded the byte limit")
            status = int(response.status)
            latency = int((time.monotonic() - started) * 1000)
            content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            ok = 200 <= status < 300
            return PathProbe(
                path=path,
                ok=ok,
                status=status,
                latency_ms=latency,
                content_type=content_type,
                body_sha256=sha256_hex(body),
                body_bytes=len(body),
                error_kind=None if ok else f"HTTP_{status}",
            )
    except Exception as exc:
        return PathProbe(
            path=path,
            ok=False,
            status=int(exc.code) if isinstance(exc, urllib.error.HTTPError) else None,
            latency_ms=int((time.monotonic() - started) * 1000),
            content_type="",
            body_sha256=None,
            body_bytes=None,
            error_kind=safe_error_kind(exc),
        )


def classify_provider_blocker(paths: Iterable[PathProbe]) -> str | None:
    statuses = {item.status for item in paths if item.status is not None}
    if 402 in statuses:
        return "PAYMENT_REQUIRED"
    if 429 in statuses:
        return "RATE_LIMITED"
    if 451 in statuses:
        return "LEGAL_RESTRICTION"
    if 403 in statuses:
        return "ACCESS_DENIED"
    return None


def probe_surface(surface: Mapping[str, Any], *, policy: Mapping[str, Any]) -> SurfaceProbe:
    paths = list(surface["required_paths"])
    rows: dict[str, PathProbe] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(policy["probe"]["parallelism"], len(paths)),
        thread_name_prefix=f"slo-{surface['id']}",
    ) as pool:
        futures = {
            pool.submit(
                probe_path,
                base_url=surface["base_url"],
                path=path,
                timeout_seconds=policy["probe"]["timeout_seconds"],
                max_response_bytes=policy["probe"]["max_response_bytes"],
            ): path
            for path in paths
        }
        for future in concurrent.futures.as_completed(futures):
            path = futures[future]
            try:
                rows[path] = future.result()
            except Exception as exc:
                rows[path] = PathProbe(
                    path=path,
                    ok=False,
                    status=None,
                    latency_ms=0,
                    content_type="",
                    body_sha256=None,
                    body_bytes=None,
                    error_kind=safe_error_kind(exc),
                )
    ordered = tuple(rows[path] for path in paths)
    return SurfaceProbe(
        surface_id=surface["id"],
        hf_repository=surface["hf_repository"],
        base_url=surface["base_url"],
        ok=all(item.ok for item in ordered),
        maximum_latency_ms=max((item.latency_ms for item in ordered), default=0),
        provider_blocker=classify_provider_blocker(ordered),
        paths=ordered,
    )


def empty_state() -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "updated_at": None,
        "manifest_revision": None,
        "policy_sha256": None,
        "healthy_cycles": 0,
        "incident_last_refreshed_at": None,
        "surface_history": {},
    }


def encode_state(state: Mapping[str, Any]) -> str:
    raw = canonical_json(state)
    require(len(raw) <= MAX_STATE_BYTES, "SLO state exceeded the decompressed byte limit")
    compressed = zlib.compress(raw, level=9)
    return base64.b64encode(compressed).decode("ascii")


def decode_state(encoded: str) -> dict[str, Any]:
    try:
        compressed = base64.b64decode(encoded, validate=True)
        decompressor = zlib.decompressobj()
        raw = decompressor.decompress(compressed, MAX_STATE_BYTES + 1)
        raw += decompressor.flush()
        require(len(raw) <= MAX_STATE_BYTES, "SLO state exceeded the decompressed byte limit")
        value = json.loads(raw.decode("utf-8"))
    except Exception:
        return empty_state()
    if not isinstance(value, dict) or value.get("schema") != STATE_SCHEMA:
        return empty_state()
    if not isinstance(value.get("surface_history"), dict):
        value["surface_history"] = {}
    return value


def extract_state(body: Any) -> dict[str, Any]:
    if not isinstance(body, str):
        return empty_state()
    start = body.find(STATE_BEGIN)
    end = body.find(STATE_END)
    if start < 0 or end < 0 or end <= start:
        return empty_state()
    return decode_state(body[start + len(STATE_BEGIN) : end].strip())


def issue_state_body(state: Mapping[str, Any], report: Mapping[str, Any]) -> str:
    lines = [
        "# SZL Autonomic SLO State",
        "",
        "Machine-managed reliability history for the declared public estate.",
        "The embedded state is compressed, bounded, and contains public telemetry only.",
        "",
        f"- Updated: `{state.get('updated_at') or 'UNAVAILABLE'}`",
        f"- Manifest revision: `{state.get('manifest_revision') or 'UNAVAILABLE'}`",
        f"- Verdict: `{report.get('verdict', 'UNKNOWN')}`",
        f"- Severity: `{report.get('severity', 'NONE')}`",
        f"- Deadman: `{(report.get('deadman') or {}).get('state', 'UNKNOWN')}`",
        f"- Healthy cycles: `{state.get('healthy_cycles', 0)}`",
        "",
        "| Surface | Current | Provider blocker | Fast burn | Medium burn | Slow burn |",
        "|---|---|---|---:|---:|---:|",
    ]
    for surface in report.get("surfaces", []):
        windows = {item["name"]: item for item in surface.get("windows", [])}
        def burn(name: str) -> str:
            value = (windows.get(name) or {}).get("error_budget_burn")
            return "—" if value is None else f"{value:.2f}×"
        lines.append(
            f"| {surface.get('id')} | {'UP' if surface.get('current_ok') else 'DOWN'} | "
            f"{surface.get('provider_blocker') or '—'} | {burn('fast')} | {burn('medium')} | {burn('slow')} |"
        )
    encoded = encode_state(state)
    lines.extend(
        [
            "",
            "Do not edit the machine state between the markers.",
            "",
            STATE_BEGIN + encoded + STATE_END,
            "",
        ]
    )
    body = "\n".join(lines)
    require(len(body.encode("utf-8")) <= MAX_ISSUE_BODY_BYTES, "state issue body exceeded GitHub limits")
    return body


def bucket_epoch(epoch: int) -> int:
    seconds = BUCKET_MINUTES * 60
    return epoch - (epoch % seconds)


def normalize_buckets(value: Any) -> list[list[int]]:
    if not isinstance(value, list):
        return []
    rows: list[list[int]] = []
    for raw in value:
        if not isinstance(raw, list) or len(raw) != 6:
            continue
        if not all(isinstance(item, int) and not isinstance(item, bool) for item in raw):
            continue
        start, total, failures, latency_breaches, maximum_latency, last_sample = raw
        if total < 0 or failures < 0 or latency_breaches < 0:
            continue
        if failures > total or latency_breaches > total or maximum_latency < 0:
            continue
        rows.append([start, total, failures, latency_breaches, maximum_latency, last_sample])
    rows.sort(key=lambda item: item[0])
    return rows


def append_sample(
    buckets: Any,
    *,
    sample_epoch: int,
    ok: bool,
    latency_ms: int,
    latency_objective_ms: int,
    retention_minutes: int,
) -> list[list[int]]:
    rows = normalize_buckets(buckets)
    cutoff = sample_epoch - retention_minutes * 60
    rows = [item for item in rows if item[0] >= cutoff]
    start = bucket_epoch(sample_epoch)
    if rows and rows[-1][0] == start:
        row = rows[-1]
        if row[5] == sample_epoch:
            return rows
        row[1] += 1
        row[2] += 0 if ok else 1
        row[3] += 1 if latency_ms > latency_objective_ms else 0
        row[4] = max(row[4], latency_ms)
        row[5] = sample_epoch
    else:
        rows.append(
            [
                start,
                1,
                0 if ok else 1,
                1 if latency_ms > latency_objective_ms else 0,
                latency_ms,
                sample_epoch,
            ]
        )
    return rows


def summarize_window(
    buckets: Any,
    *,
    name: str,
    minutes: int,
    now_epoch: int,
    cadence_minutes: int,
    availability_objective_percent: float,
    minimum_coverage_percent: float,
) -> WindowResult:
    cutoff = now_epoch - minutes * 60
    bucket_span = BUCKET_MINUTES * 60
    rows = [
        item
        for item in normalize_buckets(buckets)
        if item[0] <= now_epoch and item[0] + bucket_span > cutoff
    ]
    observed = sum(item[1] for item in rows)
    failures = sum(item[2] for item in rows)
    latency_breaches = sum(item[3] for item in rows)
    expected = max(1, math.ceil(minutes / cadence_minutes))
    coverage = min(100.0, observed / expected * 100.0)
    sufficient = coverage >= minimum_coverage_percent
    if observed == 0:
        availability = None
        burn = None
        latency_percent = None
    else:
        availability = (observed - failures) / observed * 100.0
        error_fraction = failures / observed
        budget_fraction = max(1e-12, 1.0 - availability_objective_percent / 100.0)
        burn = error_fraction / budget_fraction
        latency_percent = latency_breaches / observed * 100.0
    return WindowResult(
        name=name,
        minutes=minutes,
        expected_samples=expected,
        observed_samples=observed,
        coverage_percent=round(coverage, 4),
        availability_percent=None if availability is None else round(availability, 6),
        error_budget_burn=None if burn is None else round(burn, 6),
        latency_breach_percent=None if latency_percent is None else round(latency_percent, 6),
        sufficient_coverage=sufficient,
    )


def severity_for_surface(
    *,
    current_ok: bool,
    provider_blocker: str | None,
    windows: Sequence[WindowResult],
    policy: Mapping[str, Any],
) -> tuple[str | None, list[str]]:
    by_name = {item.name: item for item in windows}
    configured = {item["name"]: item for item in policy["burn_windows"]}
    reasons: list[str] = []
    if provider_blocker:
        reasons.append(f"provider blocker: {provider_blocker}")
        return "SEV2", reasons
    fast = by_name.get("fast")
    medium = by_name.get("medium")
    slow = by_name.get("slow")
    fast_burn = fast.error_budget_burn if fast and fast.sufficient_coverage else None
    medium_burn = medium.error_budget_burn if medium and medium.sufficient_coverage else None
    slow_burn = slow.error_budget_burn if slow and slow.sufficient_coverage else None
    if (
        fast_burn is not None
        and medium_burn is not None
        and fast_burn >= configured["fast"]["burn_threshold"]
        and medium_burn >= configured["medium"]["burn_threshold"]
    ):
        reasons.append(f"fast/medium error-budget burn is {fast_burn:.2f}×/{medium_burn:.2f}×")
        return "SEV1", reasons
    if (
        medium_burn is not None
        and slow_burn is not None
        and medium_burn >= configured["medium"]["burn_threshold"]
        and slow_burn >= configured["slow"]["burn_threshold"]
    ):
        reasons.append(f"medium/slow error-budget burn is {medium_burn:.2f}×/{slow_burn:.2f}×")
        return "SEV2", reasons
    if slow_burn is not None and slow_burn >= configured["slow"]["burn_threshold"]:
        reasons.append(f"slow error-budget burn is {slow_burn:.2f}×")
        return "SEV3", reasons
    if fast and fast.sufficient_coverage and (fast.latency_breach_percent or 0.0) >= 25.0:
        reasons.append(f"fast-window latency breach rate is {fast.latency_breach_percent:.2f}%")
        return "SEV3", reasons
    if not current_ok:
        reasons.append("one or more required routes are currently unavailable")
        return "SEV3", reasons
    return None, reasons


def severity_rank(value: str | None) -> int:
    return {None: 0, "SEV3": 1, "SEV2": 2, "SEV1": 3}.get(value, 0)


def incident_body(report: Mapping[str, Any]) -> str:
    lines = [
        "# SZL Public Estate Reliability Incident",
        "",
        "The independent SLO plane observed a reliability or recovery-control violation.",
        "This issue is machine-managed and deduplicated.",
        "",
        f"- Observed: `{report.get('generated_at')}`",
        f"- Severity: `{report.get('severity')}`",
        f"- Verdict: `{report.get('verdict')}`",
        f"- Deadman: `{(report.get('deadman') or {}).get('state', 'UNKNOWN')}`",
        f"- Manifest: `{report.get('manifest_revision')}`",
        f"- Observation SHA-256: `{report.get('observation_sha256')}`",
        "",
        "The observation hash binds to the measured result in the workflow receipt, before incident lifecycle updates. "
        "A RECOVERED closure describes the lifecycle transition; its observation remains the recorded HEALTHY measurement.",
        "",
        "## Reasons",
        "",
    ]
    for reason in report.get("reasons", []):
        lines.append(f"- {reason}")
    lines.extend(
        [
            "",
            "| Surface | Current | Provider blocker | Max latency | Severity |",
            "|---|---|---|---:|---|",
        ]
    )
    for item in report.get("surfaces", []):
        lines.append(
            f"| {item.get('id')} | {'UP' if item.get('current_ok') else 'DOWN'} | "
            f"{item.get('provider_blocker') or '—'} | {item.get('maximum_latency_ms')} ms | "
            f"{item.get('severity') or '—'} |"
        )
    lines.extend(
        [
            "",
            "The controller does not restart services or execute product actions. Recovery remains bounded to the separate autonomic SRE plane.",
            "No credential values, response bodies, private addresses, or arbitrary commands are recorded.",
        ]
    )
    body = "\n".join(lines) + "\n"
    require(len(body.encode("utf-8")) <= MAX_ISSUE_BODY_BYTES, "incident body exceeded GitHub limits")
    return body


def offline_contract(policy: Mapping[str, Any], policy_sha256: str) -> dict[str, Any]:
    return {
        "schema": CONTRACT_SCHEMA,
        "valid": True,
        "policy_sha256": policy_sha256,
        "source_manifest": policy["source_manifest"],
        "allowed_hf_repositories": policy["allowed_hf_repositories"],
        "authority": {
            "fixed_signed_manifest": True,
            "fixed_https_origins": True,
            "issue_state_only": True,
            "service_restart": False,
            "workflow_dispatch": False,
            "source_write": False,
            "dns_mutation": False,
            "asset_deletion": False,
            "product_action": False,
            "arbitrary_shell": False,
        },
        "secret_values_recorded": False,
    }


def run_live(
    *,
    policy: Mapping[str, Any],
    policy_sha256: str,
    output: Path,
) -> int:
    repository = os.getenv("GITHUB_REPOSITORY", "").strip()
    if repository:
        require(repository == policy["controller_repository"], "workflow repository does not match policy")
    token = (os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or "").strip() or None
    require(bool(token), "GITHUB_TOKEN is required for durable reliability state")
    github = GitHubApi(
        token=token,
        repository=policy["controller_repository"],
        timeout=policy["probe"]["timeout_seconds"],
    )
    controller_tip = github.verified_tip(policy["controller_repository"], policy["controller_branch"])
    workflow_sha = os.getenv("GITHUB_SHA", "").strip()
    if workflow_sha:
        require(workflow_sha == controller_tip, "SLO workflow is not running from the exact verified main tip")
    manifest, manifest_revision, manifest_sha256 = load_signed_manifest(github, policy)
    now = dt.datetime.now(dt.timezone.utc)
    now_text = now.isoformat().replace("+00:00", "Z")
    now_epoch = int(now.timestamp())
    sample_epoch = now_epoch - (now_epoch % (policy["cadence_minutes"] * 60))

    state_issue = github.find_open_issue(policy["state_issue"]["title"])
    state = extract_state(state_issue.get("body") if state_issue else None)
    history = state.get("surface_history") if isinstance(state.get("surface_history"), dict) else {}

    probes: dict[str, SurfaceProbe] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(policy["probe"]["parallelism"], len(manifest["surfaces"])),
        thread_name_prefix="estate-slo",
    ) as pool:
        futures = {
            pool.submit(probe_surface, surface, policy=policy): surface
            for surface in manifest["surfaces"]
        }
        for future in concurrent.futures.as_completed(futures):
            surface = futures[future]
            try:
                probes[surface["id"]] = future.result()
            except Exception as exc:
                probes[surface["id"]] = SurfaceProbe(
                    surface_id=surface["id"],
                    hf_repository=surface["hf_repository"],
                    base_url=surface["base_url"],
                    ok=False,
                    maximum_latency_ms=0,
                    provider_blocker=None,
                    paths=(
                        PathProbe(
                            path="/",
                            ok=False,
                            status=None,
                            latency_ms=0,
                            content_type="",
                            body_sha256=None,
                            body_bytes=None,
                            error_kind=safe_error_kind(exc),
                        ),
                    ),
                )

    surface_rows: list[dict[str, Any]] = []
    global_severity: str | None = None
    reasons: list[str] = []
    next_history: dict[str, Any] = {}
    for surface in manifest["surfaces"]:
        probe = probes[surface["id"]]
        previous = history.get(surface["id"])
        previous_buckets = previous.get("buckets") if isinstance(previous, dict) else []
        buckets = append_sample(
            previous_buckets,
            sample_epoch=sample_epoch,
            ok=probe.ok,
            latency_ms=probe.maximum_latency_ms,
            latency_objective_ms=policy["latency_objective_ms"],
            retention_minutes=policy["history_retention_minutes"],
        )
        windows = [
            summarize_window(
                buckets,
                name=window["name"],
                minutes=window["minutes"],
                now_epoch=now_epoch,
                cadence_minutes=policy["cadence_minutes"],
                availability_objective_percent=policy["availability_objective_percent"],
                minimum_coverage_percent=policy["minimum_window_coverage_percent"],
            )
            for window in policy["burn_windows"]
        ]
        severity, surface_reasons = severity_for_surface(
            current_ok=probe.ok,
            provider_blocker=probe.provider_blocker,
            windows=windows,
            policy=policy,
        )
        if severity_rank(severity) > severity_rank(global_severity):
            global_severity = severity
        reasons.extend(f"{surface['id']}: {reason}" for reason in surface_reasons)
        current_failure_started_at = None
        if not probe.ok:
            if isinstance(previous, dict) and previous.get("current_failure_started_at"):
                current_failure_started_at = previous.get("current_failure_started_at")
            else:
                current_failure_started_at = now_text
        next_history[surface["id"]] = {
            "buckets": buckets,
            "current_failure_started_at": current_failure_started_at,
            "last_ok_at": now_text if probe.ok else (previous.get("last_ok_at") if isinstance(previous, dict) else None),
            "last_provider_blocker": probe.provider_blocker,
        }
        failure_started = parse_time(current_failure_started_at)
        recovery_age = None
        if failure_started is not None:
            recovery_age = max(0.0, (now - failure_started).total_seconds() / 60.0)
            if recovery_age > policy["recovery_objective_minutes"]:
                reasons.append(
                    f"{surface['id']}: recovery objective exceeded ({recovery_age:.1f} > {policy['recovery_objective_minutes']} minutes)"
                )
                if severity_rank("SEV2") > severity_rank(global_severity):
                    global_severity = "SEV2"
        row = probe.receipt()
        row.update(
            {
                "current_ok": probe.ok,
                "windows": [item.receipt() for item in windows],
                "severity": severity,
                "reasons": surface_reasons,
                "current_failure_age_minutes": None if recovery_age is None else round(recovery_age, 3),
            }
        )
        surface_rows.append(row)

    deadman = github.workflow_deadman(
        policy["deadman"]["workflow_file"], now=now, policy=policy
    )
    if not deadman["ok"]:
        reasons.append(f"autonomic recovery deadman: {deadman['reason']}")
        global_severity = "SEV1"

    if global_severity is None:
        sparse = [
            f"{row['id']}/{window['name']}"
            for row in surface_rows
            for window in row["windows"]
            if not window["sufficient_coverage"]
        ]
        if sparse:
            reasons.append("insufficient sample coverage to establish health: " + ", ".join(sparse))
            global_severity = "SEV3"

    verdict = "HEALTHY" if global_severity is None else "INCIDENT"
    previous_healthy_cycles = int(state.get("healthy_cycles") or 0)
    healthy_cycles = previous_healthy_cycles + 1 if verdict == "HEALTHY" else 0
    next_state = {
        "schema": STATE_SCHEMA,
        "updated_at": now_text,
        "controller_revision": controller_tip,
        "manifest_revision": manifest_revision,
        "manifest_sha256": manifest_sha256,
        "policy_sha256": policy_sha256,
        "healthy_cycles": healthy_cycles,
        "incident_last_refreshed_at": state.get("incident_last_refreshed_at"),
        "surface_history": next_history,
        "secret_values_recorded": False,
    }

    report = {
        "schema": RECEIPT_SCHEMA,
        "cycle_id": f"slo_{uuid.uuid4().hex}",
        "generated_at": now_text,
        "controller_repository": policy["controller_repository"],
        "controller_revision": controller_tip,
        "manifest_repository": policy["source_manifest"]["repository"],
        "manifest_revision": manifest_revision,
        "manifest_sha256": manifest_sha256,
        "policy_sha256": policy_sha256,
        "availability_objective_percent": policy["availability_objective_percent"],
        "latency_objective_ms": policy["latency_objective_ms"],
        "recovery_objective_minutes": policy["recovery_objective_minutes"],
        "verdict": verdict,
        "severity": global_severity,
        "reasons": sorted(set(reasons)),
        "deadman": deadman,
        "surfaces": surface_rows,
        "healthy_cycles": healthy_cycles,
        "authority": {
            "fixed_signed_manifest": True,
            "fixed_https_origins": True,
            "issue_state_only": True,
            "service_restart": False,
            "workflow_dispatch": False,
            "source_write": False,
            "dns_mutation": False,
            "asset_deletion": False,
            "product_action": False,
            "arbitrary_shell": False,
        },
        "secret_values_recorded": False,
    }
    report["observation_sha256"] = observation_digest(report)

    github.ensure_label(policy["incident"]["label"])
    incident = github.find_open_issue(policy["incident"]["title"])
    incident_action = "none"
    if verdict == "INCIDENT":
        body = incident_body(report)
        if incident is None:
            incident = github.create_issue(
                title=policy["incident"]["title"],
                body=body,
                labels=[policy["incident"]["label"]],
            )
            incident_action = "created"
            next_state["incident_last_refreshed_at"] = now_text
        else:
            last_refresh = parse_time(state.get("incident_last_refreshed_at"))
            due = last_refresh is None or now - last_refresh >= dt.timedelta(
                minutes=policy["incident"]["refresh_minutes"]
            )
            if due:
                github.update_issue(incident, body=body, state="open")
                incident_action = "refreshed"
                next_state["incident_last_refreshed_at"] = now_text
            else:
                incident_action = "throttled"
    elif incident is not None and healthy_cycles >= policy["incident"]["healthy_cycles_before_close"]:
        closure = incident_body(
            {
                **report,
                "verdict": "RECOVERED",
                "severity": None,
                "reasons": [
                    f"all objectives passed for {healthy_cycles} consecutive cycles"
                ],
            }
        )
        github.update_issue(incident, body=closure, state="closed")
        incident_action = "closed"
        next_state["incident_last_refreshed_at"] = None
    report["incident"] = {
        "action": incident_action,
        "number": incident.get("number") if isinstance(incident, dict) else None,
    }
    report["receipt_sha256"] = sha256_hex(canonical_json({key: value for key, value in report.items() if key != "receipt_sha256"}))

    state_body = issue_state_body(next_state, report)
    if state_issue is None:
        github.create_issue(title=policy["state_issue"]["title"], body=state_body)
    else:
        last_update = parse_time(state.get("updated_at"))
        heartbeat_due = last_update is None or now - last_update >= dt.timedelta(
            minutes=policy["state_issue"]["heartbeat_minutes"]
        )
        changed = (
            state.get("surface_history") != next_state.get("surface_history")
            or state.get("healthy_cycles") != next_state.get("healthy_cycles")
            or state.get("manifest_revision") != next_state.get("manifest_revision")
            or state.get("incident_last_refreshed_at") != next_state.get("incident_last_refreshed_at")
        )
        if changed or heartbeat_due:
            github.update_issue(state_issue, body=state_body, state="open")

    write_json_atomic(output, report)
    output.with_suffix(output.suffix + ".sha256").write_text(
        report["receipt_sha256"] + "\n", encoding="ascii"
    )
    return 0 if verdict == "HEALTHY" else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path("autonomic/slo_policy.json"))
    parser.add_argument("--output", type=Path, default=Path("reports/autonomic-slo.json"))
    parser.add_argument("--offline-contract-only", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy, policy_sha256 = load_policy(args.policy)
        if args.offline_contract_only:
            contract = offline_contract(policy, policy_sha256)
            write_json_atomic(args.output, contract)
            print(json.dumps(contract, indent=2, sort_keys=True))
            return 0
        return run_live(policy=policy, policy_sha256=policy_sha256, output=args.output)
    except Exception as exc:
        failure = {
            "schema": RECEIPT_SCHEMA,
            "generated_at": utc_now(),
            "verdict": "FAILED",
            "error_kind": safe_error_kind(exc),
            "error": "controller failed closed",
            "authority": {
                "service_restart": False,
                "workflow_dispatch": False,
                "source_write": False,
                "product_action": False,
                "arbitrary_shell": False,
            },
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
