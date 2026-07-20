"""Dynamic GitHub organization census with latest-per-workflow CI truth."""
from __future__ import annotations

import concurrent.futures as cf
import urllib.parse
from typing import Any

from .common import paginate_json, request_json, token_header

ORG = "szl-holdings"
GH = "https://api.github.com"
API_VERSION = "2022-11-28"

KEY_REPOS_FALLBACK = [
    "a11oy",
    "killinchu",
    "platform",
    ".github",
    "szl-org-health",
    "szl-telemetry",
    "szl-router",
    "szl-lake",
    "immune",
    "anatomy",
    "yarqa",
]
CONTROL_PLANE_REPOS = {
    ".github",
    "platform",
    "szl-org-health",
    "szl-telemetry",
    "szl-build-env",
    "szl-doctrine",
}
PRODUCTION_REPOS = {
    "a11oy",
    "killinchu",
    "anatomy",
    "immune",
    "szl-router",
    "szl-lake",
    "hatun-mcp",
    "yarqa",
    "lean-kernel",
    "khipu-sda-core",
}
RESEARCH_REPOS = {
    "lutar-lean",
    "szl-papers",
    "szl-quant",
    "szl-quant-witness",
    "khipu-consensus",
    "evidence-typed-formula-governance",
    "fail-closed-governed-ai-services",
}
FAILURE_CONCLUSIONS = {
    "action_required",
    "cancelled",
    "failure",
    "startup_failure",
    "timed_out",
}


def github_headers() -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
        **token_header(("GITHUB_TOKEN", "GH_TOKEN", "SZL_GITHUB_TOKEN")),
    }


def gh(path: str, timeout: float = 20.0, retries: int = 2):
    data, _, error = request_json(
        f"{GH}{path}", headers=github_headers(), timeout=timeout, retries=retries
    )
    return data, error


def gh_paginate(path: str, timeout: float, retries: int):
    return paginate_json(
        f"{GH}{path}",
        headers=github_headers(),
        timeout=timeout,
        retries=retries,
        max_pages=20,
    )


def classify_repo(repo: dict[str, Any]) -> str:
    """Preliminary deterministic classification; unknown roles stay unclassified."""
    name = str(repo.get("name") or "")
    if repo.get("archived"):
        return "archive"
    if name in CONTROL_PLANE_REPOS:
        return "control-plane"
    if name in PRODUCTION_REPOS:
        return "production"
    if name in RESEARCH_REPOS or any(
        token in name for token in ("paper", "witness", "formula", "consensus")
    ):
        return "research"
    if (
        name.endswith("-holo")
        or name.endswith("-live")
        or name.endswith(".github.io")
        or name in {"docs-site", "a11oy-net"}
    ):
        return "product-surface"
    return "unclassified"


def aggregate_workflow_runs(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Use latest run per workflow so unrelated green runs cannot hide a red."""
    latest: dict[str, dict[str, Any]] = {}
    for run in runs:
        key = str(
            run.get("workflow_id") or run.get("name") or run.get("id") or "unknown"
        )
        stamp = str(run.get("created_at") or run.get("run_started_at") or "")
        current = latest.get(key)
        current_stamp = str(
            (current or {}).get("created_at")
            or (current or {}).get("run_started_at")
            or ""
        )
        if current is None or stamp > current_stamp:
            latest[key] = run

    if not latest:
        return {
            "ci": "unknown",
            "workflow_count": 0,
            "failing_workflows": [],
            "pending_workflows": [],
        }

    failing = sorted(
        str(run.get("name") or key)
        for key, run in latest.items()
        if run.get("conclusion") in FAILURE_CONCLUSIONS
    )
    pending = sorted(
        str(run.get("name") or key)
        for key, run in latest.items()
        if not run.get("conclusion") and run.get("status") != "completed"
    )
    ci = "failure" if failing else "pending" if pending else "success"
    return {
        "ci": ci,
        "workflow_count": len(latest),
        "failing_workflows": failing,
        "pending_workflows": pending,
    }


def _repo_census(
    repo: dict[str, Any],
    *,
    request_timeout: float,
    retries: int,
    include_branch_protection: bool,
) -> tuple[str, dict[str, Any]]:
    name = str(repo.get("name") or "unknown")
    default = str(repo.get("default_branch") or "main")
    archived = bool(repo.get("archived"))
    if archived:
        aggregate = {
            "ci": "archived",
            "workflow_count": 0,
            "failing_workflows": [],
            "pending_workflows": [],
            "error": None,
        }
    else:
        runs, run_error = gh(
            f"/repos/{ORG}/{urllib.parse.quote(name)}/actions/runs"
            f"?branch={urllib.parse.quote(default)}&event=push&per_page=100",
            timeout=request_timeout,
            retries=retries,
        )
        if isinstance(runs, dict) and isinstance(runs.get("workflow_runs"), list):
            aggregate = aggregate_workflow_runs(runs["workflow_runs"])
            aggregate["error"] = None
        else:
            aggregate = {
                "ci": "unknown",
                "workflow_count": None,
                "failing_workflows": [],
                "pending_workflows": [],
                "error": run_error or "workflow runs unavailable",
            }

    protected: bool | None = None
    protection_error: str | None = None
    if include_branch_protection and not archived:
        protection, protection_error = gh(
            f"/repos/{ORG}/{urllib.parse.quote(name)}/branches/"
            f"{urllib.parse.quote(default)}/protection",
            timeout=request_timeout,
            retries=retries,
        )
        if isinstance(protection, dict) and (
            "enforce_admins" in protection
            or "required_pull_request_reviews" in protection
        ):
            protected = True
        else:
            protected = None

    return name, {
        **aggregate,
        "classification": classify_repo(repo),
        "visibility": repo.get("visibility")
        or ("private" if repo.get("private") else "public"),
        "archived": archived,
        "fork": bool(repo.get("fork")),
        "default_branch": default,
        "pushed_at": repo.get("pushed_at"),
        "updated_at": repo.get("updated_at"),
        "size_kb": repo.get("size"),
        "protected": protected,
        "protection_error": protection_error if protected is None else None,
        "url": repo.get("html_url") or f"https://github.com/{ORG}/{name}",
    }


def collect_github(
    *,
    request_timeout: float = 20.0,
    retries: int = 2,
    include_branch_protection: bool = True,
) -> dict[str, Any]:
    discovered, discovery_error = gh_paginate(
        f"/orgs/{ORG}/repos?type=all&sort=full_name&direction=asc&per_page=100",
        request_timeout,
        retries,
    )
    discovery_complete = discovered is not None
    if discovered is None:
        discovered = [
            {"name": name, "full_name": f"{ORG}/{name}", "default_branch": "main"}
            for name in KEY_REPOS_FALLBACK
        ]

    repos: dict[str, dict[str, Any]] = {}
    with cf.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [
            executor.submit(
                _repo_census,
                repo,
                request_timeout=request_timeout,
                retries=retries,
                include_branch_protection=include_branch_protection,
            )
            for repo in discovered
        ]
        for future in cf.as_completed(futures):
            name, info = future.result()
            repos[name] = info

    def count(path: str):
        data, error = gh(path, timeout=request_timeout, retries=retries)
        return None if error or not isinstance(data, list) else len(data)

    code_alerts_raw, _ = gh(
        f"/orgs/{ORG}/code-scanning/alerts?state=open&per_page=100",
        timeout=request_timeout,
        retries=retries,
    )
    code_total = len(code_alerts_raw) if isinstance(code_alerts_raw, list) else None
    code_high = None
    if isinstance(code_alerts_raw, list):
        code_high = sum(
            1
            for alert in code_alerts_raw
            if ((alert.get("rule") or {}).get("security_severity_level") == "high")
        )

    prs, _ = gh(
        f"/search/issues?q=org:{ORG}+is:pr+is:open&per_page=1",
        request_timeout,
        retries,
    )
    issues, _ = gh(
        f"/search/issues?q=org:{ORG}+is:issue+is:open&per_page=1",
        request_timeout,
        retries,
    )

    classifications: dict[str, int] = {}
    for info in repos.values():
        key = str(info["classification"])
        classifications[key] = classifications.get(key, 0) + 1

    return {
        "discovery": {
            "complete": discovery_complete,
            "scope": "organization-api" if discovery_complete else "fallback-subset",
            "error": discovery_error,
        },
        "summary": {
            "total": len(repos),
            "active": sum(1 for repo in repos.values() if not repo["archived"]),
            "archived": sum(1 for repo in repos.values() if repo["archived"]),
            "ci_green": sum(1 for repo in repos.values() if repo["ci"] == "success"),
            "ci_red": sum(1 for repo in repos.values() if repo["ci"] == "failure"),
            "ci_unknown": sum(1 for repo in repos.values() if repo["ci"] == "unknown"),
            "classifications": classifications,
        },
        "repos": dict(sorted(repos.items())),
        "alerts": {
            "code_scanning_open": code_total,
            "code_scanning_high": code_high,
            "secret_scanning_open": count(
                f"/orgs/{ORG}/secret-scanning/alerts?state=open&per_page=100"
            ),
            "dependabot_open": count(
                f"/orgs/{ORG}/dependabot/alerts?state=open&per_page=100"
            ),
        },
        "open_prs": (prs or {}).get("total_count") if isinstance(prs, dict) else None,
        "open_issues": (
            (issues or {}).get("total_count") if isinstance(issues, dict) else None
        ),
    }
