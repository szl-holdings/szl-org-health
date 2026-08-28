"""Dynamic GitHub organization census with bounded, fail-closed evidence."""
from __future__ import annotations

import concurrent.futures as cf
import urllib.parse
from typing import Any

from .common import paginate_json, request_json, token_header

ORG = "szl-holdings"
GH = "https://api.github.com"
API_VERSION = "2022-11-28"
RUN_WINDOW = 100
MAX_PAGES = 20

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
RULESET_PAGE_SIZE = 100
ENFORCING_BRANCH_RULE_TYPES = frozenset(
    {
        "pull_request",
        "required_code_scanning",
        "required_deployments",
        "required_signatures",
        "required_status_checks",
        "required_workflows",
        "update",
    }
)


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


def gh_paginate(
    path: str,
    timeout: float,
    retries: int,
    *,
    max_pages: int = MAX_PAGES,
):
    return paginate_json(
        f"{GH}{path}",
        headers=github_headers(),
        timeout=timeout,
        retries=retries,
        max_pages=max_pages,
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
    """Use the latest observed run per workflow so unrelated green cannot hide red."""
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


def _branch_governance_result(
    *,
    protected: bool | None,
    state: str,
    source: str,
    error: str | None,
    rule_types: set[str] | None = None,
    ruleset_ids: set[int] | None = None,
    inherited: bool | None = None,
) -> dict[str, Any]:
    return {
        "protected": protected,
        "protection_state": state,
        "protection_source": source,
        "protection_error": error,
        "protection_rule_types": sorted(rule_types or set()),
        "protection_ruleset_ids": sorted(ruleset_ids or set()),
        "protection_inherited": inherited,
    }


def _classic_protection_observed(protection: Any) -> bool:
    """Retain the collector's existing classic-protection acceptance contract."""
    return isinstance(protection, dict) and (
        "enforce_admins" in protection
        or "required_pull_request_reviews" in protection
    )


def _positive_ruleset_id(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def _ruleset_source_identity(
    source_type: Any,
    source: Any,
    repo_name: str,
) -> tuple[str, str] | None:
    if not isinstance(source_type, str) or not isinstance(source, str):
        return None
    normalized_type = source_type.strip().casefold()
    normalized_source = source.strip().casefold()
    if normalized_type == "organization" and normalized_source == ORG.casefold():
        return normalized_type, normalized_source
    expected_repo = f"{ORG}/{repo_name}".casefold()
    if normalized_type == "repository" and normalized_source == expected_repo:
        return normalized_type, normalized_source
    return None


def _failed_branch_governance(
    reason: str,
    *,
    rule_types: set[str] | None = None,
    ruleset_ids: set[int] | None = None,
    inherited: bool | None = None,
) -> dict[str, Any]:
    return _branch_governance_result(
        protected=None,
        state="FAILED_CLOSED",
        source="none",
        error=reason,
        rule_types=rule_types,
        ruleset_ids=ruleset_ids,
        inherited=inherited,
    )


def _branch_governance(
    repo_name: str,
    default_branch: str,
    *,
    request_timeout: float,
    retries: int,
) -> dict[str, Any]:
    """Resolve classic or effective ruleset protection without optimistic gaps."""
    encoded_repo = urllib.parse.quote(repo_name, safe="")
    encoded_branch = urllib.parse.quote(default_branch, safe="")
    repo_path = f"/repos/{ORG}/{encoded_repo}"

    classic, classic_error = gh(
        f"{repo_path}/branches/{encoded_branch}/protection",
        timeout=request_timeout,
        retries=retries,
    )
    if _classic_protection_observed(classic):
        return _branch_governance_result(
            protected=True,
            state="PROTECTED",
            source="classic",
            error=None,
            inherited=False,
        )

    effective, effective_error = gh(
        f"{repo_path}/rules/branches/{encoded_branch}",
        timeout=request_timeout,
        retries=retries,
    )
    if effective_error is not None or not isinstance(effective, list):
        reason = effective_error or "effective branch rules response is malformed"
        return _failed_branch_governance(
            f"effective branch rules unavailable: {reason}; "
            f"classic protection: {classic_error or 'not observed'}"
        )

    rulesets, rulesets_error = gh(
        f"{repo_path}/rulesets?includes_parents=true&targets=branch"
        f"&per_page={RULESET_PAGE_SIZE}",
        timeout=request_timeout,
        retries=retries,
    )
    if rulesets_error is not None or not isinstance(rulesets, list):
        reason = rulesets_error or "ruleset inventory response is malformed"
        return _failed_branch_governance(
            f"inherited ruleset inventory unavailable: {reason}; "
            f"classic protection: {classic_error or 'not observed'}"
        )
    if len(rulesets) >= RULESET_PAGE_SIZE:
        return _failed_branch_governance(
            "inherited ruleset inventory may be truncated at the page limit"
        )

    summaries: dict[int, dict[str, Any]] = {}
    summary_sources: dict[int, tuple[str, str]] = {}
    for summary in rulesets:
        if not isinstance(summary, dict):
            return _failed_branch_governance(
                "ruleset inventory contains a malformed entry"
            )
        ruleset_id = _positive_ruleset_id(summary.get("id"))
        source_identity = _ruleset_source_identity(
            summary.get("source_type"), summary.get("source"), repo_name
        )
        target = summary.get("target")
        enforcement = summary.get("enforcement")
        if (
            ruleset_id is None
            or source_identity is None
            or target not in {"branch", "tag", "push"}
            or enforcement not in {"active", "disabled", "evaluate"}
            or ruleset_id in summaries
        ):
            return _failed_branch_governance(
                "ruleset inventory contains a malformed entry"
            )
        if target == "branch":
            summaries[ruleset_id] = summary
            summary_sources[ruleset_id] = source_identity

    effective_types: set[str] = set()
    candidate_types: dict[int, set[str]] = {}
    candidate_sources: dict[int, tuple[str, str]] = {}
    for rule in effective:
        if not isinstance(rule, dict) or not isinstance(rule.get("type"), str):
            return _failed_branch_governance(
                "effective branch rules contain a malformed entry"
            )
        rule_type = rule["type"].strip()
        ruleset_id = _positive_ruleset_id(rule.get("ruleset_id"))
        source_identity = _ruleset_source_identity(
            rule.get("ruleset_source_type"),
            rule.get("ruleset_source"),
            repo_name,
        )
        if not rule_type or ruleset_id is None or source_identity is None:
            return _failed_branch_governance(
                "effective branch rules contain a malformed entry"
            )
        effective_types.add(rule_type)
        if rule_type not in ENFORCING_BRANCH_RULE_TYPES:
            continue
        prior_source = candidate_sources.get(ruleset_id)
        if prior_source is not None and prior_source != source_identity:
            return _failed_branch_governance(
                "effective branch rules disagree on ruleset source identity",
                rule_types=effective_types,
                ruleset_ids=set(candidate_types),
            )
        candidate_sources[ruleset_id] = source_identity
        candidate_types.setdefault(ruleset_id, set()).add(rule_type)

    if not candidate_types:
        inactive = sorted(
            ruleset_id
            for ruleset_id, summary in summaries.items()
            if summary["enforcement"] != "active"
        )
        suffix = f"; inactive branch rulesets: {inactive}" if inactive else ""
        return _failed_branch_governance(
            f"no enforceable effective branch governance rule observed{suffix}",
            rule_types=effective_types,
        )

    candidate_ids = set(candidate_types)
    inherited = any(
        source_identity[0] == "organization"
        for source_identity in candidate_sources.values()
    )
    for ruleset_id in sorted(candidate_ids):
        summary = summaries.get(ruleset_id)
        if summary is None:
            return _failed_branch_governance(
                f"effective rule references absent ruleset {ruleset_id}",
                rule_types=effective_types,
                ruleset_ids=candidate_ids,
                inherited=inherited,
            )
        if summary["enforcement"] != "active":
            return _failed_branch_governance(
                f"ruleset {ruleset_id} is not actively enforced",
                rule_types=effective_types,
                ruleset_ids=candidate_ids,
                inherited=inherited,
            )
        if summary_sources[ruleset_id] != candidate_sources[ruleset_id]:
            return _failed_branch_governance(
                f"ruleset {ruleset_id} source does not match effective rules",
                rule_types=effective_types,
                ruleset_ids=candidate_ids,
                inherited=inherited,
            )

        detail, detail_error = gh(
            f"{repo_path}/rulesets/{ruleset_id}",
            timeout=request_timeout,
            retries=retries,
        )
        if detail_error is not None or not isinstance(detail, dict):
            reason = detail_error or "malformed detail response"
            return _failed_branch_governance(
                f"ruleset {ruleset_id} detail unavailable: {reason}",
                rule_types=effective_types,
                ruleset_ids=candidate_ids,
                inherited=inherited,
            )

        detail_id = _positive_ruleset_id(detail.get("id"))
        detail_source = _ruleset_source_identity(
            detail.get("source_type"), detail.get("source"), repo_name
        )
        detail_rules = detail.get("rules")
        bypass_actors = detail.get("bypass_actors")
        if (
            detail_id != ruleset_id
            or detail_source != summary_sources[ruleset_id]
            or detail.get("target") != "branch"
            or detail.get("enforcement") != "active"
            or not isinstance(detail_rules, list)
            or not isinstance(bypass_actors, list)
        ):
            return _failed_branch_governance(
                f"ruleset {ruleset_id} detail is malformed or inconsistent",
                rule_types=effective_types,
                ruleset_ids=candidate_ids,
                inherited=inherited,
            )
        if bypass_actors:
            return _failed_branch_governance(
                f"ruleset {ruleset_id} permits bypass actors",
                rule_types=effective_types,
                ruleset_ids=candidate_ids,
                inherited=inherited,
            )

        detailed_types: set[str] = set()
        for detailed_rule in detail_rules:
            if (
                not isinstance(detailed_rule, dict)
                or not isinstance(detailed_rule.get("type"), str)
                or not detailed_rule["type"].strip()
            ):
                return _failed_branch_governance(
                    f"ruleset {ruleset_id} contains a malformed rule",
                    rule_types=effective_types,
                    ruleset_ids=candidate_ids,
                    inherited=inherited,
                )
            detailed_types.add(detailed_rule["type"].strip())
        if not candidate_types[ruleset_id].issubset(detailed_types):
            return _failed_branch_governance(
                f"ruleset {ruleset_id} detail omits effective governance rules",
                rule_types=effective_types,
                ruleset_ids=candidate_ids,
                inherited=inherited,
            )

    governing_types = set().union(*candidate_types.values())
    return _branch_governance_result(
        protected=True,
        state="PROTECTED",
        source="effective-ruleset",
        error=None,
        rule_types=governing_types,
        ruleset_ids=candidate_ids,
        inherited=inherited,
    )


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
        aggregate: dict[str, Any] = {
            "ci": "archived",
            "workflow_count": 0,
            "failing_workflows": [],
            "pending_workflows": [],
            "error": None,
            "ci_scope": "archived",
            "run_window_observed": 0,
            "default_branch_push_runs_total": 0,
        }
    else:
        runs, run_error = gh(
            f"/repos/{ORG}/{urllib.parse.quote(name)}/actions/runs"
            f"?branch={urllib.parse.quote(default)}&event=push&per_page={RUN_WINDOW}",
            timeout=request_timeout,
            retries=retries,
        )
        if isinstance(runs, dict) and isinstance(runs.get("workflow_runs"), list):
            observed = runs["workflow_runs"]
            aggregate = aggregate_workflow_runs(observed)
            aggregate.update(
                {
                    "error": None,
                    "ci_scope": "latest-per-workflow-within-recent-default-branch-push-window",
                    "run_window_observed": len(observed),
                    "default_branch_push_runs_total": runs.get("total_count"),
                }
            )
        else:
            aggregate = {
                "ci": "unknown",
                "workflow_count": None,
                "failing_workflows": [],
                "pending_workflows": [],
                "error": run_error or "workflow runs unavailable",
                "ci_scope": "unavailable",
                "run_window_observed": None,
                "default_branch_push_runs_total": None,
            }

    branch_governance = _branch_governance_result(
        protected=None,
        state="NOT_APPLICABLE" if archived else "NOT_EVALUATED",
        source="none",
        error=None,
    )
    if include_branch_protection and not archived:
        branch_governance = _branch_governance(
            name,
            default,
            request_timeout=request_timeout,
            retries=retries,
        )

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
        **branch_governance,
        "url": repo.get("html_url") or f"https://github.com/{ORG}/{name}",
    }


def _all_alerts(
    path: str,
    *,
    request_timeout: float,
    retries: int,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Read all alert pages within the hard cap; overflow/failure stays UNKNOWN."""
    return gh_paginate(
        path,
        request_timeout,
        retries,
        max_pages=MAX_PAGES,
    )


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

    alert_paths = {
        "code": f"/orgs/{ORG}/code-scanning/alerts?state=open&per_page=100",
        "secret": f"/orgs/{ORG}/secret-scanning/alerts?state=open&per_page=100",
        "dependabot": f"/orgs/{ORG}/dependabot/alerts?state=open&per_page=100",
    }
    alerts: dict[str, list[dict[str, Any]] | None] = {}
    alert_errors: dict[str, str | None] = {}
    with cf.ThreadPoolExecutor(max_workers=3) as executor:
        future_map = {
            executor.submit(
                _all_alerts,
                path,
                request_timeout=request_timeout,
                retries=retries,
            ): name
            for name, path in alert_paths.items()
        }
        for future in cf.as_completed(future_map):
            name = future_map[future]
            items, error = future.result()
            alerts[name] = items
            alert_errors[name] = error

    code_alerts = alerts.get("code")
    code_high = None
    if code_alerts is not None:
        code_high = sum(
            1
            for alert in code_alerts
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
            "code_scanning_open": (
                len(code_alerts) if code_alerts is not None else None
            ),
            "code_scanning_high": code_high,
            "secret_scanning_open": (
                len(alerts["secret"]) if alerts.get("secret") is not None else None
            ),
            "dependabot_open": (
                len(alerts["dependabot"])
                if alerts.get("dependabot") is not None
                else None
            ),
            "complete": all(value is None for value in alert_errors.values()),
            "errors": {
                name: error for name, error in alert_errors.items() if error is not None
            },
            "page_cap": MAX_PAGES,
        },
        "open_prs": (prs or {}).get("total_count") if isinstance(prs, dict) else None,
        "open_issues": (
            (issues or {}).get("total_count") if isinstance(issues, dict) else None
        ),
    }
