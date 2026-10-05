"""Dynamic GitHub organization census with bounded, fail-closed evidence."""
from __future__ import annotations

import concurrent.futures as cf
import json
import math
import re
import urllib.parse
from typing import Any

from .common import paginate_json, request_json, token_header
from .github_inventory import discover_repositories

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
    "stale",
    "startup_failure",
    "timed_out",
}
GREEN_CONCLUSIONS = {"neutral", "skipped", "success"}
PENDING_STATUSES = {"in_progress", "pending", "queued", "requested", "waiting"}
RULESET_PAGE_SIZE = 100
ENFORCING_BRANCH_RULE_TYPES = frozenset(
    {
        "pull_request",
        "code_scanning",
        "required_deployments",
        "required_signatures",
        "required_status_checks",
        "workflows",
        "update",
    }
)
PARAMETERIZED_BRANCH_RULE_TYPES = frozenset(
    {
        "code_scanning",
        "pull_request",
        "required_deployments",
        "required_status_checks",
        "workflows",
    }
)
REQUIRED_PARAMETER_LISTS = {
    "code_scanning": "code_scanning_tools",
    "required_deployments": "required_deployment_environments",
    "required_status_checks": "required_status_checks",
    "workflows": "workflows",
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


def _repository_visibility(repo: dict[str, Any]) -> str:
    """Return explicit or derived visibility; missing contradictions stay unknown."""
    explicit = repo.get("visibility")
    if explicit not in {"public", "private", "internal"}:
        explicit = None

    private = repo.get("private")
    derived = "private" if private is True else "public" if private is False else None
    if explicit is None:
        return derived or "unknown"
    if derived is None:
        return explicit
    if explicit == "public":
        return explicit if derived == "public" else "unknown"
    return explicit if derived == "private" else "unknown"


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
            "unknown_workflows": [],
        }

    failing: list[str] = []
    pending: list[str] = []
    unknown: list[str] = []
    for key, run in latest.items():
        name = str(run.get("name") or key)
        status = run.get("status")
        conclusion = run.get("conclusion")
        if status == "completed" and conclusion in FAILURE_CONCLUSIONS:
            failing.append(name)
        elif status == "completed" and conclusion in GREEN_CONCLUSIONS:
            continue
        elif status in PENDING_STATUSES and conclusion is None:
            pending.append(name)
        else:
            # Missing, future, decorated, or status/conclusion-incoherent values
            # are not evidence of a successful terminal workflow.
            unknown.append(name)
    failing.sort()
    pending.sort()
    unknown.sort()
    ci = (
        "failure"
        if failing
        else "unknown"
        if unknown
        else "pending"
        if pending
        else "success"
    )
    return {
        "ci": ci,
        "workflow_count": len(latest),
        "failing_workflows": failing,
        "pending_workflows": pending,
        "unknown_workflows": unknown,
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
    """Accept classic protection only when administrators cannot bypass it."""
    if not isinstance(protection, dict):
        return False
    enforce_admins = protection.get("enforce_admins")
    if not isinstance(enforce_admins, dict) or enforce_admins.get("enabled") is not True:
        return False
    for escape_hatch in ("allow_force_pushes", "allow_deletions"):
        setting = protection.get(escape_hatch)
        if isinstance(setting, dict) and setting.get("enabled") is True:
            return False
    return True


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
    if source_type == "Organization" and source == ORG:
        return "organization", source
    expected_repo = f"{ORG}/{repo_name}"
    if source_type == "Repository" and source == expected_repo:
        return "repository", source
    return None


def _exact_rule_type(value: Any) -> str | None:
    """Accept GitHub's exact discriminator, never a decorated equivalent."""
    if not isinstance(value, str) or not value:
        return None
    if value != value.strip() or not all(
        char.isascii() and (char.islower() or char.isdigit() or char == "_")
        for char in value
    ):
        return None
    return value


def _strict_json_value(value: Any, *, depth: int = 0) -> bool:
    """Validate the exact JSON data model without Python equality coercions."""
    if depth > 128:
        return False
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_strict_json_value(item, depth=depth + 1) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str)
            and _strict_json_value(item, depth=depth + 1)
            for key, item in value.items()
        )
    return False


def _rule_parameter_signature(
    rule_type: str,
    rule: dict[str, Any],
) -> tuple[str | None, str | None]:
    """Return one canonical signature for a semantically enforcing rule body."""
    has_parameters = "parameters" in rule
    parameters = rule.get("parameters")
    if rule_type in PARAMETERIZED_BRANCH_RULE_TYPES and (
        not has_parameters or not isinstance(parameters, dict)
    ):
        return None, f"{rule_type} rule parameters are missing or malformed"
    if not has_parameters:
        parameters = None
    if not _strict_json_value(parameters):
        return None, f"{rule_type} rule parameters are not strict JSON"

    required_list = REQUIRED_PARAMETER_LISTS.get(rule_type)
    if required_list is not None:
        entries = parameters.get(required_list) if isinstance(parameters, dict) else None
        if not isinstance(entries, list) or not entries:
            return None, f"{rule_type} rule has no enforced {required_list}"
        if rule_type == "required_deployments":
            if any(not isinstance(item, str) or not item for item in entries):
                return None, f"{rule_type} rule contains a malformed requirement"
        elif any(not isinstance(item, dict) or not item for item in entries):
            return None, f"{rule_type} rule contains a malformed requirement"
        elif rule_type == "required_status_checks" and any(
            not isinstance(item.get("context"), str) or not item["context"]
            for item in entries
        ):
            return None, f"{rule_type} rule contains a malformed requirement"
        elif rule_type == "workflows" and any(
            not isinstance(item.get("path"), str) or not item["path"]
            for item in entries
        ):
            return None, f"{rule_type} rule contains a malformed requirement"
        elif rule_type == "code_scanning" and any(
            not isinstance(item.get("tool"), str) or not item["tool"]
            for item in entries
        ):
            return None, f"{rule_type} rule contains a malformed requirement"

    try:
        signature = json.dumps(
            parameters,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (RecursionError, TypeError, ValueError):
        return None, f"{rule_type} rule parameters cannot be canonicalized"
    return signature, None


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

    effective, effective_error = gh_paginate(
        f"{repo_path}/rules/branches/{encoded_branch}?per_page={RULESET_PAGE_SIZE}",
        request_timeout,
        retries,
        max_pages=MAX_PAGES,
    )
    if effective_error is not None or not isinstance(effective, list):
        reason = effective_error or "effective branch rules response is malformed"
        return _failed_branch_governance(
            f"effective branch rules unavailable: {reason}; "
            f"classic protection: {classic_error or 'not observed'}"
        )

    rulesets, rulesets_error = gh_paginate(
        f"{repo_path}/rulesets?includes_parents=true&targets=branch"
        f"&per_page={RULESET_PAGE_SIZE}",
        request_timeout,
        retries,
        max_pages=MAX_PAGES,
    )
    if rulesets_error is not None or not isinstance(rulesets, list):
        reason = rulesets_error or "ruleset inventory response is malformed"
        return _failed_branch_governance(
            f"inherited ruleset inventory unavailable: {reason}; "
            f"classic protection: {classic_error or 'not observed'}"
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
    candidate_parameters: dict[int, dict[str, str]] = {}
    candidate_sources: dict[int, tuple[str, str]] = {}
    for rule in effective:
        if not isinstance(rule, dict):
            return _failed_branch_governance(
                "effective branch rules contain a malformed entry"
            )
        rule_type = _exact_rule_type(rule.get("type"))
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
        parameter_signature, parameter_error = _rule_parameter_signature(
            rule_type, rule
        )
        if parameter_error is not None or parameter_signature is None:
            return _failed_branch_governance(
                f"effective branch rule is not enforcing: {parameter_error}",
                rule_types=effective_types,
                ruleset_ids=set(candidate_parameters),
            )
        prior_source = candidate_sources.get(ruleset_id)
        if prior_source is not None and prior_source != source_identity:
            return _failed_branch_governance(
                "effective branch rules disagree on ruleset source identity",
                rule_types=effective_types,
                ruleset_ids=set(candidate_parameters),
            )
        candidate_sources[ruleset_id] = source_identity
        rules = candidate_parameters.setdefault(ruleset_id, {})
        if rule_type in rules:
            return _failed_branch_governance(
                "effective branch rules contain a duplicate rule type",
                rule_types=effective_types,
                ruleset_ids=set(candidate_parameters),
            )
        rules[rule_type] = parameter_signature

    if not candidate_parameters:
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

    candidate_ids = set(candidate_parameters)
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
            f"{repo_path}/rulesets/{ruleset_id}?includes_parents=true",
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

        detailed_parameters: dict[str, str] = {}
        for detailed_rule in detail_rules:
            if not isinstance(detailed_rule, dict):
                return _failed_branch_governance(
                    f"ruleset {ruleset_id} contains a malformed rule",
                    rule_types=effective_types,
                    ruleset_ids=candidate_ids,
                    inherited=inherited,
                )
            detailed_type = _exact_rule_type(detailed_rule.get("type"))
            if detailed_type is None:
                return _failed_branch_governance(
                    f"ruleset {ruleset_id} contains a malformed rule",
                    rule_types=effective_types,
                    ruleset_ids=candidate_ids,
                    inherited=inherited,
                )
            parameter_signature, parameter_error = _rule_parameter_signature(
                detailed_type, detailed_rule
            )
            if parameter_error is not None or parameter_signature is None:
                return _failed_branch_governance(
                    f"ruleset {ruleset_id} contains a non-enforcing rule: "
                    f"{parameter_error}",
                    rule_types=effective_types,
                    ruleset_ids=candidate_ids,
                    inherited=inherited,
                )
            if detailed_type in detailed_parameters:
                return _failed_branch_governance(
                    f"ruleset {ruleset_id} contains a duplicate rule type",
                    rule_types=effective_types,
                    ruleset_ids=candidate_ids,
                    inherited=inherited,
                )
            detailed_parameters[detailed_type] = parameter_signature
        if not set(candidate_parameters[ruleset_id]).issubset(detailed_parameters):
            return _failed_branch_governance(
                f"ruleset {ruleset_id} detail omits effective governance rules",
                rule_types=effective_types,
                ruleset_ids=candidate_ids,
                inherited=inherited,
            )
        for rule_type, signature in candidate_parameters[ruleset_id].items():
            if detailed_parameters[rule_type] != signature:
                return _failed_branch_governance(
                    f"ruleset {ruleset_id} detail parameters do not match "
                    f"effective {rule_type} rule",
                    rule_types=effective_types,
                    ruleset_ids=candidate_ids,
                    inherited=inherited,
                )

    governing_types = set().union(
        *(set(rules) for rules in candidate_parameters.values())
    )
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
            "unknown_workflows": [],
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
                "unknown_workflows": [],
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
        "visibility": _repository_visibility(repo),
        "archived": archived,
        "fork": bool(repo.get("fork")),
        "default_branch": default,
        "pushed_at": repo.get("pushed_at"),
        "updated_at": repo.get("updated_at"),
        "size_kb": repo.get("size"),
        **branch_governance,
        "url": repo.get("html_url") or f"https://github.com/{ORG}/{name}",
    }


def _code_alert_path(organization: Any) -> str | None:
    """Reuse discovery's validated identity so GitHub's numeric next path stays exact."""
    if not isinstance(organization, dict):
        return None
    identifier = organization.get("id")
    login = organization.get("login")
    if (
        type(identifier) is not int or identifier <= 0
        or not isinstance(login, str) or login.casefold() != ORG.casefold()
    ):
        return None
    return (
        f"/organizations/{identifier}/code-scanning/alerts"
        "?state=open&per_page=100"
    )


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


def _pagination_diagnostic(error: str) -> str:
    """Classify pagination failures without exposing URLs, Link fields, or items."""
    if re.fullmatch(r"pagination exceeded [0-9]+ pages", error):
        return "PAGE_CAP_EXCEEDED"
    if re.fullmatch(r"pagination exceeded [0-9]+ items", error):
        return "ITEM_CAP_EXCEEDED"
    return {
        "pagination next origin changed": "NEXT_ORIGIN_CHANGED",
        "pagination next path changed": "NEXT_PATH_CHANGED",
        "pagination cycle detected": "CYCLE_DETECTED",
    }.get(
        error,
        "INVALID_URL" if error.startswith("invalid pagination URL:") else
        "LINK_INVALID" if error.startswith("Link ") else "OTHER",
    )


def _alert_endpoint_read_observation(items: Any, error: Any) -> dict[str, Any]:
    """Describe collection readability without alert counts or provider text.

    A failed status may come from any page. It is not evidence that the initial
    endpoint was unreadable, and an empty successful list is complete evidence.
    """
    state = "UNKNOWN"
    reason = "INVALID_RESPONSE" if error is None else "REQUEST_FAILED"
    status = None
    pagination_diagnostic = None
    complete = (
        error is None
        and isinstance(items, list)
        and all(isinstance(item, dict) for item in items)
    )
    if complete:
        state, reason = "READ_COMPLETE", "NONE"
    elif isinstance(error, str):
        http_error = re.fullmatch(r"http([45][0-9]{2})", error)
        if http_error:
            status = int(http_error[1])
            if status in {401, 403, 404}:
                state = "UNAVAILABLE"
                reason = {
                    401: "HTTP_UNAUTHORIZED",
                    403: "HTTP_DENIED_OR_RESTRICTED",
                    404: "HTTP_NOT_FOUND_OR_HIDDEN",
                }[status]
            elif status == 429:
                reason = "HTTP_RATE_LIMITED"
            else:
                reason = "HTTP_PROVIDER_ERROR" if status >= 500 else "HTTP_FAILURE"
        elif error.startswith(("pagination ", "invalid pagination URL:", "Link ")):
            reason = "PAGINATION_INCOMPLETE"
            pagination_diagnostic = _pagination_diagnostic(error)
        elif error.startswith("invalid-json:") or error in {
            "unexpected non-list API response", "API page contains a non-object entry",
        }:
            reason = "INVALID_RESPONSE"
        elif error in {"response-body-limit-exceeded", "invalid-content-length"}:
            reason = "RESPONSE_LIMIT"
        elif error.startswith("URLError:") or error in {
            "TimeoutError", "ConnectionError", "ConnectionResetError",
        }:
            reason = "TRANSPORT_ERROR"
    result = {
        "state": state,
        "collection_complete": complete,
        "http_failure_status": status,
        "reason": reason,
    }
    if pagination_diagnostic is not None:
        result["pagination_diagnostic"] = pagination_diagnostic
    return result


def collect_github(
    *,
    request_timeout: float = 20.0,
    retries: int = 2,
    include_branch_protection: bool = True,
) -> dict[str, Any]:
    discovered, organization, discovery_error = discover_repositories(
        ORG, headers=github_headers(), timeout=request_timeout, retries=retries,
        max_pages=MAX_PAGES,
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
        "code": _code_alert_path(organization),
        "secret": f"/orgs/{ORG}/secret-scanning/alerts?state=open&per_page=100",
        "dependabot": f"/orgs/{ORG}/dependabot/alerts?state=open&per_page=100",
    }
    alerts: dict[str, list[dict[str, Any]] | None] = {}
    alert_errors: dict[str, str | None] = {}
    if alert_paths["code"] is None:
        alerts["code"] = None
        alert_errors["code"] = "organization identity unavailable"
    with cf.ThreadPoolExecutor(max_workers=3) as executor:
        future_map = {
            executor.submit(
                _all_alerts,
                path,
                request_timeout=request_timeout,
                retries=retries,
            ): name
            for name, path in alert_paths.items()
            if path is not None
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
            "ci_pending": sum(
                1 for repo in repos.values() if repo["ci"] == "pending"
            ),
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
            "endpoint_reads": {
                name: _alert_endpoint_read_observation(
                    alerts.get(name), alert_errors.get(name)
                )
                for name in alert_paths
            },
        },
        "open_prs": (prs or {}).get("total_count") if isinstance(prs, dict) else None,
        "open_issues": (
            (issues or {}).get("total_count") if isinstance(issues, dict) else None
        ),
    }
