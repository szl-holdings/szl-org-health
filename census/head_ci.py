"""Source-bound GitHub push-run witness, distinct from release readiness.

Never infer protected-main HEAD from a workflow run. The caller supplies an
independently read default-branch commit SHA, bracketed before/after the run
query. A green observation covers only the returned latest push-run sample,
NOT required PR checks, signed provenance, HF publication, or production.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import re
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SCOPE = "bracketed-default-head-latest-push-workflow-observation/v1"
STATES = frozenset({
    "ARCHIVED", "NOT_SAMPLED", "UNAVAILABLE", "CURRENT_HEAD_RED", "CURRENT_HEAD_PENDING",
    "CURRENT_HEAD_INCOMPLETE", "NO_CURRENT_HEAD_RUN", "HISTORICAL_FAILURE_ONLY",
    "OBSERVED_HEAD_GREEN",
})
FAILURES = frozenset({"failure", "timed_out", "action_required", "startup_failure"})
NONEXECUTED = frozenset({"cancelled", "skipped", "neutral", "stale"})
PENDING = frozenset({"queued", "requested", "waiting", "pending", "in_progress"})


def witness(state: str, *, coverage: str = "UNAVAILABLE",
            current: int = 0, historical_failed: int = 0,
            missing: int = 0, failed: int = 0) -> dict[str, Any]:
    if state not in STATES:
        raise ValueError("invalid source-head CI state")
    return {
        "head_ci": state,
        "head_ci_scope": SCOPE,
        "head_ci_window_coverage": coverage if coverage in {
            "COMPLETE", "INCOMPLETE", "UNAVAILABLE"} else "UNAVAILABLE",
        "head_push_workflows_observed": current,
        "head_historical_failed_workflows": historical_failed,
        "head_missing_workflows": missing,
        "head_failed_workflows": failed,
    }


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return observed.astimezone(timezone.utc) if observed.tzinfo else None


def classify_head_push_runs(
    runs: Any, *, default_head_sha: str | None,
    default_branch: str, coverage: str,
) -> dict[str, Any]:
    """Classify only latest per-workflow push runs against independently read HEAD.

    Historical failed attempts remain historical even if other workflows run
    successfully at HEAD. Cancelled/skipped/neutral/manual workflows cannot
    make a green witness. No caller may treat OBSERVED_HEAD_GREEN as merge
    authorization or production release evidence.
    """
    if not (isinstance(default_head_sha, str)
            and SHA40.fullmatch(default_head_sha)
            and isinstance(default_branch, str) and default_branch
            and type(runs) is list and len(runs) <= 1000):
        return witness("UNAVAILABLE", coverage=coverage)
    seen_ids: set[int] = set()
    latest: dict[int, tuple[tuple[datetime, int, int], Mapping[str, Any]]] = {}
    for row in runs:
        if not isinstance(row, Mapping):
            return witness("UNAVAILABLE", coverage=coverage)
        run_id, workflow_id = row.get("id"), row.get("workflow_id")
        attempt = row.get("run_attempt", 1)
        created = _timestamp(row.get("created_at"))
        sha = row.get("head_sha")
        if (type(run_id) is not int or run_id <= 0 or run_id in seen_ids
                or type(workflow_id) is not int or workflow_id <= 0
                or type(attempt) is not int or attempt <= 0
                or created is None or not isinstance(sha, str)
                or SHA40.fullmatch(sha) is None
                or row.get("event") != "push"
                or row.get("head_branch") != default_branch):
            return witness("UNAVAILABLE", coverage=coverage)
        seen_ids.add(run_id)
        ordering = created, run_id, attempt
        old = latest.get(workflow_id)
        if old is None or ordering > old[0]:
            latest[workflow_id] = ordering, row

    current = 0
    historical_failed = 0
    missing = 0
    failed = 0
    pending = 0
    nonexecuted = 0
    for _, row in latest.values():
        status, conclusion = row.get("status"), row.get("conclusion")
        coherent = (
            (status == "completed" and conclusion in
             FAILURES | NONEXECUTED | {"success"})
            or (status in PENDING and conclusion is None)
        )
        if not coherent:
            return witness("UNAVAILABLE", coverage=coverage)
        if row["head_sha"] != default_head_sha:
            missing += 1
            if status == "completed" and conclusion in FAILURES:
                historical_failed += 1
            continue
        current += 1
        if conclusion in FAILURES:
            failed += 1
        elif status in PENDING:
            pending += 1
        elif conclusion in NONEXECUTED:
            nonexecuted += 1

    details = dict(coverage=coverage, current=current,
                   historical_failed=historical_failed,
                   missing=missing, failed=failed)
    if failed:
        return witness("CURRENT_HEAD_RED", **details)
    if pending:
        return witness("CURRENT_HEAD_PENDING", **details)
    if not current:
        return witness("HISTORICAL_FAILURE_ONLY" if historical_failed else
                       "NO_CURRENT_HEAD_RUN", **details)
    if missing or nonexecuted or coverage != "COMPLETE":
        return witness("CURRENT_HEAD_INCOMPLETE", **details)
    return witness("OBSERVED_HEAD_GREEN", **details)
