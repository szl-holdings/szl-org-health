"""Closed metadata contract for bounded default-branch push-run coverage.

COMPLETE means all runs reported by this API query were returned. It does not
prove current-head CI, workflow inventory, or history already deleted by GitHub.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

RUN_WINDOW = 100
MAX_CI_RUN_PAGES = 10
MAX_CI_RUNS = RUN_WINDOW * MAX_CI_RUN_PAGES
CI_SCOPE = "latest-per-workflow-within-recent-default-branch-push-window"


def _count(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def ci_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate retained metadata without copying names, URLs, or errors."""
    if value.get("archived") is True:
        return {"ci_coverage": "NOT_APPLICABLE", "ci_scope": "archived",
                "run_window_observed": None, "default_branch_push_runs_total": None}
    observed = _count(value.get("run_window_observed"))
    total = _count(value.get("default_branch_push_runs_total"))
    if observed is not None and observed > MAX_CI_RUNS:
        observed = None
    scope = CI_SCOPE if value.get("ci_scope") == CI_SCOPE else "unavailable"
    state = "UNAVAILABLE"
    if scope == CI_SCOPE and observed is not None and total is not None:
        error = value.get("error")
        no_error = error is None or (isinstance(error, (str, list, tuple, dict)) and not error)
        if value.get("ci_coverage") == "COMPLETE" and observed == total and no_error:
            state = "COMPLETE"
        elif value.get("ci_coverage") == "INCOMPLETE" and observed < total:
            state = "INCOMPLETE"
    return {"ci_coverage": state, "ci_scope": scope,
            "run_window_observed": observed, "default_branch_push_runs_total": total}
