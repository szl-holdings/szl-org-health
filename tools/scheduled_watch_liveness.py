#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only liveness supervisor for scheduled watch workflows in other repositories.

A daily cron inside a target repository cannot detect its own disablement:
GitHub disables schedules in public repositories after 60 days without
repository activity, and a schedule that no longer fires reports nothing.
This checker therefore runs from szl-org-health. For every entry in
governance/scheduled-watches.v1.json it reads GitHub REST state and requires:

  (a) the workflow `state` is `active` (`disabled_inactivity`,
      `disabled_manually`, `disabled_fork` and `deleted` are DISABLED);
  (b) the newest completed `schedule` run (and `workflow_dispatch` only when
      the entry sets accept_workflow_dispatch) was created within
      max_age_hours, concluded `success`, and every required job in that run
      concluded `success`.

Verdicts: HEALTHY | STALE | DISABLED | FAILED | UNKNOWN. UNKNOWN (API error,
missing or malformed evidence) is never HEALTHY. Exit 0 only when every entry
is HEALTHY, 1 otherwise, 2 when the watch list itself is invalid.

Strictly read-only: GET requests to api.github.com repository endpoints only,
at most five per entry (the fifth only for optional dispatch+partial rerun). A
missing required job in a completed successful rerun may trigger one independent
same-run, same-attempt job-list read; failed/absent jobs remain non-healthy.
It never re-enables a workflow, dispatches a run, or
writes to any repository. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

API = "https://api.github.com"
SCHEMA = "szl.scheduled-watch-liveness.v1"
DEFAULT_WATCHLIST = "governance/scheduled-watches.v1.json"
VERDICTS = ("HEALTHY", "STALE", "DISABLED", "FAILED", "UNKNOWN")
DISABLED_STATES = frozenset(
    {"disabled_inactivity", "disabled_manually", "disabled_fork", "deleted"}
)
RUNS_PER_PAGE = 1
JOBS_PER_PAGE = 30
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_AGE_HOURS_LIMIT = 24 * 31
CLOCK_SKEW = timedelta(minutes=5)
REPO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}")
WORKFLOW_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}\.ya?ml")
TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
RUN_URL_RE = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/\d+")
ENTRY_KEYS = frozenset(
    {"repo", "workflow", "required_jobs", "max_age_hours", "accept_workflow_dispatch", "note"}
)
REQUIRED_ENTRY_KEYS = frozenset({"repo", "workflow", "required_jobs", "max_age_hours"})


class WatchListError(ValueError):
    """The declared watch list is malformed; nothing can be supervised."""


@dataclass(frozen=True)
class Watch:
    repo: str
    workflow: str
    required_jobs: tuple[tuple[str, str], ...]  # (job id, job display name)
    max_age_hours: int
    accept_workflow_dispatch: bool = False


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    keys = [key for key, _ in pairs]
    duplicates = sorted({key for key in keys if keys.count(key) > 1})
    if duplicates:
        raise WatchListError(f"duplicate keys {duplicates}")
    return dict(pairs)


def _nonempty_str(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def load_watchlist(path: Path) -> list[Watch]:
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WatchListError(f"{path}: unreadable ({type(exc).__name__})") from None
    if not isinstance(document, dict) or set(document) != {"schema", "watches"}:
        raise WatchListError("top level must be exactly {schema, watches}")
    if document["schema"] != SCHEMA:
        raise WatchListError(f"schema must be {SCHEMA!r}")
    entries = document["watches"]
    if not isinstance(entries, list) or not entries:
        raise WatchListError("watches must be a non-empty list")

    watches: list[Watch] = []
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(entries):
        where = f"watches[{index}]"
        if not isinstance(entry, dict):
            raise WatchListError(f"{where}: must be an object")
        unknown = set(entry) - ENTRY_KEYS
        missing = REQUIRED_ENTRY_KEYS - set(entry)
        if unknown or missing:
            raise WatchListError(
                f"{where}: unknown keys {sorted(unknown)}, missing keys {sorted(missing)}"
            )
        repo, workflow = entry["repo"], entry["workflow"]
        if not isinstance(repo, str) or not REPO_RE.fullmatch(repo) or repo.split("/")[1] in (".", ".."):
            raise WatchListError(f"{where}: repo must be owner/name")
        if not isinstance(workflow, str) or not WORKFLOW_RE.fullmatch(workflow):
            raise WatchListError(f"{where}: workflow must be a .github/workflows file name")
        if (repo.lower(), workflow) in seen:
            raise WatchListError(f"{where}: duplicate watch {repo} {workflow}")
        seen.add((repo.lower(), workflow))

        max_age = entry["max_age_hours"]
        if isinstance(max_age, bool) or not isinstance(max_age, int) or not 1 <= max_age <= MAX_AGE_HOURS_LIMIT:
            raise WatchListError(f"{where}: max_age_hours must be an integer in 1..{MAX_AGE_HOURS_LIMIT}")
        accept_dispatch = entry.get("accept_workflow_dispatch", False)
        if not isinstance(accept_dispatch, bool):
            raise WatchListError(f"{where}: accept_workflow_dispatch must be a boolean")
        if "note" in entry and not isinstance(entry["note"], str):
            raise WatchListError(f"{where}: note must be a string")

        jobs = entry["required_jobs"]
        if not isinstance(jobs, list) or not jobs:
            raise WatchListError(f"{where}: required_jobs must be a non-empty list")
        required: list[tuple[str, str]] = []
        for job in jobs:
            if (
                not isinstance(job, dict)
                or set(job) != {"id", "name"}
                or not _nonempty_str(job["id"])
                or not _nonempty_str(job["name"])
            ):
                raise WatchListError(f"{where}: each required job must be exactly {{id, name}} strings")
            required.append((job["id"], job["name"]))
        if len({name for _, name in required}) != len(required):
            raise WatchListError(f"{where}: duplicate required job name")
        watches.append(Watch(repo, workflow, tuple(required), max_age, accept_dispatch))
    return watches


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Never forward the token off api.github.com."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith(API + "/"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class GitHubReader:
    """GET-only GitHub REST client. Returns (status, body); status -1 means no HTTP answer."""

    def __init__(self, token: str | None, opener=None, timeout: float = 30.0):
        self._token = token
        self._opener = opener or urllib.request.build_opener(_SameHostRedirects())
        self._timeout = timeout
        self.calls = 0

    def get(self, url: str) -> tuple[int, object]:
        if not url.startswith(API + "/repos/"):
            raise ValueError("reader is restricted to GitHub REST repository reads")
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "szl-scheduled-watch-liveness/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        request = urllib.request.Request(url, headers=headers, method="GET")
        self.calls += 1
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                data = response.read(MAX_RESPONSE_BYTES + 1)
                if len(data) > MAX_RESPONSE_BYTES:
                    return -1, "response exceeds size limit"
                return response.status, json.loads(data or b"null")
        except urllib.error.HTTPError as exc:
            exc.close()
            return exc.code, None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return -1, type(exc).__name__


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _parse_run(run: object, event: str, workflow_id: int) -> dict | None:
    """Accept only a completed run of the queried event and workflow."""
    if not isinstance(run, dict):
        return None
    created = _parse_time(run.get("created_at"))
    if (
        created is None
        or not _positive_int(run.get("id"))
        or run.get("event") != event
        or run.get("status") != "completed"
        or run.get("workflow_id") != workflow_id
        or not _nonempty_str(run.get("conclusion"))
    ):
        return None
    url = run.get("html_url")
    return {
        "id": run["id"],
        "event": event,
        "conclusion": run["conclusion"],
        "created_at": run["created_at"],
        "created": created,
        "run_attempt": run.get("run_attempt") if _positive_int(run.get("run_attempt")) else None,
        "html_url": url if isinstance(url, str) and RUN_URL_RE.fullmatch(url) else None,
    }


def check_watch(reader, watch: Watch, now: datetime) -> dict:
    """Return one verdict record for one declared watch (at most four GETs)."""
    result: dict = {
        "repo": watch.repo,
        "workflow": watch.workflow,
        "max_age_hours": watch.max_age_hours,
        "events": ["schedule"] + (["workflow_dispatch"] if watch.accept_workflow_dispatch else []),
        "state": None,
        "run": None,
        "jobs": [],
    }

    def done(verdict: str, detail: str) -> dict:
        result["verdict"] = verdict
        result["detail"] = detail
        return result

    # (a) The workflow must exist at the declared path and be active.
    workflow_url = f"{API}/repos/{watch.repo}/actions/workflows/{watch.workflow}"
    status, body = reader.get(workflow_url)
    if status == 404:
        return done("UNKNOWN", "workflow not found (HTTP 404)")
    if status != 200:
        return done("UNKNOWN", f"workflow read failed (HTTP {status})")
    if (
        not isinstance(body, dict)
        or not _positive_int(body.get("id"))
        or not isinstance(body.get("state"), str)
    ):
        return done("UNKNOWN", "workflow response malformed")
    if body.get("path") != f".github/workflows/{watch.workflow}":
        return done("UNKNOWN", "workflow response path does not match the declared file")
    workflow_id = body["id"]
    state = body["state"]
    result["state"] = state
    if state in DISABLED_STATES:
        return done("DISABLED", f"workflow state is {state}; its schedule will not fire")
    if state != "active":
        return done("UNKNOWN", f"unrecognized workflow state {state[:40]!r}")

    # (b) The newest completed counted run must be fresh and green.
    candidates: list[dict] = []
    for event in result["events"]:
        status, body = reader.get(
            f"{workflow_url}/runs?event={event}&status=completed&per_page={RUNS_PER_PAGE}"
        )
        if status != 200:
            return done("UNKNOWN", f"{event} run list failed (HTTP {status})")
        runs = body.get("workflow_runs") if isinstance(body, dict) else None
        total = body.get("total_count") if isinstance(body, dict) else None
        if not isinstance(runs, list) or not isinstance(total, int) or bool(runs) != (total > 0):
            return done("UNKNOWN", f"{event} run list malformed")
        for raw in runs[:RUNS_PER_PAGE]:
            run = _parse_run(raw, event, workflow_id)
            if run is None:
                return done("UNKNOWN", f"{event} run record malformed or not a completed {event} run")
            candidates.append(run)
    if not candidates:
        return done("STALE", f"no completed {' or '.join(result['events'])} run has ever been recorded")

    newest = max(candidates, key=lambda run: (run["created"], run["id"]))
    age_hours = (now - newest["created"]).total_seconds() / 3600
    result["run"] = {
        key: newest[key]
        for key in ("id", "event", "conclusion", "created_at", "run_attempt", "html_url")
    }
    result["run"]["age_hours"] = round(age_hours, 2)
    if newest["created"] > now + CLOCK_SKEW:
        return done("UNKNOWN", "newest run is timestamped in the future")
    if age_hours > watch.max_age_hours:
        return done(
            "STALE",
            f"newest completed {newest['event']} run is {age_hours:.1f}h old "
            f"(max {watch.max_age_hours}h; it concluded {newest['conclusion']})",
        )
    if newest["conclusion"] != "success":
        return done("FAILED", f"newest {newest['event']} run concluded {newest['conclusion']}")

    status, body = reader.get(
        f"{API}/repos/{watch.repo}/actions/runs/{newest['id']}/jobs"
        f"?filter=latest&per_page={JOBS_PER_PAGE}"
    )
    if status != 200:
        return done("UNKNOWN", f"job list for run {newest['id']} failed (HTTP {status})")
    jobs = body.get("jobs") if isinstance(body, dict) else None
    total = body.get("total_count") if isinstance(body, dict) else None
    if (
        not isinstance(jobs, list)
        or not isinstance(total, int)
        or not all(isinstance(job, dict) for job in jobs)
    ):
        return done("UNKNOWN", f"job list for run {newest['id']} malformed")
    result["job_readback"] = "latest"

    # GitHub's latest-job index can temporarily omit one job after a successful
    # rerun. Do not accept the run's aggregate success as proof of that job.
    # If—and only if—the latest index lacks a required job, no required job
    # already has an explicit failure, and this is an identified rerun,
    # independently read the jobs of that exact run attempt. Never combine
    # earlier attempts, ignore 401/403/429, or silently truncate a job page.
    names = {name for _, name in watch.required_jobs}
    missing = any(not any(j.get("name") == name for j in jobs) for name in names)
    observed_failure = any(
        j.get("name") in names
        and _nonempty_str(j.get("conclusion"))
        and j.get("conclusion") != "success"
        for j in jobs
    )
    attempt = newest["run_attempt"]
    if missing and not observed_failure and isinstance(attempt, int) and attempt > 1:
        status, attempt_body = reader.get(
            f"{API}/repos/{watch.repo}/actions/runs/{newest['id']}"
            f"/attempts/{attempt}/jobs?per_page={JOBS_PER_PAGE}"
        )
        if status != 200:
            return done("UNKNOWN", f"exact-attempt job read failed (HTTP {status})")
        attempt_jobs = attempt_body.get("jobs") if isinstance(attempt_body, dict) else None
        attempt_total = attempt_body.get("total_count") if isinstance(attempt_body, dict) else None
        if (
            not isinstance(attempt_jobs, list)
            or not isinstance(attempt_total, int)
            or attempt_total != len(attempt_jobs)
            or not all(
                isinstance(job, dict)
                and _positive_int(job.get("id"))
                and job.get("run_attempt") == attempt
                and job.get("status") == "completed"
                for job in attempt_jobs
            )
            or len({job["id"] for job in attempt_jobs}) != len(attempt_jobs)
        ):
            return done("UNKNOWN", "exact-attempt job list incomplete or malformed")
        jobs, total = attempt_jobs, attempt_total
        result["job_readback"] = f"exact_attempt_{attempt}"

    failed: list[str] = []
    unknown: list[str] = []
    for job_id, job_name in watch.required_jobs:
        matches = [job for job in jobs if job.get("name") == job_name]
        conclusions = [job.get("conclusion") for job in matches]
        result["jobs"].append({"id": job_id, "name": job_name, "conclusions": conclusions})
        if not matches:
            truncated = " (job list truncated)" if total > len(jobs) else ""
            unknown.append(f"required job {job_id} absent from run{truncated}")
        elif any(not _nonempty_str(conclusion) for conclusion in conclusions):
            unknown.append(f"required job {job_id} has no conclusion")
        elif any(conclusion != "success" for conclusion in conclusions):
            bad = sorted({c for c in conclusions if c != "success"})
            failed.append(f"required job {job_id} concluded {'/'.join(bad)}")
    # FAILED > UNKNOWN: definite red evidence outranks missing evidence.
    if failed:
        return done("FAILED", "; ".join(failed + unknown))
    if unknown:
        return done("UNKNOWN", "; ".join(unknown))
    return done(
        "HEALTHY",
        f"newest {newest['event']} run is {age_hours:.1f}h old and every required job succeeded "
        f"(readback={result['job_readback']})",
    )


def _cell(value: object) -> str:
    text = "—" if value is None or value == "" else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _escape_command(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def render_summary(results: list[dict], generated_at: str) -> str:
    counts = {verdict: sum(r["verdict"] == verdict for r in results) for verdict in VERDICTS}
    overall = "ALL HEALTHY" if counts["HEALTHY"] == len(results) else "NOT HEALTHY"
    lines = [
        f"# Scheduled watch liveness — {overall}",
        "",
        f"Generated {generated_at} · " + " · ".join(f"{v} {counts[v]}" for v in VERDICTS),
        "",
        "| Verdict | Repository | Workflow | State | Newest counted run | Age (h) / max | Required jobs | Detail |",
        "|---|---|---|---|---|---:|---|---|",
    ]
    for r in results:
        run = r.get("run")
        if run:
            label = _cell(f"#{run['id']} {run['event']} {run['conclusion']}")
            run_cell = f"[{label}]({run['html_url']})" if run.get("html_url") else label
            age = f"{run['age_hours']:.1f} / {r['max_age_hours']}"
        else:
            run_cell, age = "—", f"— / {r['max_age_hours']}"
        jobs = ", ".join(
            f"{job['id']}={'/'.join(str(c) for c in job['conclusions']) or 'absent'}"
            for job in r["jobs"]
        )
        lines.append(
            f"| **{r['verdict']}** | {_cell(r['repo'])} | {_cell(r['workflow'])} | "
            f"{_cell(r['state'])} | {run_cell} | {age} | {_cell(jobs)} | {_cell(r['detail'])} |"
        )
    lines += [
        "",
        "Read-only: GET requests only. This check never re-enables a workflow, dispatches a run, "
        "or writes to a target repository. UNKNOWN is never healthy.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None, *, reader=None, now: datetime | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only liveness supervisor for scheduled watch workflows in other repositories."
    )
    parser.add_argument("--watchlist", default=DEFAULT_WATCHLIST)
    parser.add_argument("--summary", help="also write the Markdown summary to this path")
    args = parser.parse_args(argv)
    try:
        watches = load_watchlist(Path(args.watchlist))
    except WatchListError as exc:
        print(f"::error title=Invalid watch list::{_escape_command(str(exc))}")
        return 2

    if reader is None:
        reader = GitHubReader(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
    now = now or datetime.now(timezone.utc)
    generated_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    results = [check_watch(reader, watch, now) for watch in watches]

    summary = render_summary(results, generated_at)
    print(summary)
    report = {"schema": SCHEMA, "generated_at": generated_at, "results": results}
    print(json.dumps(report, sort_keys=True))
    for target in (args.summary, os.environ.get("GITHUB_STEP_SUMMARY")):
        if target:
            with open(target, "a", encoding="utf-8") as stream:
                stream.write(summary)
    for r in results:
        if r["verdict"] != "HEALTHY":
            print(
                f"::error title=Scheduled watch {r['verdict']}::"
                + _escape_command(f"{r['repo']} {r['workflow']}: {r['detail']}")
            )
    return 0 if all(r["verdict"] == "HEALTHY" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())

