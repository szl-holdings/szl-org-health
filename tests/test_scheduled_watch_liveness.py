# SPDX-License-Identifier: Apache-2.0
"""Offline contracts for the external scheduled-watch liveness supervisor.

Every GitHub response here is a recorded-shape fake; no test touches the network.
"""
from __future__ import annotations

import copy
import io
import json
import re
import tempfile
import unittest
import urllib.error
import urllib.parse
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.test_secret_workflow_boundary import _canonical_triggers, _uses_actions_secrets
from tools.scheduled_watch_liveness import (
    API,
    GitHubReader,
    Watch,
    WatchListError,
    check_watch,
    load_watchlist,
    main,
)


ROOT = Path(__file__).resolve().parents[1]
WATCHLIST = ROOT / "governance" / "scheduled-watches.v1.json"
WORKFLOW = ROOT / ".github" / "workflows" / "scheduled-watch-liveness.yml"
NOW = datetime(2026, 10, 13, 18, 0, 0, tzinfo=timezone.utc)
REPO = "szl-holdings/the-grid"
FILE = "hf-space-drift.yml"
WORKFLOW_ID = 383483901
CREDENTIAL = "Hub credential census (read-only metadata)"
DRIFT = "Public Space serves main"
GRID = Watch(
    repo=REPO,
    workflow=FILE,
    required_jobs=(("credential", CREDENTIAL), ("drift", DRIFT)),
    max_age_hours=48,
)


def stamp(hours_ago: float) -> str:
    return (NOW - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeGitHub:
    """Serves the GitHub REST shapes the checker reads, applying server-side filters."""

    def __init__(self, state: str = "active"):
        self.workflow: dict = {
            "id": WORKFLOW_ID,
            "name": "HF Space drift watch",
            "path": f".github/workflows/{FILE}",
            "state": state,
        }
        self.runs: list[dict] = []
        self.jobs: dict[int, list[dict]] = {}
        self.errors: dict[str, tuple[int, object]] = {}
        self.calls: list[str] = []
        self._next_id = 1000

    def add_run(
        self,
        hours_ago: float,
        conclusion: str = "success",
        event: str = "schedule",
        status: str = "completed",
        jobs: dict[str, str] | None = None,
    ) -> int:
        self._next_id += 1
        run_id = self._next_id
        self.runs.append(
            {
                "id": run_id,
                "workflow_id": WORKFLOW_ID,
                "event": event,
                "status": status,
                "conclusion": conclusion if status == "completed" else None,
                "created_at": stamp(hours_ago),
                "run_attempt": 1,
                "head_branch": "main",
                "html_url": f"https://github.com/{REPO}/actions/runs/{run_id}",
            }
        )
        if jobs is None:
            jobs = {CREDENTIAL: "success", DRIFT: "success"}
        self.jobs[run_id] = [
            {"id": run_id * 10 + index, "name": name, "status": "completed", "conclusion": result}
            for index, (name, result) in enumerate(jobs.items())
        ]
        return run_id

    def get(self, url: str) -> tuple[int, object]:
        self.calls.append(url)
        for marker, response in self.errors.items():
            if marker in url:
                return copy.deepcopy(response)
        parsed = urllib.parse.urlsplit(url)
        query = dict(urllib.parse.parse_qsl(parsed.query))
        base = f"/repos/{REPO}/actions"
        if parsed.path == f"{base}/workflows/{FILE}" and not query:
            return 200, copy.deepcopy(self.workflow)
        if parsed.path == f"{base}/workflows/{FILE}/runs":
            selected = [
                run
                for run in self.runs
                if run["event"] == query["event"] and run["status"] == query["status"]
            ]
            selected.sort(key=lambda run: run["created_at"], reverse=True)
            page = selected[: int(query["per_page"])]
            return 200, {"total_count": len(selected), "workflow_runs": copy.deepcopy(page)}
        match = re.fullmatch(rf"{base}/runs/(\d+)/jobs", parsed.path)
        if match and query == {"filter": "latest", "per_page": "30"}:
            jobs = self.jobs[int(match.group(1))]
            return 200, {"total_count": len(jobs), "jobs": copy.deepcopy(jobs)}
        raise AssertionError(f"unexpected request: {url}")


class ScheduledWatchVerdictTests(unittest.TestCase):
    def verdict(self, github: FakeGitHub, watch: Watch = GRID) -> dict:
        result = check_watch(github, watch, NOW)
        self.assertLessEqual(len(github.calls), 4, "API calls per entry must stay bounded")
        self.assertTrue(all(call.startswith(f"{API}/repos/") for call in github.calls))
        return result

    def test_fresh_green_scheduled_run_is_healthy(self) -> None:
        github = FakeGitHub()
        run_id = github.add_run(hours_ago=5)
        result = self.verdict(github)
        self.assertEqual(result["verdict"], "HEALTHY", result)
        self.assertEqual(result["run"]["id"], run_id)
        self.assertEqual(result["run"]["event"], "schedule")
        self.assertEqual(
            [(job["id"], job["conclusions"]) for job in result["jobs"]],
            [("credential", ["success"]), ("drift", ["success"])],
        )
        self.assertEqual(len(github.calls), 3)

    def test_old_last_success_is_stale(self) -> None:
        github = FakeGitHub()
        github.add_run(hours_ago=72)
        result = self.verdict(github)
        self.assertEqual(result["verdict"], "STALE", result)
        self.assertIn("72.0h old", result["detail"])
        self.assertEqual(len(github.calls), 2, "a stale run needs no job read")

    def test_disabled_for_inactivity_is_flagged_explicitly(self) -> None:
        github = FakeGitHub(state="disabled_inactivity")
        github.add_run(hours_ago=1)
        result = self.verdict(github)
        self.assertEqual(result["verdict"], "DISABLED", result)
        self.assertEqual(result["state"], "disabled_inactivity")
        self.assertIn("disabled_inactivity", result["detail"])

    def test_manually_disabled_is_flagged_explicitly(self) -> None:
        github = FakeGitHub(state="disabled_manually")
        github.add_run(hours_ago=1)
        result = self.verdict(github)
        self.assertEqual(result["verdict"], "DISABLED", result)
        self.assertEqual(result["state"], "disabled_manually")
        self.assertIn("disabled_manually", result["detail"])

    def test_unrecognized_workflow_state_is_unknown(self) -> None:
        github = FakeGitHub(state="paused_for_reasons")
        self.assertEqual(self.verdict(github)["verdict"], "UNKNOWN")

    def test_latest_scheduled_run_failed(self) -> None:
        github = FakeGitHub()
        github.add_run(hours_ago=30)
        github.add_run(hours_ago=6, conclusion="failure", jobs={CREDENTIAL: "success", DRIFT: "failure"})
        result = self.verdict(github)
        self.assertEqual(result["verdict"], "FAILED", result)
        self.assertIn("concluded failure", result["detail"])

    def test_cancelled_latest_scheduled_run_is_not_healthy(self) -> None:
        github = FakeGitHub()
        github.add_run(hours_ago=6, conclusion="cancelled")
        self.assertEqual(self.verdict(github)["verdict"], "FAILED")

    def test_required_job_failed_while_run_succeeded(self) -> None:
        github = FakeGitHub()
        github.add_run(hours_ago=3, conclusion="success", jobs={CREDENTIAL: "failure", DRIFT: "success"})
        result = self.verdict(github)
        self.assertEqual(result["verdict"], "FAILED", result)
        self.assertIn("required job credential concluded failure", result["detail"])

    def test_skipped_required_job_is_not_success(self) -> None:
        github = FakeGitHub()
        github.add_run(hours_ago=3, jobs={CREDENTIAL: "success", DRIFT: "skipped"})
        result = self.verdict(github)
        self.assertEqual(result["verdict"], "FAILED", result)
        self.assertIn("drift concluded skipped", result["detail"])

    def test_missing_required_job_is_unknown(self) -> None:
        github = FakeGitHub()
        github.add_run(hours_ago=3, jobs={CREDENTIAL: "success", "renamed drift job": "success"})
        result = self.verdict(github)
        self.assertEqual(result["verdict"], "UNKNOWN", result)
        self.assertIn("required job drift absent", result["detail"])

    def test_api_errors_are_unknown_never_healthy(self) -> None:
        cases = {
            f"/actions/workflows/{FILE}": (500, None),
            "/runs?event=schedule": (403, None),
            "/jobs?": (-1, "URLError"),
        }
        for marker, response in cases.items():
            with self.subTest(marker=marker):
                github = FakeGitHub()
                github.add_run(hours_ago=2)
                github.errors[marker] = response
                result = self.verdict(github)
                self.assertEqual(result["verdict"], "UNKNOWN", result)
                self.assertIn(f"HTTP {response[0]}", result["detail"])

    def test_missing_workflow_is_unknown(self) -> None:
        github = FakeGitHub()
        github.errors[f"/actions/workflows/{FILE}"] = (404, None)
        result = self.verdict(github)
        self.assertEqual(result["verdict"], "UNKNOWN")
        self.assertIn("not found", result["detail"])

    def test_malformed_responses_are_unknown(self) -> None:
        mutations = {
            "workflow body": lambda gh: gh.errors.__setitem__(f"/actions/workflows/{FILE}", (200, ["not", "a", "dict"])),
            "workflow path": lambda gh: gh.workflow.__setitem__("path", ".github/workflows/other.yml"),
            "run list": lambda gh: gh.errors.__setitem__("/runs?event=schedule", (200, {"workflow_runs": None})),
            "run workflow id": lambda gh: gh.runs[0].__setitem__("workflow_id", 1),
            "run event": lambda gh: gh.errors.__setitem__(
                "/runs?event=schedule",
                (200, {"total_count": 1, "workflow_runs": [{**gh.runs[0], "event": "push"}]}),
            ),
            "run timestamp": lambda gh: gh.runs[0].__setitem__("created_at", "yesterday"),
            "job list": lambda gh: gh.errors.__setitem__("/jobs?", (200, {"jobs": "nope"})),
            "job conclusion": lambda gh: gh.jobs[gh.runs[0]["id"]][0].__setitem__("conclusion", None),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                github = FakeGitHub()
                github.add_run(hours_ago=2)
                mutate(github)
                result = self.verdict(github)
                self.assertEqual(result["verdict"], "UNKNOWN", result)

    def test_future_run_timestamp_is_unknown(self) -> None:
        github = FakeGitHub()
        github.add_run(hours_ago=-3)
        self.assertEqual(self.verdict(github)["verdict"], "UNKNOWN")

    def test_no_scheduled_run_ever_is_stale(self) -> None:
        github = FakeGitHub()
        result = self.verdict(github)
        self.assertEqual(result["verdict"], "STALE", result)
        self.assertIn("no completed schedule run", result["detail"])

    def test_dispatch_runs_do_not_count_unless_the_entry_allows_them(self) -> None:
        github = FakeGitHub()
        github.add_run(hours_ago=1, event="workflow_dispatch")
        github.add_run(hours_ago=0.5, event="push")
        self.assertEqual(self.verdict(github)["verdict"], "STALE")

        github = FakeGitHub()
        github.add_run(hours_ago=100)
        dispatch_id = github.add_run(hours_ago=1, event="workflow_dispatch")
        lenient = Watch(REPO, FILE, GRID.required_jobs, 48, accept_workflow_dispatch=True)
        result = self.verdict(github, lenient)
        self.assertEqual(result["verdict"], "HEALTHY", result)
        self.assertEqual(result["run"]["id"], dispatch_id)

    def test_in_progress_run_does_not_mask_the_newest_completed_run(self) -> None:
        github = FakeGitHub()
        github.add_run(hours_ago=60)
        github.add_run(hours_ago=0.2, status="in_progress")
        self.assertEqual(self.verdict(github)["verdict"], "STALE")

    def test_fresh_green_run_clears_the_alert(self) -> None:
        github = FakeGitHub()
        github.add_run(hours_ago=50)
        self.assertEqual(self.verdict(github)["verdict"], "STALE")
        github.add_run(hours_ago=26, conclusion="failure")
        github.calls.clear()
        self.assertEqual(self.verdict(github)["verdict"], "FAILED")
        github.add_run(hours_ago=2)
        github.calls.clear()
        self.assertEqual(self.verdict(github)["verdict"], "HEALTHY")


class ScheduledWatchMainTests(unittest.TestCase):
    def run_main(self, github: FakeGitHub, watchlist: Path = WATCHLIST) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / "summary.md"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(
                    ["--watchlist", str(watchlist), "--summary", str(summary)],
                    reader=github,
                    now=NOW,
                )
            text = summary.read_text(encoding="utf-8") if summary.exists() else ""
        return code, stdout.getvalue(), text

    def one_watch_list(self, tmp: str) -> Path:
        path = Path(tmp) / "watches.json"
        path.write_text(
            json.dumps(
                {
                    "schema": "szl.scheduled-watch-liveness.v1",
                    "watches": [
                        {
                            "repo": REPO,
                            "workflow": FILE,
                            "required_jobs": [
                                {"id": "credential", "name": CREDENTIAL},
                                {"id": "drift", "name": DRIFT},
                            ],
                            "max_age_hours": 48,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_healthy_exits_zero_and_writes_summary_table(self) -> None:
        github = FakeGitHub()
        github.add_run(hours_ago=4)
        with tempfile.TemporaryDirectory() as tmp:
            code, stdout, summary = self.run_main(github, self.one_watch_list(tmp))
        self.assertEqual(code, 0)
        self.assertIn("ALL HEALTHY", summary)
        self.assertIn("| **HEALTHY** | szl-holdings/the-grid | hf-space-drift.yml | active |", summary)
        self.assertNotIn("::error", stdout)

    def test_any_unhealthy_entry_exits_nonzero_with_annotation(self) -> None:
        github = FakeGitHub(state="disabled_inactivity")
        with tempfile.TemporaryDirectory() as tmp:
            code, stdout, summary = self.run_main(github, self.one_watch_list(tmp))
        self.assertEqual(code, 1)
        self.assertIn("NOT HEALTHY", summary)
        self.assertIn("| **DISABLED** |", summary)
        self.assertIn("::error title=Scheduled watch DISABLED::szl-holdings/the-grid", stdout)

    def test_invalid_watch_list_exits_two_without_requests(self) -> None:
        github = FakeGitHub()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text('{"schema": "szl.scheduled-watch-liveness.v1", "watches": []}', encoding="utf-8")
            code, stdout, _ = self.run_main(github, path)
        self.assertEqual(code, 2)
        self.assertIn("::error title=Invalid watch list::", stdout)
        self.assertEqual(github.calls, [])

    def test_summary_cells_cannot_break_the_table_or_inject_commands(self) -> None:
        github = FakeGitHub(state="odd|state\n::set-env name=X::1")
        with tempfile.TemporaryDirectory() as tmp:
            code, stdout, summary = self.run_main(github, self.one_watch_list(tmp))
        self.assertEqual(code, 1)
        self.assertIn("odd\\|state", summary)
        self.assertNotIn("\n::set-env", stdout)


class WatchListContractTests(unittest.TestCase):
    def test_committed_watch_list_declares_both_seed_watches(self) -> None:
        watches = {(w.repo, w.workflow): w for w in load_watchlist(WATCHLIST)}
        grid = watches[("szl-holdings/the-grid", "hf-space-drift.yml")]
        self.assertEqual([job_id for job_id, _ in grid.required_jobs], ["credential", "drift"])
        self.assertEqual(grid.max_age_hours, 48)
        self.assertFalse(grid.accept_workflow_dispatch)
        router = watches[("szl-holdings/szl-router", "hf-space-drift-check.yml")]
        self.assertEqual(router.required_jobs, (("drift-check", "drift-check"),))
        self.assertEqual(router.max_age_hours, 48)
        self.assertFalse(router.accept_workflow_dispatch)

    def test_malformed_watch_lists_are_rejected(self) -> None:
        good = json.loads(WATCHLIST.read_text(encoding="utf-8"))
        entry = good["watches"][0]
        bad_entries = {
            "unknown key": {**entry, "max_age": 48},
            "bad repo": {**entry, "repo": "../the-grid"},
            "workflow path": {**entry, "workflow": ".github/workflows/hf-space-drift.yml"},
            "zero age": {**entry, "max_age_hours": 0},
            "bool age": {**entry, "max_age_hours": True},
            "no jobs": {**entry, "required_jobs": []},
            "job shape": {**entry, "required_jobs": ["credential"]},
            "dispatch type": {**entry, "accept_workflow_dispatch": "yes"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "watches.json"
            for name, bad in bad_entries.items():
                with self.subTest(name=name):
                    path.write_text(json.dumps({**good, "watches": [bad]}), encoding="utf-8")
                    with self.assertRaises(WatchListError):
                        load_watchlist(path)
            with self.subTest(name="duplicate entry"):
                path.write_text(json.dumps({**good, "watches": [entry, entry]}), encoding="utf-8")
                with self.assertRaises(WatchListError):
                    load_watchlist(path)
            with self.subTest(name="duplicate key"):
                path.write_text('{"schema": "x", "schema": "y", "watches": []}', encoding="utf-8")
                with self.assertRaises(WatchListError):
                    load_watchlist(path)


class SupervisorWorkflowContractTests(unittest.TestCase):
    def test_workflow_is_scheduled_read_only_and_pinned(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")
        events, crons = _canonical_triggers(source, WORKFLOW.name)
        self.assertEqual(events, ("schedule", "workflow_dispatch"))
        self.assertEqual(len(crons), 1)
        self.assertRegex(crons[0], r"^\d{1,2} \*/6 \* \* \*$")
        self.assertFalse(_uses_actions_secrets(source), "only the run's GITHUB_TOKEN is allowed")
        self.assertIn("permissions:\n  contents: read\n  actions: read\n", source)
        self.assertNotRegex(source, r":\s*write\b")
        self.assertNotIn("write-all", source)
        self.assertIn("persist-credentials: false", source)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", source)
        self.assertIn(
            "tools/scheduled_watch_liveness.py --watchlist governance/scheduled-watches.v1.json",
            source,
        )
        uses = re.findall(r"(?m)^\s+(?:-\s+)?uses:\s*(\S+)", source)
        self.assertTrue(uses)
        for ref in uses:
            self.assertRegex(ref, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$", ref)

    def test_checker_only_issues_get_requests(self) -> None:
        source = (ROOT / "tools" / "scheduled_watch_liveness.py").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r'method="([A-Z]+)"', source), ["GET"])
        for verb in ("POST", "PUT", "PATCH", "DELETE"):
            self.assertNotIn(f'"{verb}"', source)
        self.assertNotIn("/dispatches", source)
        self.assertNotIn("/enable", source)


class GitHubReaderTests(unittest.TestCase):
    def test_reader_refuses_anything_but_repository_reads(self) -> None:
        reader = GitHubReader("token", opener=object())
        for url in ("https://example.com/repos/x/y", f"{API}/user", "http://api.github.com/repos/x/y"):
            with self.assertRaises(ValueError):
                reader.get(url)
        self.assertEqual(reader.calls, 0)

    def test_reader_sends_authenticated_get_and_maps_errors(self) -> None:
        class Response(io.BytesIO):
            status = 200

        class Opener:
            def __init__(self, outcome):
                self.outcome = outcome
                self.requests = []

            def open(self, request, timeout):
                self.requests.append(request)
                if isinstance(self.outcome, Exception):
                    raise self.outcome
                return Response(self.outcome)

        ok = Opener(b'{"state": "active"}')
        self.assertEqual(GitHubReader("t0ken", opener=ok).get(f"{API}/repos/a/b"), (200, {"state": "active"}))
        request = ok.requests[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.get_header("Authorization"), "Bearer t0ken")

        url = f"{API}/repos/a/b"
        denied = Opener(urllib.error.HTTPError(url, 403, "Forbidden", {}, io.BytesIO(b"")))
        self.assertEqual(GitHubReader(None, opener=denied).get(url), (403, None))
        offline = Opener(urllib.error.URLError("down"))
        self.assertEqual(GitHubReader(None, opener=offline).get(url)[0], -1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
