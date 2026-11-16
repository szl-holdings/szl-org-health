"""Execute the real workflow guard across trusted and untrusted contexts."""

from __future__ import annotations

import os
import re
import tempfile
import textwrap
from pathlib import Path
from unittest import TestCase, main, mock


WORKFLOW_PATH = Path(__file__).resolve().parents[1] / ".github/workflows/pypi-release-path-audit.yml"
SHA = "a" * 40


class PyPIAuditTrustTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        match = re.search(
            r"      - name: Validate default-branch audit source\n(.*?)\n      - name:",
            cls.workflow, re.DOTALL,
        )
        if match is None:
            raise AssertionError("workflow source guard is missing")
        cls.guard_block = match.group(1)
        cls.guard = compile(
            textwrap.dedent(cls.guard_block.split("        run: |\n", 1)[1]),
            str(WORKFLOW_PATH), "exec",
        )

    def run_guard(self, event, ref, *, default_branch="main", head=SHA, expected_sha=SHA):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "step-output.txt"
            environ = {
                "GITHUB_EVENT_NAME": event,
                "GITHUB_REF": ref,
                "AUDIT_DEFAULT_BRANCH": default_branch,
                "GITHUB_SHA": expected_sha,
                "GITHUB_OUTPUT": str(output),
            }
            error = None
            with mock.patch.dict(os.environ, environ, clear=True), \
                    mock.patch("subprocess.check_output", return_value=head + "\n") as git:
                try:
                    exec(self.guard, {"__name__": "__main__"})
                except SystemExit as exc:
                    error = str(exc)
            return output.read_text() if output.exists() else "", error, git

    def test_actual_guard_allows_only_three_events_on_exact_default_branch(self):
        for event in (
            "push", "schedule", "workflow_dispatch", "pull_request",
            "pull_request_target", "workflow_run", "repository_dispatch", "unknown",
        ):
            for ref in (
                "refs/heads/main", "refs/heads/topic", "refs/pull/123/merge",
                "refs/tags/main", "refs/heads/main-suffix",
            ):
                with self.subTest(event=event, ref=ref):
                    output, error, git = self.run_guard(event, ref)
                    allowed = event in ("push", "schedule", "workflow_dispatch") and ref == "refs/heads/main"
                    self.assertIsNone(error)
                    self.assertEqual(output, "trusted=true\n" if allowed else "")
                    if allowed:
                        git.assert_called_once_with(["git", "rev-parse", "HEAD"], text=True)
                    else:
                        git.assert_not_called()

    def test_default_branch_comes_from_repository_context(self):
        output, error, _ = self.run_guard("push", "refs/heads/release", default_branch="release")
        self.assertIsNone(error)
        self.assertEqual(output, "trusted=true\n")
        output, error, git = self.run_guard("push", "refs/heads/main", default_branch="release")
        self.assertIsNone(error)
        self.assertEqual(output, "")
        git.assert_not_called()

    def test_mismatched_checkout_stops_before_credential_selection(self):
        for event in ("push", "schedule", "workflow_dispatch"):
            with self.subTest(event=event):
                output, error, _ = self.run_guard(event, "refs/heads/main", head="b" * 40)
                self.assertEqual(output, "")
                self.assertEqual(error, "audit checkout does not match exact workflow source")

    def test_credential_expression_requires_event_ref_and_successful_guard(self):
        match = re.search(r"          GITHUB_TOKEN: >-\n(.*?)\n        run:", self.workflow, re.DOTALL)
        self.assertIsNotNone(match)
        expression = " ".join(match.group(1).split())
        self.assertEqual(expression, (
            "${{ contains(fromJSON('[\"push\",\"schedule\",\"workflow_dispatch\"]'), github.event_name) "
            "&& github.ref == format('refs/heads/{0}', github.event.repository.default_branch) "
            "&& steps.audit-source.outputs.trusted == 'true' "
            "&& secrets.SZL_GITHUB_TOKEN || github.token }}"
        ))
        self.assertIn("        id: audit-source", self.guard_block)
        self.assertIn("        shell: python", self.guard_block)
        self.assertNotIn("secrets.", self.guard_block)
        self.assertEqual(self.workflow.count("secrets.SZL_GITHUB_TOKEN"), 1)
        self.assertIn("    permissions:\n      contents: read\n", self.workflow)
        self.assertNotIn("continue-on-error:", self.workflow)
        self.assertLess(
            self.workflow.index("- name: Validate default-branch audit source"),
            self.workflow.index("secrets.SZL_GITHUB_TOKEN"),
        )


if __name__ == "__main__":
    main()
