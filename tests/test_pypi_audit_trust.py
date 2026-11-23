"""Execute the scheduled PyPI reader guard across trusted and untrusted contexts."""

from __future__ import annotations

import os
import re
import textwrap
from pathlib import Path
from unittest import TestCase, main, mock

from tests.test_secret_workflow_boundary import (
    _canonical_triggers,
    _reader_permission_pairs,
    _uses_actions_secrets,
)


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github/workflows"
WORKFLOW_PATH = WORKFLOWS / "scheduled-pypi-release-audit.yml"
SHA = "a" * 40


class PyPIAuditTrustTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.job = cls.workflow.split("\n  pypi-audit:\n", 1)[1]
        match = re.search(
            r"      - name: Validate provider-scheduled PyPI audit source\n(.*?)\n      - name:",
            cls.job, re.DOTALL,
        )
        if match is None:
            raise AssertionError("workflow source guard is missing")
        cls.guard_block = match.group(1)
        cls.guard = compile(
            textwrap.dedent(cls.guard_block.split("        run: |\n", 1)[1]),
            str(WORKFLOW_PATH), "exec",
        )

    def run_guard(self, event, ref, *, default_branch="main", head=SHA, expected_sha=SHA):
        environ = {
            "GITHUB_EVENT_NAME": event,
            "GITHUB_REF": ref,
            "AUDIT_DEFAULT_BRANCH": default_branch,
            "GITHUB_SHA": expected_sha,
        }
        error = None
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch("subprocess.check_output", return_value=head + "\n") as git:
            try:
                exec(self.guard, {"__name__": "__main__"})
            except SystemExit as exc:
                error = str(exc)
        return error, git

    def test_actual_guard_allows_only_provider_schedule_on_exact_default_branch(self):
        for event in (
            "push", "schedule", "workflow_dispatch", "pull_request",
            "pull_request_target", "workflow_run", "repository_dispatch", "unknown",
        ):
            for ref in (
                "refs/heads/main", "refs/heads/topic", "refs/pull/123/merge",
                "refs/tags/main", "refs/heads/main-suffix",
            ):
                with self.subTest(event=event, ref=ref):
                    error, git = self.run_guard(event, ref)
                    allowed = event == "schedule" and ref == "refs/heads/main"
                    if allowed:
                        self.assertIsNone(error)
                        git.assert_called_once_with(["git", "rev-parse", "HEAD"], text=True)
                    else:
                        self.assertIsNotNone(error)
                        git.assert_not_called()

    def test_default_branch_comes_from_repository_context(self):
        error, _ = self.run_guard("schedule", "refs/heads/release", default_branch="release")
        self.assertIsNone(error)
        error, git = self.run_guard("schedule", "refs/heads/main", default_branch="release")
        self.assertEqual(error, "PyPI reader requires the repository default branch")
        git.assert_not_called()

    def test_mismatched_checkout_stops_before_credential_selection(self):
        error, _ = self.run_guard("schedule", "refs/heads/main", head="b" * 40)
        self.assertEqual(error, "audit checkout does not match exact workflow source")

    def test_credentials_remain_in_named_schedule_only_workflow(self):
        self.assertEqual(
            _canonical_triggers(self.workflow, WORKFLOW_PATH.name),
            (("schedule",), ("29 */6 * * *",)),
        )
        unprivileged = (WORKFLOWS / "pypi-release-path-audit.yml").read_text(encoding="utf-8")
        self.assertFalse(_uses_actions_secrets(unprivileged))
        self.assertIn("GITHUB_TOKEN: " + "$" + "{{ github.token }}", unprivileged)
        self.assertIn(
            "if: github.event_name == 'schedule' && github.ref == "
            "format('refs/heads/{0}', github.event.repository.default_branch)",
            self.job,
        )
        self.assertIn("ref: " + "$" + "{{ github.sha }}", self.job)
        self.assertIn("persist-credentials: false", self.job)
        self.assertLess(
            self.job.index("- name: Validate provider-scheduled PyPI audit source"),
            self.job.index("secrets."),
        )

    def test_scheduled_reader_uses_pinned_live_verifier(self):
        self.assertIn(
            'python -m pip install --quiet "sigstore==4.5.1" "pypi-attestations==0.0.31"',
            self.job,
        )
        audit_step = self.job.split("- name: Audit live GitHub and PyPI state", 1)[1]
        self.assertIn("python -B tools/pypi_release_path_audit.py --verify-attestations", audit_step)
        self.assertIn("tests.test_pypi_distribution_verification", self.job)
        self.assertIn("tests.test_pypi_sigstore_verify", self.job)

    def test_reader_permissions_and_aliases_are_existing_read_only_subset(self):
        census_workflow = (WORKFLOWS / "scheduled-estate-census.yml").read_text(encoding="utf-8")
        census = dict(_reader_permission_pairs(census_workflow, "census"))
        pypi = dict(_reader_permission_pairs(self.workflow, "pypi-audit"))
        self.assertEqual(pypi, {
            "permission-contents": "read",
            "permission-organization-administration": "read",
            "permission-administration": "read",
        })
        self.assertLessEqual(pypi.items(), census.items())
        census_job = census_workflow.split("\n  census:\n", 1)[1].split("\n  file-audit:\n", 1)[0]
        existing_secrets = set(re.findall(r"\bsecrets\.([A-Z_0-9]+)", census_job))
        pypi_secrets = set(re.findall(r"\bsecrets\.([A-Z_0-9]+)", self.job))
        # PyPI audit intentionally keeps its own explicit reader aliases.
        # Census collection no longer carries these legacy aliases.
        self.assertEqual(
            pypi_secrets,
            {
                "DOCS_AUTOMATION_TEAM_READ_TOKEN",
                "GH_PAT",
                "GH_TOKEN",
                "GITHUB_PAT",
                "ORG_REPO_WORKFLOW_TOKEN",
                "PAT_TOKEN",
                "SZL_GITHUB_PAT",
                "SZL_GITHUB_TOKEN",
                "SZL_ORG_PAT",
            },
        )
        self.assertIn("python -B -m tools.run_with_validated_github_reader", self.job)
        self.assertIn("--minimum-repositories 123", self.job)
        self.assertIn("python -B tools/pypi_release_path_audit.py", self.job)
        audit_step = self.job.split("- name: Audit live GitHub and PyPI state", 1)[1]
        self.assertNotIn("continue-on-error:", audit_step)
        self.assertNotIn("secrets.", self.guard_block)


if __name__ == "__main__":
    main()
