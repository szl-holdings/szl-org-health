# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
SECRET_EXPR = re.compile(
    r"\$\{\{.*?\bsecrets\s*(?:\.|\[).*?\}\}",
    re.IGNORECASE | re.DOTALL,
)
SECRET_INHERIT = re.compile(
    r"(?m)^\s+secrets\s*:\s*inherit\s*(?:#.*)?$",
    re.IGNORECASE,
)
TOP_LEVEL_ON = re.compile(r"""^(?:on|'on'|"on")\s*:(?P<tail>.*)$""")
EVENT = re.compile(
    r"""^ {2}(?P<key>[A-Za-z_][A-Za-z0-9_-]*|'[^']+'|"[^"]+")\s*:\s*(?:#.*)?$"""
)
CRON = re.compile(
    r"""^ {4}-\s+cron\s*:\s*(?P<q>['"])(?P<cron>[^'"]+)(?P=q)\s*(?:#.*)?$"""
)


def _uses_actions_secrets(source: str) -> bool:
    return bool(SECRET_EXPR.search(source) or SECRET_INHERIT.search(source))


def _reader_permission_pairs(source: str, job: str) -> list[tuple[str, str]]:
    """Inspect one mint step independently, without conflating the two jobs."""
    job_tail = source.split(f"\n  {job}:\n", 1)[1]
    job_source = re.split(
        r"(?m)^  [A-Za-z][A-Za-z0-9_-]*:\s*$", job_tail, maxsplit=1
    )[0]
    step = re.search(
        r"(?ms)^      - name: Mint short-lived organization reader\n"
        r"(.*?)(?=^      - name:|\Z)",
        job_source,
    )
    if step is None:
        raise AssertionError(f"{job}: organization reader mint step missing")
    return re.findall(r"(?m)^          (permission-[a-z-]+):\s*(\S+)\s*$", step[1])


def _canonical_triggers(
    source: str, name: str
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    lines = source.splitlines()
    if any("\t" in line[: len(line) - len(line.lstrip(" \t"))] for line in lines):
        raise AssertionError(f"{name}: tabs in indentation")

    found = [
        (index, match)
        for index, line in enumerate(lines)
        if line
        and not line[0].isspace()
        and (match := TOP_LEVEL_ON.fullmatch(line.rstrip()))
    ]
    if len(found) != 1:
        raise AssertionError(
            f"{name}: expected exactly one canonical top-level on block"
        )

    start, match = found[0]
    tail = match.group("tail").strip()
    if tail and not tail.startswith("#"):
        raise AssertionError(f"{name}: inline, flow, or aliased on syntax is forbidden")

    block: list[str] = []
    for line in lines[start + 1 :]:
        if line.strip() and not line[0].isspace():
            break
        block.append(line)

    events: list[str] = []
    crons: list[str] = []
    for line in block:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 2:
            event = EVENT.fullmatch(line.rstrip())
            if not event:
                raise AssertionError(f"{name}: noncanonical event line: {line!r}")
            events.append(event.group("key").strip("'\""))
        elif indent < 2:
            raise AssertionError(f"{name}: malformed on indentation")

        cron_match = CRON.fullmatch(line.rstrip())
        if cron_match:
            cron = cron_match.group("cron")
            if "${{" in cron or len(cron.split()) != 5:
                raise AssertionError(f"{name}: cron must be a fixed five-field literal")
            crons.append(cron)

    return tuple(events), tuple(crons)


class SecretWorkflowBoundaryTests(unittest.TestCase):
    def test_census_never_falls_back_to_hf_write_token(self) -> None:
        workflow = (WORKFLOWS / "scheduled-estate-census.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("HF_WRITE_TOKEN", workflow)

    def test_census_reader_has_exact_read_only_observation_permissions(self) -> None:
        workflow = (WORKFLOWS / "scheduled-estate-census.yml").read_text(
            encoding="utf-8"
        )
        pairs = _reader_permission_pairs(workflow, "census")
        expected = {
            "permission-contents": "read",
            "permission-organization-administration": "read",
            "permission-actions": "read",
            "permission-administration": "read",
            "permission-security-events": "read",
            "permission-secret-scanning-alerts": "read",
            "permission-vulnerability-alerts": "read",
        }
        self.assertEqual(dict(pairs), expected)
        self.assertEqual(len(pairs), len(expected), "duplicate permission input")

    def test_file_audit_reader_retains_exact_inventory_only_permissions(self) -> None:
        workflow = (WORKFLOWS / "scheduled-estate-census.yml").read_text(
            encoding="utf-8"
        )
        pairs = _reader_permission_pairs(workflow, "file-audit")
        expected = {
            "permission-contents": "read",
            "permission-organization-administration": "read",
        }
        self.assertEqual(dict(pairs), expected)
        self.assertEqual(len(pairs), len(expected), "duplicate permission input")

    def test_pypi_reader_has_only_inventory_contents_and_controls_permissions(self) -> None:
        workflow = (WORKFLOWS / "scheduled-estate-census.yml").read_text(encoding="utf-8")
        pairs = _reader_permission_pairs(workflow, "pypi-audit")
        expected = {
            "permission-contents": "read",
            "permission-organization-administration": "read",
            "permission-administration": "read",
        }
        self.assertEqual(dict(pairs), expected)
        self.assertEqual(len(pairs), len(expected), "duplicate permission input")

    def test_retired_one_shot_executor_is_absent(self) -> None:
        self.assertFalse((WORKFLOWS / "zz-org-convergence-20260828.yml").exists())
        self.assertFalse((REPO_ROOT / "tools" / "org_converge_20260828.py").exists())

    def test_actions_secret_workflows_are_provider_scheduled_only(self) -> None:
        secret_workflows: list[str] = []
        workflows = sorted(
            {*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")},
            key=lambda path: path.name,
        )
        for workflow in workflows:
            source = workflow.read_text(encoding="utf-8")
            if not _uses_actions_secrets(source):
                continue

            secret_workflows.append(workflow.name)
            events, crons = _canonical_triggers(source, workflow.name)
            self.assertEqual(events, ("schedule",), workflow.name)
            self.assertTrue(crons, workflow.name)
            self.assertNotIn("persist-credentials: true", source, workflow.name)
            self.assertIn("persist-credentials: false", source, workflow.name)
            self.assertIn(r"ref: ${{ github.sha }}", source, workflow.name)
            self.assertIn(
                "github.event.repository.default_branch",
                source,
                workflow.name,
            )

        self.assertEqual(
            secret_workflows,
            ["autonomic-sre.yml", "scheduled-estate-census.yml"],
        )

    def test_scheduled_census_validates_each_reader_before_use(self) -> None:
        workflow = (WORKFLOWS / "scheduled-estate-census.yml").read_text(
            encoding="utf-8"
        )
        events, crons = _canonical_triggers(workflow, "scheduled-estate-census.yml")

        self.assertEqual(events, ("schedule",))
        self.assertEqual(crons, ("17 */6 * * *",))
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertEqual(
            workflow.count("python -B -m tools.run_with_validated_github_reader"),
            3,
        )
        self.assertEqual(
            workflow.count("permission-organization-administration: read"),
            3,
        )
        self.assertEqual(
            workflow.count("if: vars.QILLQAQ_CLIENT_ID != ''"),
            3,
        )
        self.assertNotIn(
            "GITHUB_TOKEN: ${{ steps.org-reader.outputs.token ||",
            workflow,
        )
        self.assertGreaterEqual(
            workflow.count("--minimum-repositories 123"),
            3,
        )

        aliases = (
            "SZL_GITHUB_TOKEN",
            "DOCS_AUTOMATION_TEAM_READ_TOKEN",
            "ORG_REPO_WORKFLOW_TOKEN",
            "SZL_ORG_PAT",
            "SZL_GITHUB_PAT",
            "GH_PAT",
            "PAT_TOKEN",
            "GITHUB_PAT",
            "GH_TOKEN",
        )
        for alias in aliases:
            self.assertIn(f"secrets.{alias}", workflow)

        self.assertIn("REPOSITORY_GITHUB_TOKEN: ${{ github.token }}", workflow)
        self.assertIn(
            "EXPECTED_GITHUB_REPOSITORIES_MINIMUM: \"63\"",
            workflow,
        )
        self.assertIn(
            "tests.test_validated_github_reader",
            workflow,
        )
        self.assertIn(
            "tests.test_repository_hygiene",
            workflow,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
