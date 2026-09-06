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
EXPECTED_SECRET_WORKFLOWS = {
    "autonomic-sre.yml": ("schedule",),
    "operator-deep-repository-audit.yml": ("workflow_dispatch",),
    "scheduled-estate-census.yml": ("schedule",),
}


def _uses_actions_secrets(source: str) -> bool:
    return bool(SECRET_EXPR.search(source) or SECRET_INHERIT.search(source))


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
    def test_retired_one_shot_executor_is_absent(self) -> None:
        self.assertFalse((WORKFLOWS / "zz-org-convergence-20260828.yml").exists())
        self.assertFalse((REPO_ROOT / "tools" / "org_converge_20260828.py").exists())

    def test_actions_secret_workflows_have_exact_bounded_triggers(self) -> None:
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
            self.assertIn(workflow.name, EXPECTED_SECRET_WORKFLOWS)
            events, crons = _canonical_triggers(source, workflow.name)
            self.assertEqual(
                events,
                EXPECTED_SECRET_WORKFLOWS[workflow.name],
                workflow.name,
            )
            self.assertNotIn("persist-credentials: true", source, workflow.name)
            self.assertIn("persist-credentials: false", source, workflow.name)
            self.assertIn(r"ref: ${{ github.sha }}", source, workflow.name)
            self.assertIn(
                "github.event.repository.default_branch",
                source,
                workflow.name,
            )

            if events == ("schedule",):
                self.assertTrue(crons, workflow.name)
                self.assertNotIn("workflow_dispatch", source, workflow.name)
            elif events == ("workflow_dispatch",):
                self.assertEqual(crons, (), workflow.name)
                self.assertEqual(workflow.name, "operator-deep-repository-audit.yml")
                self.assertIn(
                    'test "$REQUEST_ACTOR" = "stephenlutar2-hash"',
                    source,
                    workflow.name,
                )
                self.assertIn(
                    'test "$GITHUB_REF" = "refs/heads/$DEFAULT_BRANCH"',
                    source,
                    workflow.name,
                )
                self.assertIn("permissions:\n  actions: read\n  contents: read", source)
                self.assertNotRegex(source, r"(?m)^\s+(?:contents|pull-requests):\s+write\s*$")
            else:  # pragma: no cover - expected map makes this unreachable
                self.fail(f"{workflow.name}: unhandled secret trigger contract")

        self.assertEqual(secret_workflows, sorted(EXPECTED_SECRET_WORKFLOWS))


if __name__ == "__main__":
    unittest.main(verbosity=2)
