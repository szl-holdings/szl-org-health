# SPDX-License-Identifier: Apache-2.0
"""Offline text contract for the braid-turn workflow and its hash-locked requirements.

Nothing here runs a workflow, contacts GitHub or installs a package. It reads
the checked-in files as text and holds them to the boundaries the workflow
header promises: read-only, no repository secret, pinned actions, and an
attestation job that runs no repository code.
"""
import json
from pathlib import Path
import re
from unittest import TestCase, main as unittest_main

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ouroboros-braid-turn.yml"
POLICY = ROOT / "governance/database_contracts/ouroboros_braid_v2.json"
LOCK = ROOT / "requirements-braid.lock"
USES = re.compile(r"^\s*(?:- )?uses:\s*(\S+)", re.M)
PINNED = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}\Z")


def job(text, name):
    """The text of one top-level job block."""
    start = text.index(f"\n  {name}:\n")
    following = re.search(r"\n  [a-z][a-z0-9_-]*:\n", text[start + 1:])
    return text[start:start + 1 + following.start()] if following else text[start:]


class BraidTurnWorkflowContract(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.turn = job(cls.text, "turn")
        cls.attest = job(cls.text, "attest")
        cls.policy = json.loads(POLICY.read_text(encoding="utf-8"))

    def test_uses_no_repository_secret_and_no_privileged_trigger(self):
        self.assertNotIn("secrets.", self.text)
        self.assertNotIn("pull_request_target", self.text)
        self.assertNotIn("write-all", self.text)

    def test_triggers_are_a_fixed_schedule_and_manual_dispatch_only(self):
        header = self.text[:self.text.index("\npermissions:")]
        self.assertIn('    - cron: "17 5 * * 1"', header)
        self.assertIn("  workflow_dispatch:", header)
        self.assertNotRegex(header, r"\n  (push|pull_request):")

    def test_default_permissions_are_empty_and_jobs_grant_the_minimum(self):
        self.assertIn("\npermissions: {}\n", self.text)
        granted = re.findall(r"^      ([a-z-]+): (read|write)$", self.turn, re.M)
        self.assertEqual(sorted(granted), [("actions", "read"), ("contents", "read")])
        granted = re.findall(r"^      ([a-z-]+): (read|write)$", self.attest, re.M)
        self.assertEqual(sorted(granted), [("attestations", "write"), ("contents", "read"),
                                           ("id-token", "write")])
        self.assertNotIn("id-token", self.turn)

    def test_every_action_is_pinned_to_a_full_commit(self):
        found = USES.findall(self.text)
        self.assertGreater(len(found), 10)
        for reference in found:
            self.assertRegex(reference, PINNED)

    def test_every_checkout_drops_its_credentials(self):
        checkouts = self.text.count("uses: actions/checkout@")
        self.assertEqual(self.text.count("persist-credentials: false"), checkouts)
        self.assertGreaterEqual(checkouts, 12)

    def test_attestation_job_is_opt_in_and_runs_no_repository_code(self):
        self.assertIn("if: ${{ vars.BRAID_ATTEST_PROVIDER == 'github' }}", self.attest)
        self.assertIn("needs: turn", self.attest)
        self.assertNotIn("actions/checkout@", self.attest)
        self.assertNotRegex(self.attest, r"^\s*run:", )
        self.assertNotIn("python", self.attest)

    def test_turn_job_checks_out_every_repository_the_policy_censuses(self):
        named = set(re.findall(r'--checkout "(szl-holdings/[A-Za-z0-9_.-]+)=', self.turn))
        wanted = {r["repository"] for r in self.policy["census"]["repositories"]}
        self.assertEqual(named, wanted)

    def test_turn_job_uses_the_checked_in_contracts(self):
        for relative in ("governance/database_contracts/ouroboros_braid_v2.json",
                         "governance/database_contracts/braid_family_map_v1.json",
                         "governance/database_contracts/braid_codex_known_answers_v1.json",
                         "tools/database_braid_turn.py", "requirements-braid.lock"):
            self.assertIn("braid/" + relative, self.turn)
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_installer_is_checked_before_it_runs_and_never_piped_to_a_shell(self):
        download = self.turn.index("curl -sSfL")
        check = self.turn.index("sha256sum -c")
        execute = self.turn.index('"$RUNNER_TEMP/elan-init/elan-init" -y')
        self.assertLess(download, check)
        self.assertLess(check, execute)
        self.assertNotRegex(self.text, r"curl[^\n]*\|\s*(ba)?sh")

    def test_dependencies_come_from_the_cache_and_the_manifest_is_not_rewritten(self):
        self.assertIn("lake exe cache get", self.turn)
        self.assertNotIn("lake update", self.text)
        self.assertEqual(self.turn.count("git diff --exit-code HEAD -- lake-manifest.json"), 2)

    def test_previous_turn_is_only_ever_read_from_this_workflow_on_the_default_branch(self):
        self.assertIn("--workflow ouroboros-braid-turn.yml", self.turn)
        self.assertIn("--branch main --status success --limit 1", self.turn)
        self.assertIn("GH_TOKEN: ${{ github.token }}", self.turn)

    def test_locked_requirements_are_hash_pinned_and_match_the_policy(self):
        text = LOCK.read_text(encoding="utf-8")
        entries = re.split(r"\n(?=[A-Za-z0-9_.\[\]-]+==)", text)
        packages = [e for e in entries if re.match(r"[A-Za-z0-9_.\[\]-]+==", e)]
        self.assertGreater(len(packages), 5)
        for entry in packages:
            self.assertIn("--hash=sha256:", entry, entry.splitlines()[0])
        version = self.policy["lake"]["receipt_library"]["version"]
        self.assertIn(f"\nszl-receipt-dsse=={version} \\\n", "\n" + text)
        self.assertIn("--require-hashes", self.turn)
        self.assertIn("--only-binary=:all:", self.turn)


if __name__ == "__main__":
    unittest_main()
