#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline contracts for the braid v2 turn runner (tools/database_braid_turn.py).

Runs the runner on a synthetic estate with only the stages that need no Lean,
no Hatun and no receipt library: census and known answers. Checks the staged
output, the refusal directory, the output-location rules and the chained fixed
point, and that every closed turn was re-verified and replayed from its files.
"""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
from unittest import TestCase, main as unittest_main

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_database_ouroboros_braid_v2 import (  # noqa: E402
    HATUN_REPO, LAKE_REPO, LEAN_REPO, answer_set, make_estate, test_policy,
)
from tools import database_braid_turn as runner  # noqa: E402
from tools import database_ouroboros_braid_v2 as braid  # noqa: E402


class TurnRunnerTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.checkouts = make_estate(base / "src")
        self.policy = base / "policy.json"
        self.policy.write_text(json.dumps(test_policy(), indent=2) + "\n")
        self.answers = base / "answers.json"
        self.answers.write_text(json.dumps(answer_set(self.checkouts), indent=2) + "\n")
        self.base = base

    def tearDown(self):
        self.tmp.cleanup()

    def run_turn(self, out, *extra):
        argv = ["--policy", str(self.policy), "--answers", str(self.answers),
                "--out-dir", str(out), *extra]
        for repository, directory in self.checkouts.items():
            argv += ["--checkout", f"{repository}={directory}"]
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = runner.main(argv)
        return code, json.loads(buffer.getvalue().strip().splitlines()[-1])

    def test_closed_turn_is_staged_verified_and_replayed(self):
        out = self.base / "turn-1"
        code, manifest = self.run_turn(out)
        self.assertEqual(code, 0)
        self.assertEqual(manifest["schema"], runner.SCHEMA)
        self.assertIs(manifest["verified_from_written_files"], True)
        self.assertIs(manifest["replayed_byte_identical"], True)
        self.assertEqual(manifest["evidence_produced_in_invocation"],
                         ["census", "known_answers"])
        self.assertEqual(manifest["stages"]["known_answers"], "1/2")
        self.assertEqual(manifest["stages"]["lean_witness"], "NOT_RUN")
        self.assertEqual(sorted(p.name for p in out.iterdir()), [
            "census.json", "khipu_tree.json", "known_answers.json", "manifest.json",
            "turn.json"])
        self.assertFalse((self.base / "turn-1.staging").exists())
        self.assertFalse((self.base / "turn-1.refused").exists())
        turn = json.loads((out / "turn.json").read_text())
        self.assertEqual(turn["census"]["label"], "MEASURED")
        self.assertEqual(turn["known_answers"]["label"], "MEASURED")
        self.assertIn("LEAN_WITNESS_NOT_SUPPLIED", turn["decision"]["sub_reasons"])
        self.assertIs(manifest["signed"], False)
        self.assertIs(manifest["production_authorized"], False)

    def test_existing_empty_directory_is_accepted(self):
        out = self.base / "empty"
        out.mkdir()
        code, _ = self.run_turn(out)
        self.assertEqual(code, 0)
        self.assertTrue((out / "turn.json").is_file())

    def test_chained_turn_with_unchanged_evidence_reaches_the_fixed_point(self):
        first, second = self.base / "turn-1", self.base / "turn-2"
        self.assertEqual(self.run_turn(first)[0], 0)
        code, manifest = self.run_turn(second, "--previous-dir", str(first))
        self.assertEqual(code, 0)
        self.assertEqual(manifest["ordinal"], 2)
        turn_1 = json.loads((first / "turn.json").read_text())
        turn_2 = json.loads((second / "turn.json").read_text())
        self.assertNotEqual(turn_1["inputs"]["census"], turn_2["inputs"]["census"])
        self.assertIs(turn_2["ouroboros_fixed_point"], True)
        self.assertEqual(turn_2["previous_turn_id"], turn_1["turn_id"])
        self.assertEqual(turn_2["previous_turn_lake_receipt"], "NOT_SUPPLIED")

    def test_output_inside_a_checkout_is_refused_and_nothing_is_written(self):
        for out in (self.checkouts[LEAN_REPO] / "out", ROOT / "braid-out-never"):
            code, result = self.run_turn(out)
            self.assertEqual((code, result["code"]), (3, "TURN_OUTPUT_DIRECTORY_DENIED"))
            self.assertFalse(out.exists())
            self.assertFalse(out.with_name(out.name + ".staging").exists())

    def test_non_empty_output_directory_is_refused(self):
        out = self.base / "busy"
        out.mkdir()
        (out / "keep.txt").write_text("x")
        code, result = self.run_turn(out)
        self.assertEqual((code, result["code"]), (3, "TURN_OUTPUT_DIRECTORY_DENIED"))
        self.assertEqual([p.name for p in out.iterdir()], ["keep.txt"])

    def test_refused_attempt_leaves_no_turn_and_a_refusal_record(self):
        out = self.base / "turn-x"
        missing = self.base / "no-such-previous"
        missing.mkdir()
        code, result = self.run_turn(out, "--previous-dir", str(missing))
        self.assertEqual(code, 3)
        self.assertFalse(out.exists())
        refused = self.base / "turn-x.refused"
        record = json.loads((refused / "REFUSED.json").read_text())
        self.assertEqual(record["state"], "REFUSED")
        self.assertEqual(record["code"], result["code"])
        self.assertIs(record["is_a_turn"], False)
        self.assertTrue((refused / "census.json").is_file())
        self.assertFalse((refused / "turn.json").exists())
        code, again = self.run_turn(out)
        self.assertEqual((code, again["code"]), (3, "TURN_OUTPUT_DIRECTORY_DENIED"))

    def test_checkout_argument_must_name_a_repository_once(self):
        out = self.base / "dup"
        code, result = self.run_turn(out, "--checkout", f"{HATUN_REPO}={self.base}")
        self.assertEqual((code, result["code"]), (3, "TURN_CHECKOUT_ARGUMENT_INVALID"))
        code, result = self.run_turn(out, "--checkout", "not a repository")
        self.assertEqual((code, result["code"]), (3, "TURN_CHECKOUT_ARGUMENT_INVALID"))

    def test_relative_toolchain_path_refused(self):
        code, result = self.run_turn(self.base / "rel", "--toolchain-bin", "relative/bin")
        self.assertEqual((code, result["code"]), (3, "TURN_TOOLCHAIN_PATH_INVALID"))

    def test_runner_and_orchestrator_exit_codes_are_documented(self):
        self.assertIn("returns 2 for the same outcome", runner.__doc__)
        self.assertIn("2 for a closed turn", braid.__doc__)
        self.assertEqual(sorted({LAKE_REPO, LEAN_REPO, HATUN_REPO}),
                         [r["repository"] for r in test_policy()["census"]["repositories"]])


if __name__ == "__main__":
    unittest_main()
