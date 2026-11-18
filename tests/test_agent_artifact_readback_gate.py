# SPDX-License-Identifier: Apache-2.0
"""Fail-closed contract tests for an intentionally read-only gate."""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import agent_artifact_readback_gate as gate


class AgentArtifactReadbackGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base / "source"
        self.copy = self.base / "copy"
        self.source.mkdir()
        self.copy.mkdir()
        self.payload = b"ledger-event\n\x00record\n"
        self.rel = "khipu/operator/ledger.ndjson"
        for root in (self.source, self.copy):
            path = root / self.rel
            path.parent.mkdir(parents=True)
            path.write_bytes(self.payload)
        self.manifest = {
            "schema": gate.SCHEMA,
            "artifacts": [{
                "relative_path": self.rel, "copy_relative_path": self.rel,
                "sha256": hashlib.sha256(self.payload).hexdigest(),
                "size_bytes": len(self.payload),
                "owner": "szl-holdings/energy", "evidence_id": "receipt:abc",
            }],
        }

    def evaluate(self, **kwargs):
        return gate.evaluate(self.manifest, self.source, self.copy, **kwargs)

    def assert_hold(self, expected: str) -> None:
        result = self.evaluate()
        self.assertEqual(result["status"], "HOLD", result)
        self.assertFalse(result["deletion_authorized"])
        codes = [row.get("code") for row in result["rows"]]
        if "error_code" in result:
            codes.append(result["error_code"])
        self.assertIn(expected, codes)

    def test_matched_copy_is_not_cleanup_authorization(self):
        result = self.evaluate()
        self.assertEqual(result["status"], "READBACK_VERIFIED_NOT_RELEASED")
        self.assertEqual(result["copy_verified"], 1)
        self.assertFalse(result["deletion_authorized"])
        self.assertIn("SIGNATURE_UNVERIFIED", result["limitations"])

    def test_all_bytes_and_files_remain_unchanged(self):
        before = (self.source / self.rel).read_bytes()
        result = self.evaluate()
        self.assertEqual(result["copy_verified"], 1)
        self.assertEqual((self.source / self.rel).read_bytes(), before)
        self.assertEqual((self.copy / self.rel).read_bytes(), before)

    def test_missing_copy_is_hold(self):
        (self.copy / self.rel).unlink()
        self.assert_hold("PATH_UNAVAILABLE")

    def test_mismatched_copy_is_hold(self):
        (self.copy / self.rel).write_bytes(b"different but also ledger")
        self.assert_hold("SIZE_MISMATCH")

    def test_same_size_mismatched_hash_is_hold(self):
        (self.copy / self.rel).write_bytes(b"Z" * len(self.payload))
        self.assert_hold("DIGEST_MISMATCH")

    def test_wrong_expected_hash_is_hold(self):
        self.manifest["artifacts"][0]["sha256"] = "0" * 64
        self.assert_hold("DIGEST_MISMATCH")

    def test_wrong_declared_length_is_hold(self):
        self.manifest["artifacts"][0]["size_bytes"] += 1
        self.assert_hold("SIZE_MISMATCH")

    def test_path_traversal_is_hold(self):
        self.manifest["artifacts"][0]["relative_path"] = "../credentials"
        self.assert_hold("INVALID_RELATIVE_PATH")

    def test_windows_backslash_is_hold(self):
        self.manifest["artifacts"][0]["relative_path"] = "khipu\\..\\token"
        self.assert_hold("INVALID_RELATIVE_PATH")

    def test_absolute_windows_drive_is_hold(self):
        self.manifest["artifacts"][0]["copy_relative_path"] = "C:/users/root/data"
        self.assert_hold("INVALID_RELATIVE_PATH")

    def test_protected_cache_is_hold(self):
        self.manifest["artifacts"][0]["relative_path"] = "OneDrive/sample"
        self.assert_hold("PROTECTED_PATH")

    def test_protected_git_is_hold(self):
        self.manifest["artifacts"][0]["relative_path"] = ".git/config"
        self.assert_hold("PROTECTED_PATH")

    def test_duplicate_paths_case_insensitive_are_hold(self):
        duplicate = dict(self.manifest["artifacts"][0])
        duplicate["relative_path"] = duplicate["relative_path"].upper()
        self.manifest["artifacts"].append(duplicate)
        self.assert_hold("DUPLICATE_ARTIFACT_PATH")

    def test_missing_owner_is_hold(self):
        self.manifest["artifacts"][0]["owner"] = ""
        self.assert_hold("OWNERSHIP_UNDECLARED")

    def test_missing_evidence_ref_is_hold(self):
        self.manifest["artifacts"][0]["evidence_id"] = ""
        self.assert_hold("EVIDENCE_ID_MISSING")

    def test_unverified_size_type_is_hold(self):
        self.manifest["artifacts"][0]["size_bytes"] = True
        self.assert_hold("INVALID_SIZE")

    def test_budget_boundary_is_hold(self):
        self.assert_hold_budget(2)

    def assert_hold_budget(self, budget):
        result = self.evaluate(read_budget=budget)
        self.assertEqual(result["status"], "HOLD")
        self.assertEqual(result["rows"][0]["code"], "BUDGET_EXHAUSTED")

    def test_empty_manifest_is_hold(self):
        self.manifest["artifacts"] = []
        self.assert_hold("INVALID_ARTIFACT_COUNT")

    def test_schema_mismatch_is_hold(self):
        self.manifest["schema"] = "fake"
        self.assert_hold("SCHEMA_MISMATCH")

    def test_nested_roots_are_hold(self):
        self.assertEqual(
            gate.evaluate(self.manifest, self.source, self.source)["error_code"],
            "ROOTS_NOT_SEPARATE",
        )

    def test_symlinked_copy_is_hold(self):
        victim = self.copy / self.rel
        victim.unlink()
        try:
            os.symlink(self.source / self.rel, victim)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable under this user's privileges")
        self.assert_hold("REPARSE_OR_SYMLINK")

    def test_hardlinked_copy_is_hold(self):
        victim = self.copy / self.rel
        victim.unlink()
        try:
            os.link(self.source / self.rel, victim)
        except (OSError, NotImplementedError):
            self.skipTest("hardlinks unavailable under this user's privileges")
        self.assert_hold("SAME_INODE_NOT_COPY")

    def test_report_defaults_to_private_identifiers(self):
        result = self.evaluate()
        rendered = json.dumps(result)
        self.assertNotIn(str(self.base), rendered)
        self.assertNotIn("khipu/operator/ledger.ndjson", rendered)
        self.assertNotIn("szl-holdings/energy", rendered)

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaises(gate.GateError) as ctx:
            gate._read_json_unique(b'{"schema":"good","schema":"bad"}')
        self.assertEqual(ctx.exception.code, "DUPLICATE_JSON_KEY")

    def test_unexpected_binary_json_is_hold(self):
        with self.assertRaises(gate.GateError) as ctx:
            gate._read_json_unique(b"\xff")
        self.assertEqual(ctx.exception.code, "INVALID_MANIFEST_JSON")

    def test_cli_json_result_and_exit_code(self):
        manifest_path = self.base / "manifest.json"
        manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        output = io.StringIO()
        with redirect_stdout(output):
            code = gate.main([
                "--manifest", str(manifest_path),
                "--source-root", str(self.source),
                "--copy-root", str(self.copy),
            ])
        self.assertEqual(code, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["status"], "READBACK_VERIFIED_NOT_RELEASED")
        self.assertFalse(payload["deletion_authorized"])
        self.assertEqual(payload["input_sha256"],
                         hashlib.sha256(manifest_path.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main(verbosity=2)