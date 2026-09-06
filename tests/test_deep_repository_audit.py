# SPDX-License-Identifier: Apache-2.0
"""Offline contracts for the recursive organization/file audit."""
from __future__ import annotations

import gzip
import importlib.util
import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "census" / "deep_repository_audit.py"
SPEC = importlib.util.spec_from_file_location("szl_deep_repository_audit_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


class DeepRepositoryAuditContracts(unittest.TestCase):
    def test_git_blob_identity_matches_git_object_contract(self) -> None:
        payload = b"hello\n"
        expected = hashlib.sha1(b"blob 6\0hello\n").hexdigest()  # noqa: S324
        self.assertEqual(audit.git_blob_sha(payload), expected)

    def test_empty_workflow_window_is_unknown_not_green(self) -> None:
        self.assertEqual(
            audit.aggregate_workflow_runs([]),
            {
                "state": "UNKNOWN",
                "workflow_count": 0,
                "failing": [],
                "pending": [],
                "unknown": [],
            },
        )

    def test_sharding_is_complete_disjoint_and_deterministic(self) -> None:
        repos = [{"full_name": f"szl-holdings/repo-{index:03d}"} for index in range(23)]
        shards = [audit.select_shard(repos, index, 6) for index in range(6)]
        flattened = [row["full_name"] for shard in shards for row in shard]
        self.assertEqual(sorted(flattened), sorted(row["full_name"] for row in repos))
        self.assertEqual(len(flattened), len(set(flattened)))
        self.assertEqual(audit.select_shard(repos, 2, 6), shards[2])

    def test_archive_path_traversal_is_rejected(self) -> None:
        for name in ("/absolute/path", "../escape", "root/../escape", "root//double"):
            with self.subTest(name=name), self.assertRaises(audit.AuditError):
                audit.safe_member_path(name)

    def test_symlink_blob_is_materialized_as_target_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "repo.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                info = tarfile.TarInfo("repo-abcdef/")
                info.type = tarfile.DIRTYPE
                tf.addfile(info)

                link = tarfile.TarInfo("repo-abcdef/current")
                link.type = tarfile.SYMTYPE
                link.linkname = "releases/v1"
                tf.addfile(link)

                payload = b"ok\n"
                regular = tarfile.TarInfo("repo-abcdef/README.md")
                regular.size = len(payload)
                tf.addfile(regular, io.BytesIO(payload))

            extracted = audit.extract_archive(archive, root / "out")
            self.assertTrue((extracted / "current").is_file())
            self.assertFalse((extracted / "current").is_symlink())
            self.assertEqual((extracted / "current").read_bytes(), b"releases/v1")
            self.assertEqual((extracted / "README.md").read_bytes(), b"ok\n")

    def test_workflow_scanner_rejects_unpinned_and_ephemeral_self_mutation(self) -> None:
        findings: list[audit.Finding] = []
        workflow = b"""
name: Sync once
on: workflow_dispatch
permissions:
  contents: write
jobs:
  patch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: true
      - run: git push origin HEAD:repair
# one-shot self-removing compatibility shim
"""
        audit.scan_file(
            "szl-holdings/example",
            ".github/workflows/_repair_once.yml",
            workflow,
            classification="workflow",
            findings=findings,
            technology_hits=set(),
        )
        rules = {(finding.rule_id, finding.severity) for finding in findings}
        self.assertIn(("workflow-action-unpinned", "P1"), rules)
        self.assertIn(("ephemeral-self-mutating-workflow", "P0"), rules)

    def test_explicit_release_writer_is_review_required_not_false_p0(self) -> None:
        findings: list[audit.Finding] = []
        workflow = b"""
name: Release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: true
      - run: git push origin --tags
"""
        audit.scan_file(
            "szl-holdings/example",
            ".github/workflows/release.yml",
            workflow,
            classification="workflow",
            findings=findings,
            technology_hits=set(),
        )
        self.assertTrue(
            any(
                finding.rule_id == "repository-writing-workflow"
                and finding.severity == "P1"
                for finding in findings
            )
        )
        self.assertFalse(any(finding.severity == "P0" for finding in findings))

    def test_sitecustomize_is_never_treated_as_ordinary_source(self) -> None:
        findings: list[audit.Finding] = []
        audit.scan_file(
            "szl-holdings/example",
            "sitecustomize.py",
            b"import os\n",
            classification="source",
            findings=findings,
            technology_hits=set(),
        )
        self.assertTrue(
            any(
                finding.rule_id == "python-sitecustomize"
                and finding.severity == "P1"
                for finding in findings
            )
        )

    def test_high_confidence_secret_is_p0_in_first_party_source(self) -> None:
        findings: list[audit.Finding] = []
        audit.scan_file(
            "szl-holdings/example",
            "src/config.py",
            b'TOKEN = "github_pat_' + b"A" * 60 + b'"\n',
            classification="source",
            findings=findings,
            technology_hits=set(),
        )
        secret = next(
            finding
            for finding in findings
            if finding.rule_id == "github-fine-grained-token"
        )
        self.assertEqual(secret.severity, "P0")
        self.assertIn("github_pat_", str(secret.evidence))
        self.assertLess(len(str(secret.evidence)), 20)

    def test_grok_stall_is_indexed_without_claiming_executable_recovery(self) -> None:
        findings: list[audit.Finding] = []
        result = audit.scan_file(
            "szl-holdings/example",
            "payloads/GROK_TERMINAL.md",
            b"# Grok terminal\nState: STALLED\nThis is a payload, not runtime proof.\n",
            classification="documentation",
            findings=findings,
            technology_hits=set(),
        )
        self.assertGreater(result["grok_markers"], 0)
        self.assertGreater(result["stall_markers"], 0)
        self.assertTrue(
            any(finding.rule_id == "grok-stall-marker" for finding in findings)
        )

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.write_text(
            json.dumps(
                value,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def _write_inventory(
        path: Path, rows: list[dict[str, object]]
    ) -> tuple[str, str]:
        uncompressed = b"".join(
            json.dumps(
                row,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            + b"\n"
            for row in rows
        )
        with path.open("wb") as handle:
            with gzip.GzipFile(
                filename="", fileobj=handle, mode="wb", mtime=0
            ) as zipped:
                zipped.write(uncompressed)
        return (
            hashlib.sha256(path.read_bytes()).hexdigest(),
            hashlib.sha256(uncompressed).hexdigest(),
        )

    def test_merge_requires_every_shard_and_verifies_inventory_digests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "shards"
            output = root / "merged"
            source.mkdir()
            total = 2
            for index in range(total):
                repo = {
                    "repository": f"szl-holdings/repo-{index}",
                    "archived": False,
                    "state": "OBSERVED",
                    "revision": "a" * 40,
                    "technology_hits": (
                        ["observability.opentelemetry"] if index == 0 else []
                    ),
                    "grok_files": ["GROK.md"] if index == 1 else [],
                    "stalled_grok_files": [],
                    "grok_branch_candidates": [],
                    "open_pull_requests": [],
                    "ci": {"failing": []},
                }
                inventory_path = (
                    source / f"file-inventory-shard-{index}.ndjson.gz"
                )
                compressed, uncompressed = self._write_inventory(
                    inventory_path,
                    [{"repository": repo["repository"], "path": "README.md"}],
                )
                self._write_json(
                    source / f"repositories-shard-{index}.json", [repo]
                )
                self._write_json(
                    source / f"findings-shard-{index}.json", []
                )
                self._write_json(
                    source / f"receipt-shard-{index}.json",
                    {
                        "shard_index": index,
                        "shard_count": total,
                        "organization_repository_count": total,
                        "inventory_archive_sha256": compressed,
                        "inventory_uncompressed_sha256": uncompressed,
                        "inventory_row_count": 1,
                        "state": "OBSERVED",
                    },
                )

            args = Namespace(
                input_dir=str(source),
                output_dir=str(output),
                shard_count=total,
                org="szl-holdings",
            )
            self.assertEqual(audit.merge_shards(args), 0)
            receipt = json.loads(
                (output / "receipt.json").read_text(encoding="utf-8")
            )
            self.assertEqual(receipt["repository_count"], 2)
            self.assertEqual(receipt["file_inventory_row_count"], 2)
            self.assertEqual(receipt["grok_recovery_repository_count"], 1)

            (source / "receipt-shard-1.json").unlink()
            with self.assertRaises(audit.AuditError):
                audit.merge_shards(args)


if __name__ == "__main__":
    unittest.main()
