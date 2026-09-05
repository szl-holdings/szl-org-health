# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import io
import tarfile
import unittest
from unittest.mock import patch

from census import file_audit as audit


def git_blob_sha1(payload: bytes) -> str:
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"blob {len(payload)}\0".encode("ascii"))
    digest.update(payload)
    return digest.hexdigest()


def archive_bytes(
    files: dict[str, bytes],
    *,
    symlinks: dict[str, str] | None = None,
    prefix: str = "szl-holdings-fixture-deadbeef",
) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        root = tarfile.TarInfo(prefix + "/")
        root.type = tarfile.DIRTYPE
        bundle.addfile(root)
        directories: set[str] = set()
        for path in [*files, *(symlinks or {})]:
            parts = path.split("/")[:-1]
            for index in range(1, len(parts) + 1):
                directories.add("/".join(parts[:index]))
        for directory in sorted(directories):
            member = tarfile.TarInfo(f"{prefix}/{directory}/")
            member.type = tarfile.DIRTYPE
            bundle.addfile(member)
        for path, payload in sorted(files.items()):
            member = tarfile.TarInfo(f"{prefix}/{path}")
            member.size = len(payload)
            member.mode = 0o644
            bundle.addfile(member, io.BytesIO(payload))
        for path, target in sorted((symlinks or {}).items()):
            member = tarfile.TarInfo(f"{prefix}/{path}")
            member.type = tarfile.SYMTYPE
            member.linkname = target
            member.mode = 0o777
            bundle.addfile(member)
    return buffer.getvalue()


def tree_entry(path: str, payload: bytes, mode: str = "100644") -> dict[str, object]:
    return {
        "path": path,
        "type": "blob",
        "mode": mode,
        "size": len(payload),
        "sha": git_blob_sha1(payload),
    }


class FileAuditTests(unittest.TestCase):
    def test_archive_verifies_every_blob_and_separates_source_inspection(self) -> None:
        workflow = b"name: CI\nsteps:\n  - uses: actions/checkout@v4\n"
        dockerfile = b"FROM python:3.12-slim\n"
        source = b"# SPDX-License-Identifier: Apache-2.0\nprint('ok')\n"
        target = "src/app.py"
        files = {
            ".github/workflows/ci.yml": workflow,
            "Dockerfile": dockerfile,
            "src/app.py": source,
        }
        tree = [tree_entry(path, body) for path, body in files.items()]
        tree.append(tree_entry("app-link", target.encode(), mode="120000"))

        records, findings, roles, archive_sha = audit._archive_file_records(
            "szl-holdings/fixture",
            "public",
            archive_bytes(files, symlinks={"app-link": target}),
            tree,
            max_text_bytes=1024,
            max_repository_bytes=1024 * 1024,
        )

        self.assertEqual({row["path"] for row in records}, {*files, "app-link"})
        self.assertEqual(len(archive_sha), 64)
        self.assertEqual(roles["workflow"], 1)
        self.assertTrue(all(len(row["content_sha256"]) == 64 for row in records))
        self.assertTrue(all(len(row["git_blob_sha1"]) == 40 for row in records))
        self.assertIn("unpinned-github-action", {row["rule"] for row in findings})
        self.assertIn("mutable-container-image", {row["rule"] for row in findings})
        self.assertEqual(
            next(row for row in records if row["path"] == "src/app.py")["inspection"],
            "hashed-and-source-inspected",
        )

    def test_tampered_archive_fails_git_object_verification(self) -> None:
        expected = b"expected\n"
        with self.assertRaisesRegex(audit.AuditError, "Git blob digest mismatch"):
            audit._archive_file_records(
                "szl-holdings/fixture",
                "public",
                archive_bytes({"README.md": b"tampered\n"}),
                [tree_entry("README.md", expected)],
                max_text_bytes=1024,
                max_repository_bytes=1024 * 1024,
            )

    def test_missing_archive_blob_is_incomplete(self) -> None:
        tree = [tree_entry("a.txt", b"a"), tree_entry("b.txt", b"b")]
        with self.assertRaisesRegex(audit.AuditError, "archive omitted 1 Git blobs"):
            audit._archive_file_records(
                "szl-holdings/fixture",
                "public",
                archive_bytes({"a.txt": b"a"}),
                tree,
                max_text_bytes=1024,
                max_repository_bytes=1024 * 1024,
            )

    def test_archive_path_traversal_is_rejected(self) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
            root = tarfile.TarInfo("root/")
            root.type = tarfile.DIRTYPE
            bundle.addfile(root)
            member = tarfile.TarInfo("root/../escape")
            member.size = 1
            bundle.addfile(member, io.BytesIO(b"x"))
        with self.assertRaisesRegex(audit.AuditError, "traversal-like"):
            audit._archive_file_records(
                "szl-holdings/fixture",
                "public",
                buffer.getvalue(),
                [],
                max_text_bytes=1024,
                max_repository_bytes=1024 * 1024,
            )

    def test_recursive_tree_truncation_falls_back_to_explicit_walk(self) -> None:
        root_sha = "1" * 40
        child_sha = "2" * 40
        blob_sha = "3" * 40

        def tree_request(_repository: str, sha: str, *, recursive: bool):
            if recursive:
                return {"truncated": True, "tree": []}
            if sha == root_sha:
                return {
                    "truncated": False,
                    "tree": [
                        {"path": "src", "type": "tree", "sha": child_sha, "mode": "040000"}
                    ],
                }
            return {
                "truncated": False,
                "tree": [
                    {"path": "app.py", "type": "blob", "sha": blob_sha, "mode": "100644", "size": 4}
                ],
            }

        with patch.object(audit, "_root_tree_sha", return_value=("4" * 40, root_sha)), patch.object(
            audit, "_tree_request", side_effect=tree_request
        ):
            commit, tree, entries, proof = audit.walk_repository_tree(
                "szl-holdings/fixture", "main"
            )
        self.assertEqual(commit, "4" * 40)
        self.assertEqual(tree, root_sha)
        self.assertEqual(proof, "explicit-subtree-walk")
        self.assertEqual([row["path"] for row in entries], ["src", "src/app.py"])

    def test_bandaid_words_in_proof_docs_and_tests_are_not_implementation_findings(self) -> None:
        text = "ephemeral compatibility shim and one-shot workflow"
        self.assertFalse(
            {row["rule"] for row in audit.inspect_text("szl-holdings/x", "public", "docs/proof.md", text)}
            & {"ephemeral-shim", "one-shot-controller"}
        )
        self.assertFalse(
            {row["rule"] for row in audit.inspect_text("szl-holdings/x", "public", "tests/test_guard.py", text)}
            & {"ephemeral-shim", "one-shot-controller"}
        )
        self.assertIn(
            "ephemeral-shim",
            {row["rule"] for row in audit.inspect_text("szl-holdings/x", "public", "src/runtime.py", text)},
        )

    def test_public_projection_never_discloses_private_names_or_paths(self) -> None:
        private = {
            "repository": "szl-holdings/private-alpha",
            "visibility": "private",
            "state": "FAIL",
            "files": [{"path": "secret/name.py"}],
            "findings": [{"path": "secret/name.py", "severity": "high"}],
        }
        public = {
            "repository": "szl-holdings/public-alpha",
            "visibility": "public",
            "state": "PASS",
            "files": [],
            "findings": [],
        }
        report = {
            "observed_at": "2026-09-05T00:00:00Z",
            "organization": "szl-holdings",
            "source": {},
            "inventory_reconciliation": {},
            "summary": audit.summarize([private, public]),
            "repositories": [private, public],
        }
        projected = audit.public_projection(report)
        rendered = audit.canonical_json(projected).decode()
        self.assertNotIn("private-alpha", rendered)
        self.assertNotIn("secret/name.py", rendered)
        self.assertEqual(projected["private_repositories"]["count"], 1)
        self.assertEqual(len(projected["public_repositories"]), 1)

    def test_run_audit_requires_inventory_floor_and_authoritative_match(self) -> None:
        with self.assertRaisesRegex(audit.AuditError, "below required minimum"):
            audit.run_audit(
                minimum_repositories=2,
                repository_provider=lambda _org: ([{"full_name": "szl-holdings/one"}], {}),
            )
        with self.assertRaisesRegex(audit.AuditError, "authoritative organization counts"):
            audit.run_audit(
                repository_provider=lambda _org: (
                    [{"full_name": "szl-holdings/one"}],
                    {"authoritative_count_available": True, "matched": False},
                ),
            )

    def test_summary_precedence_is_incomplete_then_fail_then_warn(self) -> None:
        self.assertEqual(audit.summarize([{"state": "WARN"}])["state"], "WARN")
        self.assertEqual(
            audit.summarize([{"state": "WARN"}, {"state": "FAIL"}])["state"],
            "FAIL",
        )
        self.assertEqual(
            audit.summarize([{"state": "FAIL"}, {"state": "INCOMPLETE"}])["state"],
            "INCOMPLETE",
        )


if __name__ == "__main__":
    unittest.main()
