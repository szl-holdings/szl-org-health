# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RepositoryHygieneTests(unittest.TestCase):
    def test_python_bytecode_is_never_tracked(self) -> None:
        completed = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
        paths = [
            value.decode("utf-8")
            for value in completed.stdout.split(b"\0")
            if value
        ]
        offenders = sorted(
            path
            for path in paths
            if "__pycache__/" in path
            or path.endswith((".pyc", ".pyo", ".pyd"))
        )
        self.assertEqual(offenders, [])

    def test_gitignore_blocks_generated_python_artifacts(self) -> None:
        source = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("__pycache__/", source)
        self.assertIn("*.py[cod]", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
