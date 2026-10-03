"""Release-path source bindings reject lookalike repositories before building."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
ORG = "szl-holdings"
REPO = "sample-repo"
PACKAGE = "sample-package"
SOURCE = f"https://github.com/{ORG}/{REPO}"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load_module("pypi_source_url_gate", ROOT / "governance/pypi/canonical/szl_pypi_release_gate.py")
audit = load_module("pypi_source_url_audit", ROOT / "tools/pypi_release_path_audit.py")

ACCEPTED = (SOURCE, SOURCE.upper(), SOURCE + "/", SOURCE + "///")
REJECTED = (
    SOURCE + "-evil",
    SOURCE + ".git",
    SOURCE + "/issues",
    SOURCE + "/tree/main",
    SOURCE + "?publisher=expected",
    SOURCE + "#expected",
    SOURCE + "@attacker.example",
    SOURCE.replace("github.com", "github.com.attacker.example"),
    SOURCE.replace("https://", "http://"),
    "",
    None,
    42,
    True,
    [SOURCE],
    {"url": SOURCE},
)


class BuildReached(Exception):
    """Stop at the first build command without executing packaging tools."""


class FakeHttp:
    """Readback fixture with no credentials, external calls, or attestation claim."""

    def __init__(self, source, key="Source"):
        self.source = source
        self.key = key
        self.calls = []

    def get(self, url, accept=None, raw=False):
        self.calls.append(url)
        if url.endswith("/.github/workflows/publish-pypi.yml"):
            return 200, f'SZL_PACKAGES: "{PACKAGE}=.:pypi"\n'.encode()
        if url.endswith("/.github/scripts/szl_pypi_release_gate.py"):
            return 200, b"canonical fixture gate\n"
        if url == f"https://pypi.org/pypi/{PACKAGE}/json":
            return 200, {"info": {"version": "1.0.0", "project_urls": {self.key: self.source}}, "urls": []}
        if url == f"https://pypi.org/simple/{PACKAGE}/":
            return 503, None
        raise AssertionError(f"Unexpected external lookup: {url}")


class PyPISourceUrlTests(unittest.TestCase):
    def run_gate(self, source, key="Source"):
        with tempfile.TemporaryDirectory(prefix="szl-pypi-source-url-") as directory:
            root = Path(directory)
            if source is None:
                url_line = ""
            elif isinstance(source, dict):
                url_line = f'{json.dumps(key)} = {{ url = {json.dumps(source["url"])} }}'
            else:
                url_line = f"{json.dumps(key)} = {json.dumps(source)}"
            (root / "pyproject.toml").write_text(
                '[build-system]\nbuild-backend = "setuptools.build_meta"\n'
                f'[project]\nname = "{PACKAGE}"\n'
                'description = "source URL regression fixture"\nreadme = "README.md"\n'
                'requires-python = ">=3.11"\nlicense = "MIT"\n'
                f"[project.urls]\n{url_line}\n",
                encoding="utf-8",
            )
            pkg = {"name": PACKAGE, "dir": str(root), "environment": "pypi"}
            with patch.object(gate, "sh", side_effect=BuildReached) as build, \
                    patch.object(gate, "pypi_versions") as pypi, \
                    patch.object(gate.shutil, "rmtree") as remove, \
                    contextlib.redirect_stdout(io.StringIO()):
                try:
                    gate.gate_package(pkg, f"{ORG}/{REPO}", "pull_request", "branch", "test", root / "dist")
                except BuildReached:
                    self.assertEqual(build.call_count, 1)
                    self.assertEqual(build.call_args.args[0][1:3], ["-m", "build"])
                    pypi.assert_not_called()
                    return "BUILD_REACHED"
                except SystemExit as error:
                    self.assertEqual(error.code, 1)
                    build.assert_not_called()
                    pypi.assert_not_called()
                    remove.assert_not_called()
                    return "REJECTED_BEFORE_BUILD"
                self.fail("gate returned without rejecting metadata or reaching build")

    def audit_source(self, source, key="Source"):
        http = FakeHttp(source, key)
        canon = {
            "render": lambda spec: f'SZL_PACKAGES: "{spec}"\n',
            "gate_sha256": audit.sha256(b"canonical fixture gate\n"),
        }
        cache = {REPO: {
            "workflows": [], "workflows_status": 200,
            "token_hits": [], "workflow_errors": [],
            "environments_status": 200, "environments_total_count": 1,
            "environments": {"pypi": {
                "deployment_branch_policy": {"custom_branch_policies": True, "protected_branches": False},
                "_policies": [("v*", "tag")],
                "_policies_status": 200, "_policies_total_count": 1,
            }},
            "tag_rulesets_status": 200, "tag_rulesets": [],
        }}
        results = []
        with contextlib.redirect_stdout(io.StringIO()):
            audit.audit_release_repo(http, ORG, {"name": PACKAGE, "repo": REPO, "status": "published"}, canon, results, cache)
        source_result = [r for r in results if r["check"] == "pypi:source-url"]
        self.assertEqual(len(source_result), 1)
        self.assertEqual(len(http.calls), 4)
        self.assertEqual([r["status"] for r in results if r["check"] == "pypi:provenance"], ["UNKNOWN"])
        return source_result[0]["status"]

    def test_gate_allows_the_canonical_repository(self):
        for source in ACCEPTED:
            with self.subTest(source=source):
                self.assertEqual(self.run_gate(source), "BUILD_REACHED")

    def test_gate_rejects_lookalikes_and_nonstrings_before_build(self):
        for source in REJECTED:
            with self.subTest(source=source):
                self.assertEqual(self.run_gate(source), "REJECTED_BEFORE_BUILD")

    def test_audit_allows_the_canonical_repository(self):
        for source in ACCEPTED:
            with self.subTest(source=source):
                self.assertEqual(self.audit_source(source), "PASS")

    def test_audit_fails_lookalikes_and_nonstrings(self):
        for source in REJECTED:
            with self.subTest(source=source):
                self.assertEqual(self.audit_source(source), "FAIL")

    def test_gate_preserves_supported_source_url_labels(self):
        for key in ("Source", "Repository", "Source Code"):
            with self.subTest(key=key):
                self.assertEqual(self.run_gate(SOURCE, key), "BUILD_REACHED")

    def test_audit_preserves_supported_source_url_labels(self):
        for key in ("Source", "Repository", "Source Code"):
            with self.subTest(key=key):
                self.assertEqual(self.audit_source(SOURCE, key), "PASS")


if __name__ == "__main__":
    unittest.main()
