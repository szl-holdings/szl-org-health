"""Installed-wheel checks must not import a healthy source checkout instead."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import venv
import zipfile


ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "governance/pypi/canonical"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load("pypi_wheel_isolation_gate", CANONICAL / "szl_pypi_release_gate.py")
audit = load("pypi_utf8_audit", ROOT / "tools/pypi_release_path_audit.py")


class InstalledWheelIsolationTests(unittest.TestCase):
    def run_gate(self, root, *, wheel_broken, checkout_broken, missing_dependency=False):
        """Stub build/network steps; execute actual venv dependency/import probes."""
        checkout = root / "checkout"
        checkout.mkdir()
        source = checkout / "shadow_probe"
        source.mkdir()
        failure = 'raise RuntimeError("SYNTHETIC_BROKEN_MODULE")\n'
        healthy = 'origin = "synthetic healthy module"\n'
        (source / "__init__.py").write_text(failure if checkout_broken else healthy, encoding="utf-8")
        (checkout / "README.md").write_text("Synthetic package fixture.\n", encoding="utf-8")
        (checkout / "pyproject.toml").write_text(
            '[build-system]\nbuild-backend = "setuptools.build_meta"\n'
            '[project]\nname = "shadow-probe"\nversion = "1.2.3"\n'
            'description = "synthetic wheel isolation fixture"\nreadme = "README.md"\n'
            'requires-python = ">=3.11"\nlicense = "MIT"\n'
            '[project.urls]\nSource = "https://github.com/szl-holdings/shadow-repo"\n'
            '[tool.szl.release]\nimport_names = ["shadow_probe"]\n',
            encoding="utf-8",
        )
        commands = []

        def sh(command, **kwargs):
            commands.append(command)
            if command[1:3] == ["-m", "build"]:
                stage = Path(command[command.index("--outdir") + 1])
                wheel = stage / "shadow_probe-1.2.3-py3-none-any.whl"
                with zipfile.ZipFile(wheel, "w") as archive:
                    archive.writestr("shadow_probe/__init__.py", failure if wheel_broken else healthy)
                    archive.writestr(
                        "shadow_probe-1.2.3.dist-info/METADATA",
                        "Metadata-Version: 2.1\nName: shadow-probe\nVersion: 1.2.3\n"
                        "Project-URL: Source, https://github.com/szl-holdings/shadow-repo\n"
                        + ("Requires-Dist: szl-test-missing-dependency==1.0\n" if missing_dependency else "")
                        + "\n",
                    )
                (stage / "shadow_probe-1.2.3.tar.gz").write_bytes(b"synthetic sdist; not built or published")
                return
            if command[1:3] == ["-m", "twine"]:
                return
            if command[1:3] == ["-m", "venv"]:
                # ensurepip supplies pip offline; pip check below is a real
                # subprocess, not a mocked success or network-dependent install.
                venv.EnvBuilder(with_pip=True).create(command[-1])
                return
            if "pip" in command and "install" in command:
                # No installer or network: lay out only our own two fixture files.
                env = Path(command[0]).parents[1]
                site = env / ("Lib/site-packages" if os.name == "nt" else
                              f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")
                with zipfile.ZipFile(command[-1]) as archive:
                    archive.extractall(site)
                return
            return subprocess.run(command, check=True, text=True, capture_output=True,
                                  cwd=checkout, timeout=20, **kwargs)

        package = {"name": "shadow-probe", "dir": str(checkout), "environment": "pypi"}
        with mock.patch.object(gate, "sh", side_effect=sh), \
                mock.patch.object(gate, "pypi_versions", return_value=set()), \
                contextlib.redirect_stdout(io.StringIO()):
            receipt = gate.gate_package(package, "szl-holdings/shadow-repo", "pull_request",
                                        "branch", "synthetic-test", root / "dist")
        return receipt, commands

    def test_broken_installed_wheel_cannot_pass_using_healthy_checkout(self):
        with tempfile.TemporaryDirectory(prefix="szl-pypi-isolation-") as directory:
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                self.run_gate(Path(directory), wheel_broken=True, checkout_broken=False)
            self.assertIn("SYNTHETIC_BROKEN_MODULE", failure.exception.stderr)
            self.assertIn("site-packages", failure.exception.stderr)

    def test_healthy_installed_wheel_is_not_shadowed_by_broken_checkout(self):
        with tempfile.TemporaryDirectory(prefix="szl-pypi-isolation-") as directory:
            receipt, commands = self.run_gate(Path(directory), wheel_broken=False, checkout_broken=True)
            self.assertEqual(receipt["package"], "shadow-probe")
            self.assertEqual(receipt["version"], "1.2.3")
            venv_commands = [command for command in commands if "venv-shadow-probe" in command[0]]
            self.assertEqual(len(venv_commands), 4)
            self.assertTrue(all(command[1] == "-I" for command in venv_commands))
            self.assertEqual(venv_commands[1][1:], ["-I", "-m", "pip", "check"])

    def test_missing_installed_dependency_stops_before_distribution_admission(self):
        with tempfile.TemporaryDirectory(prefix="szl-pypi-dependencies-") as directory:
            root = Path(directory)
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                self.run_gate(root, wheel_broken=False, checkout_broken=False,
                              missing_dependency=True)
            self.assertEqual(failure.exception.cmd[1:], ["-I", "-m", "pip", "check"])
            self.assertEqual(failure.exception.returncode, 1)
            self.assertIn("szl-test-missing-dependency", failure.exception.stdout)
            self.assertFalse((root / "dist").exists())
            # The installed module/version are healthy: only its dependency
            # metadata is incomplete. Import-only checks would miss this case.
            subprocess.run(
                [failure.exception.cmd[0], "-I", "-c",
                 "import shadow_probe; from importlib.metadata import version; "
                 "assert version('shadow-probe') == '1.2.3'"],
                check=True, capture_output=True, text=True, timeout=20,
            )


class AuditUtf8Tests(unittest.TestCase):
    def test_utf8_canonical_files_do_not_depend_on_windows_locale(self):
        original_read_text = Path.read_text

        def cp1252_default(path, *args, **kwargs):
            if not args and kwargs.get("encoding") is None:
                kwargs["encoding"] = "cp1252"
            return original_read_text(path, *args, **kwargs)

        with tempfile.TemporaryDirectory(prefix="szl-pypi-utf8-") as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({
                "owner": {"github_org": "szl-holdings"},
                "packages": [{"name": "synthetic-hold", "path": "pyproject.toml",
                              "status": "hold", "reason": "fixture — no release"}],
            }, ensure_ascii=False), encoding="utf-8")
            report, summary = root / "report.json", root / "summary.md"
            argv = ["pypi_release_path_audit.py", "--manifest", str(manifest),
                    "--canonical-dir", str(CANONICAL), "--report", str(report),
                    "--summary", str(summary)]
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(sys, "path", list(sys.path)), \
                    mock.patch.dict(os.environ, {}, clear=True), \
                    mock.patch.object(Path, "read_text", cp1252_default), \
                    mock.patch.object(audit.Http, "get", side_effect=AssertionError("no network")) as network, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(audit.main(), 0)
            network.assert_not_called()
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(result["counts"], {"PASS": 1, "FAIL": 0, "UNKNOWN": 0})


if __name__ == "__main__":
    unittest.main()
