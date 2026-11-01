"""Exercise exactly the Docker COPY allowlist without building an image."""
from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
IMPORT_PROBE = r'''
import json
import os
from pathlib import Path
import socket
import sys
import urllib.request

root = Path(sys.argv[1]).resolve()
os.chdir(root)
sys.path.insert(0, str(root))

def network_forbidden(*args, **kwargs):
    raise AssertionError("container import probe must not use the network")

socket.create_connection = network_forbidden
socket.getaddrinfo = network_forbidden
socket.socket.connect = network_forbidden
socket.socket.connect_ex = network_forbidden
urllib.request.urlopen = network_forbidden

import app
from census import github, github_ci, governance, report, portal_projection

modules = [app, github, github_ci, governance, report, portal_projection]
for module in modules:
    assert Path(module.__file__).resolve().is_relative_to(root), module.__name__
for name, module in list(sys.modules.items()):
    if name == "census" or name.startswith("census."):
        assert Path(module.__file__).resolve().is_relative_to(root), name

sent = []
handler = object.__new__(app.Handler)
handler.path = "/healthz"
handler._send = lambda *args: sent.append(args)
handler.do_GET()
assert sent[0][0] == 200
assert json.loads(sent[0][1]) == {
    "status": "ok", "service": "szl-org-health", "schema_version": 2
}
print(json.dumps({"imported": [module.__name__ for module in modules], "healthz": 200}))
'''


class ContainerSourceLayoutTests(unittest.TestCase):
    def assemble(self, directory):
        root = Path(directory).resolve()
        self.assertTrue(root.is_relative_to(Path(tempfile.gettempdir()).resolve()))
        copied = []
        for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines():
            if not line.startswith("COPY "):
                continue
            parts = shlex.split(line)
            self.assertEqual(len(parts), 3, "test expects the explicit one-file COPY contract")
            relative = PurePosixPath(parts[2]).relative_to("/app")
            target = root.joinpath(*relative.parts)
            self.assertTrue(target.resolve().is_relative_to(root))
            source = ROOT / parts[1]
            self.assertTrue(source.is_file())
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            copied.append(relative.as_posix())
        return root, copied

    def probe(self, root):
        return subprocess.run(
            [sys.executable, "-I", "-B", "-c", IMPORT_PROBE, str(root)],
            cwd=root, capture_output=True, text=True, timeout=30, check=False,
        )

    def test_copied_container_sources_import_and_serve_liveness(self):
        with tempfile.TemporaryDirectory(prefix="org-health-container-layout-") as directory:
            root, copied = self.assemble(directory)
            result = self.probe(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("census/github_ci.py", copied)
            self.assertEqual(json.loads(result.stdout)["healthz"], 200)

    def test_checkout_cannot_mask_a_missing_container_module(self):
        with tempfile.TemporaryDirectory(prefix="org-health-container-layout-") as directory:
            root, _ = self.assemble(directory)
            (root / "census" / "github_ci.py").unlink(missing_ok=True)
            result = self.probe(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ModuleNotFoundError", result.stderr)
            self.assertIn("census.github_ci", result.stderr)


if __name__ == "__main__":
    unittest.main()
