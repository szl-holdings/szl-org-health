"""The inert artifact-transport probe uses the canonical pins and really checks bytes.

The canonical publish-pypi.yml downloads `pypi-dists` only on `release: published`,
so the download pin is never exercised by ordinary PR/push runs. The probe
workflow carries two inert files through the same pins and inputs; these tests keep
it rendered from PINS, unprivileged and non-publishing, and prove that its verifier
rejects missing, extra and altered files.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from tests.test_pypi_canonical_generator import CANONICAL_SPEC, PIN, ROOT, action_steps, gen, job_block, permissions_of
from tools import pypi_artifact_transport as probe


WORKFLOW = ROOT / gen.TRANSPORT_PROBE_PATH
TRIGGER_PATHS = (
    '      - "governance/pypi/canonical/**"\n'
    '      - "tools/pypi_artifact_transport.py"\n'
    '      - ".github/workflows/pypi-artifact-transport.yml"\n'
)
TRIGGERS = (
    "on:\n  pull_request:\n    paths:\n" + TRIGGER_PATHS
    + "  push:\n    branches: [main]\n    paths:\n" + TRIGGER_PATHS
)


def step_lines(text: str, step_name: str) -> list[str]:
    """The lines of one named step, from `- name:` to the next step or job."""
    lines = text.split("\n")
    start = lines.index(f"      - name: {step_name}")
    block = [lines[start]]
    for line in lines[start + 1:]:
        if line.startswith("      - ") or line.startswith("      # ") or not line.startswith("        "):
            break
        block.append(line)
    return block


def with_block(text: str, step_name: str) -> list[str]:
    block = step_lines(text, step_name)
    start = block.index("        with:")
    return [line for line in block[start + 1:] if line.startswith("          ")]


class TransportProbeWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = gen.render_transport_probe()

    def test_committed_workflow_is_the_renderer_output(self):
        with open(WORKFLOW, encoding="utf-8", newline="") as stream:
            self.assertEqual(stream.read(), self.text)

    def test_every_action_is_a_canonical_pin(self):
        steps, errors = action_steps(self.text)
        self.assertEqual(errors, [])
        uses = [line for line in self.text.split("\n") if "uses:" in line]
        self.assertEqual(len(steps), len(uses))
        by_ref = {ref: key for key, (ref, _) in gen.PINS.items()}
        keys = []
        for step in steps:
            self.assertRegex(step["ref"], PIN)
            self.assertIn(step["ref"], by_ref, step)
            key = by_ref[step["ref"]]
            keys.append((step["job"], key))
            ref, version = gen.PINS[key]
            self.assertEqual(step["comment"], (ref.split("@")[0], version), step)
        self.assertEqual(keys, [
            ("stage", "checkout"), ("stage", "upload"), ("stage", "upload"),
            ("fetch", "checkout"), ("fetch", "download"),
        ])

    def test_probe_follows_the_one_pin_definition(self):
        moved = {
            "upload": ("actions/upload-artifact@" + "e" * 40, "v9.9.9"),
            "download": ("actions/download-artifact@" + "d" * 40, "v9.9.8"),
        }
        with mock.patch.dict(gen.PINS, moved):
            text = gen.render_transport_probe()
            canonical = gen.render(CANONICAL_SPEC)
        for key, (ref, version) in moved.items():
            action = ref.split("@")[0]
            self.assertEqual(text.count(f"uses: {ref}\n"), 2 if key == "upload" else 1)
            self.assertEqual(text.count(f"# {action} {version}\n"), 2 if key == "upload" else 1)
            self.assertIn(f"uses: {ref}\n", canonical)
        self.assertNotIn(gen.PINS["upload"][0], text)
        self.assertNotIn(gen.PINS["download"][0], text)

    def test_transport_inputs_mirror_the_canonical_release_path(self):
        canonical = gen.render(CANONICAL_SPEC)
        self.assertEqual(
            with_block(self.text, "Upload inert distributions"),
            with_block(canonical, "Upload distributions (release only)") + ["          retention-days: 1"],
        )
        self.assertEqual(
            with_block(self.text, "Download inert distributions"),
            with_block(canonical, "Download gated distributions") + ["          digest-mismatch: error"],
        )

    def test_unprivileged_and_never_publishes(self):
        self.assertEqual(self.text.count("\npermissions: {}\n"), 1)
        for job in ("stage", "fetch"):
            self.assertEqual(permissions_of(job_block(self.text, job)), ["      contents: read"], job)
        body = "\n".join(line for line in self.text.split("\n") if not line.lstrip().startswith("#"))
        for forbidden in ("id-token", "secrets", "environment:", "pypa/gh-action-pypi-publish", "github.token",
                          "GITHUB_TOKEN", "github-token", "run-id:", "repository:", "write"):
            self.assertNotIn(forbidden, body, forbidden)
        self.assertIn("\n" + TRIGGERS + "\n", self.text)
        for trigger in ("release:", "workflow_dispatch", "workflow_run", "pull_request_target", "schedule:"):
            self.assertNotIn(trigger, body, trigger)
        for line in self.text.split("\n"):
            if line.lstrip().startswith("run:") or line.startswith("          python3") or line.startswith("          echo"):
                self.assertNotIn("${{", line, "expressions reach shell steps through env only")

    def test_jobs_and_steps(self):
        self.assertIn("    needs: stage\n", self.text)
        fetch = job_block(self.text, "fetch")
        self.assertIn("    needs: stage", fetch)
        for step in ("Verify pre/post SHA-256 equality", "Negative controls - missing, extra and altered files are rejected"):
            block = step_lines(self.text, step)
            self.assertIn("          MANIFEST: ${{ needs.stage.outputs.manifest }}", block)
        self.assertIn("      manifest: ${{ steps.stage.outputs.manifest }}", job_block(self.text, "stage"))

    def test_missing_file_upload_is_a_required_failure(self):
        block = step_lines(self.text, "Negative control - upload of a missing expected file is rejected")
        self.assertIn("        id: missing_upload", block)
        self.assertIn("        continue-on-error: true", block)
        self.assertIn("          if-no-files-found: error", block)
        self.assertIn("          path: dist/missing-expected-file.whl", block)
        assertion = step_lines(self.text, "Assert the missing-file upload failed")
        self.assertIn("          OUTCOME: ${{ steps.missing_upload.outcome }}", assertion)
        self.assertIn('          test "$OUTCOME" = failure', assertion)

    def test_cli_renders_the_probe(self):
        with mock.patch("sys.argv", ["gen", "--transport-probe"]), redirect_stdout(io.StringIO()) as out:
            exec(compile((ROOT / "governance/pypi/canonical/gen_publish_workflow.py").read_text(encoding="utf-8"),
                         "gen_publish_workflow.py", "exec"), {"__name__": "__main__"})
        self.assertEqual(out.getvalue(), self.text)


class TransportProbeToolTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.dist = self.root / "dist"
        self.manifest = probe.stage(self.dist)
        self.expected = probe.parse_manifest(json.dumps(self.manifest))

    def run_cli(self, *args: str) -> tuple[int, str]:
        with redirect_stdout(io.StringIO()) as out:
            code = probe.main(list(args))
        return code, out.getvalue()

    def test_stage_is_deterministic_inert_and_complete(self):
        again = probe.stage(self.root / "again")
        self.assertEqual(again, self.manifest)
        self.assertEqual(sorted(self.manifest["files"]), sorted([probe.WHEEL, probe.SDIST]))
        for name, digest in self.manifest["files"].items():
            data = (self.dist / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            self.assertEqual(data, (self.root / "again" / name).read_bytes())
        with zipfile.ZipFile(self.dist / probe.WHEEL) as wheel:
            metadata = wheel.read(f"{probe.NAME}-{probe.VERSION}.dist-info/METADATA").decode()
            record = wheel.read(f"{probe.NAME}-{probe.VERSION}.dist-info/RECORD").decode()
            for info in wheel.infolist():
                self.assertEqual(info.date_time, probe.ZIP_EPOCH)
                self.assertEqual(info.create_system, 3)
        self.assertIn("Classifier: Private :: Do Not Upload", metadata)
        self.assertIn(f"{probe.NAME}/__init__.py,sha256=", record)
        with tarfile.open(self.dist / probe.SDIST, "r:gz") as sdist:
            members = {member.name: member for member in sdist.getmembers()}
            pkg_info = sdist.extractfile(f"{probe.NAME}-{probe.VERSION}/PKG-INFO").read().decode()
        self.assertEqual({member.mtime for member in members.values()}, {0})
        self.assertIn("Classifier: Private :: Do Not Upload", pkg_info)
        self.assertEqual(gzip.decompress((self.dist / probe.SDIST).read_bytes())[:len(probe.NAME)], probe.NAME.encode())

    def test_stage_refuses_a_non_empty_directory(self):
        with self.assertRaises(SystemExit):
            probe.stage(self.dist)

    def test_untouched_transport_verifies(self):
        errors, observed = probe.verify(self.dist, self.expected)
        self.assertEqual(errors, [])
        self.assertEqual(observed, self.expected)
        code, out = self.run_cli("verify", "--dir", str(self.dist), "--manifest-json", json.dumps(self.manifest))
        self.assertEqual(code, 0, out)
        self.assertIn("pre/post SHA-256 equal for 2/2 files", out)
        for name, digest in self.expected.items():
            self.assertIn(f"downloaded sha256={digest} {name} MATCH", out)

    def test_missing_extra_altered_and_nested_files_are_rejected(self):
        wheel = self.dist / probe.WHEEL
        original = wheel.read_bytes()
        wheel.unlink()
        errors, _ = probe.verify(self.dist, self.expected)
        self.assertEqual(errors, [f"missing expected file {probe.WHEEL}"])
        code, out = self.run_cli("verify", "--dir", str(self.dist), "--manifest-json", json.dumps(self.manifest))
        self.assertEqual(code, 1)
        self.assertIn(f"::error::missing expected file {probe.WHEEL}", out)

        wheel.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        errors, _ = probe.verify(self.dist, self.expected)
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith(f"sha256 mismatch for {probe.WHEEL}"), errors)

        wheel.write_bytes(original)
        (self.dist / "nested").mkdir()
        (self.dist / "nested" / probe.WHEEL).write_bytes(original)
        errors, _ = probe.verify(self.dist, self.expected)
        self.assertEqual(errors, [f"unexpected file nested/{probe.WHEEL}"])

        errors, _ = probe.verify(self.root / "absent", self.expected)
        self.assertEqual(len(errors), 1)
        self.assertIn("does not exist", errors[0])

    def test_linked_entries_are_rejected(self):
        link = self.dist / "linked.whl"
        try:
            os.symlink(self.dist / probe.WHEEL, link)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlinks unavailable on this host: {error}")
        errors, _ = probe.verify(self.dist, self.expected)
        self.assertIn("linked entry linked.whl is not accepted", errors)

    def test_malformed_manifests_are_rejected(self):
        good = self.manifest["files"]
        digest = next(iter(good.values()))
        for label, text in (
            ("not json", "{"),
            ("wrong schema", json.dumps({"schema": "other", "files": good})),
            ("no files", json.dumps({"schema": probe.SCHEMA, "files": {}})),
            ("path traversal", json.dumps({"schema": probe.SCHEMA, "files": {"../x.whl": digest}})),
            ("nested path", json.dumps({"schema": probe.SCHEMA, "files": {"a/x.whl": digest}})),
            ("uppercase digest", json.dumps({"schema": probe.SCHEMA, "files": {"x.whl": digest.upper()}})),
            ("short digest", json.dumps({"schema": probe.SCHEMA, "files": {"x.whl": digest[:40]}})),
        ):
            with self.subTest(manifest=label):
                with self.assertRaises(probe.ManifestError):
                    probe.parse_manifest(text)
                code, out = self.run_cli("verify", "--dir", str(self.dist), "--manifest-json", text)
                self.assertEqual(code, 1)
                self.assertIn("::error::", out)

    def test_self_check_rejects_every_control_and_leaves_the_download_untouched(self):
        before = {path.name: path.read_bytes() for path in self.dist.iterdir()}
        code, out = self.run_cli("self-check", "--dir", str(self.dist), "--manifest-json", json.dumps(self.manifest))
        self.assertEqual(code, 0, out)
        for label in ("missing expected file", "extra file", "altered byte"):
            self.assertIn(f"negative control [{label}]: rejected", out)
        self.assertIn("all negative controls rejected; untouched download accepted", out)
        self.assertEqual({path.name: path.read_bytes() for path in self.dist.iterdir()}, before)

    def test_self_check_fails_when_the_download_does_not_verify(self):
        (self.dist / probe.SDIST).unlink()
        code, out = self.run_cli("self-check", "--dir", str(self.dist), "--manifest-json", json.dumps(self.manifest))
        self.assertEqual(code, 1)
        self.assertIn("untouched download does not verify", out)

    def test_self_check_detects_a_verifier_that_accepts_everything(self):
        with mock.patch.object(probe, "verify", return_value=([], {})):
            failures = probe.self_check(self.dist, self.expected)
        self.assertEqual(len(failures), 3, failures)
        self.assertTrue(all("was not rejected" in failure for failure in failures))

    def test_cli_stage_writes_the_manifest_the_workflow_forwards(self):
        outdir, manifest = self.root / "cli-dist", self.root / "manifest.json"
        code, out = self.run_cli("stage", "--outdir", str(outdir), "--manifest", str(manifest))
        self.assertEqual(code, 0)
        text = manifest.read_text(encoding="utf-8")
        self.assertEqual(text.count("\n"), 1, "GITHUB_OUTPUT needs a single-line value")
        self.assertEqual(json.loads(text), self.manifest)
        for name, digest in self.manifest["files"].items():
            self.assertIn(f"staged sha256={digest} {name}", out)


if __name__ == "__main__":
    unittest.main()
