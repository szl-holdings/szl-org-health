"""The REAL canonical publish-pypi.yml renderer keeps every action pin in step.

The audit tests in test_pypi_release_path_audit.py stub the renderer, so they
cannot see the generator itself drift. Here the shipped generator renders the
canonical copy, a normal single-package consumer and the two-package
szl-evidence-litellm consumer, and the output is held to one pin contract: both
artifact uploads share one pin and version comment, every download matches,
every reference is a 40-hex SHA, and the release-only conditions, permissions
and publish inputs are unchanged. One-pin and one-comment drifts must fail.
"""
from __future__ import annotations

import importlib.util
import io
import json
import re
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from tests.test_pypi_release_path_audit import (
    GATE,
    ORG,
    PACKAGE,
    RAW,
    REPO,
    FakeHttp,
    fixture,
)
from tools.pypi_release_path_audit import audit_release_repo, sha256


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_DIR = ROOT / "governance" / "pypi" / "canonical"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = load_module("pypi_canonical_generator", CANONICAL_DIR / "gen_publish_workflow.py")
gate = load_module("pypi_canonical_generator_gate", CANONICAL_DIR / "szl_pypi_release_gate.py")

# Owner-accepted baseline (R04). Official tag readback: both tags are lightweight
# refs whose object is the commit itself (no annotated tag to peel).
ACCEPTED_UPLOAD = ("actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9", "v7.0.2")
ACCEPTED_DOWNLOAD = ("actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333", "v8.0.2")
RETIRED_SHAS = (
    "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",  # actions/upload-artifact v7.0.1
    "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",  # actions/download-artifact v8.0.1
)

CANONICAL_SPEC = "PACKAGE=.:pypi"
SINGLE_SPEC = "szl-pin=.:pypi"
# Exact SZL_PACKAGES line of szl-holdings/szl-evidence-litellm: two packages,
# two environments, two `<package>-v<version>` tag families.
MULTI_SPEC = (
    "szl-receipts=packages/szl-receipts:pypi;"
    "szl-evidence-litellm=packages/szl-evidence-litellm:pypi-litellm"
)
CASES = {
    "canonical": (CANONICAL_SPEC, [("PACKAGE", "pypi")]),
    "single": (SINGLE_SPEC, [("szl-pin", "pypi")]),
    "multi": (MULTI_SPEC, [("szl-receipts", "pypi"), ("szl-evidence-litellm", "pypi-litellm")]),
}

TRIGGERS = """on:
  release:
    types: [published]
  pull_request:
    paths:
      - "pyproject.toml"
      - "**/pyproject.toml"
      - ".github/workflows/publish-pypi.yml"
      - ".github/scripts/szl_pypi_release_gate.py"
      - "src/**"
      - "**/*.py"
  push:
    branches: [main]
    paths:
      - "pyproject.toml"
      - "**/pyproject.toml"
      - ".github/workflows/publish-pypi.yml"
      - ".github/scripts/szl_pypi_release_gate.py"
"""
RELEASE_ONLY = "github.event_name == 'release'"
OIDC_PERMISSION = "      id-token: write   # OIDC token for PyPI Trusted Publishing — the only credential"

JOB = re.compile(r"^  (?P<job>[A-Za-z0-9_-]+):$")
USES = re.compile(r"^(?P<lead> {6}- | {8})uses: (?P<ref>.*)$")
COMMENT = re.compile(r"^ {6}# (?P<action>\S+) (?P<version>\S+)$")
PIN = re.compile(r"^(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(?P<sha>[0-9a-f]{40})$")


def publish_job_id(name: str, multi: bool) -> str:
    return "publish" if not multi else "publish-" + name.lower().replace(".", "-").replace("_", "-")


def action_steps(text: str) -> tuple[list[dict], list[str]]:
    """Every step that runs an action, with its job, name, condition and version comment."""
    lines = text.split("\n")
    steps: list[dict] = []
    errors: list[str] = []
    in_jobs, job = False, None
    for index, line in enumerate(lines):
        if line == "jobs:":
            in_jobs = True
            continue
        found = JOB.match(line)
        if in_jobs and found:
            job = found["job"]
            continue
        if "uses:" not in line:
            continue
        used = USES.match(line)
        if not used:
            errors.append(f"line {index + 1}: unexpected uses layout {line!r}")
            continue
        start, name, condition = index, None, None
        if used["lead"] == " " * 8:
            start -= 1
            if lines[start].startswith("        if: "):
                condition = lines[start][len("        if: "):]
                start -= 1
            named = re.match(r"^ {6}- name: (.+)$", lines[start])
            if not named:
                errors.append(f"line {index + 1}: action step without a `- name:` line")
                continue
            name = named[1]
        comment = COMMENT.match(lines[start - 1]) if start else None
        steps.append({
            "job": job,
            "line": index + 1,
            "name": name,
            "condition": condition,
            "ref": used["ref"],
            "comment": (comment["action"], comment["version"]) if comment else None,
        })
    return steps, errors


def pin_contract_errors(text: str, packages: list[tuple[str, str]],
                        upload=ACCEPTED_UPLOAD, download=ACCEPTED_DOWNLOAD) -> list[str]:
    """Empty when every action reference and its version comment come from one pin."""
    steps, errors = action_steps(text)
    defined = set(gen.PINS.values())
    for step in steps:
        where = f"{step['job']}/{step['name'] or step['ref']} (line {step['line']})"
        pinned = PIN.match(step["ref"])
        if not pinned:
            errors.append(f"{where}: reference is not owner/repo@<40-hex SHA>: {step['ref']!r}")
            continue
        if step["comment"] is None:
            errors.append(f"{where}: no version comment above the step")
            continue
        action, version = step["comment"]
        if action != pinned["action"]:
            errors.append(f"{where}: comment names {action}, step uses {pinned['action']}")
        if (step["ref"], version) not in defined:
            errors.append(f"{where}: {step['ref']} with comment {version} is not one PINS entry")
    uploads = [s for s in steps if s["ref"].startswith("actions/upload-artifact@")]
    if [(s["job"], s["name"]) for s in uploads] != [
        ("build", "Upload release-gate receipt"),
        ("build", "Upload distributions (release only)"),
    ]:
        errors.append(f"expected exactly the two build uploads, got {[(s['job'], s['name']) for s in uploads]}")
    upload_pins = {(s["ref"], s["comment"][1] if s["comment"] else None) for s in uploads}
    if upload_pins != {upload}:
        errors.append(f"uploads do not share the pin and comment {upload}: {sorted(upload_pins, key=str)}")
    multi = len(packages) > 1
    downloads = [s for s in steps if s["ref"].startswith("actions/download-artifact@")]
    expected_jobs = [publish_job_id(name, multi) for name, _ in packages]
    if [s["job"] for s in downloads] != expected_jobs:
        errors.append(f"expected one download per publish job {expected_jobs}, got {[s['job'] for s in downloads]}")
    download_pins = {(s["ref"], s["comment"][1] if s["comment"] else None) for s in downloads}
    if download_pins != {download}:
        errors.append(f"downloads do not all match {download}: {sorted(download_pins, key=str)}")
    for retired in RETIRED_SHAS:
        if retired in text:
            errors.append(f"retired SHA {retired} still present")
    return errors


def job_block(text: str, job: str) -> list[str]:
    lines = text.split("\n")
    start = lines.index(f"  {job}:")
    block = []
    for line in lines[start + 1:]:
        if JOB.match(line):
            break
        block.append(line)
    return block


def permissions_of(block: list[str]) -> list[str]:
    start = block.index("    permissions:")
    granted = []
    for line in block[start + 1:]:
        if not line.startswith("      "):
            break
        granted.append(line)
    return granted


def release_contract_errors(text: str, spec: str, packages: list[tuple[str, str]]) -> list[str]:
    """Empty when triggers, release-only conditions, permissions and publish inputs are unchanged."""
    errors: list[str] = []
    multi = len(packages) > 1
    count = len(packages)

    def expect(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    expect(f'\n  SZL_PACKAGES: "{spec}"\n' in text, "SZL_PACKAGES line is not the declared spec")
    expect("\n" + TRIGGERS + "\n" in text, "triggers changed")
    for forbidden in ("workflow_dispatch", "schedule:", "workflow_run", "pull_request_target"):
        expect(forbidden not in text, f"unexpected trigger {forbidden}")
    expect(text.count("\npermissions: {}\n") == 1, "top-level permissions must be exactly {}")
    tag_rule = "`<package>-v<version>`" if multi else "`v<version>`"
    expect(f"Release whose tag is {tag_rule}" in text, f"tag rule comment is not {tag_rule}")

    jobs = [line.strip()[:-1] for line in text.split("\n") if JOB.match(line)]
    jobs = jobs[jobs.index("build"):] if "build" in jobs else jobs
    publish_jobs = [publish_job_id(name, multi) for name, _ in packages]
    expect(jobs == ["build"] + publish_jobs, f"jobs are {jobs}, expected build + {publish_jobs}")

    conditions = [line for line in text.split("\n") if line.lstrip().startswith("if: ")]
    expected_conditions = [f"        if: {RELEASE_ONLY}"]
    for name, _ in packages:
        condition = RELEASE_ONLY + (f" && needs.build.outputs.package == '{name}'" if multi else "")
        expected_conditions.append(f"    if: {condition}")
    expect(conditions == expected_conditions, f"conditions changed: {conditions}")
    steps, _ = action_steps(text)
    conditional = [(s["job"], s["name"], s["condition"]) for s in steps if s["condition"]]
    expect(conditional == [("build", "Upload distributions (release only)", RELEASE_ONLY)],
           f"release-only step conditions changed: {conditional}")

    if "build" in jobs:
        build = job_block(text, "build")
        expect(permissions_of(build) == ["      contents: read"], "build permissions must be contents: read only")
        expect("    timeout-minutes: 20" in build, "build timeout changed")
        expect("          name: release-gate-receipt" in build, "receipt artifact name changed")
        expect(build.count("          name: pypi-dists") == 1, "distribution artifact name changed")
        expect(build.count("          if-no-files-found: error") == 2, "upload if-no-files-found changed")
        expect(all("id-token" not in line for line in build), "build job must never hold id-token")
    for (name, environment), job in zip(packages, publish_jobs):
        if job not in jobs:
            continue
        block = job_block(text, job)
        expect(f"    name: Publish {name} to PyPI (Trusted Publishing)" in block, f"{job}: name changed")
        expect("    needs: build" in block, f"{job}: must need build")
        expect("    timeout-minutes: 15" in block, f"{job}: timeout changed")
        expect(f"      name: {environment}" in block, f"{job}: environment is not {environment}")
        expect(f"      url: https://pypi.org/project/{name}/${{{{ needs.build.outputs.version }}}}/" in block,
               f"{job}: project URL changed")
        expect(permissions_of(block) == [OIDC_PERMISSION, "      contents: read"],
               f"{job}: permissions must be id-token: write + contents: read")
        expect(block.count("          name: pypi-dists") == 1, f"{job}: download artifact name changed")
        for line in ("          packages-dir: dist/",
                     "          attestations: true     # PEP 740 provenance, signed via Sigstore",
                     "          verify-metadata: true",
                     "          skip-existing: false   # a duplicate version is a release error, never a silent skip",
                     "          print-hash: true"):
            expect(line in block, f"{job}: publish input changed: {line.strip()}")
    expect(text.count("id-token: write") == count, "id-token: write must appear once per publish job only")
    return errors


def replace_nth(text: str, old: str, new: str, nth: int) -> str:
    """Replace only the nth (0-based) occurrence of old."""
    index = -1
    for _ in range(nth + 1):
        index = text.index(old, index + 1)
    return text[:index] + new + text[index + len(old):]


class RealRendererPinContractTests(unittest.TestCase):
    def test_canonical_file_is_the_renderer_output(self):
        with open(CANONICAL_DIR / "publish-pypi.yml", encoding="utf-8", newline="") as stream:
            self.assertEqual(stream.read(), gen.render(CANONICAL_SPEC))

    def test_generator_pins_are_the_accepted_baseline(self):
        self.assertEqual(gen.PINS["upload"], ACCEPTED_UPLOAD)
        self.assertEqual(gen.PINS["download"], ACCEPTED_DOWNLOAD)
        for ref, version in gen.PINS.values():
            self.assertRegex(ref, PIN)
            self.assertRegex(version, r"^v\d+\.\d+\.\d+$")

    def test_every_case_meets_the_pin_contract(self):
        for case, (spec, packages) in CASES.items():
            with self.subTest(case=case):
                self.assertEqual(pin_contract_errors(gen.render(spec), packages), [])

    def test_every_case_keeps_the_release_contract(self):
        for case, (spec, packages) in CASES.items():
            with self.subTest(case=case):
                self.assertEqual(release_contract_errors(gen.render(spec), spec, packages), [])

    def test_every_uses_line_ends_at_a_40_hex_sha(self):
        for case, (spec, _) in CASES.items():
            with self.subTest(case=case):
                text = gen.render(spec)
                uses = [line for line in text.split("\n") if "uses:" in line]
                self.assertTrue(uses)
                for line in uses:
                    self.assertRegex(line, r"uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
                steps, errors = action_steps(text)
                self.assertEqual(errors, [])
                self.assertEqual(len(steps), len(uses))

    def test_multi_package_identities_and_tag_families_are_preserved(self):
        text = gen.render(MULTI_SPEC)
        manifest = json.loads((ROOT / "governance" / "pypi" / "pypi-packages.v1.json").read_text(encoding="utf-8"))
        declared = {p["name"]: p for p in manifest["packages"] if p.get("repo") == "szl-evidence-litellm"
                    and p.get("status") == "published"}
        self.assertEqual(set(declared), {"szl-evidence-litellm", "szl-receipts"})
        for name, environment in CASES["multi"][1]:
            entry = declared[name]
            self.assertEqual(entry["github_environment"], environment)
            self.assertEqual(entry["tag_pattern"], f"{gate.norm(name)}-v<version>")
            self.assertEqual(entry["workflow"], ".github/workflows/publish-pypi.yml")
            block = job_block(text, publish_job_id(name, True))
            self.assertIn(f"    if: {RELEASE_ONLY} && needs.build.outputs.package == '{name}'", block)
            self.assertIn(f"      name: {environment}", block)
        self.assertEqual([(p["name"], p["environment"]) for p in gate.parse_packages(MULTI_SPEC)],
                         CASES["multi"][1])

    def test_both_uploads_follow_one_pin_definition(self):
        moved = ("actions/upload-artifact@" + "e" * 40, "v9.9.9")
        with mock.patch.dict(gen.PINS, {"upload": moved}):
            for case, (spec, packages) in CASES.items():
                with self.subTest(case=case):
                    text = gen.render(spec)
                    self.assertEqual(pin_contract_errors(text, packages, upload=moved), [])
                    self.assertNotIn(ACCEPTED_UPLOAD[0], text)
                    self.assertEqual(text.count(f"# actions/upload-artifact {moved[1]}\n"), 2)

    def test_every_download_follows_one_pin_definition(self):
        moved = ("actions/download-artifact@" + "d" * 40, "v9.9.9")
        with mock.patch.dict(gen.PINS, {"download": moved}):
            for case, (spec, packages) in CASES.items():
                with self.subTest(case=case):
                    text = gen.render(spec)
                    self.assertEqual(pin_contract_errors(text, packages, download=moved), [])
                    self.assertNotIn(ACCEPTED_DOWNLOAD[0], text)

    def test_a_conditional_step_must_be_named(self):
        with self.assertRaises(ValueError):
            gen.use("upload", 6, None, RELEASE_ONLY)


class PinDriftIsRejectedTests(unittest.TestCase):
    UPLOAD_SHA = ACCEPTED_UPLOAD[0].split("@")[1]
    DOWNLOAD_SHA = ACCEPTED_DOWNLOAD[0].split("@")[1]

    def assert_rejected(self, text: str, packages, fragment: str):
        errors = pin_contract_errors(text, packages)
        self.assertTrue(errors, "drifted workflow passed the pin contract")
        self.assertTrue(any(fragment in error for error in errors), errors)

    def test_one_upload_pin_drift_fails(self):
        for case, (spec, packages) in CASES.items():
            for nth in (0, 1):  # receipt upload, then distribution upload
                with self.subTest(case=case, upload=nth):
                    text = replace_nth(gen.render(spec), self.UPLOAD_SHA, "f" * 40, nth)
                    self.assert_rejected(text, packages, "uploads do not share")

    def test_one_upload_comment_drift_fails(self):
        for case, (spec, packages) in CASES.items():
            for nth in (0, 1):
                with self.subTest(case=case, upload=nth):
                    text = replace_nth(gen.render(spec), "# actions/upload-artifact v7.0.2\n",
                                       "# actions/upload-artifact v7.0.1\n", nth)
                    self.assert_rejected(text, packages, "is not one PINS entry")

    def test_one_download_pin_drift_fails(self):
        for case, (spec, packages) in CASES.items():
            for nth in range(len(packages)):
                with self.subTest(case=case, download=nth):
                    text = replace_nth(gen.render(spec), self.DOWNLOAD_SHA, "f" * 40, nth)
                    self.assert_rejected(text, packages, "downloads do not all match")

    def test_one_download_comment_drift_fails(self):
        for case, (spec, packages) in CASES.items():
            for nth in range(len(packages)):
                with self.subTest(case=case, download=nth):
                    text = replace_nth(gen.render(spec), "# actions/download-artifact v8.0.2\n",
                                       "# actions/download-artifact v8.0.1\n", nth)
                    self.assert_rejected(text, packages, "is not one PINS entry")

    def test_moved_shas_with_stale_comments_fail(self):
        # The shape seen in consumers whose SHAs were bumped by hand while the
        # version comments kept v7.0.1 / v8.0.1.
        text = gen.render(SINGLE_SPEC).replace("# actions/upload-artifact v7.0.2\n", "# actions/upload-artifact v7.0.1\n")
        text = text.replace("# actions/download-artifact v8.0.2\n", "# actions/download-artifact v8.0.1\n")
        self.assert_rejected(text, CASES["single"][1], "uploads do not share")
        self.assert_rejected(text, CASES["single"][1], "downloads do not all match")

    def test_distribution_upload_left_on_a_literal_old_pin_fails(self):
        # The pre-fix generator wrote the distribution upload as a literal.
        text = replace_nth(gen.render(SINGLE_SPEC), f"{ACCEPTED_UPLOAD[0]}\n", f"actions/upload-artifact@{RETIRED_SHAS[0]}\n", 1)
        text = replace_nth(text, "# actions/upload-artifact v7.0.2\n", "# actions/upload-artifact v7.0.1\n", 1)
        self.assert_rejected(text, CASES["single"][1], "uploads do not share")
        self.assert_rejected(text, CASES["single"][1], "retired SHA")

    def test_short_or_tag_reference_fails(self):
        text = replace_nth(gen.render(SINGLE_SPEC), self.UPLOAD_SHA, "v7.0.2", 1)
        self.assert_rejected(text, CASES["single"][1], "not owner/repo@<40-hex SHA>")
        text = replace_nth(gen.render(SINGLE_SPEC), self.UPLOAD_SHA, self.UPLOAD_SHA[:12], 0)
        self.assert_rejected(text, CASES["single"][1], "not owner/repo@<40-hex SHA>")

    def test_release_condition_drift_fails(self):
        spec, packages = CASES["multi"]
        text = gen.render(spec)
        for label, drifted in (
            ("distribution upload runs outside releases", text.replace(f"        if: {RELEASE_ONLY}\n", "")),
            ("second publish job condition", replace_nth(text, f"    if: {RELEASE_ONLY} && ", "    if: always() && ", 1)),
            ("OIDC permission", text.replace("      id-token: write", "      id-token: none", 1)),
            ("skip-existing", text.replace("          skip-existing: false", "          skip-existing: true", 1)),
            ("attestations", text.replace("          attestations: true", "          attestations: false", 1)),
            ("verify-metadata", text.replace("          verify-metadata: true", "          verify-metadata: false", 1)),
            ("build permission", text.replace("      contents: read", "      contents: write", 1)),
            ("top-level permission", text.replace("\npermissions: {}\n", "\npermissions: write-all\n")),
            ("extra trigger", text.replace("\non:\n", "\non:\n  workflow_dispatch:\n")),
        ):
            with self.subTest(drift=label):
                self.assertNotEqual(drifted, text)
                self.assertTrue(release_contract_errors(drifted, spec, packages))

    def test_canonical_parity_rejects_a_one_line_drift(self):
        canonical = gen.render(CANONICAL_SPEC)
        drifted = replace_nth(canonical, self.UPLOAD_SHA, "f" * 40, 1)
        self.assertNotEqual(drifted, gen.render(CANONICAL_SPEC))


class RealRendererThroughTheAuditorTests(unittest.TestCase):
    """tools/pypi_release_path_audit.py with the shipped renderer, not a stub."""

    WORKFLOW_URL = f"{RAW}/{ORG}/{REPO}/HEAD/.github/workflows/publish-pypi.yml"
    SPEC = f"{PACKAGE}=.:pypi"

    def canonical_status(self, workflow: str) -> str:
        responses = fixture()
        responses[self.WORKFLOW_URL] = (200, workflow.encode("utf-8"))
        results: list[dict] = []
        with redirect_stdout(io.StringIO()):
            audit_release_repo(
                FakeHttp(responses), ORG,
                {"name": PACKAGE, "repo": REPO, "status": "published", "tag_pattern": "v<version>"},
                {"render": gen.render, "gate_sha256": sha256(GATE)},
                results, {},
            )
        rows = {row["check"]: row for row in results}
        self.assertEqual(rows["canonical:workflow-declares-package"]["status"], "PASS")
        self.assertEqual(rows["canonical:workflow-environment"]["status"], "PASS")
        return rows["canonical:workflow"]["status"]

    def test_regenerated_consumer_is_canonical(self):
        workflow = gen.render(self.SPEC)
        self.assertEqual(pin_contract_errors(workflow, [(PACKAGE, "pypi")]), [])
        self.assertEqual(self.canonical_status(workflow), "PASS")

    def test_one_pin_or_comment_drift_in_a_consumer_fails_the_audit(self):
        workflow = gen.render(self.SPEC)
        upload_sha = ACCEPTED_UPLOAD[0].split("@")[1]
        download_sha = ACCEPTED_DOWNLOAD[0].split("@")[1]
        for label, drifted in (
            ("receipt upload pin", replace_nth(workflow, upload_sha, RETIRED_SHAS[0], 0)),
            ("distribution upload pin", replace_nth(workflow, upload_sha, RETIRED_SHAS[0], 1)),
            ("download pin", workflow.replace(download_sha, RETIRED_SHAS[1])),
            ("upload comment", replace_nth(workflow, "upload-artifact v7.0.2", "upload-artifact v7.0.1", 1)),
            ("download comment", workflow.replace("download-artifact v8.0.2", "download-artifact v8.0.1")),
        ):
            with self.subTest(drift=label):
                self.assertNotEqual(drifted, workflow)
                self.assertEqual(self.canonical_status(drifted), "FAIL")


if __name__ == "__main__":
    unittest.main()
