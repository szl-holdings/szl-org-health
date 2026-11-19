"""Every PyPI publisher mapping, rendered by the REAL canonical generator.

governance/pypi/pypi-packages.v1.json declares 43 releasable packages (42
published: the 2026-11-15 release wave plus szl-atelier and szl-drift,
measured live on PyPI on 2026-11-16; szl-cram queued 2026-11-17, held pending
PyPI pending-publisher registration) in 42 repositories, each releasing through exactly one
`.github/workflows/publish-pypi.yml`. CONSUMER_SPECS is the exact SZL_PACKAGES
line of each of those 42 committed workflows, read at each repository's HEAD (36 on
2026-10-14, all then byte-identical to this renderer at org-health 9bf5447;
szl-formulas and szl-provctl on 2026-11-16, both byte-identical to this renderer;
szl-atelier and szl-drift on 2026-11-16, both byte-identical to this renderer;
szl-cram on 2026-11-17, byte-identical to this renderer;
szl-inference-gateway on 2026-11-19, byte-identical to this renderer). The table and the manifest are bound in both directions, so a package
cannot be queued, published or moved without its workflow mapping being stated.

For every mapping the shipped generator renders the workflow and the shipped
auditor compares it byte for byte. One changed pin or one changed version
comment at any single action site must fail both the pin contract and parity.
Release-only permissions and package/tag/environment identity are checked per
package, through the shipped release gate with a synthetic build. Queued
publishers stay inert: the auditor accepts them only while PyPI has no project.

Nothing here runs a packaging tool, uploads or publishes, and no request leaves
the process. Real wheel/sdist builds, `twine check` and the isolated install run
in each consumer's own pull_request build job. PyPI DSSE signatures,
certificate chains, transparency proofs and installed-sdist acceptance are not
evaluated here.
"""
from __future__ import annotations

import collections
import contextlib
import hashlib
import io
import json
import os
import posixpath
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from tests.test_pypi_canonical_generator import (
    CANONICAL_DIR,
    JOB,
    RELEASE_ONLY,
    ROOT,
    action_steps,
    gate,
    gen,
    job_block,
    permissions_of,
    pin_contract_errors,
    publish_job_id,
    release_contract_errors,
)
from tools.pypi_release_path_audit import GH_API, RAW, audit_release_repo, release_tag_family, sha256


MANIFEST = json.loads((ROOT / "governance" / "pypi" / "pypi-packages.v1.json").read_text(encoding="utf-8"))
ORG = MANIFEST["owner"]["github_org"]
WORKFLOW = MANIFEST["release_path"]["workflow"]
GATE_BYTES = (CANONICAL_DIR / "szl_pypi_release_gate.py").read_bytes()
RELEASABLE = ("published", "queued")
VERSION = "1.2.3"

# Exact SZL_PACKAGES line of every committed consumer publish-pypi.yml, keyed by repository.
CONSUMER_SPECS = {
    "a11oy-factory": "a11oy-factory=.:pypi",
    "khipu-consensus": "khipu-consensus=python:pypi",
    "khipu-x1": "khipu-x1=.:pypi",
    "lyte-services": "szl-lyte-enterprise=.:pypi",
    "szl-atelier": "szl-atelier=.:pypi",
    "szl-calibration": "szl-calibration=.:pypi",
    "szl-ci-witness": "szl-ci-witness=.:pypi",
    "szl-cram": "szl-cram=.:pypi",
    "szl-crosscheck": "szl-crosscheck=.:pypi",
    "szl-drift": "szl-drift=.:pypi",
    "szl-eclipse": "szl-eclipse=.:pypi",
    "szl-energy-attest": "szl-energy-attest=.:pypi",
    "szl-engine-bench": "szl-engine-bench=.:pypi",
    "szl-evidence-litellm": (
        "szl-receipts=packages/szl-receipts:pypi;"
        "szl-evidence-litellm=packages/szl-evidence-litellm:pypi-litellm"
    ),
    "szl-evidence-mandate": "szl-evidence-mandate=.:pypi",
    "szl-formulas": "szl-formulas=.:pypi",
    "szl-frontier": "szl-frontier-control-plane=.:pypi",
    "szl-guardrail-receipt": "szl-guardrail-receipt=.:pypi",
    "szl-inference-gateway": "szl-inference-gateway=.:pypi",
    "szl-invariants": "szl-invariants=.:pypi",
    "szl-kernels": "szl-kernels=.:pypi",
    "szl-khipu": "szl-khipu=.:pypi",
    "szl-mesh": "szl-mesh=.:pypi",
    "szl-nemo": "szl-nemo=.:pypi",
    "szl-openshell-receipts": "szl-openshell-receipts=.:pypi",
    "szl-ouroboros": "szl-ouroboros=.:pypi",
    "szl-pin": "szl-pin=.:pypi",
    "szl-provctl": "szl-provctl=.:pypi",
    "szl-quant-bench": "szl-quant-bench=.:pypi",
    "szl-real-estate": "szl-re=.:pypi",
    "szl-receipt": "szl-receipt-dsse=.:pypi",
    "szl-retrieval-bench": "szl-retrieval-bench=.:pypi",
    "szl-router": "szl-router=.:pypi",
    "szl-second-brain": "szl-second-brain=.:pypi",
    "szl-serve": "szl-serve=.:pypi",
    "szl-sovereign-os": "szl-os=.:pypi",
    "szl-substrate": "szl-substrate=.:pypi",
    "szl-typesafe-triage": "szl-triage=.:pypi",
    "szl-vertical-forge": "szl-vertical-forge=.:pypi",
    "szl-wave1-report": "szl-wave1-report=.:pypi",
    "vsp-otel": "vsp-otel=.:pypi",
    "yarqa": "yarqa=.:pypi",
}

USES_SITE = re.compile(r"^(?P<lead> {6}- | {8})uses: (?P<action>[^@\s]+)@(?P<sha>[0-9a-f]{40})$")
COMMENT_SITE = re.compile(r"^(?P<pad> {6})# (?P<action>\S+) v(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")
PACKAGE_CLAUSE = re.compile(r"^needs\.build\.outputs\.package == '(?P<name>[^']*)'$")


def releasable() -> list[dict]:
    return [m for m in MANIFEST["packages"] if m.get("status") in RELEASABLE]


def manifest_by_repo() -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = collections.defaultdict(list)
    for m in releasable():
        grouped[m["repo"]].append(m)
    return dict(grouped)


def manifest_entry(name: str) -> dict:
    matches = [m for m in releasable() if m["name"] == name]
    if len(matches) != 1:
        raise AssertionError(f"{name}: {len(matches)} releasable manifest entries")
    return matches[0]


def spec_packages(repo: str) -> list[tuple[str, str]]:
    """(name, environment) in workflow order, the environment taken from the manifest."""
    return [(p["name"], manifest_entry(p["name"])["github_environment"]) for p in gen.parse(CONSUMER_SPECS[repo])]


def expected_directory(m: dict) -> str:
    return posixpath.dirname(m["path"]) or "."


def expected_tag_pattern(name: str, multi: bool) -> str:
    return f"{gate.norm(name)}-v<version>" if multi else "v<version>"


def job_ids(text: str) -> list[str]:
    lines = text.split("\n")
    return [JOB.match(line)["job"] for line in lines[lines.index("jobs:") + 1:] if JOB.match(line)]


def job_condition(text: str, job: str) -> str | None:
    found = [line[len("    if: "):] for line in job_block(text, job) if line.startswith("    if: ")]
    if len(found) > 1:
        raise AssertionError(f"{job}: {len(found)} job conditions")
    return found[0] if found else None


def job_runs(condition: str | None, event: str, package: str) -> bool:
    """Evaluate the only two clause shapes the canonical publish jobs may carry."""
    if condition is None:
        return True
    for clause in condition.split(" && "):
        named = PACKAGE_CLAUSE.match(clause)
        if clause == RELEASE_ONLY:
            ok = event == "release"
        elif named:
            ok = package == named["name"]
        else:
            raise AssertionError(f"unrecognized publish condition clause {clause!r}")
        if not ok:
            return False
    return True


def environment_of(text: str, job: str) -> str | None:
    block = job_block(text, job)
    if "    environment:" not in block:
        return None
    line = block[block.index("    environment:") + 1]
    return line[len("      name: "):] if line.startswith("      name: ") else None


def mutations(text: str) -> list[tuple[str, int, str]]:
    """One single-site drift per action pin and per version comment."""
    lines = text.split("\n")
    found = []
    for index, line in enumerate(lines):
        used = USES_SITE.match(line)
        if used:
            moved = hashlib.sha256(used["sha"].encode("ascii")).hexdigest()[:40]
            changed = lines[:index] + [line.replace(used["sha"], moved)] + lines[index + 1:]
            found.append(("pin", index + 1, "\n".join(changed)))
            continue
        comment = COMMENT_SITE.match(line)
        if comment:
            bumped = f"{comment['pad']}# {comment['action']} v{comment['major']}.{comment['minor']}.{int(comment['patch']) + 1}"
            changed = lines[:index] + [bumped] + lines[index + 1:]
            found.append(("comment", index + 1, "\n".join(changed)))
    return found


class ReadbackHttp:
    """In-process readback of one consumer: its workflow and gate bytes, nothing else."""

    def __init__(self, repo: str, workflow: bytes, pypi_status: int = 503):
        self.repo = repo
        self.workflow = workflow
        self.pypi_status = pypi_status
        self.calls: list[str] = []

    def get(self, url: str, accept: str | None = None, raw: bool = False):
        self.calls.append(url)
        base = f"{RAW}/{ORG}/{self.repo}/HEAD/"
        if url == base + ".github/workflows/publish-pypi.yml":
            return 200, self.workflow
        if url == base + ".github/scripts/szl_pypi_release_gate.py":
            return 200, GATE_BYTES
        if url.startswith(f"{GH_API}/repos/{ORG}/{self.repo}/"):
            return 503, None
        if re.fullmatch(r"https://pypi\.org/pypi/[a-z0-9-]+/json", url):
            return self.pypi_status, ({"info": {}} if self.pypi_status == 200 else None)
        raise AssertionError(f"unexpected request: {url}")


def audit(m: dict, workflow: bytes, pypi_status: int = 503) -> tuple[dict[str, dict], ReadbackHttp]:
    http = ReadbackHttp(m["repo"], workflow, pypi_status)
    results: list[dict] = []
    with contextlib.redirect_stdout(io.StringIO()):
        audit_release_repo(http, ORG, m, {"render": gen.render, "gate_sha256": sha256(GATE_BYTES)}, results, {})
    rows: dict[str, dict] = {}
    for row in results:
        if row["check"] in rows:
            raise AssertionError(f"{m['name']}: duplicate check {row['check']}")
        rows[row["check"]] = row
    return rows, http


def canonical_statuses(rows: dict[str, dict]) -> dict[str, str]:
    return {check: row["status"] for check, row in rows.items() if check.startswith("canonical:")}


ALL_CANONICAL_PASS = {
    "canonical:workflow": "PASS",
    "canonical:gate": "PASS",
    "canonical:workflow-declares-package": "PASS",
    "canonical:workflow-environment": "PASS",
}


class PublisherMappingCensusTests(unittest.TestCase):
    def test_manifest_declares_43_packages_in_42_workflows(self):
        packages = releasable()
        self.assertEqual(len(packages), 43)
        self.assertEqual(len({(m["repo"], m["workflow"]) for m in packages}), 42)
        self.assertEqual(
            collections.Counter(m["status"] for m in packages),
            {"published": 42, "queued": 1},
        )
        self.assertEqual({m["workflow"] for m in packages}, {WORKFLOW})
        self.assertEqual(WORKFLOW, ".github/workflows/publish-pypi.yml")
        self.assertEqual(len({m["name"] for m in packages}), 43)

    def test_every_releasable_package_has_exactly_one_workflow_mapping(self):
        grouped = manifest_by_repo()
        self.assertEqual(sorted(CONSUMER_SPECS), sorted(grouped))
        declared = collections.Counter(p["name"] for spec in CONSUMER_SPECS.values() for p in gen.parse(spec))
        self.assertEqual(set(declared.values()), {1}, f"declared more than once: {declared}")
        self.assertEqual(set(declared), {m["name"] for m in releasable()})
        for repo, entries in grouped.items():
            with self.subTest(repo=repo):
                self.assertEqual(sorted(p["name"] for p in gen.parse(CONSUMER_SPECS[repo])),
                                 sorted(m["name"] for m in entries))

    def test_every_spec_binds_directory_environment_tag_and_workflow(self):
        for repo, spec in CONSUMER_SPECS.items():
            parsed = gen.parse(spec)
            multi = len(parsed) > 1
            with self.subTest(repo=repo):
                # the renderer and the release gate read SZL_PACKAGES identically
                self.assertEqual(parsed, gate.parse_packages(spec))
                self.assertEqual(spec, ";".join(f"{p['name']}={p['dir']}:{p['environment']}" for p in parsed))
            for p in parsed:
                m = manifest_entry(p["name"])
                with self.subTest(repo=repo, package=p["name"]):
                    self.assertEqual(m["repo"], repo)
                    self.assertEqual(posixpath.basename(m["path"]), "pyproject.toml")
                    self.assertEqual(p["dir"], expected_directory(m))
                    self.assertEqual(p["environment"], m["github_environment"])
                    self.assertEqual(m["tag_pattern"], expected_tag_pattern(p["name"], multi))
                    self.assertIsNotNone(release_tag_family(m))
                    self.assertEqual(m["source"], f"https://github.com/{ORG}/{repo}")

    def test_mapping_shapes_cover_root_subdirectory_and_dual_packages(self):
        shapes: dict[str, list[str]] = collections.defaultdict(list)
        for repo, spec in CONSUMER_SPECS.items():
            parsed = gen.parse(spec)
            shape = "dual" if len(parsed) == 2 else "root" if parsed[0]["dir"] == "." else "subdirectory"
            self.assertLessEqual(len(parsed), 2, repo)
            shapes[shape].append(repo)
        self.assertEqual({shape: len(repos) for shape, repos in shapes.items()},
                         {"root": 40, "subdirectory": 1, "dual": 1})
        self.assertEqual(shapes["subdirectory"], ["khipu-consensus"])
        self.assertEqual(shapes["dual"], ["szl-evidence-litellm"])


class RenderedPublisherContractTests(unittest.TestCase):
    def test_every_workflow_meets_the_pin_contract(self):
        for repo, spec in CONSUMER_SPECS.items():
            with self.subTest(repo=repo):
                self.assertEqual(pin_contract_errors(gen.render(spec), spec_packages(repo)), [])

    def test_every_workflow_keeps_release_only_permissions_and_identity(self):
        for repo, spec in CONSUMER_SPECS.items():
            text = gen.render(spec)
            packages = spec_packages(repo)
            multi = len(packages) > 1
            with self.subTest(repo=repo):
                self.assertEqual(release_contract_errors(text, spec, packages), [])
                self.assertEqual(job_ids(text), ["build"] + [publish_job_id(n, multi) for n, _ in packages])
                self.assertIsNone(job_condition(text, "build"))
                self.assertEqual(permissions_of(job_block(text, "build")), ["      contents: read"])
                self.assertIsNone(environment_of(text, "build"))
            for name, environment in packages:
                job = publish_job_id(name, multi)
                with self.subTest(repo=repo, package=name):
                    # the OIDC grant exists only in a job that cannot run outside a release
                    self.assertIn("id-token: write", "\n".join(permissions_of(job_block(text, job))))
                    self.assertTrue(job_condition(text, job).startswith(RELEASE_ONLY))
                    self.assertFalse(job_runs(job_condition(text, job), "pull_request", name))
                    self.assertFalse(job_runs(job_condition(text, job), "push", name))
                    self.assertEqual(environment_of(text, job), environment)
                    self.assertIn(f"      url: https://pypi.org/project/{name}/${{{{ needs.build.outputs.version }}}}/",
                                  job_block(text, job))

    def test_every_pin_moves_every_site_that_uses_it(self):
        for key, (ref, version) in gen.PINS.items():
            action = ref.split("@")[0]
            moved = (f"{action}@{hashlib.sha256(ref.encode('ascii')).hexdigest()[:40]}", "v99.0.0")
            with mock.patch.dict(gen.PINS, {key: moved}):
                for repo, spec in CONSUMER_SPECS.items():
                    packages = spec_packages(repo)
                    sites = {"checkout": 1, "setup_python": 1,
                             "upload": 3 if repo == "szl-evidence-mandate" else 2,
                             "download": len(packages), "publish": len(packages)}[key]
                    text = gen.render(spec)
                    with self.subTest(pin=key, repo=repo):
                        self.assertEqual(text.count(f"uses: {moved[0]}\n"), sites)
                        self.assertEqual(text.count(f"# {action} {moved[1]}\n"), sites)
                        self.assertNotIn(ref, text)
                        self.assertNotIn(f"# {action} {version}\n", text)
                        upload = gen.PINS["upload"]
                        download = gen.PINS["download"]
                        self.assertEqual(pin_contract_errors(text, packages, upload=upload, download=download), [])


class ConsumerParityTests(unittest.TestCase):
    """tools/pypi_release_path_audit.py with the shipped renderer for every package."""

    def test_every_regenerated_consumer_passes_for_each_package(self):
        for m in releasable():
            workflow = gen.render(CONSUMER_SPECS[m["repo"]]).encode("utf-8")
            with self.subTest(package=m["name"]):
                rows, _ = audit(m, workflow)
                self.assertEqual(canonical_statuses(rows), ALL_CANONICAL_PASS)

    def test_every_single_site_pin_or_comment_drift_fails(self):
        checked = collections.Counter()
        expected = collections.Counter()
        for repo, spec in CONSUMER_SPECS.items():
            packages = spec_packages(repo)
            text = gen.render(spec)
            steps, errors = action_steps(text)
            self.assertEqual(errors, [])
            self.assertEqual(len(steps), 4 + 2 * len(packages) + (1 if repo == "szl-evidence-mandate" else 0))
            expected["pin"] += len(steps)
            expected["comment"] += len(steps)
            for kind, line, drifted in mutations(text):
                with self.subTest(repo=repo, kind=kind, line=line):
                    self.assertNotEqual(drifted, text)
                    self.assertTrue(pin_contract_errors(drifted, packages), "drift passed the pin contract")
                    for name, _ in packages:
                        rows, _ = audit(manifest_entry(name), drifted.encode("utf-8"))
                        self.assertEqual(canonical_statuses(rows), {**ALL_CANONICAL_PASS, "canonical:workflow": "FAIL"})
                checked[kind] += 1
        self.assertEqual(checked, expected)
        # The explicit evidence-mandate SBOM adds one shared-pin upload site.
        self.assertEqual(checked, {"pin": 255, "comment": 255})

    def test_one_byte_and_line_ending_drift_fail(self):
        for repo, spec in CONSUMER_SPECS.items():
            text = gen.render(spec)
            for label, drifted in (
                ("CRLF", text.replace("\n", "\r\n")),
                ("trailing newline", text + "\n"),
                ("missing final newline", text[:-1]),
                ("trailing space", text.replace("    steps:\n", "    steps: \n", 1)),
            ):
                for name, _ in spec_packages(repo):
                    with self.subTest(repo=repo, drift=label, package=name):
                        rows, _ = audit(manifest_entry(name), drifted.encode("utf-8"))
                        self.assertEqual(rows["canonical:workflow"]["status"], "FAIL")

    def test_environment_and_package_identity_drift_fail(self):
        dual = gen.render(CONSUMER_SPECS["szl-evidence-litellm"])
        litellm = manifest_entry("szl-evidence-litellm")
        receipts = manifest_entry("szl-receipts")
        # a hand edit of one environment breaks parity
        rows, _ = audit(litellm, dual.replace("      name: pypi-litellm\n", "      name: pypi\n").encode("utf-8"))
        self.assertEqual(rows["canonical:workflow"]["status"], "FAIL")
        # a consistently regenerated workflow with the wrong environment still fails identity
        swapped = gen.render("szl-receipts=packages/szl-receipts:pypi;"
                             "szl-evidence-litellm=packages/szl-evidence-litellm:pypi")
        rows, _ = audit(litellm, swapped.encode("utf-8"))
        self.assertEqual(rows["canonical:workflow"]["status"], "PASS")
        self.assertEqual(rows["canonical:workflow-environment"]["status"], "FAIL")
        rows, _ = audit(receipts, swapped.encode("utf-8"))
        self.assertEqual(rows["canonical:workflow-environment"]["status"], "PASS")
        # a consistently regenerated workflow that names another package fails identity
        for m in releasable():
            other = next(o for o in releasable() if o["repo"] != m["repo"])
            foreign = gen.render(f"{other['name']}=.:{m['github_environment']}")
            with self.subTest(package=m["name"]):
                rows, _ = audit(m, foreign.encode("utf-8"))
                self.assertEqual(rows["canonical:workflow-declares-package"]["status"], "FAIL")


@contextlib.contextmanager
def consumer_checkout(repo: str):
    """A throwaway checkout holding a minimal pyproject.toml at each declared directory."""
    with tempfile.TemporaryDirectory(prefix="szl-pypi-mapping-") as directory:
        root = Path(directory)
        checkout = root / "checkout"
        for p in gen.parse(CONSUMER_SPECS[repo]):
            package_dir = checkout / p["dir"]
            package_dir.mkdir(parents=True, exist_ok=True)
            (package_dir / "pyproject.toml").write_text("\n".join([
                "[build-system]",
                'requires = ["setuptools>=69"]',
                'build-backend = "setuptools.build_meta"',
                "[project]",
                f'name = "{p["name"]}"',
                f'version = "{VERSION}"',
                'description = "inert mapping fixture"',
                'readme = "README.md"',
                'requires-python = ">=3.10"',
                'license = "Apache-2.0"',
                "[project.urls]",
                f'Source = "https://github.com/{ORG}/{repo}"',
                "",
            ]), encoding="utf-8")
        with contextlib.chdir(checkout):
            yield root


class SyntheticBuild:
    """Stands in for every gate subprocess: `-m build` writes one wheel and one sdist; the rest is a no-op."""

    def __init__(self):
        self.commands: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        self.commands.append(list(cmd))
        if cmd[1:3] == ["-m", "build"]:
            stage, source = Path(cmd[cmd.index("--outdir") + 1]), Path(cmd[-1])
            with open(source / "pyproject.toml", "rb") as stream:
                project = tomllib.load(stream)["project"]
            dist = re.sub(r"[-_.]+", "_", project["name"]).lower()
            metadata = (f"Metadata-Version: 2.4\nName: {project['name']}\nVersion: {project['version']}\n"
                        f"Project-URL: Source, {project['urls']['Source']}\n\n")
            with zipfile.ZipFile(stage / f"{dist}-{project['version']}-py3-none-any.whl", "w") as wheel:
                wheel.writestr(f"{dist}/__init__.py", "")
                wheel.writestr(f"{dist}-{project['version']}.dist-info/METADATA", metadata)
            with tarfile.open(stage / f"{dist}-{project['version']}.tar.gz", "w:gz") as sdist:
                info = tarfile.TarInfo(f"{dist}-{project['version']}/PKG-INFO")
                info.size = len(metadata.encode("utf-8"))
                sdist.addfile(info, io.BytesIO(metadata.encode("utf-8")))
        return subprocess.CompletedProcess(cmd, 0)


def run_gate(repo: str, event: str, ref_type: str, ref_name: str, spec: str | None = None) -> dict:
    """Run the shipped release gate's main() for one consumer with no packaging tool and no network."""
    build = SyntheticBuild()
    with consumer_checkout(repo) as root:
        output = root / "github-output"
        output.write_text("", encoding="utf-8")
        argv = ["szl_pypi_release_gate.py", "--packages", spec or CONSUMER_SPECS[repo], "--repo", f"{ORG}/{repo}",
                "--event", event, "--ref-type", ref_type, "--ref-name", ref_name, "--outdir", "dist"]
        environ = {k: v for k, v in os.environ.items() if k not in ("GITHUB_SHA", "GITHUB_RUN_ID")}
        environ["GITHUB_OUTPUT"] = str(output)
        exit_code = 0
        with mock.patch.object(sys, "argv", argv), mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(gate, "sh", build), mock.patch.object(gate, "pypi_versions", return_value=set()), \
                contextlib.redirect_stdout(io.StringIO()):
            try:
                gate.main()
            except SystemExit as stop:
                exit_code = stop.code
        dist = root / "checkout" / "dist"
        files = sorted(str(f.relative_to(dist)).replace(os.sep, "/") for f in dist.rglob("*") if f.is_file()) if dist.is_dir() else []
        outputs = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines() if line)
        built = [Path(c[-1]).resolve().relative_to((root / "checkout").resolve()).as_posix() for c in build.commands
                 if c[1:3] == ["-m", "build"]]
    return {"exit": exit_code, "outputs": outputs, "files": files, "built": built,
            "uploads": [c for c in build.commands if "upload" in c]}


def tag_for(name: str) -> str:
    return manifest_entry(name)["tag_pattern"].replace("<version>", VERSION)


class ReleaseGateIdentityTests(unittest.TestCase):
    """The shipped gate selects, binds and hands over exactly the declared package."""

    def test_every_release_tag_selects_exactly_its_package_and_environment(self):
        for m in releasable():
            repo, name = m["repo"], m["name"]
            text = gen.render(CONSUMER_SPECS[repo])
            multi = len(gen.parse(CONSUMER_SPECS[repo])) > 1
            dist = re.sub(r"[-_.]+", "_", name).lower()
            with self.subTest(package=name):
                result = run_gate(repo, "release", "tag", tag_for(name))
                self.assertEqual(result["exit"], 0)
                self.assertEqual(result["outputs"], {"package": name, "version": VERSION,
                                                     "environment": m["github_environment"]})
                self.assertEqual(result["built"], [expected_directory(m)])
                self.assertEqual(result["files"], [f"{dist}-{VERSION}-py3-none-any.whl", f"{dist}-{VERSION}.tar.gz"])
                self.assertEqual(result["uploads"], [])
                runnable = [job for job in job_ids(text)[1:]
                            if job_runs(job_condition(text, job), "release", result["outputs"]["package"])]
                self.assertEqual(runnable, [publish_job_id(name, multi)])
                self.assertEqual(environment_of(text, runnable[0]), result["outputs"]["environment"])

    def test_wrong_version_and_foreign_tags_are_refused(self):
        for m in releasable():
            repo, name = m["repo"], m["name"]
            others = [o["name"] for o in releasable() if o["repo"] != repo]
            for tag in (tag_for(name).replace(VERSION, "1.2.4"), f"{gate.norm(others[0])}-v{VERSION}", VERSION):
                with self.subTest(package=name, tag=tag):
                    result = run_gate(repo, "release", "tag", tag)
                    self.assertEqual(result["exit"], 1)
                    self.assertEqual(result["outputs"], {})
                    self.assertEqual(result["files"], [])
        # a release must come from a tag, and a two-package repository needs <package>-v<version>
        self.assertEqual(run_gate("szl-pin", "release", "branch", "main")["exit"], 1)
        for tag in (f"v{VERSION}", f"szl-evidence-v{VERSION}", f"szl-receipts-{VERSION}"):
            with self.subTest(tag=tag):
                result = run_gate("szl-evidence-litellm", "release", "tag", tag)
                self.assertEqual((result["exit"], result["outputs"], result["built"]), (1, {}, []))

    def test_pull_request_and_push_gate_every_package_without_release_outputs(self):
        for repo, spec in CONSUMER_SPECS.items():
            parsed = gen.parse(spec)
            text = gen.render(spec)
            for event, ref_type, ref_name in (("pull_request", "branch", "1/merge"), ("push", "branch", "main")):
                with self.subTest(repo=repo, event=event):
                    result = run_gate(repo, event, ref_type, ref_name)
                    self.assertEqual(result["exit"], 0)
                    self.assertEqual(result["built"], [p["dir"] for p in parsed])
                    self.assertEqual(result["outputs"], {})
                    # readiness copies land in dist/<package>/, never at the dist/*.whl / dist/*.tar.gz upload paths
                    self.assertFalse([f for f in result["files"] if "/" not in f])
                    for p in parsed:
                        dist = re.sub(r"[-_.]+", "_", p["name"]).lower()
                        self.assertEqual([f for f in result["files"] if f.startswith(gate.norm(p["name"]) + "/")],
                                         [f"{gate.norm(p['name'])}/{dist}-{VERSION}-py3-none-any.whl",
                                          f"{gate.norm(p['name'])}/{dist}-{VERSION}.tar.gz"])
                    self.assertEqual(result["uploads"], [])
                    self.assertEqual([job for job in job_ids(text)[1:] if job_runs(job_condition(text, job), event, "")], [])

    def test_directory_and_name_must_agree(self):
        # szl-receipts pointed at the szl-evidence-litellm directory is refused before any build
        swapped = ("szl-receipts=packages/szl-evidence-litellm:pypi;"
                   "szl-evidence-litellm=packages/szl-receipts:pypi-litellm")
        for name in ("szl-receipts", "szl-evidence-litellm"):
            with self.subTest(package=name):
                result = run_gate("szl-evidence-litellm", "release", "tag", tag_for(name), spec=swapped)
                self.assertEqual((result["exit"], result["outputs"], result["built"], result["files"]), (1, {}, [], []))


class QueuedPublisherInertTests(unittest.TestCase):
    def test_queued_publishers_pass_only_while_pypi_has_no_project(self):
        # szl-cram was queued on 2026-11-17 (first tag held pending PyPI
        # pending-publisher registration), so the census holds a real queued
        # subject; a published entry is additionally synthesized so the
        # fail-closed inertness contract stays covered regardless of census state.
        queued = [m for m in releasable() if m["status"] == "queued"]
        queued += [dict(m, status="queued") for m in releasable() if m["status"] == "published"][:1]
        self.assertTrue(queued)
        for m in queued:
            workflow = gen.render(CONSUMER_SPECS[m["repo"]]).encode("utf-8")
            for status, verdict in ((404, "PASS"), (200, "FAIL"), (503, "UNKNOWN"), (403, "UNKNOWN")):
                with self.subTest(package=m["name"], pypi=status):
                    rows, http = audit(m, workflow, pypi_status=status)
                    self.assertEqual(rows["pypi:not-yet-published"]["status"], verdict)
                    self.assertEqual(canonical_statuses(rows), ALL_CANONICAL_PASS)
                    self.assertNotIn("pypi:project", rows)
                    self.assertFalse([url for url in http.calls if "/simple/" in url or "/integrity/" in url])

    def test_published_packages_are_never_audited_as_queued(self):
        for m in (m for m in releasable() if m["status"] == "published"):
            with self.subTest(package=m["name"]):
                rows, _ = audit(m, gen.render(CONSUMER_SPECS[m["repo"]]).encode("utf-8"), pypi_status=404)
                self.assertNotIn("pypi:not-yet-published", rows)
                self.assertEqual(rows["pypi:project"]["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
