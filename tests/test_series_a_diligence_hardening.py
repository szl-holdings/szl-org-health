from __future__ import annotations

import contextlib
import copy
import datetime as dt
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from build_series_a_diligence import (
    _atomic_write_pair,
    _guard_distinct_paths,
    _pair_lock,
    main,
)
from census.diligence import (
    SOURCE_BOUND_PATHS,
    DiligenceError,
    _load_policy,
    _parse_timestamp,
    _verify_compiler_source_revision,
    canonical_bytes,
    compile_diligence,
    strict_load_json,
    validate_artifact,
)
from scripts.verify_series_a_schema_contract import (
    ContractError as SchemaContractError,
    Draft202012Validator as SchemaContractValidator,
    assert_supported_schema,
    verify as verify_schema_contract,
)
from tests.test_series_a_diligence import (
    AS_OF,
    ROOT,
    SHA,
    passing_report,
    public_cli_report,
)


class SeriesADiligenceHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = strict_load_json(ROOT / "diligence" / "policy.json")

    def compile(self, report: dict, *, as_of: str = AS_OF) -> dict:
        return compile_diligence(
            report,
            compiler_source_revision=None,
            policy=self.policy,
            as_of=as_of,
        )

    def test_cli_bootstraps_repository_package_in_isolated_mode(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(ROOT / "build_series_a_diligence.py"),
                "--help",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Build or verify a source-bound Series-A", completed.stdout)

    def test_isolated_loader_does_not_import_repository_stdlib_shadows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (
                "build_series_a_diligence.py",
                "census/__init__.py",
                "census/diligence.py",
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / relative).read_bytes())
            marker = root / "repository-shadow-loaded"
            poison = (
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('loaded', encoding='utf-8')\n"
                "raise RuntimeError('repository stdlib shadow imported')\n"
            )
            for name in ("datetime.py", "subprocess.py"):
                (root / name).write_text(poison, encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(root / "build_series_a_diligence.py"),
                    "--help",
                ],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(marker.exists())

    def redigest(self, artifact: dict) -> dict:
        artifact.pop("digest_sha256", None)
        artifact["digest_sha256"] = hashlib.sha256(
            canonical_bytes(artifact)
        ).hexdigest()
        return artifact

    def test_kind_specific_collection_and_bucket_shapes_are_measured(self) -> None:
        report = passing_report()
        assets = report["sources"]["huggingface"]["data"]["assets"]
        assets["collections"] = {
            "ok": True,
            "count": 1,
            "items": [
                {
                    "slug": "SZLHOLDINGS/investor-diligence",
                    "private": False,
                    "complete": True,
                    "detail_error": None,
                }
            ],
        }
        assets["buckets"] = {
            "ok": True,
            "count": 1,
            "items": [
                {
                    "id": "SZLHOLDINGS/evidence-bucket",
                    "private": False,
                    "tree_state": "OBSERVED",
                    "tree_error": None,
                }
            ],
        }

        artifact = self.compile(report)
        hf = artifact["inventory"]["huggingface"]
        self.assertEqual(hf["subinventory_states"]["collections"], "MEASURED")
        self.assertEqual(hf["subinventory_states"]["buckets"], "MEASURED")
        self.assertEqual(hf["counts"]["collections"], 1)
        self.assertEqual(hf["counts"]["buckets"], 1)
        self.assertNotIn("SZLHOLDINGS/investor-diligence", hf["invalid_revision_ids"])
        self.assertNotIn("SZLHOLDINGS/evidence-bucket", hf["invalid_revision_ids"])
        self.assertEqual(validate_artifact(artifact), [])

    def test_partial_collections_and_collection_only_buckets_fail_closed(self) -> None:
        report = passing_report()
        assets = report["sources"]["huggingface"]["data"]["assets"]
        assets["collections"] = {
            "ok": True,
            "count": 1,
            "items": [
                {
                    "slug": "SZLHOLDINGS/partial",
                    "private": False,
                    "complete": False,
                    "detail_error": None,
                }
            ],
        }
        artifact = self.compile(report)
        self.assertEqual(
            artifact["inventory"]["huggingface"]["subinventory_states"]["collections"],
            "UNAVAILABLE",
        )
        self.assertEqual(artifact["inventory"]["huggingface"]["state"], "UNAVAILABLE")
        self.assertEqual(artifact["governed_agent_bench"]["state"], "MEASURED")
        self.assertEqual(validate_artifact(artifact), [])

        report = passing_report()
        assets = report["sources"]["huggingface"]["data"]["assets"]
        assets["buckets"] = {
            "ok": True,
            "count": 1,
            "items": [
                {
                    "id": "SZLHOLDINGS/referenced-only",
                    "private": False,
                    "tree_state": "OBSERVED",
                    "tree_error": None,
                    "discovered_via": "collection",
                }
            ],
        }
        artifact = self.compile(report)
        self.assertEqual(
            artifact["inventory"]["huggingface"]["subinventory_states"]["buckets"],
            "UNAVAILABLE",
        )
        self.assertEqual(artifact["inventory"]["huggingface"]["state"], "UNAVAILABLE")
        self.assertEqual(artifact["governed_agent_bench"]["state"], "MEASURED")
        self.assertEqual(validate_artifact(artifact), [])

    def test_kind_specific_identity_and_revision_fail_closed(self) -> None:
        cases = []

        collection = passing_report()
        collection["sources"]["huggingface"]["data"]["assets"]["collections"] = {
            "ok": True,
            "count": 1,
            "items": [{"id": "SZLHOLDINGS/not-a-slug", "private": False}],
        }
        cases.append(("collections", collection))

        bucket = passing_report()
        bucket["sources"]["huggingface"]["data"]["assets"]["buckets"] = {
            "ok": True,
            "count": 1,
            "items": [
                {
                    "id": "SZLHOLDINGS/bucket",
                    "private": False,
                    "tree_state": "OBSERVED",
                    "tree_error": None,
                    "sha": "not-required-and-ignored",
                }
            ],
        }
        cases.append(("buckets-control", bucket))

        model = passing_report()
        model["sources"]["huggingface"]["data"]["assets"]["models"]["items"][0].pop(
            "sha"
        )
        cases.append(("models", model))

        for name, report in cases:
            with self.subTest(name=name):
                artifact = self.compile(report)
                if name == "buckets-control":
                    self.assertEqual(
                        artifact["inventory"]["huggingface"]["subinventory_states"][
                            "buckets"
                        ],
                        "MEASURED",
                    )
                else:
                    self.assertEqual(
                        artifact["inventory"]["huggingface"]["subinventory_states"][
                            name
                        ],
                        "DIVERGENT",
                    )
                self.assertEqual(validate_artifact(artifact), [])

    def test_collector_preserves_collection_bucket_references_without_fabrication(
        self,
    ) -> None:
        import census.huggingface as hf

        def fake_paginate(path: str, timeout: float = 30.0, retries: int = 2):
            del timeout, retries
            if "/collections" in path:
                return ([{"slug": "SZLHOLDINGS/collection"}], None)
            if "/buckets" in path:
                return (None, "direct listing unavailable")
            return ([], None)

        full_collection = (
            {
                "slug": "SZLHOLDINGS/collection",
                "private": False,
                "complete": True,
                "detail_error": None,
                "items": [{"id": "SZLHOLDINGS/referenced-bucket", "type": "bucket"}],
            },
            {"SZLHOLDINGS/referenced-bucket"},
        )
        with (
            mock.patch.object(hf, "hf_paginate", side_effect=fake_paginate),
            mock.patch.object(hf, "_full_collection", return_value=full_collection),
        ):
            result = hf.collect_huggingface()

        self.assertEqual(
            result["collection_bucket_references"],
            ["SZLHOLDINGS/referenced-bucket"],
        )
        self.assertFalse(result["assets"]["buckets"]["ok"])
        self.assertIsNone(result["assets"]["buckets"]["count"])
        self.assertEqual(result["assets"]["buckets"]["items"], [])
        self.assertIn("preserved separately", result["assets"]["buckets"]["error"])

    def test_benchmark_requires_every_cross_bound_primitive(self) -> None:
        baseline = self.compile(passing_report())
        self.assertEqual(baseline["governed_agent_bench"]["state"], "MEASURED")
        self.assertEqual(validate_artifact(baseline), [])

        sensitive_receipt = "hf_" + "A" * 24
        mutations = (
            ("healthz-contract", "healthz_contract", False, False),
            ("dataset-revision", "eval_dataset_revision", "c" * 40, "c" * 40),
            ("space-revision", "eval_space_revision", "d" * 40, "d" * 40),
            ("output-revision", "eval_output_revision", None, None),
            ("output-sha-malformed", "eval_output_sha256", "not-a-sha", None),
            ("output-sha-all-zero", "eval_output_sha256", "0" * 64, None),
            ("receipt-malformed", "eval_receipt_id", "receipt contains spaces", None),
            ("receipt-sensitive", "eval_receipt_id", sensitive_receipt, None),
            ("http-zero", "http", 0, None),
            (
                "reproduction-state",
                "eval_reproduction_state",
                "CALLER_ASSERTED",
                None,
            ),
        )
        for name, field, replacement, expected_summary in mutations:
            with self.subTest(name=name):
                report = passing_report()
                space = report["sources"]["huggingface"]["data"]["assets"]["spaces"][
                    "items"
                ][0]
                space[field] = replacement
                artifact = self.compile(report)
                self.assertEqual(artifact["governed_agent_bench"]["state"], "BLOCKED")
                self.assertEqual(
                    artifact["governed_agent_bench"]["space"][field],
                    expected_summary,
                )
                self.assertEqual(validate_artifact(artifact), [])
                self.assertNotIn(
                    sensitive_receipt,
                    canonical_bytes(artifact).decode("utf-8"),
                )

    def test_unrelated_hf_subinventory_failure_does_not_erase_benchmark_evidence(
        self,
    ) -> None:
        report = passing_report()
        report["sources"]["huggingface"]["data"]["assets"]["collections"] = {
            "ok": False,
            "count": None,
            "items": [],
            "error": "protected collector has details",
        }
        artifact = self.compile(report)
        self.assertEqual(artifact["inventory"]["huggingface"]["state"], "UNAVAILABLE")
        self.assertEqual(artifact["governed_agent_bench"]["state"], "MEASURED")
        self.assertEqual(validate_artifact(artifact), [])

    def test_policy_rejects_extra_authority_at_every_level(self) -> None:
        mutations = {
            "root": lambda policy: policy.__setitem__("authority", "caller"),
            "public": lambda policy: policy["public_space_policy"].__setitem__(
                "authority", "caller"
            ),
            "exception": lambda policy: policy["public_space_policy"]["exceptions"][
                0
            ].__setitem__("authority", "caller"),
            "role": lambda policy: policy["domain_roles"][0].__setitem__(
                "authority", "caller"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                policy = copy.deepcopy(self.policy)
                mutate(policy)
                artifact = compile_diligence(
                    passing_report(),
                    compiler_source_revision=None,
                    policy=policy,
                    as_of=AS_OF,
                )
                self.assertEqual(
                    artifact["requirements"]["target_policy"]["state"], "DIVERGENT"
                )
                self.assertIsNone(artifact["source_binding"]["policy_sha256"])
                self.assertEqual(validate_artifact(artifact), [])

    def test_source_binding_sorts_only_declared_set_paths(self) -> None:
        report = passing_report()
        reversed_sets = copy.deepcopy(report)
        reversed_sets["governance"]["controls"].reverse()
        reversed_sets["sources"]["huggingface"]["data"]["assets"]["spaces"][
            "items"
        ].reverse()
        first = self.compile(report)
        second = self.compile(reversed_sets)
        self.assertEqual(
            first["source_binding"]["census_sha256"],
            second["source_binding"]["census_sha256"],
        )

        arbitrary_a = passing_report()
        arbitrary_b = copy.deepcopy(arbitrary_a)
        arbitrary_a["other"] = {
            "controls": [{"id": "first"}, {"id": "second"}],
            "items": ["first", "second"],
        }
        arbitrary_b["other"] = {
            "controls": [{"id": "second"}, {"id": "first"}],
            "items": ["second", "first"],
        }
        first = self.compile(arbitrary_a)
        second = self.compile(arbitrary_b)
        self.assertNotEqual(
            first["source_binding"]["census_sha256"],
            second["source_binding"]["census_sha256"],
        )

    def test_validator_rejects_redigested_derived_field_forgeries(self) -> None:
        baseline = self.compile(passing_report())
        self.assertEqual(validate_artifact(baseline), [])

        cases: list[tuple[str, object, str]] = [
            (
                "freshness",
                lambda value: value["source_binding"].__setitem__(
                    "census_age_seconds",
                    value["source_binding"]["census_age_seconds"] + 1,
                ),
                "source_binding.census_age_seconds",
            ),
            (
                "expired-exception",
                lambda value: value["public_space_policy"].__setitem__(
                    "expired_exception_count", 1
                ),
                "public_space_policy",
            ),
            (
                "benchmark",
                lambda value: value["governed_agent_bench"]["space"].__setitem__(
                    "eval_output_sha256", "not-a-sha"
                ),
                "governed_agent_bench.space",
            ),
            (
                "hf-contradiction",
                lambda value: value["inventory"]["huggingface"]["counts"].__setitem__(
                    "models", None
                ),
                "inventory.huggingface.counts.models",
            ),
            (
                "requirement-reason",
                lambda value: value["requirements"]["governed_mcp"].__setitem__(
                    "reason", "caller says shipped"
                ),
                "requirements_binding",
            ),
            (
                "governance-ledger",
                lambda value: value["correction_ledger"].__setitem__(
                    "state", "BLOCKED"
                ),
                "correction_ledger",
            ),
        ]
        for name, mutate, expected in cases:
            with self.subTest(name=name):
                artifact = copy.deepcopy(baseline)
                mutate(artifact)
                errors = validate_artifact(self.redigest(artifact))
                self.assertIn(expected, errors)

    def test_validator_reverifies_claimed_compiler_revision(self) -> None:
        artifact = self.compile(passing_report())
        artifact["source_binding"].update(
            {
                "state": "MEASURED",
                "compiler_revision": "b" * 40,
                "compiler_revision_verified": True,
            }
        )
        with mock.patch(
            "census.diligence._verify_compiler_source_revision",
            return_value=False,
        ) as verifier:
            errors = validate_artifact(self.redigest(artifact))
        verifier.assert_called_once_with("b" * 40)
        self.assertIn("source_binding.compiler_revision_verified", errors)

    def test_validator_rejects_null_census_digest(self) -> None:
        artifact = self.compile(passing_report())
        artifact["source_binding"]["census_sha256"] = "0" * 64
        errors = validate_artifact(self.redigest(artifact))
        self.assertIn("source_binding.census_sha256", errors)

    def test_validator_binds_unavailable_sources_to_inventories(self) -> None:
        baseline = self.compile(passing_report())
        cases = (
            (
                "github",
                {
                    "state": "UNAVAILABLE",
                    "error": (
                        "Source collection failed; inspect the protected collector log."
                    ),
                },
            ),
            (
                "huggingface",
                {
                    "state": "DIVERGENT",
                    "error": "Source wrapper is malformed.",
                },
            ),
        )
        for name, source in cases:
            with self.subTest(source=name):
                artifact = copy.deepcopy(baseline)
                artifact["sources"][name] = source
                errors = validate_artifact(self.redigest(artifact))
                self.assertIn(f"inventory.{name}.source_binding", errors)

        artifact = copy.deepcopy(baseline)
        artifact["sources"]["github"] = {
            "state": "UNAVAILABLE",
            "error": "Source collection failed; inspect the protected collector log.",
        }
        artifact["inventory"]["github"].update(
            {
                "state": "UNAVAILABLE",
                "release_gate": "UNAVAILABLE",
                "reason": "GitHub inventory is unavailable.",
            }
        )
        errors = validate_artifact(self.redigest(artifact))
        self.assertIn("inventory.github.source_binding", errors)

    def test_incomplete_space_visibility_keeps_exception_observation_unknown(
        self,
    ) -> None:
        report = passing_report()
        spaces = report["sources"]["huggingface"]["data"]["assets"]["spaces"]
        spaces.update({"ok": False, "count": None, "items": []})
        policy = self.compile(report)["public_space_policy"]
        self.assertEqual(policy["state"], "UNAVAILABLE")
        self.assertIsNone(policy["public_space_count"])
        self.assertIsNone(policy["killinchu_observed"])
        self.assertIsNone(policy["authorized_exception_count"])
        self.assertIsNone(policy["authorized_maximum"])

    def test_exception_is_not_authorized_before_decision_date(self) -> None:
        artifact = self.compile(
            passing_report(generated_at="2026-07-01T11:00:00Z"),
            as_of="2026-07-01T12:00:00Z",
        )
        policy = artifact["public_space_policy"]
        self.assertEqual(policy["state"], "DIVERGENT")
        self.assertEqual(
            policy["reason"],
            "A conditional public-Space exception is not yet effective.",
        )
        self.assertTrue(policy["killinchu_observed"])
        self.assertEqual(policy["authorized_exception_count"], 0)
        self.assertEqual(policy["authorized_maximum"], 5)

    def test_policy_chronology_is_validated_independently_of_lock_equality(
        self,
    ) -> None:
        policy = copy.deepcopy(self.policy)
        exception = policy["public_space_policy"]["exceptions"][0]
        exception["decision_date"] = "2026-10-24"
        exception["review_due"] = "2026-10-23"
        with mock.patch("census.diligence.LOCKED_POLICY", policy):
            state, normalized, _reason = _load_policy(policy)
        self.assertEqual(state, "DIVERGENT")
        self.assertEqual(normalized, {})

    def test_validator_rejects_false_absence_under_unavailable_space_inventory(
        self,
    ) -> None:
        report = passing_report()
        report["sources"]["huggingface"]["data"]["assets"]["spaces"].update(
            {"ok": False, "count": None, "items": []}
        )
        artifact = self.compile(report)
        self.assertEqual(validate_artifact(artifact), [])
        artifact["inventory"]["huggingface"]["public_space_count"] = 0
        artifact["summary"]["hf_public_spaces"] = 0
        policy = artifact["public_space_policy"]
        policy.update(
            {
                "state": "BLOCKED",
                "authorized_exception_count": 0,
                "authorized_maximum": 5,
                "public_space_count": 0,
                "killinchu_observed": False,
                "reason": "The normal five-Space allowlist is not machine-readable.",
            }
        )
        requirement = artifact["requirements"]["public_space_policy"]
        requirement.update({"state": policy["state"], "reason": policy["reason"]})
        gap = next(
            item
            for item in artifact["gaps"]
            if item["requirement"] == "public_space_policy"
        )
        gap.update({"state": policy["state"], "reason": policy["reason"]})
        errors = validate_artifact(self.redigest(artifact))
        self.assertIn("inventory.huggingface.public_space_evidence", errors)

    def test_validator_rejects_false_absence_under_divergent_space_inventory(
        self,
    ) -> None:
        report = passing_report()
        spaces = report["sources"]["huggingface"]["data"]["assets"]["spaces"]["items"]
        next(item for item in spaces if item["id"] == "SZLHOLDINGS/killinchu").pop(
            "private"
        )
        artifact = self.compile(report)
        self.assertEqual(
            artifact["inventory"]["huggingface"]["subinventory_states"]["spaces"],
            "DIVERGENT",
        )
        artifact["inventory"]["huggingface"]["public_space_count"] = 0
        artifact["summary"]["hf_public_spaces"] = 0
        policy = artifact["public_space_policy"]
        policy.update(
            {
                "state": "BLOCKED",
                "authorized_exception_count": 0,
                "authorized_maximum": 5,
                "public_space_count": 0,
                "killinchu_observed": False,
                "reason": "The normal five-Space allowlist is not machine-readable.",
            }
        )
        requirement = artifact["requirements"]["public_space_policy"]
        requirement.update({"state": policy["state"], "reason": policy["reason"]})
        gap = next(
            item
            for item in artifact["gaps"]
            if item["requirement"] == "public_space_policy"
        )
        gap.update({"state": policy["state"], "reason": policy["reason"]})
        errors = validate_artifact(self.redigest(artifact))
        self.assertIn("inventory.huggingface.public_space_evidence", errors)

    def test_validator_rejects_each_fixed_unshipped_component_when_relabelled(
        self,
    ) -> None:
        baseline = self.compile(passing_report())
        for component in (
            "governed_mcp",
            "model_promotion",
            "route_tab_inventory",
            "space_cost_posture",
        ):
            with self.subTest(component=component):
                artifact = copy.deepcopy(baseline)
                artifact[component]["state"] = "MEASURED"
                artifact[component]["reason"] = "caller claims this is shipped"
                errors = validate_artifact(self.redigest(artifact))
                self.assertIn(component, errors)

    def test_validator_rejects_secrets_across_requirements_ledgers_and_repos(
        self,
    ) -> None:
        baseline = self.compile(passing_report())
        mutations = {
            "requirement": lambda value: value["requirements"][
                "governed_mcp"
            ].__setitem__("reason", "Bearer abcdefghijklmnop"),
            "ledger": lambda value: value["correction_ledger"].__setitem__(
                "reason", "api_key=supersecret"
            ),
            "repository": lambda value: value["inventory"]["github"][
                "blocked_repositories"
            ].append("ghp_1234567890"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                artifact = copy.deepcopy(baseline)
                mutate(artifact)
                errors = validate_artifact(self.redigest(artifact))
                self.assertIn("sensitive_text", errors)

    @contextlib.contextmanager
    def source_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.git(root, "init")
            self.git(root, "config", "user.name", "Series A Test")
            self.git(root, "config", "user.email", "series-a@example.invalid")
            self.git(root, "config", "core.autocrlf", "false")
            attributes = "".join(
                f"/{relative} text eol=lf\n" for relative in SOURCE_BOUND_PATHS
            ).encode("utf-8")
            for relative in SOURCE_BOUND_PATHS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                payload = (
                    attributes
                    if relative == ".gitattributes"
                    else f"source-bound fixture: {relative}\n".encode("utf-8")
                )
                path.write_bytes(payload)
            self.git(root, "add", "--all")
            self.git(root, "commit", "-m", "source-bound fixture")
            revision = self.git(root, "rev-parse", "HEAD").stdout.strip()
            yield root, revision

    def git(self, root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_source_verifier_covers_all_bound_files_and_hidden_index_flags(
        self,
    ) -> None:
        with self.source_repository() as (root, revision):
            self.assertEqual(
                set(SOURCE_BOUND_PATHS),
                {
                    ".gitattributes",
                    "build_series_a_diligence.py",
                    "census/__init__.py",
                    "census/diligence.py",
                    "diligence/policy.json",
                    "schemas/series-a-diligence.schema.json",
                },
            )
            for relative in SOURCE_BOUND_PATHS:
                raw = (root / relative).read_bytes()
                self.assertNotIn(b"\r\n", raw, relative)
                self.assertTrue(raw.endswith(b"\n"), relative)
            attributes = (root / ".gitattributes").read_text(encoding="utf-8")
            for relative in SOURCE_BOUND_PATHS:
                self.assertIn(f"/{relative} text eol=lf\n", attributes)
            self.assertTrue(_verify_compiler_source_revision(revision, root=root))
            self.assertFalse(
                _verify_compiler_source_revision(revision.upper(), root=root)
            )

            for relative in SOURCE_BOUND_PATHS:
                with self.subTest(dirty=relative):
                    (root / relative).write_bytes(
                        (root / relative).read_bytes() + b"dirty\n"
                    )
                    self.assertFalse(
                        _verify_compiler_source_revision(revision, root=root)
                    )
                    self.git(root, "checkout", "--", relative)
                    self.assertTrue(
                        _verify_compiler_source_revision(revision, root=root)
                    )

            hidden = "build_series_a_diligence.py"
            self.git(root, "update-index", "--assume-unchanged", hidden)
            self.assertFalse(_verify_compiler_source_revision(revision, root=root))
            self.git(root, "update-index", "--no-assume-unchanged", hidden)
            self.assertTrue(_verify_compiler_source_revision(revision, root=root))

            skipped = "census/diligence.py"
            self.git(root, "update-index", "--skip-worktree", skipped)
            self.assertFalse(_verify_compiler_source_revision(revision, root=root))
            self.git(root, "update-index", "--no-skip-worktree", skipped)
            self.assertTrue(_verify_compiler_source_revision(revision, root=root))

            missing = root / "diligence" / "policy.json"
            missing.unlink()
            self.assertFalse(_verify_compiler_source_revision(revision, root=root))
            self.git(root, "checkout", "--", "diligence/policy.json")
            self.assertTrue(_verify_compiler_source_revision(revision, root=root))

    def test_source_verifier_rejects_symlinked_bound_file(self) -> None:
        with self.source_repository() as (root, revision):
            working = root / "build_series_a_diligence.py"
            target = root / "symlink-target.py"
            target.write_bytes(working.read_bytes())
            working.unlink()
            try:
                working.symlink_to(target)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable on this host: {exc}")
            self.assertTrue(working.is_symlink())
            self.assertFalse(_verify_compiler_source_revision(revision, root=root))

    def test_source_verifier_rejects_hardlinked_bound_file(self) -> None:
        with self.source_repository() as (root, revision):
            working = root / "build_series_a_diligence.py"
            target = root / "hardlink-target.py"
            target.write_bytes(working.read_bytes())
            working.unlink()
            os.link(target, working)
            self.assertEqual(working.stat().st_nlink, 2)
            self.assertFalse(_verify_compiler_source_revision(revision, root=root))

    def test_path_guard_rejects_hardlink_and_symlink_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            source.write_text("{}", encoding="utf-8")
            policy = root / "policy.json"
            policy.write_text("{}", encoding="utf-8")
            markdown = root / "output.md"
            markdown.write_text("", encoding="utf-8")
            hardlink = root / "hardlink.json"
            os.link(source, hardlink)
            with self.assertRaises(DiligenceError):
                _guard_distinct_paths(source, policy, hardlink, markdown)

            symlink = root / "symlink.json"
            try:
                symlink.symlink_to(source)
            except (OSError, NotImplementedError):
                return
            with self.assertRaises(DiligenceError):
                _guard_distinct_paths(source, policy, symlink, markdown)

    def test_cli_parser_errors_are_single_json_objects(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = main(["--definitely-not-an-option"])
        self.assertEqual(result, 2)
        self.assertEqual(stdout.getvalue(), "")
        payload = json.loads(stderr.getvalue().strip())
        self.assertEqual(payload["state"], "FAILED")
        self.assertEqual(payload["error"], "command-line arguments are invalid")

    def test_cli_source_bound_gate_fails_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            policy = root / "policy.json"
            output = root / "output.json"
            markdown = root / "output.md"
            report.write_text(json.dumps(public_cli_report()), encoding="utf-8")
            policy.write_text(json.dumps(self.policy), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(
                    [
                        "--input",
                        str(report),
                        "--policy",
                        str(policy),
                        "--output",
                        str(output),
                        "--markdown",
                        str(markdown),
                        "--source-revision",
                        SHA,
                        "--as-of",
                        AS_OF,
                        "--require-source-bound",
                    ]
                )
            self.assertEqual(result, 5)
            self.assertEqual(
                json.loads(stdout.getvalue())["state"], "SOURCE_BINDING_NOT_MET"
            )
            self.assertFalse(output.exists())
            self.assertFalse(markdown.exists())

    def test_current_check_keeps_verified_output_digest_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            policy = root / "policy.json"
            output = root / "output.json"
            markdown = root / "output.md"
            report.write_text(json.dumps(public_cli_report()), encoding="utf-8")
            policy.write_text(json.dumps(self.policy), encoding="utf-8")
            common = [
                "--input",
                str(report),
                "--policy",
                str(policy),
                "--output",
                str(output),
                "--markdown",
                str(markdown),
                "--source-revision",
                SHA,
            ]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([*common, "--as-of", AS_OF]), 0)
            stored = strict_load_json(output)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(main([*common, "--check"]), 4)
            result = json.loads(stderr.getvalue())
            self.assertEqual(result["digest_sha256"], stored["digest_sha256"])
            self.assertEqual(result["artifact_state"], stored["state"])
            self.assertEqual(result["gap_count"], len(stored["gaps"]))
            self.assertEqual(result["current_artifact_state"], "STALE")
            self.assertNotEqual(result["current_assessed_at"], stored["assessed_at"])
            self.assertEqual(result["current_snapshot_freshness_state"], "STALE")
            self.assertNotEqual(
                result["current_digest_sha256"],
                result["digest_sha256"],
            )

    def test_current_check_reports_stale_and_source_binding_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            policy = root / "policy.json"
            output = root / "output.json"
            markdown = root / "output.md"
            report.write_text(json.dumps(public_cli_report()), encoding="utf-8")
            policy.write_text(json.dumps(self.policy), encoding="utf-8")
            common = [
                "--input",
                str(report),
                "--policy",
                str(policy),
                "--output",
                str(output),
                "--markdown",
                str(markdown),
                "--source-revision",
                SHA,
            ]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([*common, "--as-of", AS_OF]), 0)
            stored = strict_load_json(output)
            stored_json = output.read_bytes()
            stored_markdown = markdown.read_bytes()

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(
                    main([*common, "--check", "--require-source-bound"]),
                    4,
                )
            self.assertEqual(stdout.getvalue(), "")
            result = json.loads(stderr.getvalue())
            self.assertEqual(result["state"], "CURRENT_EVIDENCE_STALE")
            self.assertEqual(
                result["failures"],
                ["CURRENT_EVIDENCE_STALE", "SOURCE_BINDING_NOT_MET"],
            )
            self.assertEqual(result["digest_sha256"], stored["digest_sha256"])
            self.assertEqual(result["artifact_state"], stored["state"])
            self.assertEqual(result["gap_count"], len(stored["gaps"]))
            self.assertEqual(result["current_artifact_state"], "STALE")
            self.assertEqual(result["current_snapshot_freshness_state"], "STALE")
            self.assertNotEqual(
                result["current_digest_sha256"],
                result["digest_sha256"],
            )
            self.assertEqual(output.read_bytes(), stored_json)
            self.assertEqual(markdown.read_bytes(), stored_markdown)

    def test_fresh_and_historical_checks_label_current_fields_explicitly(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            policy = root / "policy.json"
            output = root / "output.json"
            markdown = root / "output.md"
            now = (
                dt.datetime.now(dt.UTC)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )
            report.write_text(
                json.dumps(public_cli_report(generated_at=now)),
                encoding="utf-8",
            )
            policy.write_text(json.dumps(self.policy), encoding="utf-8")
            common = [
                "--input",
                str(report),
                "--policy",
                str(policy),
                "--output",
                str(output),
                "--markdown",
                str(markdown),
                "--source-revision",
                SHA,
            ]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([*common, "--as-of", now]), 0)
            stored = strict_load_json(output)
            stored_json = output.read_bytes()
            stored_markdown = markdown.read_bytes()

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main([*common, "--check"]), 0)
            current = json.loads(stdout.getvalue())
            self.assertEqual(current["state"], "CURRENT_CHECK_COMPLETE")
            self.assertEqual(current["digest_sha256"], stored["digest_sha256"])
            self.assertEqual(current["artifact_state"], stored["state"])
            self.assertEqual(current["current_snapshot_freshness_state"], "MEASURED")
            self.assertIn("current_assessed_at", current)
            self.assertEqual(output.read_bytes(), stored_json)
            self.assertEqual(markdown.read_bytes(), stored_markdown)

            for extra in (
                ["--check", "--historical-check"],
                ["--check", "--as-of", now],
            ):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    self.assertEqual(main([*common, *extra]), 0)
                check = json.loads(stdout.getvalue())
                self.assertEqual(check["digest_sha256"], stored["digest_sha256"])
                self.assertFalse(
                    any(key.startswith("current_") for key in check),
                    check,
                )

    def test_public_schema_pins_unshipped_requirements_and_aggregate(self) -> None:
        schema = strict_load_json(ROOT / "schemas" / "series-a-diligence.schema.json")
        self.assertEqual(
            schema["properties"]["state"],
            {"enum": ["BLOCKED", "DIVERGENT", "STALE"]},
        )
        requirements = schema["properties"]["requirements"]["properties"]
        expected = {
            "generated_api_contract": (
                "A generated API contract has not been collected and verified."
            ),
            "governed_mcp": (
                "The census does not verify governed MCP authorization, receipts, "
                "or endpoint availability."
            ),
            "model_promotion": (
                "Immutable revisions and licenses are inventoried, but SZL eval "
                "reproduction and production promotion are not observed."
            ),
            "product_proof_roles": (
                "The census observes site transport, not route ownership or role "
                "conformance."
            ),
            "route_tab_inventory": (
                "No current route/tab purpose, data-source, and owner collector exists."
            ),
            "shared_design_system_contract": (
                "A shared design-system contract has not been collected and verified."
            ),
            "space_cost_posture": (
                "The census does not observe billed cost, sleep policy, or capacity "
                "quotas."
            ),
            "space_deployment_reconciliation": (
                "The full GitHub SHA, Hub SHA, image digest, registered organs, and "
                "observed routes chain is unavailable until collected."
            ),
        }
        for name, reason in expected.items():
            with self.subTest(requirement=name):
                self.assertEqual(
                    requirements[name],
                    {"const": {"state": "UNAVAILABLE", "reason": reason}},
                )
        public = schema["$defs"]["publicSpacePolicy"]["oneOf"][0]["properties"]
        self.assertEqual(
            public["state"],
            {"enum": ["BLOCKED", "UNAVAILABLE", "DIVERGENT"]},
        )
        for name in (
            "authorized_exception_count",
            "authorized_maximum",
        ):
            self.assertIn({"type": "null"}, public[name]["anyOf"])
        self.assertEqual(
            public["killinchu_observed"],
            {"$ref": "#/$defs/nullableBoolean"},
        )
        gaps = schema["properties"]["gaps"]
        self.assertEqual(gaps["minItems"], 8)
        self.assertTrue(gaps["uniqueItems"])
        fixed_gap_names = {
            item["contains"]["const"]["requirement"] for item in gaps["allOf"]
        }
        self.assertEqual(fixed_gap_names, set(expected))

    def test_public_schema_executes_real_artifact_and_adversarial_fixtures(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schema_path = ROOT / "schemas" / "series-a-diligence.schema.json"
            artifact_path = root / "artifact.json"
            artifact_path.write_bytes(
                canonical_bytes(self.compile(passing_report())) + b"\n"
            )
            command = [
                sys.executable,
                "-I",
                "-B",
                str(ROOT / "scripts" / "verify_series_a_schema_contract.py"),
                "--schema",
                str(schema_path),
                "--artifact",
                str(artifact_path),
            ]
            completed = subprocess.run(
                command,
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            receipt = json.loads(completed.stdout)
            self.assertEqual(receipt["state"], "SCHEMA_CONTRACT_VERIFIED")
            self.assertTrue(receipt["real_artifact_valid"])
            self.assertEqual(
                receipt["adversarial_fixtures_verified"],
                [
                    "missing-required-claim-boundary",
                    "unexpected-root-member",
                    "all-zero-digest",
                    "fixed-unavailable-component-overclaim",
                    "duplicate-gap",
                    "invalid-date-time",
                    "conditional-public-space-count",
                    "boolean-integer-confusion",
                ],
            )

            unsupported_path = root / "unsupported-schema.json"
            unsupported = strict_load_json(schema_path)
            unsupported["minProperties"] = 1
            unsupported_path.write_text(
                json.dumps(unsupported),
                encoding="utf-8",
            )
            rejected = subprocess.run(
                [
                    *command[:4],
                    "--schema",
                    str(unsupported_path),
                    "--artifact",
                    str(artifact_path),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(rejected.returncode, 2, rejected.stdout)
            failure = json.loads(rejected.stderr)
            self.assertEqual(failure["state"], "FAILED")
            self.assertIn("unsupported schema keyword(s)", failure["error"])
            self.assertIn("minProperties", failure["error"])

    def test_schema_contract_recomputes_digest_and_validates_enum_shape(
        self,
    ) -> None:
        schema_path = ROOT / "schemas" / "series-a-diligence.schema.json"
        artifact = self.compile(passing_report())
        with tempfile.TemporaryDirectory() as directory:
            artifact_path = Path(directory) / "artifact.json"
            artifact_path.write_bytes(canonical_bytes(artifact) + b"\n")
            receipt = verify_schema_contract(schema_path, artifact_path)
            self.assertEqual(receipt["state"], "SCHEMA_CONTRACT_VERIFIED")
            self.assertEqual(
                receipt["artifact_digest_sha256"], artifact["digest_sha256"]
            )

            wrong_digest = copy.deepcopy(artifact)
            wrong_digest["digest_sha256"] = "1" * 64
            artifact_path.write_bytes(canonical_bytes(wrong_digest) + b"\n")
            with self.assertRaisesRegex(
                SchemaContractError,
                "digest_sha256 does not match independent canonical recomputation",
            ):
                verify_schema_contract(schema_path, artifact_path)

        duplicate_enum = strict_load_json(schema_path)
        duplicate_enum["properties"]["state"]["enum"].append("BLOCKED")
        with self.assertRaisesRegex(
            SchemaContractError,
            "enum values must be JSON-semantically unique",
        ):
            assert_supported_schema(duplicate_enum)
        with self.assertRaisesRegex(
            SchemaContractError,
            "enum values must be JSON-semantically unique",
        ):
            assert_supported_schema({"enum": [1, 1.0]})
        assert_supported_schema({"enum": [True, 1, False, 0]})

    def test_public_schema_binds_provider_summary_and_hf_aggregate_truth(
        self,
    ) -> None:
        schema = strict_load_json(ROOT / "schemas" / "series-a-diligence.schema.json")
        validator = SchemaContractValidator(schema)

        def assert_valid(artifact: dict) -> None:
            self.assertEqual(validator.validate(artifact), [])

        def assert_invalid(artifact: dict, expected_path: str) -> None:
            errors = validator.validate(self.redigest(artifact))
            self.assertTrue(
                any(error.startswith(expected_path) for error in errors),
                errors,
            )

        github_unavailable_report = passing_report()
        github_unavailable_report["sources"]["github"]["ok"] = False
        github_unavailable = self.compile(github_unavailable_report)
        assert_valid(github_unavailable)
        for field in (
            "github_repositories",
            "github_active_repositories",
            "github_ci_failures",
        ):
            with self.subTest(summary_field=field):
                forged = copy.deepcopy(github_unavailable)
                forged["summary"][field] = 0
                assert_invalid(forged, f"$.summary.{field}:")

        unavailable_report = passing_report()
        unavailable_report["sources"]["huggingface"]["data"]["assets"]["models"][
            "ok"
        ] = False
        hf_unavailable = self.compile(unavailable_report)
        assert_valid(hf_unavailable)
        forged = copy.deepcopy(hf_unavailable)
        forged["summary"]["hf_models"] = 0
        assert_invalid(forged, "$.summary.hf_models:")
        forged = copy.deepcopy(hf_unavailable)
        forged["inventory"]["huggingface"].update(
            {"state": "MEASURED", "release_gate": "MEASURED"}
        )
        assert_invalid(forged, "$.inventory.huggingface.state:")

        divergent_report = passing_report()
        divergent_report["sources"]["huggingface"]["data"]["assets"]["datasets"][
            "count"
        ] = "1"
        hf_divergent = self.compile(divergent_report)
        assert_valid(hf_divergent)
        forged = copy.deepcopy(hf_divergent)
        forged["summary"]["hf_datasets"] = 0
        assert_invalid(forged, "$.summary.hf_datasets:")
        forged = copy.deepcopy(hf_divergent)
        forged["inventory"]["huggingface"].update(
            {"state": "MEASURED", "release_gate": "MEASURED"}
        )
        assert_invalid(forged, "$.inventory.huggingface.state:")

        measured = self.compile(passing_report())
        self.assertEqual(measured["inventory"]["huggingface"]["state"], "MEASURED")
        self.assertEqual(
            measured["inventory"]["huggingface"]["release_gate"], "MEASURED"
        )
        assert_valid(measured)
        forged = copy.deepcopy(measured)
        forged["inventory"]["huggingface"]["release_gate"] = "BLOCKED"
        assert_invalid(forged, "$.inventory.huggingface.release_gate:")

        blocked_report = passing_report()
        blocked_report["sources"]["huggingface"]["data"]["assets"]["models"]["items"][
            0
        ]["license_declared"] = False
        hf_blocked = self.compile(blocked_report)
        self.assertEqual(hf_blocked["inventory"]["huggingface"]["state"], "MEASURED")
        self.assertEqual(
            hf_blocked["inventory"]["huggingface"]["release_gate"], "BLOCKED"
        )
        assert_valid(hf_blocked)
        forged = copy.deepcopy(hf_blocked)
        forged["inventory"]["huggingface"]["release_gate"] = "MEASURED"
        assert_invalid(forged, "$.inventory.huggingface.release_gate:")

    def test_schema_contract_rejects_redigested_cross_field_forgeries(
        self,
    ) -> None:
        schema_path = ROOT / "schemas" / "series-a-diligence.schema.json"
        schema = strict_load_json(schema_path)
        structural_validator = SchemaContractValidator(schema)
        baseline = self.compile(passing_report())
        mutations = (
            (
                "summary-count-mismatch",
                lambda value: value["summary"].__setitem__("github_repositories", 3),
                "summary",
            ),
            (
                "aggregate-state-mismatch",
                lambda value: value.__setitem__("state", "STALE"),
                "aggregate_state",
            ),
            (
                "github-release-gate-mismatch",
                lambda value: value["inventory"]["github"].__setitem__(
                    "release_gate", "BLOCKED"
                ),
                "inventory.github.release_gate",
            ),
            (
                "hf-count-summary-mismatch",
                lambda value: value["inventory"]["huggingface"]["counts"].__setitem__(
                    "spaces", 7
                ),
                "summary",
            ),
            (
                "requirement-inventory-mismatch",
                lambda value: value["requirements"]["github_inventory"].__setitem__(
                    "state", "UNAVAILABLE"
                ),
                "requirements_binding",
            ),
            (
                "dynamic-gap-omission",
                lambda value: value.__setitem__(
                    "gaps",
                    [
                        gap
                        for gap in value["gaps"]
                        if gap["requirement"] != "compiler_source"
                    ],
                ),
                "gaps",
            ),
        )

        with tempfile.TemporaryDirectory() as directory:
            artifact_path = Path(directory) / "artifact.json"
            for name, mutate, expected_error in mutations:
                with self.subTest(name=name):
                    forged = copy.deepcopy(baseline)
                    mutate(forged)
                    self.redigest(forged)
                    self.assertEqual(structural_validator.validate(forged), [])
                    artifact_path.write_bytes(canonical_bytes(forged) + b"\n")
                    with self.assertRaises(SchemaContractError) as raised:
                        verify_schema_contract(schema_path, artifact_path)
                    self.assertIn(
                        "real artifact violates semantic contract",
                        str(raised.exception),
                    )
                    self.assertIn(expected_error, str(raised.exception))

    def test_rfc3339_parser_rejects_non_contract_timestamp_forms(self) -> None:
        invalid = (
            "2026-08-11T12:00:00",
            "2026-08-11 12:00:00Z",
            "2026-08-11T12:00:00z",
            "2026-08-11T12:00:00.1234567Z",
            "2026-08-11",
            "2026-08-11T12:00:00+0000",
            "2026-08-11T24:00:00Z",
            "2026-13-11T12:00:00Z",
            "2026-08-11T12:00:00+99:99",
        )
        for value in invalid:
            with self.subTest(value=value):
                self.assertIsNone(_parse_timestamp(value))
                with self.assertRaises(DiligenceError):
                    self.compile(passing_report(), as_of=value)

        self.assertIsNotNone(_parse_timestamp("2026-08-11T12:00:00.123456Z"))
        self.assertIsNotNone(_parse_timestamp("2026-08-11T08:00:00-04:00"))

    def test_pair_publication_rolls_back_both_files_on_second_replace_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "artifact.json"
            second = root / "artifact.md"
            first.write_bytes(b"old-json")
            second.write_bytes(b"old-markdown")
            real_replace = os.replace
            calls = 0

            def fail_second_replace(source, target):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected second replace failure")
                return real_replace(source, target)

            with (
                mock.patch(
                    "build_series_a_diligence.os.replace",
                    side_effect=fail_second_replace,
                ),
                self.assertRaises(OSError),
            ):
                _atomic_write_pair(
                    (first, b"new-json"),
                    (second, b"new-markdown"),
                )

            self.assertEqual(first.read_bytes(), b"old-json")
            self.assertEqual(second.read_bytes(), b"old-markdown")
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                ["artifact.json", "artifact.md"],
            )

    def test_pair_lock_serializes_across_processes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "artifact.json"
            markdown = root / "artifact.md"
            ready = root / "ready"
            code = (
                "import sys,time;"
                "from pathlib import Path;"
                "from build_series_a_diligence import _pair_lock;"
                "a,b,r=map(Path,sys.argv[1:]);"
                "\nwith _pair_lock(a,b):"
                "\n r.write_text('ready',encoding='utf-8');"
                "\n time.sleep(1.1)"
            )
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    code,
                    str(output),
                    str(markdown),
                    str(ready),
                ],
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                if not ready.exists():
                    self.fail(f"lock holder did not start; exit={process.poll()}")
                started = time.monotonic()
                with _pair_lock(output, markdown):
                    elapsed = time.monotonic() - started
                self.assertGreaterEqual(elapsed, 0.45)
                self.assertEqual(process.wait(timeout=3), 0)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=3)

    def test_static_census_counts_and_truth_states_are_not_overclaimed(self) -> None:
        report = strict_load_json(ROOT / "static" / "data.json")
        artifact = compile_diligence(
            report,
            compiler_source_revision=None,
            policy=self.policy,
            as_of="2026-08-01T18:43:05Z",
        )
        hf = artifact["inventory"]["huggingface"]
        self.assertEqual(
            hf["counts"],
            {
                "models": None,
                "datasets": None,
                "spaces": None,
                "kernels": None,
                "collections": None,
                "buckets": None,
            },
        )
        self.assertEqual(
            hf["subinventory_states"],
            {
                "models": "UNAVAILABLE",
                "datasets": "UNAVAILABLE",
                "spaces": "UNAVAILABLE",
                "kernels": "UNAVAILABLE",
                "collections": "UNAVAILABLE",
                "buckets": "UNAVAILABLE",
            },
        )
        self.assertEqual(hf["state"], "UNAVAILABLE")
        self.assertEqual(hf["release_gate"], "UNAVAILABLE")
        self.assertIsNone(hf["public_space_count"])
        self.assertIn("public subset", hf["reason"])
        self.assertEqual(artifact["governed_agent_bench"]["state"], "UNAVAILABLE")
        self.assertEqual(artifact["public_space_policy"]["state"], "UNAVAILABLE")
        self.assertEqual(artifact["state"], "BLOCKED")
        self.assertEqual(
            artifact["requirements"]["compiler_source"]["state"], "UNAVAILABLE"
        )
        self.assertEqual(validate_artifact(artifact), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
