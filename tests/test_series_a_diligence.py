from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from build_series_a_diligence import main
from census.diligence import (
    DiligenceError,
    GOVERNANCE_CONTROL_SEVERITIES,
    compile_diligence,
    render_markdown,
    canonical_bytes,
    strict_load_json,
    validate_artifact,
)


SHA = "a" * 40
AS_OF = "2026-08-11T12:00:00Z"
GENERATED_AT = "2026-08-11T11:00:00Z"
ROOT = Path(__file__).resolve().parents[1]


def public_cli_report(*, generated_at: str = GENERATED_AT) -> dict:
    """Use a genuinely closed public fixture for CLI publication tests."""

    report = copy.deepcopy(strict_load_json(ROOT / "static" / "data.json"))
    report["generated_at"] = generated_at
    return report


def _asset(item_id: str, **extra) -> dict:
    return {
        "id": item_id,
        "sha": SHA,
        "private": False,
        "license_declared": True,
        "card_state": "COMPLETE",
        **extra,
    }


def passing_report(
    *,
    public_spaces: int = 6,
    bench_stage: str = "RUNNING",
    bench_binding: str = "OBSERVED",
    generated_at: str = GENERATED_AT,
) -> dict:
    repos = {
        "a11oy": {
            "archived": False,
            "ci": "success",
            "protected": True,
            "classification": "production",
        },
        "archive": {
            "archived": True,
            "ci": "archived",
            "protected": None,
            "classification": "archive",
        },
    }
    spaces = [
        _asset(
            "SZLHOLDINGS/governed-agent-bench",
            sdk="gradio",
            stage=bench_stage,
            source_binding_state=bench_binding,
            source_revision=SHA,
            canonical_source_revision=SHA,
            operational_state="OPERATIONAL_SOURCE_BOUND",
            http=200,
            healthz=200,
            healthz_contract=True,
            build_info_http=200,
            leaderboard_http=200,
            eval_output_revision=SHA,
            eval_dataset_revision=SHA,
            eval_space_revision=SHA,
            eval_output_sha256="b" * 64,
            eval_receipt_id="receipt:series-a-test",
            eval_reproduction_state="VERIFIED",
        )
    ]
    if public_spaces > 1:
        spaces.append(
            _asset(
                "SZLHOLDINGS/killinchu",
                sdk="static",
                stage="RUNNING",
                source_binding_state="NOT_APPLICABLE",
            )
        )
    for index in range(2, public_spaces):
        spaces.append(
            _asset(
                f"SZLHOLDINGS/flagship-{index}",
                sdk="static",
                stage="RUNNING",
                source_binding_state="NOT_APPLICABLE",
            )
        )
    assets = {
        "models": {"ok": True, "count": 1, "items": [_asset("SZLHOLDINGS/model")]},
        "datasets": {
            "ok": True,
            "count": 1,
            "items": [_asset("SZLHOLDINGS/governed-agent-bench")],
        },
        "spaces": {"ok": True, "count": len(spaces), "items": spaces},
        "kernels": {"ok": True, "count": 0, "items": []},
        "collections": {"ok": True, "count": 0, "items": []},
        "buckets": {"ok": True, "count": 0, "items": []},
    }
    controls = [
        {
            "id": control_id,
            "status": "PASS",
            "severity": severity,
            "summary": f"{control_id} evidence observed.",
        }
        for control_id, severity in sorted(GOVERNANCE_CONTROL_SEVERITIES.items())
    ]
    return {
        "schema_version": 2,
        "generated_at": generated_at,
        "sources": {
            "github": {
                "ok": True,
                "data": {
                    "discovery": {"complete": True, "scope": "organization-api"},
                    "summary": {
                        "total": 2,
                        "active": 1,
                        "archived": 1,
                        "ci_green": 1,
                        "ci_red": 0,
                        "ci_unknown": 0,
                    },
                    "repos": repos,
                },
            },
            "huggingface": {
                "ok": True,
                "data": {
                    "authentication": {"organization_complete": True},
                    "assets": assets,
                },
            },
            "sites": {
                "ok": True,
                "data": {"a-11-oy.com": {"http": 200}, "a11oy.net": {"http": 200}},
            },
            "dns": {"ok": True, "data": {}},
        },
        "governance": {
            "schema": "szl.estate-governance-evaluation/v1",
            "overall_status": "PASS",
            "certification": "NOT_A_CERTIFICATION",
            "summary": {
                "PASS": len(controls),
                "FAIL": 0,
                "UNKNOWN": 0,
                "NOT_APPLICABLE": 0,
            },
            "controls": controls,
        },
    }


def redigest(artifact: dict) -> dict:
    artifact.pop("digest_sha256", None)
    artifact["digest_sha256"] = hashlib.sha256(canonical_bytes(artifact)).hexdigest()
    return artifact


class SeriesADiligenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = strict_load_json(ROOT / "diligence" / "policy.json")

    def compile(
        self, report: dict, *, source_revision: str | None = SHA, as_of: str = AS_OF
    ) -> dict:
        return compile_diligence(
            report,
            compiler_source_revision=source_revision,
            policy=self.policy,
            as_of=as_of,
        )

    def test_missing_compiler_source_blocks_instead_of_claiming_measured(self) -> None:
        artifact = self.compile(passing_report(), source_revision=None)
        self.assertEqual(
            artifact["requirements"]["compiler_source"]["state"], "UNAVAILABLE"
        )
        self.assertEqual(artifact["state"], "BLOCKED")
        self.assertEqual(validate_artifact(artifact), [])

    def test_twenty_six_public_spaces_diverge_from_five_plus_one_policy(self) -> None:
        artifact = self.compile(passing_report(public_spaces=26))
        policy = artifact["public_space_policy"]
        self.assertEqual(policy["authorized_maximum"], 6)
        self.assertEqual(policy["public_space_count"], 26)
        self.assertEqual(policy["state"], "DIVERGENT")
        self.assertEqual(artifact["state"], "DIVERGENT")
        self.assertEqual(
            policy["killinchu_exception"]["source_blob_oid"],
            "02fe8afa7a6063d3f6265882fa0b0dadace1e6c7",
        )

    def test_exception_expiry_is_divergent(self) -> None:
        artifact = self.compile(passing_report(), as_of="2026-11-01T12:00:00Z")
        self.assertEqual(artifact["public_space_policy"]["state"], "DIVERGENT")
        self.assertEqual(artifact["public_space_policy"]["expired_exception_count"], 1)

    def test_policy_inflation_or_replacement_is_rejected(self) -> None:
        for mutate in (
            lambda policy: policy["public_space_policy"].__setitem__(
                "normal_limit", 27
            ),
            lambda policy: policy["public_space_policy"]["exceptions"][0].__setitem__(
                "surface", "SZLHOLDINGS/another-space"
            ),
        ):
            with self.subTest(mutate=mutate):
                policy = copy.deepcopy(self.policy)
                mutate(policy)
                artifact = compile_diligence(
                    passing_report(),
                    compiler_source_revision=SHA,
                    policy=policy,
                    as_of=AS_OF,
                )
                self.assertEqual(
                    artifact["requirements"]["target_policy"]["state"], "DIVERGENT"
                )
                self.assertEqual(artifact["state"], "DIVERGENT")

    def test_killinchu_exception_does_not_authorize_an_unrelated_sixth_space(
        self,
    ) -> None:
        report = passing_report(public_spaces=6)
        spaces = report["sources"]["huggingface"]["data"]["assets"]["spaces"]["items"]
        killinchu = next(
            item for item in spaces if item["id"] == "SZLHOLDINGS/killinchu"
        )
        killinchu["id"] = "SZLHOLDINGS/unrelated-sixth"
        artifact = self.compile(report)
        self.assertFalse(artifact["public_space_policy"]["killinchu_observed"])
        self.assertEqual(artifact["public_space_policy"]["authorized_maximum"], 5)
        self.assertEqual(artifact["public_space_policy"]["state"], "DIVERGENT")

    def test_stale_snapshot_is_never_current(self) -> None:
        artifact = self.compile(
            passing_report(generated_at="2026-08-09T11:00:00Z"),
        )
        self.assertEqual(
            artifact["requirements"]["snapshot_freshness"]["state"], "STALE"
        )
        self.assertEqual(artifact["state"], "STALE")

    def test_paused_benchmark_is_not_operational(self) -> None:
        artifact = self.compile(passing_report(bench_stage="PAUSED"))
        self.assertEqual(artifact["governed_agent_bench"]["state"], "BLOCKED")
        self.assertIn("not RUNNING", artifact["governed_agent_bench"]["reason"])

    def test_running_unbound_benchmark_is_not_verified(self) -> None:
        artifact = self.compile(passing_report(bench_binding="UNAVAILABLE"))
        self.assertEqual(artifact["governed_agent_bench"]["state"], "BLOCKED")
        self.assertIn(
            "primitive exact-source", artifact["governed_agent_bench"]["reason"]
        )

    def test_invalid_counts_diverge_instead_of_coercing(self) -> None:
        for invalid in (True, "1", -1):
            with self.subTest(invalid=invalid):
                report = passing_report()
                report["sources"]["huggingface"]["data"]["assets"]["models"][
                    "count"
                ] = invalid
                artifact = self.compile(report)
                self.assertEqual(
                    artifact["inventory"]["huggingface"]["state"], "DIVERGENT"
                )
                self.assertEqual(artifact["state"], "DIVERGENT")

    def test_hf_nonmeasured_subinventories_require_null_counts(self) -> None:
        reports = {}

        unavailable = passing_report()
        unavailable["sources"]["huggingface"]["data"]["assets"]["models"]["ok"] = False
        reports["UNAVAILABLE"] = unavailable

        divergent = passing_report()
        divergent["sources"]["huggingface"]["data"]["assets"]["models"]["count"] = "1"
        reports["DIVERGENT"] = divergent

        for expected_state, report in reports.items():
            with self.subTest(expected_state=expected_state):
                artifact = self.compile(report)
                huggingface = artifact["inventory"]["huggingface"]
                self.assertEqual(
                    huggingface["subinventory_states"]["models"], expected_state
                )
                self.assertIsNone(huggingface["counts"]["models"])
                self.assertEqual(validate_artifact(artifact), [])

                forged = copy.deepcopy(artifact)
                forged["inventory"]["huggingface"]["counts"]["models"] = 0
                forged["summary"]["hf_models"] = 0
                redigest(forged)
                self.assertIn(
                    "inventory.huggingface.counts.models",
                    validate_artifact(forged),
                )

    def test_public_projection_cannot_claim_complete_organization_inventory(
        self,
    ) -> None:
        for authentication, expected_reason in (
            (
                {"evidence_scope": "PUBLIC_PROJECTION", "organization_complete": False},
                "public subset",
            ),
            ({"evidence_scope": "PUBLIC_PROJECTION"}, "public subset"),
            ({}, "completeness is unverified"),
        ):
            with self.subTest(authentication=authentication):
                report = passing_report()
                report["sources"]["huggingface"]["data"]["authentication"] = (
                    authentication
                )
                artifact = self.compile(report)
                hf = artifact["inventory"]["huggingface"]
                self.assertEqual(hf["state"], "UNAVAILABLE")
                self.assertEqual(hf["release_gate"], "UNAVAILABLE")
                self.assertEqual(
                    set(hf["subinventory_states"].values()), {"UNAVAILABLE"}
                )
                self.assertTrue(all(count is None for count in hf["counts"].values()))
                self.assertIsNone(hf["public_space_count"])
                self.assertEqual(hf["public_space_ids"], [])
                self.assertIn(expected_reason, hf["reason"])
                self.assertIsNone(artifact["summary"]["hf_models"])
                self.assertIsNone(artifact["summary"]["hf_public_spaces"])
                self.assertEqual(
                    artifact["public_space_policy"]["state"], "UNAVAILABLE"
                )
                self.assertEqual(validate_artifact(artifact), [])

    def test_public_projection_conflicting_completeness_claim_diverges(self) -> None:
        report = passing_report()
        report["sources"]["huggingface"]["data"]["authentication"] = {
            "evidence_scope": "PUBLIC_PROJECTION",
            "organization_complete": True,
        }
        artifact = self.compile(report)
        hf = artifact["inventory"]["huggingface"]
        self.assertEqual(hf["state"], "DIVERGENT")
        self.assertEqual(hf["release_gate"], "DIVERGENT")
        self.assertTrue(all(count is None for count in hf["counts"].values()))
        self.assertIsNone(hf["public_space_count"])
        self.assertIn("conflicts", hf["reason"])
        self.assertEqual(validate_artifact(artifact), [])

    def test_hf_projected_asset_diagnostics_preserve_invalid_vs_unavailable(
        self,
    ) -> None:
        for authentication in (
            {"organization_complete": True},
            {"evidence_scope": "PUBLIC_PROJECTION", "organization_complete": False},
        ):
            for diagnostic, expected in (
                ("INVALID_RESPONSE", "DIVERGENT"),
                ("SOURCE_UNAVAILABLE", "UNAVAILABLE"),
            ):
                with self.subTest(authentication=authentication, diagnostic=diagnostic):
                    report = passing_report()
                    hf_data = report["sources"]["huggingface"]["data"]
                    hf_data["authentication"] = authentication
                    hf_data["assets"]["models"] = {
                        "ok": False,
                        "count": None,
                        "diagnostic_state": diagnostic,
                        "error": "SOURCE_UNAVAILABLE",
                        "items": [],
                    }
                    artifact = self.compile(report)
                    hf = artifact["inventory"]["huggingface"]
                    self.assertEqual(hf["subinventory_states"]["models"], expected)
                    self.assertEqual(hf["state"], expected)
                    self.assertEqual(hf["release_gate"], expected)
                    self.assertIsNone(hf["counts"]["models"])
                    self.assertEqual(validate_artifact(artifact), [])

    def test_active_repository_cannot_claim_archived_ci(self) -> None:
        report = passing_report()
        report["sources"]["github"]["data"]["repos"]["a11oy"]["ci"] = "archived"

        artifact = self.compile(report)
        github = artifact["inventory"]["github"]
        self.assertEqual(github["state"], "DIVERGENT")
        self.assertEqual(github["release_gate"], "DIVERGENT")
        self.assertEqual(
            github["reason"], "Repository lifecycle and CI state disagree."
        )
        self.assertIsNone(github["repository_count"])
        self.assertTrue(all(value is None for value in github["ci"].values()))
        self.assertEqual(validate_artifact(artifact), [])

    def test_github_nonmeasured_inventory_rejects_exact_count_forgery(self) -> None:
        reports = {}

        unavailable = passing_report()
        unavailable["sources"]["github"]["data"]["discovery"]["complete"] = False
        reports["UNAVAILABLE"] = unavailable

        divergent = passing_report()
        divergent["sources"]["github"]["data"]["repos"]["a11oy"]["ci"] = "archived"
        reports["DIVERGENT"] = divergent

        for expected_state, report in reports.items():
            with self.subTest(expected_state=expected_state):
                artifact = self.compile(report)
                github = artifact["inventory"]["github"]
                self.assertEqual(github["state"], expected_state)
                self.assertIsNone(github["repository_count"])
                self.assertTrue(all(value is None for value in github["ci"].values()))
                self.assertEqual(validate_artifact(artifact), [])

                forged = copy.deepcopy(artifact)
                forged_github = forged["inventory"]["github"]
                forged_github.update(
                    repository_count=2,
                    active_count=1,
                    archived_count=1,
                    ci={"success": 1, "failure": 0, "pending": 0, "unknown": 0},
                )
                forged["summary"].update(
                    github_repositories=2,
                    github_active_repositories=1,
                    github_ci_failures=0,
                )
                redigest(forged)
                errors = validate_artifact(forged)
                self.assertIn("inventory.github.counts", errors)
                self.assertIn("inventory.github.ci", errors)

    def test_fixed_unavailable_release_prerequisites_are_tamper_evident(
        self,
    ) -> None:
        artifact = self.compile(passing_report())
        expected = {
            "generated_api_contract": (
                "A generated API contract has not been collected and verified."
            ),
            "shared_design_system_contract": (
                "A shared design-system contract has not been collected and verified."
            ),
            "space_deployment_reconciliation": (
                "The full GitHub SHA, Hub SHA, image digest, registered organs, and "
                "observed routes chain is unavailable until collected."
            ),
        }
        self.assertEqual(validate_artifact(artifact), [])

        for name, reason in expected.items():
            with self.subTest(name=name):
                self.assertEqual(
                    artifact["requirements"][name],
                    {"state": "UNAVAILABLE", "reason": reason},
                )
                self.assertIn(
                    {
                        "requirement": name,
                        "state": "UNAVAILABLE",
                        "reason": reason,
                    },
                    artifact["gaps"],
                )

                tampered = copy.deepcopy(artifact)
                tampered["requirements"][name]["reason"] = "Caller asserted complete."
                next(gap for gap in tampered["gaps"] if gap["requirement"] == name)[
                    "reason"
                ] = "Caller asserted complete."
                redigest(tampered)
                self.assertIn("requirements_binding", validate_artifact(tampered))

                omitted = copy.deepcopy(artifact)
                del omitted["requirements"][name]
                omitted["gaps"] = [
                    gap for gap in omitted["gaps"] if gap["requirement"] != name
                ]
                redigest(omitted)
                self.assertIn("requirements", validate_artifact(omitted))

    def test_duplicate_or_malformed_asset_identity_diverges(self) -> None:
        report = passing_report()
        spaces = report["sources"]["huggingface"]["data"]["assets"]["spaces"]
        spaces["items"].append(copy.deepcopy(spaces["items"][0]))
        spaces["count"] += 1
        artifact = self.compile(report)
        self.assertEqual(artifact["inventory"]["huggingface"]["state"], "DIVERGENT")
        self.assertEqual(
            artifact["inventory"]["huggingface"]["duplicate_asset_ids"],
            ["SZLHOLDINGS/governed-agent-bench"],
        )

        malformed = passing_report()
        malformed["sources"]["huggingface"]["data"]["assets"]["models"]["items"][0][
            "id"
        ] = "model"
        artifact = self.compile(malformed)
        self.assertEqual(artifact["inventory"]["huggingface"]["state"], "DIVERGENT")

    def test_runtime_labels_without_primitive_evidence_never_measure(self) -> None:
        report = passing_report()
        bench = report["sources"]["huggingface"]["data"]["assets"]["spaces"]["items"][0]
        for field in (
            "canonical_source_revision",
            "http",
            "healthz",
            "healthz_contract",
            "build_info_http",
        ):
            bench.pop(field)
        artifact = self.compile(report)
        self.assertEqual(
            artifact["inventory"]["huggingface"]["release_gate"], "BLOCKED"
        )
        self.assertEqual(artifact["governed_agent_bench"]["state"], "BLOCKED")

    def test_incomplete_governance_is_not_a_zero_issue_ledger(self) -> None:
        report = passing_report()
        report.pop("governance")
        artifact = self.compile(report)
        self.assertEqual(artifact["correction_ledger"]["state"], "UNAVAILABLE")
        self.assertIsNone(artifact["summary"]["open_corrections"])
        self.assertIsNone(artifact["summary"]["open_overclaims"])
        markdown = render_markdown(artifact)
        self.assertIn(
            "**UNAVAILABLE**: Governance evaluation is unavailable.", markdown
        )
        self.assertNotIn("No FAIL controls were observed", markdown)

    def test_governance_requires_exact_complete_control_set(self) -> None:
        report = passing_report()
        report["governance"]["controls"].pop()
        report["governance"]["summary"]["PASS"] -= 1
        artifact = self.compile(report)
        self.assertEqual(
            artifact["requirements"]["correction_and_overclaim_ledger"]["state"],
            "DIVERGENT",
        )

    def test_collector_error_text_is_never_rendered(self) -> None:
        report = passing_report()
        report["sources"]["github"] = {
            "ok": False,
            "error": "Bearer ghp_super_secret must not leak",
        }
        artifact = self.compile(report)
        rendered = canonical_bytes(artifact).decode("utf-8") + render_markdown(artifact)
        self.assertNotIn("Bearer", rendered)
        self.assertNotIn("ghp_", rendered)

    def test_input_aggregate_labels_are_ignored_and_recomputed(self) -> None:
        report = passing_report()
        report["state"] = "PASS"
        control = next(
            item
            for item in report["governance"]["controls"]
            if item["id"] == "GH-INVENTORY"
        )
        control["status"] = "FAIL"
        control["summary"] = "An observed control failed."
        report["governance"]["overall_status"] = "FAIL"
        report["governance"]["summary"] = {
            "PASS": len(GOVERNANCE_CONTROL_SEVERITIES) - 1,
            "FAIL": 1,
            "UNKNOWN": 0,
            "NOT_APPLICABLE": 0,
        }
        artifact = self.compile(report)
        self.assertEqual(artifact["correction_ledger"]["state"], "BLOCKED")
        self.assertEqual(
            artifact["correction_ledger"]["entries"][0]["id"], "GH-INVENTORY"
        )
        self.assertNotEqual(artifact["state"], report["state"])

    def test_strict_json_rejects_duplicate_members_and_nonfinite_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            for payload in (
                '{"state":"PASS","state":"FAIL"}',
                '{"value":NaN}',
                '{"value":Infinity}',
            ):
                with self.subTest(payload=payload):
                    path.write_text(payload, encoding="utf-8")
                    with self.assertRaises(DiligenceError):
                        strict_load_json(path)

    def test_semantic_output_is_deterministic_under_mapping_and_item_order(
        self,
    ) -> None:
        report = passing_report()
        permuted = copy.deepcopy(report)
        permuted["sources"] = dict(reversed(list(permuted["sources"].items())))
        github = permuted["sources"]["github"]["data"]
        github["repos"] = dict(reversed(list(github["repos"].items())))
        assets = permuted["sources"]["huggingface"]["data"]["assets"]
        assets["spaces"]["items"] = list(reversed(assets["spaces"]["items"]))
        permuted["governance"]["controls"] = list(
            reversed(permuted["governance"]["controls"])
        )
        first = self.compile(report)
        second = self.compile(permuted)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))

    def test_order_sensitive_unknown_array_changes_source_binding(self) -> None:
        first_report = passing_report()
        second_report = copy.deepcopy(first_report)
        first_report["evidence_sequence"] = ["first", "second"]
        second_report["evidence_sequence"] = ["second", "first"]
        first = self.compile(first_report)
        second = self.compile(second_report)
        self.assertNotEqual(
            first["source_binding"]["census_sha256"],
            second["source_binding"]["census_sha256"],
        )

    def test_artifact_digest_tamper_is_rejected(self) -> None:
        artifact = self.compile(passing_report())
        self.assertEqual(validate_artifact(artifact), [])
        artifact["summary"]["hf_spaces"] = 99
        self.assertIn("digest_mismatch", validate_artifact(artifact))

    def test_self_digested_malformed_artifact_is_rejected_before_render(self) -> None:
        artifact = self.compile(passing_report())
        artifact["inventory"] = "malformed"
        artifact["requirements"] = {
            "caller_green": {"state": "MEASURED", "reason": "caller says green"}
        }
        artifact["summary"] = {"hf_spaces": 999}
        artifact.pop("digest_sha256")
        artifact["digest_sha256"] = hashlib.sha256(
            canonical_bytes(artifact)
        ).hexdigest()
        errors = validate_artifact(artifact)
        self.assertIn("inventory", errors)
        self.assertIn("requirements", errors)
        with self.assertRaises(DiligenceError):
            render_markdown(artifact)

    def test_every_accepted_artifact_is_renderer_safe(self) -> None:
        artifact = self.compile(passing_report())
        self.assertEqual(validate_artifact(artifact), [])
        self.assertTrue(render_markdown(artifact).endswith("\n"))

    def test_markdown_counts_match_json_summary(self) -> None:
        artifact = self.compile(passing_report())
        markdown = render_markdown(artifact)
        self.assertIn(
            f"- GitHub repositories: {artifact['summary']['github_repositories']}",
            markdown,
        )
        self.assertIn(
            f"- Hugging Face Spaces: {artifact['summary']['hf_spaces']}", markdown
        )
        self.assertIn(
            f"- Open corrections: {artifact['summary']['open_corrections']}", markdown
        )

    def test_cli_check_detects_byte_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "report.json"
            policy_path = root / "policy.json"
            output_path = root / "diligence.json"
            markdown_path = root / "diligence.md"
            report_path.write_text(json.dumps(public_cli_report()), encoding="utf-8")
            policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
            args = [
                "--input",
                str(report_path),
                "--policy",
                str(policy_path),
                "--output",
                str(output_path),
                "--markdown",
                str(markdown_path),
                "--source-revision",
                SHA,
                "--as-of",
                AS_OF,
            ]
            self.assertEqual(main(args), 0)
            self.assertEqual(main([*args, "--check"]), 0)
            output_path.write_bytes(output_path.read_bytes() + b" ")
            self.assertEqual(main([*args, "--check"]), 2)

    def test_cli_current_check_rejects_stale_bytes_but_historical_mode_is_explicit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "report.json"
            policy_path = root / "policy.json"
            output_path = root / "diligence.json"
            markdown_path = root / "diligence.md"
            report_path.write_text(json.dumps(public_cli_report()), encoding="utf-8")
            policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
            common = [
                "--input",
                str(report_path),
                "--policy",
                str(policy_path),
                "--output",
                str(output_path),
                "--markdown",
                str(markdown_path),
                "--source-revision",
                SHA,
            ]
            self.assertEqual(main([*common, "--as-of", AS_OF]), 0)
            self.assertEqual(main([*common, "--check"]), 4)
            self.assertEqual(main([*common, "--check", "--historical-check"]), 0)

    def test_cli_rejects_path_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "report.json"
            policy_path = root / "policy.json"
            report_path.write_text(json.dumps(public_cli_report()), encoding="utf-8")
            policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "--input",
                        str(report_path),
                        "--policy",
                        str(policy_path),
                        "--output",
                        str(report_path),
                        "--markdown",
                        str(root / "out.md"),
                        "--source-revision",
                        SHA,
                        "--as-of",
                        AS_OF,
                    ]
                ),
                2,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
