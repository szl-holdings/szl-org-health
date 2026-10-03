from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from census.governance import DEFAULT_POLICY, evaluate_report

SHA = "a" * 40


def passing_report() -> dict:
    repos = {
        "control": {
            "archived": False,
            "ci": "success",
            "protected": True,
            "classification": "control-plane",
        },
        "archive": {
            "archived": True,
            "ci": "archived",
            "protected": None,
            "classification": "archive",
        },
    }
    hf_item = {
        "id": "SZLHOLDINGS/asset",
        "sha": SHA,
        "card_state": "COMPLETE",
        "card_present": True,
        "license_declared": True,
    }
    model = {
        **hf_item,
        "model_artifact_files_observed": ["model.safetensors"],
        "weight_files_observed": ["model.safetensors"],
        "estimator_files_observed": [],
    }
    space = {
        **hf_item,
        "sdk": "docker",
        "stage": "RUNNING",
        "source_binding_state": "OBSERVED",
    }
    assets = {
        "models": {"ok": True, "count": 1, "items": [model]},
        "datasets": {"ok": True, "count": 1, "items": [hf_item]},
        "spaces": {"ok": True, "count": 1, "items": [space]},
        "kernels": {"ok": True, "count": 0, "items": []},
        "collections": {"ok": True, "count": 0, "items": []},
        "buckets": {"ok": True, "count": 0, "items": []},
    }
    dns = {
        domain: {"spf": True, "dmarc": True, "dmarc_reject": True}
        for domain in (
            "szlholdings.com",
            "a-11-oy.com",
            "a11oy.net",
            "alloyszlholdings.com",
            "killinchu.net",
        )
    }
    return {
        "schema_version": 2,
        "generated_at": "2026-08-11T00:00:00Z",
        "sources": {
            "github": {
                "ok": True,
                "data": {
                    "discovery": {"complete": True, "scope": "organization-api"},
                    "summary": {"total": 2},
                    "repos": repos,
                    "alerts": {
                        "code_scanning_high": 0,
                        "secret_scanning_open": 0,
                        "dependabot_open": 0,
                        "complete": True,
                        "errors": {},
                    },
                },
            },
            "huggingface": {
                "ok": True,
                "data": {
                    "authentication": {
                        "schema": "szl.hf-authentication-evidence/v2",
                        "credential_present": True,
                        "identity_authenticated": True,
                        "user_identity_observed": True,
                        "target_organization": "SZLHOLDINGS",
                        "target_organization_match_observed": True,
                        "organization_membership_observed": True,
                        "organization_read_role_observed": True,
                        "credential_class": "FINE_GRAINED",
                        "fine_grained_metadata_observed": True,
                        "org_scope_candidate_observed": True,
                        "unknown_grants_observed": False,
                        "global_permissions_state": "NONE",
                        "inventory_scope": "AUTHENTICATED_BOUNDED",
                        "probe_state": "AUTHENTICATED",
                    },
                    "assets": assets,
                },
            },
            "dns": {"ok": True, "data": dns},
        },
    }


def by_id(result: dict) -> dict[str, dict]:
    return {control["id"]: control for control in result["controls"]}


class GovernanceEvaluationTests(unittest.TestCase):
    def test_admin_repository_reconciliation_does_not_complete_collections(self) -> None:
        report = passing_report()
        hf_data = report["sources"]["huggingface"]["data"]
        hf_data["authentication"]["organization_admin_role_observed"] = True
        hf_data["repository_export"] = {
            "schema": "szl.hf-repository-export/v1",
            "source": "ADMIN_SETTINGS_REPOSITORIES_API",
            "status": "RECONCILED",
            "repository_count": 3,
            "type_counts": {"model": 1, "dataset": 1, "space": 1, "kernel": 0, "bucket": 0},
            "typed_id_sha256": "a" * 64,
            "collections_scope": "UNKNOWN",
        }

        result = evaluate_report(report)
        inventory = by_id(result)["HF-INVENTORY"]

        self.assertEqual(inventory["status"], "UNKNOWN")
        self.assertEqual(inventory["evidence"]["repository_export"]["status"], "RECONCILED")
        self.assertEqual(inventory["evidence"]["repository_export"]["collections_scope"], "UNKNOWN")
        self.assertEqual(result["overall_status"], "UNKNOWN")

    def test_clean_bounded_evidence_remains_unknown_without_completeness_claim(
        self,
    ) -> None:
        result = evaluate_report(passing_report())
        self.assertEqual(result["overall_status"], "UNKNOWN")
        self.assertEqual(
            result["summary"], {"PASS": 9, "FAIL": 0, "UNKNOWN": 6, "NOT_APPLICABLE": 0}
        )
        self.assertEqual(result["certification"], "NOT_A_CERTIFICATION")
        controls = by_id(result)
        self.assertEqual(
            controls["HF-INVENTORY"]["evidence"]["visibility_boundary"],
            "AUTHENTICATED_BOUNDED",
        )
        for control_id in (
            "HF-CARDS",
            "HF-LICENSES",
            "HF-SAFE-MODEL-FORMATS",
            "HF-IMMUTABLE-REVISIONS",
            "HF-DYNAMIC-SPACE-SOURCE-BINDING",
        ):
            self.assertEqual(controls[control_id]["status"], "UNKNOWN")

    def test_known_failures_are_not_hidden_by_unknown_evidence(self) -> None:
        report = passing_report()
        github = report["sources"]["github"]["data"]
        github["repos"]["control"]["ci"] = "failure"
        github["repos"]["control"]["protected"] = None
        github["repos"]["control"]["classification"] = "unclassified"
        github["alerts"]["code_scanning_high"] = 3
        model = report["sources"]["huggingface"]["data"]["assets"]["models"]["items"][0]
        model["model_artifact_files_observed"] = ["model.joblib"]
        report["sources"]["dns"]["data"]["szlholdings.com"]["dmarc_reject"] = None
        result = evaluate_report(report)
        controls = by_id(result)
        self.assertEqual(result["overall_status"], "FAIL")
        self.assertEqual(controls["GH-ACTIVE-CI"]["status"], "FAIL")
        self.assertEqual(controls["GH-BRANCH-PROTECTION"]["status"], "UNKNOWN")
        self.assertEqual(controls["GH-HIGH-CODE-ALERTS"]["status"], "FAIL")
        self.assertEqual(controls["GH-REPOSITORY-CLASSIFICATION"]["status"], "FAIL")
        self.assertEqual(controls["HF-SAFE-MODEL-FORMATS"]["status"], "FAIL")
        self.assertEqual(controls["DNS-DMARC-REJECT"]["status"], "UNKNOWN")

    def test_partial_assets_preserve_observed_failure_precedence(self) -> None:
        report = passing_report()
        assets = report["sources"]["huggingface"]["data"]["assets"]
        models = assets["models"]
        models["ok"] = False
        models["partial"] = True
        models["error"] = "page 2 failed"
        model = models["items"][0]
        model.update(
            {
                "sha": None,
                "card_state": "INCOMPLETE",
                "license_declared": False,
                "model_artifact_files_observed": ["model.joblib"],
            }
        )
        spaces = assets["spaces"]
        spaces.update({"ok": False, "partial": True, "error": "page 2 failed"})
        spaces["items"][0]["source_binding_state"] = "UNAVAILABLE"
        controls = by_id(evaluate_report(report))
        for control_id in (
            "HF-CARDS",
            "HF-LICENSES",
            "HF-SAFE-MODEL-FORMATS",
            "HF-IMMUTABLE-REVISIONS",
            "HF-DYNAMIC-SPACE-SOURCE-BINDING",
        ):
            self.assertEqual(controls[control_id]["status"], "FAIL")

    def test_source_failures_remain_unknown(self) -> None:
        report = {
            "generated_at": "2026-08-11T00:00:00Z",
            "sources": {
                "github": {"ok": False, "error": "denied"},
                "huggingface": {"ok": False, "error": "timeout"},
                "dns": {"ok": False, "error": "timeout"},
            },
        }
        result = evaluate_report(report)
        self.assertEqual(result["overall_status"], "UNKNOWN")
        self.assertEqual(result["summary"]["FAIL"], 0)
        self.assertEqual(result["summary"]["UNKNOWN"], 15)

    def test_running_unbound_space_fails_but_paused_unbound_space_is_unknown(
        self,
    ) -> None:
        report = passing_report()
        space = report["sources"]["huggingface"]["data"]["assets"]["spaces"]["items"][0]
        space["source_binding_state"] = "UNAVAILABLE"
        running = evaluate_report(report)
        self.assertEqual(
            by_id(running)["HF-DYNAMIC-SPACE-SOURCE-BINDING"]["status"], "FAIL"
        )
        space["stage"] = "PAUSED"
        paused = evaluate_report(report)
        self.assertEqual(
            by_id(paused)["HF-DYNAMIC-SPACE-SOURCE-BINDING"]["status"], "UNKNOWN"
        )

    def test_invalid_sha_and_incomplete_card_fail(self) -> None:
        report = passing_report()
        dataset = report["sources"]["huggingface"]["data"]["assets"]["datasets"][
            "items"
        ][0]
        dataset["sha"] = None
        dataset["card_state"] = "INCOMPLETE"
        dataset["license_declared"] = False
        controls = by_id(evaluate_report(report))
        self.assertEqual(controls["HF-IMMUTABLE-REVISIONS"]["status"], "FAIL")
        self.assertEqual(controls["HF-CARDS"]["status"], "FAIL")
        self.assertEqual(controls["HF-LICENSES"]["status"], "FAIL")

    def test_hf_inventory_requires_observed_authenticated_org_identity(self) -> None:
        report = passing_report()
        authentication = report["sources"]["huggingface"]["data"]["authentication"]
        authentication["credential_present"] = False
        authentication["identity_authenticated"] = False
        authentication["organization_membership_observed"] = False
        authentication["inventory_scope"] = "UNAVAILABLE"
        authentication["probe_state"] = "REQUEST_FAILED"

        control = by_id(evaluate_report(report))["HF-INVENTORY"]
        self.assertEqual(control["status"], "UNKNOWN")
        self.assertIs(control["evidence"]["authenticated_scope"], False)
        self.assertEqual(
            control["evidence"]["authentication"]["probe_state"], "REQUEST_FAILED"
        )

    def test_policy_encodes_solo_maintainer_without_dco_or_fake_review(self) -> None:
        policy = json.loads(DEFAULT_POLICY.read_text(encoding="utf-8"))
        operating = policy["operating_model"]
        self.assertEqual(operating["type"], "solo-maintainer")
        self.assertIs(operating["dco_required"], False)
        self.assertIs(operating["independent_human_review_required"], False)
        self.assertIs(
            operating["independent_review_claim_allowed_without_external_actor"], False
        )
        self.assertIn("verified-signed-commits", operating["required_change_controls"])
        self.assertIn("protected-exact-head-ci", operating["required_change_controls"])

    def test_invalid_policy_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text('{"schema":"wrong"}', encoding="utf-8")
            result = evaluate_report(passing_report(), path)
        self.assertEqual(result["overall_status"], "UNKNOWN")
        self.assertEqual(result["policy_status"], "UNAVAILABLE")
        self.assertEqual(result["controls"][0]["id"], "POLICY-LOAD")


if __name__ == "__main__":
    unittest.main(verbosity=2)
