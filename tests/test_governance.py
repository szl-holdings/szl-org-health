from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from census.governance import DEFAULT_POLICY, evaluate_report


SHA = "a" * 40


def passing_report() -> dict:
    repos = {
        "control": {"archived": False, "ci": "success", "protected": True, "classification": "control-plane"},
        "archive": {"archived": True, "ci": "archived", "protected": None, "classification": "archive"},
    }
    hf_item = {"id": "SZLHOLDINGS/asset", "sha": SHA, "card_state": "COMPLETE", "card_present": True, "license_declared": True}
    model = {**hf_item, "model_artifact_files_observed": ["model.safetensors"], "weight_files_observed": ["model.safetensors"], "estimator_files_observed": []}
    space = {**hf_item, "sdk": "docker", "stage": "RUNNING", "source_binding_state": "OBSERVED"}
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
        for domain in ("szlholdings.com", "a-11-oy.com", "a11oy.net", "alloyszlholdings.com", "killinchu.net")
    }
    return {
        "schema_version": 2,
        "generated_at": "2026-08-11T00:00:00Z",
        "sources": {
            "github": {"ok": True, "data": {"discovery": {"complete": True, "scope": "organization-api"}, "summary": {"total": 2}, "repos": repos, "alerts": {"code_scanning_high": 0, "secret_scanning_open": 0, "dependabot_open": 0, "complete": True, "errors": {}}}},
            "huggingface": {"ok": True, "data": {"assets": assets}},
            "dns": {"ok": True, "data": dns},
        },
    }


def by_id(result: dict) -> dict[str, dict]:
    return {control["id"]: control for control in result["controls"]}


class GovernanceEvaluationTests(unittest.TestCase):
    def test_complete_clean_evidence_passes_without_certification_claim(self) -> None:
        result = evaluate_report(passing_report())
        self.assertEqual(result["overall_status"], "PASS")
        self.assertEqual(result["summary"], {"PASS": 15, "FAIL": 0, "UNKNOWN": 0, "NOT_APPLICABLE": 0})
        self.assertEqual(result["certification"], "NOT_A_CERTIFICATION")

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

    def test_source_failures_remain_unknown(self) -> None:
        report = {"generated_at": "2026-08-11T00:00:00Z", "sources": {"github": {"ok": False, "error": "denied"}, "huggingface": {"ok": False, "error": "timeout"}, "dns": {"ok": False, "error": "timeout"}}}
        result = evaluate_report(report)
        self.assertEqual(result["overall_status"], "UNKNOWN")
        self.assertEqual(result["summary"]["FAIL"], 0)
        self.assertEqual(result["summary"]["UNKNOWN"], 15)

    def test_running_unbound_space_fails_but_paused_unbound_space_is_unknown(self) -> None:
        report = passing_report()
        space = report["sources"]["huggingface"]["data"]["assets"]["spaces"]["items"][0]
        space["source_binding_state"] = "UNAVAILABLE"
        running = evaluate_report(report)
        self.assertEqual(by_id(running)["HF-DYNAMIC-SPACE-SOURCE-BINDING"]["status"], "FAIL")
        space["stage"] = "PAUSED"
        paused = evaluate_report(report)
        self.assertEqual(by_id(paused)["HF-DYNAMIC-SPACE-SOURCE-BINDING"]["status"], "UNKNOWN")

    def test_invalid_sha_and_incomplete_card_fail(self) -> None:
        report = passing_report()
        dataset = report["sources"]["huggingface"]["data"]["assets"]["datasets"]["items"][0]
        dataset["sha"] = None
        dataset["card_state"] = "INCOMPLETE"
        dataset["license_declared"] = False
        controls = by_id(evaluate_report(report))
        self.assertEqual(controls["HF-IMMUTABLE-REVISIONS"]["status"], "FAIL")
        self.assertEqual(controls["HF-CARDS"]["status"], "FAIL")
        self.assertEqual(controls["HF-LICENSES"]["status"], "FAIL")

    def test_policy_encodes_solo_maintainer_without_dco_or_fake_review(self) -> None:
        policy = json.loads(DEFAULT_POLICY.read_text(encoding="utf-8"))
        operating = policy["operating_model"]
        self.assertEqual(operating["type"], "solo-maintainer")
        self.assertIs(operating["dco_required"], False)
        self.assertIs(operating["independent_human_review_required"], False)
        self.assertIs(operating["independent_review_claim_allowed_without_external_actor"], False)
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

