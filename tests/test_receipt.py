from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

from census.governance import evaluate_report
from census.receipt import RECEIPT_SCHEMA, build_receipt, main, parse_utc_timestamp

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).parent / "fixtures" / "estate_snapshot_v2.json"
NOW = datetime(2026, 8, 26, 17, 0, 6, tzinfo=timezone.utc)
SUBJECT = {
    "repository": "szl-holdings/szl-org-health",
    "workflow_sha": "a" * 40,
    "run_id": "32974997169",
    "run_attempt": "1",
    "run_url": "https://github.com/szl-holdings/szl-org-health/actions/runs/32974997169",
}


def fixture_object() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def bounded_snapshot(*, age_seconds: float = 6) -> bytes:
    snapshot = fixture_object()
    generated_at = (
        (NOW - timedelta(seconds=age_seconds)).isoformat().replace("+00:00", "Z")
    )
    snapshot["generated_at"] = generated_at
    repos = {
        f"repo-{index:02d}": {
            "archived": False,
            "ci": "success",
            "protected": True,
            "classification": "product",
        }
        for index in range(63)
    }
    snapshot["sources"]["github"]["data"] = {
        "discovery": {"complete": True, "scope": "organization-api"},
        "summary": {"total": 63},
        "repos": repos,
        "alerts": {
            "code_scanning_high": 0,
            "secret_scanning_open": 0,
            "dependabot_open": 0,
            "complete": True,
            "errors": {},
        },
    }
    hf_item = {
        "id": "SZLHOLDINGS/asset",
        "sha": "b" * 40,
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
    snapshot["sources"]["huggingface"]["data"] = {
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
        "assets": {
            "models": {"ok": True, "count": 1, "items": [model]},
            "datasets": {"ok": True, "count": 1, "items": [hf_item]},
            "spaces": {"ok": True, "count": 1, "items": [space]},
            "kernels": {"ok": True, "count": 0, "items": []},
            "collections": {"ok": True, "count": 0, "items": []},
            "buckets": {"ok": True, "count": 0, "items": []},
        },
    }
    snapshot["sources"]["sites"]["data"] = {
        "a-11-oy.com": {"http": 200, "hsts": True},
        "a11oy.net": {"http": 200, "hsts": True},
    }
    snapshot["sources"]["dns"]["data"] = {
        domain: {"spf": True, "dmarc": True, "dmarc_reject": True}
        for domain in (
            "szlholdings.com",
            "a-11-oy.com",
            "a11oy.net",
            "alloyszlholdings.com",
            "killinchu.net",
        )
    }
    snapshot["governance"] = evaluate_report(snapshot)
    return json.dumps(snapshot, sort_keys=True).encode("utf-8")


def receipt_for(
    snapshot_bytes: bytes | None,
    *,
    minimum: int | None = 63,
    credentials: dict | None = None,
    load_error: str | None = None,
    extra_errors: tuple[str, ...] = (),
    subject_value: dict | None = None,
) -> dict:
    return build_receipt(
        snapshot_bytes,
        snapshot_path="census-internal.json",
        snapshot_load_error=load_error,
        now=NOW,
        collector_outcome="success",
        expected_github_repositories_minimum=minimum,
        credential_presence=(
            credentials
            if credentials is not None
            else {
                "cross_repository_github_read": True,
                "huggingface_token_supplied": True,
            }
        ),
        subject=SUBJECT if subject_value is None else subject_value,
        extra_errors=extra_errors,
    )


class ReceiptContractTests(unittest.TestCase):
    def test_hosted_failure_shape_replays_fail_closed(self) -> None:
        result = receipt_for(
            FIXTURE.read_bytes(),
            credentials={
                "cross_repository_github_read": True,
                "huggingface_token_supplied": False,
            },
        )

        self.assertEqual(result["status"], "FAIL_CLOSED")
        self.assertIn("GitHub organization discovery is not complete", result["errors"])
        self.assertIn(
            "GitHub discovery scope is not organization-api", result["errors"]
        )
        self.assertIn(
            "observed GitHub repository count is below the governed minimum of 63",
            result["errors"],
        )
        self.assertIn(
            "embedded governance overall_status is not PASS: FAIL", result["errors"]
        )
        self.assertIn(
            "Hugging Face credential was not supplied",
            result["errors"],
        )
        self.assertNotIn(
            "cross-repository GitHub read credential is not configured",
            result["errors"],
        )

    def test_fresh_exact_bounded_evidence_remains_fail_closed(self) -> None:
        snapshot_bytes = bounded_snapshot()
        result = receipt_for(snapshot_bytes)

        self.assertEqual(result["schema"], RECEIPT_SCHEMA)
        self.assertEqual(result["status"], "FAIL_CLOSED")
        self.assertIn(
            "Hugging Face organization-complete inventory was not proven",
            result["errors"],
        )
        self.assertIn(
            "recomputed governance overall_status is not PASS: UNKNOWN",
            result["errors"],
        )
        self.assertEqual(
            result["snapshot"]["sha256"], hashlib.sha256(snapshot_bytes).hexdigest()
        )
        self.assertEqual(result["snapshot"]["age_seconds"], 6)
        self.assertEqual(result["snapshot"]["schema_version"], 2)
        self.assertEqual(result["subject"], SUBJECT)
        self.assertIs(result["observations"]["governance_binding_matches"], True)
        self.assertIs(result["observations"]["governance_contract_valid"], True)
        self.assertIs(result["observations"]["governance_recomputed_matches"], True)
        self.assertEqual(
            result["observations"]["governance_recomputed_status"], "UNKNOWN"
        )
        self.assertIs(result["observations"]["subject_valid"], True)
        self.assertIs(
            result["observations"]["huggingface_authentication"][
                "identity_authenticated"
            ],
            True,
        )
        self.assertNotIn(
            "principal", result["observations"]["huggingface_authentication"]
        )

    def test_freshness_boundaries_fail_closed_only_outside_window(self) -> None:
        boundary_old = receipt_for(bounded_snapshot(age_seconds=1800))
        boundary_future = receipt_for(bounded_snapshot(age_seconds=-300))
        old = receipt_for(bounded_snapshot(age_seconds=1800.9))
        future = receipt_for(bounded_snapshot(age_seconds=-300.9))
        freshness_error = (
            "snapshot freshness is outside the accepted -300..1800 second window"
        )
        self.assertNotIn(freshness_error, boundary_old["errors"])
        self.assertNotIn(freshness_error, boundary_future["errors"])
        self.assertIn(freshness_error, old["errors"])
        self.assertIn(freshness_error, future["errors"])
        self.assertEqual(old["snapshot"]["age_seconds"], 1800.9)
        self.assertEqual(future["snapshot"]["age_seconds"], -300.9)

    def test_invalid_and_naive_snapshot_timestamps_fail_closed(self) -> None:
        for timestamp in ("not-a-timestamp", "2026-08-26T17:00:00"):
            snapshot = json.loads(bounded_snapshot())
            snapshot["generated_at"] = timestamp
            snapshot["governance"]["generated_at_from_census"] = timestamp
            result = receipt_for(json.dumps(snapshot).encode("utf-8"))
            self.assertEqual(result["status"], "FAIL_CLOSED")
            self.assertIn(
                "snapshot generated_at is missing or invalid", result["errors"]
            )
        self.assertIsNone(parse_utc_timestamp("2026-08-26T17:00:00"))

    def test_missing_invalid_and_non_object_snapshots_still_return_receipts(
        self,
    ) -> None:
        missing = receipt_for(None, load_error="file not found")
        invalid = receipt_for(b"{not-json")
        non_object = receipt_for(b"[]")

        for result in (missing, invalid, non_object):
            self.assertEqual(result["schema"], RECEIPT_SCHEMA)
            self.assertEqual(result["status"], "FAIL_CLOSED")
            self.assertTrue(result["errors"])
        self.assertIsNone(missing["snapshot"]["sha256"])
        self.assertEqual(
            invalid["snapshot"]["sha256"], hashlib.sha256(b"{not-json").hexdigest()
        )

    def test_incomplete_source_is_an_explicit_failure(self) -> None:
        snapshot = json.loads(bounded_snapshot())
        snapshot["sources"]["huggingface"] = {"ok": False, "error": "denied"}
        result = receipt_for(json.dumps(snapshot).encode("utf-8"))

        self.assertEqual(result["status"], "FAIL_CLOSED")
        self.assertIs(result["observations"]["required_sources"]["huggingface"], False)
        self.assertIn("required source is not complete: huggingface", result["errors"])

    def test_partial_sources_governance_and_subject_cannot_pass(self) -> None:
        missing_data = json.loads(bounded_snapshot())
        missing_data["sources"]["sites"] = {"ok": True}
        source_result = receipt_for(json.dumps(missing_data).encode("utf-8"))
        self.assertEqual(source_result["status"], "FAIL_CLOSED")
        self.assertIn("required source is not complete: sites", source_result["errors"])

        partial_governance = json.loads(bounded_snapshot())
        partial_governance["governance"] = {
            "overall_status": "PASS",
            "generated_at_from_census": partial_governance["generated_at"],
        }
        governance_result = receipt_for(json.dumps(partial_governance).encode("utf-8"))
        self.assertEqual(governance_result["status"], "FAIL_CLOSED")
        self.assertIs(
            governance_result["observations"]["governance_contract_valid"], False
        )
        self.assertIn(
            "governance evaluation schema is missing or unsupported",
            governance_result["errors"],
        )
        empty_evidence = json.loads(bounded_snapshot())
        for control in empty_evidence["governance"]["controls"]:
            control["evidence"] = {}
        empty_evidence_result = receipt_for(json.dumps(empty_evidence).encode("utf-8"))
        self.assertEqual(empty_evidence_result["status"], "FAIL_CLOSED")
        self.assertIs(
            empty_evidence_result["observations"]["governance_contract_valid"],
            False,
        )
        self.assertIn(
            "governance control evidence metadata is incomplete",
            empty_evidence_result["errors"],
        )

        subject_result = receipt_for(bounded_snapshot(), subject_value={})
        self.assertEqual(subject_result["status"], "FAIL_CLOSED")
        self.assertIs(subject_result["observations"]["subject_valid"], False)
        self.assertIn(
            "receipt subject workflow_sha is missing or invalid",
            subject_result["errors"],
        )

    def test_governance_timestamp_must_bind_to_snapshot(self) -> None:
        snapshot = json.loads(bounded_snapshot())
        snapshot["governance"]["generated_at_from_census"] = "2026-08-26T16:59:59Z"
        result = receipt_for(json.dumps(snapshot).encode("utf-8"))

        self.assertEqual(result["status"], "FAIL_CLOSED")
        self.assertIs(result["observations"]["governance_binding_matches"], False)
        self.assertIn(
            "governance evaluation is not bound to snapshot generated_at",
            result["errors"],
        )

    def test_contradictory_hf_authentication_cannot_pass_or_leak_fields(self) -> None:
        snapshot = json.loads(bounded_snapshot())
        authentication = snapshot["sources"]["huggingface"]["data"]["authentication"]
        authentication.update(
            {
                "credential_present": False,
                "identity_authenticated": True,
                "user_identity_observed": False,
                "organization_membership_observed": True,
                "inventory_scope": "AUTHENTICATED_BOUNDED",
                "probe_state": "REQUEST_FAILED",
                "principal": "must-not-be-persisted",
                "token_role": "write",
            }
        )
        result = receipt_for(json.dumps(snapshot).encode("utf-8"))
        encoded = json.dumps(result)

        self.assertEqual(result["status"], "FAIL_CLOSED")
        self.assertIn(
            "Hugging Face credential presence was not observed", result["errors"]
        )
        self.assertIn("Hugging Face user identity was not observed", result["errors"])
        self.assertIn(
            "Hugging Face identity probe was not authenticated", result["errors"]
        )
        self.assertIs(result["observations"]["governance_recomputed_matches"], False)
        self.assertNotIn("must-not-be-persisted", encoded)
        self.assertNotIn("token_role", encoded)

    def test_known_governance_failure_is_not_hidden_by_unknown_evidence(self) -> None:
        snapshot = fixture_object()
        snapshot["sources"]["huggingface"] = {"ok": False, "error": "timeout"}
        result = receipt_for(json.dumps(snapshot).encode("utf-8"))

        self.assertEqual(result["status"], "FAIL_CLOSED")
        self.assertEqual(result["observations"]["governance_status"], "FAIL")
        self.assertIn(
            "embedded governance overall_status is not PASS: FAIL", result["errors"]
        )
        self.assertIn("required source is not complete: huggingface", result["errors"])

    def test_missing_or_invalid_minimum_fails_without_throwing(self) -> None:
        for minimum in (None, -1, True):
            result = receipt_for(bounded_snapshot(), minimum=minimum)
            self.assertEqual(result["status"], "FAIL_CLOSED")
            self.assertIn(
                "expected GitHub repository minimum is missing or invalid",
                result["errors"],
            )
            self.assertIsNone(result["observations"]["github_repository_minimum"])

    def test_credentials_are_allowlisted_booleans_only(self) -> None:
        result = receipt_for(
            bounded_snapshot(),
            credentials={
                "cross_repository_github_read": "secret-token",
                "huggingface_token_supplied": object(),
                "unexpected": "must-not-appear",
            },
        )
        encoded = json.dumps(result)

        self.assertEqual(
            result["credential_presence"],
            {
                "cross_repository_github_read": False,
                "huggingface_token_supplied": False,
            },
        )
        self.assertNotIn("secret-token", encoded)
        self.assertNotIn("must-not-appear", encoded)

    def test_untrusted_diagnostics_and_subject_values_never_leak(self) -> None:
        canary = "PRIVATE-RECEIPT-CANARY"
        snapshot = json.loads(bounded_snapshot())
        github = snapshot["sources"]["github"]["data"]
        github["discovery"]["error"] = canary
        github["summary"]["total"] = canary
        snapshot["generated_at"] = canary
        snapshot["governance"]["generated_at_from_census"] = canary
        result = build_receipt(
            json.dumps(snapshot).encode("utf-8"),
            snapshot_path=f"C:/private/{canary}/data.json",
            snapshot_load_error=canary,
            now=NOW,
            collector_outcome=canary,
            expected_github_repositories_minimum=63,
            credential_presence={
                "cross_repository_github_read": True,
                "huggingface_token_supplied": True,
            },
            subject={field: canary for field in SUBJECT},
            extra_errors=(canary,),
        )
        encoded = json.dumps(result, sort_keys=True)

        self.assertNotIn(canary, encoded)
        self.assertEqual(result["collector_outcome"], "unknown")
        self.assertEqual(result["snapshot"]["path"], "data.json")
        self.assertIsNone(result["snapshot"]["generated_at"])
        self.assertEqual(
            result["observations"]["github_discovery"],
            {"complete": True, "scope": "organization-api"},
        )
        self.assertIsNone(result["observations"]["github_repository_total"])
        self.assertEqual(
            result["subject"],
            {
                "repository": None,
                "workflow_sha": None,
                "run_id": None,
                "run_attempt": None,
                "run_url": None,
            },
        )
        self.assertIn("receipt precondition failed", result["errors"])

    def test_json_round_trip_preserves_receipt_contract(self) -> None:
        result = receipt_for(bounded_snapshot())
        restored = json.loads(json.dumps(result, sort_keys=True))

        self.assertEqual(restored["schema"], RECEIPT_SCHEMA)
        self.assertEqual(restored["snapshot"], result["snapshot"])
        self.assertEqual(restored["subject"], SUBJECT)
        self.assertEqual(restored["observations"], result["observations"])
        self.assertEqual(restored["errors"], result["errors"])
        self.assertIn(
            "Hugging Face organization-complete inventory was not proven",
            restored["errors"],
        )

    def test_exact_isolated_workflow_command_writes_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "census").mkdir()
            (root / "governance").mkdir()
            (root / "static").mkdir()
            shutil.copy2(
                REPO_ROOT / "census" / "receipt.py", root / "census" / "receipt.py"
            )
            shutil.copy2(
                REPO_ROOT / "census" / "governance.py",
                root / "census" / "governance.py",
            )
            shutil.copy2(
                REPO_ROOT / "governance" / "policy.json",
                root / "governance" / "policy.json",
            )
            shutil.copy2(FIXTURE, root / "census-internal.json")
            environment = os.environ.copy()
            environment.update(
                {
                    "COLLECT_OUTCOME": "success",
                    "EXPECTED_GITHUB_REPOSITORIES_MINIMUM": "63",
                    "HAS_CROSS_REPO_GITHUB_TOKEN": "true",
                    "HAS_HF_TOKEN": "true",
                    "RECEIPT_REPOSITORY": SUBJECT["repository"],
                    "RECEIPT_WORKFLOW_SHA": SUBJECT["workflow_sha"],
                    "RECEIPT_RUN_ID": SUBJECT["run_id"],
                    "RECEIPT_RUN_ATTEMPT": SUBJECT["run_attempt"],
                    "RECEIPT_RUN_URL": SUBJECT["run_url"],
                }
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "census/receipt.py",
                    "--snapshot",
                    "census-internal.json",
                ],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            receipt_path = root / "census-receipt.json"
            self.assertEqual(completed.returncode, 1, completed.stderr)
            self.assertTrue(receipt_path.is_file(), completed.stderr)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

        self.assertEqual(receipt["status"], "FAIL_CLOSED")
        self.assertIs(receipt["observations"]["governance_recomputed_matches"], False)

    def test_cli_writes_fail_closed_receipt_for_invalid_minimum(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot_path = root / "data.json"
            receipt_path = root / "receipt.json"
            snapshot_path.write_bytes(bounded_snapshot())
            environment = {
                "COLLECT_OUTCOME": "success",
                "EXPECTED_GITHUB_REPOSITORIES_MINIMUM": "not-an-integer",
                "HAS_CROSS_REPO_GITHUB_TOKEN": "true",
                "HAS_HF_TOKEN": "true",
                "RECEIPT_REPOSITORY": SUBJECT["repository"],
                "RECEIPT_WORKFLOW_SHA": SUBJECT["workflow_sha"],
                "RECEIPT_RUN_ID": SUBJECT["run_id"],
                "RECEIPT_RUN_ATTEMPT": SUBJECT["run_attempt"],
                "RECEIPT_RUN_URL": SUBJECT["run_url"],
            }

            with redirect_stdout(io.StringIO()):
                exit_code = main(
                    [
                        "--snapshot",
                        str(snapshot_path),
                        "--receipt",
                        str(receipt_path),
                    ],
                    environ=environment,
                    now=NOW,
                )
            persisted = json.loads(receipt_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 1)
        self.assertEqual(persisted["status"], "FAIL_CLOSED")
        self.assertIn(
            "expected GitHub repository minimum is missing or invalid",
            persisted["errors"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
