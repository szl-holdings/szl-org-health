from __future__ import annotations

import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from autonomic import slo_controller
from autonomic.slo_evidence import load_receipt

from autonomic.slo_controller import (
    ContractError,
    GitHubApi,
    PathProbe,
    append_sample,
    classify_provider_blocker,
    decode_state,
    empty_state,
    encode_state,
    extract_state,
    fixed_url,
    incident_body,
    issue_state_body,
    load_policy,
    offline_contract,
    severity_for_surface,
    summarize_window,
    validate_manifest,
    validate_policy,
)


def policy_payload() -> dict:
    return {
        "schema": "szl.autonomic-slo-policy/v1",
        "controller_repository": "szl-holdings/szl-org-health",
        "controller_branch": "main",
        "source_manifest": {
            "repository": "szl-holdings/a11oy",
            "branch": "main",
            "path": "governance/public-estate.v1.json",
            "require_verified_commit": True,
        },
        "cadence_minutes": 5,
        "history_retention_minutes": 20160,
        "availability_objective_percent": 99.9,
        "latency_objective_ms": 2500,
        "recovery_objective_minutes": 20,
        "minimum_window_coverage_percent": 50,
        "probe": {
            "timeout_seconds": 8,
            "max_response_bytes": 262144,
            "parallelism": 16,
        },
        "burn_windows": [
            {"name": "fast", "minutes": 60, "burn_threshold": 14.4},
            {"name": "medium", "minutes": 360, "burn_threshold": 6.0},
            {"name": "slow", "minutes": 1440, "burn_threshold": 3.0},
        ],
        "deadman": {
            "workflow_file": "autonomic-sre.yml",
            "maximum_age_minutes": 20,
            "accepted_conclusions": ["success", "failure"],
        },
        "incident": {
            "label": "autonomic-slo",
            "title": "[AUTONOMIC-SLO] Public estate reliability incident",
            "healthy_cycles_before_close": 3,
            "refresh_minutes": 30,
        },
        "state_issue": {
            "title": "[AUTONOMIC-SLO] Public estate reliability state",
            "heartbeat_minutes": 60,
        },
        "allowed_hf_repositories": [
            "SZLHOLDINGS/a11oy",
            "SZLHOLDINGS/killinchu",
        ],
    }


def manifest_payload() -> dict:
    return {
        "schema": "szl.public-estate/v1",
        "estate": "test",
        "source_repository": "szl-holdings/a11oy",
        "truth_policy": "exact-source-or-unverified",
        "allowed_hosts": [
            "api.github.com",
            "huggingface.co",
            "szlholdings-a11oy.hf.space",
            "szlholdings-killinchu.hf.space",
        ],
        "platforms": [
            {
                "id": "a11oy",
                "title": "A11oy",
                "public": True,
                "hf_repository": "SZLHOLDINGS/a11oy",
                "base_url": "https://szlholdings-a11oy.hf.space",
                "required_paths": ["/", "/api/build-info"],
                "build_info_path": "/api/build-info",
            }
        ],
        "public_products": [
            {
                "id": "killinchu",
                "title": "Killinchu",
                "public": True,
                "hf_repository": "SZLHOLDINGS/killinchu",
                "base_url": "https://szlholdings-killinchu.hf.space",
                "required_paths": ["/", "/api/build-info"],
                "build_info_path": "/api/build-info",
            }
        ],
    }


def path_probe(status: int | None) -> PathProbe:
    return PathProbe(
        path="/healthz",
        ok=status is not None and 200 <= status < 300,
        status=status,
        latency_ms=100,
        content_type="application/json",
        body_sha256="a" * 64 if status == 200 else None,
        body_bytes=2 if status == 200 else None,
        error_kind=None if status == 200 else "HTTP_ERROR",
    )


def complete_buckets(
    *,
    now_epoch: int,
    minutes: int,
    cadence: int,
    failures: set[int] | None = None,
    latency_breaches: set[int] | None = None,
) -> list[list[int]]:
    rows: list[list[int]] = []
    failures = failures or set()
    latency_breaches = latency_breaches or set()
    for index in range(minutes // cadence):
        sample = now_epoch - index * cadence * 60
        rows = append_sample(
            rows,
            sample_epoch=sample,
            ok=index not in failures,
            latency_ms=3000 if index in latency_breaches else 100,
            latency_objective_ms=2500,
            retention_minutes=20160,
        )
    return rows


class PolicyAndManifestTests(unittest.TestCase):
    def test_policy_is_strict_and_hashable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "policy.json"
            path.write_text(json.dumps(policy_payload()), encoding="utf-8")
            policy, digest = load_policy(path)
        self.assertEqual(policy["cadence_minutes"], 5)
        self.assertEqual([item["name"] for item in policy["burn_windows"]], ["fast", "medium", "slow"])
        self.assertEqual(len(digest), 64)

    def test_policy_requires_verified_manifest_tip(self) -> None:
        payload = policy_payload()
        payload["source_manifest"]["require_verified_commit"] = False
        with self.assertRaises(ContractError):
            validate_policy(payload)

    def test_policy_rejects_unbounded_workflow_path(self) -> None:
        payload = policy_payload()
        payload["deadman"]["workflow_file"] = "../../arbitrary.yml"
        with self.assertRaises(ContractError):
            validate_policy(payload)

    def test_policy_requires_increasing_windows_and_retention(self) -> None:
        payload = policy_payload()
        payload["burn_windows"][1]["minutes"] = 30
        with self.assertRaises(ContractError):
            validate_policy(payload)
        payload = policy_payload()
        payload["history_retention_minutes"] = 1200
        with self.assertRaises(ContractError):
            validate_policy(payload)

    def test_manifest_exactly_matches_policy_repository_set(self) -> None:
        value = validate_manifest(manifest_payload(), policy=validate_policy(policy_payload()))
        self.assertEqual([item["id"] for item in value["surfaces"]], ["a11oy", "killinchu"])

    def test_manifest_rejects_origin_escape_and_repo_mismatch(self) -> None:
        payload = manifest_payload()
        payload["platforms"][0]["base_url"] = "https://attacker.example"
        with self.assertRaises(ContractError):
            validate_manifest(payload, policy=validate_policy(policy_payload()))
        payload = manifest_payload()
        payload["platforms"][0]["base_url"] = "https://szlholdings-killinchu.hf.space"
        with self.assertRaises(ContractError):
            validate_manifest(payload, policy=validate_policy(policy_payload()))

    def test_manifest_rejects_query_fragment_and_duplicate_paths(self) -> None:
        payload = manifest_payload()
        payload["platforms"][0]["required_paths"][0] = "/?redirect=https://attacker.example"
        with self.assertRaises(ContractError):
            validate_manifest(payload, policy=validate_policy(policy_payload()))
        payload = manifest_payload()
        payload["platforms"][0]["required_paths"] = ["/api/build-info", "/api/build-info"]
        with self.assertRaises(ContractError):
            validate_manifest(payload, policy=validate_policy(policy_payload()))

    def test_fixed_url_never_accepts_an_origin(self) -> None:
        self.assertEqual(
            fixed_url("https://szlholdings-a11oy.hf.space", "/healthz"),
            "https://szlholdings-a11oy.hf.space/healthz",
        )
        with self.assertRaises(ContractError):
            fixed_url("https://szlholdings-a11oy.hf.space", "https://attacker.example/")


class StateTests(unittest.TestCase):
    def test_compressed_state_round_trip(self) -> None:
        state = empty_state()
        state["updated_at"] = "2026-09-04T12:00:00Z"
        state["surface_history"] = {
            "a11oy": {"buckets": [[1_788_500_000, 3, 1, 1, 3000, 1_788_500_300]]}
        }
        encoded = encode_state(state)
        self.assertNotIn("surface_history", encoded)
        self.assertEqual(decode_state(encoded), state)

    def test_malformed_or_oversized_state_fails_closed(self) -> None:
        self.assertEqual(decode_state("not-base64")["surface_history"], {})
        self.assertEqual(extract_state("no markers")["surface_history"], {})

    def test_duplicate_sample_in_same_slot_is_not_counted_twice(self) -> None:
        rows = append_sample(
            [],
            sample_epoch=1_788_500_000,
            ok=True,
            latency_ms=100,
            latency_objective_ms=2500,
            retention_minutes=1440,
        )
        duplicate = append_sample(
            rows,
            sample_epoch=1_788_500_000,
            ok=False,
            latency_ms=9000,
            latency_objective_ms=2500,
            retention_minutes=1440,
        )
        self.assertEqual(duplicate, rows)
        self.assertEqual(sum(item[1] for item in duplicate), 1)

    def test_samples_aggregate_and_retention_trims_old_buckets(self) -> None:
        rows: list[list[int]] = []
        for sample in (1_788_000_000, 1_788_500_000, 1_788_500_300):
            rows = append_sample(
                rows,
                sample_epoch=sample,
                ok=sample != 1_788_500_300,
                latency_ms=3000 if sample == 1_788_500_300 else 100,
                latency_objective_ms=2500,
                retention_minutes=60,
            )
        self.assertEqual(sum(item[1] for item in rows), 2)
        self.assertEqual(sum(item[2] for item in rows), 1)
        self.assertEqual(sum(item[3] for item in rows), 1)


class ObjectiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = validate_policy(policy_payload())
        self.now_epoch = 1_788_500_000

    def result(self, rows: list[list[int]], name: str = "fast", minutes: int = 60):
        return summarize_window(
            rows,
            name=name,
            minutes=minutes,
            now_epoch=self.now_epoch,
            cadence_minutes=5,
            availability_objective_percent=99.9,
            minimum_coverage_percent=50,
        )

    def test_zero_samples_are_unknown_not_healthy(self) -> None:
        result = self.result([])
        self.assertIsNone(result.availability_percent)
        self.assertIsNone(result.error_budget_burn)
        self.assertFalse(result.sufficient_coverage)

    def test_coverage_gate_prevents_sparse_burn_claim(self) -> None:
        rows = complete_buckets(now_epoch=self.now_epoch, minutes=20, cadence=5, failures={0})
        result = self.result(rows)
        self.assertLess(result.coverage_percent, 50)
        self.assertFalse(result.sufficient_coverage)

    def test_one_failure_in_twelve_samples_has_expected_burn(self) -> None:
        rows = complete_buckets(now_epoch=self.now_epoch, minutes=60, cadence=5, failures={0})
        result = self.result(rows)
        self.assertTrue(result.sufficient_coverage)
        self.assertAlmostEqual(result.availability_percent or 0, 91.666667, places=5)
        self.assertGreater(result.error_budget_burn or 0, 80)

    def test_latency_breach_rate_is_independent_of_availability(self) -> None:
        rows = complete_buckets(
            now_epoch=self.now_epoch,
            minutes=60,
            cadence=5,
            latency_breaches={0, 1, 2},
        )
        result = self.result(rows)
        self.assertEqual(result.availability_percent, 100.0)
        self.assertEqual(result.latency_breach_percent, 25.0)

    def test_fast_and_medium_burn_trigger_sev1(self) -> None:
        rows = complete_buckets(
            now_epoch=self.now_epoch,
            minutes=360,
            cadence=5,
            failures=set(range(8)),
        )
        windows = [
            self.result(rows, window["name"], window["minutes"])
            for window in self.policy["burn_windows"]
        ]
        severity, reasons = severity_for_surface(
            current_ok=False,
            provider_blocker=None,
            windows=windows,
            policy=self.policy,
        )
        self.assertEqual(severity, "SEV1")
        self.assertTrue(reasons)

    def test_provider_payment_blocker_is_sev2_without_restart_claim(self) -> None:
        windows = [self.result([]) for _ in range(3)]
        severity, reasons = severity_for_surface(
            current_ok=False,
            provider_blocker="PAYMENT_REQUIRED",
            windows=windows,
            policy=self.policy,
        )
        self.assertEqual(severity, "SEV2")
        self.assertIn("PAYMENT_REQUIRED", reasons[0])

    def test_current_outage_with_insufficient_history_is_sev3(self) -> None:
        windows = [self.result([]) for _ in range(3)]
        severity, reasons = severity_for_surface(
            current_ok=False,
            provider_blocker=None,
            windows=windows,
            policy=self.policy,
        )
        self.assertEqual(severity, "SEV3")
        self.assertTrue(reasons)

    def test_provider_blocker_classification_is_explicit(self) -> None:
        self.assertEqual(classify_provider_blocker([path_probe(402)]), "PAYMENT_REQUIRED")
        self.assertEqual(classify_provider_blocker([path_probe(429)]), "RATE_LIMITED")
        self.assertEqual(classify_provider_blocker([path_probe(403)]), "ACCESS_DENIED")
        self.assertIsNone(classify_provider_blocker([path_probe(503)]))


class DeadmanTests(unittest.TestCase):
    def client(self, payload: dict) -> GitHubApi:
        client = GitHubApi(
            token="not-used",
            repository="szl-holdings/szl-org-health",
            timeout=8,
        )
        client.request = lambda method, path, body=None: payload  # type: ignore[method-assign]
        return client

    def test_recent_success_or_failure_is_a_live_scheduler_heartbeat(self) -> None:
        now = dt.datetime(2026, 9, 4, 12, 0, tzinfo=dt.timezone.utc)
        for conclusion in ("success", "failure"):
            payload = {
                "workflow_runs": [
                    {
                        "id": 10,
                        "status": "completed",
                        "conclusion": conclusion,
                        "created_at": "2026-09-04T11:55:00Z",
                        "updated_at": "2026-09-04T11:56:00Z",
                    }
                ]
            }
            result = self.client(payload).workflow_deadman(
                "autonomic-sre.yml",
                now=now,
                policy=validate_policy(policy_payload()),
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["state"], "FRESH")

    def test_old_or_missing_run_fails_deadman(self) -> None:
        now = dt.datetime(2026, 9, 4, 12, 0, tzinfo=dt.timezone.utc)
        old = {
            "workflow_runs": [
                {
                    "id": 10,
                    "status": "completed",
                    "conclusion": "success",
                    "created_at": "2026-09-04T10:00:00Z",
                    "updated_at": "2026-09-04T10:01:00Z",
                }
            ]
        }
        result = self.client(old).workflow_deadman(
            "autonomic-sre.yml",
            now=now,
            policy=validate_policy(policy_payload()),
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "STALE")
        missing = self.client({"workflow_runs": []}).workflow_deadman(
            "autonomic-sre.yml",
            now=now,
            policy=validate_policy(policy_payload()),
        )
        self.assertEqual(missing["state"], "MISSING")


class RenderingAndAuthorityTests(unittest.TestCase):
    def report(self) -> dict:
        windows = [
            {
                "name": name,
                "error_budget_burn": 0.0,
                "availability_percent": 100.0,
            }
            for name in ("fast", "medium", "slow")
        ]
        return {
            "generated_at": "2026-09-04T12:00:00Z",
            "verdict": "HEALTHY",
            "severity": None,
            "manifest_revision": "a" * 40,
            "receipt_sha256": "b" * 64,
            "observation_sha256": "c" * 64,
            "reasons": [],
            "deadman": {"state": "FRESH"},
            "surfaces": [
                {
                    "id": "a11oy",
                    "current_ok": True,
                    "provider_blocker": None,
                    "maximum_latency_ms": 100,
                    "severity": None,
                    "windows": windows,
                }
            ],
        }

    def test_state_issue_is_bounded_and_round_trips(self) -> None:
        state = empty_state()
        state["updated_at"] = "2026-09-04T12:00:00Z"
        body = issue_state_body(state, self.report())
        self.assertLess(len(body.encode("utf-8")), 60_000)
        self.assertEqual(extract_state(body), state)

    def test_incident_body_contains_no_command_or_credential_material(self) -> None:
        report = self.report()
        report["verdict"] = "INCIDENT"
        report["severity"] = "SEV2"
        report["reasons"] = ["a11oy: provider blocker: PAYMENT_REQUIRED"]
        body = incident_body(report)
        self.assertIn("PAYMENT_REQUIRED", body)
        self.assertNotIn("Authorization", body)
        self.assertNotIn("Bearer ", body)
        self.assertNotIn("Invoke-Expression", body)

    def test_offline_contract_denies_mutating_authority(self) -> None:
        policy = validate_policy(policy_payload())
        contract = offline_contract(policy, "a" * 64)
        self.assertTrue(contract["authority"]["issue_state_only"])
        for key in (
            "service_restart",
            "workflow_dispatch",
            "source_write",
            "dns_mutation",
            "asset_deletion",
            "product_action",
            "arbitrary_shell",
        ):
            self.assertFalse(contract["authority"][key])
        self.assertFalse(contract["secret_values_recorded"])


class LiveReceiptBindingTests(unittest.TestCase):
    def test_incident_lifecycle_binds_to_immutable_observation(self) -> None:
        policy = validate_policy(policy_payload())
        manifest = validate_manifest(manifest_payload(), policy=policy)

        class FakeGitHub:
            def __init__(self, action: str) -> None:
                self.action = action
                self.writes: list[dict] = []
                self.previous = empty_state()
                self.previous["healthy_cycles"] = 2 if action in ("closed", "sparse") else 0
                if action in ("closed", "sparse"):
                    now_epoch = int(dt.datetime.now(dt.timezone.utc).timestamp())
                    rows = complete_buckets(
                        now_epoch=now_epoch - now_epoch % 300,
                        minutes=1440 if action == "closed" else 360,
                        cadence=5,
                        failures={20, 30} if action == "sparse" else None,
                    )
                    self.previous["surface_history"] = {
                        surface["id"]: {"buckets": rows}
                        for surface in manifest["surfaces"]
                    }

            def verified_tip(self, *args):
                return "a" * 40

            def find_open_issue(self, title):
                if title == policy["state_issue"]["title"]:
                    return {
                        "number": 44,
                        "body": issue_state_body(self.previous, {}),
                    }
                return None if self.action == "created" else {"number": 93}

            def workflow_deadman(self, *args, **kwargs):
                return {"ok": True, "state": "FRESH"}

            def ensure_label(self, *args):
                pass

            def create_issue(self, **kwargs):
                self.writes.append({"number": 93, "state": "open", **kwargs})
                return {"number": 93}

            def update_issue(self, issue, **kwargs):
                self.writes.append({"number": issue["number"], **kwargs})

        for action in ("created", "refreshed", "closed", "sparse"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as temporary:
                github = FakeGitHub(action)

                def probe(surface, *, policy):
                    ok = action in ("closed", "sparse") or surface["id"] != "a11oy"
                    return slo_controller.SurfaceProbe(
                        surface_id=surface["id"],
                        hf_repository=surface["hf_repository"],
                        base_url=surface["base_url"],
                        ok=ok,
                        maximum_latency_ms=100 if ok else 8000,
                        provider_blocker=None,
                        paths=(path_probe(200 if ok else 503),),
                    )

                output = Path(temporary) / "receipt.json"
                with (
                    patch.object(slo_controller, "GitHubApi", return_value=github),
                    patch.object(slo_controller, "load_signed_manifest", return_value=(
                        manifest, "b" * 40, "c" * 64
                    )),
                    patch.object(slo_controller, "probe_surface", side_effect=probe),
                    patch.dict(os.environ, {
                        "GITHUB_REPOSITORY": policy["controller_repository"],
                        "GITHUB_SHA": "a" * 40,
                        "GITHUB_TOKEN": "test-value-never-sent",
                    }),
                ):
                    result = slo_controller.run_live(
                        policy=policy, policy_sha256="d" * 64, output=output
                    )

                self.assertEqual(result, 0 if action == "closed" else 2)
                report = load_receipt(output, str(result))
                expected_action = "refreshed" if action == "sparse" else action
                self.assertEqual(report["incident"], {"action": expected_action, "number": 93})
                measurement = {
                    key: value for key, value in report.items()
                    if key not in {"incident", "receipt_sha256", "observation_sha256"}
                }
                expected = slo_controller.sha256_hex(slo_controller.canonical_json(measurement))
                self.assertEqual(report["observation_sha256"], expected)
                incident_write = next(item for item in github.writes if item["number"] == 93)
                body = incident_write["body"]
                self.assertIn(f"- Observation SHA-256: `{expected}`", body)
                self.assertNotIn("- Receipt:", body)
                self.assertNotEqual(report["receipt_sha256"], expected)
                if action == "closed":
                    self.assertEqual(incident_write["state"], "closed")
                    self.assertIn("- Verdict: `RECOVERED`", body)
                    self.assertIn("recorded HEALTHY measurement", body)
                    self.assertEqual(report["verdict"], "HEALTHY")
                    self.assertEqual(report["reasons"], [])
                    self.assertEqual(report["healthy_cycles"], 3)
                else:
                    self.assertEqual(incident_write["state"], "open")
                    self.assertEqual(report["verdict"], "INCIDENT")
                    self.assertEqual(report["healthy_cycles"], 0)
                    if action == "sparse":
                        self.assertEqual(report["severity"], "SEV3")
                        self.assertTrue(
                            any(
                                "insufficient sample coverage to establish health: " in reason
                                and "/slow" in reason
                                for reason in report["reasons"]
                            )
                        )
                        a11oy = next(row for row in report["surfaces"] if row["id"] == "a11oy")
                        windows = {row["name"]: row for row in a11oy["windows"]}
                        self.assertGreater(windows["medium"]["error_budget_burn"], 6.0)
                        self.assertFalse(windows["slow"]["sufficient_coverage"])
                        state_write = next(item for item in github.writes if item["number"] == 44)
                        retained = extract_state(state_write["body"])["surface_history"]["a11oy"]["buckets"]
                        self.assertEqual(sum(bucket[2] for bucket in retained), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
