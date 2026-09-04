from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from autonomic.controller import (
    ContractError,
    PathObservation,
    SurfaceObservation,
    extract_state,
    issue_body,
    load_policy,
    plan_recovery,
    state_requires_write,
    validate_manifest,
)


def policy_payload() -> dict:
    return {
        "schema": "szl.autonomic-sre-policy/v1",
        "controller_repository": "szl-holdings/szl-org-health",
        "controller_branch": "main",
        "source_manifest": {
            "repository": "szl-holdings/a11oy",
            "branch": "main",
            "path": "governance/public-estate.v1.json",
            "require_verified_commit": True,
        },
        "probe": {
            "interval_minutes": 5,
            "timeout_seconds": 8,
            "max_response_bytes": 262144,
            "parallelism": 8,
            "failure_threshold": 2,
        },
        "recovery": {
            "enabled": True,
            "max_actions_per_cycle": 1,
            "cooldown_minutes": 30,
            "max_attempts_before_incident": 3,
            "paused_stages": ["PAUSED", "SLEEPING", "STOPPED"],
            "transitional_stages": ["BUILDING", "STARTING", "RESTARTING"],
            "terminal_stages": ["RUNTIME_ERROR", "BUILD_ERROR", "CONFIG_ERROR"],
        },
        "state_issue": {
            "title": "[AUTONOMIC-SRE] Public estate state",
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
                "class": "platform",
                "public": True,
                "hf_repository": "SZLHOLDINGS/a11oy",
                "base_url": "https://szlholdings-a11oy.hf.space",
                "deployment_source_repository": "szl-holdings/a11oy",
                "revision_policy": "exact-default-branch",
                "default_branch": "main",
                "build_info_path": "/api/build-info",
                "required_paths": ["/", "/api/build-info"],
            }
        ],
        "public_products": [
            {
                "id": "killinchu",
                "title": "Killinchu",
                "class": "resilience",
                "public": True,
                "hf_repository": "SZLHOLDINGS/killinchu",
                "base_url": "https://szlholdings-killinchu.hf.space",
                "deployment_source_repository": "szl-holdings/killinchu",
                "revision_policy": "declared-commit",
                "build_info_path": "/api/build-info",
                "required_paths": ["/api/killinchu/healthz", "/api/build-info"],
            }
        ],
    }


def observation(*, available: bool, source_ok: bool = True) -> SurfaceObservation:
    row = PathObservation(
        path="/healthz",
        status=200 if available else 503,
        elapsed_ms=10,
        content_type="application/json",
        body_sha256="a" * 64 if available else None,
        body_bytes=2 if available else None,
        ok=available,
        error_kind=None if available else "HTTP_503",
    )
    return SurfaceObservation(
        surface_id="a11oy",
        hf_repository="SZLHOLDINGS/a11oy",
        base_url="https://szlholdings-a11oy.hf.space",
        availability_ok=available,
        source_ok=source_ok,
        source_status="EXACT" if source_ok else "DRIFT",
        source_revision="a" * 40,
        expected_revision="a" * 40 if source_ok else "b" * 40,
        paths=(row,),
        failures=() if available and source_ok else ("unhealthy",),
    )


class PolicyTests(unittest.TestCase):
    def test_policy_is_validated_and_canonicalized(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "policy.json"
            path.write_text(json.dumps(policy_payload()), encoding="utf-8")
            policy, digest = load_policy(path)
        self.assertEqual(policy["probe"]["failure_threshold"], 2)
        self.assertEqual(policy["recovery"]["max_actions_per_cycle"], 1)
        self.assertEqual(len(digest), 64)

    def test_policy_rejects_non_szl_hf_repository(self) -> None:
        payload = policy_payload()
        payload["allowed_hf_repositories"][0] = "outside/a11oy"
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "policy.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(ContractError):
                load_policy(path)

    def test_manifest_must_match_policy_repository_set(self) -> None:
        policy = policy_payload()
        manifest = manifest_payload()
        validated = validate_manifest(manifest, policy=policy)
        self.assertEqual(
            [item["id"] for item in validated["surfaces"]],
            ["a11oy", "killinchu"],
        )
        manifest["public_products"][0]["hf_repository"] = "SZLHOLDINGS/terra"
        with self.assertRaises(ContractError):
            validate_manifest(manifest, policy=policy)

    def test_manifest_rejects_origin_escape(self) -> None:
        manifest = manifest_payload()
        manifest["platforms"][0]["base_url"] = "https://attacker.example"
        with self.assertRaises(ContractError):
            validate_manifest(manifest, policy=policy_payload())


class StateMachineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = policy_payload()
        self.now = dt.datetime(2026, 9, 4, 12, 0, tzinfo=dt.timezone.utc)

    def test_healthy_resets_failure_and_attempt_budgets(self) -> None:
        result = plan_recovery(
            observation=observation(available=True),
            previous={
                "state": "RECOVERING",
                "consecutive_failures": 3,
                "recovery_attempts": 2,
            },
            hf_stage="RUNNING",
            policy=self.policy,
            now=self.now,
            action_budget_available=True,
        )
        self.assertEqual(result.state, "HEALTHY")
        self.assertEqual(result.consecutive_failures, 0)
        self.assertEqual(result.recovery_attempts, 0)
        self.assertIsNone(result.action)

    def test_first_failure_is_suspect_without_mutation(self) -> None:
        result = plan_recovery(
            observation=observation(available=False),
            previous=None,
            hf_stage="RUNNING",
            policy=self.policy,
            now=self.now,
            action_budget_available=True,
        )
        self.assertEqual(result.state, "SUSPECT")
        self.assertIsNone(result.action)

    def test_second_running_failure_requests_soft_restart(self) -> None:
        result = plan_recovery(
            observation=observation(available=False),
            previous={
                "state": "SUSPECT",
                "consecutive_failures": 1,
                "recovery_attempts": 0,
            },
            hf_stage="RUNNING",
            policy=self.policy,
            now=self.now,
            action_budget_available=True,
        )
        self.assertEqual(result.state, "RECOVERING")
        self.assertEqual(result.action, "soft-restart")
        self.assertEqual(result.recovery_attempts, 1)

    def test_paused_stage_requests_resume(self) -> None:
        result = plan_recovery(
            observation=observation(available=False),
            previous={"consecutive_failures": 1, "recovery_attempts": 0},
            hf_stage="PAUSED",
            policy=self.policy,
            now=self.now,
            action_budget_available=True,
        )
        self.assertEqual(result.action, "resume")

    def test_terminal_stage_requests_factory_restart(self) -> None:
        result = plan_recovery(
            observation=observation(available=False),
            previous={"consecutive_failures": 1, "recovery_attempts": 0},
            hf_stage="RUNTIME_ERROR",
            policy=self.policy,
            now=self.now,
            action_budget_available=True,
        )
        self.assertEqual(result.action, "factory-restart")

    def test_transitional_stage_is_not_restarted_again(self) -> None:
        result = plan_recovery(
            observation=observation(available=False),
            previous={"consecutive_failures": 1, "recovery_attempts": 1},
            hf_stage="BUILDING",
            policy=self.policy,
            now=self.now,
            action_budget_available=True,
        )
        self.assertEqual(result.state, "RECOVERING")
        self.assertIsNone(result.action)

    def test_cooldown_prevents_restart_storm(self) -> None:
        result = plan_recovery(
            observation=observation(available=False),
            previous={
                "consecutive_failures": 2,
                "recovery_attempts": 1,
                "last_action_at": "2026-09-04T11:50:00Z",
            },
            hf_stage="RUNNING",
            policy=self.policy,
            now=self.now,
            action_budget_available=True,
        )
        self.assertEqual(result.state, "DEGRADED")
        self.assertIsNone(result.action)
        self.assertIn("cooldown", result.reason)

    def test_recovery_budget_terminalizes_to_incident(self) -> None:
        result = plan_recovery(
            observation=observation(available=False),
            previous={
                "consecutive_failures": 4,
                "recovery_attempts": 3,
                "last_action_at": "2026-09-04T10:00:00Z",
            },
            hf_stage="RUNNING",
            policy=self.policy,
            now=self.now,
            action_budget_available=True,
        )
        self.assertEqual(result.state, "INCIDENT")
        self.assertIsNone(result.action)

    def test_source_drift_never_triggers_runtime_restart(self) -> None:
        result = plan_recovery(
            observation=observation(available=True, source_ok=False),
            previous=None,
            hf_stage="RUNNING",
            policy=self.policy,
            now=self.now,
            action_budget_available=True,
        )
        self.assertEqual(result.state, "INCIDENT")
        self.assertIsNone(result.action)
        self.assertIn("source integrity", result.reason)


class DurableStateTests(unittest.TestCase):
    def test_issue_state_round_trip(self) -> None:
        state = {
            "schema": "szl.autonomic-sre-state/v1",
            "updated_at": "2026-09-04T12:00:00Z",
            "manifest_revision": "a" * 40,
            "controller_revision": "b" * 40,
            "surfaces": {
                "a11oy": {
                    "state": "HEALTHY",
                    "consecutive_failures": 0,
                    "recovery_attempts": 0,
                }
            },
        }
        body = issue_body(state)
        self.assertEqual(extract_state(body), state)

    def test_malformed_issue_state_fails_closed_to_empty(self) -> None:
        state = extract_state(
            "<!-- SZL_AUTONOMIC_STATE_BEGIN\nnot json\nSZL_AUTONOMIC_STATE_END -->"
        )
        self.assertEqual(state["surfaces"], {})

    def test_heartbeat_requires_periodic_durable_write(self) -> None:
        now = dt.datetime(2026, 9, 4, 12, 0, tzinfo=dt.timezone.utc)
        previous = {
            "updated_at": "2026-09-04T10:00:00Z",
            "surfaces": {"a11oy": {"state": "HEALTHY"}},
        }
        current = {
            "updated_at": "2026-09-04T12:00:00Z",
            "surfaces": {"a11oy": {"state": "HEALTHY"}},
        }
        self.assertTrue(
            state_requires_write(previous, current, heartbeat_minutes=60, now=now)
        )
        previous["updated_at"] = "2026-09-04T11:30:00Z"
        self.assertFalse(
            state_requires_write(previous, current, heartbeat_minutes=60, now=now)
        )


if __name__ == "__main__":
    unittest.main()
