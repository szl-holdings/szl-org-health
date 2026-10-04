"""Incident containment: keep observations, prohibit provider restart effects.

These tests load the checked-in policy. Re-enabling automatic recovery requires
an explicit, reviewed policy/test successor rather than a timeout or retry.
All integration dependencies are replaced before run_live; no network or
provider credentials are used.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from autonomic import controller as base
from autonomic import controller_v2 as v2

ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 10, 4, 20, tzinfo=dt.timezone.utc)
SHA = "b" * 40


class RecoveryContainmentTests(unittest.TestCase):
    def setUp(self):
        self.policy, self.digest = base.load_policy(ROOT / "autonomic/policy.json")

    def test_production_policy_disables_automatic_provider_recovery(self):
        self.assertIs(self.policy["recovery"]["enabled"], False)
        self.assertTrue(self.policy["source_manifest"]["require_verified_commit"])
        self.assertEqual(self.policy["probe"]["failure_threshold"], 2)
        self.assertEqual(self.policy["probe"]["interval_minutes"], 5)

    def test_both_planners_deny_effects_across_unhealthy_states(self):
        stages = set(self.policy["recovery"]["paused_stages"])
        stages.update(self.policy["recovery"]["terminal_stages"])
        stages.update(self.policy["recovery"]["transitional_stages"])
        stages.update(("RUNNING", "UNKNOWN", "UNAVAILABLE", ""))
        for planner in (base.plan_recovery, v2.plan_recovery):
            for stage in sorted(stages):
                for available, source_ok in ((False, False), (False, True), (True, False)):
                    for attempts in (0, 2, 3):
                        with self.subTest(planner=planner.__module__, stage=stage,
                                          available=available, source_ok=source_ok,
                                          attempts=attempts):
                            plan = planner(
                                observation=SimpleNamespace(healthy=False,
                                    availability_ok=available, source_ok=source_ok),
                                previous={"consecutive_failures": 3,
                                    "recovery_attempts": attempts,
                                    "last_action_at": None},
                                hf_stage=stage, policy=self.policy, now=NOW,
                                action_budget_available=True,
                            )
                            self.assertIsNone(plan.action)
                            self.assertNotEqual(plan.state, "HEALTHY")
                            self.assertEqual(plan.recovery_attempts, attempts)
                            self.assertIsNone(plan.last_action_at)

    def test_healthy_observations_are_not_hidden_by_the_hold(self):
        for planner in (base.plan_recovery, v2.plan_recovery):
            with self.subTest(planner=planner.__module__):
                plan = planner(observation=SimpleNamespace(healthy=True,
                    availability_ok=True, source_ok=True), previous=None,
                    hf_stage="RUNNING", policy=self.policy, now=NOW,
                    action_budget_available=True)
                self.assertEqual(plan.state, "HEALTHY")
                self.assertIsNone(plan.action)

    def test_disabled_policy_still_produces_valid_offline_contract(self):
        for contract in (base.offline_contract, v2.offline_contract):
            with self.subTest(contract=contract.__module__):
                receipt = contract(self.policy, self.digest)
                self.assertIs(receipt["valid"], True)
                self.assertEqual(receipt["policy_sha256"], self.digest)

    def test_live_cycle_records_outage_without_calling_provider_recovery(self):
        for stage in ("PAUSED", "RUNTIME_ERROR", "UNAVAILABLE", "RUNNING"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp) / "cycle.json"
                github = mock.Mock()
                github.verified_tip.return_value = SHA
                github.find_state_issue.return_value = {"body": "fixture"}
                provider = mock.Mock()
                provider.stage.return_value = stage
                observation = v2.SurfaceObservation(
                    surface_id="a11oy", hf_repository="SZLHOLDINGS/a11oy",
                    base_url="https://szlholdings-a11oy.hf.space",
                    availability_ok=False, source_ok=False,
                    source_status="UNAVAILABLE", source_repository=None,
                    source_revision=None, expected_revision=None,
                    source_evidence="UNAVAILABLE", paths=(),
                    failures=("test:unavailable",),
                )
                manifest = {"surfaces": [{"id": "a11oy",
                    "hf_repository": "SZLHOLDINGS/a11oy"}]}
                old = {"schema": base.STATE_SCHEMA, "surfaces": {
                    "a11oy": {"consecutive_failures": 3,
                        "recovery_attempts": 0, "last_action_at": None}}}
                with mock.patch.dict(os.environ, {
                    "GITHUB_REPOSITORY": self.policy["controller_repository"],
                    "GITHUB_SHA": SHA, "GITHUB_TOKEN": "offline-fixture-only",
                }, clear=True), mock.patch.object(v2, "GitHubApi", return_value=github), \
                    mock.patch.object(base, "load_signed_manifest", return_value=(manifest, SHA, "a" * 64)), \
                    mock.patch.object(base, "extract_state", return_value=old), \
                    mock.patch.object(v2, "probe_surface", return_value=observation), \
                    mock.patch.object(v2, "select_hf_token", return_value=(None, None)), \
                    mock.patch.object(base, "HuggingFaceControl", return_value=provider), \
                    mock.patch.object(socket, "socket", side_effect=AssertionError("network prohibited")):
                    result = v2.run_live(policy=self.policy, policy_sha256=self.digest,
                        output=output, dry_run=False)
                self.assertEqual(result, 0)
                provider.recover.assert_not_called()
                provider.stage.assert_called_once_with("SZLHOLDINGS/a11oy")
                github.upsert_state_issue.assert_called_once()
                receipt = json.loads(output.read_text())
                self.assertIs(receipt["all_healthy"], False)
                self.assertEqual(receipt["healthy_surface_count"], 0)
                self.assertEqual(receipt["attempted_mutation_count"], 0)
                self.assertEqual(receipt["actions"], [])
                self.assertIsNone(receipt["surfaces"][0]["planned_action"])
                self.assertEqual(receipt["surfaces"][0]["reason"],
                                 "automatic recovery is disabled by policy")
                self.assertEqual(output.with_suffix(".json.sha256").read_text().strip(),
                                 receipt["receipt_sha256"])


if __name__ == "__main__":
    unittest.main()
