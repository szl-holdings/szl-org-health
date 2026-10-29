from __future__ import annotations

import datetime as dt
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from autonomic import controller as base
from autonomic import controller_v2 as v2
from tests.test_autonomic_controller import manifest_payload, policy_payload


def exact_surface() -> dict:
    return {
        "id": "a11oy",
        "hf_repository": "SZLHOLDINGS/a11oy",
        "base_url": "https://szlholdings-a11oy.hf.space",
        "deployment_source_repository": "szl-holdings/a11oy",
        "revision_policy": "exact-default-branch",
        "default_branch": "main",
        "build_info_path": "/api/build-info",
        "required_paths": ["/", "/api/build-info"],
    }


def declared_surface() -> dict:
    value = exact_surface()
    value.update(
        {
            "id": "terra",
            "hf_repository": "SZLHOLDINGS/terra",
            "base_url": "https://szlholdings-terra.hf.space",
            "revision_policy": "declared-commit",
            "default_branch": None,
        }
    )
    return value


def policy() -> dict:
    return {
        "probe": {"failure_threshold": 2},
        "recovery": {
            "enabled": True,
            "max_actions_per_cycle": 1,
            "cooldown_minutes": 30,
            "max_attempts_before_incident": 3,
            "paused_stages": ["PAUSED", "SLEEPING", "STOPPED"],
            "transitional_stages": ["BUILDING", "STARTING", "RESTARTING"],
            "terminal_stages": ["RUNTIME_ERROR", "BUILD_ERROR", "CONFIG_ERROR"],
        },
    }


def observation(*, available: bool, source_ok: bool = True) -> v2.SurfaceObservation:
    row = base.PathObservation(
        path="/api/build-info",
        status=200 if available else 503,
        elapsed_ms=8,
        content_type="application/json",
        body_sha256="a" * 64 if available else None,
        body_bytes=2 if available else None,
        ok=available,
        error_kind=None if available else "HTTP_503",
    )
    return v2.SurfaceObservation(
        surface_id="a11oy",
        hf_repository="SZLHOLDINGS/a11oy",
        base_url="https://szlholdings-a11oy.hf.space",
        availability_ok=available,
        source_ok=source_ok,
        source_status="EXACT" if source_ok else "DRIFT",
        source_repository="szl-holdings/a11oy",
        source_revision="a" * 40,
        expected_revision="a" * 40 if source_ok else "b" * 40,
        source_evidence="EXPLICIT_REPOSITORY_AND_REVISION",
        paths=(row,),
        failures=() if available and source_ok else ("unhealthy",),
    )


class SourceIdentityTests(unittest.TestCase):
    def test_explicit_gateway_source_is_accepted(self) -> None:
        identity = v2.select_source_identity(
            {
                "service": "terra",
                "source_repository": "szl-holdings/a11oy",
                "source_revision": "a" * 40,
            },
            declared_surface(),
        )
        self.assertEqual(identity["source_repository"], "szl-holdings/a11oy")
        self.assertEqual(identity["source_revision"], "a" * 40)
        self.assertEqual(identity["evidence"], "EXPLICIT_REPOSITORY_AND_REVISION")

    def test_trusted_runtime_revision_source_binds_manifest_repository(self) -> None:
        identity = v2.select_source_identity(
            {
                "status": "OBSERVED",
                "service": "a11oy",
                "build": {
                    "revision": "b" * 40,
                    "revision_source": "env:A11OY_GIT_SHA",
                },
            },
            exact_surface(),
        )
        self.assertEqual(identity["source_repository"], "szl-holdings/a11oy")
        self.assertEqual(identity["source_revision"], "b" * 40)
        self.assertEqual(
            identity["evidence"],
            "MANIFEST_PLUS_env:A11OY_GIT_SHA",
        )

    def test_repository_local_git_head_is_not_deployment_binding(self) -> None:
        with self.assertRaises(base.ContractError):
            v2.select_source_identity(
                {
                    "service": "a11oy",
                    "build": {
                        "revision": "c" * 40,
                        "revision_source": "git:HEAD",
                    },
                },
                exact_surface(),
            )

    def test_declared_commit_requires_explicit_repository(self) -> None:
        with self.assertRaises(base.ContractError):
            v2.select_source_identity(
                {
                    "service": "terra",
                    "build": {
                        "revision": "d" * 40,
                        "revision_source": "env:SZL_GIT_SHA",
                    },
                },
                declared_surface(),
            )

    def test_wrong_explicit_repository_is_rejected(self) -> None:
        with self.assertRaises(base.ContractError):
            v2.select_source_identity(
                {
                    "source_repository": "other/repository",
                    "source_revision": "e" * 40,
                },
                declared_surface(),
            )


class VerifiedCommitTests(unittest.TestCase):
    def test_declared_commit_must_be_cryptographically_verified(self) -> None:
        revision = "f" * 40

        class FakeApi(v2.GitHubApi):
            def __init__(self, verified: bool) -> None:
                self.verified = verified

            def _request(self, method: str, path: str, payload=None):
                del method, path, payload
                return {
                    "sha": revision,
                    "commit": {"verification": {"verified": self.verified}},
                }

        self.assertEqual(
            FakeApi(True).verified_commit("szl-holdings/a11oy", revision),
            revision,
        )
        with self.assertRaises(base.ContractError):
            FakeApi(False).verified_commit("szl-holdings/a11oy", revision)


class AuthorityBudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = dt.datetime(2026, 9, 4, 13, 0, tzinfo=dt.timezone.utc)

    def test_v1_blocked_attempts_are_released_and_remain_retryable(self) -> None:
        previous = {
            "state": "INCIDENT",
            "consecutive_failures": 18,
            "recovery_attempts": 3,
            "last_action": "resume",
            "last_action_at": "2026-09-04T12:55:00Z",
            "last_action_result": {
                "ok": False,
                "status": "BLOCKED",
                "reason": "HF_TOKEN_MISSING",
            },
        }
        plan = v2.plan_recovery(
            observation=observation(available=False),
            previous=previous,
            hf_stage="PAUSED",
            policy=policy(),
            now=self.now,
            action_budget_available=True,
        )
        self.assertEqual(plan.action, "resume")
        self.assertEqual(plan.recovery_attempts, 1)

        state = v2.make_surface_state(
            previous=previous,
            observation=observation(available=False),
            plan=plan,
            stage="PAUSED",
            action_result={
                "ok": False,
                "status": "BLOCKED",
                "reason": "HF_TOKEN_MISSING",
            },
            now_text="2026-09-04T13:00:00Z",
        )
        self.assertEqual(state["state"], "DEGRADED")
        self.assertEqual(state["recovery_attempts"], 0)
        self.assertIsNone(state["last_action_at"])
        self.assertIsNone(state["last_action"])
        self.assertEqual(state["last_blocked_action"], "resume")
        self.assertIn("not consumed", state["last_reason"])

    def test_real_provider_failure_consumes_attempt_and_cooldown(self) -> None:
        plan = v2.plan_recovery(
            observation=observation(available=False),
            previous={"consecutive_failures": 1, "recovery_attempts": 0},
            hf_stage="RUNNING",
            policy=policy(),
            now=self.now,
            action_budget_available=True,
        )
        state = v2.make_surface_state(
            previous={"consecutive_failures": 1, "recovery_attempts": 0},
            observation=observation(available=False),
            plan=plan,
            stage="RUNNING",
            action_result={"ok": False, "status": "FAILED"},
            now_text="2026-09-04T13:00:00Z",
        )
        self.assertEqual(state["state"], "DEGRADED")
        self.assertEqual(state["recovery_attempts"], 1)
        self.assertEqual(state["last_action_at"], "2026-09-04T13:00:00Z")

        cooldown = v2.plan_recovery(
            observation=observation(available=False),
            previous=state,
            hf_stage="RUNNING",
            policy=policy(),
            now=self.now + dt.timedelta(minutes=5),
            action_budget_available=True,
        )
        self.assertIsNone(cooldown.action)
        self.assertIn("cooldown", cooldown.reason)


class TokenSelectionTests(unittest.TestCase):
    def test_all_admitted_aliases_are_discovered_in_fixed_order(self) -> None:
        token, source = v2.select_hf_token(
            {
                "HF_TOKEN": "generic",
                "HF_WRITE_TOKEN": "writer",
                "HF_ORG_TOKEN": "org-writer",
            }
        )
        self.assertEqual(token, "org-writer")
        self.assertEqual(source, "HF_ORG_TOKEN")
        self.assertEqual(
            v2.select_hf_token({"HUGGING_FACE_HUB_TOKEN": "fallback"}),
            ("fallback", "HUGGING_FACE_HUB_TOKEN"),
        )
        self.assertEqual(v2.select_hf_token({}), (None, None))


class FailureDiagnosticTests(unittest.TestCase):
    sensitive_text = "test-secret-value C:\\private\\credential.txt https://private.invalid/?token=secret"

    def branch(self, verified=True):
        return {"commit": {"sha": "a" * 40, "commit": {"verification": {"verified": verified}}}}

    def failure_receipt(self, responses, workflow_sha="a" * 40):
        client = v2.GitHubApi(
            token=self.sensitive_text, controller_repository="szl-holdings/szl-org-health",
            timeout=8, max_response_bytes=1_048_576,
        )
        payload = policy_payload()
        payload["state_issue"]["title"] = self.sensitive_text
        with tempfile.TemporaryDirectory() as temporary:
            policy_path = Path(temporary) / "policy.json"
            policy_path.write_text(json.dumps(payload), encoding="utf-8")
            output = Path(temporary) / "receipt.json"
            stderr = io.StringIO()
            with (
                patch.dict(os.environ, {"GITHUB_TOKEN": self.sensitive_text, "GITHUB_SHA": workflow_sha}, clear=True),
                patch.object(v2, "GitHubApi", return_value=client),
                patch.object(client, "_request", side_effect=responses) as requests,
                patch.object(base, "load_signed_manifest", return_value=({}, "a" * 40, "0" * 64)),
                patch.object(client, "upsert_state_issue") as write,
                patch.object(v2, "probe_surface") as probe,
                patch("sys.stderr", stderr),
            ):
                result = v2.main(["--policy", str(policy_path), "--output", str(output)])
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result, 1)
            self.assertFalse(receipt["ok"])
            self.assertFalse(receipt["secret_values_recorded"])
            self.assertEqual(receipt["error"], base.REDACTED_ERROR)
            self.assertEqual(json.loads(stderr.getvalue()), receipt)
            for marker in ("test-secret-value", "credential.txt", "private.invalid", str(Path(base.__file__).parent)):
                self.assertNotIn(marker, stderr.getvalue())
            self.assertTrue(all(call.args[0] == "GET" for call in requests.call_args_list))
            write.assert_not_called()
            probe.assert_not_called()
            return receipt

    def assert_origin(self, receipt, module, function, fragment):
        origin = receipt["error_origin"]
        self.assertEqual(set(origin), {"module", "function", "line"})
        self.assertEqual(origin["module"], f"autonomic.{module}")
        self.assertEqual(origin["function"], function)
        source = Path(base.__file__).with_name(f"{module}.py").read_text(encoding="utf-8").splitlines()
        self.assertIn(fragment, source[origin["line"] - 1])

    def test_unverified_tip_identifies_signature_guard_without_probing_or_writing(self):
        receipt = self.failure_receipt([self.branch(verified=False)])
        self.assertEqual(receipt["error_kind"], "CONTRACTERROR")
        self.assert_origin(receipt, "controller", "verified_tip", "require(")

    def test_stale_schedule_identifies_exact_head_guard_without_probing_or_writing(self):
        receipt = self.failure_receipt([self.branch()], workflow_sha="b" * 40)
        self.assert_origin(receipt, "controller_v2", "run_live", "base.require(")

    def test_duplicate_state_identifies_guard_without_exposing_title(self):
        receipt = self.failure_receipt([
            self.branch(),
            {"items": [{"number": number, "title": self.sensitive_text} for number in (1, 2)]},
        ])
        self.assert_origin(receipt, "controller", "find_state_issue", "multiple autonomic state issues")

    def test_foreign_error_records_only_trusted_callsite(self):
        receipt = self.failure_receipt([RuntimeError(self.sensitive_text)])
        self.assertEqual(receipt["error_kind"], "RUNTIMEERROR")
        self.assert_origin(receipt, "controller", "branch", "self._request(")


class OfflineContractTests(unittest.TestCase):
    def test_v2_contract_exposes_bounded_migrations_without_values(self) -> None:
        receipt = v2.offline_contract(
            {
                "controller_repository": "szl-holdings/szl-org-health",
                "controller_branch": "main",
                "source_manifest": {},
                "allowed_hf_repositories": ["SZLHOLDINGS/a11oy"],
                "recovery": {"max_actions_per_cycle": 1},
            },
            "0" * 64,
        )
        self.assertEqual(receipt["schema"], v2.OFFLINE_SCHEMA)
        self.assertFalse(receipt["blocked_authority_consumes_attempt"])
        self.assertTrue(receipt["declared_commit_verification_required"])
        self.assertEqual(receipt["secret_values_recorded"], False)
        self.assertNotIn("org-writer", json_string(receipt))


class PayloadPolicyIntegrationTests(unittest.TestCase):
    def surface(self):
        surface = exact_surface()
        surface["revision_policy"] = "payload-equivalent-default-branch"
        return surface

    def test_manifest_policy_is_restricted_to_canonical_a11oy(self):
        raw = manifest_payload()
        raw["platforms"][0]["revision_policy"] = "payload-equivalent-default-branch"
        self.assertEqual(base.validate_manifest(raw, policy=policy_payload())["surfaces"][0]["id"], "a11oy")
        for key, value in (("id", "other"), ("deployment_source_repository", "szl-holdings/other"),
                           ("default_branch", "other")):
            with self.subTest(key=key):
                changed = json.loads(json.dumps(raw))
                changed["platforms"][0][key] = value
                with self.assertRaises(base.ContractError):
                    base.validate_manifest(changed, policy=policy_payload())
        raw["public_products"][0]["revision_policy"] = "payload-equivalent-default-branch"
        raw["public_products"][0]["default_branch"] = "main"
        with self.assertRaises(base.ContractError):
            base.validate_manifest(raw, policy=policy_payload())

    def probe(self, controller=v2, *, source=None, available=True, changed_payload=False, policy_name=None):
        from tests.test_payload_equivalence import EXPECTED, OBSERVED, GitHubFixture, payload_files

        after = payload_files()
        after["app.py" if changed_payload else "docs/notes.md"] = ("100644", b"changed\n")
        github = GitHubFixture(after=after)
        github.verified_tip = lambda *_: EXPECTED
        payload = source or {"source_repository": "szl-holdings/a11oy", "source_revision": OBSERVED}
        surface = self.surface()
        if policy_name:
            surface["revision_policy"] = policy_name

        def path_probe(_opener, *, path, **_kwargs):
            body = json.dumps(payload).encode()
            ok = available or path == "/api/build-info"
            return base.PathObservation(path, 200 if ok else 503, 1, "application/json",
                                        base.sha256_hex(body), len(body), ok,
                                        None if ok else "HTTP_503"), body

        with patch.object(base, "probe_path", side_effect=path_probe):
            result = controller.probe_surface(surface, opener=None, github=github,
                                              timeout=8, max_response_bytes=262144, parallelism=2)
        return result, github

    def test_v1_and_v2_retain_actual_revision_and_payload_proof(self):
        from tests.test_payload_equivalence import EXPECTED, OBSERVED

        for controller in (base, v2):
            with self.subTest(controller=controller.__name__):
                result, _ = self.probe(controller)
                self.assertTrue(result.healthy)
                self.assertEqual(result.source_status, "PAYLOAD_EQUIVALENT")
                self.assertEqual(result.source_revision, OBSERVED)
                self.assertEqual(result.expected_revision, EXPECTED)
                self.assertEqual(result.receipt()["source_verification"]["match"], "PAYLOAD_EQUIVALENT")

    def test_trusted_runtime_identity_remains_required_for_implicit_repository(self):
        from tests.test_payload_equivalence import OBSERVED

        for service, revision_source, accepted in (("a11oy", "env:A11OY_GIT_SHA", True),
                                                    ("a11oy", "git:HEAD", False),
                                                    ("other", "env:A11OY_GIT_SHA", False)):
            with self.subTest(service=service, revision_source=revision_source):
                result, _ = self.probe(source={"service": service, "build": {
                    "revision": OBSERVED, "revision_source": revision_source}})
                self.assertEqual(result.source_ok, accepted)

    def test_exact_match_needs_no_equivalence_api_requests(self):
        from tests.test_payload_equivalence import EXPECTED

        result, github = self.probe(source={"source_repository": "szl-holdings/a11oy",
                                           "source_revision": EXPECTED})
        self.assertEqual(result.source_status, "EXACT")
        self.assertIsNone(result.source_verification)
        self.assertEqual(github.requests, [])

    def test_failed_equivalence_stays_unhealthy_and_cannot_request_restart(self):
        result, _ = self.probe(changed_payload=True)
        self.assertFalse(result.source_ok)
        self.assertFalse(result.healthy)
        self.assertEqual(result.source_verification["match"], "NONE")
        self.assertEqual(result.source_verification["error_origin"]["module"], "autonomic.payload_equivalence")
        self.assertEqual(result.source_verification["error_origin"]["function"], "verified_payload_equivalence")
        plan = v2.plan_recovery(observation=result, previous={"consecutive_failures": 3},
                                hf_stage="RUNNING", policy=policy(),
                                now=dt.datetime(2026, 10, 28, tzinfo=dt.timezone.utc),
                                action_budget_available=True)
        self.assertIsNone(plan.action)
        self.assertEqual(plan.state, "INCIDENT")

    def test_failed_proof_redacts_foreign_error_text(self):
        from autonomic.payload_equivalence import failed_verification
        sensitive = "token=secret /private/credential.txt"
        proof = failed_verification(sensitive, None, RuntimeError(sensitive))
        self.assertEqual(proof["match"], "NONE")
        self.assertIsNone(proof["observed_revision"])
        self.assertIsNone(proof["error_origin"])
        self.assertNotIn(sensitive, json.dumps(proof))

    def test_exact_policy_is_not_silently_broadened(self):
        result, github = self.probe(policy_name="exact-default-branch")
        self.assertFalse(result.source_ok)
        self.assertEqual(result.source_status, "DRIFT")
        self.assertEqual(github.requests, [])

    def test_payload_equivalence_does_not_mask_failed_route_and_proof_survives_state(self):
        result, _ = self.probe(available=False)
        self.assertTrue(result.source_ok)
        self.assertFalse(result.healthy)
        now = dt.datetime(2026, 10, 28, tzinfo=dt.timezone.utc)
        plan = v2.plan_recovery(observation=result, previous={}, hf_stage="RUNNING",
                                policy=policy(), now=now, action_budget_available=False)
        state = v2.make_surface_state(previous={}, observation=result, plan=plan, stage="RUNNING",
                                      action_result=None, now_text=now.isoformat())
        projected = state["source_verification"]
        self.assertEqual(projected["observed_revision"], result.source_revision)
        self.assertEqual(projected["expected_revision"], result.expected_revision)
        self.assertEqual(projected["proof_sha256"], base.sha256_hex(base.canonical_json(result.source_verification)))
        self.assertNotIn("copy_sources", projected)


def json_string(value) -> str:
    import json

    return json.dumps(value, sort_keys=True)


if __name__ == "__main__":
    unittest.main()
