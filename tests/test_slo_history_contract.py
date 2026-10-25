from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from autonomic import slo_history_contract as migration
from autonomic.slo_controller import ContractError, STATE_BEGIN, STATE_END, extract_state
from tests.test_autonomic_slo import policy_payload
from autonomic.slo_history_contract import (
    MARKER_SCHEMA,
    apply_registered_migration,
    contract_digest,
    load_registry,
    marker_body,
    migrate_history,
    parse_marker_state,
    replace_embedded_state,
)


def surface(identifier: str, *paths: str) -> dict[str, object]:
    return {
        "id": identifier,
        "title": identifier.title(),
        "hf_repository": f"SZLHOLDINGS/{identifier}",
        "base_url": f"https://szlholdings-{identifier}.hf.space",
        "required_paths": list(paths),
        "build_info_path": "/api/build-info",
    }


class SloHistoryContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.a11oy = surface("a11oy", "/", "/api/build-info")
        self.killinchu_old = surface(
            "killinchu",
            "/",
            "/api/build-info",
            "/api/defend/readyz",
            "/api/defend/status",
        )
        self.killinchu_new = surface(
            "killinchu",
            "/",
            "/api/build-info",
            "/api/defend/status",
        )

    def history_state(self) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        retained = {
            "buckets": [[100, 2, 0, 0, 120, 110]],
            "current_failure_started_at": None,
            "last_ok_at": "2026-10-10T20:00:00Z",
            "last_provider_blocker": None,
        }
        invalid_contract_history = {
            "buckets": [[100, 2, 2, 0, 503, 110]],
            "current_failure_started_at": "2026-10-10T19:00:00Z",
            "last_ok_at": None,
            "last_provider_blocker": None,
        }
        state = {
            "schema": "szl.autonomic-slo-state/v1",
            "manifest_revision": "b" * 40,
            "surface_history": {
                "a11oy": retained,
                "killinchu": invalid_contract_history,
            },
        }
        return state, retained, invalid_contract_history

    def test_contract_digest_changes_only_when_the_predicate_changes(self) -> None:
        self.assertNotEqual(
            contract_digest(self.killinchu_old),
            contract_digest(self.killinchu_new),
        )
        reordered = dict(self.killinchu_old)
        reordered["required_paths"] = list(reversed(self.killinchu_old["required_paths"]))
        self.assertEqual(contract_digest(self.killinchu_old), contract_digest(reordered))
        self.assertEqual(contract_digest(self.a11oy), contract_digest(dict(self.a11oy)))

    def test_migration_resets_only_changed_surface_history(self) -> None:
        state, retained, _ = self.history_state()
        previous = {"surfaces": [self.a11oy, self.killinchu_old]}
        current = {"surfaces": [self.a11oy, self.killinchu_new]}

        migrated, receipt = migrate_history(state, previous, current)

        self.assertIs(migrated["surface_history"]["a11oy"], retained)
        self.assertEqual(
            migrated["surface_history"]["killinchu"],
            {
                "buckets": [],
                "current_failure_started_at": None,
                "last_ok_at": None,
                "last_provider_blocker": None,
            },
        )
        self.assertEqual(receipt["changed"], ["killinchu"])
        self.assertEqual(receipt["added"], [])
        self.assertEqual(receipt["removed"], [])
        self.assertEqual(receipt["reset_bucket_counts"], {"killinchu": 1})

    def test_registered_migration_applies_after_manifest_revision_already_advanced(self) -> None:
        state, retained, _ = self.history_state()
        state["manifest_revision"] = "b" * 40
        previous = {"surfaces": [self.a11oy, self.killinchu_old]}
        current = {"surfaces": [self.a11oy, self.killinchu_new]}
        entry = {
            "id": "killinchu-readiness-is-not-availability-20261010",
            "from_manifest_revision": "a" * 40,
            "to_manifest_revision": "b" * 40,
            "reset_surfaces": ["killinchu"],
            "reason": "The readiness route is not an availability predicate.",
        }

        migrated, receipt = apply_registered_migration(state, entry, previous, current)

        self.assertEqual(migrated["manifest_revision"], "b" * 40)
        self.assertIs(migrated["surface_history"]["a11oy"], retained)
        self.assertEqual(migrated["surface_history"]["killinchu"]["buckets"], [])
        self.assertEqual(receipt["migration_id"], entry["id"])
        self.assertEqual(receipt["changed"], ["killinchu"])
        self.assertEqual(receipt["reset_bucket_counts"], {"killinchu": 1})

    def test_registered_migration_rejects_inexact_reset_scope(self) -> None:
        state, _, _ = self.history_state()
        previous = {"surfaces": [self.a11oy, self.killinchu_old]}
        current = {"surfaces": [self.a11oy, self.killinchu_new]}
        entry = {
            "id": "wrong-scope-20261010",
            "from_manifest_revision": "a" * 40,
            "to_manifest_revision": "b" * 40,
            "reset_surfaces": ["a11oy"],
            "reason": "This intentionally names the wrong surface.",
        }
        with self.assertRaises(ContractError):
            apply_registered_migration(state, entry, previous, current)

    def test_migration_handles_added_and_removed_surfaces(self) -> None:
        old_only = surface("old-only", "/", "/api/build-info")
        new_only = surface("new-only", "/", "/api/build-info")
        state = {
            "schema": "szl.autonomic-slo-state/v1",
            "surface_history": {
                "a11oy": {"buckets": [], "current_failure_started_at": None},
                "old-only": {"buckets": [[100, 1, 0, 0, 10, 100]]},
            },
        }
        migrated, receipt = migrate_history(
            state,
            {"surfaces": [self.a11oy, old_only]},
            {"surfaces": [self.a11oy, new_only]},
        )
        self.assertEqual(set(migrated["surface_history"]), {"a11oy", "new-only"})
        self.assertEqual(receipt["added"], ["new-only"])
        self.assertEqual(receipt["removed"], ["old-only"])

    def test_registry_is_strict_and_round_trips_one_exact_entry(self) -> None:
        registry = {
            "schema": "szl.autonomic-slo-history-migrations/v1",
            "migrations": [
                {
                    "id": "killinchu-readiness-is-not-availability-20261010",
                    "from_manifest_revision": "a" * 40,
                    "to_manifest_revision": "b" * 40,
                    "reset_surfaces": ["killinchu"],
                    "reason": "The readiness route is not an availability predicate.",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "migrations.json"
            path.write_text(json.dumps(registry), encoding="utf-8")
            self.assertEqual(load_registry(path), registry["migrations"])

    def test_marker_state_round_trip_preserves_replay_fence(self) -> None:
        state = {
            "schema": MARKER_SCHEMA,
            "updated_at": "2026-10-10T21:00:00Z",
            "applied": [
                {
                    "id": "killinchu-readiness-is-not-availability-20261010",
                    "applied_at": "2026-10-10T21:00:00Z",
                    "state_sha256": "a" * 64,
                }
            ],
        }
        self.assertEqual(parse_marker_state(marker_body(state)), state)

    def test_replace_embedded_state_preserves_surrounding_issue_body(self) -> None:
        original_state = {
            "schema": "szl.autonomic-slo-state/v1",
            "surface_history": {},
        }
        from autonomic.slo_controller import encode_state

        body = "# Header\n\n" + STATE_BEGIN + encode_state(original_state) + STATE_END + "\nTail\n"
        replacement = {
            "schema": "szl.autonomic-slo-state/v1",
            "surface_history": {
                "a11oy": {
                    "buckets": [],
                    "current_failure_started_at": None,
                    "last_ok_at": None,
                    "last_provider_blocker": None,
                }
            },
        }
        updated = replace_embedded_state(body, replacement)
        self.assertTrue(updated.startswith("# Header\n\n" + STATE_BEGIN))
        self.assertTrue(updated.endswith(STATE_END + "\nTail\n"))
        self.assertEqual(extract_state(updated), replacement)


class FailureDiagnosticTests(unittest.TestCase):
    sensitive_text = "test-secret-value C:\\private\\credential.txt https://private.invalid/?token=secret"

    def branch(self, verified=True):
        return {"commit": {"sha": "a" * 40, "commit": {"verification": {"verified": verified}}}}

    def failure_receipt(self, responses, workflow_sha="a" * 40):
        client = migration.GitHubApi(
            token=self.sensitive_text, repository="szl-holdings/szl-org-health", timeout=8,
        )
        payload = policy_payload()
        payload["state_issue"]["title"] = self.sensitive_text
        with tempfile.TemporaryDirectory() as temporary:
            policy_path = Path(temporary) / "policy.json"
            policy_path.write_text(json.dumps(payload), encoding="utf-8")
            registry = Path(temporary) / "registry.json"
            registry.write_text(json.dumps({"schema": migration.REGISTRY_SCHEMA, "migrations": []}), encoding="utf-8")
            output = Path(temporary) / "receipt.json"
            stderr = io.StringIO()
            with (
                patch.dict(os.environ, {"GITHUB_TOKEN": self.sensitive_text, "GITHUB_SHA": workflow_sha}, clear=True),
                patch.object(migration, "GitHubApi", return_value=client),
                patch.object(client, "request", side_effect=responses) as requests,
                patch.object(migration, "load_signed_manifest", return_value=({}, "a" * 40, "0" * 64)),
                patch.object(client, "update_issue") as update,
                patch.object(client, "create_issue") as create,
                patch("sys.stderr", stderr),
            ):
                result = migration.main([
                    "--policy", str(policy_path), "--registry", str(registry), "--output", str(output),
                ])
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result, 1)
            self.assertEqual(receipt["status"], "FAILED")
            self.assertEqual(receipt["error"], "history migration failed closed")
            self.assertFalse(receipt["mutation_performed"])
            self.assertFalse(receipt["secret_values_recorded"])
            self.assertEqual(json.loads(stderr.getvalue()), receipt)
            for marker in ("test-secret-value", "credential.txt", "private.invalid", str(Path(migration.__file__).parent)):
                self.assertNotIn(marker, stderr.getvalue())
            self.assertTrue(all(call.args[0] == "GET" for call in requests.call_args_list))
            update.assert_not_called()
            create.assert_not_called()
            return receipt

    def assert_origin(self, receipt, module, function, fragment):
        origin = receipt["error_origin"]
        self.assertEqual(set(origin), {"module", "function", "line"})
        self.assertEqual(origin["module"], f"autonomic.{module}")
        self.assertEqual(origin["function"], function)
        source = Path(migration.__file__).with_name(f"{module}.py").read_text(encoding="utf-8").splitlines()
        self.assertIn(fragment, source[origin["line"] - 1])

    def test_unverified_tip_identifies_signature_guard_without_writes(self):
        receipt = self.failure_receipt([self.branch(verified=False)])
        self.assertEqual(receipt["error_kind"], "CONTRACTERROR")
        self.assert_origin(receipt, "slo_controller", "verified_tip", "require(")

    def test_stale_schedule_identifies_exact_head_guard_without_writes(self):
        receipt = self.failure_receipt([self.branch()], workflow_sha="b" * 40)
        self.assert_origin(receipt, "slo_history_contract", "run_migration", "migration is not running from exact verified main")

    def test_duplicate_state_identifies_guard_without_exposing_title(self):
        receipt = self.failure_receipt([
            self.branch(),
            [{"number": number, "title": self.sensitive_text} for number in (1, 2)],
        ])
        self.assert_origin(receipt, "slo_controller", "find_open_issue", "multiple open issues exist")

    def test_foreign_error_records_only_trusted_callsite(self):
        receipt = self.failure_receipt([RuntimeError(self.sensitive_text)])
        self.assertEqual(receipt["error_kind"], "RUNTIMEERROR")
        self.assert_origin(receipt, "slo_controller", "branch", "self.request(")


if __name__ == "__main__":
    unittest.main()
