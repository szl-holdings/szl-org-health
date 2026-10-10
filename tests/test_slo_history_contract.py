from __future__ import annotations

import unittest

from autonomic.slo_controller import STATE_BEGIN, STATE_END, extract_state
from autonomic.slo_history_contract import (
    contract_digest,
    migrate_history,
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

    def test_contract_digest_changes_when_required_paths_change(self) -> None:
        self.assertNotEqual(
            contract_digest(self.killinchu_old),
            contract_digest(self.killinchu_new),
        )
        self.assertEqual(contract_digest(self.a11oy), contract_digest(dict(self.a11oy)))

    def test_migration_resets_only_changed_surface_history(self) -> None:
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
            "manifest_revision": "a" * 40,
            "surface_history": {
                "a11oy": retained,
                "killinchu": invalid_contract_history,
            },
        }
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


if __name__ == "__main__":
    unittest.main()
