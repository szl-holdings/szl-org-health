# SPDX-License-Identifier: Apache-2.0
"""Synthetic, offline tests for Neon recovery/security admission. Never query users."""
import copy
from datetime import datetime, timezone
import json
import unittest

from tools import neon_resilience_admission as gate

NOW = datetime(2026, 11, 19, 20, 10, tzinfo=timezone.utc)
POLICY = {
    "schema": gate.POLICY_SCHEMA,
    "environment": "PRODUCTION",
    "max_age_seconds": 900,
    "min_history_seconds": 604800,
    "require_protected_branch": True,
    "require_automatic_backups": True,
    "max_snapshot_age_seconds": 86400,
    "min_snapshot_remaining_seconds": 172800,
    "max_restore_drill_age_seconds": 2592000,
}


def observed():
    return {
        "schema": gate.READBACK_SCHEMA,
        "environment": "PRODUCTION",
        "observed_at": "2026-11-19T20:09:30Z",
        "source_state": "OBSERVED",
        "history_retention_seconds": 604800,
        "default_branch_protected": True,
        "snapshots": {
            "count": 1,
            "latest_created_at": "2026-11-19T20:09:00Z",
            "latest_expires_at": "2026-11-26T20:15:00Z",
            "automatic_schedule_count": 1,
            "last_restore_drill_at": "2026-11-18T12:00:00Z",
        },
        "network": {
            "public_connections_blocked": True,
            "ip_allowlist_count": 0,
            "independent_network_exception_approved": False,
        },
        "catalog": {
            "public_table_acl_entries": 0,
            "unreviewed_rls_exceptions": 0,
            "catalog_state": "CATALOG_MATCH_ONLY",
        },
        "credentials_recorded": False,
    }


class NeonResilienceAdmissionTests(unittest.TestCase):
    def check(self, change=None):
        snap = observed()
        if change:
            change(snap)
        return gate.assess(POLICY, snap, now=NOW)

    def test_even_all_green_is_not_production_authorization(self):
        result = self.check()
        self.assertEqual(result["state"], "SCOPED_METADATA_MATCH_ONLY")
        self.assertFalse(result["production_authorized"])
        self.assertFalse(result["control_plane_identity_independently_verified"])
        self.assertFalse(result["restore_independently_verified_by_this_verifier"])
        self.assertEqual(result["findings"], [])

    def test_six_hour_pitr_cannot_pass_production_policy(self):
        result = self.check(lambda x: x.update(history_retention_seconds=21600))
        self.assertIn("HISTORY_WINDOW_TOO_SHORT", result["findings"])
        self.assertEqual(result["state"], "HOLD")

    def test_manual_snapshot_does_not_replace_backups(self):
        result = self.check(lambda x: x["snapshots"].update(automatic_schedule_count=0))
        self.assertIn("AUTOMATIC_BACKUPS_UNCONFIGURED", result["findings"])

    def test_snapshots_without_restore_drill_do_not_pass(self):
        result = self.check(lambda x: x["snapshots"].update(last_restore_drill_at=None))
        self.assertIn("RESTORE_DRILL_UNVERIFIED", result["findings"])

    def test_snapshots_expiring_soon_fail(self):
        result = self.check(lambda x: x["snapshots"].update(latest_expires_at="2026-11-20T00:00:00Z"))
        self.assertIn("SNAPSHOT_RETENTION_SHORT", result["findings"])

    def test_unprotected_default_branch_fails(self):
        result = self.check(lambda x: x.update(default_branch_protected=False))
        self.assertIn("DEFAULT_BRANCH_UNPROTECTED", result["findings"])

    def test_public_database_without_exposure_review_fails(self):
        def public(x):
            x["network"].update(public_connections_blocked=False, ip_allowlist_count=0,
                                independent_network_exception_approved=False)
        self.assertIn("NETWORK_EXPOSURE_REVIEW_REQUIRED", self.check(public)["findings"])

    def test_public_acl_and_unreviewed_rls_exception_fail(self):
        result = self.check(lambda x: x["catalog"].update(
            public_table_acl_entries=1, unreviewed_rls_exceptions=2
        ))
        self.assertIn("PUBLIC_TABLE_GRANTS_PRESENT", result["findings"])
        self.assertIn("RLS_EXCEPTION_NOT_REVIEWED", result["findings"])

    def test_missing_catalog_admission_is_not_green(self):
        result = self.check(lambda x: x["catalog"].update(catalog_state="HOLD"))
        self.assertIn("CATALOG_ADMISSION_NOT_MET", result["findings"])

    def test_stale_and_future_readbacks_refused(self):
        for stamp in ("2026-11-19T19:00:00Z", "2026-11-19T20:30:00Z"):
            result = self.check(lambda x: x.update(observed_at=stamp))
            self.assertIn("READBACK_STALE_OR_FUTURE", result["findings"])

    def test_reject_sensitive_extra_keys(self):
        inp = observed()
        inp["password"] = "not-a-real-secret"
        with self.assertRaisesRegex(gate.InvalidInput, "FIELDS_INVALID"):
            gate.assess(POLICY, inp, now=NOW)

    def test_credential_flag_fails_input(self):
        with self.assertRaisesRegex(gate.InvalidInput, "CREDENTIAL_MATERIAL_REFUSED"):
            self.check(lambda x: x.update(credentials_recorded=True))

    def test_bool_must_not_coerce_to_count(self):
        with self.assertRaisesRegex(gate.InvalidInput, "INTEGER_INVALID"):
            self.check(lambda x: x["snapshots"].update(count=True))

    def test_duplicate_json_keys_refused(self):
        with self.assertRaisesRegex(gate.InvalidInput, "DUPLICATE_JSON_KEY"):
            gate.strict_json(b'{"schema":"one","schema":"two"}')

    def test_nonfinite_json_and_large_payload_refused(self):
        with self.assertRaisesRegex(gate.InvalidInput, "NONFINITE_VALUE"):
            gate.strict_json(b'{"x":NaN}')
        with self.assertRaisesRegex(gate.InvalidInput, "INPUT_SIZE_INVALID"):
            gate.strict_json(b" " * (gate.MAX_BYTES + 1))

    def test_invalid_policy_cannot_weaken_min_history_silently(self):
        weak = dict(POLICY, min_history_seconds=0)
        with self.assertRaisesRegex(gate.InvalidInput, "HISTORY_POLICY_INVALID"):
            gate.assess(weak, observed(), now=NOW)

    def test_source_unavailable_fails_closed(self):
        result = self.check(lambda x: x.update(source_state="UNAVAILABLE"))
        self.assertIn("CONTROL_PLANE_UNAVAILABLE", result["findings"])


if __name__ == "__main__":
    unittest.main()
