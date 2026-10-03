from __future__ import annotations

import hashlib
import unittest
from unittest.mock import patch

from census.huggingface import (
    HF_REPOSITORY_EXPORT_PATH,
    HF_REPOSITORY_TYPES,
    asset_result,
    collect_huggingface,
    finalize_hf_authentication,
    reconcile_hf_repository_export,
)
from census.report import _public_hf_data


def admin_authentication() -> dict:
    return {
        "schema": "szl.hf-authentication-evidence/v2",
        "credential_present": True,
        "identity_authenticated": True,
        "principal_type_user_observed": True,
        "principal_id_observed": True,
        "user_identity_observed": True,
        "access_token_auth_observed": True,
        "access_token_metadata_observed": True,
        "target_organization": "SZLHOLDINGS",
        "organization_type_observed": True,
        "organization_id_observed": True,
        "organization_name_match_observed": True,
        "target_organization_match_observed": True,
        "organization_membership_observed": True,
        "organization_read_role_observed": True,
        "organization_admin_role_observed": True,
        "probe_state": "AUTHENTICATED",
    }


def export_and_assets() -> tuple[list[dict], dict]:
    rows = [
        {"type": repo_type, "id": f"SZLHOLDINGS/example-{repo_type}"}
        for repo_type in HF_REPOSITORY_TYPES
    ]
    assets = {
        asset_kind: asset_result(
            [{"id": f"SZLHOLDINGS/example-{repo_type}"}], None
        )
        for repo_type, asset_kind in HF_REPOSITORY_TYPES.items()
    }
    assets["collections"] = asset_result(None, "collection visibility unavailable")
    return rows, assets


class RepositoryExportReconciliationTests(unittest.TestCase):
    def test_stable_admin_export_reconciles_only_repositories(self) -> None:
        rows, assets = export_and_assets()
        evidence = reconcile_hf_repository_export(
            admin_authentication(), (rows, None), (list(reversed(rows)), None), assets
        )

        expected_ids = sorted(f"{row['type']}:{row['id']}" for row in rows)
        self.assertEqual(evidence["status"], "RECONCILED")
        self.assertEqual(evidence["repository_count"], 5)
        self.assertEqual(evidence["type_counts"], {kind: 1 for kind in HF_REPOSITORY_TYPES})
        self.assertEqual(
            evidence["typed_id_sha256"],
            hashlib.sha256("\n".join(expected_ids).encode()).hexdigest(),
        )
        self.assertEqual(evidence["collections_scope"], "UNKNOWN")
        self.assertNotIn("typed_ids", evidence)

    def test_admin_identity_and_stable_export_are_independent_requirements(self) -> None:
        rows, assets = export_and_assets()
        non_admin = {**admin_authentication(), "organization_admin_role_observed": False}
        self.assertEqual(
            reconcile_hf_repository_export(non_admin, (rows, None), (rows, None), assets)[
                "status"
            ],
            "ADMIN_AUTHORITY_UNPROVEN",
        )
        self.assertEqual(
            reconcile_hf_repository_export(
                admin_authentication(), (rows, None), (rows[:-1], None), assets
            )["status"],
            "EXPORT_DRIFT",
        )
        self.assertEqual(
            reconcile_hf_repository_export(
                admin_authentication(), (rows, "http403"), (rows, None), assets
            )["status"],
            "EXPORT_REQUEST_FAILED",
        )

    def test_malformed_unrecognized_or_duplicate_export_fails_closed(self) -> None:
        rows, assets = export_and_assets()
        cases = (
            [*rows, rows[0]],
            [{**rows[0], "type": "collection"}, *rows[1:]],
            [{**rows[0], "type": {}}, *rows[1:]],
            [{**rows[0], "id": "OTHER/model"}, *rows[1:]],
            [{**rows[0], "id": "SZLHOLDINGS/nested/name"}, *rows[1:]],
        )
        for invalid in cases:
            with self.subTest(invalid=invalid[0]):
                evidence = reconcile_hf_repository_export(
                    admin_authentication(), (invalid, None), (invalid, None), assets
                )
                self.assertEqual(evidence["status"], "EXPORT_INVALID_RESPONSE")
                self.assertIsNone(evidence["typed_id_sha256"])

    def test_partial_or_mismatching_detail_listing_does_not_reconcile(self) -> None:
        rows, assets = export_and_assets()
        partial = {**assets, "models": asset_result([], "http206")}
        mismatch = {
            **assets,
            "models": asset_result([{"id": "SZLHOLDINGS/different"}], None),
        }
        duplicate = {
            **assets,
            "models": asset_result(
                [{"id": rows[0]["id"]}, {"id": rows[0]["id"]}], None
            ),
        }
        for candidate, status in (
            (partial, "DETAIL_LIST_INCOMPLETE"),
            (mismatch, "DETAIL_LIST_MISMATCH"),
            (duplicate, "DETAIL_LIST_INVALID"),
        ):
            with self.subTest(status=status):
                evidence = reconcile_hf_repository_export(
                    admin_authentication(), (rows, None), (rows, None), candidate
                )
                self.assertEqual(evidence["status"], status)

    @patch("census.huggingface.hf_paginate", return_value=([], None))
    @patch("census.huggingface.collect_hf_authentication")
    def test_collector_brackets_detail_queries_without_org_complete_promotion(
        self, authentication, paginate
    ) -> None:
        authentication.return_value = admin_authentication()

        result = collect_huggingface()

        export_calls = [
            index
            for index, call in enumerate(paginate.call_args_list)
            if call.args[0] == HF_REPOSITORY_EXPORT_PATH
        ]
        self.assertEqual(export_calls, [0, 7])
        self.assertEqual(result["repository_export"]["status"], "RECONCILED")
        self.assertEqual(result["authentication"]["inventory_scope"], "AUTHENTICATED_BOUNDED")
        self.assertIs(
            result["authentication"]["organization_complete_reconciliation_observed"],
            False,
        )
        self.assertEqual(
            result["authentication"]["organization_complete_reconciliation_method"],
            "UNAVAILABLE",
        )

    def test_preclaimed_complete_scope_and_private_export_never_reach_public(self) -> None:
        rows, assets = export_and_assets()
        evidence = reconcile_hf_repository_export(
            admin_authentication(), (rows, None), (rows, None), assets
        )
        finalized = finalize_hf_authentication(
            {
                **admin_authentication(),
                "inventory_scope": "ORG_COMPLETE",
                "organization_complete_reconciliation_observed": True,
                "organization_complete_reconciliation_method": "AUTHORITATIVE_ORG_EXPORT",
            },
            assets,
        )
        self.assertNotEqual(finalized["inventory_scope"], "ORG_COMPLETE")
        self.assertIs(finalized["organization_complete_reconciliation_observed"], False)
        public = _public_hf_data(
            {
                "organization": "SZLHOLDINGS",
                "authentication": finalized,
                "repository_export": evidence,
                "assets": assets,
            }
        )
        self.assertNotIn("repository_export", public)
        self.assertNotIn(evidence["typed_id_sha256"], str(public))


if __name__ == "__main__":
    unittest.main()
