from __future__ import annotations

import copy
import json
import unittest
from typing import Any
from unittest.mock import patch

from census.huggingface import (
    HF_ASSET_KINDS,
    HF_AUTH_SCHEMA,
    HF_SCOPE_AUTHENTICATED_BOUNDED,
    HF_SCOPE_IDENTITY_AND_ORG,
    HF_SCOPE_IDENTITY_ONLY,
    HF_SCOPE_UNAVAILABLE,
    asset_result,
    collect_hf_authentication,
    collect_huggingface,
    finalize_hf_authentication,
    normalize_space,
    space_runtime_url,
)

AUTH_HEADERS = {
    "Accept": "application/json",
    "Authorization": "Bearer test-secret-token",
}
SAFE_AUTH_KEYS = {
    "schema",
    "credential_present",
    "identity_authenticated",
    "principal_type_user_observed",
    "principal_id_observed",
    "user_identity_observed",
    "access_token_auth_observed",
    "access_token_metadata_observed",
    "target_organization",
    "organization_type_observed",
    "organization_id_observed",
    "organization_name_match_observed",
    "target_organization_match_observed",
    "organization_membership_observed",
    "organization_read_role_observed",
    "credential_class",
    "fine_grained_metadata_observed",
    "org_scope_candidate_observed",
    "unknown_grants_observed",
    "global_permissions_state",
    "inventory_scope",
    "probe_state",
}
RAW_SECRETS = (
    "principal-secret-id",
    "principal-secret-name",
    "principal@example.test",
    "org-secret-id",
    "token-secret-id",
    "token-secret-name",
    "test-secret-token",
    "repo.content.read",
    "repo.content.write",
    "discussion.write",
    "raw-auth-permission",
    "raw-error-detail",
    "response-secret",
    "secret-restriction",
    "secret-resource-group",
)


def valid_payload(
    *,
    token_role: Any = "read",
    organization_role: Any = "read",
    fine_grained: Any = None,
) -> dict[str, Any]:
    access_token: dict[str, Any] = {
        "role": token_role,
        "id": "token-secret-id",
        "displayName": "token-secret-name",
    }
    if fine_grained is not None:
        access_token["fineGrained"] = fine_grained
    return {
        "type": "user",
        "id": "principal-secret-id",
        "name": "principal-secret-name",
        "email": "principal@example.test",
        "orgs": [
            {
                "type": "org",
                "id": "org-secret-id",
                "name": "SZLHOLDINGS",
                "roleInOrg": organization_role,
                "securityRestrictions": ["secret-restriction"],
                "resourceGroups": [{"name": "secret-resource-group"}],
            }
        ],
        "auth": {
            "type": "access_token",
            "accessToken": access_token,
            "permissions": ["raw-auth-permission"],
        },
    }


def complete_assets() -> dict[str, dict[str, Any]]:
    return {name: asset_result([], None) for name in HF_ASSET_KINDS}


class HuggingFaceAuthenticationTests(unittest.TestCase):
    def collect_payload(self, payload: Any) -> dict[str, Any]:
        with (
            patch("census.huggingface.hf_headers", return_value=AUTH_HEADERS),
            patch(
                "census.huggingface.request_json",
                return_value=(payload, {"x-secret": "response-secret"}, None),
            ),
        ):
            return collect_hf_authentication()

    def assert_safe_projection(self, result: dict[str, Any]) -> None:
        self.assertEqual(set(result), SAFE_AUTH_KEYS)
        encoded = json.dumps(result, sort_keys=True)
        for secret in RAW_SECRETS:
            self.assertNotIn(secret, encoded)
        for raw_field in (
            "accessToken",
            "fineGrained",
            "permissions",
            "roleInOrg",
            "securityRestrictions",
            "resourceGroups",
        ):
            self.assertNotIn(raw_field, result)

    @patch("census.huggingface.request_json")
    @patch(
        "census.huggingface.hf_headers",
        return_value={"Accept": "application/json"},
    )
    def test_missing_token_fails_closed_without_identity_request(
        self, _headers, request_json
    ) -> None:
        result = collect_hf_authentication()

        self.assertEqual(result["schema"], HF_AUTH_SCHEMA)
        self.assertIs(result["credential_present"], False)
        self.assertIs(result["identity_authenticated"], False)
        self.assertEqual(result["inventory_scope"], HF_SCOPE_UNAVAILABLE)
        self.assertEqual(result["probe_state"], "CREDENTIAL_NOT_CONFIGURED")
        self.assert_safe_projection(result)
        request_json.assert_not_called()

    def test_request_failures_become_sanitized_probe_states(self) -> None:
        cases = {
            "http401 raw-error-detail": "INVALID_CREDENTIAL",
            "http403 raw-error-detail": "DENIED_OR_RESTRICTED",
            "http429 raw-error-detail": "RATE_LIMITED",
            "timeout raw-error-detail": "REQUEST_FAILED",
        }
        for raw_error, expected_state in cases.items():
            with self.subTest(raw_error=raw_error):
                with (
                    patch(
                        "census.huggingface.hf_headers",
                        return_value=AUTH_HEADERS,
                    ),
                    patch(
                        "census.huggingface.request_json",
                        return_value=(None, {}, raw_error),
                    ),
                ):
                    result = collect_hf_authentication()

                self.assertIs(result["credential_present"], True)
                self.assertIs(result["identity_authenticated"], False)
                self.assertEqual(result["inventory_scope"], HF_SCOPE_UNAVAILABLE)
                self.assertEqual(result["probe_state"], expected_state)
                self.assert_safe_projection(result)

    def test_non_mapping_response_is_invalid_and_sanitized(self) -> None:
        for payload in (None, [], "principal-secret-name"):
            with self.subTest(payload=payload):
                result = self.collect_payload(payload)
                self.assertIs(result["identity_authenticated"], False)
                self.assertEqual(result["inventory_scope"], HF_SCOPE_UNAVAILABLE)
                self.assertEqual(result["probe_state"], "INVALID_RESPONSE")
                self.assert_safe_projection(result)

    def test_principal_and_access_token_schema_are_strict(self) -> None:
        cases: list[tuple[str, Any]] = [
            ("missing-principal-type", None),
            ("wrong-principal-type", "org"),
            ("missing-principal-id", None),
            ("blank-principal-id", " "),
            ("missing-auth", None),
            ("wrong-auth-type", "oauth"),
            ("missing-access-token", None),
            ("non-mapping-access-token", []),
        ]
        for label, replacement in cases:
            with self.subTest(case=label):
                payload = valid_payload()
                if label == "missing-principal-type":
                    payload.pop("type")
                elif label == "wrong-principal-type":
                    payload["type"] = replacement
                elif label == "missing-principal-id":
                    payload.pop("id")
                elif label == "blank-principal-id":
                    payload["id"] = replacement
                elif label == "missing-auth":
                    payload.pop("auth")
                elif label == "wrong-auth-type":
                    payload["auth"]["type"] = replacement
                elif label == "missing-access-token":
                    payload["auth"].pop("accessToken")
                else:
                    payload["auth"]["accessToken"] = replacement

                result = self.collect_payload(payload)

                self.assertIs(result["identity_authenticated"], False)
                self.assertEqual(result["inventory_scope"], HF_SCOPE_UNAVAILABLE)
                self.assertEqual(result["probe_state"], "INVALID_RESPONSE")
                self.assert_safe_projection(result)

    def test_principal_display_name_is_optional_and_never_persisted(self) -> None:
        payload = valid_payload()
        payload.pop("name")

        result = self.collect_payload(payload)

        self.assertIs(result["identity_authenticated"], True)
        self.assertIs(result["principal_id_observed"], True)
        self.assertEqual(result["inventory_scope"], HF_SCOPE_IDENTITY_AND_ORG)
        self.assertEqual(result["probe_state"], "AUTHENTICATED")
        self.assert_safe_projection(result)

    def test_org_schema_requires_type_id_name_and_role_in_org(self) -> None:
        cases = (
            "orgs-not-list",
            "missing-org-type",
            "wrong-org-type",
            "missing-org-id",
            "blank-org-id",
            "missing-org-name",
            "wrong-org-name",
            "missing-role-in-org",
            "non-string-role-in-org",
        )
        for label in cases:
            with self.subTest(case=label):
                payload = valid_payload()
                organization = payload["orgs"][0]
                if label == "orgs-not-list":
                    payload["orgs"] = {}
                elif label == "missing-org-type":
                    organization.pop("type")
                elif label == "wrong-org-type":
                    organization["type"] = "user"
                elif label == "missing-org-id":
                    organization.pop("id")
                elif label == "blank-org-id":
                    organization["id"] = " "
                elif label == "missing-org-name":
                    organization.pop("name")
                elif label == "wrong-org-name":
                    organization["name"] = "ANOTHER-ORG"
                elif label == "missing-role-in-org":
                    organization.pop("roleInOrg")
                    organization["role"] = "admin"
                else:
                    organization["roleInOrg"] = {"role": "admin"}

                result = self.collect_payload(payload)

                self.assertIs(result["identity_authenticated"], True)
                self.assertIs(result["organization_read_role_observed"], False)
                self.assertEqual(result["inventory_scope"], HF_SCOPE_IDENTITY_ONLY)
                self.assertEqual(result["probe_state"], "AUTHENTICATED")
                self.assert_safe_projection(result)

    def test_legacy_token_roles_are_safely_classified(self) -> None:
        for raw_role, expected in (
            ("read", "LEGACY_READ"),
            ("write", "LEGACY_WRITE"),
            ({"malformed": "role"}, "UNKNOWN"),
        ):
            with self.subTest(raw_role=raw_role):
                result = self.collect_payload(valid_payload(token_role=raw_role))

                self.assertEqual(result["credential_class"], expected)
                self.assertIs(result["fine_grained_metadata_observed"], False)
                self.assertIs(result["org_scope_candidate_observed"], False)
                self.assertEqual(result["global_permissions_state"], "UNAVAILABLE")
                self.assertEqual(result["inventory_scope"], HF_SCOPE_IDENTITY_AND_ORG)
                self.assert_safe_projection(result)

    def test_fine_grained_classification_is_redacted_and_non_authoritative(
        self,
    ) -> None:
        fine_grained = {
            "scoped": [
                {
                    "entity": {
                        "type": "org",
                        "_id": "org-secret-id",
                        "name": "SZLHOLDINGS",
                    },
                    "permissions": ["repo.content.read"],
                }
            ],
            "global": [],
        }

        result = self.collect_payload(
            valid_payload(token_role="fineGrained", fine_grained=fine_grained)
        )

        self.assertEqual(result["credential_class"], "FINE_GRAINED")
        self.assertIs(result["fine_grained_metadata_observed"], True)
        self.assertIs(result["org_scope_candidate_observed"], True)
        self.assertIs(result["unknown_grants_observed"], False)
        self.assertEqual(result["global_permissions_state"], "NONE")
        self.assertEqual(result["inventory_scope"], HF_SCOPE_IDENTITY_AND_ORG)
        self.assert_safe_projection(result)

    def test_unknown_fine_grained_permissions_are_only_boolean_evidence(self) -> None:
        fine_grained = {
            "scoped": [
                {
                    "entity": {"type": "org", "_id": "org-secret-id"},
                    "permissions": ["repo.content.write"],
                }
            ],
            "global": ["discussion.write"],
        }

        result = self.collect_payload(
            valid_payload(token_role="fineGrained", fine_grained=fine_grained)
        )

        self.assertEqual(result["credential_class"], "FINE_GRAINED")
        self.assertIs(result["fine_grained_metadata_observed"], True)
        self.assertIs(result["org_scope_candidate_observed"], False)
        self.assertIs(result["unknown_grants_observed"], True)
        self.assertEqual(result["global_permissions_state"], "PRESENT")
        self.assert_safe_projection(result)

    def test_whoami_never_claims_bounded_inventory_before_assets(self) -> None:
        result = self.collect_payload(valid_payload())

        self.assertEqual(result["inventory_scope"], HF_SCOPE_IDENTITY_AND_ORG)
        self.assertNotEqual(result["inventory_scope"], HF_SCOPE_AUTHENTICATED_BOUNDED)

    def test_finalize_promotes_only_with_every_configured_asset_ok(self) -> None:
        initial = self.collect_payload(valid_payload())
        original = copy.deepcopy(initial)

        finalized = finalize_hf_authentication(initial, complete_assets())

        self.assertEqual(finalized["inventory_scope"], HF_SCOPE_AUTHENTICATED_BOUNDED)
        self.assertEqual(initial, original)
        self.assert_safe_projection(finalized)

    def test_legacy_write_bounded_scope_preserves_least_privilege_evidence(
        self,
    ) -> None:
        initial = self.collect_payload(valid_payload(token_role="write"))

        finalized = finalize_hf_authentication(initial, complete_assets())

        self.assertEqual(finalized["inventory_scope"], HF_SCOPE_AUTHENTICATED_BOUNDED)
        self.assertEqual(finalized["credential_class"], "LEGACY_WRITE")
        self.assertIs(finalized["fine_grained_metadata_observed"], False)
        self.assertIs(finalized["org_scope_candidate_observed"], False)
        self.assertIs(finalized["unknown_grants_observed"], False)
        self.assertEqual(finalized["global_permissions_state"], "UNAVAILABLE")
        self.assert_safe_projection(finalized)

    def test_finalize_rejects_missing_partial_or_unavailable_assets(self) -> None:
        initial = self.collect_payload(valid_payload())
        asset_cases = {
            "missing": {
                name: result
                for name, result in complete_assets().items()
                if name != "buckets"
            },
            "partial": {
                **complete_assets(),
                "models": asset_result([], "http206 raw-error-detail"),
            },
            "unavailable": {
                **complete_assets(),
                "datasets": asset_result(None, "timeout raw-error-detail"),
            },
        }
        for label, assets in asset_cases.items():
            with self.subTest(case=label):
                finalized = finalize_hf_authentication(initial, assets)
                self.assertEqual(
                    finalized["inventory_scope"], HF_SCOPE_IDENTITY_AND_ORG
                )

    def test_finalize_canonicalizes_preclaimed_or_contradictory_scope(self) -> None:
        assets = complete_assets()
        initial = self.collect_payload(valid_payload())

        preclaimed = {**initial, "inventory_scope": HF_SCOPE_AUTHENTICATED_BOUNDED}
        without_one_asset = dict(assets)
        without_one_asset.pop("models")
        finalized = finalize_hf_authentication(preclaimed, without_one_asset)
        self.assertEqual(finalized["inventory_scope"], HF_SCOPE_IDENTITY_AND_ORG)

        contradictory_identity = {
            **preclaimed,
            "principal_id_observed": False,
        }
        finalized = finalize_hf_authentication(contradictory_identity, assets)
        self.assertEqual(finalized["inventory_scope"], HF_SCOPE_UNAVAILABLE)

        contradictory_org = {
            **preclaimed,
            "organization_membership_observed": False,
        }
        finalized = finalize_hf_authentication(contradictory_org, assets)
        self.assertEqual(finalized["inventory_scope"], HF_SCOPE_IDENTITY_ONLY)

    def test_asset_result_distinguishes_complete_partial_and_unavailable(self) -> None:
        complete = asset_result([], None)
        partial = asset_result([{"id": "public-item"}], "http206")
        unavailable = asset_result(None, "timeout")

        self.assertEqual(
            complete,
            {
                "ok": True,
                "partial": False,
                "count": 0,
                "error": None,
                "items": [],
            },
        )
        self.assertIs(partial["ok"], False)
        self.assertIs(partial["partial"], True)
        self.assertEqual(partial["count"], 1)
        self.assertEqual(partial["items"], [{"id": "public-item"}])
        self.assertIs(unavailable["ok"], False)
        self.assertIs(unavailable["partial"], False)
        self.assertIsNone(unavailable["count"])
        self.assertEqual(unavailable["items"], [])

    def test_space_runtime_url_accepts_only_canonical_hf_host_labels(self) -> None:
        self.assertEqual(
            space_runtime_url(
                {
                    "subdomain": "szlholdings-anatomy",
                    "sdk": "gradio",
                }
            ),
            "https://szlholdings-anatomy.hf.space/",
        )
        self.assertEqual(
            space_runtime_url(
                {
                    "id": "SZLHOLDINGS/anatomy",
                    "subdomain": "",
                    "sdk": "static",
                }
            ),
            "https://szlholdings-anatomy.static.hf.space/",
        )

    def test_space_runtime_url_rejects_host_path_and_port_injection(self) -> None:
        invalid_subdomains: tuple[Any, ...] = (
            "127.0.0.1:1234/",
            "127.0.0.1",
            "space.example.test",
            "space.hf.space",
            "bad/path",
            "bad:443",
            "-leading-hyphen",
            "trailing-hyphen-",
            "UpperCase",
            " leading-space",
            "trailing-space ",
            "a" * 64,
            ["not", "a", "label"],
            {"not": "a-label"},
        )
        for subdomain in invalid_subdomains:
            with self.subTest(subdomain=subdomain):
                self.assertIsNone(
                    space_runtime_url(
                        {
                            "id": "SZLHOLDINGS/anatomy",
                            "subdomain": subdomain,
                            "sdk": "gradio",
                        }
                    )
                )

    @patch("census.huggingface.request_json")
    @patch("census.huggingface.http_probe")
    def test_invalid_space_subdomain_never_drives_runtime_probe(
        self, probe, request_json
    ) -> None:
        result = normalize_space(
            {
                "id": "SZLHOLDINGS/adversarial",
                "subdomain": "127.0.0.1:1234/",
                "sdk": "gradio",
                "runtime": {"stage": "RUNNING"},
            }
        )

        self.assertIsNone(result["runtime_url"])
        self.assertEqual(result["http"], 0)
        probe.assert_not_called()
        request_json.assert_not_called()

    @patch("census.huggingface.hf_paginate", return_value=([], None))
    @patch("census.huggingface.collect_hf_authentication")
    def test_collector_applies_finalization_after_all_assets(
        self, authentication, _paginate
    ) -> None:
        authentication.return_value = self.collect_payload(valid_payload())

        result = collect_huggingface()

        self.assertEqual(
            result["authentication"]["inventory_scope"],
            HF_SCOPE_AUTHENTICATED_BOUNDED,
        )
        self.assertTrue(all(result["assets"][name]["ok"] for name in HF_ASSET_KINDS))

    @patch("census.huggingface.collect_hf_authentication")
    def test_collector_does_not_promote_partial_asset_result(
        self, authentication
    ) -> None:
        authentication.return_value = self.collect_payload(valid_payload())

        def paginate(path: str, **_kwargs: Any):
            if path.startswith("/api/models"):
                return [], "http206 raw-error-detail"
            return [], None

        with patch("census.huggingface.hf_paginate", side_effect=paginate):
            result = collect_huggingface()

        self.assertIs(result["assets"]["models"]["ok"], False)
        self.assertIs(result["assets"]["models"]["partial"], True)
        self.assertEqual(
            result["authentication"]["inventory_scope"],
            HF_SCOPE_IDENTITY_AND_ORG,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
