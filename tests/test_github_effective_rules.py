from __future__ import annotations

import unittest
from unittest import mock

from census.github import MAX_PAGES, _branch_governance


ORG_RULESET_ID = 17630223


def rule_parameters(rule_type: str) -> dict:
    if rule_type == "pull_request":
        return {"required_approving_review_count": 0}
    if rule_type == "required_status_checks":
        return {
            "strict_required_status_checks_policy": True,
            "required_status_checks": [{"context": "ci"}],
        }
    if rule_type == "workflows":
        return {"workflows": [{"path": ".github/workflows/ci.yml"}]}
    if rule_type == "code_scanning":
        return {
            "code_scanning_tools": [
                {
                    "tool": "CodeQL",
                    "security_alerts_threshold": "high_or_higher",
                    "alerts_threshold": "errors",
                }
            ]
        }
    if rule_type == "required_deployments":
        return {"required_deployment_environments": ["production"]}
    raise AssertionError(f"no parameters fixture for {rule_type}")


def inherited_rule(rule_type: str) -> dict:
    rule = {
        "type": rule_type,
        "ruleset_source_type": "Organization",
        "ruleset_source": "szl-holdings",
        "ruleset_id": ORG_RULESET_ID,
    }
    if rule_type in {
        "pull_request",
        "required_status_checks",
        "workflows",
        "code_scanning",
        "required_deployments",
    }:
        rule["parameters"] = rule_parameters(rule_type)
    return rule


def detailed_rule(rule_type: str) -> dict:
    rule = {"type": rule_type}
    if rule_type in {
        "pull_request",
        "required_status_checks",
        "workflows",
        "code_scanning",
        "required_deployments",
    }:
        rule["parameters"] = rule_parameters(rule_type)
    return rule


def inherited_summary(enforcement: str = "active") -> dict:
    return {
        "id": ORG_RULESET_ID,
        "name": "SZL inherited branch governance",
        "target": "branch",
        "source_type": "Organization",
        "source": "szl-holdings",
        "enforcement": enforcement,
    }


def inherited_detail(*, bypass_actors: list | None = None) -> dict:
    detail = {
        **inherited_summary(),
        "rules": [
            detailed_rule("pull_request"),
            detailed_rule("required_status_checks"),
        ],
    }
    if bypass_actors is not None:
        detail["bypass_actors"] = bypass_actors
    return detail


def evaluate() -> dict:
    return _branch_governance(
        "szl-org-health",
        "main",
        request_timeout=1.0,
        retries=0,
    )


class EffectiveBranchRulesTests(unittest.TestCase):
    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_active_inherited_org_rules_are_recognized_semantically(
        self, gh, paginate
    ):
        gh.side_effect = [
            (None, "http404"),
            (inherited_detail(bypass_actors=[]), None),
        ]
        paginate.side_effect = [
            (
                [
                    inherited_rule("pull_request"),
                    inherited_rule("required_status_checks"),
                ],
                None,
            ),
            ([inherited_summary()], None),
        ]

        result = evaluate()

        self.assertIs(result["protected"], True)
        self.assertEqual(result["protection_state"], "PROTECTED")
        self.assertEqual(result["protection_source"], "effective-ruleset")
        self.assertIs(result["protection_inherited"], True)
        self.assertEqual(result["protection_ruleset_ids"], [ORG_RULESET_ID])
        self.assertEqual(
            result["protection_rule_types"],
            ["pull_request", "required_status_checks"],
        )
        paginated_paths = [call.args[0] for call in paginate.call_args_list]
        self.assertIn(
            "/repos/szl-holdings/szl-org-health/rules/branches/main?per_page=100",
            paginated_paths,
        )
        self.assertTrue(
            any("includes_parents=true" in path for path in paginated_paths)
        )
        self.assertTrue(
            all(
                call.kwargs["max_pages"] == MAX_PAGES
                for call in paginate.call_args_list
            )
        )
        self.assertIn(
            (
                f"/repos/szl-holdings/szl-org-health/rulesets/{ORG_RULESET_ID}"
                "?includes_parents=true"
            ),
            [call.args[0] for call in gh.call_args_list],
        )

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_workflow_and_code_scanning_api_rules_are_enforcing(
        self, gh, paginate
    ):
        for rule_type in ("workflows", "code_scanning"):
            with self.subTest(rule_type=rule_type):
                gh.reset_mock()
                paginate.reset_mock()
                detail = inherited_detail(bypass_actors=[])
                detail["rules"] = [detailed_rule(rule_type)]
                gh.side_effect = [(None, "http404"), (detail, None)]
                paginate.side_effect = [
                    ([inherited_rule(rule_type)], None),
                    ([inherited_summary()], None),
                ]

                result = evaluate()

                self.assertIs(result["protected"], True)
                self.assertEqual(result["protection_source"], "effective-ruleset")
                self.assertEqual(result["protection_rule_types"], [rule_type])

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_classic_branch_protection_remains_the_first_fallback(
        self, gh, paginate
    ):
        gh.return_value = ({"enforce_admins": {"enabled": True}}, None)

        result = evaluate()

        self.assertIs(result["protected"], True)
        self.assertEqual(result["protection_source"], "classic")
        self.assertIs(result["protection_inherited"], False)
        self.assertEqual(gh.call_count, 1)
        paginate.assert_not_called()

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_classic_branch_protection_rejects_admin_or_write_bypass(
        self, gh, paginate
    ):
        cases = (
            {"enforce_admins": {"enabled": False}},
            {"required_pull_request_reviews": {}},
            {
                "enforce_admins": {"enabled": True},
                "allow_force_pushes": {"enabled": True},
            },
            {
                "enforce_admins": {"enabled": True},
                "allow_deletions": {"enabled": True},
            },
        )
        for classic in cases:
            with self.subTest(classic=classic):
                gh.reset_mock()
                paginate.reset_mock()
                gh.return_value = (classic, None)
                paginate.return_value = (None, "http403")

                result = evaluate()

                self.assertIsNone(result["protected"])
                self.assertEqual(result["protection_state"], "FAILED_CLOSED")
                paginate.assert_called()

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_inaccessible_effective_rules_fail_closed(self, gh, paginate):
        gh.return_value = (None, "http404")
        paginate.return_value = (None, "http403")

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertEqual(result["protection_state"], "FAILED_CLOSED")
        self.assertIn("effective branch rules unavailable", result["protection_error"])

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_inactive_ruleset_fails_closed(self, gh, paginate):
        gh.return_value = (None, "http404")
        paginate.side_effect = [
            ([inherited_rule("pull_request")], None),
            ([inherited_summary(enforcement="evaluate")], None),
        ]

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertIn("not actively enforced", result["protection_error"])

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_ruleset_with_bypass_actor_fails_closed(self, gh, paginate):
        gh.side_effect = [
            (None, "http404"),
            (
                inherited_detail(
                    bypass_actors=[
                        {
                            "actor_id": 1,
                            "actor_type": "OrganizationAdmin",
                            "bypass_mode": "always",
                        }
                    ]
                ),
                None,
            ),
        ]
        paginate.side_effect = [
            ([inherited_rule("pull_request")], None),
            ([inherited_summary()], None),
        ]

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertIn("permits bypass actors", result["protection_error"])

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_malformed_ruleset_detail_fails_closed(self, gh, paginate):
        gh.side_effect = [(None, "http404"), (inherited_detail(), None)]
        paginate.side_effect = [
            ([inherited_rule("pull_request")], None),
            ([inherited_summary()], None),
        ]

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertIn("malformed or inconsistent", result["protection_error"])

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_absent_classic_and_ruleset_protection_fails_closed(
        self, gh, paginate
    ):
        gh.return_value = (None, "http404")
        paginate.side_effect = [([], None), ([], None)]

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertIn(
            "no enforceable effective branch governance rule observed",
            result["protection_error"],
        )

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_decorated_rule_type_is_not_normalized(self, gh, paginate):
        gh.return_value = (None, "http404")
        paginate.side_effect = [
            ([inherited_rule(" workflows ")], None),
            ([inherited_summary()], None),
        ]

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertIn("malformed entry", result["protection_error"])

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_decorated_source_identity_is_not_normalized(self, gh, paginate):
        gh.return_value = (None, "http404")
        rule = inherited_rule("pull_request")
        rule["ruleset_source"] = "szl-holdings "
        paginate.side_effect = [([rule], None), ([inherited_summary()], None)]

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertIn("malformed entry", result["protection_error"])

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_paginated_inventory_error_fails_closed(self, gh, paginate):
        gh.return_value = (None, "http404")
        paginate.side_effect = [
            ([inherited_rule("pull_request")], None),
            (None, "pagination cycle detected"),
        ]

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertIn("pagination cycle detected", result["protection_error"])

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_effective_and_detail_rule_parameters_must_match_exactly(
        self, gh, paginate
    ):
        effective_rule = inherited_rule("required_status_checks")
        detail = inherited_detail(bypass_actors=[])
        detail["rules"][1]["parameters"]["required_status_checks"][0][
            "context"
        ] = "different-ci"
        gh.side_effect = [(None, "http404"), (detail, None)]
        paginate.side_effect = [
            ([effective_rule], None),
            ([inherited_summary()], None),
        ]

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertIn("parameters do not match", result["protection_error"])

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_rule_parameter_boolean_integer_substitution_is_not_equal(
        self, gh, paginate
    ):
        rule = inherited_rule("pull_request")
        rule["parameters"] = {"required_approving_review_count": 1}
        detail = inherited_detail(bypass_actors=[])
        detail["rules"] = [
            {
                "type": "pull_request",
                "parameters": {"required_approving_review_count": True},
            }
        ]
        gh.side_effect = [(None, "http404"), (detail, None)]
        paginate.side_effect = [([rule], None), ([inherited_summary()], None)]

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertIn("parameters do not match", result["protection_error"])

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_noop_status_check_or_workflow_rule_fails_closed(self, gh, paginate):
        for rule_type, list_name in (
            ("required_status_checks", "required_status_checks"),
            ("workflows", "workflows"),
            ("code_scanning", "code_scanning_tools"),
            ("required_deployments", "required_deployment_environments"),
        ):
            with self.subTest(rule_type=rule_type):
                gh.reset_mock()
                paginate.reset_mock()
                rule = inherited_rule(rule_type)
                rule["parameters"][list_name] = []
                gh.return_value = (None, "http404")
                paginate.side_effect = [
                    ([rule], None),
                    ([inherited_summary()], None),
                ]

                result = evaluate()

                self.assertIsNone(result["protected"])
                self.assertIn("no enforced", result["protection_error"])

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_nonempty_but_semantically_empty_requirements_fail_closed(
        self, gh, paginate
    ):
        for rule_type, list_name in (
            ("required_status_checks", "required_status_checks"),
            ("workflows", "workflows"),
            ("code_scanning", "code_scanning_tools"),
        ):
            with self.subTest(rule_type=rule_type):
                gh.reset_mock()
                paginate.reset_mock()
                rule = inherited_rule(rule_type)
                rule["parameters"][list_name] = [{"unrelated": "value"}]
                gh.return_value = (None, "http404")
                paginate.side_effect = [
                    ([rule], None),
                    ([inherited_summary()], None),
                ]

                result = evaluate()

                self.assertIsNone(result["protected"])
                self.assertIn("malformed requirement", result["protection_error"])

    @mock.patch("census.github.gh_paginate")
    @mock.patch("census.github.gh")
    def test_duplicate_or_non_json_rule_parameters_fail_closed(self, gh, paginate):
        cases = []
        duplicate = inherited_rule("pull_request")
        cases.append([duplicate, inherited_rule("pull_request")])
        non_json = inherited_rule("pull_request")
        non_json["parameters"] = {"bad": object()}
        cases.append([non_json])
        non_finite = inherited_rule("pull_request")
        non_finite["parameters"] = {"bad": float("nan")}
        cases.append([non_finite])

        for rules in cases:
            with self.subTest(rules=rules):
                gh.reset_mock()
                paginate.reset_mock()
                gh.return_value = (None, "http404")
                paginate.side_effect = [
                    (rules, None),
                    ([inherited_summary()], None),
                ]

                result = evaluate()

                self.assertIsNone(result["protected"])
                self.assertEqual(result["protection_state"], "FAILED_CLOSED")


if __name__ == "__main__":
    unittest.main()
