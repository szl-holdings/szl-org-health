from __future__ import annotations

import unittest
from unittest import mock

from census.github import _branch_governance


ORG_RULESET_ID = 17630223


def inherited_rule(rule_type: str) -> dict:
    return {
        "type": rule_type,
        "ruleset_source_type": "Organization",
        "ruleset_source": "szl-holdings",
        "ruleset_id": ORG_RULESET_ID,
    }


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
            {"type": "pull_request", "parameters": {}},
            {"type": "required_status_checks", "parameters": {}},
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
    @mock.patch("census.github.gh")
    def test_active_inherited_org_rules_are_recognized_semantically(self, gh):
        gh.side_effect = [
            (None, "http404"),
            (
                [
                    inherited_rule("pull_request"),
                    inherited_rule("required_status_checks"),
                ],
                None,
            ),
            ([inherited_summary()], None),
            (inherited_detail(bypass_actors=[]), None),
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
        requested_paths = [call.args[0] for call in gh.call_args_list]
        self.assertIn(
            "/repos/szl-holdings/szl-org-health/rules/branches/main",
            requested_paths,
        )
        self.assertTrue(
            any("includes_parents=true" in path for path in requested_paths)
        )
        self.assertIn(
            f"/repos/szl-holdings/szl-org-health/rulesets/{ORG_RULESET_ID}",
            requested_paths,
        )

    @mock.patch("census.github.gh")
    def test_workflow_and_code_scanning_api_rules_are_enforcing(self, gh):
        for rule_type in ("workflows", "code_scanning"):
            with self.subTest(rule_type=rule_type):
                detail = inherited_detail(bypass_actors=[])
                detail["rules"] = [{"type": rule_type}]
                gh.side_effect = [
                    (None, "http404"),
                    ([inherited_rule(rule_type)], None),
                    ([inherited_summary()], None),
                    (detail, None),
                ]

                result = evaluate()

                self.assertIs(result["protected"], True)
                self.assertEqual(result["protection_state"], "PROTECTED")
                self.assertEqual(result["protection_source"], "effective-ruleset")
                self.assertEqual(result["protection_rule_types"], [rule_type])
                self.assertEqual(
                    result["protection_ruleset_ids"], [ORG_RULESET_ID]
                )

    @mock.patch("census.github.gh")
    def test_classic_branch_protection_remains_the_first_fallback(self, gh):
        gh.return_value = ({"enforce_admins": {"enabled": True}}, None)

        result = evaluate()

        self.assertIs(result["protected"], True)
        self.assertEqual(result["protection_source"], "classic")
        self.assertIs(result["protection_inherited"], False)
        self.assertEqual(gh.call_count, 1)

    @mock.patch("census.github.gh")
    def test_inaccessible_effective_rules_fail_closed(self, gh):
        gh.side_effect = [(None, "http404"), (None, "http403")]

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertEqual(result["protection_state"], "FAILED_CLOSED")
        self.assertIn(
            "effective branch rules unavailable",
            result["protection_error"],
        )

    @mock.patch("census.github.gh")
    def test_inactive_ruleset_fails_closed(self, gh):
        gh.side_effect = [
            (None, "http404"),
            ([inherited_rule("pull_request")], None),
            ([inherited_summary(enforcement="evaluate")], None),
        ]

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertEqual(result["protection_state"], "FAILED_CLOSED")
        self.assertIn("not actively enforced", result["protection_error"])

    @mock.patch("census.github.gh")
    def test_ruleset_with_bypass_actor_fails_closed(self, gh):
        gh.side_effect = [
            (None, "http404"),
            ([inherited_rule("pull_request")], None),
            ([inherited_summary()], None),
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

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertEqual(result["protection_state"], "FAILED_CLOSED")
        self.assertIn("permits bypass actors", result["protection_error"])

    @mock.patch("census.github.gh")
    def test_malformed_ruleset_detail_fails_closed(self, gh):
        gh.side_effect = [
            (None, "http404"),
            ([inherited_rule("pull_request")], None),
            ([inherited_summary()], None),
            (inherited_detail(), None),
        ]

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertEqual(result["protection_state"], "FAILED_CLOSED")
        self.assertIn(
            "malformed or inconsistent",
            result["protection_error"],
        )

    @mock.patch("census.github.gh")
    def test_absent_classic_and_ruleset_protection_fails_closed(self, gh):
        gh.side_effect = [(None, "http404"), ([], None), ([], None)]

        result = evaluate()

        self.assertIsNone(result["protected"])
        self.assertEqual(result["protection_state"], "FAILED_CLOSED")
        self.assertIn(
            "no enforceable effective branch governance rule observed",
            result["protection_error"],
        )


if __name__ == "__main__":
    unittest.main()