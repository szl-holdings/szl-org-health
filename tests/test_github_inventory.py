"""Regression for real GitHub numeric-organization continuation links."""
import unittest
from unittest.mock import patch

from census import file_audit, github_inventory as inventory


class OrganizationInventoryTests(unittest.TestCase):
    metadata = {"id": 273360816, "login": "szl-holdings", "public_repos": 117,
                "total_private_repos": 7}

    def collect(self):
        return inventory.discover_repositories(
            "szl-holdings", headers={"Authorization": "Bearer fixture"},
            timeout=1, retries=0,
        )

    def test_two_pages_cover_public_and_private_repositories(self):
        rows = [{"full_name": f"szl-holdings/repo-{i}", "private": i >= 117}
                for i in range(124)]
        url = "https://api.github.com/organizations/273360816/repos?page=2"
        with patch.object(inventory, "request_json", return_value=(self.metadata, {}, None)), \
             patch("census.common.request_json", side_effect=[
                 (rows[:100], {"link": f'<{url}>; rel="next"'}, None),
                 (rows[100:], {}, None),
             ]) as pages:
            result, reconciliation = file_audit.list_repositories("szl-holdings")
        self.assertEqual(len(result), 124)
        self.assertIs(reconciliation["matched"], True)
        self.assertEqual(reconciliation["observed_private_or_internal_count"], 7)
        self.assertEqual(pages.call_count, 2)
        for call in pages.call_args_list:
            self.assertEqual(call.kwargs["redirect_path"], "/organizations/273360816/repos")
            self.assertEqual(call.kwargs["redirect_origin"], ("https", "api.github.com", 443))

    def test_unverified_org_identity_cannot_start_pagination(self):
        for metadata in ({}, None, {**self.metadata, "id": True},
                         {**self.metadata, "id": "273360816"},
                         {**self.metadata, "id": -1},
                         {**self.metadata, "login": "foreign"}):
            with self.subTest(metadata=metadata), \
                 patch.object(inventory, "request_json", return_value=(metadata, {}, None)), \
                 patch.object(inventory, "paginate_json") as pages:
                rows, _, error = self.collect()
                self.assertIsNone(rows)
                self.assertTrue(error)
                pages.assert_not_called()

    def test_foreign_or_duplicate_repository_is_rejected(self):
        for rows in ([{"full_name": "foreign/repo"}],
                     [{"full_name": "szl-holdings/a"}, {"full_name": "SZL-HOLDINGS/A"}]):
            with self.subTest(rows=rows), \
                 patch.object(inventory, "request_json", return_value=(self.metadata, {}, None)), \
                 patch.object(inventory, "paginate_json", return_value=(rows, None)):
                result, _, error = self.collect()
                self.assertIsNone(result)
                self.assertIn("identity", error)

    def test_changed_org_and_origin_links_remain_blocked(self):
        for target in ("https://api.github.com/organizations/999/repos?page=2",
                       "https://example.org/organizations/273360816/repos?page=2"):
            with self.subTest(target=target), \
                 patch.object(inventory, "request_json", return_value=(self.metadata, {}, None)), \
                 patch("census.common.request_json", return_value=(
                     [{"full_name": "szl-holdings/a"}],
                     {"link": f'<{target}>; rel="next"'}, None,
                 )) as pages:
                rows, _, error = self.collect()
                self.assertIsNone(rows)
                self.assertIn("changed", error)
                pages.assert_called_once()

    def test_failed_metadata_read_never_uses_partial_inventory(self):
        with patch.object(inventory, "request_json", return_value=(None, {}, "http403")), \
             patch.object(inventory, "paginate_json") as pages:
            self.assertEqual(self.collect(), (None, None, "http403"))
            pages.assert_not_called()


if __name__ == "__main__":
    unittest.main()
