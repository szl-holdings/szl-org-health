# SPDX-License-Identifier: Apache-2.0
"""Security and completeness contracts for deep repository audit v2."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
import urllib.request
from argparse import Namespace
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "census" / "deep_repository_audit_v2.py"
SPEC = importlib.util.spec_from_file_location("szl_deep_repository_audit_v2_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


class DeepRepositoryAuditV2Contracts(unittest.TestCase):
    def test_api_origin_is_exact_and_rejects_userinfo_port_or_other_host(self) -> None:
        self.assertEqual(
            audit._api_url("/repos/szl-holdings/a11oy", "https://api.github.com"),
            "https://api.github.com/repos/szl-holdings/a11oy",
        )
        for value in (
            "http://api.github.com/repos/x/y",
            "https://token@api.github.com/repos/x/y",
            "https://api.github.com:444/repos/x/y",
            "https://example.com/repos/x/y",
        ):
            with self.subTest(value=value), self.assertRaises(audit.AuditError):
                audit._api_url(value, "https://api.github.com")

    def test_archive_redirect_strips_authorization_and_proxy_authorization(self) -> None:
        handler = audit.LockedRedirectHandler(allow_codeload=True)
        request = urllib.request.Request(
            "https://api.github.com/repos/szl-holdings/a11oy/tarball/" + "a" * 40,
            headers={
                "Authorization": "Bearer secret-value",
                "Proxy-Authorization": "Basic secret-value",
                "Accept": "application/vnd.github+json",
            },
        )
        redirected = handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://codeload.github.com/szl-holdings/a11oy/legacy.tar.gz/" + "a" * 40,
        )
        self.assertIsNotNone(redirected)
        assert redirected is not None
        headers = {
            key.lower(): value
            for mapping in (redirected.headers, redirected.unredirected_hdrs)
            for key, value in mapping.items()
        }
        self.assertNotIn("authorization", headers)
        self.assertNotIn("proxy-authorization", headers)
        self.assertEqual(audit._origin(redirected.full_url), audit.CODELOAD_ORIGIN)

    def test_non_archive_cross_origin_redirect_is_rejected(self) -> None:
        handler = audit.LockedRedirectHandler(allow_codeload=False)
        request = urllib.request.Request(
            "https://api.github.com/repos/szl-holdings/a11oy",
            headers={"Authorization": "Bearer secret-value"},
        )
        with self.assertRaises(audit.AuditError):
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "https://example.com/collect",
            )

    def test_pagination_accepts_one_same_path_next_link(self) -> None:
        value = (
            '<https://api.github.com/orgs/szl-holdings/repos?per_page=100&page=2>; rel="next", '
            '<https://api.github.com/orgs/szl-holdings/repos?per_page=100&page=4>; rel="last"'
        )
        self.assertEqual(
            audit.next_link(value, expected_path="/orgs/szl-holdings/repos"),
            "https://api.github.com/orgs/szl-holdings/repos?per_page=100&page=2",
        )

    def test_pagination_rejects_origin_path_ambiguity_and_cycles_before_network(self) -> None:
        bad_values = (
            '<https://example.com/orgs/szl-holdings/repos?page=2>; rel="next"',
            '<https://api.github.com/users/szl-holdings/repos?page=2>; rel="next"',
            (
                '<https://api.github.com/orgs/szl-holdings/repos?page=2>; rel="next", '
                '<https://api.github.com/orgs/szl-holdings/repos?page=3>; rel="next"'
            ),
            '<https://api.github.com/orgs/szl-holdings/repos?page=2; rel="next"',
        )
        for value in bad_values:
            with self.subTest(value=value), self.assertRaises(audit.AuditError):
                audit.next_link(value, expected_path="/orgs/szl-holdings/repos")

    def test_inventory_minimum_fails_closed_on_repo_local_token_scope(self) -> None:
        with self.assertRaises(audit.AuditError):
            audit.enforce_inventory_minimum([{"full_name": "szl-holdings/only-one"}], 100)
        audit.enforce_inventory_minimum(
            [{"full_name": f"szl-holdings/repo-{index}"} for index in range(100)],
            100,
        )

    def test_repository_inventory_digest_is_order_independent_and_duplicate_strict(self) -> None:
        left = [
            {"full_name": "szl-holdings/a"},
            {"full_name": "szl-holdings/b"},
        ]
        right = list(reversed(left))
        self.assertEqual(
            audit.repository_inventory_digest(left),
            audit.repository_inventory_digest(right),
        )
        with self.assertRaises(audit.AuditError):
            audit.repository_inventory_digest(left + [{"full_name": "SZL-HOLDINGS/A"}])

    @staticmethod
    def _write_receipt(path: Path, index: int, digest: str) -> None:
        path.write_text(
            json.dumps(
                {
                    "shard_index": index,
                    "shard_count": 2,
                    "organization_repository_count": 123,
                    "organization_repository_minimum": 100,
                    "organization_inventory_sha256": digest,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def test_merge_rejects_shards_from_different_organization_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            self._write_receipt(source / "receipt-shard-0.json", 0, "a" * 64)
            self._write_receipt(source / "receipt-shard-1.json", 1, "b" * 64)
            args = Namespace(
                input_dir=str(source),
                output_dir=str(root / "output"),
                shard_count=2,
                org="szl-holdings",
            )
            with self.assertRaises(audit.AuditError):
                audit.merge_shards(args)

    def test_codeload_is_never_accepted_as_a_direct_api_request(self) -> None:
        client = audit.HardenedGitHubClient("test-token", retries=0)
        with self.assertRaises(audit.AuditError):
            client.request(
                "https://codeload.github.com/szl-holdings/a11oy/legacy.tar.gz/"
                + "a" * 40
            )


if __name__ == "__main__":
    unittest.main()
