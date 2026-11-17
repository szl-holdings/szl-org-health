# SPDX-License-Identifier: Apache-2.0
"""Network-free contracts for the read-only, five-pass source evidence graph."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "tools" / "estate_frontier_readback.py"
spec = importlib.util.spec_from_file_location("estate_frontier_readback", SOURCE)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EstateReadbackTests(unittest.TestCase):
    def test_workflow_metadata_not_zero_on_permission_error(self):
        failure = module.summarize_workflows(None, "HTTP_403")
        self.assertEqual(failure["coverage"], "UNAVAILABLE")
        self.assertIsNone(failure["enabled"])
        self.assertIsNone(failure["disabled"])
        self.assertIsNone(failure["total"])

    def test_known_workflow_states_and_pagination(self):
        rows = [{"id": 1, "state": "active"},
                {"id": 2, "state": "disabled_manually"},
                {"id": 3, "state": "disabled_inactivity"},
                {"id": 4, "state": "unknown_future"}]
        observed = module.summarize_workflows({"workflows": rows, "total_count": 4}, None)
        self.assertEqual(observed["coverage"], "COMPLETE")
        self.assertEqual((observed["enabled"], observed["disabled"], observed["unknown_state"]), (1, 2, 1))
        partial = module.summarize_workflows({"workflows": rows, "total_count": 8}, None)
        self.assertEqual(partial["coverage"], "INCOMPLETE")
        self.assertIsNone(partial["total"])

    def test_historical_failed_attempt_not_current_head(self):
        head = "b" * 40
        older = {"head_sha": "a" * 40, "status": "completed", "conclusion": "failure",
                 "name": "tests", "html_url": "https://github.com/owner/repo/actions/runs/1"}
        success = {"head_sha": head, "status": "completed", "conclusion": "success",
                   "name": "tests", "html_url": "https://github.com/owner/repo/actions/runs/2"}
        skipped = {"head_sha": head, "status": "completed", "conclusion": "skipped"}
        result = module.summarize_current_push([older, success, skipped], head)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["success"], 1)
        self.assertEqual(result["skipped_or_neutral_or_cancelled"], 1)
        self.assertEqual(result["required_status"], "UNVERIFIED")
        self.assertEqual(result["release_readiness"], "UNVERIFIED")

    def test_source_roles_are_declarations_not_runtime_proof(self):
        roles = module.source_roles(["pyproject.toml", "src/api.py", "web/src/App.tsx",
                                     "package.json", ".github/workflows/ci.yml"])
        self.assertTrue(roles["python"])
        self.assertTrue(roles["frontend"])
        self.assertTrue(roles["backend"])
        self.assertTrue(roles["node"])
        self.assertTrue(roles["github_actions"])

    def test_private_repos_excluded_and_graph_edges_never_prove_release(self):
        items = [
            {"repository": "szl-holdings/public", "private": False, "visibility": "public",
             "source": {"coverage": "COMPLETE", "roles": {"python": True, "frontend": True}}},
            {"repository": "szl-holdings/private", "private": True, "visibility": "private",
             "source": {"coverage": "COMPLETE", "roles": {"python": True}}},
            {"repository": "szl-holdings/unavailable", "private": False, "visibility": "public",
             "source": {"coverage": "UNAVAILABLE", "roles": None}},
        ]
        graph = module.graph_public(items)
        raw = module.canonical(graph).decode()
        self.assertNotIn("szl-holdings/private", raw)
        self.assertIn("szl-holdings/public", raw)
        self.assertIn("szl-holdings/unavailable", raw)
        self.assertEqual(graph["release_readiness"], "UNVERIFIED")
        self.assertEqual(len(graph["edges"]), 2)
        self.assertTrue(all(e["source_deploy_parity"] == "UNVERIFIED" for e in graph["edges"]))
        self.assertEqual(graph, module.graph_public(list(reversed(items))))

    def test_fixed_links_are_head_only_and_do_not_prove_payment(self):
        observed = []
        def probe(url, method):
            observed.append((url, method))
            return 402 if url.startswith("https://inference.") else 200
        links = module.probe_fixed_links(probe)
        self.assertEqual(len(links), len(module.FIXED_URLS))
        self.assertTrue(all(method == "HEAD" for _, method in observed))
        self.assertEqual(sum(r["http_status"] == 402 for r in links), 1)
        self.assertTrue(all(r["payment_settlement"] == "UNVERIFIED" for r in links))
        self.assertTrue(all(r["release_readiness"] == "UNVERIFIED" for r in links))

    def test_head_405_source_identity_only_get_fallback(self):
        calls = []
        def probe(url, method):
            calls.append((url, method))
            if url.endswith("/.well-known/szl-source.json") and method == "HEAD":
                return 405
            return 402 if url.startswith("https://inference.") else 200
        links = module.probe_fixed_links(probe)
        source = next(x for x in links if x["url"].endswith("/.well-known/szl-source.json"))
        self.assertEqual(source["head_http_status"], 405)
        self.assertEqual(source["method"], "GET")
        self.assertEqual(source["http_status"], 200)
        self.assertEqual([x for x in calls if x[1] == "GET"],
                         [(source["url"], "GET")])
        self.assertEqual(source["release_readiness"], "UNVERIFIED")
        self.assertEqual(source["schema_state"], "UNVERIFIED_TEST_DOUBLE")

    def test_live_rest_budget_preserves_floor_and_unknown(self):
        self.assertEqual(module.capped_budget(1200, 850), 700)
        self.assertEqual(module.capped_budget(6000, 850), 850)
        self.assertEqual(module.capped_budget(250, 850), 0)
        self.assertEqual(module.capped_budget(None, 850), 0)
        self.assertEqual(module.capped_budget(True, 850), 0)

    def test_cli_rejects_external_org_without_network(self):
        read = module.Reader(100)
        report, error = read.get("orgs/foreign-organization")
        self.assertIsNone(report)
        self.assertEqual(error, "UNAPPROVED_READ_PATH")
        self.assertEqual(read.calls, 0)

    def test_live_collection_passes_repository_name_not_record(self):
        class Fake:
            calls = []
            maximum = 20
            errors = {}
            def get(self, path):
                self.calls.append(path)
                if path == "orgs/szl-holdings":
                    return {"login": "szl-holdings", "id": 42}, None
                if path.startswith("organizations/"):
                    return [{"full_name": "szl-holdings/example", "private": False,
                             "visibility": "public", "archived": False,
                             "default_branch": "main"}], None
                if path.startswith("repos/szl-holdings/example/git/trees/"):
                    return {"truncated": False, "tree": [],
                            "sha": "1" * 40}, None
                if path.startswith("repos/szl-holdings/example/actions/workflows?"):
                    return {"workflows": [{"id": 7, "state": "active",
                                           "name": "CI", "path": ".github/workflows/ci.yml"}],
                            "total_count": 1}, None
                raise AssertionError(f"unexpected path: {path}")
        fake = Fake()
        with patch.object(module, "probe_fixed_links", return_value=[]):
            result = module.collect(fake, sample_limit=0)
        self.assertEqual(result["totals"]["workflow_repositories_complete"], 1)
        self.assertEqual(result["totals"]["workflow_enabled_observed"], 1)
        self.assertTrue(any(path.startswith("repos/szl-holdings/example/actions/workflows?")
                            for path in fake.calls))
        self.assertFalse(any(path.startswith("repos/{") for path in fake.calls))

    def test_bad_org_identity_and_page_are_unavailable(self):
        class Fake:
            def get(self, path):
                if path.startswith("orgs/"):
                    return {"login": "foreign", "id": 2}, None
                raise AssertionError("unexpected query")
        rows, complete, error = module.enumerate_repos(Fake())
        self.assertEqual(rows, [])
        self.assertFalse(complete)
        self.assertEqual(error, "ORG_IDENTITY_INVALID")


if __name__ == "__main__":
    unittest.main()
