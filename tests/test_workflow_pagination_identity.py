# SPDX-License-Identifier: Apache-2.0
"""Offline regression: paginated workflow counts cannot admit duplicate identities."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("estate_frontier_readback", ROOT / "tools" / "estate_frontier_readback.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

class WorkflowIdentityTests(unittest.TestCase):
    def test_unique_workflows_admitted(self):
        rows = [{"id": 11, "state": "active"}, {"id": 12, "state": "disabled_manually"}]
        observed = mod.summarize_workflows({"workflows": rows, "total_count": 2}, None)
        self.assertEqual(observed["coverage"], "COMPLETE")
        self.assertEqual(observed["total"], 2)

    def test_duplicate_ids_in_single_page_fail_closed(self):
        rows = [{"id": 11, "state": "active"}, {"id": 11, "state": "disabled_manually"}]
        observed = mod.summarize_workflows({"workflows": rows, "total_count": 2}, None)
        self.assertNotEqual(observed["coverage"], "COMPLETE")
        self.assertIsNone(observed["total"])

    def test_overlapping_pagination_cannot_claim_complete(self):
        class Reader:
            def get(self, path):
                if path.endswith("page=1"):
                    return {"workflows": [{"id": i, "state": "active"} for i in range(1, 101)],
                            "total_count": 101}, None
                return {"workflows": [{"id": 100, "state": "active"}], "total_count": 101}, None
        observed = mod.fetch_workflows(Reader(), "szl-holdings/test-public")
        self.assertNotEqual(observed["coverage"], "COMPLETE")
        self.assertIsNone(observed["total"])

    def test_missing_or_invalid_identity_fails_closed(self):
        for bad in ({"state": "active"}, {"id": None, "state": "active"},
                    {"id": True, "state": "active"}, {"id": "12", "state": "active"},
                    {"id": 0, "state": "active"}, "not-an-object"):
            with self.subTest(bad=bad):
                observed = mod.summarize_workflows({"workflows": [bad], "total_count": 1}, None)
                self.assertNotEqual(observed["coverage"], "COMPLETE")
                self.assertIsNone(observed["total"])

if __name__ == "__main__":
    unittest.main()
