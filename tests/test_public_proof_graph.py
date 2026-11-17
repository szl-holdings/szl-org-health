# SPDX-License-Identifier: Apache-2.0
"""Closed public evidence-graph and HTTP cache tests (no provider calls)."""
from __future__ import annotations

import copy
import datetime as dt
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import app
from census.proof_graph import SCHEMA, permitted_url, project_proof_graph
from tests.test_portal_projection import fresh_public_report

ROOT = Path(__file__).resolve().parents[1]
SENTINEL = "private-graph-sentinel-99fa8"


class ProofGraphTests(unittest.TestCase):
    def setUp(self):
        self.report = fresh_public_report(dt.datetime.now(dt.UTC).replace(microsecond=0))

    def test_only_public_source_membership_and_explicit_unknown_parity(self):
        graph = project_proof_graph(self.report)
        self.assertEqual(graph["schema"], SCHEMA)
        self.assertEqual(graph["source_scope"], "PUBLIC_SUBSET_ONLY")
        self.assertEqual(graph["cross_provider_parity"], "UNKNOWN")
        self.assertEqual(graph["runtime_readiness"], "UNKNOWN")
        self.assertEqual(graph["model_quality"], "UNKNOWN")
        self.assertEqual(graph["revenue_settlement"], "UNKNOWN")
        self.assertEqual(graph["signature_state"], "UNSIGNED_STRUCTURAL_HASH_ONLY")
        self.assertEqual(len(graph["content_sha256"]), 64)
        self.assertTrue(graph["nodes"])
        self.assertTrue(all(node["runtime_verified"] is False for node in graph["nodes"]))
        self.assertEqual(sum(edge["relation"] == "PARITY_NOT_ESTABLISHED"
                             for edge in graph["edges"]), 3)
        self.assertTrue(all(e["source_deployment_parity"] == "UNKNOWN"
                            for e in graph["edges"]))
        self.assertEqual(graph, project_proof_graph(self.report))

    def test_private_provider_rows_and_injected_urls_are_not_exported(self):
        report = copy.deepcopy(self.report)
        repos = report["sources"]["github"]["data"]["repos"]
        repos[SENTINEL] = {
            "visibility": "private", "private": True, "url": "https://github.com/szl-holdings/" + SENTINEL
        }
        models = report["sources"]["huggingface"]["data"]["assets"]["models"]["items"]
        models.append({"id": "SZLHOLDINGS/" + SENTINEL, "private": True,
                       "url": "https://huggingface.co/SZLHOLDINGS/" + SENTINEL})
        models.append({"id": "SZLHOLDINGS/unrelated-asset", "private": False,
                       "url": "https://huggingface.co/SZLHOLDINGS/wrong-asset"})
        result = json.dumps(project_proof_graph(report), sort_keys=True)
        self.assertNotIn(SENTINEL, result)
        self.assertNotIn("unrelated-asset", result)
        self.assertIn("PUBLIC_SUBSET_ONLY", result)

    def test_invalid_internal_report_and_untrusted_urls_refused(self):
        internal = copy.deepcopy(self.report)
        internal["exposure"] = "internal"
        with self.assertRaises(ValueError):
            project_proof_graph(internal)
        for url in ("http://huggingface.co/SZLHOLDINGS/foo",
                    "https://huggingface.co:123/SZLHOLDINGS/foo",
                    "https://user:pass@huggingface.co/SZLHOLDINGS/foo",
                    "https://huggingface.co/SZLHOLDINGS/foo?token=secret",
                    "https://huggingface.co:99999/SZLHOLDINGS/foo",
                    "https://evil.example/SZLHOLDINGS/foo"):
            self.assertFalse(permitted_url(url, "huggingface.co"), url)

    def test_public_response_cache_adds_graph_without_extra_collector_call(self):
        cache = app.PublicResponses()
        observed = []
        def source(**kwargs):
            observed.append(kwargs)
            return self.report
        with patch.object(app, "build_report", side_effect=source):
            cache._refresh()
        self.assertEqual(len(observed), 1)
        graph = json.loads(cache.get("/api/proof-graph"))
        health = json.loads(cache.get("/api/health"))
        portal = json.loads(cache.get("/api/portal"))
        self.assertEqual(graph["schema"], SCHEMA)
        self.assertEqual(portal["schema"], "szl.portal-evidence-index/v1")
        self.assertEqual(health["projection_schema"], "szl.estate-public-projection/v1")
        self.assertEqual(len(observed), 1)

    def test_static_viewer_self_hosted_with_no_provider_inference(self):
        html = (ROOT / "static" / "proof-graph.html").read_text(encoding="utf-8")
        self.assertIn("'/api/proof-graph'", html)
        self.assertNotIn("<script src=", html)
        self.assertNotIn("fetch('https://", html)
        self.assertIn("No privileged reads", html)
        self.assertIn("Runtime, deployment and settlement unverified", html)


if __name__ == "__main__":
    unittest.main()
