# SPDX-License-Identifier: Apache-2.0
"""Offline contracts for the official open-source frontier radar."""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "census" / "frontier_radar.py"
SPEC = importlib.util.spec_from_file_location("szl_frontier_radar_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
radar = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = radar
SPEC.loader.exec_module(radar)


class FakeClient:
    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, bool]] = []

    def get(self, path: str, *, allow_404: bool = False) -> Any:
        self.calls.append((path, allow_404))
        if path not in self.responses:
            if allow_404:
                return None
            raise AssertionError(f"unexpected API call: {path}")
        value = self.responses[path]
        if isinstance(value, Exception):
            raise value
        return value


class FrontierRadarContracts(unittest.TestCase):
    NOW = dt.datetime(2026, 9, 6, tzinfo=dt.timezone.utc)

    def test_allowlist_is_unique_official_and_category_bounded(self) -> None:
        repositories = [upstream.repository for upstream in radar.UPSTREAMS]
        capabilities = [upstream.capability for upstream in radar.UPSTREAMS]
        self.assertEqual(len(repositories), len(set(repository.lower() for repository in repositories)))
        self.assertTrue(all(repository.count("/") == 1 for repository in repositories))
        self.assertTrue(all(upstream.category in radar.CATEGORY_PRIORITY for upstream in radar.UPSTREAMS))
        self.assertTrue(all(capability and "." in capability for capability in capabilities))
        self.assertGreaterEqual(len(repositories), 40)

    def test_annotated_release_tag_is_dereferenced_to_exact_commit(self) -> None:
        tag_object = "a" * 40
        commit = "b" * 40
        client = FakeClient(
            {
                "/repos/example/project/git/ref/tags/v1.2.3": {
                    "object": {"type": "tag", "sha": tag_object}
                },
                f"/repos/example/project/git/tags/{tag_object}": {
                    "object": {"type": "commit", "sha": commit}
                },
            }
        )
        observed, error = radar._deref_tag(client, "example/project", "v1.2.3")
        self.assertEqual(observed, commit)
        self.assertIsNone(error)

    def test_lightweight_release_tag_resolves_without_inventing_annotation(self) -> None:
        commit = "c" * 40
        client = FakeClient(
            {
                "/repos/example/project/git/ref/tags/release%2F1": {
                    "object": {"type": "commit", "sha": commit}
                }
            }
        )
        observed, error = radar._deref_tag(client, "example/project", "release/1")
        self.assertEqual(observed, commit)
        self.assertIsNone(error)
        self.assertEqual(len(client.calls), 1)

    def test_permissive_current_release_is_candidate_not_install_claim(self) -> None:
        commit = "d" * 40
        client = FakeClient(
            {
                "/repos/example/project": {
                    "default_branch": "main",
                    "pushed_at": "2026-09-05T00:00:00Z",
                    "archived": False,
                    "disabled": False,
                    "fork": False,
                    "stargazers_count": 123,
                    "license": {"spdx_id": "Apache-2.0"},
                },
                "/repos/example/project/releases/latest": {
                    "tag_name": "v1.2.3",
                    "html_url": "https://github.com/example/project/releases/tag/v1.2.3",
                    "published_at": "2026-09-04T00:00:00Z",
                    "prerelease": False,
                    "draft": False,
                },
                "/repos/example/project/git/ref/tags/v1.2.3": {
                    "object": {"type": "commit", "sha": commit}
                },
            }
        )
        upstream = radar.Upstream(
            repository="example/project",
            category="serving",
            capability="inference.example",
            role="example inference",
            deployment_boundary="inference-plane",
        )
        row = radar.resolve_upstream(client, upstream, self.NOW)
        self.assertEqual(row["state"], "ADOPT_CANDIDATE")
        self.assertEqual(row["release"]["commit_sha"], commit)
        self.assertEqual(row["license"]["state"], "PERMISSIVE_REVIEWABLE")
        self.assertEqual(row["maintenance"]["state"], "ACTIVE_OBSERVED")
        self.assertEqual(row["blockers"], [])
        self.assertNotIn("installed", json.dumps(row).lower())

    def test_archived_or_unknown_license_never_becomes_candidate(self) -> None:
        commit = "e" * 40
        client = FakeClient(
            {
                "/repos/example/project": {
                    "default_branch": "main",
                    "pushed_at": "2026-09-05T00:00:00Z",
                    "archived": True,
                    "disabled": False,
                    "fork": False,
                    "stargazers_count": 1,
                    "license": {"spdx_id": "NOASSERTION"},
                },
                "/repos/example/project/releases/latest": {
                    "tag_name": "v1",
                    "published_at": "2026-09-04T00:00:00Z",
                    "prerelease": False,
                    "draft": False,
                },
                "/repos/example/project/git/ref/tags/v1": {
                    "object": {"type": "commit", "sha": commit}
                },
            }
        )
        upstream = radar.Upstream(
            repository="example/project",
            category="evaluation",
            capability="evaluation.example",
            role="example evaluation",
            deployment_boundary="evaluation-plane",
        )
        row = radar.resolve_upstream(client, upstream, self.NOW)
        self.assertEqual(row["state"], "REVIEW_REQUIRED")
        self.assertEqual(row["maintenance"]["state"], "ARCHIVED")
        self.assertEqual(row["license"]["state"], "UNKNOWN")
        self.assertIn("upstream archived or disabled", row["blockers"])
        self.assertIn("license evidence unavailable", row["blockers"])

    def test_copyleft_license_is_visible_and_requires_use_specific_review(self) -> None:
        self.assertEqual(radar._license_state("AGPL-3.0"), "LEGAL_REVIEW_REQUIRED")
        self.assertEqual(radar._license_state("GPL-3.0-only"), "LEGAL_REVIEW_REQUIRED")
        self.assertEqual(radar._license_state("MIT"), "PERMISSIVE_REVIEWABLE")
        self.assertEqual(radar._license_state(None), "UNKNOWN")

    def test_estate_presence_prioritizes_missing_capability_without_overclaim(self) -> None:
        rows = [
            {"category": "serving", "capability": "inference.vllm"},
            {"category": "observability", "capability": "observability.opentelemetry"},
        ]
        radar.apply_estate_presence(
            rows,
            {"observability.opentelemetry": ["szl-holdings/szl-telemetry"]},
        )
        self.assertEqual(rows[0]["estate_presence"]["state"], "NOT_OBSERVED")
        self.assertEqual(rows[1]["estate_presence"]["state"], "OBSERVED")
        self.assertLess(rows[0]["priority"], rows[1]["priority"])

    def test_malformed_technology_index_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "technology.json"
            path.write_text('{"technologies":{"inference.vllm":"not-a-list"}}', encoding="utf-8")
            with self.assertRaises(radar.RadarError):
                radar.load_technology_index(path)

    def test_markdown_keeps_candidate_and_production_claims_separate(self) -> None:
        payload = {
            "state": "REVIEW_READY",
            "summary": {
                "resolved": 1,
                "total": 1,
                "adopt_candidates": 1,
                "review_required": 0,
                "not_observed": 1,
            },
            "upstreams": [
                {
                    "priority": 10,
                    "capability": "security.sigstore",
                    "repository": "sigstore/cosign",
                    "release": {"tag": "v3.0.0", "commit_sha": "f" * 40},
                    "license": {"spdx": "Apache-2.0"},
                    "estate_presence": {"state": "NOT_OBSERVED"},
                    "state": "ADOPT_CANDIDATE",
                }
            ],
        }
        rendered = radar.render_markdown(payload)
        self.assertIn("Candidate does not mean installed", rendered)
        self.assertIn("pin the exact release commit or package digest", rendered)
        self.assertIn("never performs that mutation itself", rendered)

    def test_canonical_json_is_stable_and_rejects_nan(self) -> None:
        self.assertEqual(
            radar.canonical_json_bytes({"b": 2, "a": 1}),
            b'{"a":1,"b":2}',
        )
        with self.assertRaises(ValueError):
            radar.canonical_json_bytes({"bad": float("nan")})


if __name__ == "__main__":
    unittest.main()
