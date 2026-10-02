"""Public Space readiness never substitutes reachability for product authority."""

import unittest
from unittest.mock import patch

from census.huggingface import normalize_space
from census.report import _public_hf_item
from census.space_readiness import collect_space_readiness


ROOT = "https://szlholdings-example.hf.space/"
HUB_SHA = "a" * 40
SOURCE_SHA = "b" * 40


def item(name, *, sdk="docker", stage="RUNNING", hub_sha=HUB_SHA, runtime_sha=HUB_SHA):
    return {
        "id": f"SZLHOLDINGS/{name}",
        "private": False,
        "sdk": sdk,
        "sha": hub_sha,
        "runtime": {"stage": stage, "sha": runtime_sha},
    }


class SpaceReadinessTests(unittest.TestCase):
    @patch("census.space_readiness.request_json")
    def test_a11oy_old_runtime_200_during_new_head_is_transitioning(self, request_json):
        space = item(
            "a11oy", stage="RUNNING_APP_STARTING", hub_sha="c" * 40,
            runtime_sha=HUB_SHA,
        )
        result = collect_space_readiness(space, ROOT, {})
        self.assertEqual(result["readiness_state"], "TRANSITIONING")
        self.assertEqual(result["readiness_reason"], "HUB_RUNTIME_REVISION_MISMATCH")
        self.assertIsNone(result["readiness_http"])
        request_json.assert_not_called()

    @patch("census.space_readiness.request_json")
    def test_a11oy_aligned_head_preserves_source_verification_gap(self, request_json):
        request_json.side_effect = [
            ({"status": "ready", "organ": "a11oy"}, {}, None),
            ({"git_sha": SOURCE_SHA}, {}, None),
        ]
        result = collect_space_readiness(item("a11oy"), ROOT, {
            "source_binding_state": "UNKNOWN", "source_revision": SOURCE_SHA,
        })
        self.assertEqual(result["readiness_state"], "SCOPED_READY_SOURCE_UNVERIFIED")
        self.assertEqual(result["readiness_scope"], "SERVING_PROCESS")
        self.assertIsNone(result["production_ready_declared"])
        self.assertEqual(result["readiness_http"], 200)
        self.assertEqual(request_json.call_count, 2)

    @patch("census.space_readiness.request_json")
    def test_a11oy_contradictory_source_is_not_ready(self, request_json):
        request_json.side_effect = [
            ({"status": "ready", "organ": "a11oy"}, {}, None),
            ({"git_sha": SOURCE_SHA}, {}, None),
        ]
        result = collect_space_readiness(item("a11oy"), ROOT, {
            "source_binding_state": "OBSERVED", "source_revision": "c" * 40,
        })
        self.assertEqual(result["readiness_state"], "SOURCE_CONFLICT")

    @patch("census.space_readiness.request_json")
    def test_immune_lattice_running_health_does_not_mask_readyz_503(self, request_json):
        request_json.return_value = (None, {}, "http503")
        result = collect_space_readiness(item("immune-lattice"), ROOT, {})
        self.assertEqual(result["readiness_state"], "NOT_READY")
        self.assertEqual(result["readiness_http"], 503)
        self.assertEqual(result["readiness_scope"], "ACTION_AUTHORITY")

    @patch("census.space_readiness.request_json")
    def test_immune_lattice_http_200_with_false_authority_is_not_ready(self, request_json):
        request_json.return_value = ({
            "schema": "szl.immune-readiness/v1", "status": "READY", "ready": True,
            "runtime_ready": True, "read_ready": True,
            "authority_ready": False, "write_ready": True,
        }, {}, None)
        result = collect_space_readiness(item("immune-lattice"), ROOT, {})
        self.assertEqual(result["readiness_state"], "NOT_READY")

    @patch("census.space_readiness.request_json")
    def test_frontier_operator_200_with_production_hold_and_drift(self, request_json):
        request_json.side_effect = [
            ({
                "schema": "szl.frontier.readiness/v1", "ready": True,
                "productionReady": False, "productionAuthorization": False,
            }, {}, None),
            ({
                "schema": "szl.frontier.source-identity/v1", "headMatch": "DRIFT",
                "productionAuthorization": False, "runtimeVerified": False,
            }, {}, None),
        ]
        result = collect_space_readiness(item("szl-frontier"), ROOT, {})
        self.assertEqual(result["readiness_state"], "PRODUCTION_HOLD")
        self.assertEqual(result["readiness_scope"], "OPERATOR_PLANE")
        self.assertEqual(result["declared_head_match"], "DRIFT")
        self.assertIs(result["production_ready_declared"], False)
        self.assertEqual(result["readiness_http"], 200)

    @patch("census.space_readiness.request_json")
    def test_frontier_operator_not_ready_outranks_production_hold(self, request_json):
        request_json.side_effect = [
            ({
                "schema": "szl.frontier.readiness/v1", "ready": False,
                "productionReady": False, "productionAuthorization": False,
            }, {}, None),
            ({
                "schema": "szl.frontier.source-identity/v1", "headMatch": "DRIFT",
                "productionAuthorization": False, "runtimeVerified": False,
            }, {}, None),
        ]
        result = collect_space_readiness(item("szl-frontier"), ROOT, {})
        self.assertEqual(result["readiness_state"], "NOT_READY")

    @patch("census.space_readiness.request_json")
    def test_frontier_unhashable_head_match_is_unknown(self, request_json):
        for head_match in ([], {}):
            with self.subTest(head_match=head_match):
                request_json.side_effect = [
                    ({
                        "schema": "szl.frontier.readiness/v1", "ready": True,
                        "productionReady": False, "productionAuthorization": False,
                    }, {}, None),
                    ({
                        "schema": "szl.frontier.source-identity/v1",
                        "headMatch": head_match, "productionAuthorization": False,
                        "runtimeVerified": False,
                    }, {}, None),
                ]
                result = collect_space_readiness(item("szl-frontier"), ROOT, {})
                self.assertEqual(result["readiness_state"], "UNKNOWN")
                self.assertEqual(result["readiness_reason"], "SOURCE_HEAD_MATCH_INVALID")

    @patch("census.space_readiness.request_bytes")
    def test_brand_campaign_stock_page_is_placeholder_even_with_http_200(self, request_bytes):
        request_bytes.return_value = (
            b"<title>My static Space</title><h1>Welcome to your static Space!</h1>",
            {}, None,
        )
        result = collect_space_readiness(item("szl-brand-campaign", sdk="static"), ROOT, {})
        self.assertEqual(result["readiness_state"], "PLACEHOLDER")
        self.assertEqual(result["readiness_http"], 200)
        self.assertEqual(result["readiness_scope"], "STATIC_CONTENT")

    @patch("census.space_readiness.request_json")
    @patch("census.space_readiness.request_bytes")
    def test_private_and_unlisted_spaces_are_not_probed(self, request_bytes, request_json):
        private = item("a11oy")
        private["private"] = True
        self.assertEqual(
            collect_space_readiness(private, ROOT, {})["readiness_state"],
            "NOT_EVALUATED",
        )
        self.assertEqual(
            collect_space_readiness(item("other"), ROOT, {})["readiness_state"],
            "NOT_EVALUATED",
        )
        request_bytes.assert_not_called()
        request_json.assert_not_called()

    @patch("census.space_readiness.request_json")
    @patch("census.space_readiness.request_bytes")
    def test_unhashable_id_or_stage_fails_closed_without_network(self, request_bytes, request_json):
        for invalid in ([], {}, 42):
            with self.subTest(field="id", value=invalid):
                space = item("a11oy")
                space["id"] = invalid
                result = collect_space_readiness(space, ROOT, {})
                self.assertEqual(result["readiness_state"], "NOT_EVALUATED")
            with self.subTest(field="stage", value=invalid):
                space = item("a11oy")
                space["runtime"]["stage"] = invalid
                result = collect_space_readiness(space, ROOT, {})
                self.assertEqual(result["readiness_state"], "UNKNOWN")
        request_bytes.assert_not_called()
        request_json.assert_not_called()

    @patch("census.huggingface.collect_space_readiness")
    @patch("census.huggingface._resolve_space_source_binding")
    @patch("census.huggingface.http_probe")
    def test_normalization_keeps_readiness_separate_from_operational_state(
        self, http_probe, source_binding, readiness,
    ):
        http_probe.side_effect = [{"http": 200}, {"http": 200}]
        source_binding.return_value = {
            "source_binding_state": "UNKNOWN", "source_revision": None,
        }
        readiness.return_value = {
            "readiness_state": "NOT_READY", "readiness_scope": "ACTION_AUTHORITY",
            "readiness_route": "/readyz", "readiness_http": 503,
        }
        space = item("immune-lattice")
        space["subdomain"] = "szlholdings-immune-lattice"
        normalized = normalize_space(space)
        self.assertEqual(normalized["stage"], "RUNNING")
        self.assertEqual(normalized["healthz"], 200)
        self.assertEqual(normalized["operational_state"], "RUNTIME_HEALTHY_UNBOUND")
        self.assertEqual(normalized["readiness_state"], "NOT_READY")
        self.assertEqual(normalized["runtime_revision"], HUB_SHA)

    def test_closed_public_projection_drops_private_and_untrusted_readiness(self):
        space = item("szl-frontier")
        space.update({
            "readiness_state": "PRODUCTION_HOLD",
            "readiness_scope": "OPERATOR_PLANE",
            "readiness_route": "/api/ready",
            "readiness_http": 200,
            "production_ready_declared": False,
            "declared_head_match": "DRIFT",
            "runtime_revision": HUB_SHA,
            "readiness_reason": "private diagnostic not for publication",
        })
        projected = _public_hf_item(space, "spaces")
        self.assertEqual(projected["readiness_state"], "PRODUCTION_HOLD")
        self.assertEqual(projected["declared_head_match"], "DRIFT")
        self.assertIs(projected["production_ready_declared"], False)
        self.assertNotIn("readiness_reason", projected)
        space["private"] = True
        self.assertIsNone(_public_hf_item(space, "spaces"))
        space["private"] = False
        space["readiness_state"] = {"private": "sentinel"}
        space["readiness_scope"] = "PRIVATE_SENTINEL"
        space["declared_head_match"] = "PRIVATE_SENTINEL"
        space["runtime_revision"] = "PRIVATE_SENTINEL"
        projected = _public_hf_item(space, "spaces")
        for field in ("readiness_state", "readiness_scope", "declared_head_match", "runtime_revision"):
            self.assertNotIn(field, projected)


if __name__ == "__main__":
    unittest.main()
