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
    def test_failed_paused_sleeping_stages_outweigh_sha_drift(self, request_json):
        for stage in ("RUNTIME_ERROR", "BUILD_ERROR", "CONFIG_ERROR", "PAUSED", "SLEEPING", "STOPPED"):
            with self.subTest(stage=stage):
                space = item("a11oy", stage=stage, hub_sha="c" * 40, runtime_sha=HUB_SHA)
                result = collect_space_readiness(space, ROOT, {})
                self.assertEqual(result["readiness_state"], "NOT_READY")
                self.assertEqual(result["readiness_reason"], "PROVIDER_NOT_RUNNING")
                self.assertIsNone(result["readiness_http"])
        request_json.assert_not_called()

    @patch("census.space_readiness.request_json")
    def test_running_sha_drift_stays_transitioning(self, request_json):
        space = item("a11oy", stage="RUNNING", hub_sha="c" * 40, runtime_sha=HUB_SHA)
        result = collect_space_readiness(space, ROOT, {})
        self.assertEqual(result["readiness_state"], "TRANSITIONING")
        self.assertEqual(result["readiness_reason"], "HUB_RUNTIME_REVISION_MISMATCH")
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

    @patch("census.space_readiness.request_json")
    def test_second_brain_only_public_retrieval_not_inference(self, request_json):
        request_json.return_value = ({
            "schema": "szl.second-brain.readiness/v1",
            "ready": True, "state": "READY",
            "scope": "PUBLIC_RETRIEVAL_AND_REVIEW",
            "runtime_mode": "BM25_ONLY",
            "model_generation": "NOT_CONFIGURED",
            "execution_authority": "NONE",
        }, {}, None)
        result = collect_space_readiness(item("szl-second-brain"), ROOT, {})
        self.assertEqual(result["readiness_state"], "SCOPED_READY_UNVERIFIED")
        self.assertEqual(result["readiness_scope"], "PUBLIC_RETRIEVAL_REVIEW")
        self.assertEqual(result["readiness_http"], 200)
        self.assertIn("NO_MODEL_INFERENCE", result["readiness_reason"])

    @patch("census.space_readiness.request_json")
    def test_second_brain_503_and_bogus_200_never_green(self, request_json):
        request_json.return_value = (None, {}, "http503")
        result = collect_space_readiness(item("szl-second-brain"), ROOT, {})
        self.assertEqual((result["readiness_state"], result["readiness_http"]), ("NOT_READY", 503))
        request_json.return_value = ({
            "schema": "szl.second-brain.readiness/v1", "ready": True,
            "state": "READY", "scope": "PUBLIC_RETRIEVAL_AND_REVIEW",
            "runtime_mode": "BM25_ONLY", "execution_authority": "NONE",
            "model_generation": "ENABLED",
        }, {}, None)
        result = collect_space_readiness(item("szl-second-brain"), ROOT, {})
        self.assertEqual(result["readiness_state"], "UNKNOWN")
        self.assertEqual(result["readiness_reason"], "RETRIEVAL_SCOPE_CHANGED")

    @staticmethod
    def _anatomy_fixtures():
        status = {
            "schema": "szl.anatomy.frontier-status/v1",
            "ready": True, "state": "SOURCE_BOUND_REVIEW_MEMORY",
            "candidate_count": 144, "candidate_set_sha256": "f" * 64,
            "second_brain_source_repository": "szl-holdings/szl-second-brain",
            "second_brain_source_revision": SOURCE_SHA, "content_access": "HANDLES_ONLY",
            "execution_authority": "NONE", "promotion_authority": "NONE",
            "training_authority": "NONE", "raw_graph_nodes_admitted_to_gradients": 0,
            "private_graph_present": False,
        }
        return status, {
            "schema": "szl.anatomy.holographic-v7/v1",
            "ready": True, "state": "SOURCE_BOUND_READ_ONLY", "frontier": dict(status),
        }

    @patch("census.space_readiness.request_json")
    def test_anatomy_feed_ready_is_renderer_and_signature_unverified(self, request_json):
        status, holo = self._anatomy_fixtures()
        request_json.side_effect = [(status, {}, None), (holo, {}, None)]
        result = collect_space_readiness(item("anatomy"), ROOT, {})
        self.assertEqual(result["readiness_state"], "SCOPED_READY_UNVERIFIED")
        self.assertEqual(result["readiness_scope"], "SOURCE_FEED")
        self.assertEqual(result["readiness_route"], "/api/anatomy/v1/frontier/status")
        self.assertIn("WEBGL_AND_SIGNATURE_UNVERIFIED", result["readiness_reason"])
        self.assertEqual(request_json.call_count, 2)

    @patch("census.space_readiness.request_json")
    def test_anatomy_conflicting_source_200_is_not_ready(self, request_json):
        status, holo = self._anatomy_fixtures()
        holo["frontier"]["second_brain_source_revision"] = "c" * 40
        request_json.side_effect = [(status, {}, None), (holo, {}, None)]
        result = collect_space_readiness(item("anatomy"), ROOT, {})
        self.assertEqual(result["readiness_state"], "SOURCE_CONFLICT")

    @patch("census.space_readiness.request_json")
    def test_anatomy_one_optional_feed_down_not_3d_green(self, request_json):
        status, _ = self._anatomy_fixtures()
        request_json.side_effect = [(status, {}, None), (None, {}, "http503")]
        result = collect_space_readiness(item("anatomy"), ROOT, {})
        self.assertEqual(result["readiness_state"], "NOT_READY")
        self.assertEqual(result["readiness_http"], 503)

    @patch("census.space_readiness.request_json")
    def test_anatomy_200_but_unready_status_is_not_green(self, request_json):
        status, _ = self._anatomy_fixtures()
        status["ready"] = False
        request_json.return_value = (status, {}, None)
        result = collect_space_readiness(item("anatomy"), ROOT, {})
        self.assertEqual(result["readiness_state"], "NOT_READY")
        request_json.assert_called_once()

    @patch("census.space_readiness.request_json")
    def test_anatomy_candidate_set_invalid_or_malformed_is_not_green(self, request_json):
        for key, invalid in (("candidate_set_sha256", "bad"), ("candidate_count", True)):
            with self.subTest(key=key):
                status, holo = self._anatomy_fixtures()
                status[key] = invalid
                holo["frontier"][key] = invalid
                request_json.side_effect = [(status, {}, None), (holo, {}, None)]
                result = collect_space_readiness(item("anatomy"), ROOT, {})
                self.assertEqual(result["readiness_state"], "UNKNOWN")
                request_json.side_effect = None

    @patch("census.space_readiness.request_json")
    def test_anatomy_training_authority_drift_is_not_green(self, request_json):
        status, holo = self._anatomy_fixtures()
        status["training_authority"] = holo["frontier"]["training_authority"] = "ENABLED"
        request_json.side_effect = [(status, {}, None), (holo, {}, None)]
        result = collect_space_readiness(item("anatomy"), ROOT, {})
        self.assertEqual(result["readiness_state"], "NOT_READY")

    @patch("census.space_readiness.request_json")
    def test_router_control_inference_503_is_explicitly_not_configured(self, request_json):
        request_json.return_value = (None, {}, "http503")
        result = collect_space_readiness(item("szl-router-control"), ROOT, {})
        self.assertEqual(result["readiness_state"], "NOT_READY")
        self.assertEqual(result["readiness_scope"], "INFERENCE_CONFIGURATION")
        self.assertEqual(result["readiness_http"], 503)
        self.assertIn("DEFAULT_DENY", result["readiness_reason"])

    @patch("census.space_readiness.request_json")
    def test_router_control_even_configured_200_is_not_signed_inference(self, request_json):
        payload = {
            "status": "ready", "ready_for_requests": True,
            "checks": {"registry_valid": True, "egress_enabled": True,
                       "caller_auth_configured": True, "provider_configured": True},
            "model_identity": "CONFIGURED",
        }
        request_json.return_value = (payload, {}, None)
        result = collect_space_readiness(item("szl-router-control"), ROOT, {})
        self.assertEqual(result["readiness_state"], "SCOPED_READY_UNVERIFIED")
        self.assertIn("SIGNATURE_UNVERIFIED", result["readiness_reason"])
        payload["checks"]["provider_configured"] = False
        result = collect_space_readiness(item("szl-router-control"), ROOT, {})
        self.assertEqual(result["readiness_state"], "UNKNOWN")

    @patch("census.space_readiness.request_json")
    def test_router_control_rejects_malformed_model_identity(self, request_json):
        payload = {
            "status": "ready", "ready_for_requests": True,
            "checks": {"registry_valid": True, "egress_enabled": True,
                       "caller_auth_configured": True, "provider_configured": True},
        }
        for identity in ("", [], {}):
            with self.subTest(identity=identity):
                payload["model_identity"] = identity
                request_json.return_value = (payload, {}, None)
                result = collect_space_readiness(item("szl-router-control"), ROOT, {})
                self.assertEqual(result["readiness_state"], "UNKNOWN")
                self.assertIn("EVIDENCE_INCOMPLETE", result["readiness_reason"])

    def test_extended_public_projection_preserves_scoped_routes_without_operational_claim(self):
        for name, scope, route in (
            ("anatomy", "SOURCE_FEED", "/api/anatomy/v1/frontier/status"),
            ("szl-router-control", "INFERENCE_CONFIGURATION", "/readyz/inference"),
            ("szl-second-brain", "PUBLIC_RETRIEVAL_REVIEW", "/readyz"),
        ):
            with self.subTest(name=name):
                row = item(name)
                row.update({"readiness_scope": scope, "readiness_route": route,
                            "readiness_state": "SCOPED_READY_UNVERIFIED",
                            "readiness_http": 200})
                projected = _public_hf_item(row, "spaces")
                self.assertEqual(projected["readiness_scope"], scope)
                self.assertEqual(projected["readiness_route"], route)
                self.assertEqual(projected["readiness_state"], "SCOPED_READY_UNVERIFIED")

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
