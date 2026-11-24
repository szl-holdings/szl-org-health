"""Census integration tests for fixed public router and Anatomy surfaces."""

import unittest
from unittest.mock import patch

from census.space_readiness import _critical_vertical, _json, collect_space_readiness
from test_vertical_contracts import HUB, GITHUB, evidence_fixture, router_fixture, version_fixture


def space(name, stage="RUNNING", private=False):
    return {
        "id": f"SZLHOLDINGS/{name}", "private": private, "sha": HUB,
        "runtime": {"stage": stage, "sha": HUB},
    }


class VerticalSpaceReadinessWiringTests(unittest.TestCase):
    @patch("census.space_readiness.request_json")
    def test_router_control_503_distinct_from_running(self, request_json):
        request_json.return_value = (None, {}, "http503")
        result = collect_space_readiness(
            space("szl-router-control"),
            "https://szlholdings-szl-router-control.hf.space/", {},
        )
        self.assertEqual(result["readiness_state"], "NOT_READY")
        self.assertEqual(result["readiness_http"], 503)
        self.assertEqual(result["readiness_scope"], "INFERENCE_CONFIGURATION")
        self.assertEqual(request_json.call_count, 1)

    @patch("census.space_readiness.request_json")
    def test_router_status_surface_never_qualifies_live_inference(self, request_json):
        request_json.return_value = (router_fixture(), {}, None)
        result = collect_space_readiness(
            space("llm-router-live"), "https://szlholdings-llm-router-live.hf.space/", {},
        )
        self.assertEqual(result["readiness_state"], "UNKNOWN")
        self.assertEqual(result["readiness_scope"], "PUBLIC_ROUTER_STATUS")

    @patch("census.space_readiness.request_json")
    def test_anatomy_partial_unsigned_remains_production_hold(self, request_json):
        request_json.side_effect = [
            (version_fixture(), {}, None), (evidence_fixture(), {}, None),
        ]
        result = collect_space_readiness(
            space("anatomy"), "https://szlholdings-anatomy.hf.space/",
            {"source_binding_state": "OBSERVED", "source_revision": GITHUB},
        )
        self.assertEqual(result["readiness_state"], "PRODUCTION_HOLD")
        self.assertEqual(result["readiness_scope"], "RELEASE_EVIDENCE")
        self.assertEqual(request_json.call_count, 2)

    @patch("census.space_readiness.request_json")
    def test_unapproved_origin_never_probed(self, request_json):
        for url in (
            "https://unapproved.example/", "https://szlholdings-anatomy.hf.space@evil.example/",
            "https://szlholdings-anatomy.hf.space:444/",
            "https://szlholdings-anatomy.hf.space/redirect",
        ):
            with self.subTest(url=url):
                result = collect_space_readiness(space("anatomy"), url, {})
                self.assertEqual(result["readiness_state"], "UNKNOWN")
                self.assertEqual(result["readiness_reason"], "RUNTIME_ORIGIN_MISMATCH")
        request_json.assert_not_called()

    @patch("census.space_readiness.request_json")
    def test_critical_gets_pin_redirect_origin_and_exact_path(self, request_json):
        request_json.side_effect = [
            (version_fixture(), {}, None), (evidence_fixture(), {}, None),
        ]
        collect_space_readiness(
            space("anatomy"), "https://szlholdings-anatomy.hf.space/",
            {"source_binding_state": "OBSERVED", "source_revision": GITHUB},
        )
        calls = request_json.call_args_list
        self.assertEqual(len(calls), 2)
        for call, path in zip(calls, ("/version", "/evidence")):
            self.assertEqual(
                call.kwargs["redirect_origin"],
                ("https", "szlholdings-anatomy.hf.space", 443),
            )
            self.assertEqual(call.kwargs["redirect_path"], path)
        self.assertEqual(calls[0].kwargs["max_bytes"], 8192)
        self.assertEqual(calls[1].kwargs["max_bytes"], 32768)

    @patch("census.space_readiness.request_json")
    def test_public_status_503_is_not_mislabeled_as_gateway_inference(self, request_json):
        request_json.return_value = (None, {}, "http503")
        result = collect_space_readiness(
            space("llm-router-live"), "https://szlholdings-llm-router-live.hf.space/", {},
        )
        self.assertEqual(result["readiness_http"], 503)
        self.assertEqual(result["readiness_state"], "UNKNOWN")
        self.assertEqual(result["readiness_reason"], "PUBLIC_STATUS_NOT_AN_INFERENCE_GATEWAY")
        self.assertEqual(request_json.call_count, 1)

    @patch("census.space_readiness.request_json")
    def test_route_override_denied_without_network(self, request_json):
        origin = "https://szlholdings-anatomy.hf.space/"
        for route in ("https://unapproved.example/evidence", "http://unapproved.example/evidence",
                      "//unapproved.example/evidence", "/wrong", "/evidence?redirect=1"):
            with self.subTest(route=route):
                result = _critical_vertical(
                    origin, "SZLHOLDINGS/anatomy", route, "RELEASE_EVIDENCE",
                    space("anatomy"), {},
                )
                self.assertEqual(result["readiness_state"], "UNKNOWN")
                self.assertEqual(result["readiness_reason"], "VERTICAL_CONTRACT_MISMATCH")
                body, status = _json(origin, route, fixed_origin=True)
                self.assertIsNone(body)
                self.assertIsNone(status)
        request_json.assert_not_called()

    @patch("census.space_readiness.request_json")
    def test_invalid_version_skips_evidence_and_keeps_source_http(self, request_json):
        broken = version_fixture()
        broken["service"] = "wrong"
        request_json.return_value = (broken, {}, None)
        result = collect_space_readiness(
            space("anatomy"), "https://szlholdings-anatomy.hf.space/", {},
        )
        self.assertEqual(result["readiness_state"], "UNKNOWN")
        self.assertEqual(result["readiness_reason"], "VERSION_CONTRACT_INVALID")
        self.assertEqual(result["readiness_http"], 200)
        self.assertEqual(request_json.call_count, 1)

    @patch("census.space_readiness.request_json")
    def test_source_revision_conflict_skips_evidence(self, request_json):
        request_json.return_value = (version_fixture(), {}, None)
        result = collect_space_readiness(
            space("anatomy"), "https://szlholdings-anatomy.hf.space/",
            {"source_binding_state": "OBSERVED", "source_revision": "c" * 40},
        )
        self.assertEqual(result["readiness_state"], "SOURCE_CONFLICT")
        self.assertEqual(result["readiness_http"], 200)
        self.assertEqual(request_json.call_count, 1)

    @patch("census.space_readiness.request_json")
    def test_paused_and_private_never_probe(self, request_json):
        paused = collect_space_readiness(
            space("anatomy", stage="PAUSED"),
            "https://szlholdings-anatomy.hf.space/", {},
        )
        private = collect_space_readiness(
            space("anatomy", private=True),
            "https://szlholdings-anatomy.hf.space/", {},
        )
        self.assertEqual(paused["readiness_state"], "NOT_READY")
        self.assertEqual(private["readiness_state"], "NOT_EVALUATED")
        request_json.assert_not_called()


if __name__ == "__main__":
    unittest.main()
