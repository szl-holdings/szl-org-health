"""Negative contract fixtures: Space RUNNING never upgrades to inference/admission."""

import unittest

from census.vertical_contracts import classify_anatomy, classify_router

HUB = "a" * 40
GITHUB = "b" * 40
OTHER = "c" * 40


def router_fixture():
    return {
        "basis": "LOCAL_CONFIGURATION_ONLY",
        "checks": {
            "registry_valid": True, "egress_enabled": True,
            "caller_auth_configured": True, "provider_configured": True,
        },
        "ready_for_requests": True,
        "provider_reachability": "UNVERIFIED",
        "inference_witness": "UNAVAILABLE",
        "model_identity": "UNVERIFIED",
    }


def version_fixture():
    return {
        "schemaVersion": "szl.vertical-conformance.version.v1",
        "service": "anatomy", "surface": "anatomy",
        "evidenceState": "MEASURED", "gitSha": GITHUB,
        "deploymentRevision": HUB,
    }


def evidence_fixture():
    return {
        "schemaVersion": "szl.vertical-conformance.evidence.v1",
        "service": "anatomy", "surface": "anatomy",
        "evidenceState": "PARTIAL", "gitSha": GITHUB,
        "runtime": {"ready": True, "authorityState": "READ_ONLY"},
        "receipts": [{"status": "STRUCTURAL_ONLY"}],
        "outputProvenance": {"signatureStatus": "UNSIGNED", "authenticityEstablished": False},
    }


class RouterContractTests(unittest.TestCase):
    def test_http_503_is_not_ready_even_if_space_running(self):
        for public in (True, False):
            self.assertEqual(
                classify_router(None, 503, public_status=public),
                ("NOT_READY", "INFERENCE_HTTP_503"),
            )

    def test_public_status_space_cannot_claim_200_means_inference(self):
        self.assertEqual(classify_router(router_fixture(), 200, public_status=True)[0], "UNKNOWN")

    def test_control_plane_200_is_configuration_only(self):
        state, reason = classify_router(router_fixture(), 200, public_status=False)
        self.assertEqual(state, "SCOPED_READY_UNVERIFIED")
        self.assertIn("NO_LIVE_INFERENCE", reason)

    def test_partial_configuration_denied(self):
        fixture = router_fixture()
        fixture["checks"]["egress_enabled"] = False
        self.assertEqual(classify_router(fixture, 200, public_status=False)[0], "NOT_READY")

    def test_truthy_strings_and_missing_checks_fail_closed(self):
        for mutant in ("true", 1, [], None):
            with self.subTest(mutant=mutant):
                fixture = router_fixture()
                fixture["checks"]["registry_valid"] = mutant
                self.assertEqual(classify_router(fixture, 200, public_status=False)[0], "UNKNOWN")
        fixture = router_fixture()
        del fixture["checks"]["provider_configured"]
        self.assertEqual(classify_router(fixture, 200, public_status=False)[0], "UNKNOWN")

    def test_reachability_is_not_independent_proof(self):
        fixture = router_fixture()
        fixture["provider_reachability"] = "REACHABLE"
        self.assertEqual(classify_router(fixture, 200, public_status=False)[0], "UNKNOWN")

    def test_unknown_transport_never_becomes_green(self):
        self.assertEqual(classify_router(router_fixture(), None, public_status=False)[0], "UNKNOWN")


class AnatomyContractTests(unittest.TestCase):
    def classify(self, *, version=None, version_http=200, evidence=None,
                 evidence_http=200, hub_revision=HUB, source_binding=None):
        return classify_anatomy(
            version if version is not None else version_fixture(), version_http,
            evidence if evidence is not None else evidence_fixture(), evidence_http,
            hub_revision,
            source_binding if source_binding is not None else {
                "source_binding_state": "OBSERVED", "source_revision": GITHUB,
            },
        )

    def test_actual_partial_unsigned_contract_remains_hold(self):
        state, reason = self.classify()
        self.assertEqual(state, "PRODUCTION_HOLD")
        self.assertIn("NO_WEBGL_ADMISSION", reason)

    def test_503_version_denies_readiness(self):
        self.assertEqual(self.classify(version_http=503)[0], "NOT_READY")

    def test_503_evidence_denies_readiness(self):
        self.assertEqual(self.classify(evidence_http=503)[0], "NOT_READY")

    def test_deployed_revision_mismatch(self):
        self.assertEqual(self.classify(hub_revision=OTHER)[0], "SOURCE_CONFLICT")

    def test_served_github_sha_mismatch(self):
        binding = {"source_binding_state": "OBSERVED", "source_revision": OTHER}
        self.assertEqual(self.classify(source_binding=binding)[0], "SOURCE_CONFLICT")

    def test_invalid_binding_denied(self):
        self.assertEqual(self.classify(source_binding={"source_binding_state": "INVALID"})[0], "SOURCE_CONFLICT")

    def test_still_hold_when_source_not_independently_bound(self):
        self.assertEqual(self.classify(source_binding={"source_binding_state": "UNKNOWN"})[0], "PRODUCTION_HOLD")

    def test_fake_signature_promotion_rejected(self):
        evidence = evidence_fixture()
        evidence["outputProvenance"]["signatureStatus"] = "VERIFIED"
        self.assertEqual(self.classify(evidence=evidence)[0], "UNKNOWN")

    def test_no_webgl_claim_from_receipt_presence(self):
        evidence = evidence_fixture()
        evidence["receipts"][0]["status"] = "VERIFIED"
        self.assertEqual(self.classify(evidence=evidence)[0], "UNKNOWN")

    def test_runtime_claim_false_is_not_ready(self):
        evidence = evidence_fixture()
        evidence["runtime"]["ready"] = False
        self.assertEqual(self.classify(evidence=evidence)[0], "NOT_READY")

    def test_malformed_revision_or_schema_unknown(self):
        for bad in (None, 123, ["a"], "a" * 39, "A" * 40):
            with self.subTest(bad=bad):
                self.assertEqual(self.classify(hub_revision=bad)[0], "UNKNOWN")
        version = version_fixture()
        version["service"] = "different"
        self.assertEqual(self.classify(version=version)[0], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
