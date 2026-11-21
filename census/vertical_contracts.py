"""Pure, fail-closed readiness classifiers for public SZL vertical Spaces.

Only classify an already bounded, fixed-origin GET observation.  Neither
classifier does networking, signs receipts, tests WebGL, or proves inference.
"""

from __future__ import annotations

import re
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")
ROUTER_CHECKS = frozenset({
    "registry_valid", "egress_enabled", "caller_auth_configured", "provider_configured",
})


def classify_router(payload: Any, http: int | None, *, public_status: bool) -> tuple[str, str]:
    """A status Space is not a gateway; configuration is not a signed turn."""
    if http == 503:
        return "NOT_READY", "INFERENCE_HTTP_503"
    if http != 200 or not isinstance(payload, dict):
        return "UNKNOWN", "INFERENCE_OBSERVATION_UNAVAILABLE"
    if public_status:
        return "UNKNOWN", "PUBLIC_STATUS_NOT_AN_INFERENCE_GATEWAY"

    checks = payload.get("checks")
    if (payload.get("basis") != "LOCAL_CONFIGURATION_ONLY"
            or not isinstance(checks, dict)
            or set(checks) != ROUTER_CHECKS
            or any(type(value) is not bool for value in checks.values())
            or type(payload.get("ready_for_requests")) is not bool):
        return "UNKNOWN", "INFERENCE_CONFIGURATION_CONTRACT_INVALID"
    if payload["ready_for_requests"] is False or not all(checks.values()):
        return "NOT_READY", "INFERENCE_CONFIGURATION_NOT_READY"
    if (payload.get("provider_reachability") != "UNVERIFIED"
            or payload.get("inference_witness") != "UNAVAILABLE"
            or payload.get("model_identity") != "UNVERIFIED"):
        return "UNKNOWN", "INFERENCE_PROOF_UNVERIFIED"
    return "SCOPED_READY_UNVERIFIED", "CONFIGURED_ONLY_NO_LIVE_INFERENCE_PROOF"


def classify_anatomy(
    version: Any,
    version_http: int | None,
    evidence: Any,
    evidence_http: int | None,
    hub_revision: Any,
    source_binding: Any,
) -> tuple[str, str]:
    """Distinguish source identity and unsigned structural evidence from admission."""
    if version_http == 503:
        return "NOT_READY", "VERSION_HTTP_503"
    if version_http != 200 or not isinstance(version, dict):
        return "UNKNOWN", "VERSION_OBSERVATION_UNAVAILABLE"
    if (version.get("schemaVersion") != "szl.vertical-conformance.version.v1"
            or version.get("service") != "anatomy"
            or version.get("surface") != "anatomy"
            or version.get("evidenceState") != "MEASURED"):
        return "UNKNOWN", "VERSION_CONTRACT_INVALID"

    source_sha = version.get("gitSha")
    deployed_sha = version.get("deploymentRevision")
    if not all(isinstance(s, str) and SHA40.fullmatch(s)
               for s in (source_sha, deployed_sha, hub_revision)):
        return "UNKNOWN", "EXACT_REVISION_UNAVAILABLE"
    if deployed_sha != hub_revision:
        return "SOURCE_CONFLICT", "DEPLOYMENT_REVISION_MISMATCH"
    binding = source_binding if isinstance(source_binding, dict) else {}
    if binding.get("source_binding_state") == "INVALID":
        return "SOURCE_CONFLICT", "SOURCE_BINDING_INVALID"
    declared_sha = binding.get("source_revision")
    if isinstance(declared_sha, str) and SHA40.fullmatch(declared_sha) and declared_sha != source_sha:
        return "SOURCE_CONFLICT", "GITHUB_SOURCE_REVISION_MISMATCH"

    if evidence_http == 503:
        return "NOT_READY", "EVIDENCE_HTTP_503"
    if evidence_http != 200 or not isinstance(evidence, dict):
        return "UNKNOWN", "EVIDENCE_OBSERVATION_UNAVAILABLE"
    if (evidence.get("schemaVersion") != "szl.vertical-conformance.evidence.v1"
            or evidence.get("service") != "anatomy"
            or evidence.get("surface") != "anatomy"
            or evidence.get("gitSha") != source_sha
            or evidence.get("evidenceState") != "PARTIAL"):
        return "UNKNOWN", "EVIDENCE_CONTRACT_INVALID"
    runtime = evidence.get("runtime")
    receipts = evidence.get("receipts")
    provenance = evidence.get("outputProvenance")
    if (not isinstance(runtime, dict) or runtime.get("ready") is not True
            or runtime.get("authorityState") != "READ_ONLY"):
        return "NOT_READY", "ANATOMY_RUNTIME_NOT_READY"
    if (not isinstance(receipts, list) or len(receipts) != 1
            or not isinstance(receipts[0], dict)
            or receipts[0].get("status") != "STRUCTURAL_ONLY"
            or not isinstance(provenance, dict)
            or provenance.get("signatureStatus") != "UNSIGNED"
            or provenance.get("authenticityEstablished") is not False):
        return "UNKNOWN", "RELEASE_SIGNATURE_NOT_INDEPENDENTLY_VERIFIED"
    if binding.get("source_binding_state") != "OBSERVED" or declared_sha != source_sha:
        return "PRODUCTION_HOLD", "PARTIAL_UNSIGNED_SOURCE_UNVERIFIED"
    return "PRODUCTION_HOLD", "PARTIAL_UNSIGNED_NO_WEBGL_ADMISSION"
