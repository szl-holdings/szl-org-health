#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded, non-authorizing public OSS leader research intake.

Join explicit GitHub public source metadata with official web-evidence receipts.
All claims here are *reported observations*; even structural agreement is not
proof of publication origin, license rights, independent testimony, or
execution permission. No networking, scraping, credentials, model invocation,
repository writes, or other external effects occur in this module.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

SCHEMA = "szl.oss-leader-research-observation/v1"
RESULT_SCHEMA = "szl.oss-leader-research-intake/v1"
DOMAIN = b"szl.oss-leader-research-intake/v1\x00"
MAX_INPUT_BYTES = 64 * 1024
MAX_CANDIDATES = 10
MAX_AGE_SECONDS = 7 * 86400
MAX_FUTURE_SKEW_SECONDS = 300
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,69}/[A-Za-z0-9][A-Za-z0-9_.-]{0,89}\Z")
STAMP = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z")
LICENSE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,79}\Z")

# Exact curated official documentation references, not merely same-host URLs.
# A new path/project requires ordinary protected source review. This prevents
# an unrelated page on an allowed host laundering a citation's relevance.
OFFICIAL_DOC_URLS = {
    "ossf/scorecard": "https://scorecard.dev/",
    "open-telemetry/opentelemetry-specification":
        "https://opentelemetry.io/blog/2026/agent-harness-genai-instrumentation/",
    "slsa-framework/slsa": "https://slsa.dev/spec/v1.2/build-provenance",
    "sigstore/cosign": "https://docs.sigstore.dev/cosign/verifying/verify/",
    "vllm-project/vllm": "https://docs.vllm.ai/en/latest/design/paged_attention/",
    "sgl-project/sglang": "https://docs.sglang.ai/",
    "huggingface/hub-docs": "https://huggingface.co/docs/hub/model-cards",
    "ros2/ros2": "https://docs.ros.org/en/jazzy/",
    "isaac-sim/IsaacSim": "https://docs.isaacsim.omniverse.nvidia.com/latest/",
    "ai-dynamo/dynamo": "https://docs.nvidia.com/dynamo/latest/",
}
OFFICIAL_DOC_HOSTS = {repo: urlsplit(url).hostname for repo, url in OFFICIAL_DOC_URLS.items()}
TOP = frozenset({"schema", "pass_index", "observed_at_utc", "szl_source_sha", "candidates"})
CANDIDATE = frozenset({
    "upstream_repository", "upstream_revision", "upstream_public",
    "github_observed_at_utc", "github_license_spdx", "license_file_sha256",
    "source_url", "official_reference", "publication_url",
    "szl_target_repository", "intended_mode",
})
REF_FIELDS = frozenset({
    "url", "retrieved_at", "state", "status", "robots_allowed", "body_sha256",
})
INTENDED_MODES = frozenset({"STUDY_DESIGN", "EVALUATE_DEPENDENCY", "REPRODUCE_BENCHMARK"})
UNRESOLVED_LICENSES = frozenset({
    "NOASSERTION", "NONE", "UNKNOWN", "OTHER", "UNLICENSE", "UNLICENSED",
})


class IntakeError(ValueError):
    """Fixed-shape and budget validation failure; never disclose input bodies."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise IntakeError(code)


def fields(obj: object, names: frozenset[str], code: str) -> dict:
    require(type(obj) is dict and set(obj) == names, code)
    return obj


def pairs(items: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in items:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def reject_number(_value: str) -> None:
    raise IntakeError("NONINTEGER_OR_NONFINITE_NUMBER")


def read_input(raw: bytes) -> dict:
    require(type(raw) is bytes and 0 < len(raw) <= MAX_INPUT_BYTES, "INPUT_BYTE_LIMIT")
    try:
        obj = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                         parse_constant=reject_number, parse_float=reject_number)
    except IntakeError:
        raise
    except (UnicodeError, RecursionError, ValueError, TypeError):
        raise IntakeError("INVALID_JSON") from None
    return fields(obj, TOP, "TOP_FIELDS")


def digest(value: object, pattern: re.Pattern[str], code: str) -> str:
    require(type(value) is str and pattern.fullmatch(value) is not None, code)
    return value


def timestamp(value: object) -> datetime:
    require(type(value) is str and STAMP.fullmatch(value) is not None, "TIMESTAMP_FORMAT")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError:
        raise IntakeError("TIMESTAMP_INVALID") from None


def is_fresh(value: object, now: datetime) -> bool:
    seconds = (now - timestamp(value)).total_seconds()
    return -MAX_FUTURE_SKEW_SECONDS <= seconds <= MAX_AGE_SECONDS


def safe_https(value: object, expected_host: str, code: str) -> str:
    require(type(value) is str and len(value) <= 400, code)
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise IntakeError(code) from None
    require(parsed.scheme == "https" and host == expected_host
            and port is None and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment and parsed.path.startswith("/"), code)
    return value


def evaluate(raw: bytes, *, now: datetime) -> dict:
    """Pure non-authorizing evaluation over public/source-declared observations."""
    batch = read_input(raw)
    require(type(now) is datetime and now.tzinfo is not None
            and now.utcoffset() is not None, "INDEPENDENT_CLOCK_REQUIRED")
    now = now.astimezone(timezone.utc)
    require(batch["schema"] == SCHEMA, "SCHEMA_INVALID")
    require(type(batch["pass_index"]) is int and 1 <= batch["pass_index"] <= 10,
            "PASS_INDEX_INVALID")
    digest(batch["szl_source_sha"], SHA40, "SZL_SOURCE_SHA_INVALID")
    require(is_fresh(batch["observed_at_utc"], now), "BATCH_OBSERVATION_STALE")
    candidates = batch["candidates"]
    require(type(candidates) is list and 1 <= len(candidates) <= MAX_CANDIDATES,
            "CANDIDATE_COUNT_INVALID")

    observed: set[str] = set()
    results = []
    for candidate in candidates:
        fields(candidate, CANDIDATE, "CANDIDATE_FIELDS")
        upstream = digest(candidate["upstream_repository"], REPO, "UPSTREAM_REPOSITORY_INVALID")
        require(upstream in OFFICIAL_DOC_HOSTS, "PROJECT_NOT_SOURCE_ALLOWLISTED")
        require(upstream not in observed, "DUPLICATE_UPSTREAM_IN_PASS")
        observed.add(upstream)
        target = digest(candidate["szl_target_repository"], REPO, "SZL_TARGET_INVALID")
        require(target.startswith("szl-holdings/"), "SZL_TARGET_NOT_OWNED")
        require(type(candidate["intended_mode"]) is str
                and candidate["intended_mode"] in INTENDED_MODES, "INTENDED_MODE_INVALID")
        pin = candidate["upstream_revision"]
        if pin is not None:
            digest(pin, SHA40, "UPSTREAM_SHA_INVALID")
        expected_link = (f"https://github.com/{upstream}/commit/{pin}"
                         if pin is not None else None)
        if expected_link is None:
            require(candidate["source_url"] is None, "UNPINNED_SOURCE_URL_CLAIM")
        else:
            require(candidate["source_url"] == expected_link, "MOVING_OR_MISMATCHED_SOURCE_URL")
        require(candidate["upstream_public"] is None
                or type(candidate["upstream_public"]) is bool, "UPSTREAM_VISIBILITY_INVALID")
        license_tag = candidate["github_license_spdx"]
        if license_tag is not None:
            digest(license_tag, LICENSE, "LICENSE_LABEL_INVALID")
        license_sha = candidate["license_file_sha256"]
        if license_sha is not None:
            digest(license_sha, SHA64, "LICENSE_FILE_DIGEST_INVALID")
        reference = fields(candidate["official_reference"], REF_FIELDS, "REFERENCE_FIELDS")
        safe_https(reference["url"], OFFICIAL_DOC_HOSTS[upstream], "OFFICIAL_REFERENCE_HOST_INVALID")
        require(reference["url"] == OFFICIAL_DOC_URLS[upstream],
                "OFFICIAL_REFERENCE_NOT_CURATED")
        require(type(reference["state"]) is str and reference["state"]
                in {"MEASURED", "BLOCKED", "UNAVAILABLE", "UNKNOWN"}, "REFERENCE_STATE_INVALID")
        require(reference["status"] is None
                or type(reference["status"]) is int and 100 <= reference["status"] <= 599,
                "REFERENCE_HTTP_INVALID")
        require(reference["robots_allowed"] is None
                or type(reference["robots_allowed"]) is bool, "ROBOTS_STATE_INVALID")
        body_hash = reference["body_sha256"]
        if body_hash is not None:
            digest(body_hash, SHA64, "REFERENCE_BODY_DIGEST_INVALID")
        if reference["state"] == "MEASURED":
            require(reference["status"] is not None and 200 <= reference["status"] < 300
                    and reference["robots_allowed"] is True and body_hash is not None,
                    "MEASURED_REFERENCE_INCOHERENT")
        else:
            require(body_hash is None, "UNMEASURED_REFERENCE_CANNOT_CLAIM_DIGEST")
        paper = candidate["publication_url"]
        if paper is not None:
            require(type(paper) is str, "PUBLICATION_URL_INVALID")
            try:
                host = urlsplit(paper).hostname
            except ValueError:
                raise IntakeError("PUBLICATION_URL_INVALID") from None
            require(host in {"arxiv.org", "doi.org"}, "PUBLICATION_HOST_NOT_ADMITTED")
            safe_https(paper, host, "PUBLICATION_URL_INVALID")
        flags: set[str] = set()
        if pin is None:
            flags.add("UPSTREAM_COMMIT_UNOBSERVED")
        if candidate["upstream_public"] is not True:
            flags.add("PUBLIC_VISIBILITY_UNVERIFIED")
        if not is_fresh(candidate["github_observed_at_utc"], now):
            flags.add("GITHUB_METADATA_STALE_OR_FUTURE")
        if reference["state"] != "MEASURED":
            flags.add("OFFICIAL_DOCUMENT_NOT_MEASURED")
        if not is_fresh(reference["retrieved_at"], now):
            flags.add("DOCUMENT_OBSERVATION_STALE_OR_FUTURE")
        if license_tag is None:
            flags.add("LICENSE_METADATA_MISSING")
        elif license_tag.upper() in UNRESOLVED_LICENSES:
            flags.add("LICENSE_METADATA_UNRESOLVED")
        # A digest *reported in JSON* is not independent verification.
        if license_sha is None:
            flags.add("LICENSE_FILE_DIGEST_UNOBSERVED")
        else:
            flags.add("LICENSE_FILE_DIGEST_REPORTED_NOT_ATTESTED")
        if upstream == "isaac-sim/IsaacSim":
            flags.add("NVIDIA_OMNIVERSE_ADDITIONAL_TERMS_REVIEW")
        elif upstream == "ros2/ros2":
            flags.add("ROS_COMPONENT_LICENSES_NEED_SEPARATE_REVIEW")
        if paper is not None:
            flags.add("PUBLICATION_LINK_DECLARED_NOT_CHECKED")
        primary_holds = {
            "UPSTREAM_COMMIT_UNOBSERVED", "PUBLIC_VISIBILITY_UNVERIFIED",
            "GITHUB_METADATA_STALE_OR_FUTURE",
            "OFFICIAL_DOCUMENT_NOT_MEASURED", "DOCUMENT_OBSERVATION_STALE_OR_FUTURE",
        }
        research_state = ("REPORTED_RESEARCH_EVIDENCE_REVIEWABLE"
                          if not flags.intersection(primary_holds)
                          else "HOLD_INCOMPLETE_RESEARCH_EVIDENCE")
        results.append({
            "upstream_repository": upstream,
            "upstream_commit_declared": pin,
            "upstream_public_metadata_reported": candidate["upstream_public"] is True,
            "szl_target_repository_declared": target,
            "intended_mode": candidate["intended_mode"],
            "official_reference_url": reference["url"],
            "web_receipt_state_reported": reference["state"],
            "web_receipt_body_sha256_reported": body_hash,
            "license_spdx_tag_declared_not_rights_verified": license_tag,
            "publication_url_declared_not_peer_reviewed": paper,
            "research_state": research_state,
            "license_rights_state": "INDEPENDENT_HUMAN_RIGHTS_REVIEW_REQUIRED",
            "reasons": sorted(flags),
            "upstream_metadata_authenticated": False,
            "web_receipt_origin_authenticated": False,
            "publication_and_quality_verified": False,
            "license_rights_verified": False,
            "code_copy_authorized": False,
            "dependency_admission_authorized": False,
            "training_or_inference_authorized": False,
            "merge_authorized": False,
            "deployment_authorized": False,
            "monetization_authorized": False,
            "production_ready": False,
        })
    results.sort(key=lambda r: r["upstream_repository"])
    output = {
        "schema": RESULT_SCHEMA,
        "scope": "OFFLINE_REPORTED_PUBLIC_METADATA_ONLY",
        "szl_source_sha_declared_not_attested": batch["szl_source_sha"],
        "pass_index_observed_not_campaign_completion": batch["pass_index"],
        "ten_pass_campaign_complete": False,
        "estate_coverage_state": "NOT_EVALUATED",
        "candidate_count_observed": len(results),
        "research_reviewable_count": sum(
            1 for row in results if row["research_state"] == "REPORTED_RESEARCH_EVIDENCE_REVIEWABLE"
        ),
        "observations": results,
        "signatures_independently_verified": False,
        "licensed_code_reuse_authorized": False,
        "source_automation_authorized": False,
        "production_ready": False,
    }
    encoded = json.dumps(output, sort_keys=True, ensure_ascii=True,
                         allow_nan=False, separators=(",", ":")).encode("ascii")
    output["unsigned_structural_sha256_not_signature"] = hashlib.sha256(DOMAIN + encoded).hexdigest()
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        raw = args.input.read_bytes()
        output = evaluate(raw, now=datetime.now(timezone.utc))
    except (IntakeError, OSError) as exc:
        print(f"HOLD: {type(exc).__name__} {str(exc) if isinstance(exc, IntakeError) else 'FILE_UNAVAILABLE'}", file=sys.stderr)
        return 2
    payload = json.dumps(output, sort_keys=True, indent=2) + "\n"
    if args.output:
        # Local output only, caller chooses an owned destination.
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())