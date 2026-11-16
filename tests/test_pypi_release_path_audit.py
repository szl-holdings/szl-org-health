"""Regression coverage for fail-closed PyPI release-path evidence."""

from __future__ import annotations

import base64
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest import mock

from tools.pypi_release_path_audit import (
    GH_API,
    Http,
    RAW,
    apply_sigstore_receipt,
    audit_release_repo,
    load_sigstore_receipts,
    sha256,
)


ORG = "szl-holdings"
REPO = "release-example"
PACKAGE = "release-example"
VERSION = "1.2.3"
DIGEST = "a" * 40
WHEEL = "release_example-1.2.3-py3-none-any.whl"
SDIST = "release_example-1.2.3.tar.gz"
WORKFLOW = b'SZL_PACKAGES: "release-example=.:pypi"\n'
GATE = b"canonical release gate\n"
GITHUB = f"{GH_API}/repos/{ORG}/{REPO}"
PYPI = f"https://pypi.org/pypi/{PACKAGE}/json"
SIMPLE = f"https://pypi.org/simple/{PACKAGE}/"
RULESETS = f"{GITHUB}/rulesets?includes_parents=true&targets=tag&per_page=100"
RULESET_DETAIL = f"{GITHUB}/rulesets/42?includes_parents=true"
RULESET_DETAIL_43 = f"{GITHUB}/rulesets/43?includes_parents=true"
RULESET_DETAIL_44 = f"{GITHUB}/rulesets/44?includes_parents=true"
PROVENANCE = {
    WHEEL: f"https://pypi.org/integrity/{PACKAGE}/{VERSION}/{WHEEL}/provenance",
    SDIST: f"https://pypi.org/integrity/{PACKAGE}/{VERSION}/{SDIST}/provenance",
}
FILE_SHA256 = {WHEEL: "1" * 64, SDIST: "2" * 64}


def certificate_with_source_digest(digest: str = DIGEST) -> str:
    # Minimal bytes understood by source_digest_from_cert: Sigstore source-digest
    # OID followed by an OCTET STRING containing a UTF8String.
    oid = bytes.fromhex("060a2b0601040183bf30010d")
    encoded = digest.encode("ascii")
    inner = bytes((0x0C, len(encoded))) + encoded
    return base64.b64encode(oid + bytes((0x04, len(inner))) + inner).decode("ascii")


def attestation(filename: str) -> dict:
    # PyPI's DSSE envelope carries a base64-encoded in-toto statement. This
    # fixture has structurally realistic metadata but no verified signature.
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": filename, "digest": {"sha256": FILE_SHA256[filename]}}],
        "predicateType": "https://docs.pypi.org/attestations/publish/v1",
        "predicate": None,
    }
    return {
        "version": 1,
        "attestation_bundles": [
            {
                "publisher": {
                    "kind": "GitHub",
                    "repository": f"{ORG}/{REPO}",
                    "workflow": "publish-pypi.yml",
                    "environment": "pypi",
                },
                "attestations": [
                    {
                        "envelope": {
                            "signature": base64.b64encode(b"test-signature-unverified").decode("ascii"),
                            "statement": base64.b64encode(json.dumps(statement).encode("utf-8")).decode("ascii"),
                        },
                        "verification_material": {"certificate": certificate_with_source_digest()},
                    }
                ],
            }
        ]
    }


def ruleset_detail(*, include: list[str] | None = None) -> dict:
    return {
        "id": 42,
        "name": "release tags",
        "target": "tag",
        "enforcement": "active",
        "conditions": {
            "ref_name": {"include": include if include is not None else ["refs/tags/v*"], "exclude": []}
        },
        "rules": [{"type": kind} for kind in ("creation", "update", "deletion")],
        "bypass_actors": [],
    }


class FakeHttp:
    def __init__(self, responses: dict[str, tuple[int, object]]):
        self.responses = responses
        self.calls: list[str] = []

    def get(self, url: str, accept: str | None = None, raw: bool = False):
        self.calls.append(url)
        if url not in self.responses:
            raise AssertionError(f"unexpected HTTP request: {url}")
        return copy.deepcopy(self.responses[url])


def fixture() -> dict[str, tuple[int, object]]:
    return {
        f"{RAW}/{ORG}/{REPO}/HEAD/.github/workflows/publish-pypi.yml": (200, WORKFLOW),
        f"{RAW}/{ORG}/{REPO}/HEAD/.github/scripts/szl_pypi_release_gate.py": (200, GATE),
        f"{GITHUB}/contents/.github/workflows": (
            200,
            [{"name": "publish-pypi.yml", "download_url": f"{RAW}/{ORG}/{REPO}/HEAD/.github/workflows/publish-pypi.yml"}],
        ),
        f"{GITHUB}/environments": (
            200,
            {"environments": [{"name": "pypi", "deployment_branch_policy": {
                "custom_branch_policies": True, "protected_branches": False,
            }}]},
        ),
        f"{GITHUB}/environments/pypi/deployment-branch-policies": (
            200,
            {"total_count": 1, "branch_policies": [{"name": "v*", "type": "tag"}]},
        ),
        RULESETS: (
            200,
            [{"id": 42, "name": "release tags", "target": "tag", "enforcement": "active"}],
        ),
        RULESET_DETAIL: (200, ruleset_detail()),
        PYPI: (
            200,
            {
                "info": {
                    "version": VERSION,
                    "project_urls": {"Source": f"https://github.com/{ORG}/{REPO}"},
                },
                "urls": [{"filename": name, "digests": {"sha256": FILE_SHA256[name]}}
                         for name in (WHEEL, SDIST)],
            },
        ),
        SIMPLE: (
            200,
            {"files": [{"filename": name, "hashes": {"sha256": FILE_SHA256[name]},
                        "provenance": url} for name, url in PROVENANCE.items()]},
        ),
        **{url: (200, attestation(name)) for name, url in PROVENANCE.items()},
        f"{GITHUB}/git/ref/tags/v{VERSION}": (
            200,
            {"object": {"type": "commit", "sha": DIGEST}},
        ),
    }


def audit(responses: dict[str, tuple[int, object]], *, tag_pattern: str = "v<version>") -> tuple[dict[str, dict], FakeHttp]:
    http = FakeHttp(responses)
    results: list[dict] = []
    with redirect_stdout(io.StringIO()):
        audit_release_repo(
            http,
            ORG,
            {"name": PACKAGE, "repo": REPO, "status": "published", "tag_pattern": tag_pattern},
            {"render": lambda spec: f'SZL_PACKAGES: "{spec}"\n', "gate_sha256": sha256(GATE)},
            results,
            {},
        )
    return {row["check"]: row for row in results}, http


class PyPIReleasePathAuditTests(unittest.TestCase):
    def test_complete_release_metadata_is_bound_but_signatures_unverified(self):
        results, http = audit(fixture())

        self.assertEqual(results["pypi:distribution-metadata"]["status"], "PASS")
        for name in ("pypi:provenance", "pypi:publisher-identity", "github:release-tag"):
            self.assertEqual(results[name]["status"], "UNKNOWN")
        self.assertEqual(results["canonical:workflow-environment"]["status"], "PASS")
        for name, row in results.items():
            if name not in ("pypi:provenance", "pypi:publisher-identity", "github:release-tag"):
                self.assertEqual(row["status"], "PASS", name)
        self.assertIn(RULESETS, http.calls)
        self.assertIn(RULESET_DETAIL, http.calls)
        self.assertIn(PROVENANCE[WHEEL], http.calls)
        self.assertIn(PROVENANCE[SDIST], http.calls)

    def test_verified_sigstore_receipt_promotes_only_covered_checks(self):
        result_map, _ = audit(fixture())
        receipt = {
            "package": PACKAGE,
            "repo": REPO,
            "status": "VERIFIED",
            "version": VERSION,
            "tag": f"v{VERSION}",
            "tag_commit": DIGEST,
            "attested_digests": [DIGEST],
        }
        rows = list(result_map.values())
        apply_sigstore_receipt(rows, {"name": PACKAGE, "repo": REPO, "tag_pattern": "v<version>"}, {PACKAGE: receipt})

        for name in ("pypi:provenance", "pypi:publisher-identity", "github:release-tag"):
            self.assertEqual(result_map[name]["status"], "PASS")
            self.assertIn("sigstore receipt VERIFIED", result_map[name]["detail"])
        self.assertEqual(result_map["pypi:distribution-metadata"]["status"], "PASS")

    def test_unmatched_sigstore_receipt_leaves_unknown_fail_closed(self):
        result_map, _ = audit(fixture())
        receipt = {
            "package": PACKAGE,
            "repo": REPO,
            "status": "VERIFIED",
            "version": VERSION,
            "tag": f"v{VERSION}",
            "tag_commit": "b" * 40,
            "attested_digests": ["a" * 40],
        }
        rows = list(result_map.values())
        apply_sigstore_receipt(rows, {"name": PACKAGE, "repo": REPO, "tag_pattern": "v<version>"}, {PACKAGE: receipt})

        for name in ("pypi:provenance", "pypi:publisher-identity", "github:release-tag"):
            self.assertEqual(result_map[name]["status"], "UNKNOWN")

    def test_load_sigstore_receipts_requires_exact_verified_digest_binding(self):
        report = {
            "schema": "szl.pypi-sigstore-verify.v1",
            "results": [
                {
                    "package": PACKAGE,
                    "repo": REPO,
                    "status": "VERIFIED",
                    "version": VERSION,
                    "tag": f"v{VERSION}",
                    "tag_commit": DIGEST,
                    "attested_digests": [DIGEST],
                },
                {
                    "package": "unbound",
                    "repo": REPO,
                    "status": "VERIFIED",
                    "version": VERSION,
                    "tag": f"v{VERSION}",
                    "tag_commit": DIGEST,
                    "attested_digests": ["c" * 40],
                },
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sigstore.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            receipts = load_sigstore_receipts(str(path))

        self.assertEqual(set(receipts), {PACKAGE})
        self.assertEqual(receipts[PACKAGE]["tag_commit"], DIGEST)

    def test_workflow_and_publisher_must_bind_manifest_environment(self):
        responses = fixture()
        workflow_url = f"{RAW}/{ORG}/{REPO}/HEAD/.github/workflows/publish-pypi.yml"
        responses[workflow_url] = (200, b'SZL_PACKAGES: "release-example=.:unprotected"\n')
        for url in PROVENANCE.values():
            responses[url][1]["attestation_bundles"][0]["publisher"]["environment"] = "unprotected"

        results, _ = audit(responses)

        self.assertEqual(results["canonical:workflow"]["status"], "PASS")
        self.assertEqual(results["canonical:workflow-environment"]["status"], "FAIL")
        self.assertEqual(results["pypi:publisher-identity"]["status"], "FAIL")
        self.assertEqual(results["pypi:distribution-metadata"]["status"], "PASS")

    def test_workflow_default_environment_is_pypi(self):
        responses = fixture()
        workflow_url = f"{RAW}/{ORG}/{REPO}/HEAD/.github/workflows/publish-pypi.yml"
        responses[workflow_url] = (200, b'SZL_PACKAGES: "release-example=."\n')

        results, _ = audit(responses)

        self.assertEqual(results["canonical:workflow-environment"]["status"], "PASS")

    def test_unreadable_workflow_leaves_environment_unknown(self):
        responses = fixture()
        workflow_url = f"{RAW}/{ORG}/{REPO}/HEAD/.github/workflows/publish-pypi.yml"
        responses[workflow_url] = (403, None)

        results, _ = audit(responses)

        self.assertEqual(results["canonical:workflow-environment"]["status"], "UNKNOWN")
        self.assertIn("403", results["canonical:workflow-environment"]["detail"])

    def test_extra_environment_cannot_replace_manifest_environment(self):
        responses = fixture()
        responses[f"{GITHUB}/environments"][1]["environments"].append({
            "name": "unprotected",
            "deployment_branch_policy": {"custom_branch_policies": True, "protected_branches": False},
        })
        responses[f"{GITHUB}/environments/pypi/deployment-branch-policies"][1]["branch_policies"][0]["name"] = "archive-*"
        responses[f"{GITHUB}/environments/unprotected/deployment-branch-policies"] = (
            200, {"total_count": 1, "branch_policies": [{"name": "v*", "type": "tag"}]},
        )

        results, _ = audit(responses)

        self.assertEqual(results["github:environment-tag-only"]["status"], "FAIL")
        self.assertIn("archive-*", results["github:environment-tag-only"]["detail"])
        self.assertEqual(results["pypi:publisher-identity"]["status"], "UNKNOWN")

    def test_missing_publisher_environment_is_unknown(self):
        responses = fixture()
        for url in PROVENANCE.values():
            del responses[url][1]["attestation_bundles"][0]["publisher"]["environment"]
        results, _ = audit(responses)

        self.assertEqual(results["pypi:publisher-identity"]["status"], "UNKNOWN")
        self.assertIn("environment missing", results["pypi:publisher-identity"]["detail"])
        self.assertEqual(results["pypi:distribution-metadata"]["status"], "PASS")

    def test_publisher_environment_mismatch_fails_with_canonical_workflow(self):
        responses = fixture()
        for url in PROVENANCE.values():
            responses[url][1]["attestation_bundles"][0]["publisher"]["environment"] = "unprotected"

        results, _ = audit(responses)

        self.assertEqual(results["canonical:workflow-environment"]["status"], "PASS")
        self.assertEqual(results["pypi:publisher-identity"]["status"], "FAIL")
        self.assertIn("unprotected", results["pypi:publisher-identity"]["detail"])
        self.assertIn("pypi", results["pypi:publisher-identity"]["detail"])

    def test_reused_wheel_provenance_cannot_cover_sdist(self):
        responses = fixture()
        responses[SIMPLE][1]["files"][1]["provenance"] = PROVENANCE[WHEEL]

        results, http = audit(responses)

        self.assertNotEqual(results["pypi:provenance"]["status"], "PASS")
        self.assertNotEqual(results["pypi:publisher-identity"]["status"], "PASS")
        self.assertNotEqual(results["github:release-tag"]["status"], "PASS")
        self.assertEqual(results["pypi:distribution-metadata"]["status"], "FAIL")
        self.assertIn(PROVENANCE[WHEEL], http.calls)

    def test_provenance_url_must_name_the_exact_release_version(self):
        responses = fixture()
        wrong_url = f"https://pypi.org/integrity/{PACKAGE}/9.9.9/{SDIST}/provenance"
        responses[SIMPLE][1]["files"][1]["provenance"] = wrong_url

        results, http = audit(responses)

        self.assertEqual(results["pypi:distribution-metadata"]["status"], "FAIL")
        self.assertNotEqual(results["pypi:provenance"]["status"], "PASS")
        self.assertNotIn(wrong_url, http.calls)

    def test_json_and_simple_file_digests_must_agree(self):
        responses = fixture()
        responses[SIMPLE][1]["files"][1]["hashes"]["sha256"] = "3" * 64

        results, _ = audit(responses)

        self.assertEqual(results["pypi:distribution-metadata"]["status"], "FAIL")
        self.assertNotEqual(results["pypi:provenance"]["status"], "PASS")

    def test_each_attestation_subject_must_name_its_own_file(self):
        responses = fixture()
        envelope = responses[PROVENANCE[SDIST]][1]["attestation_bundles"][0]["attestations"][0]["envelope"]
        statement = json.loads(base64.b64decode(envelope["statement"]))
        statement["subject"][0]["name"] = WHEEL
        envelope["statement"] = base64.b64encode(json.dumps(statement).encode()).decode()

        results, _ = audit(responses)

        self.assertEqual(results["pypi:distribution-metadata"]["status"], "FAIL")
        self.assertNotEqual(results["pypi:provenance"]["status"], "PASS")

    def test_each_attestation_subject_digest_must_match_file(self):
        responses = fixture()
        envelope = responses[PROVENANCE[SDIST]][1]["attestation_bundles"][0]["attestations"][0]["envelope"]
        statement = json.loads(base64.b64decode(envelope["statement"]))
        statement["subject"][0]["digest"]["sha256"] = FILE_SHA256[WHEEL]
        envelope["statement"] = base64.b64encode(json.dumps(statement).encode()).decode()

        results, _ = audit(responses)

        self.assertEqual(results["pypi:distribution-metadata"]["status"], "FAIL")
        self.assertNotEqual(results["pypi:provenance"]["status"], "PASS")

    def test_publish_statement_predicate_must_be_empty(self):
        responses = fixture()
        envelope = responses[PROVENANCE[SDIST]][1]["attestation_bundles"][0]["attestations"][0]["envelope"]
        statement = json.loads(base64.b64decode(envelope["statement"]))
        statement["predicate"] = {"arbitrary": True}
        envelope["statement"] = base64.b64encode(json.dumps(statement).encode()).decode()

        results, _ = audit(responses)

        self.assertEqual(results["pypi:distribution-metadata"]["status"], "UNKNOWN")
        self.assertIn("statement", results["pypi:distribution-metadata"]["detail"])

    def test_missing_attestation_signature_is_unknown(self):
        responses = fixture()
        envelope = responses[PROVENANCE[SDIST]][1]["attestation_bundles"][0]["attestations"][0]["envelope"]
        del envelope["signature"]

        results, _ = audit(responses)

        self.assertEqual(results["pypi:distribution-metadata"]["status"], "UNKNOWN")
        self.assertEqual(results["pypi:provenance"]["status"], "UNKNOWN")
        self.assertNotEqual(results["pypi:publisher-identity"]["status"], "PASS")

    def test_source_url_requires_exact_github_host_owner_and_repo(self):
        urls_and_statuses = (
            (f"https://github.com/{ORG}/{REPO}", "PASS"),
            (f"https://github.com/{ORG}/{REPO}/", "PASS"),
            (f"https://github.com/{ORG}/{REPO}-impostor", "FAIL"),
            (f"https://github.com.evil.example/{ORG}/{REPO}", "FAIL"),
            (f"https://github.com/{ORG}/other-repo", "FAIL"),
        )
        for url, expected in urls_and_statuses:
            with self.subTest(url=url):
                responses = fixture()
                responses[PYPI][1]["info"]["project_urls"]["Source"] = url
                results, _ = audit(responses)
                self.assertEqual(results["pypi:source-url"]["status"], expected)

    def test_unrelated_active_tag_ruleset_does_not_protect_release_tags(self):
        responses = fixture()
        responses[RULESET_DETAIL] = (200, ruleset_detail(include=["refs/tags/archive-*"]))

        results, _ = audit(responses)

        self.assertEqual(results["github:tag-ruleset"]["status"], "FAIL")
        self.assertIn("archive", results["github:tag-ruleset"]["detail"])

    def test_applicable_ruleset_needs_every_write_protection(self):
        for omitted in ("creation", "update", "deletion"):
            with self.subTest(omitted=omitted):
                responses = fixture()
                detail = ruleset_detail()
                detail["rules"] = [rule for rule in detail["rules"] if rule["type"] != omitted]
                responses[RULESET_DETAIL] = (200, detail)

                results, _ = audit(responses)

                self.assertEqual(results["github:tag-ruleset"]["status"], "FAIL")
                self.assertIn(omitted, results["github:tag-ruleset"]["detail"])

    def test_safe_rulesets_layer_to_cover_all_release_tag_protections(self):
        responses = fixture()
        responses[RULESETS][1].append(
            {"id": 43, "name": "release tag mutations", "target": "tag", "enforcement": "active"}
        )
        creation = ruleset_detail()
        creation["rules"] = [{"type": "creation"}]
        responses[RULESET_DETAIL] = (200, creation)
        mutations = ruleset_detail()
        mutations["id"] = 43
        mutations["name"] = "release tag mutations"
        mutations["rules"] = [{"type": "update"}, {"type": "deletion"}]
        responses[RULESET_DETAIL_43] = (200, mutations)

        results, http = audit(responses)

        self.assertEqual(results["github:tag-ruleset"]["status"], "PASS")
        self.assertIn(RULESET_DETAIL_43, http.calls)

    def test_permissive_unrelated_ruleset_does_not_undo_safe_layering(self):
        responses = fixture()
        responses[RULESETS][1].extend((
            {"id": 43, "name": "release tag mutations", "target": "tag", "enforcement": "active"},
            {"id": 44, "name": "archive tags", "target": "tag", "enforcement": "active"},
        ))
        creation = ruleset_detail()
        creation["rules"] = [{"type": "creation"}]
        responses[RULESET_DETAIL] = (200, creation)
        mutations = ruleset_detail()
        mutations["id"] = 43
        mutations["rules"] = [{"type": "update"}, {"type": "deletion"}]
        responses[RULESET_DETAIL_43] = (200, mutations)
        unrelated = ruleset_detail(include=["refs/tags/archive-*"])
        unrelated["id"] = 44
        unrelated["bypass_actors"] = [
            {"actor_id": 12, "actor_type": "Team", "bypass_mode": "always"}
        ]
        responses[RULESET_DETAIL_44] = (200, unrelated)

        results, _ = audit(responses)

        self.assertEqual(results["github:tag-ruleset"]["status"], "PASS")

    def test_non_admin_bypass_layer_does_not_supply_missing_protections(self):
        responses = fixture()
        responses[RULESETS][1].append(
            {"id": 43, "name": "release tag mutations", "target": "tag", "enforcement": "active"}
        )
        creation = ruleset_detail()
        creation["rules"] = [{"type": "creation"}]
        responses[RULESET_DETAIL] = (200, creation)
        mutations = ruleset_detail()
        mutations["id"] = 43
        mutations["rules"] = [{"type": "update"}, {"type": "deletion"}]
        mutations["bypass_actors"] = [
            {"actor_id": 12, "actor_type": "Team", "bypass_mode": "always"}
        ]
        responses[RULESET_DETAIL_43] = (200, mutations)

        results, _ = audit(responses)

        self.assertNotEqual(results["github:tag-ruleset"]["status"], "PASS")

    def test_opaque_bypass_layer_could_supply_missing_protections(self):
        responses = fixture()
        responses[RULESETS][1].append(
            {"id": 43, "name": "release tag mutations", "target": "tag", "enforcement": "active"}
        )
        creation = ruleset_detail()
        creation["rules"] = [{"type": "creation"}]
        responses[RULESET_DETAIL] = (200, creation)
        mutations = ruleset_detail()
        mutations["id"] = 43
        mutations["rules"] = [{"type": "update"}, {"type": "deletion"}]
        del mutations["bypass_actors"]
        responses[RULESET_DETAIL_43] = (200, mutations)

        results, _ = audit(responses)

        self.assertEqual(results["github:tag-ruleset"]["status"], "UNKNOWN")
        self.assertIn("bypass", results["github:tag-ruleset"]["detail"].lower())

    def test_non_admin_bypass_actor_fails(self):
        responses = fixture()
        detail = ruleset_detail()
        detail["bypass_actors"] = [
            {"actor_id": 12, "actor_type": "Team", "bypass_mode": "always"}
        ]
        responses[RULESET_DETAIL] = (200, detail)

        results, _ = audit(responses)

        self.assertEqual(results["github:tag-ruleset"]["status"], "FAIL")
        self.assertIn("bypass", results["github:tag-ruleset"]["detail"].lower())

    def test_package_prefixed_release_tags_need_matching_ruleset(self):
        tag_pattern = f"{PACKAGE}-v<version>"
        expected_ref = f"{GITHUB}/git/ref/tags/{PACKAGE}-v{VERSION}"
        for include, expected in (
            ([f"refs/tags/{PACKAGE}-v*"], "PASS"),
            (["refs/tags/v*"], "FAIL"),
        ):
            with self.subTest(include=include):
                responses = fixture()
                responses[RULESET_DETAIL] = (200, ruleset_detail(include=include))
                responses[f"{GITHUB}/environments/pypi/deployment-branch-policies"][1]["branch_policies"][0]["name"] = f"{PACKAGE}-v*"
                responses[expected_ref] = responses.pop(f"{GITHUB}/git/ref/tags/v{VERSION}")

                results, http = audit(responses, tag_pattern=tag_pattern)

                self.assertEqual(results["github:tag-ruleset"]["status"], expected)
                self.assertEqual(results["github:environment-tag-only"]["status"], "PASS")
                self.assertEqual(results["github:release-tag"]["status"], "UNKNOWN")
                self.assertIn(expected_ref, http.calls)

    def test_custom_manifest_tag_pattern_selects_the_attested_release_tag(self):
        responses = fixture()
        tag_pattern = "release-v<version>"
        expected_ref = f"{GITHUB}/git/ref/tags/release-v{VERSION}"
        wrong_ref = f"{GITHUB}/git/ref/tags/{PACKAGE}-v{VERSION}"
        responses[RULESET_DETAIL] = (200, ruleset_detail(include=["refs/tags/release-v*"]))
        responses[f"{GITHUB}/environments/pypi/deployment-branch-policies"][1]["branch_policies"][0]["name"] = "release-v*"
        responses[expected_ref] = responses.pop(f"{GITHUB}/git/ref/tags/v{VERSION}")
        responses[wrong_ref] = (200, {"object": {"type": "commit", "sha": "b" * 40}})

        results, http = audit(responses, tag_pattern=tag_pattern)

        self.assertEqual(results["github:tag-ruleset"]["status"], "PASS")
        self.assertEqual(results["github:environment-tag-only"]["status"], "PASS")
        self.assertEqual(results["github:release-tag"]["status"], "UNKNOWN")
        self.assertIn(expected_ref, http.calls)
        self.assertNotIn(wrong_ref, http.calls)

    def test_unsupported_manifest_tag_pattern_never_looks_up_a_fallback_tag(self):
        results, http = audit(fixture(), tag_pattern="release/?<version>")

        self.assertEqual(results["github:release-tag"]["status"], "UNKNOWN")
        self.assertIn("unsupported manifest", results["github:release-tag"]["detail"])
        self.assertFalse(any("/git/ref/tags/" in url for url in http.calls))

    def test_absent_tag_ruleset_is_reported_as_missing(self):
        responses = fixture()
        responses[RULESETS] = (200, [])

        results, _ = audit(responses)

        self.assertEqual(results["github:tag-ruleset"]["status"], "FAIL")
        self.assertTrue(results["github:tag-ruleset"]["detail"])

    def test_full_ruleset_page_without_match_is_unknown(self):
        responses = fixture()
        responses[RULESETS] = (200, [{"id": n, "target": "tag", "enforcement": "disabled"} for n in range(1, 101)])

        results, _ = audit(responses)

        self.assertEqual(results["github:tag-ruleset"]["status"], "UNKNOWN")
        self.assertIn("more pages", results["github:tag-ruleset"]["detail"])

    def test_malformed_successful_ruleset_inventory_is_unknown(self):
        for payload in ({}, {"rulesets": None}, [{"id": 42, "target": "tag"}]):
            with self.subTest(payload=payload):
                responses = fixture()
                responses[RULESETS] = (200, payload)

                results, _ = audit(responses)

                self.assertEqual(results["github:tag-ruleset"]["status"], "UNKNOWN")

    def test_inaccessible_ruleset_detail_is_unknown_with_evidence(self):
        responses = fixture()
        responses[RULESET_DETAIL] = (403, None)

        results, _ = audit(responses)

        self.assertEqual(results["github:tag-ruleset"]["status"], "UNKNOWN")
        self.assertIn("403", results["github:tag-ruleset"]["detail"])

    def test_inaccessible_ruleset_inventory_is_unknown_with_evidence(self):
        responses = fixture()
        responses[RULESETS] = (403, None)

        results, _ = audit(responses)

        self.assertEqual(results["github:tag-ruleset"]["status"], "UNKNOWN")
        self.assertIn("403", results["github:tag-ruleset"]["detail"])

    def test_opaque_bypass_policy_is_unknown(self):
        responses = fixture()
        opaque = ruleset_detail()
        del opaque["bypass_actors"]
        responses[RULESET_DETAIL] = (200, opaque)

        results, _ = audit(responses)

        self.assertEqual(results["github:tag-ruleset"]["status"], "UNKNOWN")
        self.assertIn("bypass", results["github:tag-ruleset"]["detail"].lower())

    def test_unreadable_workflow_cannot_clear_token_scan(self):
        responses = fixture()
        extra_url = f"{RAW}/{ORG}/{REPO}/HEAD/.github/workflows/other.yml"
        responses[f"{GITHUB}/contents/.github/workflows"][1].append(
            {"name": "other.yml", "download_url": extra_url}
        )
        responses[extra_url] = (403, None)

        results, _ = audit(responses)

        self.assertEqual(results["github:no-token-secrets"]["status"], "UNKNOWN")
        self.assertIn("other.yml: HTTP 403", results["github:no-token-secrets"]["detail"])

    def test_malformed_workflow_listing_is_unknown(self):
        responses = fixture()
        responses[f"{GITHUB}/contents/.github/workflows"] = (200, [{"name": "other.yml"}])

        results, _ = audit(responses)

        self.assertEqual(results["github:no-token-secrets"]["status"], "UNKNOWN")

    def test_unreadable_environment_policy_is_unknown(self):
        responses = fixture()
        responses[f"{GITHUB}/environments/pypi/deployment-branch-policies"] = (403, None)

        results, _ = audit(responses)

        self.assertEqual(results["github:environment-tag-only"]["status"], "UNKNOWN")
        self.assertIn("403", results["github:environment-tag-only"]["detail"])

    def test_incomplete_environment_policy_page_is_unknown(self):
        responses = fixture()
        responses[f"{GITHUB}/environments/pypi/deployment-branch-policies"] = (
            200,
            {"total_count": 31, "branch_policies": [{"name": f"v{n}*", "type": "tag"} for n in range(30)]},
        )

        results, _ = audit(responses)

        self.assertEqual(results["github:environment-tag-only"]["status"], "UNKNOWN")
        self.assertIn("31", results["github:environment-tag-only"]["detail"])

    def test_environment_tag_policy_must_cover_release_family(self):
        for pattern in ("archive-*", "*"):
            with self.subTest(pattern=pattern):
                responses = fixture()
                responses[f"{GITHUB}/environments/pypi/deployment-branch-policies"] = (
                    200,
                    {"total_count": 1, "branch_policies": [{"name": pattern, "type": "tag"}]},
                )

                results, _ = audit(responses)

                self.assertEqual(results["github:environment-tag-only"]["status"], "FAIL")
                self.assertIn("v*", results["github:environment-tag-only"]["detail"])

    def test_unrelated_extra_environment_tag_policy_fails(self):
        responses = fixture()
        responses[f"{GITHUB}/environments/pypi/deployment-branch-policies"] = (
            200,
            {"total_count": 2, "branch_policies": [
                {"name": "v*", "type": "tag"}, {"name": "archive-*", "type": "tag"},
            ]},
        )
        results, _ = audit(responses)

        self.assertEqual(results["github:environment-tag-only"]["status"], "FAIL")
        self.assertIn("archive-*", results["github:environment-tag-only"]["detail"])

    def test_environment_custom_policy_flag_must_be_a_boolean_true(self):
        for flag, expected in ((False, "FAIL"), ("false", "UNKNOWN"), (1, "UNKNOWN"), (None, "UNKNOWN")):
            with self.subTest(flag=flag):
                responses = fixture()
                env = responses[f"{GITHUB}/environments"][1]["environments"][0]
                env["deployment_branch_policy"]["custom_branch_policies"] = flag

                results, _ = audit(responses)

                self.assertEqual(results["github:environment-tag-only"]["status"], expected)
                if expected == "UNKNOWN":
                    self.assertIn("malformed", results["github:environment-tag-only"]["detail"])

    def test_protected_branch_policy_must_be_explicitly_disabled(self):
        for flag, expected in ((True, "FAIL"), (None, "UNKNOWN"), ("false", "UNKNOWN"), (0, "UNKNOWN")):
            with self.subTest(flag=flag):
                responses = fixture()
                policy = responses[f"{GITHUB}/environments"][1]["environments"][0]["deployment_branch_policy"]
                if flag is not None:
                    policy["protected_branches"] = flag
                else:
                    del policy["protected_branches"]

                results, _ = audit(responses)

                self.assertEqual(results["github:environment-tag-only"]["status"], expected)

    def test_full_ref_environment_tag_policy_coverage_is_unknown(self):
        responses = fixture()
        responses[f"{GITHUB}/environments/pypi/deployment-branch-policies"] = (
            200,
            {"total_count": 1, "branch_policies": [{"name": "refs/tags/v*", "type": "tag"}]},
        )
        results, _ = audit(responses)

        self.assertEqual(results["github:environment-tag-only"]["status"], "UNKNOWN")
        self.assertIn("coverage is unverified", results["github:environment-tag-only"]["detail"])

    def test_extra_full_ref_environment_policy_keeps_coverage_unknown(self):
        responses = fixture()
        responses[f"{GITHUB}/environments/pypi/deployment-branch-policies"] = (
            200,
            {"total_count": 2, "branch_policies": [
                {"name": "refs/tags/v*", "type": "tag"}, {"name": "v*", "type": "tag"},
            ]},
        )
        results, _ = audit(responses)

        self.assertEqual(results["github:environment-tag-only"]["status"], "UNKNOWN")

    def test_hidden_or_missing_release_tag_is_unknown(self):
        responses = fixture()
        responses[f"{GITHUB}/git/ref/tags/v{VERSION}"] = (404, None)

        results, _ = audit(responses)

        self.assertEqual(results["github:release-tag"]["status"], "UNKNOWN")
        self.assertIn("404", results["github:release-tag"]["detail"])

    def test_malformed_successful_release_tag_response_is_unknown(self):
        for payload in ({}, {"object": None}):
            with self.subTest(payload=payload):
                responses = fixture()
                responses[f"{GITHUB}/git/ref/tags/v{VERSION}"] = (200, payload)

                results, _ = audit(responses)

                self.assertEqual(results["github:release-tag"]["status"], "UNKNOWN")

    def test_missing_latest_sdist_cannot_count_as_complete_provenance(self):
        responses = fixture()
        responses[SIMPLE][1]["files"] = [responses[SIMPLE][1]["files"][0]]

        results, _ = audit(responses)

        self.assertEqual(results["pypi:provenance"]["status"], "FAIL")
        self.assertIn(SDIST, results["pypi:provenance"]["detail"])
        self.assertNotEqual(results["pypi:publisher-identity"]["status"], "PASS")
        self.assertNotEqual(results["github:release-tag"]["status"], "PASS")

    def test_missing_provenance_link_fails_closed(self):
        responses = fixture()
        responses[SIMPLE][1]["files"][1]["provenance"] = None

        results, _ = audit(responses)

        self.assertEqual(results["pypi:provenance"]["status"], "FAIL")
        self.assertIn(SDIST, results["pypi:provenance"]["detail"])
        self.assertNotEqual(results["pypi:publisher-identity"]["status"], "PASS")
        self.assertNotEqual(results["github:release-tag"]["status"], "PASS")

    def test_malformed_simple_file_list_is_unknown(self):
        responses = fixture()
        responses[SIMPLE] = (200, {"files": None})

        results, _ = audit(responses)

        self.assertEqual(results["pypi:provenance"]["status"], "UNKNOWN")
        self.assertEqual(results["pypi:publisher-identity"]["status"], "UNKNOWN")
        self.assertEqual(results["github:release-tag"]["status"], "UNKNOWN")

    def test_invalid_provenance_origin_is_not_fetched(self):
        responses = fixture()
        malicious_url = "https://api.github.com.evil.example/steal"
        responses[SIMPLE][1]["files"][1]["provenance"] = malicious_url

        results, http = audit(responses)

        self.assertEqual(results["pypi:provenance"]["status"], "FAIL")
        self.assertNotIn(malicious_url, http.calls)

    def test_github_api_lookalike_host_never_receives_token(self):
        response = mock.MagicMock()
        response.status = 200
        response.read.return_value = b"{}"
        response.__enter__.return_value = response
        with mock.patch("tools.pypi_release_path_audit.urllib.request.urlopen", return_value=response) as urlopen:
            status, _ = Http("placeholder-token").get("https://api.github.com.evil.example/steal")

        self.assertEqual(status, 200)
        self.assertNotIn("Authorization", urlopen.call_args.args[0].headers)

    def test_one_provenance_fetch_failure_keeps_identity_and_tag_unknown(self):
        responses = fixture()
        responses[PROVENANCE[SDIST]] = (503, None)

        results, _ = audit(responses)

        self.assertEqual(results["pypi:provenance"]["status"], "UNKNOWN")
        self.assertEqual(results["pypi:publisher-identity"]["status"], "UNKNOWN")
        self.assertEqual(results["github:release-tag"]["status"], "UNKNOWN")
        self.assertIn("503", results["pypi:publisher-identity"]["detail"])


if __name__ == "__main__":
    unittest.main()
