from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import refresh_snapshot as refresh_module
from census import report as report_module

PRIVATE_SENTINEL = "PRIVATE-HF-ASSET-SENTINEL-7f4c2a"
PRIVATE_GITHUB_SENTINEL = "private-repo-sentinel-91c82d"
TOP_LEVEL_SENTINEL = "PRIVATE-TOP-LEVEL-SENTINEL-72a4c1"
RELATED_PRIVATE_SENTINEL = "PRIVATE-RELATED-ID-SENTINEL-07bd13"
MESSAGE_SENTINEL = "PRIVATE-MESSAGE-SENTINEL-c61ab8"
ERROR_SENTINEL = "PRIVATE-HF-ERROR-SENTINEL-8de917"


def github_data() -> dict:
    return {
        "discovery": {"complete": True, "scope": "organization-api"},
        "summary": {"total": 1},
        "repos": {
            "control": {
                "visibility": "public",
                "archived": False,
                "ci": "success",
                "ci_coverage": "COMPLETE",
                "ci_scope": "latest-per-workflow-within-recent-default-branch-push-window",
                "run_window_observed": 1,
                "default_branch_push_runs_total": 1,
                "protected": True,
                "classification": "control-plane",
            }
        },
        "alerts": {
            "code_scanning_high": 0,
            "secret_scanning_open": 0,
            "dependabot_open": 0,
            "complete": True,
            "errors": {},
        },
    }


def sensitive_github_data() -> dict:
    data = github_data()
    data["message"] = MESSAGE_SENTINEL
    data["unknown_source_field"] = TOP_LEVEL_SENTINEL
    data["repos"]["control"]["message"] = MESSAGE_SENTINEL
    data["repos"][PRIVATE_GITHUB_SENTINEL] = {
        "visibility": "private",
        "archived": False,
        "ci": "success",
        "protected": True,
        "classification": "production",
        "message": MESSAGE_SENTINEL,
    }
    data["repos"]["ambiguous-visibility"] = {
        "private": False,
        "archived": False,
        "ci": "success",
        "protected": True,
        "classification": "production",
    }
    data["repos"]["contradictory-private-flag"] = {
        "visibility": "public",
        "private": True,
        "archived": False,
        "ci": "success",
        "protected": True,
        "classification": "production",
    }
    data["repos"]["contradictory-public-flag"] = {
        "visibility": "private",
        "public": True,
        "archived": False,
        "ci": "success",
        "protected": True,
        "classification": "production",
    }
    data["repos"]["explicit-public-false"] = {
        "visibility": "public",
        "public": False,
        "archived": False,
        "ci": "success",
        "protected": True,
        "classification": "production",
    }
    return data


def huggingface_data() -> dict:
    empty = {"ok": True, "count": 0, "items": []}
    return {
        "assets": {
            "models": dict(empty),
            "datasets": dict(empty),
            "spaces": dict(empty),
            "kernels": dict(empty),
            "collections": dict(empty),
            "buckets": dict(empty),
        }
    }


def _asset(items: list[dict], *, error: str | None = None) -> dict:
    return {"ok": True, "count": 999, "error": error, "items": items}


def sensitive_huggingface_data() -> dict:
    public_model = {
        "id": "SZLHOLDINGS/public-model",
        "private": False,
        "related_private_id": RELATED_PRIVATE_SENTINEL,
        "message": MESSAGE_SENTINEL,
        "sha": "a" * 40,
        "card_present": True,
        "card_state": "COMPLETE",
        "license_declared": True,
        "contract": "transformers-checkpoint",
        "weight_state": "weights-present",
        "artifact_state": "artifact-present",
        "weight_files_observed": ["model.safetensors"],
        "estimator_files_observed": [],
        "model_artifact_files_observed": ["model.safetensors"],
    }
    private_model = {
        "id": PRIVATE_SENTINEL,
        "private": True,
        "sha": None,
        "card_present": False,
        "card_state": "INCOMPLETE",
        "license_declared": False,
        "contract": "serialized-estimator",
        "artifact_state": "artifact-present",
        "estimator_files_observed": [f"{PRIVATE_SENTINEL}.pkl"],
        "model_artifact_files_observed": [f"{PRIVATE_SENTINEL}.pkl"],
    }
    unknown_visibility_model = {
        "id": f"{PRIVATE_SENTINEL}-unknown-visibility",
        "private": None,
        "sha": "b" * 40,
        "card_present": True,
        "card_state": "COMPLETE",
        "license_declared": True,
    }
    invalid_identifier_model = {
        "id": f"SZLHOLDINGS/public?{PRIVATE_SENTINEL}",
        "private": False,
        "sha": "b" * 40,
    }
    public_dataset = {
        "id": "SZLHOLDINGS/public-dataset",
        "private": False,
        "sha": "c" * 40,
        "card_present": True,
        "card_state": "COMPLETE",
        "license_declared": True,
    }
    private_dataset = {
        "id": f"{PRIVATE_SENTINEL}-dataset",
        "private": True,
        "sha": "d" * 40,
        "card_present": True,
        "card_state": "COMPLETE",
        "license_declared": True,
    }
    public_space = {
        "id": "SZLHOLDINGS/public-space",
        "private": False,
        "sha": "e" * 40,
        "sdk": "static",
        "stage": "RUNNING",
        "http": 200,
        "healthz": None,
        "source_binding_state": "NOT_APPLICABLE",
        "operational_state": "STATIC_REACHABLE",
        "card_present": True,
        "card_state": "COMPLETE",
        "license_declared": True,
    }
    private_space = {
        "id": f"{PRIVATE_SENTINEL}-space",
        "private": True,
        "sha": "f" * 40,
        "sdk": "docker",
        "stage": "RUNNING",
        "source_binding_state": "UNAVAILABLE",
        "card_present": False,
        "card_state": "INCOMPLETE",
        "license_declared": False,
    }
    public_kernel = {
        "id": "SZLHOLDINGS/public-kernel",
        "private": False,
        "metadata_state": "OBSERVED",
        "contract_state": "COMPLETE",
    }
    private_kernel = {
        "id": f"{PRIVATE_SENTINEL}-kernel",
        "private": True,
        "metadata_state": "OBSERVED",
        "contract_state": "INCOMPLETE",
    }
    public_collection = {
        "slug": "SZLHOLDINGS/public-collection",
        "private": False,
        "message": MESSAGE_SENTINEL,
        "items": [
            {"type": "model", "id": public_model["id"]},
            {"type": "model", "id": private_model["id"]},
        ],
        "item_counts": {"model": 2},
        "detail_error": ERROR_SENTINEL,
    }
    private_collection = {
        "slug": f"{PRIVATE_SENTINEL}-collection",
        "private": True,
        "items": [{"type": "model", "id": private_model["id"]}],
        "item_counts": {"model": 1},
    }
    public_bucket = {
        "id": "SZLHOLDINGS/public-bucket",
        "private": False,
        "documentation_state": "COMPLETE",
    }
    private_bucket = {
        "id": f"{PRIVATE_SENTINEL}-bucket",
        "private": True,
        "documentation_state": "INCOMPLETE",
    }
    return {
        "organization": "SZLHOLDINGS",
        "authentication": {
            "schema": "szl.hf-authentication-evidence/v2",
            "credential_present": True,
            "identity_authenticated": True,
            "user_identity_observed": True,
            "target_organization": "SZLHOLDINGS",
            "target_organization_match_observed": True,
            "organization_membership_observed": True,
            "organization_read_role_observed": True,
            "security_restrictions_clear_observed": True,
            "resource_groups_absent_observed": True,
            "credential_class": "FINE_GRAINED",
            "fine_grained_metadata_observed": True,
            "org_scope_candidate_observed": True,
            "unknown_grants_observed": False,
            "global_permissions_state": "NONE",
            "inventory_scope": "AUTHENTICATED_BOUNDED",
            "probe_state": "AUTHENTICATED",
            "principal": PRIVATE_SENTINEL,
            "raw_scope": {"entity": PRIVATE_SENTINEL},
        },
        "assets": {
            "models": _asset(
                [
                    public_model,
                    private_model,
                    unknown_visibility_model,
                    invalid_identifier_model,
                ]
            ),
            "datasets": _asset([public_dataset, private_dataset]),
            "spaces": _asset([public_space, private_space]),
            "kernels": _asset([public_kernel, private_kernel]),
            "collections": _asset([public_collection, private_collection]),
            "buckets": _asset([public_bucket, private_bucket]),
        },
        "collection_coverage": {
            "models": {
                "public_total": 999,
                "covered": 999,
                "missing": [PRIVATE_SENTINEL],
            }
        },
        "summary": {"models": 999, "private_detail": PRIVATE_SENTINEL},
        "error_detail": ERROR_SENTINEL,
        "message": MESSAGE_SENTINEL,
        "unknown_source_field": TOP_LEVEL_SENTINEL,
    }


def dns_data() -> dict:
    return {
        domain: {"spf": True, "dmarc": True, "dmarc_reject": True}
        for domain in (
            "szlholdings.com",
            "a-11-oy.com",
            "a11oy.net",
            "alloyszlholdings.com",
            "killinchu.net",
        )
    }


class ReportAssemblyContractTests(unittest.TestCase):
    def setUp(self) -> None:
        report_module._CACHE = {"data": None, "ts": 0.0}

    def test_report_binds_governance_and_survives_json_round_trip(self) -> None:
        with (
            patch.object(report_module, "collect_github", return_value=github_data()),
            patch.object(
                report_module, "collect_huggingface", return_value=huggingface_data()
            ),
            patch.object(report_module, "collect_sites", return_value={}),
            patch.object(report_module, "collect_dns", return_value=dns_data()),
        ):
            result = report_module.build_report(use_cache=False)

        restored = json.loads(json.dumps(result, sort_keys=True))
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["projection_schema"], "szl.estate-public-projection/v1")
        self.assertEqual(result["exposure"], "public")
        self.assertIn("governance", result)
        self.assertEqual(
            result["governance"]["generated_at_from_census"],
            result["generated_at"],
        )
        self.assertEqual(restored["sources"], result["sources"])
        self.assertEqual(restored["governance"], result["governance"])

    def test_collector_exception_remains_explicit_and_controls_stay_unknown(
        self,
    ) -> None:
        with (
            patch.object(report_module, "collect_github", return_value=github_data()),
            patch.object(
                report_module,
                "collect_huggingface",
                side_effect=RuntimeError("authenticated inventory denied"),
            ),
            patch.object(report_module, "collect_sites", return_value={}),
            patch.object(report_module, "collect_dns", return_value=dns_data()),
        ):
            internal = report_module.build_report(exposure="internal", use_cache=False)
            result = report_module.build_report()

        self.assertIs(result["sources"]["huggingface"]["ok"], False)
        self.assertEqual(
            internal["sources"]["huggingface"]["error"],
            "authenticated inventory denied",
        )
        self.assertEqual(
            result["sources"]["huggingface"]["error"],
            "SOURCE_UNAVAILABLE",
        )
        self.assertNotIn("authenticated inventory denied", json.dumps(result))
        controls = {
            control["id"]: control for control in result["governance"]["controls"]
        }
        self.assertEqual(controls["HF-INVENTORY"]["status"], "UNKNOWN")
        self.assertEqual(
            result["governance"]["generated_at_from_census"],
            result["generated_at"],
        )

    def test_default_public_projection_is_a_closed_evidence_boundary(self) -> None:
        with (
            patch.object(
                report_module, "collect_github", return_value=sensitive_github_data()
            ),
            patch.object(
                report_module,
                "collect_huggingface",
                return_value=sensitive_huggingface_data(),
            ) as hf_collector,
            patch.object(report_module, "collect_sites", return_value={}),
            patch.object(report_module, "collect_dns", return_value=dns_data()),
        ):
            report_module.build_report(exposure="internal", use_cache=False)
            report_module._CACHE["data"]["unknown_top_level"] = TOP_LEVEL_SENTINEL
            public = report_module.build_report()
            internal = report_module.build_report(exposure="internal")

        hf_collector.assert_called_once_with()
        self.assertEqual(public["exposure"], "public")
        self.assertEqual(internal["exposure"], "internal")
        self.assertEqual(public["generated_at"], internal["generated_at"])
        self.assertEqual(
            set(public),
            {
                "schema_version",
                "projection_schema",
                "generated_at",
                "collection",
                "exposure",
                "source_snapshot_sha256",
                "sources",
                "governance",
            },
        )

        encoded_public = json.dumps(public, sort_keys=True)
        encoded_internal = json.dumps(internal, sort_keys=True)
        for sentinel in (
            PRIVATE_SENTINEL,
            PRIVATE_GITHUB_SENTINEL,
            TOP_LEVEL_SENTINEL,
            RELATED_PRIVATE_SENTINEL,
            MESSAGE_SENTINEL,
            ERROR_SENTINEL,
        ):
            self.assertNotIn(sentinel, encoded_public)
            self.assertIn(sentinel, encoded_internal)

        github_source = public["sources"]["github"]
        self.assertIs(github_source["ok"], False)
        self.assertEqual(github_source["diagnostic_state"], "PUBLIC_SUBSET")
        self.assertEqual(set(github_source["data"]["repos"]), {"control"})
        self.assertEqual(github_source["data"]["summary"]["total"], 1)
        self.assertIs(github_source["data"]["discovery"]["complete"], False)
        self.assertIs(github_source["data"]["alerts"]["complete"], False)

        hf_data = public["sources"]["huggingface"]["data"]
        for kind, asset in hf_data["assets"].items():
            self.assertIs(asset["ok"], True, kind)
            self.assertEqual(asset["count"], 1, kind)
            self.assertEqual(len(asset["items"]), 1, kind)
            self.assertIs(asset["items"][0]["private"], False, kind)
            self.assertEqual(hf_data["summary"][kind], 1, kind)

        collection = hf_data["assets"]["collections"]["items"][0]
        self.assertNotIn("items", collection)
        self.assertNotIn("item_counts", collection)
        self.assertNotIn("detail_error", collection)
        self.assertNotIn("message", collection)
        self.assertIsNone(hf_data["assets"]["models"]["error"])
        self.assertNotIn("collection_coverage", hf_data)

        public_model = hf_data["assets"]["models"]["items"][0]
        self.assertNotIn("related_private_id", public_model)
        self.assertNotIn("message", public_model)

        self.assertEqual(
            hf_data["authentication"],
            {
                "evidence_scope": "PUBLIC_PROJECTION",
                "organization_complete": False,
            },
        )

        controls = {
            control["id"]: control for control in public["governance"]["controls"]
        }
        self.assertEqual(controls["GH-INVENTORY"]["status"], "UNKNOWN")
        self.assertEqual(controls["GH-ACTIVE-CI"]["status"], "UNKNOWN")
        self.assertEqual(controls["HF-INVENTORY"]["status"], "UNKNOWN")

        # The public object is freshly constructed; mutating it cannot alter the
        # cached internal evidence later returned to an explicit caller.
        public_model["id"] = "mutated-public-copy"
        cached_internal = report_module.build_report(exposure="internal")
        internal_ids = {
            item["id"]
            for item in cached_internal["sources"]["huggingface"]["data"]["assets"][
                "models"
            ]["items"]
        }
        self.assertIn("SZLHOLDINGS/public-model", internal_ids)
        self.assertNotIn("mutated-public-copy", internal_ids)

    def test_public_projection_is_idempotent_and_does_not_mutate_input(self) -> None:
        internal = {
            "schema_version": 2,
            "generated_at": "2026-08-26T20:00:00Z",
            "exposure": "internal",
            "unknown_top_level": TOP_LEVEL_SENTINEL,
            "sources": {
                "github": {"ok": True, "data": sensitive_github_data()},
                "huggingface": {
                    "ok": True,
                    "data": sensitive_huggingface_data(),
                },
                "sites": {"ok": True, "data": {}},
                "dns": {"ok": True, "data": dns_data()},
                "unknown_source": {
                    "ok": True,
                    "data": {"message": MESSAGE_SENTINEL},
                },
            },
            "governance": {"private_evidence": PRIVATE_SENTINEL},
        }
        before = copy.deepcopy(internal)

        public = report_module.project_public_report(internal)

        self.assertEqual(internal, before)
        self.assertEqual(public, report_module.project_public_report(public))
        self.assertEqual(
            set(public["sources"]), {"github", "huggingface", "sites", "dns"}
        )
        encoded = json.dumps(public, sort_keys=True)
        for sentinel in (
            PRIVATE_SENTINEL,
            PRIVATE_GITHUB_SENTINEL,
            TOP_LEVEL_SENTINEL,
            RELATED_PRIVATE_SENTINEL,
            MESSAGE_SENTINEL,
            ERROR_SENTINEL,
        ):
            self.assertNotIn(sentinel, encoded)

    def test_invalid_exposure_is_rejected_before_collection(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported report exposure"):
            report_module.build_report(exposure="partner", use_cache=False)

    def test_refresh_writes_internal_receipt_source_and_public_snapshot(self) -> None:
        internal = {
            "schema_version": 2,
            "generated_at": "2026-08-26T20:00:00Z",
            "exposure": "internal",
            "sources": {"huggingface": {"ok": True}},
            "private": PRIVATE_SENTINEL,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public_path = root / "static" / "data.json"
            internal_path = root / "census-internal.json"
            stdout = io.StringIO()
            with (
                patch.object(
                    refresh_module,
                    "build_report",
                    return_value=internal,
                ) as build,
                patch.object(
                    refresh_module,
                    "project_public_report",
                    wraps=report_module.project_public_report,
                ) as project,
                patch.object(refresh_module, "PUBLIC_SNAPSHOT", public_path),
                patch.object(refresh_module, "INTERNAL_SNAPSHOT", internal_path),
                patch.object(refresh_module.sys, "argv", ["refresh_snapshot.py"]),
                redirect_stdout(stdout),
            ):
                exit_code = refresh_module.main()

            persisted_public = json.loads(public_path.read_text(encoding="utf-8"))
            persisted_internal = json.loads(internal_path.read_text(encoding="utf-8"))
            staged_files = list(root.rglob("*.tmp"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            persisted_public,
            report_module.project_public_report(persisted_internal),
            self.assertEqual(
                persisted_public["source_snapshot_sha256"],
                hashlib.sha256(
                    report_module.serialize_report(persisted_internal).encode("utf-8")
                ).hexdigest(),
            ),
        )
        self.assertNotIn(PRIVATE_SENTINEL, json.dumps(persisted_public))
        self.assertEqual(persisted_internal["private"], PRIVATE_SENTINEL)
        build.assert_called_once()
        self.assertEqual(build.call_args.kwargs["exposure"], "internal")
        project.assert_called_once_with(internal)
        self.assertEqual(staged_files, [])
        self.assertNotIn(PRIVATE_SENTINEL, stdout.getvalue())
        self.assertNotIn("census-internal.json", stdout.getvalue())

    def test_refresh_preserves_both_destinations_when_serialization_fails(self) -> None:
        internal = {
            "schema_version": 2,
            "generated_at": "2026-08-26T20:00:00Z",
            "exposure": "internal",
            "sources": {"huggingface": {"ok": True}},
        }
        unserializable_public = {"not_json": object()}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public_path = root / "static" / "data.json"
            public_path.parent.mkdir()
            public_path.write_text("old-public\n", encoding="utf-8")
            internal_path = root / "census-internal.json"
            internal_path.write_text("old-internal\n", encoding="utf-8")
            with (
                patch.object(refresh_module, "build_report", return_value=internal),
                patch.object(
                    refresh_module,
                    "project_public_report",
                    return_value=unserializable_public,
                ),
                patch.object(refresh_module, "PUBLIC_SNAPSHOT", public_path),
                patch.object(refresh_module, "INTERNAL_SNAPSHOT", internal_path),
                self.assertRaises(TypeError),
            ):
                refresh_module.main()

            self.assertEqual(public_path.read_text(encoding="utf-8"), "old-public\n")
            self.assertEqual(
                internal_path.read_text(encoding="utf-8"), "old-internal\n"
            )
            self.assertEqual(list(root.rglob("*.tmp")), [])

    def test_workflow_upload_is_public_allowlist_and_internal_is_ephemeral(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / ".github" / "workflows" / "scheduled-estate-census.yml"
        ).read_text(encoding="utf-8")
        upload_block = workflow.split("uses: actions/upload-artifact@", 1)[1].split(
            "if-no-files-found:", 1
        )[0]

        self.assertIn("--snapshot census-internal.json", workflow)
        self.assertIn("rm -f -- census-internal.json", workflow)
        self.assertLess(
            workflow.index("rm -f -- census-internal.json"),
            workflow.index("uses: actions/upload-artifact@"),
        )
        self.assertNotIn("census-internal.json", upload_block)
        self.assertIn("census-public.json", upload_block)
        self.assertNotIn("static/data.json", upload_block)
        self.assertIn("--public-snapshot static/data.json --publish-snapshot census-public.json", workflow)
        self.assertIn("census-receipt.json", upload_block)
        ignored = (root / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("/census-internal.json", ignored)

    def test_public_dashboard_does_not_infer_withheld_collection_evidence(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        dashboard = (root / "static" / "index.html").read_text(encoding="utf-8")

        self.assertIn("coverage unavailable (public projection)", dashboard)
        self.assertIn("membership withheld/unknown", dashboard)
        self.assertNotIn("const coverage=hf.collection_coverage||{};", dashboard)
        self.assertNotIn("Object.values(col.item_counts||{})", dashboard)

    def test_workflow_is_schedule_only_and_binds_exact_default_branch(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (
            root / ".github" / "workflows" / "scheduled-estate-census.yml"
        ).read_text(encoding="utf-8")

        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertIn(
            "if: github.ref == format('refs/heads/{0}', "
            "github.event.repository.default_branch)",
            workflow,
        )
        self.assertIn("ref: ${{ github.sha }}", workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', workflow)
        self.assertLess(
            workflow.index("Verify default-branch checkout subject"),
            workflow.index("HF_TOKEN:"),
        )

    def test_container_context_excludes_internal_evidence_and_uses_copy_allowlist(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
        dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")

        for excluded in (
            "census-internal.json",
            "census-receipt.json",
            "*.tmp",
            "*.patch",
            "*.rej",
        ):
            self.assertIn(excluded, dockerignore)
        self.assertNotIn("COPY . /app", dockerfile)
        self.assertIn("COPY census/report.py /app/census/report.py", dockerfile)
        self.assertIn("COPY census/space_readiness.py /app/census/space_readiness.py", dockerfile)
        self.assertIn("COPY static/data.json /app/static/data.json", dockerfile)
        self.assertIn("USER 65532:65532", dockerfile)
        ci_workflow = (root / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("docker image inspect --format '{{.Config.User}}'", ci_workflow)
        self.assertIn('docker exec "$cid" id -u', ci_workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
