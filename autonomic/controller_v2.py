#!/usr/bin/env python3
"""Autonomic SRE controller v2 for the declared SZL public estate.

Version 2 keeps the fixed-origin and bounded-recovery authority of v1 while
repairing two operational contracts:

* runtime build-info may prove source identity through an explicit repository or
  through a trusted deployment revision source such as ``env:SZL_GIT_SHA``;
* missing provider authority never consumes a recovery attempt or cooldown.

The controller still cannot execute product actions, accept caller-supplied
origins, edit DNS, change hardware, alter visibility, delete assets, or execute
arbitrary commands.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import json
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

from autonomic import controller as base

CONTROLLER_SCHEMA = "szl.autonomic-sre-controller/v2"
OFFLINE_SCHEMA = "szl.autonomic-sre-contract/v2"
TRUSTED_RUNTIME_REVISION_SOURCES = {
    "env:A11OY_GIT_SHA",
    "env:SZL_GIT_SHA",
}
HF_TOKEN_NAMES = (
    "HF_ORG_TOKEN",
    "HF_WRITE_TOKEN",
    "HF_TOKEN",
    "HUGGINGFACE_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
)


@dataclasses.dataclass(frozen=True)
class SurfaceObservation:
    surface_id: str
    hf_repository: str
    base_url: str
    availability_ok: bool
    source_ok: bool
    source_status: str
    source_repository: str | None
    source_revision: str | None
    expected_revision: str | None
    source_evidence: str
    paths: tuple[base.PathObservation, ...]
    failures: tuple[str, ...]

    @property
    def healthy(self) -> bool:
        return self.availability_ok and self.source_ok

    def receipt(self) -> dict[str, Any]:
        return {
            "id": self.surface_id,
            "hf_repository": self.hf_repository,
            "base_url": self.base_url,
            "availability_ok": self.availability_ok,
            "source_ok": self.source_ok,
            "source_status": self.source_status,
            "source_repository": self.source_repository,
            "source_revision": self.source_revision,
            "expected_revision": self.expected_revision,
            "source_evidence": self.source_evidence,
            "paths": [item.receipt() for item in self.paths],
            "failures": list(self.failures),
        }


class GitHubApi(base.GitHubApi):
    """Extend the v1 client with verified immutable-commit admission."""

    def verified_commit(self, repository: str, revision: str) -> str:
        base.require(bool(base.SHA40.fullmatch(revision)), "commit revision is invalid")
        payload = self._request("GET", f"/repos/{repository}/commits/{revision}")
        base.require(isinstance(payload, dict), "GitHub commit response must be an object")
        observed = base.require_string(payload.get("sha"), "GitHub commit.sha").lower()
        base.require(observed == revision, "GitHub commit response revision drift")
        commit = payload.get("commit")
        base.require(isinstance(commit, dict), "GitHub commit detail is missing")
        verification = commit.get("verification")
        base.require(
            isinstance(verification, dict) and verification.get("verified") is True,
            f"{repository}@{revision} is not cryptographically verified",
        )
        return observed


def _candidates(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rows: list[Mapping[str, Any]] = [payload]
    for key in ("build", "source", "deployment", "data"):
        value = payload.get(key)
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _first(rows: Sequence[Mapping[str, Any]], names: Sequence[str]) -> Any:
    for row in rows:
        for name in names:
            value = row.get(name)
            if value not in (None, ""):
                return value
    return None


def select_source_identity(
    payload: Mapping[str, Any],
    surface: Mapping[str, Any],
) -> dict[str, str]:
    """Select one source identity without inventing missing provider evidence.

    Explicit repository fields remain authoritative. A runtime may omit the
    repository only when the manifest uses exact-default-branch policy and the
    build reports a trusted deployment-injected SHA source plus the exact service
    identity. ``git:HEAD`` and generic repository-local observations are not
    deployment source binding.
    """

    rows = _candidates(payload)
    revision_raw = _first(
        rows,
        ("source_revision", "git_sha", "commit_sha", "sha", "revision"),
    )
    revision = base.require_string(revision_raw, "build-info source revision").lower()
    base.require(
        bool(base.SHA40.fullmatch(revision)),
        "build-info source revision is invalid",
    )

    repository_raw = _first(rows, ("source_repository", "repository", "repo"))
    expected_repository = str(surface["deployment_source_repository"])
    revision_source_raw = _first(
        rows,
        ("source_revision_source", "revision_source"),
    )
    revision_source = str(revision_source_raw or "").strip()

    if repository_raw not in (None, ""):
        repository = base.require_repo(repository_raw, "build-info source repository")
        base.require(
            repository == expected_repository,
            "build-info source repository mismatch",
        )
        evidence = "EXPLICIT_REPOSITORY_AND_REVISION"
    else:
        base.require(
            surface["revision_policy"] == "exact-default-branch",
            "declared-commit surfaces require an explicit source repository",
        )
        base.require(
            revision_source in TRUSTED_RUNTIME_REVISION_SOURCES,
            "runtime revision source is not deployment-bound",
        )
        service = base.require_string(payload.get("service"), "build-info service")
        base.require(
            service == surface["id"],
            "runtime service identity does not match the manifest surface",
        )
        repository = expected_repository
        evidence = f"MANIFEST_PLUS_{revision_source}"

    return {
        "source_repository": repository,
        "source_revision": revision,
        "revision_source": revision_source or "EXPLICIT",
        "evidence": evidence,
    }


def probe_surface(
    surface: Mapping[str, Any],
    *,
    opener: Any,
    github: GitHubApi,
    timeout: int,
    max_response_bytes: int,
    parallelism: int,
) -> SurfaceObservation:
    paths = list(surface["required_paths"])
    rows: dict[str, tuple[base.PathObservation, bytes | None]] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(parallelism, len(paths)),
        thread_name_prefix=f"probe-{surface['id']}",
    ) as pool:
        futures = {
            pool.submit(
                base.probe_path,
                opener,
                base_url=surface["base_url"],
                path=path,
                timeout=timeout,
                max_response_bytes=max_response_bytes,
            ): path
            for path in paths
        }
        for future in concurrent.futures.as_completed(futures):
            path = futures[future]
            try:
                rows[path] = future.result()
            except Exception as exc:
                rows[path] = (
                    base.PathObservation(
                        path=path,
                        status=None,
                        elapsed_ms=0,
                        content_type="",
                        body_sha256=None,
                        body_bytes=None,
                        ok=False,
                        error_kind=base.safe_error_kind(exc),
                    ),
                    None,
                )

    observations = tuple(rows[path][0] for path in paths)
    failures = [
        f"path:{item.path}:{item.error_kind or 'UNHEALTHY'}"
        for item in observations
        if not item.ok
    ]
    availability_ok = not failures
    source_status = "UNVERIFIED"
    source_ok = False
    source_repository: str | None = None
    source_revision: str | None = None
    expected_revision: str | None = None
    source_evidence = "UNAVAILABLE"

    build_body = rows[surface["build_info_path"]][1]
    build_observation = rows[surface["build_info_path"]][0]
    if build_body is None or not build_observation.ok:
        failures.append("source:build-info-unavailable")
    else:
        try:
            payload = json.loads(build_body.decode("utf-8"))
            base.require(isinstance(payload, dict), "build info must be an object")
            identity = select_source_identity(payload, surface)
            source_repository = identity["source_repository"]
            source_revision = identity["source_revision"]
            source_evidence = identity["evidence"]
            if surface["revision_policy"] == "exact-default-branch":
                expected_revision = github.verified_tip(
                    source_repository,
                    surface["default_branch"],
                )
                source_ok = source_revision == expected_revision
                source_status = "EXACT" if source_ok else "DRIFT"
                if not source_ok:
                    failures.append("source:revision-drift")
            else:
                expected_revision = github.verified_commit(
                    source_repository,
                    source_revision,
                )
                source_ok = expected_revision == source_revision
                source_status = "VERIFIED_DECLARED_COMMIT" if source_ok else "DRIFT"
                if not source_ok:
                    failures.append("source:declared-commit-drift")
        except Exception as exc:
            source_status = "INVALID"
            failures.append(f"source:{base.safe_error_kind(exc)}")

    return SurfaceObservation(
        surface_id=surface["id"],
        hf_repository=surface["hf_repository"],
        base_url=surface["base_url"],
        availability_ok=availability_ok,
        source_ok=source_ok,
        source_status=source_status,
        source_repository=source_repository,
        source_revision=source_revision,
        expected_revision=expected_revision,
        source_evidence=source_evidence,
        paths=observations,
        failures=tuple(sorted(set(failures))),
    )


def normalized_previous(previous: Mapping[str, Any] | None) -> dict[str, Any]:
    old = {**base.default_surface_state(), **dict(previous or {})}
    last_result = old.get("last_action_result")
    if isinstance(last_result, dict) and last_result.get("status") == "BLOCKED":
        # A missing token means no provider mutation was attempted. Migrate v1
        # state by releasing attempts and cooldowns that were charged anyway.
        old["recovery_attempts"] = 0
        old["last_action_at"] = None
        old["last_action"] = None
    return old


def plan_recovery(
    *,
    observation: SurfaceObservation,
    previous: Mapping[str, Any] | None,
    hf_stage: str,
    policy: Mapping[str, Any],
    now: dt.datetime,
    action_budget_available: bool,
) -> base.RecoveryPlan:
    old = normalized_previous(previous)
    recovery = policy["recovery"]
    now_text = now.isoformat().replace("+00:00", "Z")
    if observation.healthy:
        return base.RecoveryPlan(
            state="HEALTHY",
            consecutive_failures=0,
            recovery_attempts=0,
            action=None,
            reason="all required routes and source checks passed",
            last_action_at=old.get("last_action_at"),
        )
    if observation.availability_ok and not observation.source_ok:
        return base.RecoveryPlan(
            state="INCIDENT",
            consecutive_failures=int(old.get("consecutive_failures") or 0) + 1,
            recovery_attempts=int(old.get("recovery_attempts") or 0),
            action=None,
            reason="source integrity drift cannot be repaired by a runtime restart",
            last_action_at=old.get("last_action_at"),
        )

    failures = int(old.get("consecutive_failures") or 0) + 1
    attempts = int(old.get("recovery_attempts") or 0)
    if failures < policy["probe"]["failure_threshold"]:
        return base.RecoveryPlan(
            state="SUSPECT",
            consecutive_failures=failures,
            recovery_attempts=attempts,
            action=None,
            reason="failure threshold not yet reached",
            last_action_at=old.get("last_action_at"),
        )

    stage = (hf_stage or "UNKNOWN").upper()
    if stage in recovery["transitional_stages"]:
        return base.RecoveryPlan(
            state="RECOVERING",
            consecutive_failures=failures,
            recovery_attempts=attempts,
            action=None,
            reason=f"Hugging Face runtime is already transitional ({stage})",
            last_action_at=old.get("last_action_at"),
        )
    if attempts >= recovery["max_attempts_before_incident"]:
        return base.RecoveryPlan(
            state="INCIDENT",
            consecutive_failures=failures,
            recovery_attempts=attempts,
            action=None,
            reason="bounded automatic recovery budget exhausted",
            last_action_at=old.get("last_action_at"),
        )
    last_action = base.parse_time(old.get("last_action_at"))
    if last_action is not None:
        age = now - last_action
        if age < dt.timedelta(minutes=recovery["cooldown_minutes"]):
            return base.RecoveryPlan(
                state="DEGRADED",
                consecutive_failures=failures,
                recovery_attempts=attempts,
                action=None,
                reason="restart cooldown is active",
                last_action_at=old.get("last_action_at"),
            )
    if not recovery["enabled"]:
        return base.RecoveryPlan(
            state="DEGRADED",
            consecutive_failures=failures,
            recovery_attempts=attempts,
            action=None,
            reason="automatic recovery is disabled by policy",
            last_action_at=old.get("last_action_at"),
        )
    if not action_budget_available:
        return base.RecoveryPlan(
            state="DEGRADED",
            consecutive_failures=failures,
            recovery_attempts=attempts,
            action=None,
            reason="per-cycle recovery action budget is exhausted",
            last_action_at=old.get("last_action_at"),
        )

    if stage in recovery["paused_stages"]:
        action = "resume"
    elif stage in recovery["terminal_stages"]:
        action = "factory-restart"
    else:
        action = "soft-restart"
    return base.RecoveryPlan(
        state="RECOVERING",
        consecutive_failures=failures,
        recovery_attempts=attempts + 1,
        action=action,
        reason=f"bounded {action} admitted after {failures} consecutive failures",
        last_action_at=now_text,
    )


def make_surface_state(
    *,
    previous: Mapping[str, Any] | None,
    observation: SurfaceObservation,
    plan: base.RecoveryPlan,
    stage: str,
    action_result: Mapping[str, Any] | None,
    now_text: str,
) -> dict[str, Any]:
    old = normalized_previous(previous)
    result = dict(old)
    result.update(
        {
            "state": plan.state,
            "consecutive_failures": plan.consecutive_failures,
            "recovery_attempts": plan.recovery_attempts,
            "last_hf_stage": stage,
            "last_reason": plan.reason,
            "source_status": observation.source_status,
            "source_evidence": observation.source_evidence,
            "last_probe_ok": observation.healthy,
        }
    )
    if observation.healthy:
        if old.get("state") != "HEALTHY" or not old.get("last_success_at"):
            result["last_success_at"] = now_text
        result["last_failure_at"] = old.get("last_failure_at")
        result["last_blocked_action"] = None
    else:
        result["last_failure_at"] = now_text

    if plan.action:
        provider_status = str((action_result or {}).get("status") or "FAILED")
        if provider_status == "BLOCKED":
            result["state"] = "DEGRADED"
            result["recovery_attempts"] = int(old.get("recovery_attempts") or 0)
            result["last_action"] = None
            result["last_action_at"] = None
            result["last_blocked_action"] = plan.action
            result["last_action_result"] = dict(action_result or {})
            result["last_reason"] = (
                "recovery authority unavailable; attempt and cooldown budgets not consumed"
            )
        else:
            result["last_action"] = plan.action
            result["last_action_at"] = plan.last_action_at
            result["last_blocked_action"] = None
            result["last_action_result"] = dict(action_result or {})
            if not action_result or action_result.get("ok") is not True:
                result["state"] = "DEGRADED"
    return result


def select_hf_token(
    environ: Mapping[str, str] | None = None,
) -> tuple[str | None, str | None]:
    source = environ if environ is not None else os.environ
    for name in HF_TOKEN_NAMES:
        value = str(source.get(name) or "").strip()
        if value:
            return value, name
    return None, None


def offline_contract(
    policy: Mapping[str, Any],
    policy_sha256: str,
) -> dict[str, Any]:
    receipt = base.offline_contract(policy, policy_sha256)
    receipt.update(
        {
            "schema": OFFLINE_SCHEMA,
            "controller_schema": CONTROLLER_SCHEMA,
            "trusted_runtime_revision_sources": sorted(
                TRUSTED_RUNTIME_REVISION_SOURCES
            ),
            "hf_token_source_names": list(HF_TOKEN_NAMES),
            "blocked_authority_consumes_attempt": False,
            "declared_commit_verification_required": True,
        }
    )
    return receipt


def run_live(
    *,
    policy: Mapping[str, Any],
    policy_sha256: str,
    output: Path,
    dry_run: bool,
) -> int:
    repository = os.getenv("GITHUB_REPOSITORY", "").strip()
    if repository:
        base.require(
            repository == policy["controller_repository"],
            "workflow repository does not match policy authority",
        )
    github_token = (
        os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or ""
    ).strip() or None
    github = GitHubApi(
        token=github_token,
        controller_repository=policy["controller_repository"],
        timeout=policy["probe"]["timeout_seconds"],
        max_response_bytes=max(
            policy["probe"]["max_response_bytes"],
            1_048_576,
        ),
    )
    controller_tip = github.verified_tip(
        policy["controller_repository"],
        policy["controller_branch"],
    )
    workflow_sha = os.getenv("GITHUB_SHA", "").strip()
    if workflow_sha:
        base.require(
            workflow_sha == controller_tip,
            "controller workflow is not running from the exact verified default-branch tip",
        )
    manifest, manifest_revision, manifest_sha256 = base.load_signed_manifest(
        github,
        policy,
    )
    state_issue = (
        github.find_state_issue(policy["state_issue"]["title"])
        if github_token
        else None
    )
    previous_state = base.extract_state(state_issue.get("body") if state_issue else None)
    previous_surfaces = previous_state.get("surfaces") or {}
    now = dt.datetime.now(dt.timezone.utc)
    now_text = now.isoformat().replace("+00:00", "Z")
    opener = base.build_probe_opener()

    observations: dict[str, SurfaceObservation] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(
            policy["probe"]["parallelism"],
            len(manifest["surfaces"]),
        ),
        thread_name_prefix="estate-v2",
    ) as pool:
        futures = {
            pool.submit(
                probe_surface,
                surface,
                opener=opener,
                github=github,
                timeout=policy["probe"]["timeout_seconds"],
                max_response_bytes=policy["probe"]["max_response_bytes"],
                parallelism=max(1, policy["probe"]["parallelism"] // 2),
            ): surface
            for surface in manifest["surfaces"]
        }
        for future in concurrent.futures.as_completed(futures):
            surface = futures[future]
            try:
                observations[surface["id"]] = future.result()
            except Exception as exc:
                observations[surface["id"]] = SurfaceObservation(
                    surface_id=surface["id"],
                    hf_repository=surface["hf_repository"],
                    base_url=surface["base_url"],
                    availability_ok=False,
                    source_ok=False,
                    source_status="UNAVAILABLE",
                    source_repository=None,
                    source_revision=None,
                    expected_revision=None,
                    source_evidence="UNAVAILABLE",
                    paths=(),
                    failures=(f"controller:{base.safe_error_kind(exc)}",),
                )

    hf_token, hf_token_source = select_hf_token()
    hf = base.HuggingFaceControl(hf_token)
    actions_left = 0 if dry_run else policy["recovery"]["max_actions_per_cycle"]
    surface_states: dict[str, Any] = {}
    actions: list[dict[str, Any]] = []
    report_surfaces: list[dict[str, Any]] = []
    attempted_mutations = 0

    for surface in manifest["surfaces"]:
        observation = observations[surface["id"]]
        previous = previous_surfaces.get(surface["id"])
        stage = hf.stage(surface["hf_repository"])
        plan = plan_recovery(
            observation=observation,
            previous=previous if isinstance(previous, dict) else None,
            hf_stage=stage,
            policy=policy,
            now=now,
            action_budget_available=actions_left > 0,
        )
        action_result: dict[str, Any] | None = None
        if plan.action:
            if dry_run:
                action_result = {
                    "ok": False,
                    "status": "DRY_RUN",
                    "action": plan.action,
                    "secret_values_recorded": False,
                }
            else:
                action_result = hf.recover(surface["hf_repository"], plan.action)
                if action_result.get("status") != "BLOCKED":
                    actions_left -= 1
                    attempted_mutations += 1
                actions.append(
                    {
                        "surface": surface["id"],
                        "hf_repository": surface["hf_repository"],
                        "action": plan.action,
                        "result": action_result,
                    }
                )
        current = make_surface_state(
            previous=previous if isinstance(previous, dict) else None,
            observation=observation,
            plan=plan,
            stage=stage,
            action_result=action_result,
            now_text=now_text,
        )
        surface_states[surface["id"]] = current
        row = observation.receipt()
        row.update(
            {
                "hf_stage": stage,
                "state_before": (
                    previous.get("state", "UNKNOWN")
                    if isinstance(previous, dict)
                    else "UNKNOWN"
                ),
                "state_after": current["state"],
                "consecutive_failures": current["consecutive_failures"],
                "recovery_attempts": current["recovery_attempts"],
                "planned_action": plan.action,
                "action_result": action_result,
                "reason": current["last_reason"],
            }
        )
        report_surfaces.append(row)

    current_state = {
        "schema": base.STATE_SCHEMA,
        "controller_schema": CONTROLLER_SCHEMA,
        "updated_at": now_text,
        "controller_revision": controller_tip,
        "manifest_revision": manifest_revision,
        "manifest_sha256": manifest_sha256,
        "policy_sha256": policy_sha256,
        "hf_token_source_name": hf_token_source or "UNAVAILABLE",
        "surfaces": surface_states,
        "secret_values_recorded": False,
    }
    healthy_count = sum(
        item["state"] == "HEALTHY" for item in surface_states.values()
    )
    report = {
        "schema": base.RECEIPT_SCHEMA,
        "controller_schema": CONTROLLER_SCHEMA,
        "cycle_id": f"sre2_{uuid.uuid4().hex}",
        "generated_at": now_text,
        "controller_repository": policy["controller_repository"],
        "controller_revision": controller_tip,
        "manifest_repository": policy["source_manifest"]["repository"],
        "manifest_revision": manifest_revision,
        "manifest_sha256": manifest_sha256,
        "policy_sha256": policy_sha256,
        "dry_run": dry_run,
        "public_surface_count": len(surface_states),
        "healthy_surface_count": healthy_count,
        "all_healthy": healthy_count == len(surface_states),
        "hf_token_source_name": hf_token_source or "UNAVAILABLE",
        "attempted_mutation_count": attempted_mutations,
        "actions": actions,
        "surfaces": report_surfaces,
        "authority": {
            "fixed_manifest": True,
            "fixed_https_origins": True,
            "verified_declared_commits": True,
            "trusted_runtime_revision_sources": sorted(
                TRUSTED_RUNTIME_REVISION_SOURCES
            ),
            "blocked_authority_consumes_attempt": False,
            "hf_restart_only": True,
            "arbitrary_shell": False,
            "dns_mutation": False,
            "asset_deletion": False,
            "visibility_mutation": False,
            "max_actions_per_cycle": policy["recovery"]["max_actions_per_cycle"],
        },
        "secret_values_recorded": False,
    }
    report["receipt_sha256"] = base.sha256_hex(base.canonical_json(report))
    base.write_json_atomic(output, report)
    output.with_suffix(output.suffix + ".sha256").write_text(
        report["receipt_sha256"] + "\n",
        encoding="ascii",
    )

    if not dry_run:
        base.require(
            bool(github_token),
            "GITHUB_TOKEN is required for durable controller state",
        )
        if base.state_requires_write(
            previous_state,
            current_state,
            heartbeat_minutes=policy["state_issue"]["heartbeat_minutes"],
            now=now,
        ):
            github.upsert_state_issue(
                title=policy["state_issue"]["title"],
                body=base.issue_body(current_state),
                existing=state_issue,
            )
    return 0


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument(
        "--policy",
        type=Path,
        default=Path("autonomic/policy.json"),
    )
    command.add_argument(
        "--output",
        type=Path,
        default=Path("reports/autonomic-sre.json"),
    )
    command.add_argument("--dry-run", action="store_true")
    command.add_argument("--offline-contract-only", action="store_true")
    return command


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        policy, policy_sha256 = base.load_policy(args.policy)
        if args.offline_contract_only:
            receipt = offline_contract(policy, policy_sha256)
            base.write_json_atomic(args.output, receipt)
            print(json.dumps(receipt, indent=2, sort_keys=True))
            return 0
        return run_live(
            policy=policy,
            policy_sha256=policy_sha256,
            output=args.output,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        failure = {
            "schema": base.RECEIPT_SCHEMA,
            "controller_schema": CONTROLLER_SCHEMA,
            "generated_at": base.utc_now(),
            "ok": False,
            "error_kind": base.safe_error_kind(exc),
            "error": base.REDACTED_ERROR,
            "secret_values_recorded": False,
        }
        try:
            base.write_json_atomic(args.output, failure)
        except Exception:
            pass
        print(json.dumps(failure, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
