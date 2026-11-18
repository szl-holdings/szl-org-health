#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SZL bounded database agent: observe -> diagnose -> plan -> verify -> HOLD.

Consumes *existing* sanitized admission receipts. It cannot connect to a
database, generate/execute SQL, change policy, or authorize effects.
Its action graph is fixed by reviewed source rather than an LLM prompt.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

try:
    from tools.database_catalog_admission import read_file, InputError, policy_data
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_catalog_admission import read_file, InputError, policy_data

SCHEMA = "szl.database-agent-workplan/v1"
POLICY_SCHEMA = "szl.database-agent-policy/v1"
ROLE_SCHEMA = "szl.database-audit-role-posture/v1"
CATALOG_SCHEMA = "szl.database-catalog-admission/v1"
FRONTIER_SCHEMA = "szl.database-causal-frontier-admission/v1"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CODE = re.compile(r"[A-Z][A-Z0-9_]{2,80}\Z")
STAGES = frozenset({"source_ledger", "transactional_outbox", "retrieval_index",
                    "api_projection"})

# Source-owned actions are proposals, NOT tool invocations. The result contains
# neither SQL text nor executable code. A model cannot register an action.
# severity is an ordinal triage weight, NEVER a calibrated risk probability.
ACTIONS = {
    "REHEARSE_BINDING_MIGRATION": {
        "severity": 100, "owner": "a11oy", "scope": "DISPOSABLE_DB_ONLY",
        "codes": frozenset({"TABLE_NOT_OBSERVED", "SECURITY_DEFINER_DRIFT",
                            "PRINCIPAL_BINDING_UNOBSERVED",
                            "CONTEXT_BINDING_UNOBSERVED"}),
        "evidence_gate": "BACKUP_RESTORE_AND_PG18_RLS_NEGATIVE_TESTS",
        "effects": "HUMAN_APPROVAL_REQUIRED",
    },
    "QUALIFY_AUDIT_ROLE": {
        "severity": 95, "owner": "database_security",
        "scope": "RESTRICTED_PROVIDER_ADMIN_REVIEW",
        "codes": frozenset({"AUDITOR_LEAST_PRIVILEGE_NOT_OBSERVED"}),
        "evidence_gate": "NON_SUPERUSER_NON_BYPASSRLS_READ_ONLY_ROLE",
        "effects": "HUMAN_APPROVAL_REQUIRED",
    },
    "RECOLLECT_CATALOG": {
        "severity": 90, "owner": "szl-org-health", "scope": "READ_ONLY",
        "codes": frozenset({"CATALOG_STALE", "CATALOG_IN_FUTURE",
                            "CATALOG_DIGEST_UNAVAILABLE"}),
        "evidence_gate": "FRESH_LEAST_PRIVILEGE_SOURCE_BOUND_CATALOG",
        "effects": "READ_ONLY_PROPOSAL",
    },
    "REVIEW_RLS_POLICY": {
        "severity": 90, "owner": "a11oy", "scope": "DISPOSABLE_DB_ONLY",
        "codes": frozenset({"PUBLIC_TABLE_GRANTS", "RLS_STATE_DRIFT",
                            "RLS_FORCE_STATE_DRIFT", "POLICY_COVERAGE_DRIFT",
                            "INVALID_INDEX"}),
        "evidence_gate": "PG18_ISOLATION_AND_DISPOSABLE_ROLLBACK",
        "effects": "HUMAN_APPROVAL_REQUIRED",
    },
    "INSTRUMENT_SOURCE_EPOCH": {
        "severity": 85, "owner": "a11oy", "scope": "SOURCE_ONLY",
        "codes": frozenset({"REQUIRED_STAGE_UNAVAILABLE", "REQUIRED_STAGE_MISSING",
                            "SNAPSHOT_INCOMPLETE"}),
        "stage": "source_ledger", "evidence_gate": "ATOMIC_SOURCE_RECEIPT_VERSION",
        "effects": "SOURCE_REVIEW_REQUIRED",
    },
    "INSTRUMENT_OUTBOX_ACK": {
        "severity": 80, "owner": "a11oy", "scope": "SOURCE_ONLY",
        "codes": frozenset({"REQUIRED_STAGE_UNAVAILABLE", "REQUIRED_STAGE_MISSING",
                            "SNAPSHOT_INCOMPLETE"}),
        "stage": "transactional_outbox",
        "evidence_gate": "FENCED_OUTBOX_IDEMPOTENCY_AND_ACK",
        "effects": "SOURCE_REVIEW_REQUIRED",
    },
    "VERIFY_RETRIEVAL_FRONTIER": {
        "severity": 75, "owner": "a11oy", "scope": "SOURCE_ONLY",
        "codes": frozenset({"REQUIRED_STAGE_UNAVAILABLE", "REQUIRED_STAGE_MISSING",
                            "SNAPSHOT_INCOMPLETE"}),
        "stage": "retrieval_index", "evidence_gate": "DURABLE_APPLIED_THROUGH_ACK",
        "effects": "SOURCE_REVIEW_REQUIRED",
    },
    "VERIFY_API_PROJECTION": {
        "severity": 70, "owner": "a11oy", "scope": "SOURCE_ONLY",
        "codes": frozenset({"REQUIRED_STAGE_UNAVAILABLE", "REQUIRED_STAGE_MISSING",
                            "SNAPSHOT_INCOMPLETE"}),
        "stage": "api_projection", "evidence_gate": "EXACT_READ_AFTER_WRITE_VERSION",
        "effects": "SOURCE_REVIEW_REQUIRED",
    },
    "TRACE_VERSION_GAPS": {
        "severity": 75, "owner": "a11oy", "scope": "READ_ONLY",
        "codes": frozenset({"READ_VERSION_OUTSIDE_STAGE_FRONTIER",
                            "FRONTIER_INTERSECTION_EMPTY",
                            "FRONTIER_SKEW_EXCEEDED", "STAGE_STALE",
                            "SNAPSHOT_STALE", "STAGE_TIMELINE_MISMATCH",
                            "TIMELINE_MISMATCH"}),
        "evidence_gate": "ONE_COMPARABLE_SCOPED_LOGICAL_TIMELINE",
        "effects": "READ_ONLY_PROPOSAL",
    },
    "REVERIFY_SOURCE_IDENTITY": {
        "severity": 80, "owner": "szl-org-health", "scope": "READ_ONLY",
        "codes": frozenset({"SOURCE_CLAIM_DIFFERS",
                            "SOURCE_SUBJECT_MISMATCH", "SOURCE_IDENTITY_UNVERIFIED"}),
        "evidence_gate": "PROTECTED_GITHUB_BLOB_AND_RUNTIME_READBACK",
        "effects": "READ_ONLY_PROPOSAL",
    },
}

EXPECTED_CATALOG = frozenset({
    "schema", "catalog_observed_at", "catalog_sha256", "contract_id",
    "database_queried_by_this_verifier", "external_writes_performed",
    "gap_count", "gaps", "independent_witness", "migration_authorized",
    "observed_functions", "observed_tables", "policy_sha256",
    "production_authorized", "reported_source_blob_matches",
    "required_functions", "required_tables", "source_identity_independently_verified",
    "state",
})
EXPECTED_FRONTIER = frozenset({
    "schema", "contract_id", "coverage_denominator", "coverage_numerator",
    "database_queried", "effects_authorized", "external_consistency_proven",
    "gap_count", "gaps", "intersection", "observed_stage_count",
    "policy_sha256", "production_authorized", "replication_proven",
    "requested_version", "required_stage_count", "schema_migrated_by_this_verifier",
    "snapshot_sha256", "source_identity_independently_verified",
    "stage_digests_independently_verified", "state", "true_time_available",
    "upper_version_spread",
})


def refuse(code: str):
    raise InputError(code)


def require(condition, code):
    if not condition:
        refuse(code)


def aware_time(value):
    require(type(value) is str and len(value) <= 48,
            "OBSERVATION_TIMESTAMP_INVALID")
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        refuse("OBSERVATION_TIMESTAMP_INVALID")
    require(t.tzinfo is not None and t.utcoffset() is not None,
            "OBSERVATION_TIMESTAMP_INVALID")
    return t.astimezone(timezone.utc)


def _code(value):
    require(type(value) is str and CODE.fullmatch(value) is not None,
            "FINDING_CODE_INVALID")
    return value


def _gaps(report, *, catalog):
    entries = report["gaps"]
    require(type(entries) is list and len(entries) <= 100,
            "FINDINGS_INVALID")
    require(type(report["gap_count"]) is int
            and report["gap_count"] == len(entries), "FINDING_COUNT_MISMATCH")
    seen = set()
    parsed = []
    for row in entries:
        require(type(row) is dict, "FINDING_INVALID")
        require(set(row).issubset({"code", "object" if catalog else "stage"})
                and "code" in row, "FINDING_INVALID")
        code = _code(row["code"])
        specific = row.get("object" if catalog else "stage")
        if specific is not None:
            require(type(specific) is str and len(specific) <= 160,
                    "FINDING_SUBJECT_INVALID")
            if catalog:
                require(re.fullmatch(r"[a-z_]+\.[a-z_][a-z0-9_]{0,70}",
                                     specific) is not None, "FINDING_SUBJECT_INVALID")
            else:
                require(specific in STAGES, "FINDING_SUBJECT_INVALID")
        key = (code, specific)
        require(key not in seen, "DUPLICATE_FINDING")
        seen.add(key)
        parsed.append({"code": code, "subject": specific})
    return parsed


def validate_policy(policy, source_policy):
    policy_data(source_policy)
    require(type(policy) is dict and set(policy) == {
        "schema", "source_binding", "catalog_contract_id",
        "frontier_contract_id", "max_age_seconds", "max_actions",
        "allowed_actions"}, "AGENT_POLICY_INVALID")
    require(policy["schema"] == POLICY_SCHEMA
            and policy["source_binding"] == source_policy["source_binding"],
            "AGENT_SOURCE_MISMATCH")
    require(policy["catalog_contract_id"] == "a11oy-memory-covenant-v2"
            and policy["frontier_contract_id"] == "a11oy_memory_causal_frontier_v1",
            "AGENT_CONTRACT_INVALID")
    require(type(policy["max_age_seconds"]) is int
            and 60 <= policy["max_age_seconds"] <= 86400,
            "AGENT_POLICY_INVALID")
    require(type(policy["max_actions"]) is int
            and 1 <= policy["max_actions"] <= 20, "AGENT_POLICY_INVALID")
    rules = policy["allowed_actions"]
    require(type(rules) is list and len(rules) == len(ACTIONS)
            and set(rules) == set(ACTIONS)
            and all(type(r) is str for r in rules),
            "AGENT_ACTION_POLICY_INVALID")


def validate_receipts(catalog, frontier, policy, *, role_posture=None, at=None):
    require(type(catalog) is dict and set(catalog) == EXPECTED_CATALOG,
            "CATALOG_FIELDS_INVALID")
    require(type(frontier) is dict and set(frontier) == EXPECTED_FRONTIER,
            "FRONTIER_FIELDS_INVALID")
    require(catalog["schema"] == CATALOG_SCHEMA
            and frontier["schema"] == FRONTIER_SCHEMA, "RECEIPT_SCHEMA_INVALID")
    require(catalog["contract_id"] == policy["catalog_contract_id"]
            and frontier["contract_id"] == policy["frontier_contract_id"],
            "RECEIPT_CONTRACT_MISMATCH")
    require(catalog["state"] in ("HOLD", "CATALOG_MATCH_ONLY")
            and frontier["state"] in ("HOLD", "STRUCTURAL_FRONTIER_MATCH_ONLY"),
            "RECEIPT_STATUS_INVALID")
    for row in (catalog, frontier):
        require(row["production_authorized"] is False
                and row["source_identity_independently_verified"] is False,
                "PRIVILEGED_RECEIPT_REFUSED")
    require(catalog["external_writes_performed"] is False
            and catalog["migration_authorized"] is False
            and frontier["effects_authorized"] is False
            and frontier["database_queried"] is False,
            "EFFECT_CLAIM_REFUSED")
    require(type(catalog["required_tables"]) is int
            and 1 <= catalog["required_tables"] <= 100,
            "CATALOG_COVERAGE_INVALID")
    require(type(catalog["observed_tables"]) is int
            and 0 <= catalog["observed_tables"] <= 1000, "CATALOG_COVERAGE_INVALID")
    require(type(frontier["coverage_numerator"]) is int
            and type(frontier["coverage_denominator"]) is int
            and frontier["coverage_denominator"] == len(STAGES)
            and 0 <= frontier["coverage_numerator"] <= len(STAGES),
            "FRONTIER_COVERAGE_INVALID")
    for name in ("catalog_sha256", "policy_sha256"):
        require(type(catalog[name]) is str and HEX64.fullmatch(catalog[name]),
                "CATALOG_DIGEST_INVALID")
    for name in ("policy_sha256", "snapshot_sha256"):
        require(frontier[name] is None or
                (type(frontier[name]) is str and HEX64.fullmatch(frontier[name])),
                "FRONTIER_DIGEST_INVALID")
    findings = _gaps(catalog, catalog=True) + _gaps(frontier, catalog=False)
    if catalog["state"] == "CATALOG_MATCH_ONLY":
        require(catalog["gap_count"] == 0, "RECEIPT_STATUS_INCOHERENT")
    if frontier["state"] == "STRUCTURAL_FRONTIER_MATCH_ONLY":
        require(frontier["gap_count"] == 0, "RECEIPT_STATUS_INCOHERENT")
    now = at or datetime.now(timezone.utc)
    require(now.tzinfo is not None and now.utcoffset() is not None,
            "EVALUATION_TIME_INVALID")
    age = (now - aware_time(catalog["catalog_observed_at"])).total_seconds()
    if age > policy["max_age_seconds"]:
        findings.append({"code": "CATALOG_STALE", "subject": None})
    if age < -300:
        findings.append({"code": "CATALOG_IN_FUTURE", "subject": None})
    if catalog["reported_source_blob_matches"] is not True:
        findings.append({"code": "SOURCE_CLAIM_DIFFERS", "subject": None})
    # A report that says structural match but has no independently verified
    # source remains non-authorizing, regardless of any numeric coverage.
    if role_posture is not None:
        require(type(role_posture) is dict and set(role_posture) == {
            "schema", "state", "observed_at", "scope", "least_privileged_login_count",
            "credentials_recorded"}, "ROLE_POSTURE_INVALID")
        require(role_posture["schema"] == ROLE_SCHEMA
                and role_posture["scope"] == "A11OY_MEMORY_VALIDATION"
                and role_posture["credentials_recorded"] is False,
                "ROLE_POSTURE_INVALID")
        require(role_posture["state"] in ("OBSERVED", "UNAVAILABLE"),
                "ROLE_POSTURE_INVALID")
        count = role_posture["least_privileged_login_count"]
        require((role_posture["state"] == "UNAVAILABLE" and count is None)
                or (role_posture["state"] == "OBSERVED"
                    and type(count) is int and 0 <= count <= 10000),
                "ROLE_COUNT_INVALID")
        role_time = aware_time(role_posture["observed_at"])
        age = (now - role_time).total_seconds()
        if role_posture["state"] != "OBSERVED" or age < -300 or age > policy["max_age_seconds"]:
            findings.append({"code": "AUDITOR_LEAST_PRIVILEGE_NOT_OBSERVED", "subject": None})
        else:
            if count == 0:
                findings.append({"code": "AUDITOR_LEAST_PRIVILEGE_NOT_OBSERVED", "subject": None})
    else:
        findings.append({"code": "AUDITOR_LEAST_PRIVILEGE_NOT_OBSERVED", "subject": None})
    return findings


def propose(policy, catalog, frontier, *, role_posture=None, at=None,
            catalog_sha=None, frontier_sha=None, role_sha=None):
    findings = validate_receipts(catalog, frontier, policy, role_posture=role_posture, at=at)
    by_code = {}
    for finding in findings:
        by_code.setdefault(finding["code"], set()).add(finding["subject"])
    # A failed predecessor catalog is a dependency signal, not a separate
    # request to recollect a fresh, definitively failing catalog. If the
    # upstream report *claims* it passed, this disagreement remains unmapped.
    covered = ({"CATALOG_NOT_ADMITTED"} if catalog["state"] == "HOLD"
               else set())
    actions = []
    for name in policy["allowed_actions"]:
        rule = ACTIONS[name]
        codes = sorted(set(rule["codes"]) & set(by_code))
        if not codes:
            continue
        stage = rule.get("stage")
        if stage is not None:
            # Generic SNAPSHOT_INCOMPLETE does not make one particular
            # component proven failed; propose bounded measurement instead.
            matched = any(stage in by_code.get(c, set()) for c in (
                "REQUIRED_STAGE_UNAVAILABLE", "REQUIRED_STAGE_MISSING"))
            if not matched:
                continue
        covered.update(codes)
        actions.append({
            "action_id": name,
            "state": "PROPOSED_NOT_EXECUTED",
            "priority_ordinal": rule["severity"],
            "owner": rule["owner"],
            "scope": rule["scope"],
            "trigger_codes": codes,
            "evidence_gate": rule["evidence_gate"],
            "effect_contract": rule["effects"],
            "sql_generated": False,
            "tool_invocation": False,
            "approval_recorded": False,
            "verification_complete": False,
        })
    unknown = sorted(set(by_code) - covered)
    if unknown:
        actions.append({
            "action_id": "ESCALATE_UNMAPPED_FINDINGS",
            "state": "PROPOSED_NOT_EXECUTED",
            "priority_ordinal": 110,
            "owner": "szl-org-health",
            "scope": "SOURCE_REVIEW_ONLY",
            "trigger_codes": unknown,
            "evidence_gate": "EXPLICIT_NEW_REVIEWED_RULES",
            "effect_contract": "HUMAN_APPROVAL_REQUIRED",
            "sql_generated": False, "tool_invocation": False,
            "approval_recorded": False, "verification_complete": False,
        })
    require(len(actions) <= policy["max_actions"], "AGENT_PLAN_BUDGET_EXCEEDED")
    actions.sort(key=lambda a: (-a["priority_ordinal"], a["action_id"]))
    catalog_coverage = {
        "numerator": min(catalog["observed_tables"], catalog["required_tables"]),
        "denominator": catalog["required_tables"],
        "scope": "TABLE_PRESENCE_COUNT_ONLY",
    }
    frontier_coverage = {
        "numerator": frontier["coverage_numerator"],
        "denominator": frontier["coverage_denominator"],
        "scope": "SOURCE_REPORTED_STAGE_COVERAGE_ONLY",
    }
    result = {
        "schema": SCHEMA,
        "state": "HOLD" if findings or catalog["state"] != "CATALOG_MATCH_ONLY"
                 or frontier["state"] != "STRUCTURAL_FRONTIER_MATCH_ONLY"
                 else "STRUCTURAL_ONLY",
        "catalog_state": catalog["state"],
        "frontier_state": frontier["state"],
        "source_binding": policy["source_binding"],
        "source_identity_independently_verified": False,
        "independent_witness": False,
        "catalog_coverage": catalog_coverage,
        "frontier_coverage": frontier_coverage,
        "finding_codes": sorted(set(by_code)),
        "unmapped_codes": unknown,
        "actions": actions,
        "max_actions": policy["max_actions"],
        "readiness_math": "ALL_GATE_CONJUNCTION_WITH_UNKNOWN_FAIL_CLOSED",
        "priority_math": "REVIEWED_ORDINAL_SEVERITY_NOT_RISK_PROBABILITY",
        "plan_type": "SOURCE_ONLY_INERT_WORK_ORDERS",
        "catalog_receipt_sha256": catalog_sha,
        "frontier_receipt_sha256": frontier_sha,
        "role_receipt_sha256": role_sha,
        "catalog_observation_freshness_checked": True,
        "frontier_observation_freshness_verified": False,
        "production_authorized": False,
        "database_queried": False,
        "sql_executed": False,
        "sql_generated": False,
        "external_effects_performed": False,
        "automated_migration_enabled": False,
        "action_count": len(actions),
    }
    # Content-address plan, independent of wall time. Hash is NOT a signature.
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False).encode("utf-8")
    result["content_sha256"] = hashlib.sha256(canonical).hexdigest()
    result["signature_state"] = "UNSIGNED_STRUCTURAL_HASH_ONLY"
    return result


def verify_plan(plan, policy):
    """Independently check proposed actions against fixed source-owned rules."""
    fields = {
        "schema", "state", "catalog_state", "frontier_state", "source_binding",
        "source_identity_independently_verified", "independent_witness",
        "catalog_coverage", "frontier_coverage", "finding_codes",
        "unmapped_codes", "actions", "max_actions", "readiness_math",
        "priority_math", "plan_type", "catalog_receipt_sha256",
        "frontier_receipt_sha256", "role_receipt_sha256",
        "catalog_observation_freshness_checked",
        "frontier_observation_freshness_verified", "production_authorized",
        "database_queried", "sql_executed", "sql_generated",
        "external_effects_performed", "automated_migration_enabled",
        "action_count", "content_sha256", "signature_state",
    }
    require(type(plan) is dict and set(plan) == fields
            and plan.get("schema") == SCHEMA, "PLAN_SCHEMA_INVALID")
    require(plan["source_binding"] == policy["source_binding"]
            and plan["source_identity_independently_verified"] is False
            and plan["independent_witness"] is False
            and plan["frontier_observation_freshness_verified"] is False
            and plan["database_queried"] is False
            and plan["production_authorized"] is False
            and plan["external_effects_performed"] is False
            and plan["automated_migration_enabled"] is False
            and plan["sql_executed"] is False
            and plan["sql_generated"] is False, "PLAN_EFFECT_CLAIM_REFUSED")
    require(plan["state"] in ("HOLD", "STRUCTURAL_ONLY")
            and plan["readiness_math"] == "ALL_GATE_CONJUNCTION_WITH_UNKNOWN_FAIL_CLOSED"
            and plan["priority_math"] == "REVIEWED_ORDINAL_SEVERITY_NOT_RISK_PROBABILITY"
            and plan["plan_type"] == "SOURCE_ONLY_INERT_WORK_ORDERS",
            "PLAN_MATH_OR_SCOPE_INVALID")
    require(type(plan.get("actions")) is list
            and type(plan.get("action_count")) is int
            and plan["action_count"] == len(plan["actions"])
            and plan["max_actions"] == policy["max_actions"]
            and len(plan["actions"]) <= policy["max_actions"],
            "ACTION_COUNT_MISMATCH")
    codes = plan["finding_codes"]
    require(type(codes) is list and codes == sorted(set(codes))
            and all(type(x) is str and CODE.fullmatch(x) for x in codes),
            "FINDING_CODES_INVALID")
    unmapped = plan["unmapped_codes"]
    require(type(unmapped) is list and unmapped == sorted(set(unmapped))
            and set(unmapped).issubset(codes), "UNMAPPED_CODES_INVALID")
    coverages = (
        (plan["catalog_coverage"], "TABLE_PRESENCE_COUNT_ONLY", 1000),
        (plan["frontier_coverage"], "SOURCE_REPORTED_STAGE_COVERAGE_ONLY", 4),
    )
    for row, scope, limit in coverages:
        require(type(row) is dict and set(row) == {
            "numerator", "denominator", "scope"}
            and row["scope"] == scope
            and type(row["numerator"]) is int
            and type(row["denominator"]) is int
            and 0 < row["denominator"] <= limit
            and 0 <= row["numerator"] <= row["denominator"],
            "PLAN_COVERAGE_INVALID")
    for field in ("catalog_receipt_sha256", "frontier_receipt_sha256",
                  "role_receipt_sha256"):
        digest = plan[field]
        require(digest is None or (type(digest) is str
                and HEX64.fullmatch(digest) is not None),
                "PLAN_INPUT_HASH_INVALID")
    keys = {"action_id", "state", "priority_ordinal", "owner", "scope",
            "trigger_codes", "evidence_gate", "effect_contract",
            "sql_generated", "tool_invocation", "approval_recorded",
            "verification_complete"}
    names = []
    for action in plan["actions"]:
        require(type(action) is dict and set(action) == keys,
                "PLAN_ACTION_FIELDS_INVALID")
        name = action["action_id"]
        names.append(name)
        require(action["state"] == "PROPOSED_NOT_EXECUTED"
                and action["tool_invocation"] is False
                and action["approval_recorded"] is False
                and action["verification_complete"] is False
                and action["sql_generated"] is False,
                "PLAN_ACTION_EFFECT_REFUSED")
        if name == "ESCALATE_UNMAPPED_FINDINGS":
            require(bool(unmapped) and action["trigger_codes"] == unmapped
                    and action["priority_ordinal"] == 110
                    and action["owner"] == "szl-org-health"
                    and action["scope"] == "SOURCE_REVIEW_ONLY"
                    and action["evidence_gate"] == "EXPLICIT_NEW_REVIEWED_RULES"
                    and action["effect_contract"] == "HUMAN_APPROVAL_REQUIRED",
                    "PLAN_ESCALATION_INVALID")
            continue
        require(name in ACTIONS and name in policy["allowed_actions"],
                "PLAN_ACTION_UNREVIEWED")
        rule = ACTIONS[name]
        trigger = action["trigger_codes"]
        require(type(trigger) is list and bool(trigger)
                and trigger == sorted(set(trigger))
                and set(trigger).issubset(rule["codes"])
                and set(trigger).issubset(codes)
                and action["priority_ordinal"] == rule["severity"]
                and action["owner"] == rule["owner"]
                and action["scope"] == rule["scope"]
                and action["evidence_gate"] == rule["evidence_gate"]
                and action["effect_contract"] == rule["effects"],
                "PLAN_ACTION_CONTRACT_MISMATCH")
    require(len(names) == len(set(names))
            and names == sorted(names, key=lambda n: (
                -(110 if n == "ESCALATE_UNMAPPED_FINDINGS" else ACTIONS[n]["severity"]), n)),
            "PLAN_ORDER_INVALID")
    require(plan["state"] != "STRUCTURAL_ONLY" or
            (not codes and not plan["actions"] and not unmapped),
            "STRUCTURAL_ONLY_WITH_FINDINGS")
    digest = plan.get("content_sha256")
    require(type(digest) is str and HEX64.fullmatch(digest) is not None,
            "PLAN_HASH_INVALID")
    inner = {k: v for k, v in plan.items()
             if k not in ("content_sha256", "signature_state")}
    computed = hashlib.sha256(json.dumps(
        inner, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")).hexdigest()
    require(computed == digest and plan.get("signature_state") ==
            "UNSIGNED_STRUCTURAL_HASH_ONLY", "PLAN_HASH_MISMATCH")
    return True

def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline, no-effect SZL DB agent planner")
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--frontier", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--source-policy", type=Path, required=True)
    parser.add_argument("--role-posture", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        source, source_sha = read_file(args.source_policy, max_bytes=65536)
        policy, _ = read_file(args.policy, max_bytes=65536)
        validate_policy(policy, source)
        # The predecessor's claimed policy digests must be the exact
        # current reviewed bytes, not merely syntactically plausible hashes.
        canonical_frontier_path = (Path(__file__).resolve().parent.parent /
            "governance/database_contracts/memory_causal_frontier_v1.json")
        frontier_policy, frontier_policy_sha = read_file(
            canonical_frontier_path, max_bytes=65536)
        require(type(frontier_policy) is dict
                and frontier_policy.get("source_binding") == policy["source_binding"]
                and frontier_policy.get("contract_id") ==
                    policy["frontier_contract_id"],
                "FRONTIER_POLICY_SOURCE_MISMATCH")
        cat, catsha = read_file(args.catalog)
        front, frontsha = read_file(args.frontier)
        require(type(cat) is dict and cat.get("policy_sha256") == source_sha,
                "CATALOG_POLICY_DIGEST_MISMATCH")
        require(type(front) is dict and
                front.get("policy_sha256") == frontier_policy_sha,
                "FRONTIER_POLICY_DIGEST_MISMATCH")
        role = rolesha = None
        if args.role_posture:
            role, rolesha = read_file(args.role_posture, max_bytes=8192)
        plan = propose(policy, cat, front, role_posture=role,
                       catalog_sha=catsha, frontier_sha=frontsha, role_sha=rolesha)
        verify_plan(plan, policy)
        checkout = Path(__file__).resolve().parent.parent
        if args.output.is_symlink() or args.output.exists() or args.output.resolve().is_relative_to(checkout):
            refuse("OUTPUT_PATH_DENIED")
        raw = (json.dumps(plan, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True) + "\n").encode("utf-8")
        require(len(raw) <= 65536 and args.output.parent.is_dir(),
                "OUTPUT_PATH_DENIED")
        with args.output.open("xb") as stream:
            stream.write(raw)
            stream.flush()
        print(json.dumps({"state": plan["state"], "action_count": plan["action_count"],
                          "unmapped_count": len(plan["unmapped_codes"]),
                          "production_authorized": False, "external_effects_performed": False},
                         sort_keys=True))
        return 0 if plan["state"] == "STRUCTURAL_ONLY" else 2
    except (InputError, ValueError) as exc:
        code = exc.code if isinstance(exc, InputError) else "INPUT_UNAVAILABLE"
    except Exception:
        code = "PLANNER_UNAVAILABLE"
    print(json.dumps({"state": "UNAVAILABLE", "error_code": code,
                      "production_authorized": False, "external_effects_performed": False}))
    return 3


if __name__ == "__main__":
    sys.exit(main())
