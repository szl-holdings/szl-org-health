#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SZL Ouroboros DB braid: closed-source-plan -> finite trace -> no-effect receipt.

Connects *source-pinned references*, not executable foreign runtimes. No Lean
kernel, Lake canonical DSSE signer, Hatun MCP, GPU model, database driver,
archaeological corpus or SQL engine is loaded. No action permission is minted.
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
    from tools.database_catalog_admission import read_file, InputError
    from tools.database_agentic_planner import verify_plan, validate_policy
    from tools.database_braid_source_readback import (
        validate_policy as validate_braid_policy, SCHEMA as READBACK_SCHEMA,
        FIXED_DOCTRINE,
    )
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_catalog_admission import read_file, InputError
    from tools.database_agentic_planner import verify_plan, validate_policy
    from tools.database_braid_source_readback import (
        validate_policy as validate_braid_policy, SCHEMA as READBACK_SCHEMA,
        FIXED_DOCTRINE,
    )

SCHEMA = "szl.database-ouroboros-braid/v1"
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
PHASES = (
    "PLAN_AND_SCOPE",
    "SOURCE_BLOB_RECONCILIATION",
    "KHIPU_UNIT_SUMMATION",
    "LEAN_HATUN_LAKE_PROOF_BOUNDARY",
    "TERMINAL_RECEIPT_CLOSURE",
)
GENESIS = "0" * 64
PROOF_STATUS = "NO_FRESH_LEAN_CHECKER_OR_RUNTIME_REFINEMENT"
DEFAULT_EXIT = "CLOSED_WITH_HOLD"


def require(ok, code):
    if not ok:
        raise InputError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def timestamp(value):
    require(type(value) is str and len(value) <= 48,
            "BRAID_TIMESTAMP_INVALID")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise InputError("BRAID_TIMESTAMP_INVALID") from None
    require(result.tzinfo is not None and result.utcoffset() is not None,
            "BRAID_TIMESTAMP_INVALID")
    return result.astimezone(timezone.utc)


def validate_source_readback(value, policy, *, now=None):
    refs = validate_braid_policy(policy)
    require(type(value) is dict and set(value) == {
        "schema", "observed_at", "state", "required_count",
        "matched_count", "entries", "github_commit_and_blob_pins_reported",
        "git_bytes_checked_by_this_collector",
        "runtime_sources_independently_verified", "lean_kernel_executed",
        "hatun_authority_present", "lake_canonical_receipt_emitted",
        "provider_writes", "secrets_recorded",
    }, "BRAID_READBACK_FIELDS_INVALID")
    require(value["schema"] == READBACK_SCHEMA and
            value["github_commit_and_blob_pins_reported"] is True and
            value["git_bytes_checked_by_this_collector"] is True,
            "BRAID_READBACK_SCHEMA_INVALID")
    require(all(value[name] is False for name in (
        "runtime_sources_independently_verified", "lean_kernel_executed",
        "hatun_authority_present", "lake_canonical_receipt_emitted",
        "provider_writes", "secrets_recorded")),
        "BRAID_FALSE_AUTHORITY_CLAIM")
    require(type(value["entries"]) is list
            and len(value["entries"]) == len(refs)
            and type(value["required_count"]) is int
            and value["required_count"] == len(refs)
            and type(value["matched_count"]) is int,
            "BRAID_READBACK_COVERAGE_INVALID")
    matched = 0
    missing = []
    for expected, row in zip(refs, value["entries"]):
        require(type(row) is dict and set(row) == {
            "id", "repository", "commit", "path", "blob_sha1",
            "tier", "status", "byte_length", "content_sha256",
        }, "BRAID_OBSERVATION_FIELDS_INVALID")
        for k in ("id", "repository", "commit", "path", "blob_sha1", "tier"):
            require(row[k] == expected[k], "BRAID_SOURCE_PIN_MISMATCH")
        require(row["status"] in ("MATCHED", "UNAVAILABLE", "MISMATCH"),
                "BRAID_OBSERVATION_STATUS_INVALID")
        if row["status"] == "MATCHED":
            require(type(row["byte_length"]) is int
                    and 0 < row["byte_length"] <= 512000
                    and type(row["content_sha256"]) is str
                    and SHA64.fullmatch(row["content_sha256"]) is not None,
                    "BRAID_OBSERVATION_DIGEST_INVALID")
            matched += 1
        else:
            require(row["byte_length"] is None and
                    row["content_sha256"] is None,
                    "BRAID_MISSING_SOURCE_NOT_UNKNOWN")
            missing.append(row["id"])
    require(matched == value["matched_count"] and (
        value["state"] == "COMPLETE_BLOB_MATCH") == (matched == len(refs)),
        "BRAID_SOURCE_COUNT_MISMATCH")
    require(value["state"] in ("COMPLETE_BLOB_MATCH", "HOLD"),
            "BRAID_READBACK_STATE_INVALID")
    at = now or datetime.now(timezone.utc)
    require(at.tzinfo is not None and at.utcoffset() is not None,
            "BRAID_NOW_INVALID")
    age = (at - timestamp(value["observed_at"])).total_seconds()
    # A protected repo may advance after a pin, but a source-observation
    # packet may not be reused indefinitely as if it were just collected.
    freshness = "FRESH" if -300 <= age <= 7200 else "STALE_OR_FUTURE"
    return matched, missing, freshness


def _append_step(steps, phase, state, count, *, detail):
    prior = steps[-1]["sha256"] if steps else GENESIS
    record = {
        "ordinal": len(steps) + 1, "phase": phase, "state": state,
        "prev_sha256": prior, "matched_sources": count, "detail": detail,
    }
    record["sha256"] = hashlib.sha256(canonical(record)).hexdigest()
    steps.append(record)


def braid(policy, source_readback, plan, action_policy, source_policy, *,
          now=None, policy_sha=None, readback_sha=None, plan_sha=None):
    refs = validate_braid_policy(policy)
    validate_policy(action_policy, source_policy)
    require(type(plan) is dict, "BRAID_PLAN_INVALID")
    verify_plan(plan, action_policy)
    require(plan["source_binding"] == source_policy["source_binding"],
            "BRAID_PLAN_SOURCE_MISMATCH")
    matched, missing, freshness = validate_source_readback(
        source_readback, policy, now=now)
    ref_count = len(refs)
    # Root is a sum over *present and byte-matched* source witnesses.
    # Missing sources are explicitly UNKNOWN, never encoded as zero knots.
    cords = [{
        "source_id": row["id"], "state": row["status"],
        "unit_weight": 1 if row["status"] == "MATCHED" else None,
    } for row in source_readback["entries"]]
    observed_root = sum(x["unit_weight"] for x in cords
                        if x["unit_weight"] is not None)
    require(observed_root == matched, "BRAID_CORD_CONSERVATION_FAILED")
    steps = []
    _append_step(steps, PHASES[0], "OBSERVED", matched,
                 detail="INERT_DB_PLAN_VALIDATED")
    _append_step(steps, PHASES[1],
                 "OBSERVED" if not missing and freshness == "FRESH" else "HOLD",
                 matched, detail="PINNED_GITHUB_BLOB_BYTES_ONLY")
    _append_step(steps, PHASES[2],
                 "OBSERVED" if not missing else "HOLD", matched,
                 detail="SUM_PRESENT_UNIT_CORDS_MISSING_NOT_ZERO")
    _append_step(steps, PHASES[3], "HOLD", matched,
                 detail="LEAN_KERNEL_NOT_RUN_HATUN_NO_AUTHORITY_LAKE_NOT_SIGNED")
    _append_step(steps, PHASES[4], "HOLD", matched,
                 detail="STOP_NO_EXTERNAL_EFFECTS")
    require(len(steps) == policy["max_steps"] and
            tuple(x["phase"] for x in steps) == PHASES,
            "BRAID_TERMINATION_BUDGET")
    # The pure function never invokes plan-proposed actions.
    report = {
        "schema": SCHEMA, "state": "HOLD",
        "termination": DEFAULT_EXIT,
        "doctrine": policy["doctrine"],
        "max_steps": policy["max_steps"],
        "executed_steps": len(steps),
        "loop_trace": steps,
        "source_ref_count": ref_count,
        "source_matched_count": matched,
        "source_readback_freshness": freshness,
        "missing_source_ids": missing,
        "khipu_root_observed_unit_sum": observed_root,
        "khipu_missing_cords": len(missing),
        "khipu_missing_is_zero": False,
        "cords": cords,
        "db_plan_state": plan["state"],
        "db_actions_inert": sorted(a["action_id"] for a in plan["actions"]),
        "source_policy_claim": source_policy["source_binding"],
        "source_runtime_verified": False,
        "lean_checker_result": PROOF_STATUS,
        "lambda_uniqueness_status": policy["lambda_claim"],
        "hatun_effect_authority": policy["hatun_effect_authority"],
        "lake_canonical_receipt": policy["lake_receipt_emission"],
        "archaeological_data_rights": policy["archaeological_data_rights"],
        "timing_ms_measured": None,
        "loop_tax_ms": None,
        "energy_joules": None,
        "canonical_dsse_signed": False,
        "independent_witness": False,
        "production_authorized": False,
        "database_queried": False,
        "git_source_code_executed": False,
        "model_inference_invoked": False,
        "external_effects_performed": False,
        "sql_executed": False,
        "sql_generated": False,
        "policy_sha256": policy_sha,
        "source_readback_sha256": readback_sha,
        "database_plan_sha256": plan_sha,
        "integrity_kind": "UNSIGNED_STRUCTURAL_SHA256_CHAIN",
    }
    return report


def verify_report(value, policy, plan):
    expected_fields = {
        "schema", "state", "termination", "doctrine", "max_steps",
        "executed_steps", "loop_trace", "source_ref_count",
        "source_matched_count", "source_readback_freshness",
        "missing_source_ids", "khipu_root_observed_unit_sum",
        "khipu_missing_cords", "khipu_missing_is_zero", "cords",
        "db_plan_state", "db_actions_inert", "source_policy_claim",
        "source_runtime_verified", "lean_checker_result",
        "lambda_uniqueness_status", "hatun_effect_authority",
        "lake_canonical_receipt", "archaeological_data_rights",
        "timing_ms_measured", "loop_tax_ms", "energy_joules",
        "canonical_dsse_signed", "independent_witness",
        "production_authorized", "database_queried",
        "git_source_code_executed", "model_inference_invoked",
        "external_effects_performed", "sql_executed", "sql_generated",
        "policy_sha256", "source_readback_sha256",
        "database_plan_sha256", "integrity_kind",
    }
    require(type(value) is dict and set(value) == expected_fields,
            "BRAID_REPORT_FIELDS_INVALID")
    require(value.get("source_readback_freshness") in (
                "FRESH", "STALE_OR_FUTURE"),
            "BRAID_FRESHNESS_INVALID")
    for field in ("policy_sha256", "source_readback_sha256",
                  "database_plan_sha256"):
        digest = value[field]
        require(digest is None or (type(digest) is str and
                SHA64.fullmatch(digest) is not None),
                "BRAID_INPUT_DIGEST_INVALID")
    require(value.get("schema") == SCHEMA and
            value.get("state") == "HOLD" and
            value.get("termination") == DEFAULT_EXIT and
            value.get("doctrine") == FIXED_DOCTRINE and
            value.get("max_steps") == 5 and
            value.get("executed_steps") == 5,
            "BRAID_REPORT_SCHEMA_INVALID")
    require(value.get("independent_witness") is False and
            value.get("canonical_dsse_signed") is False and
            value.get("production_authorized") is False and
            value.get("external_effects_performed") is False and
            value.get("sql_executed") is False and
            value.get("sql_generated") is False and
            value.get("model_inference_invoked") is False and
            value.get("git_source_code_executed") is False and
            value.get("source_runtime_verified") is False and
            value.get("database_queried") is False and
            value.get("lean_checker_result") == PROOF_STATUS and
            value.get("integrity_kind") == "UNSIGNED_STRUCTURAL_SHA256_CHAIN",
            "BRAID_FALSE_AUTHORITY_CLAIM")
    require(value.get("source_ref_count") == len(policy["source_refs"]) and
            type(value.get("source_matched_count")) is int and
            0 <= value["source_matched_count"] <= len(policy["source_refs"]),
            "BRAID_REPORT_COVERAGE_INVALID")
    require(value.get("source_policy_claim") == plan["source_binding"] and
            value.get("db_plan_state") == plan["state"] and
            value.get("db_actions_inert") ==
            sorted(a["action_id"] for a in plan["actions"]),
            "BRAID_REPORT_PLAN_DRIFT")
    require(value.get("lambda_uniqueness_status") == policy["lambda_claim"] and
            value.get("hatun_effect_authority") == "NOT_ATTACHED" and
            value.get("lake_canonical_receipt") == "NOT_EMITTED" and
            value.get("archaeological_data_rights") == "NOT_GRANTED" and
            value.get("khipu_missing_is_zero") is False and
            value.get("energy_joules") is None and
            value.get("timing_ms_measured") is None and
            value.get("loop_tax_ms") is None,
            "BRAID_DOCTRINE_DRIFT")
    cords = value.get("cords")
    require(type(cords) is list and len(cords) == value["source_ref_count"],
            "BRAID_CORD_COUNT_INVALID")
    seen_ids, matched = [], 0
    for pinned, cord in zip(policy["source_refs"], cords):
        require(type(cord) is dict and set(cord) == {
            "source_id", "state", "unit_weight"},
            "BRAID_CORD_SCHEMA_INVALID")
        require(cord["source_id"] == pinned["id"]
                and cord["state"] in ("MATCHED", "UNAVAILABLE", "MISMATCH"),
                "BRAID_CORD_SOURCE_INVALID")
        if cord["state"] == "MATCHED":
            require(type(cord["unit_weight"]) is int and
                    cord["unit_weight"] == 1,
                    "BRAID_CORD_WEIGHT_INVALID")
            matched += 1
        else:
            require(cord["unit_weight"] is None,
                    "BRAID_CORD_MISSING_COERCED_ZERO")
        seen_ids.append(cord["source_id"])
    missing = [c["source_id"] for c in cords if c["state"] != "MATCHED"]
    require(missing == value.get("missing_source_ids") and
            value["khipu_missing_cords"] == len(missing) and
            matched == value["khipu_root_observed_unit_sum"] ==
            value["source_matched_count"],
            "BRAID_KHIPU_CONSERVATION_DRIFT")
    steps = value.get("loop_trace")
    require(type(steps) is list and len(steps) == 5,
            "BRAID_TRACE_LENGTH_INVALID")
    expected_states = [
        "OBSERVED",
        ("OBSERVED" if matched == value["source_ref_count"] and
         value["source_readback_freshness"] == "FRESH" else "HOLD"),
        "OBSERVED" if matched == value["source_ref_count"] else "HOLD",
        "HOLD", "HOLD",
    ]
    expected_details = [
        "INERT_DB_PLAN_VALIDATED", "PINNED_GITHUB_BLOB_BYTES_ONLY",
        "SUM_PRESENT_UNIT_CORDS_MISSING_NOT_ZERO",
        "LEAN_KERNEL_NOT_RUN_HATUN_NO_AUTHORITY_LAKE_NOT_SIGNED",
        "STOP_NO_EXTERNAL_EFFECTS",
    ]
    previous = GENESIS
    for ordinal, step in enumerate(steps, 1):
        require(type(step) is dict and set(step) == {
            "ordinal", "phase", "state", "prev_sha256",
            "matched_sources", "detail", "sha256"},
            "BRAID_TRACE_SCHEMA_INVALID")
        require(type(step["ordinal"]) is int and
                step["ordinal"] == ordinal and
                step["phase"] == PHASES[ordinal - 1] and
                step["state"] == expected_states[ordinal - 1] and
                step["detail"] == expected_details[ordinal - 1] and
                step["matched_sources"] == matched and
                step["prev_sha256"] == previous,
                "BRAID_TRACE_CONTRACT_DRIFT")
        declared = step["sha256"]
        raw = {k: v for k, v in step.items() if k != "sha256"}
        require(type(declared) is str and
                SHA64.fullmatch(declared) is not None and
                hashlib.sha256(canonical(raw)).hexdigest() == declared,
                "BRAID_TRACE_HASH_MISMATCH")
        previous = declared
    require(steps[-1]["state"] == "HOLD" and
            steps[-1]["detail"] == "STOP_NO_EXTERNAL_EFFECTS",
            "BRAID_TERMINAL_NOT_CLOSED")
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description="No-effect Ouroboros evidence braid")
    ap.add_argument("--braid-policy", type=Path, required=True)
    ap.add_argument("--source-readback", type=Path, required=True)
    ap.add_argument("--db-plan", type=Path, required=True)
    ap.add_argument("--db-action-policy", type=Path, required=True)
    ap.add_argument("--source-policy", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        policy, policy_sha = read_file(args.braid_policy, max_bytes=65536)
        refs = validate_braid_policy(policy)
        assert len(refs) == policy["source_refs_required"]
        readback, readback_sha = read_file(args.source_readback, max_bytes=65536)
        plan, plan_sha = read_file(args.db_plan, max_bytes=65536)
        apolicy, _ = read_file(args.db_action_policy, max_bytes=65536)
        source_policy, _ = read_file(args.source_policy, max_bytes=65536)
        report = braid(policy, readback, plan, apolicy, source_policy,
                       policy_sha=policy_sha, readback_sha=readback_sha,
                       plan_sha=plan_sha)
        verify_report(report, policy, plan)
        output = args.output
        checkout = Path(__file__).resolve().parent.parent
        require(not output.exists() and not output.is_symlink()
                and output.parent.is_dir()
                and not output.resolve().is_relative_to(checkout),
                "BRAID_OUTPUT_PATH_DENIED")
        raw = canonical(report) + b"\n"
        require(len(raw) <= 65536, "BRAID_OUTPUT_TOO_LARGE")
        with output.open("xb") as stream:
            stream.write(raw)
            stream.flush()
        print(json.dumps({"state": report["state"],
                          "termination": report["termination"],
                          "source_match_count": report["source_matched_count"],
                          "source_required_count": report["source_ref_count"],
                          "steps": report["executed_steps"],
                          "production_authorized": False,
                          "external_effects_performed": False}))
        return 2  # no promotion from an unsigned offline evidence braid
    except InputError as exc:
        code = exc.code
    except Exception:
        code = "BRAID_UNAVAILABLE"
    print(json.dumps({"state": "UNAVAILABLE", "code": code,
                      "production_authorized": False,
                      "external_effects_performed": False}))
    return 3


if __name__ == "__main__":
    sys.exit(main())
