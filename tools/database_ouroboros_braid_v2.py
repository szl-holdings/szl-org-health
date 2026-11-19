#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SZL Ouroboros DB braid v2: one bounded turn over evidence that was really produced.

v1 pinned 33 files and recorded that the Lean kernel, Hatun and the Lake were
NOT exercised. v2 keeps v1 untouched and braids, in exactly five terminating
phases, the outputs of tools that DO exercise them:

  1 PLAN_AND_SCOPE               policy, inputs and the previous turn (the tail)
  2 SOURCE_CENSUS_RECONCILIATION every in-scope file, byte-checked from git
  3 KHIPU_SUM_TREE_CONSERVATION  sum-of-sums over cords, with partition identities
  4 LEAN_HATUN_PROOF_BOUNDARY    kernel witness and veto-ladder witness
  5 TERMINAL_RECEIPT_CLOSURE     ratchet, exact decision, content-derived turn id

Each turn consumes the previous turn's receipt, so the loop closes on itself;
proof debt may fall between turns and may not rise without the policy saying so.

This function is pure: it reads supplied evidence files, executes nothing, opens
no network connection and writes only the two files it is asked for. Absent
evidence is UNAVAILABLE and refuses the aggregate; it is never scored as zero
and never scored as a pass. The decision is an exact weighted geometric mean
(zero-pinned) against a threshold fixed in the policy before the run.

It can NOT authorize anything. Reaching the threshold yields
EVIDENCE_THRESHOLD_MET_NO_AUTHORITY: an unsigned statement about evidence. It is
not a repaired database, not a production admission, not a signature and not a
judgement that any theorem means what its name suggests. Database verdicts are
REPORTED inputs from another lane; this tool never queries a database.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
import re
import sys

try:
    from tools.database_braid_common import (
        FIXED_DOCTRINE, GENESIS, SHA64, canonical, checkout_root, closed, digest,
        natural, rational_text, read_json, require, sha256_hex, write_exclusive,
    )
    from tools.database_braid_codex_kat import validate_report as validate_kat_report
    from tools.database_braid_exact import (
        AGGREGATE, PATH_NONE, decide, ratio, verify_decision,
    )
    from tools.database_braid_hatun_gate import (
        validate_policy as validate_hatun_policy, validate_witness as validate_hatun_witness,
    )
    from tools.database_braid_khipu_tree import MAX_TREE_BYTES, build, diff, knot, verify
    from tools.database_braid_lake_receipt import (
        validate_policy as validate_lake_policy, validate_wrap,
    )
    from tools.database_braid_lean_witness import (
        ACCEPTED_DEFAULT, ACCEPTED_REQUEST, ACCEPTED_STANDALONE, CLASS_AXIOM, CLASS_CLEAN,
        CLASS_NATIVE, CLASS_SORRY, MODULE, NOT_CHECKED, REJECTED,
        validate_policy as validate_lean_policy, validate_witness as validate_lean_witness,
    )
    from tools.database_braid_source_census import (
        MAX_CENSUS_BYTES, validate_census, validate_census_policy,
    )
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_braid_common import (
        FIXED_DOCTRINE, GENESIS, SHA64, canonical, checkout_root, closed, digest,
        natural, rational_text, read_json, require, sha256_hex, write_exclusive,
    )
    from tools.database_braid_codex_kat import validate_report as validate_kat_report
    from tools.database_braid_exact import (
        AGGREGATE, PATH_NONE, decide, ratio, verify_decision,
    )
    from tools.database_braid_hatun_gate import (
        validate_policy as validate_hatun_policy, validate_witness as validate_hatun_witness,
    )
    from tools.database_braid_khipu_tree import MAX_TREE_BYTES, build, diff, knot, verify
    from tools.database_braid_lake_receipt import (
        validate_policy as validate_lake_policy, validate_wrap,
    )
    from tools.database_braid_lean_witness import (
        ACCEPTED_DEFAULT, ACCEPTED_REQUEST, ACCEPTED_STANDALONE, CLASS_AXIOM, CLASS_CLEAN,
        CLASS_NATIVE, CLASS_SORRY, MODULE, NOT_CHECKED, REJECTED,
        validate_policy as validate_lean_policy, validate_witness as validate_lean_witness,
    )
    from tools.database_braid_source_census import (
        MAX_CENSUS_BYTES, validate_census, validate_census_policy,
    )
    from tools.database_catalog_admission import InputError

SCHEMA = "szl.database-ouroboros-braid/v2"
POLICY_SCHEMA = "szl.database-ouroboros-braid-policy/v2"
PHASES = (
    "PLAN_AND_SCOPE",
    "SOURCE_CENSUS_RECONCILIATION",
    "KHIPU_SUM_TREE_CONSERVATION",
    "LEAN_HATUN_PROOF_BOUNDARY",
    "TERMINAL_RECEIPT_CLOSURE",
)
KNOTS = [
    "cords", "bytes", "lean_files", "lean_accepted_default", "lean_accepted_on_request",
    "lean_accepted_standalone", "lean_rejected", "lean_not_checked_by_policy",
    "lean_not_judged", "user_theorems", "theorems_trust_base_only", "theorems_sorry_tainted",
    "theorems_declared_axiom_dependent", "theorems_native_decide",
    "direct_sorry_declarations", "declared_axioms", "elaborator_sorry_declarations",
    "lean_text_sorry_tokens",
]
PARTITIONS = [
    {"name": "lean_status", "whole": "lean_files",
     "parts": ["lean_accepted_default", "lean_accepted_on_request", "lean_accepted_standalone",
               "lean_rejected", "lean_not_checked_by_policy", "lean_not_judged"]},
    {"name": "theorem_class", "whole": "user_theorems",
     "parts": ["theorems_trust_base_only", "theorems_sorry_tainted",
               "theorems_declared_axiom_dependent", "theorems_native_decide"]},
]
AXES = (
    "source_cords_present", "lean_files_kernel_accepted", "theorems_trust_base_only",
    "locked_set_guard", "codex_known_answers", "hatun_veto_ladder",
    "database_catalog_coverage", "database_frontier_coverage",
)
FIXED_CLAIMS = {
    "lambda_claim": "UNCONDITIONAL_UNIQUENESS_DISPROVEN_AS_STATED",
    "khipu_consensus_safety": "CONJECTURE_NOT_A_THEOREM",
    "archaeological_data_rights": "NOT_GRANTED",
    "external_effects": "DENIED",
    "production_authority": "NEVER_GRANTED_BY_THIS_TOOL",
}
FLOOR_FIELDS = ("lean_files_kernel_accepted_min", "lean_rejected_max",
                "theorems_sorry_tainted_max", "direct_sorry_declarations_max",
                "declared_axioms_allowed", "locked_guard_allowed_min")
STATE_MET = "EVIDENCE_THRESHOLD_MET_NO_AUTHORITY"
STATE_HOLD = "HOLD"
TURN_ID = re.compile(r"braid-turn:[0-9a-f]{32}\Z")
REASON = re.compile(r"[A-Z][A-Z_]{2,79}\Z")
MAX_POLICY_BYTES = 1048576
MAX_TURN_BYTES = 1048576
_FALSE_FLAGS = ("production_authorized", "external_effects_performed", "database_queried",
                "sql_generated", "sql_executed", "model_inference_invoked",
                "canonical_dsse_signed", "independent_witness", "khipu_missing_is_zero",
                "proofs_promoted", "authority_granted")
_NULL_FIELDS = ("energy_joules", "timing_ms_measured", "loop_tax_ms")
_FIELDS = (
    "schema", "state", "termination", "doctrine", "max_steps", "executed_steps", "ordinal",
    "turn_id", "previous_turn_id", "previous_turn_sha256", "previous_turn_lake_receipt",
    "ouroboros_fixed_point", "inputs", "inputs_digest", "state_digest", "census", "khipu",
    "lean", "hatun", "known_answers", "database", "v_one_braid", "ratchet", "decision",
    "evidence_labels", "fixed_claims", "loop_trace", "integrity_kind", "signed",
    *_FALSE_FLAGS, *_NULL_FIELDS,
)


def validate_policy(policy) -> dict:
    """Validate the whole braid v2 policy, section by section."""
    closed(policy, ("schema", "doctrine", "max_steps", "source_owner", "v_one_policy_sha256",
                    "census", "khipu", "lean", "hatun", "lake", "decision", "ratchet",
                    "fixed_claims"), "BRAID_POLICY_FIELDS_INVALID")
    require(policy["schema"] == POLICY_SCHEMA and policy["doctrine"] == FIXED_DOCTRINE and
            type(policy["max_steps"]) is int and policy["max_steps"] == len(PHASES) and
            policy["source_owner"] == "szl-holdings/szl-org-health" and
            type(policy["v_one_policy_sha256"]) is str and
            SHA64.fullmatch(policy["v_one_policy_sha256"]), "BRAID_POLICY_INVALID")
    require(policy["fixed_claims"] == FIXED_CLAIMS, "BRAID_AUTHORITY_CLAIM_REFUSED")
    validate_census_policy(policy["census"])
    validate_lean_policy(policy["lean"])
    validate_hatun_policy(policy["hatun"])
    validate_lake_policy(policy["lake"])
    khipu = closed(policy["khipu"], ("knots", "partitions", "missing_is_zero", "lean_carrier"),
                   "BRAID_POLICY_FIELDS_INVALID")
    require(khipu["knots"] == KNOTS and khipu["partitions"] == PARTITIONS and
            khipu["missing_is_zero"] is False and type(khipu["lean_carrier"]) is str and
            MODULE.fullmatch(khipu["lean_carrier"]) and
            khipu["lean_carrier"] in [c["decl"] for c in policy["lean"]["carrier_theorems"]],
            "BRAID_KHIPU_POLICY_INVALID")
    require(policy["lean"]["repository"] in
            [r["repository"] for r in policy["census"]["repositories"]],
            "BRAID_POLICY_LEAN_REPOSITORY_NOT_IN_CENSUS")
    decision = closed(policy["decision"], ("aggregate", "tau", "axes"),
                      "BRAID_POLICY_FIELDS_INVALID")
    require(decision["aggregate"] == AGGREGATE and type(decision["tau"]) is str and
            re.fullmatch(r"[1-9][0-9]{0,3}/[1-9][0-9]{0,3}", decision["tau"]) and
            0 < Fraction(decision["tau"]) <= 1 and
            rational_text(Fraction(decision["tau"])) == decision["tau"] and
            type(decision["axes"]) is list and
            [a.get("id") if type(a) is dict else None for a in decision["axes"]] == list(AXES)
            and all(set(a) == {"id", "weight"} and type(a["weight"]) is int and
                    1 <= a["weight"] <= 8 for a in decision["axes"]),
            "BRAID_DECISION_POLICY_INVALID")
    ratchet = closed(policy["ratchet"], ("floor", "retired_cords"), "BRAID_POLICY_FIELDS_INVALID")
    floor = closed(ratchet["floor"], FLOOR_FIELDS, "BRAID_RATCHET_POLICY_INVALID")
    for name in FLOOR_FIELDS:
        if name != "declared_axioms_allowed":
            natural(floor[name], "BRAID_RATCHET_POLICY_INVALID")
    allowed = floor["declared_axioms_allowed"]
    require(type(allowed) is list and allowed == sorted(set(allowed)) and len(allowed) <= 400
            and all(type(a) is str and 0 < len(a) <= 300 for a in allowed) and
            type(ratchet["retired_cords"]) is list and
            ratchet["retired_cords"] == sorted(set(ratchet["retired_cords"])) and
            all(type(k) is str and 0 < len(k) <= 400 for k in ratchet["retired_cords"]),
            "BRAID_RATCHET_POLICY_INVALID")
    return policy


def _lean_binding(policy, census, witness):
    """How the Lean witness relates to this census. Never joins a witness of another commit."""
    if witness is None:
        return "NOT_SUPPLIED", {}
    validate_lean_witness(witness, policy["lean"])
    repository = policy["lean"]["repository"]
    row = next((r for r in census["repositories"] if r["repository"] == repository), None)
    if row is None or row["state"] != "OBSERVED":
        return "CENSUS_REPOSITORY_UNAVAILABLE", {}
    if witness["commit"] != row["commit"]:
        return "COMMIT_MISMATCH", {}
    if witness["state"] == "UNAVAILABLE":
        return "WITNESS_UNAVAILABLE", {}
    in_census = sorted(c["path"] for c in census["cords"]
                       if c["repository"] == repository and c["is_lean"])
    require(in_census == [f["path"] for f in witness["files"]],
            "BRAID_WITNESS_CENSUS_FILE_SET_MISMATCH")
    return "BOUND_TO_CENSUS_COMMIT", {f["path"]: f for f in witness["files"]}


def _cord_knots(cord, lean_repository, files, modules):
    values = dict.fromkeys(KNOTS, 0)
    values["cords"] = 1
    values["bytes"] = cord["bytes"]
    values["lean_text_sorry_tokens"] = cord["lean_text_sorry_tokens"]
    if cord["is_lean"]:
        values["lean_files"] = 1
        row = files.get(cord["path"]) if cord["repository"] == lean_repository else None
        if row is None:
            # No kernel witness covers this file: unknown, counted as such, never as accepted.
            values["lean_not_judged"] = 1
        else:
            values[{ACCEPTED_DEFAULT: "lean_accepted_default",
                    ACCEPTED_REQUEST: "lean_accepted_on_request",
                    ACCEPTED_STANDALONE: "lean_accepted_standalone",
                    REJECTED: "lean_rejected",
                    NOT_CHECKED: "lean_not_checked_by_policy"}[row["status"]]] = 1
            values["elaborator_sorry_declarations"] = row["elaborator_sorry_declarations"]
            module = modules.get(cord["path"])
            if module is not None:
                values["user_theorems"] = module["user_theorems"]
                values["theorems_trust_base_only"] = module[CLASS_CLEAN]
                values["theorems_sorry_tainted"] = module[CLASS_SORRY]
                values["theorems_declared_axiom_dependent"] = module[CLASS_AXIOM]
                values["theorems_native_decide"] = module[CLASS_NATIVE]
                values["direct_sorry_declarations"] = module["direct_sorry_declarations"]
                values["declared_axioms"] = module["declared_axioms"]
    return [values[name] for name in KNOTS]


def braid_tree(policy, census, witness, binding_files) -> dict:
    """Build the khipu sum-tree for this census, joined with the bound kernel witness."""
    modules = {}
    if binding_files and witness is not None:
        modules = {m["path"]: m for m in witness["modules"] if m["path"] is not None}
    lean_repository = policy["lean"]["repository"]
    cords = [{"key": c["key"], "pendant": c["repository"].split("/", 1)[1] + "|" + c["family"],
              "digest": c["sha256"],
              "knots": _cord_knots(c, lean_repository, binding_files, modules)}
             for c in census["cords"]]
    return build(KNOTS, PARTITIONS, cords,
                 unavailable=[c["key"] for c in census["unavailable_cords"]])


def _database(plan, action_policy, source_policy, verify_plan, validate_plan_policy):
    """Read the database lane's inert plan as a REPORTED, digest-bound input."""
    if plan is None:
        return {"state": "UNAVAILABLE", "label": "UNAVAILABLE", "plan_state": None,
                "plan_content_sha256": None, "catalog_coverage": None,
                "frontier_coverage": None, "finding_codes": None, "inert_actions": None}
    validate_plan_policy(action_policy, source_policy)
    verify_plan(plan, action_policy)
    require(plan["source_binding"] == source_policy["source_binding"],
            "BRAID_PLAN_SOURCE_MISMATCH")
    return {"state": "REPORTED_INPUT_VERIFIED_STRUCTURALLY", "label": "REPORTED",
            "plan_state": plan["state"], "plan_content_sha256": plan["content_sha256"],
            "catalog_coverage": [plan["catalog_coverage"]["numerator"],
                                 plan["catalog_coverage"]["denominator"]],
            "frontier_coverage": [plan["frontier_coverage"]["numerator"],
                                  plan["frontier_coverage"]["denominator"]],
            "finding_codes": list(plan["finding_codes"]),
            "inert_actions": sorted(a["action_id"] for a in plan["actions"])}


def _ratchet(policy, tree, lean_summary, previous, previous_tree) -> dict:
    floor = policy["ratchet"]["floor"]
    violations, can_tighten = [], []
    if lean_summary["binding"] == "BOUND_TO_CENSUS_COMMIT":
        accepted = lean_summary["files_kernel_accepted"]
        if accepted < floor["lean_files_kernel_accepted_min"]:
            violations.append("KERNEL_ACCEPTED_FILES_BELOW_FLOOR")
        elif accepted > floor["lean_files_kernel_accepted_min"]:
            can_tighten.append("lean_files_kernel_accepted_min")
        for name, measured, bad in (
                ("lean_rejected_max", lean_summary["files_rejected"], "KERNEL_REJECTED_FILES_ABOVE_FLOOR"),
                ("theorems_sorry_tainted_max", knot(tree, "theorems_sorry_tainted"),
                 "SORRY_TAINTED_THEOREMS_ABOVE_FLOOR"),
                ("direct_sorry_declarations_max", knot(tree, "direct_sorry_declarations"),
                 "DIRECT_SORRY_DECLARATIONS_ABOVE_FLOOR")):
            if measured > floor[name]:
                violations.append(bad)
            elif measured < floor[name]:
                can_tighten.append(name)
        new_axioms = sorted(set(lean_summary["declared_axiom_names"]) -
                            set(floor["declared_axioms_allowed"]))
        if new_axioms:
            violations.append("DECLARED_AXIOM_NOT_IN_ALLOWED_SET")
        if set(floor["declared_axioms_allowed"]) - set(lean_summary["declared_axiom_names"]):
            can_tighten.append("declared_axioms_allowed")
        if lean_summary["locked_guard_allowed"] < floor["locked_guard_allowed_min"]:
            violations.append("LOCKED_GUARD_BELOW_FLOOR")
        floor_state = "CHECKED"
    else:
        new_axioms = []
        floor_state = "NOT_COMPARABLE_NO_BOUND_KERNEL_WITNESS"
    against_previous = {"state": "GENESIS_NO_PREVIOUS_TURN", "removed_cords": [],
                        "added_cords": 0, "content_changed_cords": 0, "sum_delta": None}
    if previous is not None:
        change = diff(previous_tree, tree)
        retired = set(policy["ratchet"]["retired_cords"])
        vanished = [key for key in change["removed"] if key not in retired]
        if vanished:
            violations.append("CORD_VANISHED_WITHOUT_RETIREMENT")
        both_bound = (previous["lean"]["binding"] == "BOUND_TO_CENSUS_COMMIT" and
                      lean_summary["binding"] == "BOUND_TO_CENSUS_COMMIT")
        if both_bound:
            delta = change["sum_delta"]
            if any(delta[name] > 0 for name in (
                    "theorems_sorry_tainted", "direct_sorry_declarations", "declared_axioms",
                    "lean_rejected")):
                violations.append("PROOF_DEBT_INCREASED_SINCE_PREVIOUS_TURN")
            if (delta["lean_accepted_default"] + delta["lean_accepted_on_request"] +
                    delta["lean_accepted_standalone"]) < 0:
                violations.append("KERNEL_ACCEPTED_FILES_DECREASED_SINCE_PREVIOUS_TURN")
        against_previous = {
            "state": "COMPARED" if both_bound else "COMPARED_SOURCES_ONLY",
            "removed_cords": vanished[:200], "added_cords": len(change["added"]),
            "content_changed_cords": len(change["content_changed"]),
            "sum_delta": change["sum_delta"]}
    return {"floor_state": floor_state, "violations": sorted(set(violations)),
            "can_tighten": sorted(set(can_tighten)),
            "declared_axioms_outside_allowed_set": new_axioms,
            "against_previous_turn": against_previous}


def _append_step(steps, phase, state, detail, evidence):
    record = {"ordinal": len(steps) + 1, "phase": phase, "state": state,
              "prev_sha256": steps[-1]["sha256"] if steps else GENESIS,
              "detail": detail, "evidence": evidence}
    record["sha256"] = sha256_hex(canonical(record))
    steps.append(record)


def turn(policy, census, *, lean_witness=None, hatun_witness=None, kat_report=None,
         db_plan=None, action_policy=None, source_policy=None, v_one_report=None,
         v_one_policy=None, previous_turn=None, previous_tree=None, previous_lake_wrap=None,
         previous_turn_sha256=None, input_digests=None) -> tuple:
    """Braid one turn. Returns ``(report, khipu_tree)``. Pure: executes nothing."""
    validate_policy(policy)
    cords = validate_census(census, policy["census"])
    digests = dict(input_digests or {})
    require(all(v is None or (type(v) is str and SHA64.fullmatch(v)) for v in digests.values())
            and set(digests) <= {"policy", "census", "lean_witness", "hatun_witness",
                                 "known_answers", "database_plan", "v_one_report",
                                 "previous_turn", "previous_khipu_tree",
                                 "previous_lake_wrap"}, "BRAID_INPUT_DIGEST_INVALID")
    # v1 lives on unchanged; its verifier and the planner's verifier are reused as they are.
    try:
        from tools.database_agentic_planner import verify_plan, validate_policy as plan_policy
        from tools.database_ouroboros_braid import verify_report as verify_v_one
    except ModuleNotFoundError:  # pragma: no cover - same tree, direct execution
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from tools.database_agentic_planner import verify_plan, validate_policy as plan_policy
        from tools.database_ouroboros_braid import verify_report as verify_v_one

    # ---- the tail: the previous turn must itself verify before it is consumed
    require((previous_turn is None) == (previous_tree is None), "BRAID_PREVIOUS_PAIR_INCOMPLETE")
    ordinal, previous_id, lake_state = 1, None, "NOT_SUPPLIED"
    if previous_turn is not None:
        verify_turn(previous_turn, policy_for_shape=None, tree=previous_tree)
        require(type(previous_turn_sha256) is str and SHA64.fullmatch(previous_turn_sha256),
                "BRAID_PREVIOUS_DIGEST_REQUIRED")
        ordinal, previous_id = previous_turn["ordinal"] + 1, previous_turn["turn_id"]
        if previous_lake_wrap is not None:
            validate_wrap(previous_lake_wrap, policy["lake"])
            bound = (previous_lake_wrap["subject"] == previous_id and
                     previous_lake_wrap["input_digest"] == previous_turn["inputs_digest"] and
                     previous_lake_wrap["stored_object_digest"] == previous_turn_sha256 and
                     previous_lake_wrap["state"] == "CANONICAL_RECEIPT_EMITTED_UNSIGNED")
            lake_state = "VERIFIED_UNSIGNED_BINDS_PREVIOUS_TURN" if bound else "MISMATCH"
    else:
        require(previous_lake_wrap is None and previous_turn_sha256 is None,
                "BRAID_PREVIOUS_PAIR_INCOMPLETE")

    binding, files = _lean_binding(policy, census, lean_witness)
    tree = braid_tree(policy, census, lean_witness, files)
    accepted = (knot(tree, "lean_accepted_default") + knot(tree, "lean_accepted_on_request") +
                knot(tree, "lean_accepted_standalone"))
    bound = binding == "BOUND_TO_CENSUS_COMMIT"
    carrier = None
    if bound:
        carrier = next(c for c in lean_witness["carrier_theorems"]
                       if c["decl"] == policy["khipu"]["lean_carrier"])
    lean_summary = {
        "binding": binding,
        "label": "MEASURED" if bound else "UNAVAILABLE",
        "witness_state": lean_witness["state"] if lean_witness is not None else None,
        "commit": lean_witness["commit"] if lean_witness is not None else None,
        "toolchain_pin": policy["lean"]["toolchain_pin"],
        "files_kernel_accepted": accepted if bound else None,
        "files_rejected": knot(tree, "lean_rejected") if bound else None,
        "files_not_checked_by_policy": knot(tree, "lean_not_checked_by_policy") if bound else None,
        "file_totals": lean_witness["file_totals"] if bound else None,
        "theorem_totals": lean_witness["theorem_totals"] if bound else None,
        "locked_guard_allowed": lean_witness["locked_guard"]["allowed"] if bound and
        lean_witness["locked_guard"] else None,
        "locked_guard_refused": lean_witness["locked_guard"]["refused"] if bound and
        lean_witness["locked_guard"] else None,
        "locked_guard_expected": policy["lean"]["locked_guard"]["expected_allowed"],
        "census_rows_sha256": lean_witness["census"]["rows_sha256"] if bound else None,
        "declared_axiom_names": [a["decl"] for a in lean_witness["declared_axioms"]]
        if bound else None,
        "sorry_source_names": [s["decl"] for s in lean_witness["sorry_sources"]]
        if bound else None,
        "khipu_carrier": {"decl": policy["khipu"]["lean_carrier"],
                          "found": carrier["found"] if carrier else None,
                          "class": carrier["class"] if carrier else None},
        "independent_kernel_replay": False,
    }
    if hatun_witness is not None:
        validate_hatun_witness(hatun_witness, policy["hatun"])
    hatun_summary = {
        "label": "MEASURED" if hatun_witness is not None else "UNAVAILABLE",
        "state": hatun_witness["state"] if hatun_witness is not None else None,
        "commit": hatun_witness["commit"] if hatun_witness is not None else None,
        "source_modules_digest": hatun_witness["source_modules_digest"]
        if hatun_witness is not None else None,
        "kernel_state": hatun_witness["kernel"]["state"] if hatun_witness is not None else None,
        "mcp_state": hatun_witness["mcp"]["state"] if hatun_witness is not None else None,
        "probes_matched": hatun_witness["probes_matched"] if hatun_witness is not None else None,
        "probes_expected": hatun_witness["probes_expected"] if hatun_witness is not None else None,
        "effect_authority": "NOT_ATTACHED",
    }
    if kat_report is not None:
        validate_kat_report(kat_report)
        require(kat_report["census_sha256"] is None or digests.get("census") is None or
                kat_report["census_sha256"] == digests["census"],
                "BRAID_KNOWN_ANSWERS_CENSUS_MISMATCH")
    kat_summary = {
        "label": "MEASURED" if kat_report is not None else "UNAVAILABLE",
        "review_status": kat_report["review_status"] if kat_report is not None else None,
        "answer_set_sha256": kat_report["answer_set_sha256"] if kat_report is not None else None,
        **{name: (kat_report[name] if kat_report is not None else None)
           for name in ("answers", "evaluated", "passed", "failed", "invalid_claims", "stale",
                        "source_not_in_census", "rebound_by_line")},
        "families": kat_report["families"] if kat_report is not None else None,
    }
    database = _database(db_plan, action_policy, source_policy, verify_plan, plan_policy)
    v_one = {"state": "NOT_SUPPLIED", "source_matched_count": None, "source_ref_count": None}
    if v_one_report is not None:
        require(db_plan is not None and v_one_policy is not None, "BRAID_V_ONE_INPUTS_INCOMPLETE")
        verify_v_one(v_one_report, v_one_policy, db_plan)
        v_one = {"state": "VERIFIED_BY_V_ONE_VERIFIER",
                 "source_matched_count": v_one_report["source_matched_count"],
                 "source_ref_count": v_one_report["source_ref_count"]}

    ratchet = _ratchet(policy, tree, lean_summary, previous_turn, previous_tree)

    # ---- guards first: a refusal here means NO aggregate is formed (never a zero score)
    guards = []
    if census["state"] != "COMPLETE":
        guards.append("CENSUS_PARTIAL")
    if binding != "BOUND_TO_CENSUS_COMMIT":
        guards.append("LEAN_WITNESS_" + ("NOT_SUPPLIED" if binding == "NOT_SUPPLIED" else
                                         "NOT_BOUND_TO_CENSUS"))
    elif carrier is None or carrier["found"] is not True or carrier["class"] != CLASS_CLEAN:
        guards.append("KHIPU_LEAN_CARRIER_NOT_KERNEL_CLEAN")
    if hatun_witness is None:
        guards.append("HATUN_WITNESS_NOT_SUPPLIED")
    elif hatun_witness["kernel"]["state"] != "EXECUTED" or hatun_witness["mcp"]["state"] != "EXECUTED":
        guards.append("HATUN_LADDER_NOT_FULLY_EXECUTED")
    if kat_report is None:
        guards.append("KNOWN_ANSWERS_NOT_SUPPLIED")
    elif kat_report["evaluated"] == 0:
        guards.append("KNOWN_ANSWERS_NONE_BOUND")
    if db_plan is None:
        guards.append("DATABASE_PLAN_NOT_SUPPLIED")
    if ratchet["violations"]:
        guards.append("RATCHET_VIOLATION")
    if lake_state == "MISMATCH":
        guards.append("PREVIOUS_LAKE_RECEIPT_DOES_NOT_BIND_PREVIOUS_TURN")

    computed = {}
    present = knot(tree, "cords")
    computed["source_cords_present"] = ratio(present, present + len(tree["unavailable_cords"]))
    if bound:
        judged = accepted + knot(tree, "lean_rejected")
        if judged:
            computed["lean_files_kernel_accepted"] = ratio(accepted, judged)
        if knot(tree, "user_theorems"):
            computed["theorems_trust_base_only"] = ratio(knot(tree, "theorems_trust_base_only"),
                                                         knot(tree, "user_theorems"))
        expected = policy["lean"]["locked_guard"]["expected_allowed"]
        guard = lean_witness["locked_guard"]
        if guard is not None and expected:
            computed["locked_set_guard"] = (
                Fraction(0) if guard["refused"] else ratio(min(guard["allowed"], expected), expected))
    if kat_report is not None and kat_report["evaluated"]:
        computed["codex_known_answers"] = ratio(kat_report["passed"], kat_report["evaluated"])
    if hatun_witness is not None and hatun_witness["probes_expected"]:
        computed["hatun_veto_ladder"] = ratio(hatun_witness["probes_matched"],
                                              hatun_witness["probes_expected"])
    if db_plan is not None:
        for name, key in (("database_catalog_coverage", "catalog_coverage"),
                          ("database_frontier_coverage", "frontier_coverage")):
            numerator, denominator = database[key]
            if denominator:
                computed[name] = ratio(min(numerator, denominator), denominator)
    if not guards and set(computed) != set(AXES):
        guards.append("AXIS_EVIDENCE_INCOMPLETE")
    weights = {a["id"]: a["weight"] for a in policy["decision"]["axes"]}
    tau = Fraction(policy["decision"]["tau"])
    if guards:
        decision = {"refusal_path": "PRE_AGGREGATION", "sub_reasons": guards,
                    "axes_computed": {k: rational_text(v) for k, v in sorted(computed.items())},
                    "axes_missing": sorted(set(AXES) - set(computed)), "exact": None,
                    "tau": policy["decision"]["tau"]}
    else:
        exact = decide(computed, weights, tau)
        decision = {"refusal_path": exact["refusal_path"], "sub_reasons": [],
                    "axes_computed": dict(exact["axes"]), "axes_missing": [], "exact": exact,
                    "tau": policy["decision"]["tau"]}
    met = decision["refusal_path"] == PATH_NONE
    state = STATE_MET if met else STATE_HOLD

    census_summary = {
        "label": "MEASURED", "state": census["state"],
        "repositories": [{"repository": r["repository"], "state": r["state"],
                          "commit": r["commit"], "cords": r["cords"],
                          "tracked_files": r["tracked_files"],
                          "out_of_scope_files": r["out_of_scope_files"]}
                         for r in census["repositories"]],
        "cords": len(cords), "unavailable_cords": len(census["unavailable_cords"]),
        "families": _family_counts(cords),
    }
    khipu_summary = {
        "label": "MEASURED", "primary_hash": tree["primary"]["hash"],
        "primary_sum": dict(zip(KNOTS, tree["primary"]["sum"])),
        "pendant_count": tree["primary"]["pendant_count"],
        "cord_count": tree["primary"]["cord_count"],
        "unavailable_cords": len(tree["unavailable_cords"]),
        "conservation": "SUM_OF_SUMS_AND_PARTITIONS_VERIFIED_AT_EVERY_NODE",
        "integrity": "UNSIGNED_HASH_TREE_WITH_SUMS",
    }
    state_digest = digest({
        "policy": digests.get("policy"), "census": [
            [r["repository"], r["state"], r["commit"]] for r in census["repositories"]],
        "khipu": tree["primary"]["hash"], "lean": lean_summary, "hatun": hatun_summary,
        "known_answers": kat_summary, "database": database, "v_one": v_one,
        # The comparison with the previous turn is a relation between turns, not state:
        # leaving it out lets unchanged evidence reproduce the same digest (a fixed point).
        "ratchet": {k: v for k, v in ratchet.items() if k != "against_previous_turn"},
        "decision": decision})
    inputs = {name: digests.get(name) for name in (
        "policy", "census", "lean_witness", "hatun_witness", "known_answers", "database_plan",
        "v_one_report", "previous_turn", "previous_khipu_tree", "previous_lake_wrap")}
    turn_id = "braid-turn:" + digest({"state": state_digest, "previous": previous_id,
                                      "ordinal": ordinal})[:32]
    fixed_point = previous_turn is not None and previous_turn["state_digest"] == state_digest

    steps = []
    _append_step(steps, PHASES[0], "OBSERVED" if lake_state != "MISMATCH" else "HOLD",
                 ["POLICY_VALIDATED", "TAIL_" + ("CONSUMED" if previous_turn is not None
                                                 else "GENESIS")],
                 {"policy_sha256": inputs["policy"], "previous_turn_id": previous_id,
                  "previous_turn_lake_receipt": lake_state})
    _append_step(steps, PHASES[1], "OBSERVED" if census["state"] == "COMPLETE" else "HOLD",
                 ["GIT_OBJECT_BYTES_CHECKED", "MISSING_IS_UNAVAILABLE_NOT_ZERO"],
                 {"census_sha256": inputs["census"], "cords": len(cords),
                  "unavailable_cords": len(census["unavailable_cords"])})
    _append_step(steps, PHASES[2], "OBSERVED",
                 ["SUM_OF_SUMS_CONSERVED", "PARTITIONS_CONSERVED"],
                 {"primary_hash": tree["primary"]["hash"],
                  "pendants": tree["primary"]["pendant_count"]})
    proof_ok = (bound and lean_witness["state"] == "KERNEL_EXECUTED" and
                hatun_witness is not None and hatun_witness["state"] == "VETO_LADDER_CONFORMS")
    _append_step(steps, PHASES[3], "OBSERVED" if proof_ok else "HOLD",
                 ["LEAN_KERNEL_" + ("EXECUTED_AND_BOUND" if bound else "NOT_BOUND"),
                  "HATUN_LADDER_" + (hatun_witness["state"] if hatun_witness is not None
                                     else "NOT_SUPPLIED"),
                  "EFFECT_AUTHORITY_NOT_ATTACHED"],
                 {"lean_witness_sha256": inputs["lean_witness"],
                  "hatun_witness_sha256": inputs["hatun_witness"]})
    _append_step(steps, PHASES[4], "OBSERVED" if met else "HOLD",
                 ["DECISION_" + decision["refusal_path"],
                  "STOP_NO_EXTERNAL_EFFECTS", "LAKE_RECEIPT_WRAPS_THIS_TURN_AFTERWARDS"],
                 {"state_digest": state_digest, "turn_id": turn_id})
    require(len(steps) == policy["max_steps"] and tuple(s["phase"] for s in steps) == PHASES,
            "BRAID_TERMINATION_BUDGET")
    report = {
        "schema": SCHEMA, "state": state,
        "termination": "CLOSED_EVIDENCE_COMPLETE_NO_AUTHORITY" if met else "CLOSED_WITH_HOLD",
        "doctrine": policy["doctrine"], "max_steps": policy["max_steps"],
        "executed_steps": len(steps), "ordinal": ordinal, "turn_id": turn_id,
        "previous_turn_id": previous_id, "previous_turn_sha256": previous_turn_sha256,
        "previous_turn_lake_receipt": lake_state, "ouroboros_fixed_point": fixed_point,
        "inputs": inputs, "inputs_digest": digest(inputs), "state_digest": state_digest,
        "census": census_summary, "khipu": khipu_summary, "lean": lean_summary,
        "hatun": hatun_summary, "known_answers": kat_summary, "database": database,
        "v_one_braid": v_one, "ratchet": ratchet, "decision": decision,
        "evidence_labels": {
            "MEASURED": "produced by a tool run for this turn and read from its output file",
            "REPORTED": "supplied by another lane; shape-checked and digest-bound, not re-observed",
            "UNAVAILABLE": "no evidence supplied; never scored, neither as zero nor as a pass",
        },
        "fixed_claims": dict(policy["fixed_claims"]), "loop_trace": steps,
        "integrity_kind": "UNSIGNED_STRUCTURAL_SHA256_CHAIN", "signed": False,
    }
    report.update({flag: False for flag in _FALSE_FLAGS})
    report.update({name: None for name in _NULL_FIELDS})
    verify_turn(report, policy_for_shape=policy, tree=tree)
    return report, tree


def _family_counts(cords) -> dict:
    counts = {}
    for cord in cords:
        counts[cord["family"]] = counts.get(cord["family"], 0) + 1
    return {name: counts[name] for name in sorted(counts)}


def verify_turn(value, *, policy_for_shape=None, tree=None) -> bool:
    """Independently re-check a turn report: shape, chain, identity, decision, tree binding."""
    closed(value, _FIELDS, "BRAID_TURN_FIELDS_INVALID")
    require(value["schema"] == SCHEMA and value["doctrine"] == FIXED_DOCTRINE and
            value["max_steps"] == len(PHASES) and value["executed_steps"] == len(PHASES) and
            value["integrity_kind"] == "UNSIGNED_STRUCTURAL_SHA256_CHAIN" and
            value["signed"] is False, "BRAID_TURN_SCHEMA_INVALID")
    require(all(value[flag] is False for flag in _FALSE_FLAGS) and
            all(value[name] is None for name in _NULL_FIELDS) and
            value["fixed_claims"] == FIXED_CLAIMS, "BRAID_FALSE_AUTHORITY_CLAIM")
    require(type(value["ordinal"]) is int and value["ordinal"] >= 1 and
            type(value["turn_id"]) is str and TURN_ID.fullmatch(value["turn_id"]) and
            type(value["state_digest"]) is str and SHA64.fullmatch(value["state_digest"]) and
            type(value["inputs_digest"]) is str and SHA64.fullmatch(value["inputs_digest"]),
            "BRAID_TURN_IDENTITY_INVALID")
    previous = value["previous_turn_id"]
    require((previous is None) == (value["ordinal"] == 1) and
            (previous is None or (type(previous) is str and TURN_ID.fullmatch(previous))) and
            (previous is None) == (value["previous_turn_sha256"] is None),
            "BRAID_TURN_CHAIN_INVALID")
    require(value["turn_id"] == "braid-turn:" + digest(
        {"state": value["state_digest"], "previous": previous,
         "ordinal": value["ordinal"]})[:32], "BRAID_TURN_ID_MISMATCH")
    require(type(value["inputs"]) is dict and value["inputs_digest"] == digest(value["inputs"]),
            "BRAID_TURN_INPUTS_DIGEST_MISMATCH")
    require(value["previous_turn_lake_receipt"] in (
        "NOT_SUPPLIED", "VERIFIED_UNSIGNED_BINDS_PREVIOUS_TURN", "MISMATCH") and
            type(value["ouroboros_fixed_point"]) is bool, "BRAID_TURN_FIELDS_INVALID")
    decision = closed(value["decision"], ("refusal_path", "sub_reasons", "axes_computed",
                                          "axes_missing", "exact", "tau"),
                      "BRAID_DECISION_FIELDS_INVALID")
    reasons = decision["sub_reasons"]
    require(type(reasons) is list and all(type(r) is str and REASON.fullmatch(r) for r in reasons)
            and type(decision["axes_computed"]) is dict and
            set(decision["axes_computed"]) <= set(AXES), "BRAID_DECISION_FIELDS_INVALID")
    if decision["refusal_path"] == "PRE_AGGREGATION":
        # A refused aggregate carries its reasons and no score at all.
        require(len(reasons) > 0 and decision["exact"] is None and
                decision["axes_missing"] == sorted(set(AXES) - set(decision["axes_computed"])),
                "BRAID_DECISION_REFUSAL_INVALID")
    else:
        require(reasons == [] and decision["axes_missing"] == [] and
                type(decision["exact"]) is dict and verify_decision(decision["exact"]) and
                decision["exact"]["refusal_path"] == decision["refusal_path"] and
                decision["exact"]["axes"] == decision["axes_computed"] and
                decision["exact"]["tau"] == decision["tau"] and
                set(decision["axes_computed"]) == set(AXES), "BRAID_DECISION_DRIFT")
    met = decision["refusal_path"] == PATH_NONE
    require(value["state"] == (STATE_MET if met else STATE_HOLD) and
            value["termination"] == ("CLOSED_EVIDENCE_COMPLETE_NO_AUTHORITY" if met
                                     else "CLOSED_WITH_HOLD"), "BRAID_TURN_STATE_DRIFT")
    require(type(value["hatun"]) is dict and
            value["hatun"].get("effect_authority") == "NOT_ATTACHED" and
            type(value["lean"]) is dict and
            value["lean"].get("independent_kernel_replay") is False and
            type(value["ratchet"]) is dict and type(value["ratchet"].get("violations")) is list
            and (not value["ratchet"]["violations"] or "RATCHET_VIOLATION" in reasons),
            "BRAID_TURN_BOUNDARY_DRIFT")
    steps = value["loop_trace"]
    require(type(steps) is list and len(steps) == len(PHASES), "BRAID_TRACE_LENGTH_INVALID")
    link = GENESIS
    for ordinal, step in enumerate(steps, 1):
        closed(step, ("ordinal", "phase", "state", "prev_sha256", "detail", "evidence", "sha256"),
               "BRAID_TRACE_SCHEMA_INVALID")
        require(step["ordinal"] == ordinal and step["phase"] == PHASES[ordinal - 1] and
                step["state"] in ("OBSERVED", "HOLD") and step["prev_sha256"] == link,
                "BRAID_TRACE_CONTRACT_DRIFT")
        declared = step["sha256"]
        body = {k: v for k, v in step.items() if k != "sha256"}
        require(type(declared) is str and SHA64.fullmatch(declared) and
                sha256_hex(canonical(body)) == declared, "BRAID_TRACE_HASH_MISMATCH")
        link = declared
    require(steps[-1]["state"] == ("OBSERVED" if met else "HOLD") and
            "STOP_NO_EXTERNAL_EFFECTS" in steps[-1]["detail"] and
            steps[-1]["evidence"] == {"state_digest": value["state_digest"],
                                      "turn_id": value["turn_id"]}, "BRAID_TERMINAL_NOT_CLOSED")
    khipu = value["khipu"]
    require(type(khipu) is dict and type(khipu.get("primary_hash")) is str and
            SHA64.fullmatch(khipu["primary_hash"]) and
            steps[2]["evidence"].get("primary_hash") == khipu["primary_hash"],
            "BRAID_KHIPU_BINDING_INVALID")
    if tree is not None:
        verify(tree)
        require(tree["knots"] == KNOTS and tree["partitions"] == PARTITIONS and
                tree["primary"]["hash"] == khipu["primary_hash"] and
                khipu["primary_sum"] == dict(zip(KNOTS, tree["primary"]["sum"])) and
                khipu["cord_count"] == tree["primary"]["cord_count"],
                "BRAID_KHIPU_TREE_MISMATCH")
    if policy_for_shape is not None:
        validate_policy(policy_for_shape)
        require(decision["tau"] == policy_for_shape["decision"]["tau"] and
                (decision["exact"] is None or decision["exact"]["weights"] ==
                 {a["id"]: a["weight"] for a in policy_for_shape["decision"]["axes"]}),
                "BRAID_DECISION_POLICY_DRIFT")
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description="One bounded, no-effect Ouroboros braid v2 turn")
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--census", type=Path, required=True)
    ap.add_argument("--lean-witness", type=Path)
    ap.add_argument("--hatun-witness", type=Path)
    ap.add_argument("--known-answers-report", type=Path)
    ap.add_argument("--db-plan", type=Path)
    ap.add_argument("--db-action-policy", type=Path)
    ap.add_argument("--source-policy", type=Path)
    ap.add_argument("--v-one-report", type=Path)
    ap.add_argument("--v-one-policy", type=Path)
    ap.add_argument("--previous-turn", type=Path)
    ap.add_argument("--previous-khipu-tree", type=Path)
    ap.add_argument("--previous-lake-wrap", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--khipu-tree-output", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        policy, policy_sha = read_json(args.policy, max_bytes=MAX_POLICY_BYTES)
        validate_policy(policy)
        census, census_sha = read_json(args.census, max_bytes=MAX_CENSUS_BYTES)
        digests = {"policy": policy_sha, "census": census_sha}

        def optional(path, name, limit):
            if path is None:
                return None
            loaded, sha = read_json(path, max_bytes=limit)
            digests[name] = sha
            return loaded

        lean = optional(args.lean_witness, "lean_witness", 8388608)
        hatun = optional(args.hatun_witness, "hatun_witness", 262144)
        answers = optional(args.known_answers_report, "known_answers", 4194304)
        plan = optional(args.db_plan, "database_plan", 65536)
        v_one = optional(args.v_one_report, "v_one_report", 65536)
        previous = optional(args.previous_turn, "previous_turn", MAX_TURN_BYTES)
        previous_tree = optional(args.previous_khipu_tree, "previous_khipu_tree", MAX_TREE_BYTES)
        previous_wrap = optional(args.previous_lake_wrap, "previous_lake_wrap", 65536)
        action_policy = source_policy = v_one_policy = None
        if plan is not None:
            require(args.db_action_policy is not None and args.source_policy is not None,
                    "BRAID_PLAN_POLICIES_REQUIRED")
            action_policy, _ = read_json(args.db_action_policy, max_bytes=65536)
            source_policy, _ = read_json(args.source_policy, max_bytes=65536)
        if v_one is not None:
            require(args.v_one_policy is not None, "BRAID_V_ONE_INPUTS_INCOMPLETE")
            v_one_policy, v_one_policy_sha = read_json(args.v_one_policy, max_bytes=65536)
            require(v_one_policy_sha == policy["v_one_policy_sha256"],
                    "BRAID_V_ONE_POLICY_DIGEST_MISMATCH")
        report, tree = turn(
            policy, census, lean_witness=lean, hatun_witness=hatun, kat_report=answers,
            db_plan=plan, action_policy=action_policy, source_policy=source_policy,
            v_one_report=v_one, v_one_policy=v_one_policy, previous_turn=previous,
            previous_tree=previous_tree, previous_lake_wrap=previous_wrap,
            previous_turn_sha256=digests.get("previous_turn"), input_digests=digests)
        require(args.output.resolve() != args.khipu_tree_output.resolve(),
                "OUTPUT_PATH_DENIED")
        write_exclusive(args.khipu_tree_output, tree, max_bytes=MAX_TREE_BYTES,
                        checkout=checkout_root())
        write_exclusive(args.output, report, max_bytes=MAX_TURN_BYTES, checkout=checkout_root())
        print(json.dumps({"state": report["state"], "termination": report["termination"],
                          "turn_id": report["turn_id"], "ordinal": report["ordinal"],
                          "refusal_path": report["decision"]["refusal_path"],
                          "sub_reasons": report["decision"]["sub_reasons"],
                          "cords": report["khipu"]["cord_count"],
                          "fixed_point": report["ouroboros_fixed_point"], "signed": False,
                          "production_authorized": False,
                          "external_effects_performed": False}))
        return 2  # a closed turn is evidence, never a promotion; there is no exit 0
    except InputError as exc:
        code = exc.code
    except Exception:
        code = "BRAID_TURN_UNAVAILABLE"
    print(json.dumps({"state": "UNAVAILABLE", "code": code, "signed": False,
                      "production_authorized": False, "external_effects_performed": False}))
    return 3


if __name__ == "__main__":
    sys.exit(main())
