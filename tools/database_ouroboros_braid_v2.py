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

Each turn consumes the previous turn's receipt, so the loop closes on itself.
Proof debt is compared with the last turn that had a bound kernel witness, so it
cannot rise between turns, not even through a turn that had no witness, without
a RATCHET_VIOLATION.

This function is pure: it reads supplied evidence, executes nothing, opens no
network connection and writes only the two files it is asked for. Evidence that
is absent, bound to another commit or census, outside the policy's evidence
window, or that did not conform (a kernel witness in HOLD, a veto that did not
hold) refuses the aggregate with a named reason. It is never scored as zero and
never scored as partial credit. The decision is an exact weighted geometric
mean (zero-pinned) against a threshold fixed in the policy before the run.

A verifier takes nothing in a report on trust. ``verify_turn`` re-derives the
guards, the axes, the exact decision, the five trace steps, the state digest and
the turn id from the report's own observed sections and requires the same
bytes, so an edited verdict does not verify. ``replay_turn`` goes further: given
the evidence files, it re-runs the turn and requires a byte-identical report.

It can NOT authorize anything. Reaching the threshold yields
EVIDENCE_THRESHOLD_MET_NO_AUTHORITY: an unsigned statement about evidence. It is
not a repaired database, not a production admission, not a signature and not a
judgement that any theorem means what its name suggests. Database verdicts are
REPORTED inputs from another lane; this tool never queries a database. Exit
codes: 2 for a closed turn (HOLD or MET alike), 3 for a refusal.
"""
from __future__ import annotations

import argparse
from datetime import datetime
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
        MAX_CENSUS_BYTES, MAX_MAP_BYTES, validate_census, validate_census_policy,
        validate_family_map,
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
        MAX_CENSUS_BYTES, MAX_MAP_BYTES, validate_census, validate_census_policy,
        validate_family_map,
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
# Theorem-class knots are counted over kernel-accepted modules only. A Lean file
# whose counts are unknown carries lean_theorem_counts_unknown = 1, so a zero in
# a theorem knot never stands for "not judged".
KNOTS = [
    "cords", "bytes", "lean_files", "lean_accepted_default", "lean_accepted_on_request",
    "lean_accepted_standalone", "lean_rejected", "lean_not_checked_by_policy",
    "lean_not_judged", "lean_theorem_counts_unknown", "user_theorems",
    "theorems_trust_base_only", "theorems_sorry_tainted", "theorems_declared_axiom_dependent",
    "theorems_native_decide", "direct_sorry_declarations", "declared_axioms",
    "elaborator_sorry_declarations", "lean_text_sorry_tokens",
]
PARTITIONS = [
    {"name": "lean_status", "whole": "lean_files",
     "parts": ["lean_accepted_default", "lean_accepted_on_request", "lean_accepted_standalone",
               "lean_rejected", "lean_not_checked_by_policy", "lean_not_judged"]},
    {"name": "theorem_class", "whole": "user_theorems",
     "parts": ["theorems_trust_base_only", "theorems_sorry_tainted",
               "theorems_declared_axiom_dependent", "theorems_native_decide"]},
]
_STATUS_KNOT = {ACCEPTED_DEFAULT: "lean_accepted_default",
                ACCEPTED_REQUEST: "lean_accepted_on_request",
                ACCEPTED_STANDALONE: "lean_accepted_standalone", REJECTED: "lean_rejected",
                NOT_CHECKED: "lean_not_checked_by_policy"}
_ACCEPTED_KNOTS = ("lean_accepted_default", "lean_accepted_on_request", "lean_accepted_standalone")
AXES = (
    "source_cords_present", "lean_files_kernel_accepted", "theorems_trust_base_only",
    "locked_set_guard", "codex_known_answers", "hatun_veto_ladder",
    "database_catalog_coverage", "database_frontier_coverage",
)
_AXIS_SOURCE = {
    "source_cords_present": "census", "lean_files_kernel_accepted": "lean",
    "theorems_trust_base_only": "lean", "locked_set_guard": "lean",
    "codex_known_answers": "known_answers", "hatun_veto_ladder": "hatun",
    "database_catalog_coverage": "database", "database_frontier_coverage": "database",
}
FIXED_CLAIMS = {
    "lambda_claim": "UNCONDITIONAL_UNIQUENESS_DISPROVEN_AS_STATED",
    "khipu_consensus_safety": "CONJECTURE_NOT_A_THEOREM",
    "archaeological_data_rights": "NOT_GRANTED",
    "external_effects": "DENIED",
    "production_authority": "NEVER_GRANTED_BY_THIS_TOOL",
}
FLOOR_FIELDS = ("lean_files_kernel_accepted_min", "lean_rejected_max",
                "theorems_sorry_tainted_max", "direct_sorry_declarations_max",
                "theorems_declared_axiom_dependent_max", "theorems_native_decide_max",
                "theorems_trust_base_only_min", "declared_axioms_allowed",
                "locked_guard_allowed_min")
# (floor field, debt-vector entry, bound, violation)
FLOOR_RULES = (
    ("lean_files_kernel_accepted_min", "lean_files_kernel_accepted", "MIN",
     "KERNEL_ACCEPTED_FILES_BELOW_FLOOR"),
    ("lean_rejected_max", "lean_rejected", "MAX", "KERNEL_REJECTED_FILES_ABOVE_FLOOR"),
    ("theorems_sorry_tainted_max", "theorems_sorry_tainted", "MAX",
     "SORRY_TAINTED_THEOREMS_ABOVE_FLOOR"),
    ("direct_sorry_declarations_max", "direct_sorry_declarations", "MAX",
     "DIRECT_SORRY_DECLARATIONS_ABOVE_FLOOR"),
    ("theorems_declared_axiom_dependent_max", "theorems_declared_axiom_dependent", "MAX",
     "AXIOM_DEPENDENT_THEOREMS_ABOVE_FLOOR"),
    ("theorems_native_decide_max", "theorems_native_decide", "MAX",
     "NATIVE_DECIDE_THEOREMS_ABOVE_FLOOR"),
    ("theorems_trust_base_only_min", "theorems_trust_base_only", "MIN",
     "TRUST_BASE_THEOREMS_BELOW_FLOOR"),
    ("locked_guard_allowed_min", "locked_guard_allowed", "MIN", "LOCKED_GUARD_BELOW_FLOOR"),
)
DEBT = ("lean_rejected", "theorems_sorry_tainted", "direct_sorry_declarations", "declared_axioms",
        "theorems_declared_axiom_dependent", "theorems_native_decide")
CREDIT = ("lean_files_kernel_accepted", "theorems_trust_base_only", "locked_guard_allowed")
VIOLATIONS = frozenset({rule[3] for rule in FLOOR_RULES} | {
    "LOCKED_GUARD_NOT_MEASURED", "DECLARED_AXIOM_NOT_IN_ALLOWED_SET",
    "CORD_VANISHED_WITHOUT_RETIREMENT", "PROOF_DEBT_INCREASED_SINCE_LAST_BOUND_TURN",
    "KERNEL_CREDIT_DECREASED_SINCE_LAST_BOUND_TURN"})
_BETWEEN = ("CORD_VANISHED_WITHOUT_RETIREMENT", "PROOF_DEBT_INCREASED_SINCE_LAST_BOUND_TURN",
            "KERNEL_CREDIT_DECREASED_SINCE_LAST_BOUND_TURN")
BOUND = "BOUND_TO_CENSUS_COMMIT"
CHECKOUT_MATCHES = "ORIGIN_MATCHES"
KAT_BOUND = "BOUND_TO_CENSUS_DIGEST"
NOT_SUPPLIED = "NOT_SUPPLIED"
DATABASE_PASS = "STRUCTURAL_ONLY"
LAKE_STATES = ("NOT_SUPPLIED", "VERIFIED_UNSIGNED_BINDS_PREVIOUS_TURN",
               "VERIFIED_UNSIGNED_BINDS_PREVIOUS_TURN_UNDER_OTHER_PINS", "MISMATCH",
               "RECEIPT_INVALID")
PRODUCIBLE = ("census", "hatun_witness", "known_answers", "lean_witness")
STATE_MET = "EVIDENCE_THRESHOLD_MET_NO_AUTHORITY"
STATE_HOLD = "HOLD"
TURN_ID = re.compile(r"braid-turn:[0-9a-f]{32}\Z")
REASON = re.compile(r"[A-Z][A-Z_]{2,79}\Z")
MAX_POLICY_BYTES = 1048576
MAX_TURN_BYTES = 1048576
MAX_WINDOW_SECONDS = 31 * 86400
_FALSE_FLAGS = ("production_authorized", "external_effects_performed", "database_queried",
                "sql_generated", "sql_executed", "model_inference_invoked",
                "canonical_dsse_signed", "independent_witness", "khipu_missing_is_zero",
                "proofs_promoted", "authority_granted")
_NULL_FIELDS = ("energy_joules", "timing_ms_measured", "loop_tax_ms")
_DERIVED = ("decision", "state", "termination", "state_digest", "turn_id", "loop_trace")
_FIELDS = (
    "schema", "state", "termination", "doctrine", "max_steps", "executed_steps", "ordinal",
    "turn_id", "previous_turn_id", "previous_turn_sha256", "previous_turn_lake_receipt",
    "previous_turn_rejected",
    "ouroboros_fixed_point", "inputs", "inputs_digest", "state_digest", "census", "khipu",
    "lean", "hatun", "known_answers", "database", "v_one_braid", "ratchet", "decision",
    "evidence_times", "evidence_produced_in_invocation", "evidence_labels", "fixed_claims",
    "loop_trace", "integrity_kind", "signed", *_FALSE_FLAGS, *_NULL_FIELDS,
)
EVIDENCE_LABELS = {
    "MEASURED": "produced by a tool run in the same invocation as this turn",
    "REPORTED": "supplied as a file: shape-checked, digest-bound and commit-bound where the "
                "census allows, not re-observed by this invocation",
    "UNAVAILABLE": "absent or not bound to this census; never scored, neither as zero nor "
                   "as a pass",
}


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
    in_census = [r["repository"] for r in policy["census"]["repositories"]]
    require(policy["lean"]["repository"] in in_census and
            policy["hatun"]["repository"] in in_census and
            policy["lake"]["repository"] in in_census,
            "BRAID_POLICY_REPOSITORY_NOT_IN_CENSUS")
    decision = closed(policy["decision"], ("aggregate", "tau", "axes", "evidence_window_seconds"),
                      "BRAID_POLICY_FIELDS_INVALID")
    require(decision["aggregate"] == AGGREGATE and type(decision["tau"]) is str and
            re.fullmatch(r"[1-9][0-9]{0,3}/[1-9][0-9]{0,3}", decision["tau"]) and
            0 < Fraction(decision["tau"]) <= 1 and
            rational_text(Fraction(decision["tau"])) == decision["tau"] and
            type(decision["axes"]) is list and
            [a.get("id") if type(a) is dict else None for a in decision["axes"]] == list(AXES)
            and all(set(a) == {"id", "weight"} and type(a["weight"]) is int and
                    1 <= a["weight"] <= 8 for a in decision["axes"]) and
            type(decision["evidence_window_seconds"]) is int and
            60 <= decision["evidence_window_seconds"] <= MAX_WINDOW_SECONDS,
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


def _census_row(rows, repository):
    return next((r for r in rows if type(r) is dict and r.get("repository") == repository), None)


def _commit_binding(rows, repository, commit) -> str:
    row = _census_row(rows, repository)
    if row is None or row.get("state") != "OBSERVED":
        return "CENSUS_REPOSITORY_UNAVAILABLE"
    return BOUND if commit == row.get("commit") else "COMMIT_MISMATCH"


def _lean_binding(policy, census, witness):
    """How the Lean witness relates to this census. Never joins a witness of another commit."""
    if witness is None:
        return NOT_SUPPLIED, {}
    validate_lean_witness(witness, policy["lean"])
    repository = policy["lean"]["repository"]
    binding = _commit_binding(census["repositories"], repository, witness["commit"])
    if binding != BOUND:
        return binding, {}
    if witness["state"] == "UNAVAILABLE":
        return "WITNESS_UNAVAILABLE", {}
    in_census = sorted(c["path"] for c in census["cords"]
                       if c["repository"] == repository and c["is_lean"])
    if in_census != sorted(f["path"] for f in witness["files"]):
        return "FILE_SET_MISMATCH", {}
    return BOUND, {f["path"]: f for f in witness["files"]}


def _cord_knots(cord, lean_repository, files, modules):
    values = dict.fromkeys(KNOTS, 0)
    values["cords"] = 1
    values["bytes"] = cord["bytes"]
    values["lean_text_sorry_tokens"] = cord["lean_text_sorry_tokens"]
    if cord["is_lean"]:
        values["lean_files"] = 1
        row = files.get(cord["path"]) if cord["repository"] == lean_repository else None
        module = modules.get(cord["path"]) if row is not None else None
        if row is None:
            # No kernel witness covers this file: unknown, counted as such, never as accepted.
            values["lean_not_judged"] = 1
        else:
            values[_STATUS_KNOT[row["status"]]] = 1
            values["elaborator_sorry_declarations"] = row["elaborator_sorry_declarations"]
        if module is None:
            values["lean_theorem_counts_unknown"] = 1
        else:
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


def _debt(lean, primary_sum):
    """Proof debt and kernel credit of a bound turn; None when no kernel witness binds."""
    if lean["binding"] != BOUND:
        return None
    vector = {name: primary_sum[name] for name in DEBT}
    vector["lean_files_kernel_accepted"] = lean["files_kernel_accepted"]
    vector["theorems_trust_base_only"] = primary_sum["theorems_trust_base_only"]
    vector["locked_guard_allowed"] = lean["locked_guard_allowed"]
    return vector


def _floor(floor, lean, debt):
    if debt is None:
        return "NOT_COMPARABLE_NO_BOUND_KERNEL_WITNESS", [], [], []
    violations, tighten = [], []
    for field, name, bound, bad in FLOOR_RULES:
        measured = debt[name]
        if measured is None:
            violations.append("LOCKED_GUARD_NOT_MEASURED")
            continue
        limit = floor[field]
        if (measured < limit) if bound == "MIN" else (measured > limit):
            violations.append(bad)
        elif measured != limit:
            tighten.append(field)
    names = lean["declared_axiom_names"]
    outside = sorted(set(names) - set(floor["declared_axioms_allowed"]))
    if outside:
        violations.append("DECLARED_AXIOM_NOT_IN_ALLOWED_SET")
    if set(floor["declared_axioms_allowed"]) - set(names):
        tighten.append("declared_axioms_allowed")
    return "CHECKED", sorted(set(violations)), sorted(set(tighten)), outside


def _baseline(previous):
    """The debt of the last turn with a bound kernel witness, carried through unbound turns."""
    if previous is None:
        return None, None
    if previous["ratchet"]["debt"] is not None:
        return previous["turn_id"], previous["ratchet"]["debt"]
    carried = previous["ratchet"]["against_previous_turn"]
    return carried["baseline_turn_id"], carried["baseline_debt"]


def _between_violations(record) -> list:
    found = []
    if record["removed_cords_count"]:
        found.append("CORD_VANISHED_WITHOUT_RETIREMENT")
    delta = record["debt_delta"]
    if delta is not None:
        if any(delta.get(name, 0) > 0 for name in DEBT):
            found.append("PROOF_DEBT_INCREASED_SINCE_LAST_BOUND_TURN")
        if any(delta.get(name, 0) < 0 for name in CREDIT):
            found.append("KERNEL_CREDIT_DECREASED_SINCE_LAST_BOUND_TURN")
    return found


def _debt_delta(debt, baseline):
    if debt is None or baseline is None:
        return None
    return {name: debt[name] - baseline[name] for name in (*DEBT, *CREDIT)
            if debt[name] is not None and baseline[name] is not None}


def _ratchet(policy, tree, lean, previous, previous_tree) -> dict:
    debt = _debt(lean, dict(zip(KNOTS, tree["primary"]["sum"])))
    floor_state, violations, tighten, outside = _floor(policy["ratchet"]["floor"], lean, debt)
    record = {"state": "GENESIS_NO_PREVIOUS_TURN", "removed_cords": [], "removed_cords_count": 0,
              "added_cords": 0, "content_changed_cords": 0, "sum_delta": None,
              "baseline_turn_id": None, "baseline_debt": None, "debt_delta": None}
    if previous is not None:
        change = diff(previous_tree, tree)
        retired = set(policy["ratchet"]["retired_cords"])
        vanished = sorted(key for key in change["removed"] if key not in retired)
        baseline_id, baseline = _baseline(previous)
        delta = _debt_delta(debt, baseline)
        record = {
            "state": ("SOURCES_ONLY_NO_BOUND_BASELINE" if delta is None else
                      "COMPARED_WITH_PREVIOUS_TURN" if baseline_id == previous["turn_id"] else
                      "COMPARED_WITH_EARLIER_BOUND_TURN"),
            "removed_cords": vanished[:200], "removed_cords_count": len(vanished),
            "added_cords": len(change["added"]),
            "content_changed_cords": len(change["content_changed"]),
            "sum_delta": change["sum_delta"], "baseline_turn_id": baseline_id,
            "baseline_debt": baseline, "debt_delta": delta}
    return {"floor_state": floor_state,
            "violations": sorted(set(violations) | set(_between_violations(record))),
            "can_tighten": tighten, "declared_axioms_outside_allowed_set": outside,
            "debt": debt, "against_previous_turn": record}


def _time(text):
    stamp = datetime.fromisoformat(text)
    require(stamp.utcoffset() is not None, "BRAID_EVIDENCE_TIME_INVALID")
    return stamp


def _within(window, first, second) -> bool:
    if first is None or second is None:
        return False
    return abs((_time(first) - _time(second)).total_seconds()) <= window


def _guards(report, window) -> list:
    """Every reason the aggregate is refused, from the report's own observed sections."""
    guards = []
    times = report["evidence_times"]
    if report["census"]["state"] != "COMPLETE":
        guards.append("CENSUS_PARTIAL")
    if any(row["state"] == "OBSERVED" and row["checkout_identity"] != CHECKOUT_MATCHES
           for row in report["census"]["repositories"]):
        # A checkout whose origin is not the named repository proves nothing about it.
        guards.append("CENSUS_CHECKOUT_IDENTITY_UNVERIFIED")
    lean = report["lean"]
    if lean["binding"] == NOT_SUPPLIED:
        guards.append("LEAN_WITNESS_NOT_SUPPLIED")
    else:
        if lean["binding"] != BOUND:
            guards.append("LEAN_WITNESS_NOT_BOUND_TO_CENSUS")
        else:
            if lean["witness_state"] != "KERNEL_EXECUTED":
                guards.append("LEAN_WITNESS_NOT_KERNEL_EXECUTED")
            carrier = lean["khipu_carrier"]
            if carrier["found"] is not True or carrier["class"] != CLASS_CLEAN:
                guards.append("KHIPU_LEAN_CARRIER_NOT_KERNEL_CLEAN")
        if not _within(window, times["census"], times["lean_witness"]):
            guards.append("LEAN_WITNESS_OUTSIDE_EVIDENCE_WINDOW")
    hatun = report["hatun"]
    if hatun["binding"] == NOT_SUPPLIED:
        guards.append("HATUN_WITNESS_NOT_SUPPLIED")
    else:
        if hatun["binding"] != BOUND:
            guards.append("HATUN_WITNESS_NOT_BOUND_TO_CENSUS")
        if hatun["kernel_state"] != "EXECUTED" or hatun["mcp_state"] != "EXECUTED":
            guards.append("HATUN_LADDER_NOT_FULLY_EXECUTED")
        if hatun["state"] != "VETO_LADDER_CONFORMS":
            # A veto that did not hold is a refusal, never partial credit.
            guards.append("HATUN_LADDER_DID_NOT_CONFORM")
        if not _within(window, times["census"], times["hatun_witness"]):
            guards.append("HATUN_WITNESS_OUTSIDE_EVIDENCE_WINDOW")
    answers = report["known_answers"]
    if answers["binding"] == NOT_SUPPLIED:
        guards.append("KNOWN_ANSWERS_NOT_SUPPLIED")
    else:
        if answers["binding"] != KAT_BOUND:
            guards.append("KNOWN_ANSWERS_NOT_BOUND_TO_CENSUS")
        if answers["evaluated"] < answers["answers"]:
            # Stale or unread answers are missing evidence: they refuse, they never shrink
            # the denominator.
            guards.append("KNOWN_ANSWERS_NOT_ALL_BOUND")
    database = report["database"]
    if database["state"] == "UNAVAILABLE":
        guards.append("DATABASE_PLAN_NOT_SUPPLIED")
    elif database["plan_state"] != DATABASE_PASS:
        guards.append("DATABASE_LANE_HOLD")
    if report["ratchet"]["violations"]:
        guards.append("RATCHET_VIOLATION")
    if report["previous_turn_rejected"] is not None:
        guards.append("PREVIOUS_TURN_REJECTED")
    if report["previous_turn_lake_receipt"] == "MISMATCH":
        guards.append("PREVIOUS_LAKE_RECEIPT_DOES_NOT_BIND_PREVIOUS_TURN")
    elif report["previous_turn_lake_receipt"] == "RECEIPT_INVALID":
        guards.append("PREVIOUS_LAKE_RECEIPT_INVALID")
    return guards


def _axes(report) -> dict:
    """The eight axis ratios, from the report's own observed sections. Absent stays absent."""
    computed = {}
    total = report["khipu"]["primary_sum"]
    present = total["cords"]
    computed["source_cords_present"] = ratio(present,
                                             present + report["khipu"]["unavailable_cords"])
    lean = report["lean"]
    # Numbers from a witness in HOLD (a failed gate, a shadowed search path) are not scored.
    if lean["binding"] == BOUND and lean["witness_state"] == "KERNEL_EXECUTED":
        judged = lean["files_kernel_accepted"] + lean["files_rejected"]
        if judged:
            computed["lean_files_kernel_accepted"] = ratio(lean["files_kernel_accepted"], judged)
        if total["user_theorems"]:
            computed["theorems_trust_base_only"] = ratio(total["theorems_trust_base_only"],
                                                         total["user_theorems"])
        expected = lean["locked_guard_expected"]
        if lean["locked_guard_allowed"] is not None and expected:
            computed["locked_set_guard"] = (
                Fraction(0) if lean["locked_guard_refused"] else
                ratio(min(lean["locked_guard_allowed"], expected), expected))
    answers = report["known_answers"]
    if answers["binding"] != NOT_SUPPLIED and answers["evaluated"]:
        computed["codex_known_answers"] = ratio(answers["passed"], answers["evaluated"])
    hatun = report["hatun"]
    if hatun["binding"] != NOT_SUPPLIED and hatun["probes_expected"]:
        computed["hatun_veto_ladder"] = ratio(hatun["probes_matched"], hatun["probes_expected"])
    database = report["database"]
    if database["state"] != "UNAVAILABLE":
        for name, key in (("database_catalog_coverage", "catalog_coverage"),
                          ("database_frontier_coverage", "frontier_coverage")):
            numerator, denominator = database[key]
            if denominator:
                computed[name] = ratio(min(numerator, denominator), denominator)
    return computed


def _decision(report, *, tau, weights, window) -> dict:
    guards = _guards(report, window)
    computed = _axes(report)
    labels = {name: report[_AXIS_SOURCE[name]]["label"] for name in sorted(computed)}
    if not guards and set(computed) != set(AXES):
        guards.append("AXIS_EVIDENCE_INCOMPLETE")
    common = {"axis_labels": labels, "tau": tau, "evidence_window_seconds": window}
    if guards:
        return {"refusal_path": "PRE_AGGREGATION", "sub_reasons": guards,
                "axes_computed": {k: rational_text(v) for k, v in sorted(computed.items())},
                "axes_missing": sorted(set(AXES) - set(computed)), "exact": None, **common}
    require(weights is not None, "BRAID_DECISION_DRIFT")
    exact = decide(computed, weights, Fraction(tau))
    return {"refusal_path": exact["refusal_path"], "sub_reasons": [],
            "axes_computed": dict(exact["axes"]), "axes_missing": [], "exact": exact, **common}


def _state_digest(report) -> str:
    return digest({
        "policy": report["inputs"]["policy"],
        "census": [[r["repository"], r["state"], r["commit"], r["tree_id"],
                    r["checkout_identity"]] for r in report["census"]["repositories"]],
        "khipu": report["khipu"]["primary_hash"], "lean": report["lean"],
        "hatun": report["hatun"], "known_answers": report["known_answers"],
        "database": report["database"], "v_one": report["v_one_braid"],
        "produced": report["evidence_produced_in_invocation"],
        # The comparison with earlier turns, and when evidence was taken, are relations
        # between turns, not state: leaving them out lets unchanged evidence reproduce the
        # same digest (a fixed point).
        "ratchet": {k: v for k, v in report["ratchet"].items() if k != "against_previous_turn"},
        "decision": report["decision"]})


def _append_step(steps, phase, state, detail, evidence):
    record = {"ordinal": len(steps) + 1, "phase": phase, "state": state,
              "prev_sha256": steps[-1]["sha256"] if steps else GENESIS,
              "detail": detail, "evidence": evidence}
    record["sha256"] = sha256_hex(canonical(record))
    steps.append(record)


def _trace(report) -> list:
    steps, inputs = [], report["inputs"]
    lake, previous = report["previous_turn_lake_receipt"], report["previous_turn_id"]
    rejected = report["previous_turn_rejected"]
    tail = ("REJECTED_NEW_CHAIN" if rejected is not None else
            "GENESIS" if previous is None else "CONSUMED")
    _append_step(steps, PHASES[0],
                 "HOLD" if rejected is not None or lake in ("MISMATCH", "RECEIPT_INVALID") else
                 "OBSERVED",
                 ["POLICY_VALIDATED", "TAIL_" + tail],
                 {"policy_sha256": inputs["policy"], "previous_turn_id": previous,
                  "previous_turn_lake_receipt": lake, "previous_turn_rejected": rejected})
    census = report["census"]
    _append_step(steps, PHASES[1], "OBSERVED" if census["state"] == "COMPLETE" else "HOLD",
                 ["GIT_OBJECT_BYTES_CHECKED", "MISSING_IS_UNAVAILABLE_NOT_ZERO"],
                 {"census_sha256": inputs["census"], "cords": census["cords"],
                  "unavailable_cords": census["unavailable_cords"]})
    khipu = report["khipu"]
    _append_step(steps, PHASES[2], "OBSERVED", ["SUM_OF_SUMS_CONSERVED", "PARTITIONS_CONSERVED"],
                 {"primary_hash": khipu["primary_hash"], "pendants": khipu["pendant_count"]})
    lean, hatun = report["lean"], report["hatun"]
    lean_bound = lean["binding"] == BOUND
    proof_ok = (lean_bound and lean["witness_state"] == "KERNEL_EXECUTED" and
                hatun["binding"] == BOUND and hatun["state"] == "VETO_LADDER_CONFORMS")
    _append_step(steps, PHASES[3], "OBSERVED" if proof_ok else "HOLD",
                 ["LEAN_WITNESS_" + (lean["witness_state"] + "_AND_BOUND" if lean_bound
                                     else "NOT_BOUND"),
                  "HATUN_LADDER_" + (hatun["state"] if hatun["binding"] == BOUND
                                     else "NOT_BOUND"),
                  "EFFECT_AUTHORITY_NOT_ATTACHED"],
                 {"lean_witness_sha256": inputs["lean_witness"],
                  "hatun_witness_sha256": inputs["hatun_witness"]})
    met = report["decision"]["refusal_path"] == PATH_NONE
    _append_step(steps, PHASES[4], "OBSERVED" if met else "HOLD",
                 ["DECISION_" + report["decision"]["refusal_path"], "STOP_NO_EXTERNAL_EFFECTS",
                  "LAKE_RECEIPT_WRAPS_THIS_TURN_AFTERWARDS"],
                 {"state_digest": report["state_digest"], "turn_id": report["turn_id"]})
    return steps


def _derive(report, *, tau, weights, window) -> dict:
    """Every derived section of a turn, computed from its observed sections alone."""
    decision = _decision(report, tau=tau, weights=weights, window=window)
    met = decision["refusal_path"] == PATH_NONE
    derived = {"decision": decision, "state": STATE_MET if met else STATE_HOLD,
               "termination": ("CLOSED_EVIDENCE_COMPLETE_NO_AUTHORITY" if met
                               else "CLOSED_WITH_HOLD")}
    staged = {**report, **derived}
    derived["state_digest"] = _state_digest(staged)
    derived["turn_id"] = "braid-turn:" + digest(
        {"state": derived["state_digest"], "previous": report["previous_turn_id"],
         "ordinal": report["ordinal"]})[:32]
    staged.update(derived)
    derived["loop_trace"] = _trace(staged)
    return derived


def _previous_lake_state(policy, previous, wrap, previous_sha256) -> str:
    if wrap is None:
        return "NOT_SUPPLIED"
    # The previous wrap was made under the pins of its own time; check it against those,
    # then say whether they are still the pins of this policy. A wrap that does not validate
    # (another schema, a digest that does not re-hash) is a named HOLD, not a crash.
    try:
        validate_wrap(wrap, policy["lake"], require_current_pins=False)
    except InputError:
        return "RECEIPT_INVALID"
    lake = policy["lake"]
    bound = (wrap["subject"] == previous["turn_id"] and
             wrap["input_digest"] == previous["inputs_digest"] and
             wrap["stored_object_digest"] == previous_sha256 and
             wrap["state"] == "CANONICAL_RECEIPT_EMITTED_UNSIGNED" and
             _commit_binding(previous["census"]["repositories"], wrap["repository"],
                             wrap["commit"]) == BOUND)
    if not bound:
        return "MISMATCH"
    same = (wrap["repository"] == lake["repository"] and
            wrap["adapter_path"] == lake["adapter_path"] and
            wrap["policy_id"] == lake["policy_id"] and wrap["organ"] == lake["organ"] and
            wrap["receipt_library"]["distribution"] == lake["receipt_library"]["distribution"]
            and wrap["receipt_library"]["version_required"] == lake["receipt_library"]["version"])
    return LAKE_STATES[1] if same else LAKE_STATES[2]


def _label(present, produced_name, produced) -> str:
    if not present:
        return "UNAVAILABLE"
    return "MEASURED" if produced_name in produced else "REPORTED"


def turn(policy, census, *, lean_witness=None, hatun_witness=None, kat_report=None,
         db_plan=None, action_policy=None, source_policy=None, v_one_report=None,
         v_one_policy=None, previous_turn=None, previous_tree=None, previous_lake_wrap=None,
         previous_turn_sha256=None, input_digests=None, produced=(), family_map=None,
         family_map_sha256=None) -> tuple:
    """Braid one turn. Returns ``(report, khipu_tree)``. Pure: executes nothing.

    ``produced`` names the evidence the caller itself produced in this same
    invocation (labelled MEASURED); everything else supplied is REPORTED. When the
    census was taken with a family map, that map (its validated ``families`` and the
    digest of its file) must be supplied, so every cord's family is re-derived.
    """
    validate_policy(policy)
    require(type(census) is dict and census.get("family_map_sha256") == family_map_sha256 and
            (family_map is None) == (family_map_sha256 is None), "BRAID_FAMILY_MAP_REQUIRED")
    cords = validate_census(census, policy["census"], family_map=family_map)
    digests = dict(input_digests or {})
    require(all(v is None or (type(v) is str and SHA64.fullmatch(v)) for v in digests.values())
            and set(digests) <= {"policy", "census", "lean_witness", "hatun_witness",
                                 "known_answers", "database_plan", "v_one_report",
                                 "previous_turn", "previous_khipu_tree",
                                 "previous_lake_wrap"}, "BRAID_INPUT_DIGEST_INVALID")
    produced = sorted(produced)
    supplied = {"census": True, "lean_witness": lean_witness is not None,
                "hatun_witness": hatun_witness is not None, "known_answers": kat_report is not None}
    require(len(set(produced)) == len(produced) and
            all(name in PRODUCIBLE and supplied[name] for name in produced),
            "BRAID_PRODUCED_EVIDENCE_INVALID")
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
    ordinal, previous_id, lake_state, rejected = 1, None, "NOT_SUPPLIED", None
    if previous_turn is not None:
        require(type(previous_turn_sha256) is str and SHA64.fullmatch(previous_turn_sha256),
                "BRAID_PREVIOUS_DIGEST_REQUIRED")
        try:
            verify_turn(previous_turn, policy_for_shape=None, tree=previous_tree)
        except InputError as exc:
            # A previous turn that does not verify (edited, or written by an older shape of
            # this tool) is never consumed. The rejection is recorded, the aggregate is
            # refused, and a new chain starts here instead of the loop failing every run.
            rejected = {"sha256": previous_turn_sha256, "code": exc.code}
        except (KeyError, TypeError, ValueError, AttributeError, IndexError):
            rejected = {"sha256": previous_turn_sha256, "code": "BRAID_PREVIOUS_TURN_MALFORMED"}
        if rejected is None:
            ordinal, previous_id = previous_turn["ordinal"] + 1, previous_turn["turn_id"]
            lake_state = _previous_lake_state(policy, previous_turn, previous_lake_wrap,
                                              previous_turn_sha256)
    else:
        require(previous_lake_wrap is None and previous_turn_sha256 is None,
                "BRAID_PREVIOUS_PAIR_INCOMPLETE")
    consumed = previous_turn if rejected is None else None
    consumed_tree = previous_tree if rejected is None else None

    binding, files = _lean_binding(policy, census, lean_witness)
    tree = braid_tree(policy, census, lean_witness, files)
    total = dict(zip(KNOTS, tree["primary"]["sum"]))
    bound = binding == BOUND
    carrier = None
    if bound:
        carrier = next(c for c in lean_witness["carrier_theorems"]
                       if c["decl"] == policy["khipu"]["lean_carrier"])

    def lean_field(name):
        return lean_witness.get(name) if lean_witness is not None else None

    guard = lean_witness["locked_guard"] if bound else None
    lean_summary = {
        "binding": binding,
        "label": _label(bound, "lean_witness", produced),
        "witness_state": lean_field("state"),
        "commit": lean_field("commit"),
        "toolchain_pin": policy["lean"]["toolchain_pin"],
        "build_tree": lean_field("build_tree"),
        "network_namespace": lean_field("network_namespace"),
        "project_modules_built_by_this_run": lean_field("project_modules_built_by_this_run"),
        "project_modules_replayed": lean_field("project_modules_replayed"),
        "hold_reasons": lean_field("hold_reasons"),
        "dependency_cache_state": (lean_witness["dependency_cache"]["state"]
                                   if bound and lean_witness.get("dependency_cache") else None),
        "mathlib_revision": lean_field("mathlib_revision"),
        "dependency_oleans_rechecked_by_kernel": False,
        "files_kernel_accepted": sum(total[k] for k in _ACCEPTED_KNOTS) if bound else None,
        "files_rejected": total["lean_rejected"] if bound else None,
        "files_not_checked_by_policy": total["lean_not_checked_by_policy"] if bound else None,
        "files_theorem_counts_unknown": total["lean_theorem_counts_unknown"] if bound else None,
        "theorem_counts_scope": "KERNEL_ACCEPTED_MODULES_ONLY",
        "file_totals": lean_witness["file_totals"] if bound else None,
        "theorem_totals": lean_witness["theorem_totals"] if bound else None,
        "locked_guard_allowed": guard["allowed"] if guard else None,
        "locked_guard_refused": guard["refused"] if guard else None,
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
    hatun_binding = NOT_SUPPLIED
    if hatun_witness is not None:
        validate_hatun_witness(hatun_witness, policy["hatun"])
        hatun_binding = _commit_binding(census["repositories"], policy["hatun"]["repository"],
                                        hatun_witness["commit"])

    def hatun_field(*path):
        value = hatun_witness
        for step in path:
            if value is None:
                return None
            value = value.get(step)
        return value

    hatun_summary = {
        "binding": hatun_binding,
        "label": _label(hatun_witness is not None and hatun_binding == BOUND, "hatun_witness",
                        produced),
        "state": hatun_field("state"),
        "commit": hatun_field("commit"),
        "source_modules_digest": hatun_field("source_modules_digest"),
        "source_tree": hatun_field("source_tree"),
        "network_namespace": hatun_field("network_namespace"),
        "direct_network_egress_blocked": hatun_field("direct_network_egress_blocked"),
        "kernel_state": hatun_field("kernel", "state"),
        "mcp_state": hatun_field("mcp", "state"),
        "probes_matched": hatun_field("probes_matched"),
        "probes_expected": hatun_field("probes_expected"),
        "caller_context": hatun_field("caller_context"),
        "api_key_authentication_path_exercised": hatun_field(
            "api_key_authentication_path_exercised"),
        "effect_authority": "NOT_ATTACHED",
    }
    kat_binding = NOT_SUPPLIED
    if kat_report is not None:
        validate_kat_report(kat_report)
        kat_binding = (KAT_BOUND if kat_report["census_sha256"] is not None and
                       kat_report["census_sha256"] == digests.get("census")
                       else "NOT_BOUND_TO_CENSUS")
    kat_summary = {
        "binding": kat_binding,
        "label": _label(kat_report is not None and kat_binding == KAT_BOUND, "known_answers",
                        produced),
        "review_status": kat_report["review_status"] if kat_report is not None else None,
        # The census binding is recorded as a relation (binding), not as the census file's
        # digest, which changes with every observation time and would defeat the fixed point.
        "answer_set_sha256": kat_report["answer_set_sha256"] if kat_report is not None else None,
        **{name: (kat_report[name] if kat_report is not None else None)
           for name in _KAT_COUNTS},
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

    census_summary = {
        "label": _label(True, "census", produced), "state": census["state"],
        "repositories": [{"repository": r["repository"], "state": r["state"],
                          "commit": r["commit"], "tree_id": r["tree_id"],
                          "checkout_identity": r["checkout_identity"], "cords": r["cords"],
                          "tracked_files": r["tracked_files"],
                          "out_of_scope_files": r["out_of_scope_files"]}
                         for r in census["repositories"]],
        "cords": len(cords), "unavailable_cords": len(census["unavailable_cords"]),
        "families": _family_counts(cords),
    }
    khipu_summary = {
        "label": "MEASURED", "primary_hash": tree["primary"]["hash"],
        "primary_sum": total, "pendant_count": tree["primary"]["pendant_count"],
        "cord_count": tree["primary"]["cord_count"],
        "unavailable_cords": len(tree["unavailable_cords"]),
        "conservation": "SUM_OF_SUMS_AND_PARTITIONS_VERIFIED_AT_EVERY_NODE",
        "integrity": "UNSIGNED_HASH_TREE_WITH_SUMS",
    }
    inputs = {name: digests.get(name) for name in (
        "policy", "census", "lean_witness", "hatun_witness", "known_answers", "database_plan",
        "v_one_report", "previous_turn", "previous_khipu_tree", "previous_lake_wrap")}
    report = {
        "schema": SCHEMA, "doctrine": policy["doctrine"], "max_steps": policy["max_steps"],
        "executed_steps": len(PHASES), "ordinal": ordinal, "previous_turn_id": previous_id,
        "previous_turn_sha256": previous_turn_sha256 if consumed is not None else None,
        "previous_turn_lake_receipt": lake_state, "previous_turn_rejected": rejected,
        "inputs": inputs, "inputs_digest": digest(inputs), "census": census_summary,
        "khipu": khipu_summary, "lean": lean_summary, "hatun": hatun_summary,
        "known_answers": kat_summary, "database": database, "v_one_braid": v_one,
        "evidence_times": {
            "census": census["observed_at"],
            "lean_witness": lean_witness["observed_at"] if lean_witness is not None else None,
            "hatun_witness": hatun_witness["observed_at"] if hatun_witness is not None else None,
        },
        "evidence_produced_in_invocation": produced,
        "evidence_labels": dict(EVIDENCE_LABELS),
        "fixed_claims": dict(policy["fixed_claims"]),
        "integrity_kind": "UNSIGNED_STRUCTURAL_SHA256_CHAIN", "signed": False,
    }
    report["ratchet"] = _ratchet(policy, tree, lean_summary, consumed, consumed_tree)
    report.update(_derive(report, tau=policy["decision"]["tau"],
                          weights={a["id"]: a["weight"] for a in policy["decision"]["axes"]},
                          window=policy["decision"]["evidence_window_seconds"]))
    require(len(report["loop_trace"]) == policy["max_steps"] and
            tuple(s["phase"] for s in report["loop_trace"]) == PHASES,
            "BRAID_TERMINATION_BUDGET")
    report["ouroboros_fixed_point"] = (consumed is not None and
                                       consumed["state_digest"] == report["state_digest"])
    report.update({flag: False for flag in _FALSE_FLAGS})
    report.update({name: None for name in _NULL_FIELDS})
    report = {name: report[name] for name in _FIELDS}
    verify_turn(report, policy_for_shape=policy, tree=tree, previous=consumed)
    return report, tree


_KAT_COUNTS = ("answers", "evaluated", "passed", "failed", "invalid_claims", "stale",
               "source_not_in_census", "anchor_not_at_line", "source_bytes_not_read",
               "rebound_by_line")


def _family_counts(cords) -> dict:
    counts = {}
    for cord in cords:
        counts[cord["family"]] = counts.get(cord["family"], 0) + 1
    return {name: counts[name] for name in sorted(counts)}


def _check_sections(value):
    """Shape and internal arithmetic of the observed sections, so re-derivation is total."""
    census, khipu, lean = value["census"], value["khipu"], value["lean"]
    hatun, answers, database = value["hatun"], value["known_answers"], value["database"]
    require(all(type(s) is dict for s in (census, khipu, lean, hatun, answers, database,
                                          value["ratchet"], value["evidence_times"])),
            "BRAID_TURN_SECTIONS_INVALID")
    total = khipu.get("primary_sum")
    # Key order is not part of the contract: canonical JSON sorts keys on every write.
    require(type(total) is dict and sorted(total) == sorted(KNOTS) and
            all(type(v) is int and v >= 0 for v in total.values()) and
            type(khipu.get("unavailable_cords")) is int and khipu["unavailable_cords"] >= 0 and
            census.get("cords") == total["cords"] == khipu.get("cord_count") and
            census.get("unavailable_cords") == khipu["unavailable_cords"] and
            census.get("state") in ("COMPLETE", "PARTIAL") and
            type(census.get("repositories")) is list, "BRAID_TURN_SECTIONS_INVALID")
    for part in PARTITIONS:
        require(sum(total[name] for name in part["parts"]) == total[part["whole"]],
                "BRAID_TURN_PARTITION_DRIFT")
    produced = value["evidence_produced_in_invocation"]
    require(type(produced) is list and produced == sorted(set(produced)) and
            set(produced) <= set(PRODUCIBLE), "BRAID_PRODUCED_EVIDENCE_INVALID")
    bound = lean.get("binding") == BOUND
    expected_counts = {
        "files_kernel_accepted": sum(total[k] for k in _ACCEPTED_KNOTS),
        "files_rejected": total["lean_rejected"],
        "files_not_checked_by_policy": total["lean_not_checked_by_policy"],
        "files_theorem_counts_unknown": total["lean_theorem_counts_unknown"],
    }
    require(all(lean.get(name) == (count if bound else None)
                for name, count in expected_counts.items()) and
            lean.get("label") == _label(bound, "lean_witness", produced) and
            census.get("label") == _label(True, "census", produced) and
            hatun.get("label") == _label(hatun.get("binding") == BOUND, "hatun_witness",
                                         produced) and
            answers.get("label") == _label(answers.get("binding") == KAT_BOUND,
                                           "known_answers", produced),
            "BRAID_TURN_SUMMARY_DRIFT")
    if answers.get("binding") != NOT_SUPPLIED:
        counts = [answers.get(name) for name in _KAT_COUNTS]
        require(all(type(c) is int and c >= 0 for c in counts) and
                answers["evaluated"] + answers["stale"] + answers["source_not_in_census"] +
                answers["anchor_not_at_line"] + answers["source_bytes_not_read"] ==
                answers["answers"] and
                answers["passed"] + answers["failed"] + answers["invalid_claims"] ==
                answers["evaluated"], "BRAID_TURN_SUMMARY_DRIFT")
    ratchet = value["ratchet"]
    record = ratchet.get("against_previous_turn")
    require(type(record) is dict and type(ratchet.get("violations")) is list and
            set(ratchet["violations"]) <= VIOLATIONS and
            ratchet["violations"] == sorted(set(ratchet["violations"])) and
            ratchet.get("debt") == _debt(lean, total) and
            record.get("debt_delta") == _debt_delta(ratchet["debt"], record.get("baseline_debt"))
            and type(record.get("removed_cords_count")) is int and
            set(_between_violations(record)) <= set(ratchet["violations"]),
            "BRAID_RATCHET_DRIFT")
    if value["ordinal"] == 1:
        require(record.get("state") == "GENESIS_NO_PREVIOUS_TURN" and
                record.get("baseline_debt") is None and
                value["ouroboros_fixed_point"] is False and
                value["previous_turn_lake_receipt"] == "NOT_SUPPLIED", "BRAID_TURN_CHAIN_INVALID")
    else:
        expected = ("SOURCES_ONLY_NO_BOUND_BASELINE" if record.get("debt_delta") is None else
                    "COMPARED_WITH_PREVIOUS_TURN"
                    if record.get("baseline_turn_id") == value["previous_turn_id"] else
                    "COMPARED_WITH_EARLIER_BOUND_TURN")
        require(record.get("state") == expected, "BRAID_RATCHET_DRIFT")


def verify_turn(value, *, policy_for_shape=None, tree=None, previous=None) -> bool:
    """Independently re-check a turn report.

    Re-derives the decision, state, termination, state digest, turn id and the
    five trace steps from the report's own observed sections and requires the
    same bytes. With ``policy_for_shape`` it also re-derives the ratchet floor
    and checks the policy's threshold, weights and window; with ``tree`` the
    khipu binding; with ``previous`` the chain link and the fixed point.
    """
    closed(value, _FIELDS, "BRAID_TURN_FIELDS_INVALID")
    require(value["schema"] == SCHEMA and value["doctrine"] == FIXED_DOCTRINE and
            value["max_steps"] == len(PHASES) and value["executed_steps"] == len(PHASES) and
            value["integrity_kind"] == "UNSIGNED_STRUCTURAL_SHA256_CHAIN" and
            value["signed"] is False and value["evidence_labels"] == EVIDENCE_LABELS,
            "BRAID_TURN_SCHEMA_INVALID")
    require(all(value[flag] is False for flag in _FALSE_FLAGS) and
            all(value[name] is None for name in _NULL_FIELDS) and
            value["fixed_claims"] == FIXED_CLAIMS, "BRAID_FALSE_AUTHORITY_CLAIM")
    require(type(value["ordinal"]) is int and value["ordinal"] >= 1 and
            type(value["turn_id"]) is str and TURN_ID.fullmatch(value["turn_id"]) and
            type(value["state_digest"]) is str and SHA64.fullmatch(value["state_digest"]) and
            type(value["inputs_digest"]) is str and SHA64.fullmatch(value["inputs_digest"]),
            "BRAID_TURN_IDENTITY_INVALID")
    previous_id = value["previous_turn_id"]
    require((previous_id is None) == (value["ordinal"] == 1) and
            (previous_id is None or (type(previous_id) is str and TURN_ID.fullmatch(previous_id)))
            and (previous_id is None) == (value["previous_turn_sha256"] is None),
            "BRAID_TURN_CHAIN_INVALID")
    require(type(value["inputs"]) is dict and value["inputs_digest"] == digest(value["inputs"]),
            "BRAID_TURN_INPUTS_DIGEST_MISMATCH")
    require(value["previous_turn_lake_receipt"] in LAKE_STATES and
            type(value["ouroboros_fixed_point"]) is bool, "BRAID_TURN_FIELDS_INVALID")
    rejected = value["previous_turn_rejected"]
    require(rejected is None or (
        type(rejected) is dict and set(rejected) == {"sha256", "code"} and
        type(rejected["sha256"]) is str and SHA64.fullmatch(rejected["sha256"]) is not None and
        type(rejected["code"]) is str and REASON.fullmatch(rejected["code"]) is not None and
        value["ordinal"] == 1 and value["previous_turn_lake_receipt"] == "NOT_SUPPLIED"),
        "BRAID_TURN_CHAIN_INVALID")
    require(type(value["hatun"]) is dict and
            value["hatun"].get("effect_authority") == "NOT_ATTACHED" and
            type(value["lean"]) is dict and
            value["lean"].get("independent_kernel_replay") is False and
            value["lean"].get("dependency_oleans_rechecked_by_kernel") is False,
            "BRAID_TURN_BOUNDARY_DRIFT")
    decision = value["decision"]
    require(type(decision) is dict and type(decision.get("tau")) is str and
            type(decision.get("evidence_window_seconds")) is int and
            60 <= decision["evidence_window_seconds"] <= MAX_WINDOW_SECONDS,
            "BRAID_DECISION_FIELDS_INVALID")
    weights = None
    if policy_for_shape is not None:
        validate_policy(policy_for_shape)
        weights = {a["id"]: a["weight"] for a in policy_for_shape["decision"]["axes"]}
        require(decision["tau"] == policy_for_shape["decision"]["tau"] and
                decision["evidence_window_seconds"] ==
                policy_for_shape["decision"]["evidence_window_seconds"] and
                (type(decision.get("exact")) is not dict or
                 decision["exact"].get("weights") == weights), "BRAID_DECISION_POLICY_DRIFT")
    elif type(decision.get("exact")) is dict:
        weights = decision["exact"].get("weights")
    try:
        _check_sections(value)
        derived = _derive(value, tau=decision["tau"], weights=weights,
                          window=decision["evidence_window_seconds"])
    except InputError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        # A malformed section must refuse with a code, never escape as a crash.
        raise InputError("BRAID_TURN_SECTIONS_INVALID") from None
    for name in _DERIVED:
        # Byte comparison, not ==: Python's == treats True as 1 and 0 as False.
        require(canonical(derived[name]) == canonical(value[name]), "BRAID_TURN_DERIVATION_DRIFT")
    if decision["exact"] is not None:
        verify_decision(decision["exact"])
    if value["state"] == STATE_MET:
        require(all(step["state"] == "OBSERVED" for step in value["loop_trace"]),
                "BRAID_TURN_MET_WITH_HOLD_STEP")
    khipu = value["khipu"]
    require(type(khipu.get("primary_hash")) is str and SHA64.fullmatch(khipu["primary_hash"]),
            "BRAID_KHIPU_BINDING_INVALID")
    if tree is not None:
        verify(tree)
        require(tree["knots"] == KNOTS and tree["partitions"] == PARTITIONS and
                tree["primary"]["hash"] == khipu["primary_hash"] and
                khipu["primary_sum"] == dict(zip(KNOTS, tree["primary"]["sum"])) and
                khipu["cord_count"] == tree["primary"]["cord_count"] and
                khipu["pendant_count"] == tree["primary"]["pendant_count"] and
                khipu["unavailable_cords"] == len(tree["unavailable_cords"]),
                "BRAID_KHIPU_TREE_MISMATCH")
    if policy_for_shape is not None:
        floor_state, floor_violations, tighten, outside = _floor(
            policy_for_shape["ratchet"]["floor"], value["lean"], value["ratchet"]["debt"])
        ratchet = value["ratchet"]
        require(ratchet["floor_state"] == floor_state and ratchet["can_tighten"] == tighten and
                ratchet["declared_axioms_outside_allowed_set"] == outside and
                ratchet["violations"] == sorted(set(floor_violations) | set(
                    _between_violations(ratchet["against_previous_turn"]))),
                "BRAID_RATCHET_DRIFT")
    if previous is not None:
        baseline_id, baseline = _baseline(previous)
        record = value["ratchet"]["against_previous_turn"]
        require(previous_id == previous["turn_id"] and
                value["ordinal"] == previous["ordinal"] + 1 and
                value["ouroboros_fixed_point"] ==
                (previous["state_digest"] == value["state_digest"]) and
                record["baseline_turn_id"] == baseline_id and record["baseline_debt"] == baseline,
                "BRAID_TURN_CHAIN_INVALID")
    return True


def replay_turn(report, policy, census, **evidence) -> bool:
    """Re-run a turn from its evidence and require exactly the same report bytes.

    ``evidence`` takes the same keywords as ``turn`` (witnesses, answers, plan,
    previous turn and tree, previous wrap, digests); the produced-evidence list
    is read back from the report itself.
    """
    verify_turn(report)
    again, _ = turn(policy, census, produced=report["evidence_produced_in_invocation"],
                    **evidence)
    require(canonical(again) == canonical(report), "BRAID_TURN_REPLAY_DIVERGED")
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description="One bounded, no-effect Ouroboros braid v2 turn")
    ap.add_argument("--policy", type=Path, required=True)
    ap.add_argument("--census", type=Path, required=True)
    ap.add_argument("--family-map", type=Path,
                    help="the family map the census was taken with, if any")
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
    ap.add_argument("--replay", type=Path, metavar="TURN_JSON",
                    help="re-run the turn from the same evidence and compare; writes nothing")
    ap.add_argument("--output", type=Path)
    ap.add_argument("--khipu-tree-output", type=Path)
    args = ap.parse_args(argv)
    try:
        policy, policy_sha = read_json(args.policy, max_bytes=MAX_POLICY_BYTES)
        validate_policy(policy)
        census, census_sha = read_json(args.census, max_bytes=MAX_CENSUS_BYTES)
        digests = {"policy": policy_sha, "census": census_sha}
        families = family_sha = None
        if args.family_map is not None:
            raw_map, family_sha = read_json(args.family_map, max_bytes=MAX_MAP_BYTES)
            families = validate_family_map(raw_map)

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
        evidence = dict(
            lean_witness=lean, hatun_witness=hatun, kat_report=answers, db_plan=plan,
            action_policy=action_policy, source_policy=source_policy, v_one_report=v_one,
            v_one_policy=v_one_policy, previous_turn=previous, previous_tree=previous_tree,
            previous_lake_wrap=previous_wrap, previous_turn_sha256=digests.get("previous_turn"),
            input_digests=digests, family_map=families, family_map_sha256=family_sha)
        if args.replay is not None:
            recorded, _ = read_json(args.replay, max_bytes=MAX_TURN_BYTES)
            replay_turn(recorded, policy, census, **evidence)
            print(json.dumps({"state": "REPLAY_MATCHED", "turn_id": recorded["turn_id"],
                              "signed": False, "production_authorized": False,
                              "external_effects_performed": False}))
            return 2
        require(args.output is not None and args.khipu_tree_output is not None and
                args.output.resolve() != args.khipu_tree_output.resolve(),
                "OUTPUT_PATH_DENIED")
        # This command only reads files, so nothing it braids is MEASURED by it.
        report, tree = turn(policy, census, **evidence)
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
