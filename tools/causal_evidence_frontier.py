#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline first-blocker analysis over fixed, untrusted SZL evidence claims.

The input is a redacted observation, not authenticated evidence. This module
opens no network or provider connection, executes no expression, and grants no
production, inference, signature, custody, payment, or settlement authority.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re
import sys

SCHEMA = "szl.causal-evidence-observation/v1"
RESULT_SCHEMA = "szl.causal-evidence-frontier/v1"
CLASSIFICATION = "ADVISORY_ONLY_NOT_RELEASE_PROOF"
STATES = frozenset({"VERIFIED_CLAIM", "HOLD", "UNAVAILABLE", "INVALID"})
READBACKS = frozenset({"SOURCE_CLAIM", "PROVIDER_AUTHENTICATED_CLAIM"})
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
UTC_STAMP = re.compile(
    r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z"
)
MAX_INPUT = 65536
FUTURE_SKEW_SECONDS = 300
SOURCE_REPOSITORY = "szl-holdings/szl-org-health"

TOPOLOGY = {
    "SOURCE": (),
    "BUILD": ("SOURCE",),
    "HF_PUBLICATION": ("BUILD",),
    "HF_IDENTITY": ("HF_PUBLICATION", "SOURCE"),
    "RUNTIME": ("BUILD",),
    "MODEL": ("HF_PUBLICATION", "RUNTIME"),
    "AUTH": ("RUNTIME",),
    "INFERENCE": ("AUTH", "HF_IDENTITY", "MODEL", "RUNTIME"),
    # Public HTTP serving is not the same plane as a real model completion.
    "SERVING": ("RUNTIME",),
    "SIGNER": ("BUILD",),
    "CUSTODY": ("INFERENCE", "SIGNER"),
    "PAYMENT": ("CUSTODY",),
    "SETTLEMENT": ("CUSTODY", "PAYMENT"),
}
GATE_PLANES = {
    "SOURCE": "source",
    "BUILD": "build",
    "HF_PUBLICATION": "hf",
    "HF_IDENTITY": "handoff",
    "RUNTIME": "runtime",
    "MODEL": "model",
    "AUTH": "auth",
    "INFERENCE": "inference",
    "SERVING": "serving",
    "SIGNER": "signer",
    "CUSTODY": "custody",
    "PAYMENT": "payment",
    "SETTLEMENT": "settlement",
}
IDENTITY_GATES = frozenset({"SOURCE", "HF_IDENTITY", "SIGNER", "CUSTODY"})
TARGETS = {
    "served": ("SERVING", "SERVING_CLAIM_ONLY_NOT_SERVICE_PROOF"),
    "model_inference": ("INFERENCE", "INFERENCE_CLAIM_ONLY_NO_MODEL_EXECUTED"),
    "receipt_proof": ("CUSTODY", "CUSTODY_CLAIM_ONLY_NO_INDEPENDENT_RECEIPT_PROOF"),
    "money_settled": ("SETTLEMENT", "SETTLEMENT_CLAIM_ONLY_NO_MONEY_MOVED_OR_VERIFIED"),
}
GATE_FIELDS = frozenset({
    "id", "plane", "state", "observed_at", "source_sha40", "content_sha256",
    "identity_matches", "readback", "coverage_numerator", "coverage_denominator",
})


class FrontierInputError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _require(condition, code):
    if not condition:
        raise FrontierInputError(code)


def _fields(value, expected, code):
    _require(type(value) is dict and set(value) == set(expected), code)
    return value


def _pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise FrontierInputError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _bad_constant(_value):
    raise FrontierInputError("NONFINITE_JSON_VALUE")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise FrontierInputError("NONFINITE_JSON_VALUE")
    return number


def strict_json(raw: bytes):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_INPUT, "INPUT_SIZE_INVALID")
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                          parse_constant=_bad_constant, parse_float=_finite_float)
    except FrontierInputError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise FrontierInputError("INVALID_JSON") from None


def _timestamp(value):
    _require(type(value) is str and UTC_STAMP.fullmatch(value) is not None,
             "TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise FrontierInputError("TIMESTAMP_INVALID") from None
    return parsed.astimezone(timezone.utc)


def _digest(value, pattern, code, *, nullable=False):
    if nullable and value is None:
        return
    _require(type(value) is str and pattern.fullmatch(value) is not None, code)


def _freshness_reasons(observed, evaluated, max_age_seconds):
    age = (evaluated - observed).total_seconds()
    if age > max_age_seconds:
        return ["OBSERVATION_STALE"]
    if age < -FUTURE_SKEW_SECONDS:
        return ["OBSERVATION_IN_FUTURE"]
    return []


def validate_topology(topology):
    """Validate the fixed node set and acyclicity; analysis never accepts a graph."""
    _require(type(topology) is dict and set(topology) == set(TOPOLOGY),
             "TOPOLOGY_GATES_INVALID")
    for gate, parents in topology.items():
        _require(type(parents) in (list, tuple)
                 and all(type(parent) is str for parent in parents), "TOPOLOGY_PARENTS_INVALID")
        _require(len(parents) == len(set(parents)), "TOPOLOGY_PARENTS_INVALID")
        _require(all(parent in topology for parent in parents), "TOPOLOGY_PARENT_UNKNOWN")
    state = {}

    def visit(gate):
        _require(state.get(gate) != 1, "TOPOLOGY_CYCLE")
        if state.get(gate) == 2:
            return
        state[gate] = 1
        for parent in sorted(topology[gate]):
            visit(parent)
        state[gate] = 2

    for gate in sorted(topology):
        visit(gate)
    return True


def _validate_observation(value):
    _fields(value, ("schema", "observed_at", "evaluated_at", "max_age_seconds",
                    "source", "gates", "credentials_recorded"),
            "OBSERVATION_FIELDS_INVALID")
    _require(value["schema"] == SCHEMA, "OBSERVATION_SCHEMA_INVALID")
    _require(value["credentials_recorded"] is False, "CREDENTIAL_CONTENT_REFUSED")
    _require(type(value["max_age_seconds"]) is int
             and 60 <= value["max_age_seconds"] <= 86400, "AGE_POLICY_INVALID")
    observed = _timestamp(value["observed_at"])
    evaluated = _timestamp(value["evaluated_at"])
    source = _fields(value["source"], ("repository", "commit_sha40", "tree_sha256"),
                     "SOURCE_FIELDS_INVALID")
    _require(source["repository"] == SOURCE_REPOSITORY, "SOURCE_REPOSITORY_INVALID")
    _digest(source["commit_sha40"], SHA40, "SOURCE_DIGEST_INVALID")
    _digest(source["tree_sha256"], SHA256, "SOURCE_DIGEST_INVALID")
    gates = value["gates"]
    _require(type(gates) is list and len(gates) == len(TOPOLOGY), "GATE_SET_INVALID")
    by_id = {}
    for gate in gates:
        _fields(gate, GATE_FIELDS, "GATE_FIELDS_INVALID")
        gate_id = gate["id"]
        _require(type(gate_id) is str and gate_id in TOPOLOGY, "GATE_ID_INVALID")
        _require(gate_id not in by_id, "DUPLICATE_GATE_ID")
        _require(gate["plane"] == GATE_PLANES[gate_id], "GATE_PLANE_INVALID")
        _require(type(gate["state"]) is str and gate["state"] in STATES,
                 "GATE_STATE_INVALID")
        _require(type(gate["readback"]) is str and gate["readback"] in READBACKS,
                 "READBACK_INVALID")
        _timestamp(gate["observed_at"])
        _digest(gate["source_sha40"], SHA40, "GATE_SOURCE_DIGEST_INVALID", nullable=True)
        _digest(gate["content_sha256"], SHA256, "GATE_CONTENT_DIGEST_INVALID", nullable=True)
        _require(gate["identity_matches"] is None or type(gate["identity_matches"]) is bool,
                 "IDENTITY_FLAG_INVALID")
        numerator, denominator = gate["coverage_numerator"], gate["coverage_denominator"]
        _require((numerator is None) == (denominator is None), "COVERAGE_INVALID")
        if denominator is not None:
            _require(type(numerator) is int and type(denominator) is int
                     and 0 < denominator <= 1000000 and 0 <= numerator <= denominator,
                     "COVERAGE_INVALID")
        by_id[gate_id] = gate
    _require(set(by_id) == set(TOPOLOGY), "GATE_SET_INVALID")
    return by_id, source, observed, evaluated


def _local_reasons(gate, source):
    reasons = []
    reasons.extend(_freshness_reasons(
        _timestamp(gate["observed_at"]), _timestamp(gate["_evaluated_at"]),
        gate["_max_age_seconds"]))
    if gate["state"] != "VERIFIED_CLAIM":
        reasons.append("REPORTED_" + gate["state"])
    if gate["source_sha40"] is None:
        reasons.append("SOURCE_BINDING_UNAVAILABLE")
    elif gate["source_sha40"] != source["commit_sha40"]:
        reasons.append("SOURCE_MISMATCH")
    if gate["identity_matches"] is False:
        reasons.append("IDENTITY_MISMATCH")
    elif gate["id"] in IDENTITY_GATES and gate["identity_matches"] is not True:
        reasons.append("IDENTITY_UNAVAILABLE")
    if (gate["coverage_denominator"] is not None
            and gate["coverage_numerator"] < gate["coverage_denominator"]):
        reasons.append("COVERAGE_INCOMPLETE")
    return sorted(set(reasons))


def analyze(observation):
    """Return deterministic minimal failed ancestors for four fixed target scopes."""
    validate_topology(TOPOLOGY)
    gates, source, observed, evaluated = _validate_observation(observation)
    max_age = observation["max_age_seconds"]
    global_reasons = _freshness_reasons(observed, evaluated, max_age)
    if global_reasons:
        raise FrontierInputError(global_reasons[0])
    local = {}
    for gate_id, original in gates.items():
        gate = dict(original, _evaluated_at=observation["evaluated_at"],
                    _max_age_seconds=max_age)
        local[gate_id] = _local_reasons(gate, source)

    first = {}

    def blockers(gate_id):
        if gate_id in first:
            return first[gate_id]
        # A downstream refusal cannot obscure an earlier broken prerequisite.
        # Preserve the downstream failure in gate_assessments.local_reasons,
        # but report the earliest causal cuts as the explanation of the target.
        upstream = set()
        for parent in sorted(TOPOLOGY[gate_id]):
            upstream.update(blockers(parent))
        if upstream:
            first[gate_id] = tuple(sorted(upstream))
        elif local[gate_id]:
            first[gate_id] = (gate_id,)
        else:
            first[gate_id] = ()
        return first[gate_id]

    for gate_id in sorted(TOPOLOGY):
        blockers(gate_id)
    assessments = []
    for gate_id in sorted(TOPOLOGY):
        gate = gates[gate_id]
        if local[gate_id]:
            effective = gate["state"] if gate["state"] != "VERIFIED_CLAIM" else "HOLD"
        elif first[gate_id]:
            effective = "BLOCKED_BY_ANCESTOR"
        else:
            effective = "VERIFIED_CLAIM"
        assessments.append({
            "gate_id": gate_id,
            "plane": gate["plane"],
            "reported_state": gate["state"],
            "effective_state": effective,
            "readback": gate["readback"],
            "local_reasons": local[gate_id],
            "first_blockers": list(first[gate_id]),
        })
    assessment_by_id = {row["gate_id"]: row for row in assessments}
    targets = []
    for name in sorted(TARGETS):
        gate_id, scope = TARGETS[name]
        rows = []
        for blocker in first[gate_id]:
            row = assessment_by_id[blocker]
            rows.append({"gate_id": blocker, "reported_state": row["reported_state"],
                         "readback": row["readback"], "reasons": row["local_reasons"]})
        targets.append({
            "target": name,
            "target_gate": gate_id,
            "scope": scope,
            "state": "BLOCKED" if rows else "ALL_PREREQUISITES_CLAIMED_VERIFIED",
            "first_blockers": list(first[gate_id]),
            "blocker_details": rows,
        })
    return {
        "schema": RESULT_SCHEMA,
        "classification": CLASSIFICATION,
        "state": "HOLD" if any(row["first_blockers"] for row in targets) else "CLAIMS_COMPLETE_NO_AUTHORITY",
        "source_claim": dict(source),
        "topology": {gate: list(TOPOLOGY[gate]) for gate in sorted(TOPOLOGY)},
        "targets": targets,
        "gate_assessments": assessments,
        "production_authorized": False,
        "effects_authorized": False,
        "independent_signature_verified": False,
        "provider_readback_independently_verified": False,
        "network_access_performed": False,
        "external_effects_performed": False,
    }


def _refusal(code):
    return {
        "schema": RESULT_SCHEMA,
        "state": "UNAVAILABLE",
        "classification": CLASSIFICATION,
        "error_code": code,
        "production_authorized": False,
        "effects_authorized": False,
        "independent_signature_verified": False,
        "provider_readback_independently_verified": False,
        "network_access_performed": False,
        "external_effects_performed": False,
    }


def _read(path):
    try:
        _require(not path.is_symlink() and path.is_file(), "FILE_UNAVAILABLE")
        _require(0 < path.stat().st_size <= MAX_INPUT, "INPUT_SIZE_INVALID")
        return path.read_bytes()
    except OSError:
        raise FrontierInputError("FILE_UNAVAILABLE") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline, non-authorizing causal first-blocker diagnostic")
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = analyze(strict_json(_read(args.input)))
        code = 2 if result["state"] == "HOLD" else 0
    except FrontierInputError as exc:
        result, code = _refusal(exc.code), 3
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return code


if __name__ == "__main__":
    sys.exit(main())
