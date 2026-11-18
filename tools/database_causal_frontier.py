#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed causal read-frontier comparison; NO database or network access.

An instrumented stage reports a [since, upper) logical interval; only a single
shared timeline with all required stages reporting can be compared. This is an
offline structural gate, NOT proof of serializability, transaction durability,
replication, execution authorization or independently trusted source identity.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

POLICY_SCHEMA = "szl.database-causal-frontier-policy/v1"
SNAPSHOT_SCHEMA = "szl.database-causal-frontier-readback/v1"
RESULT_SCHEMA = "szl.database-causal-frontier-admission/v1"
CATALOG_SCHEMA = "szl.database-catalog-admission/v1"
SHA1 = re.compile(r"[a-f0-9]{40}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
LABEL = re.compile(r"[a-z][a-z0-9_]{0,79}\Z")
TIMELINE = re.compile(r"szl\.[a-z][a-z0-9_.-]{2,80}\Z")
MAX_INPUT = 262144


class FrontierInputError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _pairs(values):
    data = {}
    for key, value in values:
        if key in data:
            raise FrontierInputError("DUPLICATE_JSON_KEY")
        data[key] = value
    return data


def _bad_constant(_):
    raise FrontierInputError("NONFINITE_JSON_VALUE")


def strict_json(raw: bytes, limit: int = MAX_INPUT):
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise FrontierInputError("INPUT_SIZE_INVALID")
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                          parse_constant=_bad_constant)
    except FrontierInputError:
        raise
    except (ValueError, UnicodeError):
        raise FrontierInputError("INVALID_JSON") from None


def _fields(value, required):
    if type(value) is not dict or set(value) != set(required):
        raise FrontierInputError("FIELDS_INVALID")


def _int(value):
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise FrontierInputError("VERSION_INVALID")
    return value


def _stamp(value):
    if type(value) is not str or not 10 <= len(value) <= 48:
        raise FrontierInputError("TIMESTAMP_INVALID")
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise FrontierInputError("TIMESTAMP_INVALID") from None
    if t.tzinfo is None or t.utcoffset() is None:
        raise FrontierInputError("TIMESTAMP_INVALID")
    return t.astimezone(timezone.utc)


def _subject(value):
    _fields(value, ("repository", "path", "git_blob_sha1"))
    repo, path, digest = value["repository"], value["path"], value["git_blob_sha1"]
    if (type(repo) is not str or not re.fullmatch(r"szl-holdings/[A-Za-z0-9_.-]{1,100}", repo)
            or type(path) is not str or not 1 <= len(path) <= 220
            or path.startswith("/") or "\\" in path or ".." in path.split("/")
            or type(digest) is not str or SHA1.fullmatch(digest) is None):
        raise FrontierInputError("SOURCE_SUBJECT_INVALID")
    return value


def policy_data(value):
    _fields(value, ("schema", "contract_id", "timeline", "source_binding",
                    "required_stages", "max_age_seconds",
                    "max_version_skew", "required_catalog_state"))
    if value["schema"] != POLICY_SCHEMA:
        raise FrontierInputError("POLICY_SCHEMA_INVALID")
    if type(value["contract_id"]) is not str or LABEL.fullmatch(value["contract_id"]) is None:
        raise FrontierInputError("POLICY_ID_INVALID")
    if type(value["timeline"]) is not str or TIMELINE.fullmatch(value["timeline"]) is None:
        raise FrontierInputError("TIMELINE_INVALID")
    _subject(value["source_binding"])
    stages = value["required_stages"]
    if (type(stages) is not list or not 1 <= len(stages) <= 32
            or any(type(x) is not str or LABEL.fullmatch(x) is None for x in stages)
            or len(stages) != len(set(stages))):
        raise FrontierInputError("STAGE_POLICY_INVALID")
    if (type(value["max_age_seconds"]) is not int
            or not 60 <= value["max_age_seconds"] <= 86400):
        raise FrontierInputError("AGE_POLICY_INVALID")
    if (type(value["max_version_skew"]) is not int
            or not 0 <= value["max_version_skew"] <= 10000000):
        raise FrontierInputError("SKEW_POLICY_INVALID")
    if value["required_catalog_state"] != "CATALOG_MATCH_ONLY":
        raise FrontierInputError("CATALOG_POLICY_INVALID")
    return value


def _catalog(value):
    _fields(value, ("schema", "state", "production_authorized",
                    "source_identity_independently_verified", "catalog_sha256"))
    if value["schema"] != CATALOG_SCHEMA or value["state"] not in (
            "CATALOG_MATCH_ONLY", "HOLD", "UNAVAILABLE"):
        raise FrontierInputError("CATALOG_RESULT_INVALID")
    if value["production_authorized"] is not False or value["source_identity_independently_verified"] is not False:
        raise FrontierInputError("CATALOG_AUTHORITY_CLAIM_REFUSED")
    digest = value["catalog_sha256"]
    if digest is not None and (type(digest) is not str or SHA256.fullmatch(digest) is None):
        raise FrontierInputError("CATALOG_DIGEST_INVALID")
    return value


def snapshot_data(value):
    _fields(value, ("schema", "state", "observed_at", "source_binding",
                    "timeline", "requested_version", "catalog_admission",
                    "stages", "credentials_recorded"))
    if value["schema"] != SNAPSHOT_SCHEMA or value["state"] not in (
            "OBSERVED", "INCOMPLETE"):
        raise FrontierInputError("SNAPSHOT_STATE_INVALID")
    if value["credentials_recorded"] is not False:
        raise FrontierInputError("CREDENTIAL_CONTENT_REFUSED")
    if type(value["timeline"]) is not str or TIMELINE.fullmatch(value["timeline"]) is None:
        raise FrontierInputError("TIMELINE_INVALID")
    _stamp(value["observed_at"])
    _int(value["requested_version"])
    _subject(value["source_binding"])
    _catalog(value["catalog_admission"])
    stages = value["stages"]
    if type(stages) is not list or len(stages) > 64:
        raise FrontierInputError("STAGES_INVALID")
    seen = set()
    for stage in stages:
        _fields(stage, ("name", "state", "timeline", "since_version",
                        "upper_version", "observed_at", "declared_digest_sha256"))
        name = stage["name"]
        if type(name) is not str or LABEL.fullmatch(name) is None:
            raise FrontierInputError("STAGE_NAME_INVALID")
        if name in seen:
            raise FrontierInputError("DUPLICATE_STAGE")
        seen.add(name)
        if type(stage["timeline"]) is not str or TIMELINE.fullmatch(stage["timeline"]) is None:
            raise FrontierInputError("TIMELINE_INVALID")
        if stage["state"] == "OBSERVED":
            _int(stage["since_version"])
            _int(stage["upper_version"])
            if stage["upper_version"] < stage["since_version"]:
                raise FrontierInputError("FRONTIER_ORDER_INVALID")
            _stamp(stage["observed_at"])
            dg = stage["declared_digest_sha256"]
            if type(dg) is not str or SHA256.fullmatch(dg) is None:
                raise FrontierInputError("DIGEST_INVALID")
        elif stage["state"] in ("UNAVAILABLE", "DENIED"):
            if any(stage[key] is not None for key in (
                    "since_version", "upper_version",
                    "observed_at", "declared_digest_sha256")):
                raise FrontierInputError("UNAVAILABLE_STAGE_FABRICATED")
        else:
            raise FrontierInputError("STAGE_STATE_INVALID")
    return value


def evaluate(policy, snapshot, *, at=None, policy_digest=None, readback_digest=None):
    policy_data(policy)
    snapshot_data(snapshot)
    now = at or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise FrontierInputError("NOW_MUST_BE_AWARE")
    now = now.astimezone(timezone.utc)
    issues = []
    request_version = snapshot["requested_version"]
    if snapshot["source_binding"] != policy["source_binding"]:
        issues.append({"code": "SOURCE_SUBJECT_MISMATCH"})
    if snapshot["timeline"] != policy["timeline"]:
        issues.append({"code": "TIMELINE_MISMATCH"})
    global_age = (now - _stamp(snapshot["observed_at"])).total_seconds()
    if global_age > policy["max_age_seconds"]:
        issues.append({"code": "SNAPSHOT_STALE"})
    if global_age < -300:
        issues.append({"code": "SNAPSHOT_FUTURE"})
    if snapshot["state"] != "OBSERVED":
        issues.append({"code": "SNAPSHOT_INCOMPLETE"})
    catalog = snapshot["catalog_admission"]
    if catalog["state"] != policy["required_catalog_state"]:
        issues.append({"code": "CATALOG_NOT_ADMITTED"})
    if catalog["catalog_sha256"] is None:
        issues.append({"code": "CATALOG_DIGEST_UNAVAILABLE"})
    present = {x["name"]: x for x in snapshot["stages"]}
    required = set(policy["required_stages"])
    if set(present) - required:
        issues.append({"code": "UNREVIEWED_STAGE_PRESENT"})
    seen_ranges = []
    for name in policy["required_stages"]:
        stage = present.get(name)
        if stage is None:
            issues.append({"code": "REQUIRED_STAGE_MISSING", "stage": name})
            continue
        if stage["state"] != "OBSERVED":
            issues.append({"code": "REQUIRED_STAGE_UNAVAILABLE", "stage": name})
            continue
        if stage["timeline"] != policy["timeline"]:
            issues.append({"code": "STAGE_TIMELINE_MISMATCH", "stage": name})
            continue
        age = (now - _stamp(stage["observed_at"])).total_seconds()
        if age > policy["max_age_seconds"]:
            issues.append({"code": "STAGE_STALE", "stage": name})
        if age < -300:
            issues.append({"code": "STAGE_FUTURE", "stage": name})
        seen_ranges.append((name, stage["since_version"], stage["upper_version"]))
        if not stage["since_version"] <= request_version < stage["upper_version"]:
            issues.append({"code": "READ_VERSION_OUTSIDE_STAGE_FRONTIER", "stage": name})
    overlap = None
    spread = None
    if len(seen_ranges) == len(policy["required_stages"]):
        since = max(row[1] for row in seen_ranges)
        upper = min(row[2] for row in seen_ranges)
        overlap = {"since_inclusive": since, "upper_exclusive": upper}
        if since >= upper:
            issues.append({"code": "FRONTIER_INTERSECTION_EMPTY"})
        spread = max(row[2] for row in seen_ranges) - upper
        if spread > policy["max_version_skew"]:
            issues.append({"code": "FRONTIER_SKEW_EXCEEDED"})
    structural = not issues
    return {
        "schema": RESULT_SCHEMA,
        "contract_id": policy["contract_id"],
        "state": "STRUCTURAL_FRONTIER_MATCH_ONLY" if structural else "HOLD",
        "required_stage_count": len(required),
        "observed_stage_count": len(seen_ranges),
        "coverage_numerator": len(seen_ranges),
        "coverage_denominator": len(required),
        "requested_version": request_version,
        "intersection": overlap,
        "upper_version_spread": spread,
        "gap_count": len(issues),
        "gaps": sorted(issues, key=lambda x: (x["code"], x.get("stage", ""))),
        "policy_sha256": policy_digest,
        "snapshot_sha256": readback_digest,
        "stage_digests_independently_verified": False,
        "source_identity_independently_verified": False,
        "true_time_available": False,
        "external_consistency_proven": False,
        "database_queried": False,
        "replication_proven": False,
        "schema_migrated_by_this_verifier": False,
        "production_authorized": False,
        "effects_authorized": False,
    }


def read_file(path: Path, max_bytes: int):
    if path.is_symlink() or not path.is_file():
        raise FrontierInputError("FILE_UNAVAILABLE")
    if not 0 < path.stat().st_size <= max_bytes:
        raise FrontierInputError("INPUT_SIZE_INVALID")
    raw = path.read_bytes()
    return strict_json(raw, max_bytes), hashlib.sha256(raw).hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description="No-network logical data frontier comparison")
    ap.add_argument("--policy", required=True, type=Path)
    ap.add_argument("--readback", required=True, type=Path)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args(argv)
    try:
        policy, pdigest = read_file(args.policy, 65536)
        snapshot, sdigest = read_file(args.readback, MAX_INPUT)
        result = evaluate(policy, snapshot, policy_digest=pdigest, readback_digest=sdigest)
        code = 0 if result["state"] == "STRUCTURAL_FRONTIER_MATCH_ONLY" else 2
    except FrontierInputError as exc:
        code = 3
        result = {"schema": RESULT_SCHEMA, "state": "UNAVAILABLE",
                  "error_code": exc.code, "production_authorized": False,
                  "effects_authorized": False, "database_queried": False}
    if args.output:
        if args.output.is_symlink():
            return 3
        raw = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with args.output.open("xb") as stream:
            stream.write(raw)
            stream.flush()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
