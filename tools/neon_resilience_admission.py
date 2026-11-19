#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline, metadata-only Neon recovery/security admission. No network or SQL.

Source-controlled policy is compared with a sanitized operator-provided readback.
This code does NOT authenticate the source of that readback, prove backup restore,
approve migration, inspect business rows, or confer production authority.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

POLICY_SCHEMA = "szl.neon-resilience-policy/v1"
READBACK_SCHEMA = "szl.neon-resilience-readback/v1"
RESULT_SCHEMA = "szl.neon-resilience-admission/v1"
MAX_BYTES = 16384


class InvalidInput(ValueError):
    """Invalid or potentially unsafe input, not an operational HOLD."""


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise InvalidInput("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _reject_constant(_value):
    raise InvalidInput("NONFINITE_VALUE")


def strict_json(raw: bytes) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
        raise InvalidInput("INPUT_SIZE_INVALID")
    try:
        result = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                            parse_constant=_reject_constant)
    except InvalidInput:
        raise
    except (UnicodeError, ValueError) as exc:
        raise InvalidInput("JSON_INVALID") from exc
    if type(result) is not dict:
        raise InvalidInput("OBJECT_REQUIRED")
    return result


def _keys(obj, required):
    if type(obj) is not dict or set(obj) != set(required):
        raise InvalidInput("FIELDS_INVALID")


def _integer(x, upper=10**9):
    if type(x) is not int or not 0 <= x <= upper:
        raise InvalidInput("INTEGER_INVALID")
    return x


def _boolean(x):
    if type(x) is not bool:
        raise InvalidInput("BOOLEAN_INVALID")
    return x


def _stamp(value):
    if type(value) is not str or not 19 <= len(value) <= 35:
        raise InvalidInput("TIMESTAMP_INVALID")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidInput("TIMESTAMP_INVALID") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise InvalidInput("TIMESTAMP_INVALID")
    return result.astimezone(timezone.utc)


def validate_policy(policy):
    _keys(policy, ("schema", "environment", "max_age_seconds",
                   "min_history_seconds", "require_protected_branch",
                   "require_automatic_backups", "max_snapshot_age_seconds",
                   "min_snapshot_remaining_seconds", "max_restore_drill_age_seconds"))
    if policy["schema"] != POLICY_SCHEMA or policy["environment"] != "PRODUCTION":
        raise InvalidInput("POLICY_INVALID")
    for key in ("max_age_seconds", "min_history_seconds", "max_snapshot_age_seconds",
                "min_snapshot_remaining_seconds", "max_restore_drill_age_seconds"):
        _integer(policy[key])
    if not 60 <= policy["max_age_seconds"] <= 3600:
        raise InvalidInput("AGE_POLICY_INVALID")
    if not 86400 <= policy["min_history_seconds"] <= 2592000:
        raise InvalidInput("HISTORY_POLICY_INVALID")
    for key in ("require_protected_branch", "require_automatic_backups"):
        _boolean(policy[key])


def validate_readback(value):
    _keys(value, ("schema", "environment", "observed_at", "source_state",
                  "history_retention_seconds", "default_branch_protected",
                  "snapshots", "network", "catalog", "credentials_recorded"))
    if value["schema"] != READBACK_SCHEMA or value["environment"] != "PRODUCTION":
        raise InvalidInput("READBACK_SCHEMA_INVALID")
    if value["source_state"] not in ("OBSERVED", "UNAVAILABLE"):
        raise InvalidInput("STATE_INVALID")
    observed = _stamp(value["observed_at"])
    _integer(value["history_retention_seconds"])
    _boolean(value["default_branch_protected"])
    if value["credentials_recorded"] is not False:
        raise InvalidInput("CREDENTIAL_MATERIAL_REFUSED")
    snaps = value["snapshots"]
    _keys(snaps, ("count", "latest_created_at", "latest_expires_at",
                  "automatic_schedule_count", "last_restore_drill_at"))
    _integer(snaps["count"], upper=100000)
    _integer(snaps["automatic_schedule_count"], upper=1000)
    for key in ("latest_created_at", "latest_expires_at", "last_restore_drill_at"):
        if snaps[key] is not None:
            _stamp(snaps[key])
    network = value["network"]
    _keys(network, ("public_connections_blocked", "ip_allowlist_count",
                    "independent_network_exception_approved"))
    _boolean(network["public_connections_blocked"])
    _integer(network["ip_allowlist_count"], upper=10000)
    _boolean(network["independent_network_exception_approved"])
    catalog = value["catalog"]
    _keys(catalog, ("public_table_acl_entries", "unreviewed_rls_exceptions",
                    "catalog_state"))
    _integer(catalog["public_table_acl_entries"])
    _integer(catalog["unreviewed_rls_exceptions"])
    if catalog["catalog_state"] not in ("CATALOG_MATCH_ONLY", "HOLD", "UNAVAILABLE"):
        raise InvalidInput("CATALOG_STATE_INVALID")
    return observed


def assess(policy: dict, readback: dict, *, now: datetime | None = None) -> dict:
    validate_policy(policy)
    observed = validate_readback(readback)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise InvalidInput("NOW_MUST_BE_AWARE")
    now = now.astimezone(timezone.utc)
    findings = []
    def hold(code, condition):
        if not condition:
            findings.append(code)

    age = (now - observed).total_seconds()
    hold("READBACK_STALE_OR_FUTURE", -120 <= age <= policy["max_age_seconds"])
    hold("CONTROL_PLANE_UNAVAILABLE", readback["source_state"] == "OBSERVED")
    hold("HISTORY_WINDOW_TOO_SHORT", readback["history_retention_seconds"] >= policy["min_history_seconds"])
    if policy["require_protected_branch"]:
        hold("DEFAULT_BRANCH_UNPROTECTED", readback["default_branch_protected"])
    snaps = readback["snapshots"]
    hold("SNAPSHOT_MISSING", snaps["count"] > 0)
    created = _stamp(snaps["latest_created_at"]) if snaps["latest_created_at"] is not None else None
    expiry = _stamp(snaps["latest_expires_at"]) if snaps["latest_expires_at"] is not None else None
    hold("SNAPSHOT_STALE_OR_FUTURE", created is not None and
         -120 <= (observed - created).total_seconds() <= policy["max_snapshot_age_seconds"])
    hold("SNAPSHOT_RETENTION_SHORT", expiry is not None and
         (expiry - observed).total_seconds() >= policy["min_snapshot_remaining_seconds"])
    if policy["require_automatic_backups"]:
        hold("AUTOMATIC_BACKUPS_UNCONFIGURED", snaps["automatic_schedule_count"] > 0)
    restored = _stamp(snaps["last_restore_drill_at"]) if snaps["last_restore_drill_at"] is not None else None
    hold("RESTORE_DRILL_UNVERIFIED", restored is not None and
         -120 <= (observed - restored).total_seconds() <= policy["max_restore_drill_age_seconds"])
    net = readback["network"]
    hold("NETWORK_EXPOSURE_REVIEW_REQUIRED",
         net["public_connections_blocked"] or net["ip_allowlist_count"] > 0 or
         net["independent_network_exception_approved"])
    cat = readback["catalog"]
    hold("PUBLIC_TABLE_GRANTS_PRESENT", cat["public_table_acl_entries"] == 0)
    hold("RLS_EXCEPTION_NOT_REVIEWED", cat["unreviewed_rls_exceptions"] == 0)
    hold("CATALOG_ADMISSION_NOT_MET", cat["catalog_state"] == "CATALOG_MATCH_ONLY")
    # Source binding is not independently authenticated by an offline JSON parser.
    return {
        "schema": RESULT_SCHEMA,
        "state": "HOLD" if findings else "SCOPED_METADATA_MATCH_ONLY",
        "production_authorized": False,
        "control_plane_identity_independently_verified": False,
        "restore_independently_verified_by_this_verifier": False,
        "checked_at_utc": now.isoformat().replace("+00:00", "Z"),
        "readback_sha256": hashlib.sha256(json.dumps(readback, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "findings": sorted(findings),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Offline Neon resilience policy oracle; does not connect to Neon.")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--readback", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        policy = strict_json(args.policy.read_bytes())
        readback = strict_json(args.readback.read_bytes())
        result = assess(policy, readback)
    except (InvalidInput, OSError):
        # Never print paths, input, connection strings, project IDs, or provider errors.
        print(json.dumps({"schema": RESULT_SCHEMA, "state": "UNAVAILABLE", "production_authorized": False}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0 if result["state"] == "SCOPED_METADATA_MATCH_ONLY" else 2


if __name__ == "__main__":
    sys.exit(main())
