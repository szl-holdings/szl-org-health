#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline, fail-closed database catalog admission. No network or SQL execution.

This compares a bounded sanitized catalog with reviewed structural requirements.
A passing comparison is NOT execution authority, a signature, or proof the input
really came from a database. Runtime snapshots require separate authentication.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

CATALOG_SCHEMA = "szl.database-catalog-readback/v1"
POLICY_SCHEMA = "szl.database-catalog-policy/v1"
RESULT_SCHEMA = "szl.database-catalog-admission/v1"
SHA1 = re.compile(r"[a-f0-9]{40}\Z")
IDENT = re.compile(r"(?:[a-z_][a-z0-9_]{0,62})\.(?:[a-z_][a-z0-9_]{0,62})\Z")
CODE = re.compile(r"[A-Z_]{3,80}\Z")


class InputError(ValueError):
    def __init__(self, code: str):
        if not CODE.fullmatch(code):
            code = "INVALID_INPUT"
        super().__init__(code)
        self.code = code


def _unique(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise InputError("DUPLICATE_JSON_KEY")
        seen[key] = value
    return seen


def _no_constant(_):
    raise InputError("NONFINITE_JSON_VALUE")


def strict_bytes(raw: bytes, *, max_bytes: int):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= max_bytes:
        raise InputError("INPUT_SIZE_INVALID")
    try:
        return json.loads(raw.decode("utf-8", "strict"),
                          object_pairs_hook=_unique, parse_constant=_no_constant)
    except InputError:
        raise
    except (UnicodeError, ValueError):
        raise InputError("INVALID_JSON") from None


def read_file(path: Path, *, max_bytes=262144):
    if path.is_symlink() or not path.is_file():
        raise InputError("SOURCE_FILE_UNAVAILABLE")
    if not 0 < path.stat().st_size <= max_bytes:
        raise InputError("INPUT_SIZE_INVALID")
    raw = path.read_bytes()
    return strict_bytes(raw, max_bytes=max_bytes), hashlib.sha256(raw).hexdigest()


def exact_fields(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise InputError("INVALID_FIELDS")


def identifier(text):
    if type(text) is not str or not IDENT.fullmatch(text):
        raise InputError("INVALID_IDENTIFIER")
    return text


def checked_count(value):
    if type(value) is int:
        n = value
    elif type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,7}", value):
        n = int(value)
    else:
        raise InputError("INVALID_COUNT")
    if not 0 <= n <= 10000000:
        raise InputError("INVALID_COUNT")
    return n


def source_binding(value):
    exact_fields(value, ("repository", "path", "git_blob_sha1"))
    if (type(value["repository"]) is not str
            or re.fullmatch(r"szl-holdings/[a-zA-Z0-9_.-]{1,100}", value["repository"]) is None
            or type(value["path"]) is not str
            or not value["path"] or len(value["path"]) > 220
            or value["path"].startswith("/")
            or ".." in value["path"].split("/")
            or type(value["git_blob_sha1"]) is not str
            or SHA1.fullmatch(value["git_blob_sha1"]) is None):
        raise InputError("INVALID_SOURCE_BINDING")
    return value


def policy_data(value):
    exact_fields(value, ("schema", "contract_id", "source_binding",
                         "max_age_seconds", "required_tables", "required_functions"))
    if (value["schema"] != POLICY_SCHEMA or type(value["contract_id"]) is not str
            or re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,99}", value["contract_id"]) is None):
        raise InputError("INVALID_POLICY")
    source_binding(value["source_binding"])
    if type(value["max_age_seconds"]) is not int or not 60 <= value["max_age_seconds"] <= 86400:
        raise InputError("INVALID_POLICY")
    tables = value["required_tables"]
    funcs = value["required_functions"]
    if (type(tables) is not list or not 1 <= len(tables) <= 100
            or type(funcs) is not list or not 1 <= len(funcs) <= 30):
        raise InputError("INVALID_POLICY")
    seen = set()
    for row in tables:
        exact_fields(row, ("name", "rls_enabled", "rls_forced",
                           "min_policies", "max_public_grants"))
        name = identifier(row["name"])
        if name in seen:
            raise InputError("DUPLICATE_POLICY_OBJECT")
        seen.add(name)
        if type(row["rls_enabled"]) is not bool or type(row["rls_forced"]) is not bool:
            raise InputError("INVALID_POLICY")
        if type(row["min_policies"]) is not int or not 0 <= row["min_policies"] <= 20:
            raise InputError("INVALID_POLICY")
        if type(row["max_public_grants"]) is not int or row["max_public_grants"] != 0:
            raise InputError("INVALID_POLICY")
    seen.clear()
    for row in funcs:
        exact_fields(row, ("name", "security_definer", "binds_principal",
                           "references_context_bindings"))
        name = identifier(row["name"])
        if name in seen:
            raise InputError("DUPLICATE_POLICY_OBJECT")
        seen.add(name)
        if any(type(row[k]) is not bool or row[k] is not True
               for k in ("security_definer", "binds_principal",
                         "references_context_bindings")):
            raise InputError("INVALID_POLICY")
    return value


def catalog_data(value):
    exact_fields(value, ("schema", "observed_at", "state", "scope",
                         "source_binding", "tables", "functions", "credentials_recorded"))
    if value["schema"] != CATALOG_SCHEMA or value["state"] != "OBSERVED":
        raise InputError("CATALOG_NOT_OBSERVED")
    if type(value["scope"]) is not str or value["scope"] not in (
        "NEON_VALIDATION_READ_ONLY", "NEON_PRODUCTION_READ_ONLY",
        "POSTGRES_OTHER_READ_ONLY"):
        raise InputError("INVALID_CATALOG_SCOPE")
    source_binding(value["source_binding"])
    if value["credentials_recorded"] is not False:
        raise InputError("CREDENTIAL_FIELD_DISALLOWED")
    if type(value["observed_at"]) is not str or len(value["observed_at"]) > 45:
        raise InputError("INVALID_OBSERVATION_TIME")
    try:
        when = datetime.fromisoformat(value["observed_at"].replace("Z", "+00:00"))
    except ValueError:
        raise InputError("INVALID_OBSERVATION_TIME") from None
    if when.tzinfo is None:
        raise InputError("INVALID_OBSERVATION_TIME")
    if type(value["tables"]) is not list or len(value["tables"]) > 1000:
        raise InputError("INVALID_CATALOG")
    if type(value["functions"]) is not list or len(value["functions"]) > 100:
        raise InputError("INVALID_CATALOG")
    tables, funcs = {}, {}
    for row in value["tables"]:
        exact_fields(row, ("name", "rls_enabled", "rls_forced", "policy_count",
                           "public_grants", "invalid_indexes"))
        name = identifier(row["name"])
        if name in tables:
            raise InputError("DUPLICATE_CATALOG_OBJECT")
        if type(row["rls_enabled"]) is not bool or type(row["rls_forced"]) is not bool:
            raise InputError("INVALID_CATALOG")
        for field in ("policy_count", "public_grants", "invalid_indexes"):
            checked_count(row[field])
        tables[name] = row
    for row in value["functions"]:
        exact_fields(row, ("name", "security_definer", "binds_principal",
                           "references_context_bindings"))
        name = identifier(row["name"])
        if name in funcs:
            raise InputError("DUPLICATE_CATALOG_OBJECT")
        if any(type(row[k]) is not bool
               for k in ("security_definer", "binds_principal", "references_context_bindings")):
            raise InputError("INVALID_CATALOG")
        funcs[name] = row
    return value, when, tables, funcs


def assess(policy, catalog, *, at=None, catalog_sha256=None, policy_sha256=None):
    p = policy_data(policy)
    c, when, tables, funcs = catalog_data(catalog)
    at = at or datetime.now(timezone.utc)
    if at.tzinfo is None:
        raise InputError("INVALID_OBSERVATION_TIME")
    age = (at - when).total_seconds()
    gaps = []
    if age > p["max_age_seconds"]:
        gaps.append({"code": "CATALOG_STALE"})
    if age < -300:
        gaps.append({"code": "CATALOG_IN_FUTURE"})
    if c["source_binding"] != p["source_binding"]:
        gaps.append({"code": "SOURCE_CLAIM_DIFFERS"})
    for expected in p["required_tables"]:
        name = expected["name"]
        got = tables.get(name)
        if got is None:
            gaps.append({"code": "TABLE_NOT_OBSERVED", "object": name})
            continue
        if got["rls_enabled"] != expected["rls_enabled"]:
            gaps.append({"code": "RLS_STATE_DRIFT", "object": name})
        if got["rls_forced"] != expected["rls_forced"]:
            gaps.append({"code": "RLS_FORCE_STATE_DRIFT", "object": name})
        if checked_count(got["policy_count"]) < expected["min_policies"]:
            gaps.append({"code": "POLICY_COVERAGE_DRIFT", "object": name})
        if checked_count(got["public_grants"]) > expected["max_public_grants"]:
            gaps.append({"code": "PUBLIC_TABLE_GRANTS", "object": name})
        if checked_count(got["invalid_indexes"]) != 0:
            gaps.append({"code": "INVALID_INDEX", "object": name})
    for expected in p["required_functions"]:
        name = expected["name"]
        got = funcs.get(name)
        if got is None:
            gaps.append({"code": "FUNCTION_NOT_OBSERVED", "object": name})
            continue
        for key, code in (("security_definer", "SECURITY_DEFINER_DRIFT"),
                          ("binds_principal", "PRINCIPAL_BINDING_UNOBSERVED"),
                          ("references_context_bindings", "CONTEXT_BINDING_UNOBSERVED")):
            if got[key] != expected[key]:
                gaps.append({"code": code, "object": name})
    return {
        "schema": RESULT_SCHEMA,
        "contract_id": p["contract_id"],
        "state": "CATALOG_MATCH_ONLY" if not gaps else "HOLD",
        "gap_count": len(gaps),
        "gaps": sorted(gaps, key=lambda x: (x["code"], x.get("object", ""))),
        "required_tables": len(p["required_tables"]),
        "observed_tables": len(tables),
        "required_functions": len(p["required_functions"]),
        "observed_functions": len(funcs),
        "catalog_observed_at": when.astimezone(timezone.utc).isoformat(),
        "catalog_sha256": catalog_sha256,
        "policy_sha256": policy_sha256,
        "reported_source_blob_matches": c["source_binding"] == p["source_binding"],
        "source_identity_independently_verified": False,
        "database_queried_by_this_verifier": False,
        "production_authorized": False,
        "migration_authorized": False,
        "external_writes_performed": False,
        "independent_witness": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline schema-catalog comparison; never grants production authority")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        p, pdigest = read_file(args.policy, max_bytes=65536)
        c, cdigest = read_file(args.catalog)
        result = assess(p, c, policy_sha256=pdigest, catalog_sha256=cdigest)
        exit_code = 0 if result["gap_count"] == 0 else 2
    except InputError as exc:
        result = {"schema": RESULT_SCHEMA, "state": "UNAVAILABLE",
                  "error_code": exc.code, "production_authorized": False,
                  "migration_authorized": False, "external_writes_performed": False}
        exit_code = 3
    if args.output:
        if args.output.is_symlink():
            raise SystemExit(3)
        raw = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        with args.output.open("xb") as stream:
            stream.write(raw)
            stream.flush()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
