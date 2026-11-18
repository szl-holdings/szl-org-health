#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded read-only PostgreSQL catalog observer for the offline SZL DB gate.

No application data is selected, no migrations or DDL are executed, no
credentials or SQL function bodies are emitted. Collection is a snapshot,
not a trusted actor identity, tenant isolation proof or production authority.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import parse_qs, urlsplit

try:
    from tools.database_catalog_admission import (
        CATALOG_SCHEMA, InputError, assess, policy_data, read_file,
    )
except ModuleNotFoundError:
    # Direct isolated execution under -I omits checkout; use exact parent.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_catalog_admission import (
        CATALOG_SCHEMA, InputError, assess, policy_data, read_file,
    )

SCOPES = ("NEON_VALIDATION_READ_ONLY", "NEON_PRODUCTION_READ_ONLY",
          "POSTGRES_OTHER_READ_ONLY")
DSN_ENV = "SZL_DATABASE_AUDIT_DSN"
MAX_TABLES = 200
MAX_FUNCTIONS = 20

# All statements are fixed, read only, bounded by LIMIT, with no user input.
# No role/database identifiers, private function bodies, or user table rows
# leave the connection. Pg_catalog statistics are not row-level evidence.
TX_SQL = """
SELECT current_setting('transaction_read_only') AS read_only,
       (SELECT r.rolsuper FROM pg_catalog.pg_roles r
         WHERE r.rolname=current_user) AS is_superuser,
       (SELECT r.rolbypassrls FROM pg_catalog.pg_roles r
         WHERE r.rolname=current_user) AS bypass_rls
"""
TABLE_SQL = """
SELECT n.nspname::text AS schema_name,
       c.relname::text AS table_name,
       c.relrowsecurity AS rls_enabled,
       c.relforcerowsecurity AS rls_forced,
       (SELECT count(*) FROM pg_catalog.pg_policy p WHERE p.polrelid=c.oid) AS policy_count,
       (SELECT count(*) FROM pg_catalog.pg_index i
          WHERE i.indrelid=c.oid AND NOT i.indisvalid) AS invalid_indexes,
       COALESCE((SELECT count(*) FROM pg_catalog.aclexplode(c.relacl) AS a
          WHERE a.grantee=0 AND a.privilege_type IN
             ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER')),0)
          AS public_grants
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN ('r','p')
 ORDER BY n.nspname,c.relname
 LIMIT 201
"""
FUNCTION_SQL = """
SELECT n.nspname::text AS schema_name,
       p.proname::text AS function_name,
       p.prosecdef AS security_definer,
       pg_catalog.pg_get_functiondef(p.oid) AS definition
  FROM pg_catalog.pg_proc p
  JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='public'
   AND p.proname='a11oy_memory_context_matches'
   AND p.prokind='f'
 ORDER BY p.oid
 LIMIT 21
"""


class ObservationBlocked(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def validate_dsn(dsn: str, scope: str) -> None:
    """Require hostname-verified TLS and an explicit database credential.

    Parse-only: never emit the input DSN or its components.
    Other libpq DSN methods, hostaddr overrides and service routing are denied.
    """
    if scope not in SCOPES:
        raise ObservationBlocked("SCOPE_UNSUPPORTED")
    if type(dsn) is not str or not 20 <= len(dsn) <= 4096 or any(
            x in dsn for x in ("\n", "\r", "\0")):
        raise ObservationBlocked("DSN_INVALID")
    try:
        parsed = urlsplit(dsn)
        query = parse_qs(parsed.query, strict_parsing=True, keep_blank_values=True)
        host = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except (ValueError, TypeError):
        raise ObservationBlocked("DSN_INVALID") from None
    if (parsed.scheme not in ("postgresql", "postgres") or not host
            or not username or password is None or not password
            or not parsed.path.startswith("/") or len(parsed.path) <= 1
            or parsed.fragment or parsed.username is None):
        raise ObservationBlocked("DSN_INVALID")
    if port not in (None, 5432):
        raise ObservationBlocked("DATABASE_PORT_DENIED")
    if set(query) - {"sslmode", "channel_binding"}:
        raise ObservationBlocked("DSN_OPTIONS_DENIED")
    if query.get("sslmode") != ["verify-full"]:
        raise ObservationBlocked("TLS_IDENTITY_REQUIRED")
    if "channel_binding" in query and query["channel_binding"] != ["require"]:
        raise ObservationBlocked("CHANNEL_BINDING_INVALID")
    if scope.startswith("NEON_") and not host.lower().endswith(".neon.tech"):
        raise ObservationBlocked("NEON_HOST_REQUIRED")
    # Local network, UNIX socket and hostaddr override are impossible under
    # this URI/host/TLS contract. The database user is never echoed.
    if re.search(r"[\s\\]", host):
        raise ObservationBlocked("DSN_HOST_INVALID")


def _rows(connection, statement: str, cap: int) -> list[dict]:
    with connection.cursor() as cursor:
        cursor.execute(statement)
        desc = cursor.description
        if desc is None:
            raise ObservationBlocked("CATALOG_SCHEMA_MISSING")
        columns = [col.name for col in desc]
        records = cursor.fetchmany(cap + 1)
        if len(records) > cap:
            raise ObservationBlocked("CATALOG_PAGE_LIMIT")
        result = []
        for record in records:
            if len(record) != len(columns):
                raise ObservationBlocked("CATALOG_ROW_INVALID")
            row = dict(zip(columns, record))
            if set(row) != set(columns):
                raise ObservationBlocked("CATALOG_ROW_INVALID")
            result.append(row)
        return result


def _remove_sql_comments(body: str) -> str:
    # The form is inspected for *lexical* coverage only, not authorization
    # semantics. Strip nonnested comments to prevent simple comment spoofing.
    body = re.sub(r"/\*.*?\*/", " ", body, flags=re.S)
    body = re.sub(r"--[^\r\n]*", " ", body)
    return body


def _function_flags(body: str) -> tuple[bool, bool]:
    if type(body) is not str or len(body) > 100000:
        raise ObservationBlocked("FUNCTION_BODY_UNAVAILABLE")
    text = _remove_sql_comments(body)
    principal = bool(re.search(r"\bbinding\.principal_oid\b", text, re.I)
                     and re.search(r"\bsession_user\b", text, re.I)
                     and re.search(r"\bpg_catalog\.pg_roles\b", text, re.I))
    binding = bool(re.search(
        r"\bfrom\s+public\.memory_context_bindings\b", text, re.I))
    return principal, binding


def sanitize_rows(tables: list[dict], routines: list[dict],
                  policy: dict, scope: str, *, observed_at: str | None = None) -> dict:
    """Drop raw function definitions and all connection identities."""
    policy_data(policy)
    if scope not in SCOPES:
        raise ObservationBlocked("SCOPE_UNSUPPORTED")
    if type(tables) is not list or len(tables) > MAX_TABLES:
        raise ObservationBlocked("CATALOG_PAGE_LIMIT")
    if type(routines) is not list or len(routines) > MAX_FUNCTIONS:
        raise ObservationBlocked("CATALOG_PAGE_LIMIT")
    safe_tables = []
    for row in tables:
        expected = {
            "schema_name", "table_name", "rls_enabled", "rls_forced",
            "policy_count", "public_grants", "invalid_indexes",
        }
        if type(row) is not dict or set(row) != expected:
            raise ObservationBlocked("CATALOG_ROW_INVALID")
        name = f"{row['schema_name']}.{row['table_name']}"
        if (row["schema_name"] != "public"
                or type(row["table_name"]) is not str
                or re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", row["table_name"]) is None
                or type(row["rls_enabled"]) is not bool
                or type(row["rls_forced"]) is not bool):
            raise ObservationBlocked("CATALOG_ROW_INVALID")
        for key in ("policy_count", "public_grants", "invalid_indexes"):
            value = row[key]
            if type(value) is not int or not 0 <= value <= 10000000:
                raise ObservationBlocked("CATALOG_COUNT_INVALID")
        safe_tables.append({
            "name": name,
            "rls_enabled": row["rls_enabled"],
            "rls_forced": row["rls_forced"],
            "policy_count": row["policy_count"],
            "public_grants": row["public_grants"],
            "invalid_indexes": row["invalid_indexes"],
        })
    safe_functions = []
    for row in routines:
        expected = {"schema_name", "function_name",
                    "security_definer", "definition"}
        if type(row) is not dict or set(row) != expected:
            raise ObservationBlocked("FUNCTION_ROW_INVALID")
        if (row["schema_name"] != "public"
                or row["function_name"] != "a11oy_memory_context_matches"
                or type(row["security_definer"]) is not bool):
            raise ObservationBlocked("FUNCTION_ROW_INVALID")
        principal, binding = _function_flags(row["definition"])
        safe_functions.append({
            "name": "public.a11oy_memory_context_matches",
            "security_definer": row["security_definer"],
            "binds_principal": principal,
            "references_context_bindings": binding,
        })
    observed_at = observed_at or datetime.now(timezone.utc).isoformat()
    # This source binding is a *declaration derived from the source policy*;
    # never infer it proves remote source identity or actual migration history.
    return {
        "schema": CATALOG_SCHEMA,
        "observed_at": observed_at,
        "state": "OBSERVED",
        "scope": scope,
        "source_binding": policy["source_binding"],
        "tables": safe_tables,
        "functions": safe_functions,
        "credentials_recorded": False,
    }


def collect(connection, policy: dict, scope: str) -> dict:
    """Call with a connection already configured for a read-only transaction."""
    guard = _rows(connection, TX_SQL, 1)
    if len(guard) != 1 or guard[0] != {
            "read_only": "on", "is_superuser": False, "bypass_rls": False}:
        raise ObservationBlocked("READ_ONLY_LEAST_PRIVILEGE_REQUIRED")
    tables = _rows(connection, TABLE_SQL, MAX_TABLES)
    routines = _rows(connection, FUNCTION_SQL, MAX_FUNCTIONS)
    return sanitize_rows(tables, routines, policy, scope)


def _connect_and_collect(dsn: str, scope: str, policy: dict):
    try:
        import psycopg
    except ImportError:
        raise ObservationBlocked("DATABASE_DRIVER_NOT_INSTALLED") from None
    # Never expose DSN, raw libpq errors, SQL bodies, addresses or identities.
    try:
        with psycopg.connect(
            dsn, connect_timeout=8, autocommit=False,
            options="-c statement_timeout=7000 -c idle_in_transaction_session_timeout=12000",
        ) as connection:
            connection.read_only = True
            connection.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
            snapshot = collect(connection, policy, scope)
            connection.rollback()
            return snapshot
    except ObservationBlocked:
        raise
    except Exception:
        raise ObservationBlocked("PROVIDER_READ_UNAVAILABLE") from None


def _save_exclusive(path: Path, payload: dict):
    # Prevent an operator typo from committing private DB metadata into a
    # source checkout. Compare fully resolved paths without reading secrets.
    checkout = Path(__file__).resolve().parent.parent
    if path.resolve().is_relative_to(checkout):
        raise ObservationBlocked("SOURCE_CHECKOUT_OUTPUT_DENIED")
    if path.is_symlink() or path.exists():
        raise ObservationBlocked("OUTPUT_EXISTS")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ObservationBlocked("OUTPUT_DIRECTORY_UNAVAILABLE")
    # Do not place observation in the source checkout or a public static dir.
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(raw) > 262144:
        raise ObservationBlocked("OUTPUT_TOO_LARGE")
    with path.open("xb") as fd:
        fd.write(raw)
        fd.flush()
        os.fsync(fd.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only PG catalog collector; produces private snapshots only"
    )
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--scope", choices=SCOPES, required=True)
    parser.add_argument("--catalog-output", type=Path, required=True)
    parser.add_argument("--admission-output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.catalog_output.resolve() == args.admission_output.resolve():
            raise ObservationBlocked("OUTPUT_PATH_COLLISION")
        policy, pdigest = read_file(args.policy, max_bytes=65536)
        policy_data(policy)
        # Fail before credential access if either output cannot be created.
        for dest in (args.catalog_output, args.admission_output):
            if dest.resolve().is_relative_to(Path(__file__).resolve().parent.parent):
                raise ObservationBlocked("SOURCE_CHECKOUT_OUTPUT_DENIED")
            if dest.exists() or dest.is_symlink():
                raise ObservationBlocked("OUTPUT_EXISTS")
            if not dest.parent.is_dir() or dest.parent.is_symlink():
                raise ObservationBlocked("OUTPUT_DIRECTORY_UNAVAILABLE")
        dsn = os.environ.get(DSN_ENV)
        validate_dsn(dsn, args.scope)
        snapshot = _connect_and_collect(dsn, args.scope, policy)
        verdict = assess(policy, snapshot, policy_sha256=pdigest)
        # A non-green catalog is *still* useful evidence. Save the private
        # readback and HOLD verdict, never treat a valid file as authorization.
        _save_exclusive(args.catalog_output, snapshot)
        _save_exclusive(args.admission_output, verdict)
        print(json.dumps({
            "state": verdict["state"], "gap_count": verdict["gap_count"],
            "tables_observed": verdict["observed_tables"],
            "functions_observed": verdict["observed_functions"],
            "production_authorized": False,
            "source_identity_independently_verified": False,
            "provider_changes": False,
        }, sort_keys=True))
        return 0 if verdict["state"] == "CATALOG_MATCH_ONLY" else 2
    except InputError as exc:
        error = exc.code
    except ObservationBlocked as exc:
        error = exc.code
    except Exception:
        error = "COLLECTION_UNAVAILABLE"
    print(json.dumps({"state": "UNAVAILABLE", "code": error,
                      "production_authorized": False, "provider_changes": False}))
    return 3


if __name__ == "__main__":
    sys.exit(main())
