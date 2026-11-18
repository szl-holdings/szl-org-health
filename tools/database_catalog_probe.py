#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Emit one read-only PostgreSQL catalog SELECT, without opening a connection.

Provider execution is deliberately owned by an independently authorized read-only
connection. A generated source-binding value is a policy assertion, NEVER proof
that a migration ran. Returned booleans are structural/textual indicators, not
proof of RLS principal isolation, backup durability or production admission.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from tools.database_catalog_admission import (
    InputError,
    policy_data,
    read_file,
)

SCHEMA = "szl.pg-catalog-probe/v1"
SUPPORTED_FUNCTION = "public.a11oy_memory_context_matches"
SCOPES = frozenset(
    {
        "NEON_VALIDATION_READ_ONLY",
        "NEON_PRODUCTION_READ_ONLY",
        "POSTGRES_OTHER_READ_ONLY",
    }
)
MAX_SQL_BYTES = 24_000
_NAME = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")


class ProbeHold(ValueError):
    """Fixed, secret-free refusal code."""


def sql_literal(text: str) -> str:
    """Quote a literal, never synthesize SQL identifiers from untrusted bytes."""
    if not isinstance(text, str) or len(text) > 2048 or "\x00" in text:
        raise ProbeHold("INVALID_SQL_LITERAL")
    return "'" + text.replace("'", "''") + "'"


def qualified_name(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or value.count(".") != 1:
        raise ProbeHold("INVALID_SQL_IDENTIFIER")
    schema, relation = value.split(".")
    if not _NAME.fullmatch(schema) or not _NAME.fullmatch(relation):
        raise ProbeHold("INVALID_SQL_IDENTIFIER")
    return schema, relation


def _expected_rows(names: list[str]) -> str:
    if not names:
        raise ProbeHold("EMPTY_POLICY_OBJECT_LIST")
    pairs = [qualified_name(name) for name in names]
    if len(set(pairs)) != len(pairs):
        raise ProbeHold("DUPLICATE_POLICY_OBJECT")
    return ",\n        ".join("(" + sql_literal(schema) + ", " + sql_literal(table) + ")" for schema, table in pairs)


def build_select(policy: dict, *, scope: str) -> str:
    """Build a SELECT over system catalogs, with zero user table/row reads.

    All actual table/function values come from pg_catalog. The immutable source
    binding is copied from the supplied policy, and thus remains unverified.
    The only supported function contract is Memory Covenant v2; its indicators
    are intentionally not an authorization test and are not SQL AST proofs.
    """
    policy_data(policy)
    if scope not in SCOPES:
        raise ProbeHold("INVALID_PROBE_SCOPE")
    required_tables = [item["name"] for item in policy["required_tables"]]
    required_functions = [item["name"] for item in policy["required_functions"]]
    if required_functions != [SUPPORTED_FUNCTION]:
        raise ProbeHold("UNSUPPORTED_FUNCTION_CONTRACT")
    table_values = _expected_rows(required_tables)
    func_values = _expected_rows(required_functions)
    binding = json.dumps(policy["source_binding"], sort_keys=True, separators=(",", ":"), allow_nan=False)
    # SQL code has no interpolation other than *validated and quoted literals*.
    # Database permissions and access-denial handling remain provider-owned.
    query = (
        f"""
WITH
  expected_tables(schema_name, object_name) AS (
    VALUES {table_values}
  ),
  observed_tables AS (
    SELECT e.schema_name, e.object_name, c.oid, c.relrowsecurity,
           c.relforcerowsecurity, c.relacl, c.relowner
    FROM expected_tables AS e
    JOIN pg_catalog.pg_namespace AS n ON n.nspname = e.schema_name
    JOIN pg_catalog.pg_class AS c
      ON c.relnamespace = n.oid
     AND c.relname = e.object_name
     AND c.relkind IN ('r', 'p')
  ),
  expected_functions(schema_name, object_name) AS (
    VALUES {func_values}
  ),
  observed_functions AS (
    SELECT e.schema_name, e.object_name, p.oid, p.prosecdef, p.proconfig,
           lower(pg_catalog.pg_get_functiondef(p.oid)) AS normalized_definition
    FROM expected_functions AS e
    JOIN pg_catalog.pg_namespace AS n ON n.nspname = e.schema_name
    JOIN pg_catalog.pg_proc AS p
      ON p.pronamespace = n.oid AND p.proname = e.object_name
     AND p.pronargs = 2
     AND p.proargtypes[0] = 'pg_catalog.text'::pg_catalog.regtype
     AND p.proargtypes[1] = 'pg_catalog.text'::pg_catalog.regtype
  )
SELECT pg_catalog.jsonb_build_object(
  'schema', 'szl.database-catalog-readback/v1',
  'observed_at', pg_catalog.to_char(
     pg_catalog.clock_timestamp() AT TIME ZONE 'UTC',
     'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
  ),
  'state', 'OBSERVED',
  'scope', {sql_literal(scope)},
  'source_binding', {sql_literal(binding)}::pg_catalog.jsonb,
  'tables', COALESCE((
    SELECT pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object(
        'name', t.schema_name || '.' || t.object_name,
        'rls_enabled', t.relrowsecurity,
        'rls_forced', t.relforcerowsecurity,
        'policy_count', (
           SELECT count(*)::integer FROM pg_catalog.pg_policy AS pol
           WHERE pol.polrelid = t.oid
        ),
        'public_grants', (
           SELECT count(*)::integer
           FROM pg_catalog.aclexplode(
              COALESCE(t.relacl, pg_catalog.acldefault('r', t.relowner))
           ) AS acl
           WHERE acl.grantee = 0
        ),
        'invalid_indexes', (
           SELECT count(*)::integer FROM pg_catalog.pg_index AS idx
           WHERE idx.indrelid = t.oid AND NOT idx.indisvalid
        )
      ) ORDER BY t.schema_name, t.object_name
    ) FROM observed_tables AS t
  ), '[]'::pg_catalog.jsonb),
  'functions', COALESCE((
    SELECT pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object(
        'name', f.schema_name || '.' || f.object_name,
        'security_definer', f.prosecdef,
        'binds_principal', (
          f.prosecdef
          AND EXISTS (
            SELECT 1 FROM unnest(f.proconfig) AS setting(value)
            WHERE replace(lower(setting.value), ' ', '')
                   = 'search_path=pg_catalog,pg_temp'
          )
          AND strpos(f.normalized_definition, 'session_user') > 0
          AND strpos(f.normalized_definition, 'public.memory_context_bindings') > 0
        ),
        'references_context_bindings',
          strpos(f.normalized_definition, 'public.memory_context_bindings') > 0
      ) ORDER BY f.schema_name, f.object_name
    ) FROM observed_functions AS f
  ), '[]'::pg_catalog.jsonb),
  'credentials_recorded', FALSE
) AS catalog
""".strip()
        + "\n"
    )
    if len(query.encode("utf-8")) > MAX_SQL_BYTES:
        raise ProbeHold("SQL_BYTE_BUDGET")
    # No DML, DDL, provider connections, role switches, or second statements.
    return query


def emit_file(target: Path, content: bytes) -> str:
    """Exclusive output: never replace an operator-owned SQL or private record."""
    if target.is_symlink() or target.exists():
        raise ProbeHold("OUTPUT_ALREADY_EXISTS")
    with target.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(content).hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--scope", choices=sorted(SCOPES), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        source, policy_sha = read_file(args.policy, max_bytes=65_536)
        body = build_select(source, scope=args.scope).encode("utf-8")
        query_sha = emit_file(args.output, body)
        result = {
            "schema": SCHEMA,
            "status": "SQL_EMITTED_NOT_EXECUTED",
            "policy_sha256": policy_sha,
            "sql_sha256": query_sha,
            "sql_bytes": len(body),
            "statement_count": 1,
            "read_only": True,
            "no_provider_access": True,
            "source_binding_independently_verified": False,
            "database_state_observed": False,
            "production_authorized": False,
            "rendered_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ProbeHold, InputError, OSError) as error:
        code = str(error) if isinstance(error, (ProbeHold, InputError)) else "OUTPUT_IO_UNAVAILABLE"
        print(
            json.dumps({"schema": SCHEMA, "status": "HOLD", "reason": code, "production_authorized": False}),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
