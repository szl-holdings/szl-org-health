# SPDX-License-Identifier: Apache-2.0
"""Fake-provider and security regression tests. No real DB or credentials."""
# ruff: noqa: E402
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
from unittest import TestCase, main as unittest_main, mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.postgres_catalog_observer import (
    FUNCTION_SQL, ObservationBlocked, TABLE_SQL, TX_SQL,
    _function_flags, collect, main, sanitize_rows, validate_dsn,
)

POLICY = json.loads((ROOT / "governance/database_contracts/memory_covenant_v2.json").read_text())
VALID_URI = "postgresql://auditor:not-a-real-password@ep-test.us-west-2.aws.neon.tech/neondb?sslmode=verify-full"


def tables():
    return [
        {
            "schema_name": "public",
            "table_name": name["name"].split(".")[1],
            "rls_enabled": name["rls_enabled"],
            "rls_forced": name["rls_forced"],
            "policy_count": name["min_policies"],
            "public_grants": 0,
            "invalid_indexes": 0,
        }
        for name in POLICY["required_tables"]
    ]


def routines():
    return [{
        "schema_name": "public",
        "function_name": "a11oy_memory_context_matches",
        "security_definer": True,
        "definition": """CREATE OR REPLACE FUNCTION public.a11oy_memory_context_matches(
row_tenant text,row_domain text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER AS $$
SELECT row_tenant=current_setting('a11oy.tenant_id',true)
  AND row_domain=current_setting('a11oy.security_domain',true)
  AND EXISTS(SELECT 1 FROM public.memory_context_bindings AS binding
 WHERE binding.principal_oid=(SELECT role.oid FROM pg_catalog.pg_roles AS role
                             WHERE role.rolname=session_user))
$$;""",
    }]


class FakeDescription:
    def __init__(self, name):
        self.name = name


class FakeCursor:
    def __init__(self, response, seen):
        self.response = response
        self.seen = seen
        self.description = None
        self.data = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql):
        self.seen.append(sql)
        if sql not in (TX_SQL, TABLE_SQL, FUNCTION_SQL):
            raise AssertionError("UNEXPECTED_STATEMENT")
        rows = self.response[sql]
        columns = list(rows[0]) if rows else {
            TX_SQL: ["read_only", "is_superuser", "bypass_rls"],
            TABLE_SQL: list(tables()[0]),
            FUNCTION_SQL: list(routines()[0]),
        }[sql]
        self.description = [FakeDescription(k) for k in columns]
        self.data = [tuple(row.values()) for row in rows]

    def fetchmany(self, size):
        return self.data[:size]


class FakeConnection:
    def __init__(self, responses=None):
        self.statements = []
        self.responses = responses or {
            TX_SQL: [{"read_only": "on", "is_superuser": False, "bypass_rls": False}],
            TABLE_SQL: tables(),
            FUNCTION_SQL: routines(),
        }

    def cursor(self):
        return FakeCursor(self.responses, self.statements)


class PostgresObserverTests(TestCase):
    def test_sanitizer_matches_source_contract_not_authority(self):
        result = sanitize_rows(tables(), routines(), POLICY, "NEON_VALIDATION_READ_ONLY",
                               observed_at=datetime.now(timezone.utc).isoformat())
        self.assertEqual(result["schema"], "szl.database-catalog-readback/v1")
        self.assertEqual(len(result["tables"]), 8)
        self.assertEqual(len(result["functions"]), 1)
        self.assertEqual(result["source_binding"], POLICY["source_binding"])
        self.assertFalse(result["credentials_recorded"])
        self.assertNotIn("definition", result["functions"][0])

    def test_live_like_readback_missing_bindings_emits_hold_not_fake_green(self):
        from tools.database_catalog_admission import assess
        collection = sanitize_rows(tables()[:-1], routines(), POLICY,
                                   "NEON_VALIDATION_READ_ONLY")
        result = assess(POLICY, collection)
        self.assertEqual(result["state"], "HOLD")
        self.assertIn("TABLE_NOT_OBSERVED", {x["code"] for x in result["gaps"]})
        self.assertFalse(result["production_authorized"])

    def test_read_only_transaction_and_exact_queries(self):
        con = FakeConnection()
        out = collect(con, POLICY, "NEON_VALIDATION_READ_ONLY")
        self.assertEqual(len(out["tables"]), 8)
        self.assertEqual(con.statements, [TX_SQL, TABLE_SQL, FUNCTION_SQL])
        self.assertTrue(all(stmt.lstrip().lower().startswith("select ")
                            for stmt in con.statements))

    def test_non_readonly_transaction_aborts_before_catalog(self):
        con = FakeConnection()
        con.responses[TX_SQL] = [{"read_only": "off", "is_superuser": False, "bypass_rls": False}]
        with self.assertRaisesRegex(ObservationBlocked, "READ_ONLY_LEAST_PRIVILEGE_REQUIRED"):
            collect(con, POLICY, "NEON_VALIDATION_READ_ONLY")
        self.assertEqual(con.statements, [TX_SQL])

    def test_superuser_or_bypass_rls_auditor_refused(self):
        for privilege in ("is_superuser", "bypass_rls"):
            con = FakeConnection()
            con.responses[TX_SQL][0][privilege] = True
            with self.subTest(privilege=privilege), self.assertRaisesRegex(
                    ObservationBlocked, "READ_ONLY_LEAST_PRIVILEGE_REQUIRED"):
                collect(con, POLICY, "NEON_VALIDATION_READ_ONLY")
            self.assertEqual(con.statements, [TX_SQL])

    def test_output_inside_checkout_refused(self):
        from tools.postgres_catalog_observer import _save_exclusive
        output = ROOT / "tools" / "must-never-write-private-metadata.json"
        self.assertFalse(output.exists())
        with self.assertRaisesRegex(ObservationBlocked, "SOURCE_CHECKOUT_OUTPUT_DENIED"):
            _save_exclusive(output, {"schema": "synthetic"})
        self.assertFalse(output.exists())

    def test_extra_query_result_cannot_get_truncated_as_complete(self):
        con = FakeConnection()
        con.responses[TABLE_SQL] = tables() * 26
        with self.assertRaisesRegex(ObservationBlocked, "CATALOG_PAGE_LIMIT"):
            collect(con, POLICY, "NEON_VALIDATION_READ_ONLY")

    def test_false_function_body_does_not_get_promoted(self):
        fn = routines()
        fn[0]["definition"] = "SELECT TRUE; -- session_user FROM public.memory_context_bindings binding.principal_oid"
        out = sanitize_rows(tables(), fn, POLICY, "NEON_VALIDATION_READ_ONLY")
        self.assertEqual(out["functions"][0]["binds_principal"], False)
        self.assertEqual(out["functions"][0]["references_context_bindings"], False)

    def test_real_source_structural_function_shape_is_provisional(self):
        principal, binding = _function_flags(routines()[0]["definition"])
        self.assertTrue(principal)
        self.assertTrue(binding)
        self.assertNotIn("production_authorized", routines()[0])

    def test_security_definer_false_is_not_relabelled_true(self):
        from tools.database_catalog_admission import assess
        fn = routines()
        fn[0]["security_definer"] = False
        out = sanitize_rows(tables(), fn, POLICY, "NEON_VALIDATION_READ_ONLY")
        self.assertIn("SECURITY_DEFINER_DRIFT",
                      {x["code"] for x in assess(POLICY, out)["gaps"]})

    def test_zero_tables_cannot_appear_complete(self):
        from tools.database_catalog_admission import assess
        data = sanitize_rows([], routines(), POLICY, "NEON_VALIDATION_READ_ONLY")
        out = assess(POLICY, data)
        self.assertEqual(out["required_tables"], 8)
        self.assertEqual(out["observed_tables"], 0)
        self.assertEqual(out["state"], "HOLD")

    def test_validated_neon_tls_uri_parses_but_is_not_used(self):
        validate_dsn(VALID_URI, "NEON_VALIDATION_READ_ONLY")

    def test_host_injection_and_tls_downgrade_refused(self):
        bad = (
            VALID_URI.replace("verify-full", "require"),
            VALID_URI.replace("verify-full", "disable"),
            VALID_URI.replace("verify-full", "verify-full&hostaddr=1.2.3.4"),
            VALID_URI.replace("verify-full", "verify-full&service=alternate"),
            VALID_URI.replace("verify-full", "verify-full&options=-c"),
            VALID_URI.replace("neon.tech", "example.com"),
            VALID_URI.replace("/neondb?", ":1234/neondb?"),
            "host=example.com password=synthetic dbname=postgres",
            "postgresql:///dbname?sslmode=verify-full",
            VALID_URI.replace("postgresql:", "file:"),
            VALID_URI.replace("?sslmode", "#bad?sslmode"),
            VALID_URI.replace("not-a-real-password@", "@"),
            VALID_URI.replace("neondb?", "?"),
            VALID_URI + "\n",
            "",
            None,
        )
        for dsn in bad:
            with self.subTest(dsn_kind=str(dsn)[:18]), self.assertRaises(ObservationBlocked):
                validate_dsn(dsn, "NEON_VALIDATION_READ_ONLY")

    def test_valid_non_neon_rejects_invalid_scope(self):
        with self.assertRaisesRegex(ObservationBlocked, "SCOPE_UNSUPPORTED"):
            validate_dsn(VALID_URI, "SOME_NEW_SCOPE")

    def test_wrong_password_or_provider_errors_never_echo_dsn(self):
        # A fake driver connector that fails with a full secret-bearing URL
        # is intercepted and converted into a fixed code.
        import types
        from tools.postgres_catalog_observer import _connect_and_collect
        fake = types.SimpleNamespace(connect=mock.Mock(side_effect=RuntimeError(VALID_URI)))
        with mock.patch.dict(sys.modules, {"psycopg": fake}):
            with self.assertRaisesRegex(ObservationBlocked, "^PROVIDER_READ_UNAVAILABLE$") as e:
                _connect_and_collect(VALID_URI, "NEON_VALIDATION_READ_ONLY", POLICY)
        self.assertNotIn("not-a-real-password", str(e.exception))

    def test_wrong_table_name_type_refused(self):
        raw = tables()
        raw[0]["table_name"] = "records;DROP TABLE"
        with self.assertRaisesRegex(ObservationBlocked, "CATALOG_ROW_INVALID"):
            sanitize_rows(raw, routines(), POLICY, "NEON_VALIDATION_READ_ONLY")

    def test_fabricated_count_bool_refused(self):
        raw = tables()
        raw[0]["policy_count"] = True
        with self.assertRaisesRegex(ObservationBlocked, "CATALOG_COUNT_INVALID"):
            sanitize_rows(raw, routines(), POLICY, "NEON_VALIDATION_READ_ONLY")

    def test_rogue_function_refused(self):
        fn = routines()
        fn[0]["function_name"] = "do_not_touch"
        with self.assertRaisesRegex(ObservationBlocked, "FUNCTION_ROW_INVALID"):
            sanitize_rows(tables(), fn, POLICY, "NEON_VALIDATION_READ_ONLY")

    def test_raw_extra_secret_fields_refused(self):
        raw = routines()
        raw[0]["private_token"] = "synthetic"
        with self.assertRaisesRegex(ObservationBlocked, "FUNCTION_ROW_INVALID"):
            sanitize_rows(tables(), raw, POLICY, "NEON_VALIDATION_READ_ONLY")

    def test_output_is_exclusive_and_no_overwrite(self):
        from tools.postgres_catalog_observer import _save_exclusive
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "receipt.json"
            _save_exclusive(path, {"schema": "synthetic"})
            self.assertTrue(path.exists())
            with self.assertRaisesRegex(ObservationBlocked, "OUTPUT_EXISTS"):
                _save_exclusive(path, {"schema": "changed"})

    def test_no_dsn_cli_remains_unavailable_without_auth(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            result_path = p / "catalog.json"
            status_path = p / "admission.json"
            with mock.patch.dict("os.environ", {}, clear=True):
                code = main([
                    "--policy", str(ROOT / "governance/database_contracts/memory_covenant_v2.json"),
                    "--scope", "NEON_VALIDATION_READ_ONLY",
                    "--catalog-output", str(result_path),
                    "--admission-output", str(status_path),
                ])
            self.assertEqual(code, 3)
            self.assertFalse(result_path.exists())
            self.assertFalse(status_path.exists())

    def test_cannot_save_same_path_twice(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "one.json"
            with mock.patch.dict("os.environ", {}, clear=True):
                code = main([
                    "--policy", str(ROOT / "governance/database_contracts/memory_covenant_v2.json"),
                    "--scope", "NEON_VALIDATION_READ_ONLY",
                    "--catalog-output", str(p),
                    "--admission-output", str(p),
                ])
            self.assertEqual(code, 3)
            self.assertFalse(p.exists())


if __name__ == "__main__":
    unittest_main()
