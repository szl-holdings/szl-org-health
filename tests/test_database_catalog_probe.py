"""Credential-free, offline adversarial tests for Postgres catalog SELECT emitter."""

import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import database_catalog_probe as probe
from tools.database_catalog_admission import policy_data, InputError


POLICY_FILE = Path(__file__).resolve().parents[1] / "governance" / "database_contracts" / "memory_covenant_v2.json"


def real_policy():
    result = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
    policy_data(result)
    return result


class SQLSourceContracts(unittest.TestCase):
    def test_source_controlled_policy_is_valid(self):
        policy = real_policy()
        self.assertEqual(policy["schema"], "szl.database-catalog-policy/v1")
        self.assertEqual(len(policy["required_tables"]), 8)
        self.assertEqual(len(policy["required_functions"]), 1)
        self.assertTrue(policy["source_binding"]["git_blob_sha1"])

    def test_sanitized_single_select_is_read_only(self):
        sql = probe.build_select(real_policy(), scope="NEON_VALIDATION_READ_ONLY")
        self.assertTrue(sql.startswith("WITH"))
        self.assertIn("SELECT pg_catalog.jsonb_build_object(", sql)
        self.assertIn("FROM pg_catalog.pg_policy", sql)
        self.assertIn("FROM pg_catalog.pg_index", sql)
        self.assertIn("FROM pg_catalog.aclexplode(", sql)
        self.assertIn("FROM observed_tables", sql)
        self.assertIn("FROM observed_functions", sql)
        self.assertIn("public_grants", sql)
        self.assertIn("security_definer", sql)
        self.assertIn("binds_principal", sql)
        self.assertIn("schema", sql)
        self.assertIn("'credentials_recorded', FALSE", sql)
        self.assertIn("'scope', 'NEON_VALIDATION_READ_ONLY'", sql)
        self.assertLess(len(sql.encode()), probe.MAX_SQL_BYTES)
        self.assertEqual(sql.count(";"), 0)
        # No remote data rows or user tables are queried by the tool output.
        self.assertNotIn("SELECT * FROM public.", sql)
        self.assertNotIn("COPY ", sql.upper())
        self.assertNotIn("INSERT INTO", sql.upper())
        self.assertNotIn("ALTER TABLE", sql.upper())
        self.assertNotIn("DELETE FROM", sql.upper())
        self.assertNotIn("CREATE TABLE", sql.upper())
        self.assertNotIn("DROP POLICY", sql.upper())

    def test_all_eight_required_tables_emitted(self):
        policy = real_policy()
        sql = probe.build_select(policy, scope="NEON_VALIDATION_READ_ONLY")
        for row in policy["required_tables"]:
            schema, table = row["name"].split(".", 1)
            self.assertEqual(sql.count("('" + schema + "', '" + table + "')"), 1)
        self.assertIn("('public', 'a11oy_memory_context_matches')", sql)

    def test_source_binding_is_declared_not_db_attested(self):
        policy = real_policy()
        sql = probe.build_select(policy, scope="NEON_VALIDATION_READ_ONLY")
        self.assertIn(policy["source_binding"]["git_blob_sha1"], sql)
        # The query explicitly returns only the input policy's claimed source
        # and cannot establish whether the target DB ran that migration.
        self.assertNotIn("pg_catalog.pg_available_extensions", sql)
        self.assertIn("pg_catalog.pg_get_functiondef(p.oid)", sql)
        self.assertIn("p.prosecdef", sql)

    def test_malicious_literal_cannot_escape_into_sql(self):
        self.assertEqual(probe.sql_literal("a' OR '1'='1"), "'a'' OR ''1''=''1'")
        with self.assertRaisesRegex(probe.ProbeHold, "INVALID_SQL_LITERAL"):
            probe.sql_literal("a\x00b")
        with self.assertRaisesRegex(probe.ProbeHold, "INVALID_SQL_LITERAL"):
            probe.sql_literal("x" * 2049)

    def test_unapproved_scope_stops(self):
        with self.assertRaisesRegex(probe.ProbeHold, "INVALID_PROBE_SCOPE"):
            probe.build_select(real_policy(), scope="PRODUCTION_WRITE")
        with self.assertRaisesRegex(probe.ProbeHold, "INVALID_PROBE_SCOPE"):
            probe.build_select(real_policy(), scope="NEON_VALIDATION_READ_ONLY; DROP")

    def test_policy_with_non_memory_function_is_not_misclassified(self):
        policy = real_policy()
        policy["required_functions"][0]["name"] = "public.other_helper"
        policy_data(policy)
        with self.assertRaisesRegex(probe.ProbeHold, "UNSUPPORTED_FUNCTION_CONTRACT"):
            probe.build_select(policy, scope="NEON_VALIDATION_READ_ONLY")

    def test_schema_identifiers_validated(self):
        for value in ("public.memory_context_bindings", "some_schema.some_table"):
            self.assertEqual(len(probe.qualified_name(value)), 2)
        for value in ("public.x;DROP TABLE", "public...x", "../../foo", "public.x-", "", "A.x"):
            with self.subTest(value=value):
                with self.assertRaises(probe.ProbeHold):
                    probe.qualified_name(value)

    def test_untrusted_policy_cannot_enable_sql_injection(self):
        policy = real_policy()
        policy["required_tables"][0]["name"] = "public.x'); DROP TABLE y; --"
        with self.assertRaises(InputError):
            probe.build_select(policy, scope="NEON_VALIDATION_READ_ONLY")

    def test_copy_on_write_output_requires_unique_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.sql"
            sql = probe.build_select(real_policy(), scope="NEON_VALIDATION_READ_ONLY")
            raw = sql.encode()
            value = probe.emit_file(path, raw)
            self.assertEqual(value, hashlib.sha256(raw).hexdigest())
            self.assertEqual(path.read_bytes(), raw)
            with self.assertRaisesRegex(probe.ProbeHold, "OUTPUT_ALREADY_EXISTS"):
                probe.emit_file(path, b"ALTER")
            self.assertEqual(path.read_bytes(), raw)

    def test_rendered_source_does_not_access_socket_or_provider(self):
        with patch("socket.socket") as patched:
            probe.build_select(real_policy(), scope="NEON_VALIDATION_READ_ONLY")
        patched.assert_not_called()

    def test_cli_writes_one_sql_file_and_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "catalog.sql"
            with patch("sys.stdout", new_callable=io.StringIO) as stream:
                code = probe.main(
                    [
                        "--policy",
                        str(POLICY_FILE),
                        "--scope",
                        "NEON_VALIDATION_READ_ONLY",
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(code, 0)
            receipt = json.loads(stream.getvalue())
            self.assertEqual(receipt["status"], "SQL_EMITTED_NOT_EXECUTED")
            self.assertFalse(receipt["database_state_observed"])
            self.assertFalse(receipt["production_authorized"])
            self.assertFalse(receipt["source_binding_independently_verified"])
            self.assertEqual(receipt["sql_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
            with patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(
                    probe.main(
                        [
                            "--policy",
                            str(POLICY_FILE),
                            "--scope",
                            "NEON_VALIDATION_READ_ONLY",
                            "--output",
                            str(output),
                        ]
                    ),
                    2,
                )

    def test_synthetic_provider_response_flows_to_existing_admission(self):
        # The source emitter's expected JSON shape is consumed by the existing
        # verifier. The deliberately absent eighth table is an actual HOLD;
        # the fixture is synthetic, not a Neon provider assertion.
        from datetime import datetime, timezone

        from tools.database_catalog_admission import assess

        policy = real_policy()
        when = datetime(2026, 11, 18, 1, 0, tzinfo=timezone.utc)
        table_rows = [
            {
                "name": item["name"],
                "rls_enabled": item["rls_enabled"],
                "rls_forced": item["rls_forced"],
                "policy_count": item["min_policies"],
                "public_grants": 0,
                "invalid_indexes": 0,
            }
            for item in policy["required_tables"]
            if item["name"] != "public.memory_context_bindings"
        ]
        catalog = {
            "schema": "szl.database-catalog-readback/v1",
            "observed_at": when.isoformat(),
            "state": "OBSERVED",
            "scope": "NEON_VALIDATION_READ_ONLY",
            "source_binding": policy["source_binding"],
            "tables": table_rows,
            "functions": [
                {
                    "name": "public.a11oy_memory_context_matches",
                    "security_definer": False,
                    "binds_principal": False,
                    "references_context_bindings": False,
                }
            ],
            "credentials_recorded": False,
        }
        out = assess(policy, catalog, at=when)
        self.assertEqual(out["state"], "HOLD")
        self.assertEqual(out["gap_count"], 4)
        self.assertEqual(
            {item["code"] for item in out["gaps"]},
            {
                "TABLE_NOT_OBSERVED",
                "SECURITY_DEFINER_DRIFT",
                "PRINCIPAL_BINDING_UNOBSERVED",
                "CONTEXT_BINDING_UNOBSERVED",
            },
        )
        self.assertTrue(out["reported_source_blob_matches"])
        self.assertFalse(out["source_identity_independently_verified"])
        self.assertFalse(out["production_authorized"])
        # A synthetic all-matching catalog still does not authorize rollout.
        catalog["tables"].append(
            {
                "name": "public.memory_context_bindings",
                "rls_enabled": True,
                "rls_forced": False,
                "policy_count": 0,
                "public_grants": 0,
                "invalid_indexes": 0,
            }
        )
        for field in (
            "security_definer",
            "binds_principal",
            "references_context_bindings",
        ):
            catalog["functions"][0][field] = True
        green = assess(policy, catalog, at=when)
        self.assertEqual(green["state"], "CATALOG_MATCH_ONLY")
        self.assertEqual(green["gap_count"], 0)
        self.assertFalse(green["production_authorized"])
        self.assertFalse(green["source_identity_independently_verified"])
        self.assertFalse(green["database_queried_by_this_verifier"])

    def test_oversized_source_policy_rejected(self):
        with self.assertRaisesRegex(probe.ProbeHold, "INVALID_SQL_LITERAL"):
            probe.sql_literal("a" * 2049)

    def test_unrecognized_missing_contract_is_rejected(self):
        policy = real_policy()
        policy.pop("required_tables")
        with self.assertRaises(InputError):
            probe.build_select(policy, scope="NEON_VALIDATION_READ_ONLY")


if __name__ == "__main__":
    unittest.main()
