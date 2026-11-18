# SPDX-License-Identifier: Apache-2.0
"""Offline adversarial tests for scoped DB catalog truth; never connect to DB."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest

# Isolated Python (-I) intentionally omits cwd; resolve the reviewed checkout.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.database_catalog_admission import (
    CATALOG_SCHEMA,
    InputError,
    POLICY_SCHEMA,
    RESULT_SCHEMA,
    assess,
    main,
    policy_data,
    strict_bytes,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads(
    (ROOT / "governance/database_contracts/memory_covenant_v2.json").read_text(
        encoding="utf-8"
    )
)
AT = datetime(2026, 11, 18, 0, 0, 0, tzinfo=timezone.utc)


def catalog():
    return {
        "schema": CATALOG_SCHEMA,
        "observed_at": (AT - timedelta(minutes=1)).isoformat(),
        "state": "OBSERVED",
        "scope": "NEON_VALIDATION_READ_ONLY",
        "source_binding": deepcopy(POLICY["source_binding"]),
        "tables": [
            {
                "name": t["name"],
                "rls_enabled": t["rls_enabled"],
                "rls_forced": t["rls_forced"],
                "policy_count": t["min_policies"],
                "public_grants": 0,
                "invalid_indexes": 0,
            }
            for t in POLICY["required_tables"]
        ],
        "functions": [
            {
                "name": t["name"],
                "security_definer": True,
                "binds_principal": True,
                "references_context_bindings": True,
            }
            for t in POLICY["required_functions"]
        ],
        "credentials_recorded": False,
    }


def evaluate(c):
    return assess(deepcopy(POLICY), c, at=AT)


def codes(result):
    return set(row["code"] for row in result["gaps"])


class CatalogAdmissionTests(unittest.TestCase):
    def test_policy_self_admits_as_source_contract_only(self):
        self.assertIs(policy_data(deepcopy(POLICY)) is not None, True)
        self.assertEqual(POLICY["schema"], POLICY_SCHEMA)
        self.assertEqual(len(POLICY["required_tables"]), 8)

    def test_perfect_catalog_still_never_grants_production(self):
        good = evaluate(catalog())
        self.assertEqual(good["schema"], RESULT_SCHEMA)
        self.assertEqual(good["state"], "CATALOG_MATCH_ONLY")
        self.assertEqual(good["gap_count"], 0)
        self.assertEqual(good["required_tables"], 8)
        for key in ("production_authorized", "migration_authorized",
                    "independent_witness", "database_queried_by_this_verifier",
                    "source_identity_independently_verified", "external_writes_performed"):
            self.assertIs(good[key], False, key)

    def test_reordered_catalog_does_not_fail(self):
        c = catalog()
        c["tables"].reverse()
        self.assertEqual(evaluate(c)["gap_count"], 0)

    def test_missing_principal_binding_table_fails(self):
        c = catalog()
        c["tables"] = [x for x in c["tables"]
                       if x["name"] != "public.memory_context_bindings"]
        result = evaluate(c)
        self.assertEqual(result["state"], "HOLD")
        self.assertIn("TABLE_NOT_OBSERVED", codes(result))
        self.assertIs(result["production_authorized"], False)

    def test_legacy_mutable_context_function_fails(self):
        c = catalog()
        c["functions"][0].update({
            "security_definer": False,
            "binds_principal": False,
            "references_context_bindings": False,
        })
        result = evaluate(c)
        self.assertTrue({
            "SECURITY_DEFINER_DRIFT",
            "PRINCIPAL_BINDING_UNOBSERVED",
            "CONTEXT_BINDING_UNOBSERVED",
        }.issubset(codes(result)))

    def test_dedicated_worker_outbox_no_force_is_intentional(self):
        c = catalog()
        outbox = next(row for row in c["tables"]
                      if row["name"] == "public.memory_outbox")
        self.assertIs(outbox["rls_forced"], False)
        self.assertEqual(evaluate(c)["gap_count"], 0)
        outbox["rls_forced"] = True
        self.assertIn("RLS_FORCE_STATE_DRIFT", codes(evaluate(c)))

    def test_missing_force_rls_on_ordinary_table_refuses(self):
        c = catalog()
        next(x for x in c["tables"] if x["name"] == "public.memory_records")[
            "rls_forced"] = False
        self.assertIn("RLS_FORCE_STATE_DRIFT", codes(evaluate(c)))

    def test_missing_rls_and_policy_are_separate_failures(self):
        c = catalog()
        table = next(x for x in c["tables"]
                     if x["name"] == "public.memory_records")
        table["rls_enabled"] = False
        table["policy_count"] = 0
        self.assertTrue({"RLS_STATE_DRIFT", "POLICY_COVERAGE_DRIFT"}
                        .issubset(codes(evaluate(c))))

    def test_public_permissions_never_pass_as_rls(self):
        c = catalog()
        c["tables"][0]["public_grants"] = 1
        self.assertIn("PUBLIC_TABLE_GRANTS", codes(evaluate(c)))

    def test_invalid_index_refuses(self):
        c = catalog()
        c["tables"][0]["invalid_indexes"] = 1
        self.assertIn("INVALID_INDEX", codes(evaluate(c)))

    def test_missing_routine_refuses(self):
        c = catalog()
        c["functions"] = []
        self.assertIn("FUNCTION_NOT_OBSERVED", codes(evaluate(c)))

    def test_stale_readback_refuses(self):
        c = catalog()
        c["observed_at"] = (AT - timedelta(days=2)).isoformat()
        self.assertIn("CATALOG_STALE", codes(evaluate(c)))

    def test_future_readback_refuses(self):
        c = catalog()
        c["observed_at"] = (AT + timedelta(hours=2)).isoformat()
        self.assertIn("CATALOG_IN_FUTURE", codes(evaluate(c)))

    def test_fake_source_binding_is_declared_not_authentication(self):
        c = catalog()
        c["source_binding"]["git_blob_sha1"] = "f" * 40
        result = evaluate(c)
        self.assertIn("SOURCE_CLAIM_DIFFERS", codes(result))
        self.assertIs(result["source_identity_independently_verified"], False)

    def test_duplicate_catalog_table_refused(self):
        c = catalog()
        c["tables"].append(deepcopy(c["tables"][0]))
        with self.assertRaisesRegex(InputError, "DUPLICATE_CATALOG_OBJECT"):
            evaluate(c)

    def test_duplicate_policy_table_refused(self):
        p = deepcopy(POLICY)
        p["required_tables"].append(deepcopy(p["required_tables"][0]))
        with self.assertRaisesRegex(InputError, "DUPLICATE_POLICY_OBJECT"):
            policy_data(p)

    def test_count_bool_string_or_negative_refused(self):
        for value in (True, False, -1, -3.5, None, "1.0", "+1", "01", "1e5"):
            c = catalog()
            c["tables"][0]["public_grants"] = value
            with self.subTest(value=value), self.assertRaisesRegex(InputError, "INVALID_COUNT"):
                evaluate(c)

    def test_missing_data_or_extra_sensitive_field_refused(self):
        for extra in ({"private_key": "synthetic-canary"},
                      {"db_password": "synthetic-canary"}):
            c = catalog()
            c.update(extra)
            with self.assertRaisesRegex(InputError, "INVALID_FIELDS"):
                evaluate(c)

    def test_recorded_credentials_refused(self):
        c = catalog()
        c["credentials_recorded"] = True
        with self.assertRaisesRegex(InputError, "CREDENTIAL_FIELD_DISALLOWED"):
            evaluate(c)

    def test_no_provider_observation_does_not_relabel_empty_database(self):
        c = catalog()
        c["state"] = "UNAVAILABLE"
        with self.assertRaisesRegex(InputError, "CATALOG_NOT_OBSERVED"):
            evaluate(c)

    def test_invalid_scope_refused(self):
        c = catalog()
        c["scope"] = "PUBLIC_ANONYMOUS_UNVERIFIED"
        with self.assertRaisesRegex(InputError, "INVALID_CATALOG_SCOPE"):
            evaluate(c)

    def test_duplicate_json_keys_refused(self):
        data = b'{"schema":"good","schema":"bad"}'
        with self.assertRaisesRegex(InputError, "DUPLICATE_JSON_KEY"):
            strict_bytes(data, max_bytes=256)

    def test_nonfinite_json_refused(self):
        with self.assertRaisesRegex(InputError, "NONFINITE_JSON_VALUE"):
            strict_bytes(b'{"score":NaN}', max_bytes=256)

    def test_invalid_json_and_size_refused(self):
        for data in (b"", b"{}", b"{" + b" " * 300):
            if data == b"{}":
                continue
            with self.assertRaises(InputError):
                strict_bytes(data, max_bytes=128)

    def test_malformed_timestamp_refused(self):
        c = catalog()
        c["observed_at"] = "2026-11-18T00:00:00"
        with self.assertRaisesRegex(InputError, "INVALID_OBSERVATION_TIME"):
            evaluate(c)

    def test_source_binding_noncanonical_refused(self):
        c = catalog()
        c["source_binding"]["path"] = "../../source/secrets"
        with self.assertRaisesRegex(InputError, "INVALID_SOURCE_BINDING"):
            evaluate(c)

    def test_cli_writes_new_receipt_only_and_fail_closed_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            policy_path = parent / "policy.json"
            catalog_path = parent / "readback.json"
            out = parent / "receipt.json"
            policy_path.write_text(json.dumps(POLICY), encoding="utf-8")
            c = catalog()
            c["observed_at"] = datetime.now(timezone.utc).isoformat()
            catalog_path.write_text(json.dumps(c), encoding="utf-8")
            self.assertEqual(main(["--policy", str(policy_path),
                                   "--catalog", str(catalog_path),
                                   "--output", str(out)]), 0)
            self.assertTrue(out.is_file())
            result = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(result["state"], "CATALOG_MATCH_ONLY")
            self.assertFalse(result["production_authorized"])
            with self.assertRaises(FileExistsError):
                main(["--policy", str(policy_path), "--catalog", str(catalog_path),
                      "--output", str(out)])

    def test_cli_live_like_drift_is_exit_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            policy_path = parent / "policy.json"
            catalog_path = parent / "readback.json"
            policy_path.write_text(json.dumps(POLICY), encoding="utf-8")
            c = catalog()
            c["observed_at"] = datetime.now(timezone.utc).isoformat()
            c["tables"].pop()
            catalog_path.write_text(json.dumps(c), encoding="utf-8")
            self.assertEqual(main(["--policy", str(policy_path),
                                   "--catalog", str(catalog_path)]), 2)


if __name__ == "__main__":
    unittest.main()
