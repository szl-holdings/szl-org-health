# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for the fixed, non-authorizing causal evidence frontier."""
from copy import deepcopy
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.causal_evidence_frontier import (
    CLASSIFICATION,
    GATE_PLANES,
    RESULT_SCHEMA,
    SCHEMA,
    TOPOLOGY,
    FrontierInputError,
    analyze,
    main,
    strict_json,
    validate_topology,
)

AT = datetime(2026, 11, 19, 0, 0, tzinfo=timezone.utc)
SOURCE_SHA = "af765edc49122cf84311b0f8e48ec080dfee3e47"
TREE_SHA = "a" * 64
CONTENT_SHA = "b" * 64


def observation():
    gates = []
    for gate_id in TOPOLOGY:
        gates.append({
            "id": gate_id,
            "plane": GATE_PLANES[gate_id],
            "state": "VERIFIED_CLAIM",
            "observed_at": AT.isoformat().replace("+00:00", "Z"),
            "source_sha40": SOURCE_SHA,
            "content_sha256": CONTENT_SHA,
            "identity_matches": True if gate_id in {"SOURCE", "HF_IDENTITY", "SIGNER", "CUSTODY"} else None,
            "readback": ("PROVIDER_AUTHENTICATED_CLAIM" if gate_id in {"RUNTIME", "INFERENCE"}
                         else "SOURCE_CLAIM"),
            "coverage_numerator": 1,
            "coverage_denominator": 1,
        })
    return {
        "schema": SCHEMA,
        "observed_at": AT.isoformat().replace("+00:00", "Z"),
        "evaluated_at": AT.isoformat().replace("+00:00", "Z"),
        "max_age_seconds": 3600,
        "source": {
            "repository": "szl-holdings/szl-org-health",
            "commit_sha40": SOURCE_SHA,
            "tree_sha256": TREE_SHA,
        },
        "gates": gates,
        "credentials_recorded": False,
    }


def gate(value, gate_id):
    return next(row for row in value["gates"] if row["id"] == gate_id)


def target(result, name):
    return next(row for row in result["targets"] if row["target"] == name)


class CausalEvidenceFrontierTests(unittest.TestCase):
    def assert_refused(self, value, code):
        with self.assertRaisesRegex(FrontierInputError, code):
            analyze(value)

    def test_all_claims_green_still_have_zero_authority(self):
        result = analyze(observation())
        self.assertEqual(result["schema"], RESULT_SCHEMA)
        self.assertEqual(result["classification"], CLASSIFICATION)
        self.assertEqual(result["state"], "CLAIMS_COMPLETE_NO_AUTHORITY")
        self.assertEqual(len(result["targets"]), 4)
        self.assertTrue(all(not row["first_blockers"] for row in result["targets"]))
        for name in ("production_authorized", "effects_authorized",
                     "independent_signature_verified", "provider_readback_independently_verified",
                     "network_access_performed", "external_effects_performed"):
            self.assertIs(result[name], False, name)

    def test_http_200_runtime_cannot_substitute_for_unavailable_inference(self):
        value = observation()
        gate(value, "RUNTIME")["state"] = "VERIFIED_CLAIM"
        gate(value, "INFERENCE")["state"] = "UNAVAILABLE"
        result = analyze(value)
        self.assertEqual(target(result, "model_inference")["first_blockers"], ["INFERENCE"])
        self.assertEqual(target(result, "served")["first_blockers"], [])
        self.assertEqual(target(result, "served")["state"], "ALL_PREREQUISITES_CLAIMED_VERIFIED")
        self.assertEqual(result["state"], "HOLD")

    def test_multiple_independent_first_roots_are_all_reported(self):
        value = observation()
        gate(value, "MODEL")["state"] = "HOLD"
        gate(value, "SIGNER")["state"] = "INVALID"
        result = analyze(value)
        self.assertEqual(target(result, "receipt_proof")["first_blockers"], ["MODEL", "SIGNER"])
        self.assertEqual(target(result, "money_settled")["first_blockers"], ["MODEL", "SIGNER"])
        self.assertEqual(target(result, "served")["first_blockers"], [])

    def test_earliest_failed_ancestor_precedes_descendant_failure(self):
        value = observation()
        gate(value, "SIGNER")["state"] = "HOLD"
        gate(value, "CUSTODY")["state"] = "UNAVAILABLE"
        result = analyze(value)
        self.assertEqual(target(result, "receipt_proof")["first_blockers"], ["SIGNER"])
        self.assertNotIn("CUSTODY", target(result, "receipt_proof")["first_blockers"])
        # Downstream failure stays visible even though it is not the first cut.
        custody = next(row for row in result["gate_assessments"]
                       if row["gate_id"] == "CUSTODY")
        self.assertIn("REPORTED_UNAVAILABLE", custody["local_reasons"])

    def test_source_failure_precedes_stale_downstream_http_success(self):
        value = observation()
        gate(value, "SOURCE")["state"] = "HOLD"
        gate(value, "INFERENCE")["state"] = "UNAVAILABLE"
        gate(value, "SERVING")["state"] = "UNAVAILABLE"
        result = analyze(value)
        self.assertEqual(target(result, "served")["first_blockers"], ["SOURCE"])
        self.assertEqual(target(result, "model_inference")["first_blockers"], ["SOURCE"])
        self.assertTrue(any(row["gate_id"] == "INFERENCE" and
                            "REPORTED_UNAVAILABLE" in row["local_reasons"]
                            for row in result["gate_assessments"]))

    def test_failed_ancestor_never_leaves_descendant_healthy(self):
        value = observation()
        gate(value, "SOURCE")["state"] = "HOLD"
        result = analyze(value)
        serving = next(row for row in result["gate_assessments"] if row["gate_id"] == "SERVING")
        self.assertEqual(serving["reported_state"], "VERIFIED_CLAIM")
        self.assertEqual(serving["effective_state"], "BLOCKED_BY_ANCESTOR")

    def test_source_mismatch_is_local_first_blocker(self):
        value = observation()
        gate(value, "HF_IDENTITY")["source_sha40"] = "f" * 40
        result = analyze(value)
        row = target(result, "model_inference")["blocker_details"][0]
        self.assertEqual(row["gate_id"], "HF_IDENTITY")
        self.assertIn("SOURCE_MISMATCH", row["reasons"])

    def test_missing_source_binding_is_not_silent(self):
        value = observation()
        gate(value, "MODEL")["source_sha40"] = None
        result = analyze(value)
        self.assertEqual(target(result, "model_inference")["first_blockers"], ["MODEL"])
        self.assertIn("SOURCE_BINDING_UNAVAILABLE",
                      target(result, "model_inference")["blocker_details"][0]["reasons"])

    def test_stale_gate_blocks_despite_verified_claim(self):
        value = observation()
        gate(value, "RUNTIME")["observed_at"] = (AT - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        result = analyze(value)
        self.assertEqual(target(result, "model_inference")["first_blockers"], ["RUNTIME"])
        self.assertIn("OBSERVATION_STALE",
                      target(result, "model_inference")["blocker_details"][0]["reasons"])

    def test_future_gate_blocks_despite_verified_claim(self):
        value = observation()
        gate(value, "AUTH")["observed_at"] = (AT + timedelta(minutes=6)).isoformat().replace("+00:00", "Z")
        result = analyze(value)
        self.assertEqual(target(result, "model_inference")["first_blockers"], ["AUTH"])
        self.assertIn("OBSERVATION_IN_FUTURE",
                      target(result, "model_inference")["blocker_details"][0]["reasons"])

    def test_stale_or_future_envelope_is_refused(self):
        for timestamp, code in ((AT - timedelta(hours=2), "OBSERVATION_STALE"),
                                (AT + timedelta(minutes=6), "OBSERVATION_IN_FUTURE")):
            value = observation()
            value["observed_at"] = timestamp.isoformat().replace("+00:00", "Z")
            with self.subTest(code=code):
                self.assert_refused(value, code)

    def test_duplicate_json_keys_and_nonfinite_values_refused(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}',
                    b'{"a":1e999}', b"", b"\xff"):
            with self.subTest(raw=raw), self.assertRaises(FrontierInputError):
                strict_json(raw)

    def test_invalid_or_uppercase_digests_refused(self):
        for field, bad in (("source_sha40", "A" * 40), ("source_sha40", "a" * 39),
                           ("content_sha256", "B" * 64), ("content_sha256", "b" * 65)):
            value = observation()
            gate(value, "BUILD")[field] = bad
            with self.subTest(field=field, bad=bad):
                self.assert_refused(value, "DIGEST_INVALID")

    def test_unknown_and_cross_plane_gate_ids_refused(self):
        value = observation()
        gate(value, "SOURCE")["id"] = "../../etc/passwd"
        self.assert_refused(value, "GATE_ID_INVALID")
        value = observation()
        gate(value, "INFERENCE")["plane"] = "payment"
        self.assert_refused(value, "GATE_PLANE_INVALID")

    def test_duplicate_missing_and_extra_gates_refused(self):
        value = observation()
        value["gates"].append(deepcopy(value["gates"][0]))
        self.assert_refused(value, "GATE_SET_INVALID")
        value = observation()
        value["gates"].pop()
        self.assert_refused(value, "GATE_SET_INVALID")

    def test_static_topology_cycle_refused(self):
        topology = deepcopy(TOPOLOGY)
        topology["SOURCE"] = ("BUILD",)
        with self.assertRaisesRegex(FrontierInputError, "TOPOLOGY_CYCLE"):
            validate_topology(topology)

    def test_unknown_topology_parent_and_extra_gate_refused(self):
        topology = deepcopy(TOPOLOGY)
        topology["BUILD"] = ("NOT_A_GATE",)
        with self.assertRaisesRegex(FrontierInputError, "TOPOLOGY_PARENT_UNKNOWN"):
            validate_topology(topology)
        topology = deepcopy(TOPOLOGY)
        topology["EXTRA"] = ()
        with self.assertRaisesRegex(FrontierInputError, "TOPOLOGY_GATES_INVALID"):
            validate_topology(topology)
        topology = deepcopy(TOPOLOGY)
        topology["BUILD"] = ([],)
        with self.assertRaisesRegex(FrontierInputError, "TOPOLOGY_PARENTS_INVALID"):
            validate_topology(topology)

    def test_empty_denominator_and_bool_coverage_refused(self):
        for numerator, denominator in ((0, 0), (True, 1), (1, True), (2, 1), (None, 1)):
            value = observation()
            gate(value, "MODEL")["coverage_numerator"] = numerator
            gate(value, "MODEL")["coverage_denominator"] = denominator
            with self.subTest(numerator=numerator, denominator=denominator):
                self.assert_refused(value, "COVERAGE_INVALID")

    def test_incomplete_nonzero_coverage_contradicts_verified_claim(self):
        value = observation()
        gate(value, "MODEL")["coverage_numerator"] = 0
        result = analyze(value)
        self.assertEqual(target(result, "model_inference")["first_blockers"], ["MODEL"])
        self.assertIn("COVERAGE_INCOMPLETE",
                      target(result, "model_inference")["blocker_details"][0]["reasons"])

    def test_signer_and_provider_flags_never_become_independent_signature(self):
        result = analyze(observation())
        signer = next(row for row in result["gate_assessments"] if row["gate_id"] == "SIGNER")
        self.assertEqual(signer["effective_state"], "VERIFIED_CLAIM")
        self.assertIs(result["independent_signature_verified"], False)
        self.assertIs(result["provider_readback_independently_verified"], False)

    def test_identity_mismatch_and_unavailable_fail_closed(self):
        for identity in (False, None):
            value = observation()
            gate(value, "HF_IDENTITY")["identity_matches"] = identity
            with self.subTest(identity=identity):
                result = analyze(value)
                self.assertEqual(target(result, "model_inference")["first_blockers"], ["HF_IDENTITY"])
                self.assertEqual(target(result, "served")["first_blockers"], [])

    def test_caller_cannot_inject_authority_or_private_fields(self):
        for field in ("production_authorized", "effects_authorized", "independent_signature_verified",
                      "password", "topology", "expression"):
            value = observation()
            value[field] = True
            with self.subTest(field=field):
                self.assert_refused(value, "OBSERVATION_FIELDS_INVALID")

    def test_wrong_scalar_types_and_malicious_strings_refused(self):
        cases = (("state", True, "GATE_STATE_INVALID"),
                 ("readback", 1, "READBACK_INVALID"),
                 ("identity_matches", 1, "IDENTITY_FLAG_INVALID"),
                 ("plane", "__import__('os').system('id')", "GATE_PLANE_INVALID"),
                 ("observed_at", "2026-11-19T00:00:00", "TIMESTAMP_INVALID"))
        for field, bad, code in cases:
            value = observation()
            gate(value, "MODEL")[field] = bad
            with self.subTest(field=field):
                self.assert_refused(value, code)

    def test_invalid_state_and_non_utc_timestamp_refused(self):
        value = observation()
        gate(value, "MODEL")["state"] = "HEALTHY"
        self.assert_refused(value, "GATE_STATE_INVALID")
        value = observation()
        value["evaluated_at"] = "2026-11-19T01:00:00+01:00"
        self.assert_refused(value, "TIMESTAMP_INVALID")

    def test_stable_output_under_gate_permutation(self):
        left = observation()
        gate(left, "SOURCE")["state"] = "HOLD"
        gate(left, "SIGNER")["state"] = "UNAVAILABLE"
        right = deepcopy(left)
        random.Random(712).shuffle(right["gates"])
        a, b = analyze(left), analyze(right)
        self.assertEqual(a, b)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        self.assertEqual(target(a, "receipt_proof")["first_blockers"], ["SOURCE"])

    def test_cli_hold_and_success_are_advisory_only(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "observation.json"
            value = observation()
            gate(value, "INFERENCE")["state"] = "UNAVAILABLE"
            path.write_text(json.dumps(value), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["--input", str(path)]), 2)
            result = json.loads(output.getvalue())
            self.assertEqual(result["classification"], CLASSIFICATION)
            self.assertIs(result["production_authorized"], False)
            path.write_text(json.dumps(observation()), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["--input", str(path)]), 0)
            self.assertEqual(json.loads(output.getvalue())["state"], "CLAIMS_COMPLETE_NO_AUTHORITY")

    def test_cli_subprocess_hold_and_refusal(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "observation.json"
            value = observation()
            gate(value, "INFERENCE")["state"] = "UNAVAILABLE"
            path.write_text(json.dumps(value), encoding="utf-8")
            command = [sys.executable, "tools/causal_evidence_frontier.py", "--input", str(path)]
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                       timeout=10, check=False)
            self.assertEqual(completed.returncode, 2, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(target(result, "served")["first_blockers"], [])
            self.assertTrue(all(target(result, name)["first_blockers"] == ["INFERENCE"]
                                for name in ("model_inference", "receipt_proof", "money_settled")))
            path.write_text('{"schema":"first","schema":"duplicate"}', encoding="utf-8")
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                       timeout=10, check=False)
            self.assertEqual(completed.returncode, 3, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["error_code"], "DUPLICATE_JSON_KEY")

    def test_cli_expected_duplicate_key_refusal(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "observation.json"
            path.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["--input", str(path)]), 3)
            result = json.loads(output.getvalue())
            self.assertEqual(result["error_code"], "DUPLICATE_JSON_KEY")
            self.assertEqual(result["classification"], CLASSIFICATION)
            for name in ("production_authorized", "effects_authorized", "independent_signature_verified"):
                self.assertIs(result[name], False)


if __name__ == "__main__":
    unittest.main()
