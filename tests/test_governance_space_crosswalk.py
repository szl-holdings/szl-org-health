"""Synthetic negative controls for governance Space bindings."""
import hashlib
import json
import unittest

from tools.governance_space_crosswalk import BindingHold, crosswalk, read_manifest

COMMIT = "a" * 40
HF_SHA = "b" * 40


def fixture():
    return {
        "schema": "szl.estate.alignment/v1",
        "github_org": "szl-holdings",
        "hub_org": "SZLHOLDINGS",
        "hub_alias_policy": {
            "duplicate_authority_spaces_forbidden": True,
            "canonical_public_space_slugs": ["terra", "finance"],
        },
        "public_bodies": [
            {"hub_surface": "SZLHOLDINGS/terra",
             "backend_source": "szl-holdings/szl-real-estate",
             "presentation_source": "szl-holdings/a11oy:verticals/terra",
             "publisher_workflow": "szl-holdings/a11oy:.github/workflows/hf-sync.yml"},
            {"hub_surface": "SZLHOLDINGS/finance",
             "backend_source": "szl-holdings/puriq-live",
             "presentation_source": "szl-holdings/a11oy:verticals/finance"},
        ],
    }


def run(doc=None, spaces=None):
    doc = fixture() if doc is None else doc
    spaces = [
        {"id": "SZLHOLDINGS/terra", "private": False, "sha": HF_SHA},
        {"id": "SZLHOLDINGS/finance", "private": False, "sha": HF_SHA},
    ] if spaces is None else spaces
    raw = json.dumps(doc).encode()
    blob = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
    return crosswalk(doc, spaces, manifest_commit=COMMIT,
                     manifest_blob=blob, raw_manifest=raw)


class VerticalBindingTests(unittest.TestCase):
    def test_terra_and_finance_bind_to_real_backends_without_release_claim(self):
        result = run()
        bindings = {b["hub_surface"]: b for b in result["bindings"]}
        self.assertEqual(bindings["SZLHOLDINGS/terra"]["backend_source"],
                         "szl-holdings/szl-real-estate")
        self.assertEqual(bindings["SZLHOLDINGS/finance"]["backend_source"],
                         "szl-holdings/puriq-live")
        self.assertFalse(result["release_authorized"])
        self.assertTrue(all(not b["frontend_backend_verified"]
                            and not b["source_parity_verified"] for b in result["bindings"]))

    def test_running_metadata_does_not_grant_release(self):
        result = run(spaces=[
            {"id": "SZLHOLDINGS/terra", "private": False,
             "sha": HF_SHA, "stage": "RUNNING"},
        ])
        self.assertFalse(result["release_authorized"])
        self.assertEqual(result["bindings"][0]["binding_state"],
                         "HF_REVISION_UNVERIFIED")

    def test_duplicate_authority_rejected(self):
        doc = fixture()
        doc["public_bodies"][1]["hub_surface"] = "SZLHOLDINGS/terra"
        with self.assertRaisesRegex(BindingHold, "DUPLICATE_CANONICAL_OWNER"):
            run(doc)

    def test_private_or_unproven_visibility_denied(self):
        for value in (True, None, "false"):
            with self.subTest(value=value), self.assertRaisesRegex(
                BindingHold, "PRIVATE_OR_UNKNOWN_VISIBILITY"
            ):
                run(spaces=[{"id": "SZLHOLDINGS/terra",
                             "private": value, "sha": HF_SHA}])

    def test_duplicate_space_ids_denied(self):
        row = {"id": "SZLHOLDINGS/terra", "private": False, "sha": HF_SHA}
        with self.assertRaisesRegex(BindingHold, "DUPLICATE_SPACE_ROW"):
            run(spaces=[row, dict(row)])

    def test_unowned_backend_rejected(self):
        doc = fixture()
        doc["public_bodies"][0]["backend_source"] = "other-org/terra"
        with self.assertRaisesRegex(BindingHold, "INVALID_BODY_AUTHORITY"):
            run(doc)

    def test_json_duplicate_and_nonfinite_rejected(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(BindingHold):
                read_manifest(raw)

    def test_manifest_object_cannot_impersonate_verified_blob(self):
        source = fixture()
        raw = json.dumps(source).encode()
        blob = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
        altered = fixture()
        altered["public_bodies"][0]["backend_source"] = "szl-holdings/other-repository"
        spaces = [{"id": "SZLHOLDINGS/terra", "private": False, "sha": HF_SHA}]
        with self.assertRaisesRegex(BindingHold, "MANIFEST_OBJECT_MISMATCH"):
            crosswalk(altered, spaces, manifest_commit=COMMIT,
                      manifest_blob=blob, raw_manifest=raw)

    def test_crosswalk_invalid_manifest_or_raw_bytes_fail_closed(self):
        source = fixture()
        raw = json.dumps(source).encode()
        blob = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
        cases = (
            (None, raw, "INVALID_MANIFEST"),
            ([], raw, "INVALID_MANIFEST"),
            (source, None, "INPUT_BUDGET"),
            (source, "non-bytes", "INPUT_BUDGET"),
            (source, b"", "INPUT_BUDGET"),
            (source, b"x" * 1_000_001, "INPUT_BUDGET"),
        )
        for doc, supplied_raw, reason in cases:
            with self.subTest(reason=reason, doc_type=type(doc).__name__,
                              raw_type=type(supplied_raw).__name__):
                with self.assertRaisesRegex(BindingHold, reason):
                    crosswalk(doc, [], manifest_commit=COMMIT,
                              manifest_blob=blob, raw_manifest=supplied_raw)

    def test_source_blob_mismatch_rejected(self):
        doc = fixture()
        raw = json.dumps(doc).encode()
        with self.assertRaisesRegex(BindingHold, "MANIFEST_BYTES_MISMATCH"):
            crosswalk(doc, [], manifest_commit=COMMIT,
                      manifest_blob="c" * 40, raw_manifest=raw)


if __name__ == "__main__":
    unittest.main()
