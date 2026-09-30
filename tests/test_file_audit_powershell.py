# SPDX-License-Identifier: Apache-2.0
import hashlib
import io
import tarfile
import unittest

from census import file_audit as audit


def records_for(path, payload, *, expected=None, limit=1024):
    expected = payload if expected is None else expected
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"blob {len(expected)}\0".encode("ascii"))
    digest.update(expected)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as bundle:
        root = tarfile.TarInfo("fixture/")
        root.type = tarfile.DIRTYPE
        bundle.addfile(root)
        member = tarfile.TarInfo("fixture/" + path)
        member.size = len(payload)
        bundle.addfile(member, io.BytesIO(payload))
    tree = [{"path": path, "type": "blob", "mode": "100644",
             "size": len(expected), "sha": digest.hexdigest()}]
    return audit._archive_file_records(
        "szl-holdings/fixture", "public", buffer.getvalue(), tree,
        max_text_bytes=limit, max_repository_bytes=4096,
    )


class PowerShellAuditTests(unittest.TestCase):
    def test_extensions_are_source_inspected_case_insensitively(self):
        payload = b"# temporary fix\n# TODO\n"
        for extension in ("ps1", "psm1", "psd1", "PS1", "PsM1", "PsD1"):
            path = "scripts/run." + extension
            with self.subTest(path=path):
                self.assertEqual(audit.classify_path(path), "source")
                self.assertTrue(audit.is_text_candidate(path, len(payload), len(payload)))
                records, findings, roles, _ = records_for(path, payload)
                self.assertEqual(records[0]["inspection"], "hashed-and-source-inspected")
                self.assertEqual(roles, {"source": 1})
                self.assertEqual(records[0]["content_sha256"], hashlib.sha256(payload).hexdigest())
                rules = {row["rule"] for row in findings}
                self.assertTrue({"temporary-repair", "unfinished-marker", "missing-spdx-header"} <= rules)

    def test_size_binary_and_encoding_bounds_remain(self):
        cases = (
            (b"# TODO\n", 6, "hashed-text-size-bound"),
            (b"\x00# TODO\n", 1024, "hashed-binary"),
            (b"\xff# TODO\n", 1024, "hashed-non-utf8"),
        )
        for extension in ("PS1", "PSM1", "PSD1"):
            for payload, limit, inspection in cases:
                with self.subTest(extension=extension, inspection=inspection):
                    records, findings, _, _ = records_for(
                        "scripts/run." + extension, payload, limit=limit,
                    )
                    self.assertEqual(records[0]["inspection"], inspection)
                    self.assertEqual(records[0]["content_sha256"], hashlib.sha256(payload).hexdigest())
                    self.assertEqual(findings, [])

    def test_documentation_and_test_roles_remain(self):
        payload = b"# temporary fix\n# TODO\n"
        for path, role in (("docs/example.PS1", "documentation"),
                           ("README.PSM1", "documentation"),
                           ("tests/example.PSD1", "test")):
            with self.subTest(path=path):
                records, findings, _, _ = records_for(path, payload)
                self.assertEqual(records[0]["role"], role)
                rules = {row["rule"] for row in findings}
                self.assertNotIn("temporary-repair", rules)
                self.assertEqual("unfinished-marker" in rules, role == "test")
                self.assertEqual("missing-spdx-header" in rules, role == "test")

    def test_equal_length_tampering_fails_digest_verification(self):
        expected = b"# TODO good\n"
        tampered = b"# TODO evil\n"
        self.assertEqual(len(expected), len(tampered))
        for extension in ("ps1", "psm1", "psd1"):
            with self.subTest(extension=extension):
                with self.assertRaisesRegex(audit.AuditError, "Git blob digest mismatch"):
                    records_for("scripts/run." + extension, tampered, expected=expected)

    def test_crlf_export_requires_matching_git_object(self):
        expected = b"# SPDX-License-Identifier: Apache-2.0\n# TODO\n"
        records, findings, _, _ = records_for(
            "scripts/run.PS1", expected.replace(b"\n", b"\r\n"), expected=expected,
        )
        self.assertEqual(records[0]["archive_transform"], "crlf-to-lf")
        self.assertEqual(records[0]["inspection"], "hashed-and-source-inspected")
        self.assertEqual(records[0]["content_sha256"], hashlib.sha256(expected).hexdigest())
        self.assertIn("unfinished-marker", {row["rule"] for row in findings})
        self.assertNotIn("missing-spdx-header", {row["rule"] for row in findings})


if __name__ == "__main__":
    unittest.main()
