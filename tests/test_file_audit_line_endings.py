# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import io
import unittest

from census import file_audit as audit
from test_file_audit import archive_bytes, git_blob_sha1, tree_entry


class ArchiveLineEndingTests(unittest.TestCase):
    def records(self, canonical: bytes, exported: bytes, *, max_text_bytes: int = 1024):
        return audit._archive_file_records(
            "szl-holdings/fixture", "public", archive_bytes({"source.py": exported}),
            [tree_entry("source.py", canonical)], max_text_bytes=max_text_bytes,
            max_repository_bytes=4 * 1024 * 1024,
        )[0]

    def test_crlf_export_preserves_both_hashes_and_inspects_canonical_source(self):
        canonical = b"# SPDX-License-Identifier: Apache-2.0\nprint('ok')\n"
        exported = canonical.replace(b"\n", b"\r\n")
        row = self.records(canonical, exported)[0]
        self.assertEqual(row["git_blob_sha1"], git_blob_sha1(canonical))
        self.assertEqual(row["content_sha256"], hashlib.sha256(canonical).hexdigest())
        self.assertEqual(row["size"], len(canonical))
        self.assertEqual(row["archive_size"], len(exported))
        self.assertEqual(row["archive_git_blob_sha1"], git_blob_sha1(exported))
        self.assertEqual(row["archive_content_sha256"], hashlib.sha256(exported).hexdigest())
        self.assertEqual(row["archive_transform"], "crlf-to-lf")
        self.assertEqual(row["inspection"], "hashed-and-source-inspected")

    def test_native_crlf_git_blob_is_never_normalized(self):
        canonical = b"keep\r\nthese\r\n"
        row = self.records(canonical, canonical)[0]
        self.assertEqual(row["git_blob_sha1"], git_blob_sha1(canonical))
        self.assertNotIn("archive_transform", row)

    def test_native_lf_blob_has_no_export_evidence(self):
        row = self.records(b"one\ntwo\n", b"one\ntwo\n")[0]
        self.assertNotIn("archive_transform", row)

    def test_content_tampering_remains_fatal_after_crlf_recovery(self):
        with self.assertRaisesRegex(audit.AuditError, "Git blob digest mismatch"):
            self.records(b"one\ntwo\n", b"one\r\nbad\r\n")

    def test_arbitrary_size_mismatch_is_not_accepted(self):
        for canonical, exported in [(b"a\n", b"ab\n"), (b"a\n", b"a"), (b"a\n", b"a\r\nextra")]:
            with self.subTest(exported=exported):
                with self.assertRaises(audit.AuditError):
                    self.records(canonical, exported)

    def test_normalization_handles_crlf_across_stream_chunk_boundary(self):
        canonical = b"a" * (1024 * 1024 - 1) + b"\nend\r"
        exported = canonical.replace(b"\n", b"\r\n")
        row = self.records(canonical, exported, max_text_bytes=16)[0]
        self.assertEqual(row["git_blob_sha1"], git_blob_sha1(canonical))
        self.assertEqual(row["inspection"], "hashed-text-size-bound")

    def test_truncated_or_oversized_raw_stream_still_fails(self):
        for raw in [b"a\r", b"a\r\nextra"]:
            with self.subTest(raw=raw):
                with self.assertRaises(audit.AuditError):
                    audit._stream_member(io.BytesIO(raw), size=2, collect=True, archive_size=3)

    def test_short_reads_preserve_bare_cr_and_split_crlf_pairs(self):
        exported = b"a\r\nb\rc\r\r\nend\r"
        canonical = exported.replace(b"\r\n", b"\n")
        for width in (1, 2, 3, 5):
            with self.subTest(width=width):
                class ShortReader(io.BytesIO):
                    def read(self, size=-1):
                        return super().read(min(size, width))

                git_sha, sha256, collected = audit._stream_member(
                    ShortReader(exported), size=len(canonical), collect=True,
                    archive_size=len(exported),
                )
                self.assertEqual(collected, canonical)
                self.assertEqual(git_sha, git_blob_sha1(canonical))
                self.assertEqual(sha256, hashlib.sha256(canonical).hexdigest())

    def test_empty_file_remains_valid(self):
        row = self.records(b"", b"")[0]
        self.assertEqual(row["size"], 0)
        self.assertEqual(row["git_blob_sha1"], git_blob_sha1(b""))


if __name__ == "__main__":
    unittest.main()
