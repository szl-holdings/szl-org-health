# Git Archive Export Verification

Git archives are export representations, not an unconditional byte-for-byte
view of Git blobs. Repository attributes can affect the representation. The
file auditor still requires every recovered file to match the size and Git
blob SHA-1 declared by the immutable tree. Each accepted file also receives a
SHA-256 content digest.

## Narrow CRLF Recovery

An exact archive member is accepted unchanged, including native CRLF blobs.
For a larger regular archive member, the only permitted recovery is CRLF to
LF. The original member is hashed first. The recovery is streamed, bounded,
and accepted only if both its size and Git blob hash match the tree. Arbitrary
content differences, omissions, symlink type changes, and unsafe paths remain
failures. Export substitution, export-ignore, and arbitrary filters are not
silently supported.

Recovered records retain `archive_transform: crlf-to-lf`, `archive_size`,
`archive_git_blob_sha1`, and `archive_content_sha256`. Their existing `size`,
`git_blob_sha1`, `content_sha256`, and source inspection refer to the recovered
canonical Git bytes. The enclosing receipt still binds the complete downloaded
archive. A transformed archive is never described as an exact raw Git blob.

## Observed Regression

On 2026-09-24, replay against the same captured input established:

- Repository: `szl-holdings/szl-typesafe-triage`.
- Revision: `5e5bf7aae7fe10c7aaa09cdd4a4e6cbe95e32129`.
- Archive SHA-256: `2b2633144bcfd2be23dc7df57616b336c6525ec866d6811ff8a47ffe598b2d95`.
- Before: INCOMPLETE at `SZL-TRIAGE-RUNBOOK.ps1`, 1,236 Git bytes versus
  1,258 archive bytes. There were exactly 22 LF-to-CRLF changes.
- The direct Git blob API independently returned the declared object
  `806e2df83349b1da47129c37a932633b1e3c0862`.
- After: all 691 captured Git blobs verified, totaling 332,896,912 canonical
  bytes. Eight PowerShell exports required verified CRLF recovery.

This is a regression repair observed on one immutable repository input, not a
held-out model benchmark, training admission, or production publication claim.
The run retained 162 heuristic findings; byte coverage does not clear them.
The original incomplete estate receipt is preserved separately.

## Tests

Run the existing archive contracts and the focused export regressions:

```text
python -m unittest discover -s tests -p test_file_audit.py -v
python -m unittest discover -s tests -p test_file_audit_line_endings.py -v
```

Coverage includes exact LF and CRLF, content tampering, invalid sizes, truncated
input, empty files, streaming boundaries, short reads, and bare CR preservation.
The broader file-audit suite requires symlink creation privileges on Windows;
do not weaken that test when the local operating system denies them.
