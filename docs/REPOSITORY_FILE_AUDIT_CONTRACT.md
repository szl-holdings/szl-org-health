# Complete repository file audit contract

## Purpose

`census.file_audit` is the permanent evidence plane for the question: **which repository and default-branch files exist, which exact bytes are present, and which build-integrity findings remain?**

It is not a disposable repair script, a source-code publisher, or an autonomous merger. It is read-only and produces immutable, machine-readable receipts.

## Scope proven by one successful run

A successful run:

1. paginates every repository visible to the organization reader, including public, private, active, and archived repositories;
2. enforces the known organization floor of 123 repositories and, when GitHub exposes authoritative public/private totals, requires an exact count match;
3. resolves each repository's exact default-branch commit and root tree;
4. enumerates every tree entry, falling back from GitHub's recursive-tree API to an explicit subtree walk whenever the recursive response is truncated;
5. downloads the immutable commit archive for that exact commit;
6. reads every tracked Git blob byte and recomputes the canonical Git blob SHA-1 before accepting it;
7. commits every blob into a SHA-256 file receipt and a repository-level receipt;
8. compares the archive path set with the Git tree path set so omitted, duplicated, injected, or traversal-like paths fail closed;
9. records submodules as external commit pointers without pretending their target repositories were recursively audited; and
10. emits a private evidence report plus a public projection that does not disclose private repository names, paths, hashes, or findings.

Archived repositories are evidence-bearing repositories and remain in scope. Repositories without a resolvable default branch remain `INCOMPLETE`; they are never counted as clean by absence.

## Source inspection

Every blob is byte-verified. A second, separately labelled inspection is applied to bounded UTF-8 source, test, workflow, container, configuration, and documentation files. The current rules detect:

- unpinned third-party GitHub Actions;
- remote download pipelines into a shell;
- disabled TLS verification;
- `subprocess` execution with `shell=True`;
- unsafe YAML and pickle loading;
- `write-all` workflow permissions and `pull_request_target`;
- tracked secret-like paths;
- mutable container image references;
- executable temporary, one-shot, self-deleting, or compatibility-shim machinery;
- unfinished `TODO`, `FIXME`, `HACK`, and `XXX` markers; and
- missing SPDX identifiers on bounded source and test files.

Proof documents and tests may describe a forbidden mechanism without being classified as the mechanism itself. Temporary-repair markers are therefore enforced on executable source, workflow, and container surfaces rather than prose evidence.

No file content or suspected credential value is copied into a finding. Reports contain paths, rules, bounded metadata, object hashes, and line numbers only.

## Failure semantics

| State | Meaning |
|---|---|
| `PASS` | Every tracked blob was verified and no finding was observed. |
| `WARN` | The audit is complete, with medium or low findings. |
| `FAIL` | The audit is complete, with at least one critical or high finding. |
| `INCOMPLETE` | Repository enumeration, tree traversal, archive retrieval, object verification, or a declared resource ceiling prevented proof of completeness. |

The scheduled workflow uses `--allow-findings` so it retains a complete `WARN` or `FAIL` receipt for remediation. `INCOMPLETE` always fails the workflow. This prevents a finding from suppressing evidence while also preventing partial evidence from becoming a green claim.

## Bounded resources

The default control plane uses:

- four concurrent repository workers;
- 512 MiB maximum compressed archive bytes per repository;
- 4 GiB maximum tracked bytes per repository;
- 2 MiB maximum per file for UTF-8 semantic inspection;
- two million tree nodes and 256 levels of tree depth.

Exceeding a bound is `INCOMPLETE`, not success. Binary and oversized text files remain fully byte-hashed when they are inside the repository bound; only their semantic source inspection is labelled as bounded.

## Explicit non-claims

One run does not claim to audit:

- non-default branches, deleted history, pull-request merge refs, release assets, packages, container registries, or Git LFS object payloads beyond the tracked pointer blob;
- the contents of an external submodule target;
- runtime deployment identity, Hugging Face publication state, DNS, cloud configuration, or live production behavior; or
- whether a finding is exploitable without a separate contextual review.

Those remain separate evidence planes. This contract proves the GitHub default-branch repository/file estate and preserves the exact boundary in every receipt.
