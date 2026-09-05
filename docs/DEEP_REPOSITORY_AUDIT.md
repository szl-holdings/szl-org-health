# Deep Repository and File Audit

This control closes the gap between a repository-count dashboard and a
source-complete estate audit.

## What is proven

The workflow enumerates every repository visible to the short-lived
organization reader, resolves each exact default-branch commit, inventories its
recursive Git tree, downloads that exact source archive, and recomputes every
regular file's Git blob identity and SHA-256 digest.

Every tracked blob receives a file-inventory row. First-party text files up to
2 MiB receive semantic checks. Binary, vendored, generated, submodule, and
oversized objects remain in the inventory with an explicit inspection state;
they are never silently dropped or labeled clean.

Six deterministic shards allow the current 100+ repository estate to finish
without one oversized runner becoming a single point of failure. The merge job
requires every shard, verifies each inventory digest, rejects duplicate or
missing repositories, and emits one final receipt.

## Checks

The collector records, among other evidence:

- exact repository, default branch, commit, tree, file path, Git blob SHA-1,
  local SHA-256, byte count, and semantic inspection state;
- latest default-branch run per workflow, without allowing unrelated green runs
  to hide a newer failing run;
- open pull requests and Grok/xAI-related branch/file recovery candidates;
- high-confidence tracked credential material;
- unpinned GitHub Actions and container base images;
- `pull_request_target` execution hazards;
- write-capable or self-mutating workflow controllers;
- implicit Python `sitecustomize.py` process mutation;
- missing dependency lockfiles and core governance artifacts;
- executable-shell primitives, unfinished-work markers, and technology
  capability signals.

## No-bandaid boundary

The collector is read-only. It does not push a branch, modify a pull request,
rerun a workflow, rotate a credential, change visibility, alter a provider,
publish a model, deploy a runtime, or authorize production activity.

A `P0` or `P1` finding is evidence for a separate reviewed repair PR. It is not
auto-fixed inside the audit workflow. One-shot and self-removing repair
workflows are themselves reported.

## Outputs

Each shard publishes:

- `repositories-shard-N.json`
- `findings-shard-N.json`
- `file-inventory-shard-N.ndjson.gz`
- `receipt-shard-N.json`

The final artifact publishes:

- `report.md`
- `receipt.json`
- `repositories.json`
- `findings.json`
- `grok-recovery-index.json`
- `technology-capability-index.json`
- all six compressed file inventories

`OBSERVED` means the collector completed and no P0/P1 finding was observed.
`ACTION_REQUIRED` means at least one P1 exists. `FAILED_CLOSED` means at least
one P0 or source-integrity failure exists. `INCOMPLETE` means complete evidence
could not be produced. None of these states is a production-readiness claim.
