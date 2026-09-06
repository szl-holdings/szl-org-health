# Deep Repository and File Audit

This control closes the gap between a repository-count dashboard and a source-complete estate audit.

## Canonical implementation

`census/deep_repository_audit_v2.py` is the scheduled entrypoint. It reuses the file scanner and evidence format in `census/deep_repository_audit.py`, while adding the transport and census guarantees required for an organization-wide credentialed read.

The v2 collector:

- locks all authenticated JSON requests and pagination to `https://api.github.com`;
- permits only the GitHub API tarball redirect to `https://codeload.github.com`;
- strips `Authorization` and `Proxy-Authorization` before the codeload request;
- rejects direct codeload API use, cross-origin pagination, path-changing pagination, duplicate `next` relations, pagination cycles, and oversized JSON responses;
- requires at least 100 repositories so a repository-local fallback token cannot masquerade as a complete organization census;
- hashes the sorted organization repository set and requires all six shards to present the same inventory digest before the final receipt is accepted.

## What is proven

The workflow enumerates every repository visible to the short-lived organization reader, resolves each exact default-branch commit, inventories its recursive Git tree, downloads that exact source archive, and recomputes every regular file’s Git blob identity and SHA-256 digest.

Every tracked blob receives a file-inventory row. First-party textual files up to 2 MiB receive semantic checks. Binary, vendored, generated, oversized, symlink, and submodule states remain explicitly inventoried with their inspection state; they are never silently dropped or labeled clean.

Six deterministic shards allow the current 100+ repository estate to finish without one oversized runner becoming a single point of failure. The merge job requires every shard, verifies each compressed inventory digest, rejects duplicate or missing repositories, requires one shared organization inventory digest, and emits one final receipt.

## Checks

The collector records, among other evidence:

- exact repository, default branch, commit, tree, file path, Git blob SHA-1, local SHA-256, byte count, and semantic inspection state;
- the latest default-branch result per workflow, without allowing unrelated green runs to hide a newer failing run;
- open pull requests and Grok/xAI-related branch or file recovery candidates;
- high-confidence tracked credential material;
- unpinned GitHub Actions and container base images;
- `pull_request_target` execution hazards;
- write-capable, one-shot, or self-removing workflow controllers;
- implicit Python `sitecustomize.py` process mutation;
- dynamic shell-execution and network-to-shell primitives;
- missing dependency lockfiles and core governance artifacts;
- unfinished-work, build-error, runtime-error, and Grok stall markers;
- observed open-source capability signals used by the frontier radar.

## No-bandaid boundary

The collector is read-only. It does not push a branch, modify a pull request, rerun a workflow, rotate a credential, change visibility, touch DNS, mutate a provider, publish a model, deploy a runtime, or authorize production activity.

A `P0` or `P1` finding is evidence for a separate reviewed repair pull request. It is not auto-fixed inside the audit workflow. One-shot and self-removing repair workflows are themselves findings.

The organization reader is minted only inside the existing schedule-only provider workflow. Pull-request and push validation remains secret-free. If that reader is absent or scoped only to the current repository, the 100-repository minimum fails closed.

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

`OBSERVED` means the collector completed and no P0/P1 finding was observed. `ACTION_REQUIRED` means at least one P1 exists. `FAILED_CLOSED` means at least one P0 or source-integrity failure exists. `INCOMPLETE` means complete evidence could not be produced. None of these states is a production-readiness claim.
