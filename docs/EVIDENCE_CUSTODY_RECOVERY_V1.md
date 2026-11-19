# SZL evidence-custody recovery: typed proof, not file-age heuristics

Status: **read-only recovery candidate discovery; release admission HOLD**.
Source of truth for this tool: szl-holdings/szl-org-health protected main
once reviewed and merged. It does not restore or sign records, rewrite Git,
start agents, deploy a tunnel, delete files or promote a model.

## Observed incident, 2026-11-19 UTC

On authorized BETTERWITHAGE, the old disk-hygiene receipt root
under C:\SZL\EstateOps\disk-hygiene was not present. Nine Khipu/energy
ledger paths in the earlier preserved worktree were not present at their
prior relative locations. A bounded read-only scan of six authorized SZL
archive/work directories enumerated 2,878 entries and found no exact
filename candidates; three directory errors mean the scan cannot prove
global absence. This is **NOT_FOUND_WITHIN_SCOPE**, not "deleted forever"
and not "successfully archived." C: recovered very large free-space
headroom; the cause was unverified.

The historical nine-entry hash manifest was **unsigned**. Even if another
copy hashes identically, this tool may claim only
HASH_MATCH_UNATTESTED, never authentic authorship or independent
durability. A SHA-256 is a content identity, not a signature.

## Actual implementation

The stdlib-only Python locator accepts an explicitly supplied small JSON
manifest and a bounded set of explicitly approved local roots, scans exact
basenames of .json/.jsonl/.ndjson files only, compares byte length and
SHA-256 by reading the exact candidate bytes, and emits deterministic
status without exposing private paths by default.

- Strict duplicate-key JSON parsing and unique artifact IDs.
- Refuses filesystem roots, sensitive directory components and
  symlink/junction/reparse ancestors.
- Never traverses protected directories (.git, OneDrive, .ssh, keys,
  Hugging Face models/weights, etc.) or follows reparse entries.
- Max 8 roots, 64 artifact IDs, 250,000 scanned entries, 20 seconds,
  256 MiB cumulative read, 32 MiB per candidate.
- Rechecks file metadata against open descriptor before and after reads;
  concurrent mutations, access failures or budget exhaustion produce
  UNKNOWN_INCOMPLETE_SCAN for unresolved items.
- Output excludes local full/relative paths unless the explicit
  local-only --show-paths option is selected.
- No HTTP calls, writes, cloud uploads, training, process termination,
  disposal capability, production-release authority or credentials.
- The exact manifest input SHA-256 is emitted as an **unsigned**
  fingerprint. Evidence remains untrusted until an independently
  authenticated owner and immutable source root are established.

Supported statuses:
- HASH_MATCH_UNATTESTED: exact bytes observed; preservation/custody
  admission still required.
- NOT_FOUND_IN_SCOPED_NONPROTECTED_FILES: scan complete in explicitly
  authorized ordinary directories; excludes protected and reparse paths.
- UNKNOWN_INCOMPLETE_SCAN: budget, permissions or filesystem errors
  prevent absence claims.
- HOLD: never production-admitted.

## CLI (run only after confirming the local Python runtime)

    python -B tools/evidence_custody_locator.py \
      --manifest C:\approved-evidence\manifest.json \
      --root C:\SZL\archive \
      --root C:\SZL\khipu-corpus

No historical manifest, expected hash, file or signature is generated
by this tool. Supply the original trusted owner-approved list.
An illustrative test fixture (NOT a production manifest):

    {
      "schema": "szl.custody.recovery-locator/v1",
      "artifacts": [{
        "id": "demo-ledger-1",
        "basename": "synthetic.ndjson",
        "size_bytes": 10,
        "sha256": "18c4f85a180cf29ddc1f8e3a3143ff54d643d1c306dbe610f4f70482632071d4"
      }]
    }

The example hash is for exactly the 10 bytes `synthetic\\n` (nine ASCII letters followed by LF); it is not a real evidence file. The fixture must not be presented as a matched real-world result.
Production must supply exact historical hashes and sizes from an
independently supported source. It is appropriate to leave the
nine real artifacts on custody HOLD until verified.

## What industry leaders contribute to the next SZL phase

1. Palantir Ontology: represent GitRevision, HFRevision, TrainingRun,
   WeightArtifact, Receipt, LiveEndpoint, Settlement and ActionApproval as
   *typed* operational objects with authenticated, scoped actions. SZL's
   missing artifacts should not be silently rebuilt as identical nodes.
   https://www.palantir.com/docs/foundry/architecture-center/ontology-system
2. Temporal: preserve a durable, replayable, idempotent event history of
   agent attempts. A missing local worktree must not trigger replay of
   irreversible publishing, deletions or GPU spend without an admitted
   idempotency key and last durable checkpoint.
   https://docs.temporal.io/encyclopedia/event-history
3. SLSA 1.2 / in-toto: bind each artifact SUBJECT to an authenticated
   source revision, resolved build dependencies, builder identity and a
   verified attestation. A naked SHA-256 and an unsigned local JSON
   cannot satisfy those conditions.
   https://slsa.dev/spec/v1.2/build-provenance
4. OpenTelemetry GenAI: collect privacy-safe process/tool spans for
   each agent action without retaining prompt content or token-bearing
   command lines. Separate liveness, evaluation, and evidence verification.
   https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/
5. NVIDIA: NeMo Agent Toolkit was deprecated in October 2026;
   evaluate NeMo Relay, Helix and Fabric in separately owned, pinned,
   tested migration lanes. Do not increase GPU allocation on a mere
   group-running label.
   https://docs.nvidia.com/nemo/agent-toolkit/latest/resources/migration-guide.html

The references above are published leader patterns, not proprietary source
code and not evidence that SZL already operates their capabilities.

## Production release equation (policy design, NOT implemented by this locator)

For a given deployable subject, release admission requires ALL applicable
conditions from independently verified sources:

    ADMIT = authenticated_source_revision
            AND protected_change_control
            AND exact_binary_or_weight_subject_digest
            AND trusted_build_training_attestation
            AND independent_runtime_revision_readback
            AND liveness AND readiness AND rollback_rehearsal
            AND signed_receipt_custody
            AND required_human_approval

For monetized products, add an independently checked paid-settlement
condition before declaring revenue operational. For training, require a
fresh source-bound trainer-step and durable checkpoint. A global HF commit
or a Salad group name is insufficient.

A failing edge, missing local receipts, incomplete HF source parity,
missing Python runtime, missing per-lane trainer proof or undecided
ownership keeps overall release status HOLD. Never change the gate or
hide failing checks to force a green badge.

## Evidence to recover

- Earlier BETTERWITHAGE disk-hygiene final verification and cleanup
  receipts; current original path absent.
- Nine Khipu/energy ledger files with owner-approved historical digest
  list; no exact replacement copy independently admitted yet.
- GitHub Action artifacts that remain available must be verified by exact
  retention identity and archive bytes rather than used as automatic
  replacements for unrelated missing local receipts.
- Public MCP free surfaces currently return Cloudflare 530 and require a
  verified admitted origin/tunnel owner. Do not start an unknown Windows
  Cloudflared service merely because it is stopped.
- Salad container metadata must be reconciled with ready-instance counts,
  immutable image digests, per-lane boot/step/checkpoint receipts and
  separate cost authorization before declaring GPU training operational.

## Follow-on authorization gates

This tool may be merged once CI and code review pass; it is read-only.
Running it against specific private or offline drives requires the
owner's authorization for those roots. Restoring bytes, deleting caches,
editing DNS, deploying an MCP origin, scaling Salad, or regenerating
historical attestations requires separate reviewed authority and
independent confirmation.
