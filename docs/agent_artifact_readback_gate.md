# SZL proof-first agent artifact lifecycle: research-to-code v0

Status: **research prototype / read-only admission control**. No production-ready,
signed-provenance, retention-clearance, or safe-to-delete claim. Preserve the
SZL_SOURCE_ADMISSION_HOLD in the Windows PowerShell cleanup controller.

## State-of-the-art engineering transfer

| Reference | Primary research / code | Transferred design |
| --- | --- | --- |
| Nix, Dolstra et al. (USENIX LISA 2004) | https://www.usenix.org/conference/lisa-04/nix-safe-and-policy-free-system-software-deployment ; https://github.com/NixOS/nix | Hashed immutable components; graph reachability and GC roots, rather than filename-age deletion. Retain Git roots, signed receipts, models, and agent claims. |
| Bazel | https://github.com/bazelbuild/bazel ; https://bazel.build/remote/caching | Explicit action inputs, action keys, output hashes, and content-addressed storage (CAS). Future candidate caches must link to their action and dependency identity. |
| in-toto | https://github.com/in-toto/in-toto ; https://github.com/in-toto/attestation | Authorized workflow steps and verifiable supply-chain claims. Keep producer assertions separate from independent verification. |
| SLSA v1.2 | https://slsa.dev/spec/v1.2/build-provenance | Subject, source, builder and resolved dependencies; no inference of production integrity from an unsigned digest. |
| DVC | https://github.com/treeverse/dvc ; https://doc.dvc.org/user-guide/pipelines/running-pipelines | Content-versioned data/model DAG and dependency-aware reuse; bind training to model, dataset, code, parameters and metrics. |
| OpenTelemetry GenAI | https://github.com/open-telemetry/semantic-conventions-genai | Agent, inference and tool spans; potential future claim registry and drift signals without copying prompts or process command lines. |
| NVIDIA agent runtime | https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/ ; https://github.com/NVIDIA/NeMo-Agent-Toolkit | Separate policy enforcement from agent reasoning. NeMo Agent Toolkit was deprecated in Oct. 2026; NVIDIA directs migrations to NeMo Relay, Helix and Fabric. |

Their empirical claims are not automatically SZL operational achievements.
This PR does not import their code or copy third-party algorithms.

## Exact formulas and what is actually computed

Implemented:
- Artifact identity: d = SHA256(exact source bytes); compare source digest,
  independent-path copy digest, declared digest, and exact file byte length.
- Input identity: input_sha256 = SHA256(exact manifest bytes). This is NOT a signature.
- Verified matches: V = SUM_i 1[source_i digest == copy_i digest == declared_i].
  Only V == N gives status READBACK_VERIFIED_NOT_RELEASED.
- Read budget: SUM_i(source_bytes_i + copy_bytes_i) <= B.
  Default B = 256 MiB, maximum 1000 declared artifacts. Fail closed.
- Reject traversal, protected roots, symlinks/junctions and hardlink aliases
  (where inode data is available); detect file mutation during reads.
- Output includes only pseudonymous relative-path fingerprints and reason
  codes, not private file contents, source roots, or credentials.

Not implemented and never inferred:
- Authenticated signatures for owner and evidence receipt assertions.
- Archive independence/durability, retention clearance, or trusted custody.
- Live agent/handle checks, protected-main Git reachability or worktree status.
- An authorized cleanup executor, deletion, process stops, or runtime releases.

Separate cleanup authorization would require:
  RELEASE = byte_match AND trusted_provenance AND owner_authenticated
            AND retention_clear AND durable_independent_copy
            AND no_live_agent_claim AND source_reachability_verified
            AND explicit_approval

This module implements only byte_match and ALWAYS returns
deletion_authorized=false. Even perfect readback is NOT authorization.

## Manifest shape (dummy data only)

    {
      "schema": "szl.agent-artifact-readback/v1",
      "artifacts": [
        {
          "relative_path": "khipu/operator/sample.ndjson",
          "copy_relative_path": "khipu/operator/sample.ndjson",
          "sha256": "<64 lowercase hex characters>",
          "size_bytes": 123,
          "owner": "unverified-provisional-owner",
          "evidence_id": "unverified-receipt-reference"
        }
      ]
    }

The owner and evidence_id fields are untrusted assertions and are not
cryptographically verified by this read-only tool.

## Bounded invocation

    python tools/agent_artifact_readback_gate.py --manifest INPUT.json --source-root C:\local\source --copy-root D:\separate\copy
    python -m unittest discover -s tests -p test_agent_artifact_readback_gate.py -v

Exit 0 means exact declared copy match, but NOT RELEASED.
Exit 2 means HOLD. No output files, deletes, moves, Git changes, or kills.
Normal Python runtime bytecode may be created by imports in scratch, not in
the source evidence tree. The tool is not a sandbox; feed only authorized
nonsecret roots. Reparse directories, including Windows junctions, fail shut.

## Live BETTERWITHAGE binding

The November 17, 2026 disk-hygiene receipt identified nine Khipu/energy
ledger files outside the historical HEAD in the meter-repair-20261008
residue. Read-only hash inspection at 23:53 UTC confirmed a combined
1,367,907 bytes and zero corresponding files at matching paths in the
designated primary working copy. Absence from that worktree does not prove
absence elsewhere. Until an independent archive is identified, read back
and verified, the disposition is HOLD. The .pytest_cache access-denied
area also remains unclassified.

Preserve this worktree, all dirty/unknown Git worktrees, model weights,
Hugging Face caches, signed receipts, OneDrive, user data, private keys,
Docker/WSL volumes and protected system files.

## Next phase, explicitly not part of this prototype

1. Independently verify signed SLSA/in-toto statements and authorized owner
   bindings; anchor receipts to protected Git main SHAs and canonical HF IDs.
2. Add a separate read-only agent-claim census and OpenTelemetry spans.
3. Verify off-host failure-domain separation, durable copy readback,
   retention dates, and cryptographic custody evidence.
4. Introduce a separately reviewed disposal plan only after all predicates
   are independently satisfied. Never remove the V13 safety hold as a
   shortcut; never delete based on this gate alone.