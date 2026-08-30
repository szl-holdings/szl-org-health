# Estate v10 execution control plane

This directory is the authoritative, fail-closed ledger for the 2026-08-30 SZL
estate consolidation and production-readiness program.

- `EXECUTION.md` defines architecture, gates, lifecycle rules, model/kernel
  qualification, runtime readiness and investor evidence.
- `EXECUTION_STATE.json` records current blockers and mutations without secrets.
- `../../tools/estate_v10_gate.py` rejects unsafe state such as force merges,
  premature archives, unsupported promotion or controller mutation authority.
- `../../.github/workflows/estate-v10-control-plane.yml` runs positive and
  negative validation on every relevant pull request and default-branch change.

The 2026-08-29 full audit bundle is the seed evidence pack. Live state must be
re-observed before every mutation because repositories, PRs, workflows and Hub
artifacts can change after the seed snapshot.

No file in this directory grants authority to bypass protected branches,
required checks, model qualification, migration parity, security review or
Hugging Face authentication.
