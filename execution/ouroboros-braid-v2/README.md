<!-- SPDX-License-Identifier: Apache-2.0 -->
# Evidence for the Ouroboros braid v2

The checkable artifacts behind the numbers in `docs/OUROBOROS_DB_BRAID_V2_20261119.md`. Everything
here was produced in one container by the tools in this repository, from committed bytes. Nothing
here is signed, and nothing here authorizes anything.

| Folder | What it holds |
| --- | --- |
| `turns/final-1/` | A genesis turn: the full runner output except the Lean step logs. |
| `turns/final-2/` | The next turn, which consumed `final-1` and its Lake receipt. |
| `turns/candidate-final/` | A genesis turn in which `lutar-lean` is a local candidate commit with 46 repaired files (see below). |
| `counters/` | `lutar-lean`'s own canonical counter (`.github/scripts/lean_numbers.py`) at `98f1735`. |
| `experiments/` | The float-versus-exact admit experiment against `a11oy/szl_verify_nine.py`, script and result. |
| `soundness/` | Kernel-checked findings about three `lutar-lean` statements, with their full outputs. |
| `lutar-lean-candidate/` | The 46-file repair as a patch against `lutar-lean` `98f1735`. |

## Re-checking a turn

Every turn was verified from its written files and replayed byte for byte by the runner before
it was published (`manifest.json`: `verified_from_written_files`, `replayed_byte_identical`). Anyone
can repeat the replay from this checkout:

```bash
python -I -B tools/database_ouroboros_braid_v2.py \
  --policy governance/database_contracts/ouroboros_braid_v2.json \
  --family-map governance/database_contracts/braid_family_map_v1.json \
  --census execution/ouroboros-braid-v2/turns/final-1/census.json \
  --lean-witness execution/ouroboros-braid-v2/turns/final-1/lean_witness.json \
  --hatun-witness execution/ouroboros-braid-v2/turns/final-1/hatun_witness.json \
  --known-answers-report execution/ouroboros-braid-v2/turns/final-1/known_answers.json \
  --replay execution/ouroboros-braid-v2/turns/final-1/turn.json
```

It prints `REPLAY_MATCHED` (exit 2). Changing any verdict in `turn.json` is refused with a code;
deleting one refusal reason, for example, gives `BRAID_TURN_DERIVATION_DRIFT`. For `final-2`, add
`--previous-turn`, `--previous-khipu-tree` and `--previous-lake-wrap` pointing at `final-1`. The
replay re-derives the turn from the evidence files. It does not re-run Lean, Hatun or the census.
Re-running those needs the source checkouts at the commits each `census.json` records.

## The repair candidate

`lutar-lean-candidate/0001-repair-46-files-rejected-at-98f1735.patch` applies to `lutar-lean`
`98f1735` and reproduces the candidate tree `b4ed0d47ef8a9b9b5980185e9333ed5f37d67d0e`, the tree id
`turns/candidate-final/census.json` records. The candidate commit exists only in this session's
container; it has not been pushed to `lutar-lean`. Each file was repaired so that the kernel accepts
it without adding `sorry`, axioms or `native_decide`. The meaning of each repaired statement has
not been reviewed, so the patch is unratified.

## What is deliberately not here

- The Lean step logs (about 1.8 MB per turn). Their SHA-256 digests are in each `manifest.json`
  under `lean_logs`, and in the witness's `steps`.
- Anything signed. Every receipt is `UNSIGNED`.
