# BETTERWITHAGE disk and agent hygiene — source-only triage v1

**Status: SOURCE-ONLY / NO DEPLOYMENT / HISTORICAL CUSTODY HOLD.** This tool is a narrow companion to the existing [storage admission](LOCAL_STORAGE_ADMISSION.md), [Crashpad steward](../tools/crashpad_steward.py), [artifact readback](agent_artifact_readback_gate.md), and [evidence custody locator](EVIDENCE_CUSTODY_RECOVERY_V1.md). It is **not** a new filesystem crawler, executor, cleanup controller, scheduler, or substitute for the existing tools. It classifies a **caller-supplied, sanitized JSON snapshot**, which it does not independently collect, authenticate or sign.

## Verified boundary / reason for this addition

The original `C:\SZL\EstateOps\disk-hygiene\2026-11-17` evidence directory was missing when observed on BETTERWITHAGE on November 19 and again November 20, 2026. The associated [custody incident #387](https://github.com/szl-holdings/szl-org-health/issues/387) remains open, despite [read-only locator PR #388](https://github.com/szl-holdings/szl-org-health/pull/388) merging. Nine Khipu/energy ledger file paths have **no independently validated surviving copy**. Missing original receipts must never be replaced with backdated guesses.

At 2026-11-20 05:21:01.3176306Z and 05:21:08.3678508Z, a bounded, read-only Desktop Commander observation measured C: total **1,021,821,579,264 bytes**, free **688,198,332,416** and **688,198,324,224** bytes, respectively; no large depletion occurred in the seven-second window. Three known small scan error logs remained under `C:\SZL\scratch`, their owners unverified. An earlier Edge Crashpad report path was unavailable. These observations do not prove the path was deleted or moved, or that the prior high-volume crash mechanism has stopped. No disposable cache was verified.

## Privacy and authority

- Input permits only a small number of UTC disk byte observations, process **name / PID / working-set bytes**, scratch opaque IDs / byte sizes / owner-claim state, and optional bounded cache byte-growth metadata. It rejects process command lines, file paths, prompts, tokens and unexpected fields; it does not open or inspect them.
- `historical.state=UNAVAILABLE` means no historical delta is calculated; `historical_drop_bytes=null` is intentionally not zero. A supplied prior reading needs a reference and comparable UTC/capacity, but **the tool does not verify any upstream signature**. Its state is `UPSTREAM_ASSERTED_NOT_CRYPTOGRAPHICALLY_CHECKED`, never independently authenticated. It is an alert hint, not release evidence.
- A sampled free space below **50 GiB**, a supplied historical drop of at least **5 GiB**, a free-space decline of **2 GiB** within **120 seconds**, an independently *supplied* same-cache growth of at least **2 GiB** within **600 seconds**, or any existent scratch/error item whose ownership remains unverified yields an alert. Short-term volume depletion is expressly **unattributed**, not automatically a cache fault. The growth flags are hints; the caller must prove collection and object identity separately.
- No cache is classified disposable. `cleanup_authorized`, `training_or_release_authorized`, `cache_disposable_confirmed`, `baseline_signature_independently_verified`, and `cache_growth_claim_independently_verified` are always false. No private keys, Docker/WSL disks, pagefiles, OneDrive, signed receipts, model weights, Hugging Face cache, Git worktrees or user files may be altered by this tool.
- CLI takes a single explicitly supplied JSON file, refuses symlinks/junctions, protected path components, duplicate JSON keys, NaN, oversized inputs and schema errors. It writes no output file, posts no notification and performs no network or provider call. Exit codes: **0** no trigger in supplied metadata (not a health certificate); **2** alert for human review; **3** malformed or unavailable input (HOLD).

## Example invocation (only with a sanitized operator-generated JSON input)

```powershell
python -B tools\disk_agent_hygiene_gate.py --input C:\SZL\approved-observations\disk-agent-20261120.json
python -B -m unittest discover -s tests -p test_disk_agent_hygiene_gate.py -v
```

The `approved-observations` path is an **example of a future authorized input**, not a claim that such a folder exists or that the lost November 17 evidence has been recovered. Do not create or populate the old `C:\SZL\EstateOps` path from this note. Any future persistent captures must use a distinct owner-approved path, exclusive creation, exact-byte readback, independent durable copy and separate authentication; use the existing source-owned bridge receipt writer only where its operator/daemon is actually installed.

## Next safety decision

Perform an owner-authorized **read-only evidence custody search** using exact historical receipt digests/sizes and existing approved roots, once those digests are independently sourced. Preserve the three unknown-owner scratch logs until their producer and purpose are verified. Do not alter services, restart agents, reclaim disk, or merge this tool without its normal CI and independent review. This module does not by itself resolve incident #387 or #382.

## Proposed Windows stdin sensor (review required; not installed)

`tools/windows_disk_agent_hygiene_observer.ps1` takes two read-only, time-spaced
C: readings and collects only name/PID/working-set process metadata plus file
size/existence of three specifically allowlisted scratch logs. It deliberately
marks historical custody as `UNAVAILABLE`: finding a newer bridge preflight
receipt is **not** authentication of the missing November 17 originals. Cache
growth is `UNOBSERVED`, not a guessed zero. No process commands, dump bytes,
profile cookies, private keys or model weights are accessed.

After source review, on authorized BETTERWITHAGE with an approved, source-pinned
checkout (none was verified at `C:\SZL\repos\szl-org-health` during the
November 20 check), operators can test a one-shot in-memory pipeline:

```powershell
$payload = & powershell.exe -NoProfile -NonInteractive -File tools\windows_disk_agent_hygiene_observer.ps1
if ($LASTEXITCODE -ne 0) { throw 'SENSOR_UNAVAILABLE' }
$payload | python -B tools\disk_agent_hygiene_gate.py --stdin
if ($LASTEXITCODE -ne 0) { throw 'TRIAGE_ALERT_OR_HOLD' }
```

`--stdin` is an additive bounded source to the existing strict classifier:
64 KiB maximum, identical duplicate-key/schema/privacy rejection, no file
creation, and exit 2 for a confirmed warning, 3 for malformed/unavailable
input. PowerShell observes no private command-line or task arguments. A blank
or failed sensor must never be interpreted as a healthy observation. When
executing the pipeline in production, ensure the collector's exit code is
checked separately (PowerShell pipelines can mask upstream failures).

The pipeline is NOT a watchdog installation, receipt signature, independently
verified trend or completed custody recovery. Source CI alone cannot prove the
runtime is installed. Do not enable disabled historic Windows disk-steward or
scratch-cleanup tasks: their safe execution has not been independently proven.
No scheduling/installation changes are contained in this candidate PR.
