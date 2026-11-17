# SZL Local Storage Admission — v1

**Authority:** this is a read-only capacity **precheck**, not a disk-cleaning agent, durable reservation service, production readiness certificate or permission to run any workload. Canonical GitHub source is `tools/szl_storage_admission.py` (Python 3.11+, standard library). It is intentionally separate from the historical PowerShell recovery scripts and public org-health dashboard.

## Why this exists

Multiple local build, Lean and model workers can simultaneously consume one disk. A healthy observation at one instant cannot authorize an unbounded future job. Admission has two separate inputs: a declared **maximum additional job consumption** and the **minimum free-space floor that must remain**.

By default the check requires **50 GiB** post-budget residual headroom and labels below **20 GiB** as critical. All accounting uses binary GiB (2^30 bytes), not decimal GB. Budget requests accept up to three decimal digits and round *up* to bytes. A positive budget must be explicitly declared; zero, absent, NaN, negative, ambiguous and unbounded values never admit a job.

## Run it explicitly

Windows PowerShell, from the repository:

~~~powershell
# Observe without claiming that any job is safe.
python -I tools/szl_storage_admission.py --mode observe --drive "C:/"

# Check a declared additional 8-GiB workload, sampling at a 2-second interval.
python -I tools/szl_storage_admission.py --mode admit --drive "C:/" --reserve-gib 8

# Request a 16-GiB build with a five-second measurement window.
python -I tools/szl_storage_admission.py --mode admit --drive "C:/" --reserve-gib 16 --sample-seconds 5
~~~

Linux equivalent: `--drive /`. CI tests synthetic observations and may observe its own runner, but must never represent that runner's capacity as the user's C: capacity.

## Explicit contract

- Two OS `shutil.disk_usage` observations by default, with 0–10 seconds between them. Choose **minimum observed free bytes**, never the more optimistic reading. Impossible geometry (used + available > total), changing disk totals or an unavailable sensor is an error and no admission occurs. POSIX root-reserved blocks are recorded as unavailable, not wrongly counted as user free space.
- `ADMIT_PRECHECK_ONLY` means the minimum observed free bytes **minus the declared additional budget** are still at or above the headroom floor. Otherwise return `HOLD` with a specific reason. Below-critical and below-floor conditions take precedence. `--mode observe` always returns `NOT_REQUESTED` for a successful observation, never `ADMIT`.
- CLI exit **0** means a completed observation or admitted precheck, depending on `mode`. Exit **2** means an actual admission was rejected; **3** means inputs or measurements were invalid or unavailable. Callers must check both exit code and structured `decision`; an observation exit 0 must not be confused with job approval.
- Output is a source-linked JSON receipt with raw byte readings, conservative minimum, declared budget bytes, thresholds, UTC timestamp, this implementation's SHA-256 and canonical domain-separated receipt SHA-256. **The digest is not a signature or proof of future capacity**.
- The receipt states `automatic_deletion=false`, `lease_or_reservation_established=false`, `concurrent_writer_exclusion_established=false`, `future_capacity_guaranteed=false`, `remote_production_readiness_established=false`. The checker neither reads personal data, models nor credentials, nor writes files or changes OS settings.

## Operational boundary

Run the preflight before any sizable SZL-authorized local model download, training, Lean rebuild, package install or burst of agent checkouts, and honor its return code. Recheck during/after long-running jobs. **This tool does not intercept jobs that bypass it.** The declared budget is not measured consumption; it is the caller's stated maximum. Competing writers can race immediately after success.

True cross-agent disk scheduling requires an authenticated owner/worker registry, atomic reservation ledger, lease/heartbeat expiry, PID and process-start identity, cancellation controls and signed admission/release evidence. **Those are not implemented**. In particular, do not unblock the historical `tools/SZL_DISK_CLEAN_RESUME_PS51_V13.ps1` script; its intentional `SZL_SOURCE_ADMISSION_HOLD` also guards potentially privileged Windows/hibernation actions. This feature never changes that boundary.

## Reproducibility

Run `python -m unittest discover -s tests -p test_storage_admission.py -v`. The 25 cases cover exact GiB math, threshold crossings, two-sample minimum, source/receipt checksum, malformed observations, unavailable disks and CLI behavior. The standard estate CI also compiles the module and runs these checks, separately from its production dashboard tests.

This repository does **not** embed a user's local machine paths, private cleanup journals, hardware credentials, current disk telemetry or archaeological datasets in its release artifacts. It is a reusable local source-control contract; operational live disk observations must be obtained from an authorized device at the moment of use.
