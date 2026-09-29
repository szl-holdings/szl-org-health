"""Collect three real SLO observations and independently verify every retained result."""

from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Sequence

from autonomic.slo_controller import ContractError, load_policy, parse_time
from autonomic.slo_evidence import load_receipt, render_summary


SAMPLE_COUNT = 3
SAMPLING_SCHEMA = "szl.autonomic-slo-sampling/v1"
CYCLE_TIMEOUT_SECONDS = 60
SAMPLING_BUDGET_SECONDS = 780


def sampling_policy(policy_path: Path) -> tuple[int, str]:
    policy, digest = load_policy(policy_path)
    cadence = policy["cadence_minutes"] * 60
    # The scheduled job has a fifteen-minute budget, including setup and upload.
    if cadence != 300:
        raise ValueError("sampling cadence exceeds the bounded job contract")
    return cadence, digest


def write_new(path: Path, value: str) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(value)


def run_controller(argv: Sequence[str], *, timeout: float) -> int:
    """A subprocess deadline also bounds a controller blocked in network I/O."""
    return subprocess.run(
        [sys.executable, "-B", "-m", "autonomic.slo_controller", *argv],
        timeout=timeout,
        check=False,
    ).returncode


def observe(
    output_dir: Path,
    policy_path: Path,
    *,
    controller: Callable[..., int] = run_controller,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    cadence, policy_digest = sampling_policy(policy_path)
    # A fresh directory prevents a rerun from replacing or mixing retained evidence.
    output_dir.mkdir(parents=True, exist_ok=False)
    origin = monotonic()
    budget_deadline = origin + SAMPLING_BUDGET_SECONDS
    cycles = []
    previous_finished = None
    for number in range(1, SAMPLE_COUNT + 1):
        if previous_finished is not None:
            next_sample = previous_finished + cadence
            while (remaining := min(next_sample, budget_deadline) - monotonic()) > 0:
                sleep(remaining)
        started = monotonic()
        timeout = min(CYCLE_TIMEOUT_SECONDS, budget_deadline - started)
        status = "completed"
        if timeout <= 0:
            write_new(output_dir / f"sample-{number}.exit-code", "1\n")
            cycles.append({
                "number": number,
                "started_seconds": started - origin,
                "finished_seconds": started - origin,
                "status": "deadline_exceeded",
                "timeout_seconds": 0,
            })
            break
        try:
            result = controller([
                "--policy", str(policy_path),
                "--output", str(output_dir / f"sample-{number}.json"),
            ], timeout=timeout)
        except subprocess.TimeoutExpired:
            result = 1
            status = "timed_out"
        except Exception:
            result = 1
            status = "controller_failed"
        finished = monotonic()
        if type(result) is not int or result not in (0, 1, 2):
            result = 1
        if finished > budget_deadline:
            result = 1
            status = "deadline_exceeded"
        elif finished - started > timeout:
            result = 1
            status = "timed_out"
        elif result == 1 and status == "completed":
            status = "controller_failed"
        # Exit/status evidence never substitutes for a missing or partial receipt.
        write_new(output_dir / f"sample-{number}.exit-code", f"{result}\n")
        cycles.append({
            "number": number,
            "started_seconds": started - origin,
            "finished_seconds": finished - origin,
            "status": status,
            "timeout_seconds": timeout,
        })
        previous_finished = finished
    write_new(output_dir / "sampling.json", json.dumps({
        "schema": SAMPLING_SCHEMA,
        "policy_sha256": policy_digest,
        "cadence_seconds": cadence,
        "cycle_timeout_seconds": CYCLE_TIMEOUT_SECONDS,
        "budget_seconds": SAMPLING_BUDGET_SECONDS,
        "cycles": cycles,
    }, indent=2) + "\n")
    return verify(output_dir, policy_path)[0]


def verify(
    output_dir: Path,
    policy_path: Path,
    *,
    exit_code: str | None = None,
) -> tuple[int, str]:
    summaries = ["# SZL Autonomic SLO sampling batch\n"]
    invalid = False
    incident = False
    cadence = None
    policy_digest = None
    try:
        cadence, policy_digest = sampling_policy(policy_path)
        policy, _ = load_policy(policy_path)
        manifest = json.loads((output_dir / "sampling.json").read_text(encoding="utf-8"))
        if (manifest.get("schema") != SAMPLING_SCHEMA
                or manifest.get("policy_sha256") != policy_digest
                or manifest.get("cadence_seconds") != cadence
                or manifest.get("cycle_timeout_seconds") != CYCLE_TIMEOUT_SECONDS
                or manifest.get("budget_seconds") != SAMPLING_BUDGET_SECONDS):
            raise ValueError("invalid sampling contract")
        cycles = manifest["cycles"]
        if not isinstance(cycles, list) or len(cycles) != SAMPLE_COUNT:
            raise ValueError("incomplete sampling batch")
        previous_finished = None
        for number, cycle in enumerate(cycles, 1):
            if type(cycle.get("number")) is not int or cycle.get("number") != number:
                raise ValueError("invalid sampling order")
            start, finish = cycle["started_seconds"], cycle["finished_seconds"]
            if any(type(value) not in (int, float) or not math.isfinite(value)
                   or value < 0 for value in (start, finish)):
                raise ValueError("invalid sampling clock")
            if finish < start or (previous_finished is not None
                                   and start < previous_finished + cadence):
                raise ValueError("samples were not spaced at the governed cadence")
            timeout = cycle.get("timeout_seconds")
            if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                    or timeout <= 0 or timeout > CYCLE_TIMEOUT_SECONDS
                    or timeout > SAMPLING_BUDGET_SECONDS - start
                    or finish > SAMPLING_BUDGET_SECONDS
                    or finish - start > timeout
                    or cycle.get("status") != "completed"):
                raise ValueError("sampling deadline or controller failure")
            previous_finished = finish
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ContractError):
        summaries.append("- FAILED: sampling completion, cadence, or deadline evidence is missing or invalid.\n")
        invalid = True
        policy_digest = None

    seen_ids: set[str] = set()
    seen_receipts: set[str] = set()
    seen_observations: set[str] = set()
    previous_time = None
    source = None
    for number in range(1, SAMPLE_COUNT + 1):
        try:
            path = output_dir / f"sample-{number}.json"
            code = (output_dir / f"sample-{number}.exit-code").read_text(encoding="ascii").strip()
            report = load_receipt(path, code)
            cycle_id = report.get("cycle_id")
            observed_at = parse_time(report.get("generated_at"))
            revision = report.get("controller_revision")
            manifest_revision = report.get("manifest_revision")
            manifest_digest = report.get("manifest_sha256")
            receipt_digest = report.get("receipt_sha256")
            observation_digest = report.get("observation_sha256")
            observed_source = (revision, manifest_revision, manifest_digest)
            if (not isinstance(cycle_id, str) or not cycle_id or cycle_id in seen_ids
                    or observed_at is None
                    or policy_digest is None or cadence is None
                    or (previous_time is not None
                        and (observed_at - previous_time).total_seconds() < cadence)
                    or report.get("policy_sha256") != policy_digest
                    or report.get("controller_repository") != policy["controller_repository"]
                    or report.get("manifest_repository") != policy["source_manifest"]["repository"]
                    or not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision)
                    or not isinstance(manifest_revision, str) or not re.fullmatch(r"[0-9a-f]{40}", manifest_revision)
                    or not isinstance(manifest_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", manifest_digest)
                    or not isinstance(observation_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", observation_digest)
                    or receipt_digest in seen_receipts or observation_digest in seen_observations
                    or (source is not None and observed_source != source)):
                raise ValueError("duplicate or inconsistent observation")
            seen_ids.add(cycle_id)
            seen_receipts.add(receipt_digest)
            seen_observations.add(observation_digest)
            previous_time = observed_at
            source = observed_source
            incident = incident or code == "2"
            summaries.append(f"## Observation {number}\n\n{render_summary(report)}")
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            summaries.append(f"- FAILED: observation {number} or its exit code, digest, or sidecar is invalid.\n")
            invalid = True
    result = 1 if invalid else 2 if incident else 0
    if exit_code is not None and exit_code != str(result):
        summaries.append("- FAILED: sampler exit code disagrees with retained evidence.\n")
        result = 1
    summaries.insert(1, f"- Batch result: `{'FAILED' if result == 1 else 'INCIDENT' if result == 2 else 'HEALTHY'}`\n")
    return result, "\n".join(summaries)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path("autonomic/slo_policy.json"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--exit-code")
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args(argv)
    try:
        if not args.verify_only:
            return observe(args.output_dir, args.policy)
        result, summary = verify(args.output_dir, args.policy,
                                 exit_code=args.exit_code if args.exit_code is not None else "")
        for line in summary.splitlines():
            print(f"SLO sampling evidence: {line}")
        if args.summary:
            with args.summary.open("a", encoding="utf-8") as stream:
                stream.write(summary + "\n")
        if result:
            print("::error title=SLO sampling failed closed::One or more observations failed; see retained batch evidence.")
        return result
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ContractError):
        print("SLO sampling evidence: FAILED to collect or verify a complete sampling batch.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
