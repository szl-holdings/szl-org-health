#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Retain INCOMPLETE evidence when the existing collector emitted no receipt.

This is a failure finalizer, not a collector or a credential fallback. Existing
reports are never overwritten or reclassified. The workflow must still enforce
the original collection outcome after retaining these artifacts. Job cancellation
or runner loss can prevent finalization; absence must remain UNKNOWN to observers.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from census import file_audit as audit
from tools.run_repository_file_audit import failure_report

PRIVATE_NAME = "repository-file-audit.private.json"
PUBLIC_NAME = "repository-file-audit.public.json"
FAILED_OUTCOMES = ("failure", "cancelled", "skipped")


def ensure_failure_receipts(directory: Path, outcome: str) -> str:
    """Use the canonical failure schema/projector, without any network operation.

    A zero verified-work count is not a zero organization-population claim.
    Paths come from the workflow, never a remote request. The directory must
    already exist and be owned by the runner. Exclusive creation preserves any
    report appearing between the initial existence check and the actual write.
    """
    if outcome not in FAILED_OUTCOMES:
        raise ValueError("only unsuccessful collection outcomes are accepted")
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("existing non-symlink output directory required")
    paths = (directory / PRIVATE_NAME, directory / PUBLIC_NAME)
    if any(path.is_symlink() for path in paths):
        raise ValueError("receipt symlinks are not accepted")
    present = tuple(path.exists() for path in paths)
    if all(present):
        if not all(path.is_file() for path in paths):
            raise ValueError("existing receipt paths must be regular files")
        # Preservation is not validation or success. Original failure stays red.
        return "EXISTING_EVIDENCE_PRESERVED"
    if any(present):
        raise ValueError("partial receipt pair preserved; manual reconciliation required")

    report = failure_report(
        org=audit.DEFAULT_ORG,
        reason="COLLECTION_ENDED_WITHOUT_FILE_AUDIT_RECEIPT",
        reconciliation={"authoritative_count_available": False, "matched": False},
    )
    # This step does not receive the selector's credentials. Do not infer that
    # the collector had no credential merely because this finalizer has none.
    report["source"]["credential_present"] = None
    report["source"]["collector_outcome"] = outcome
    report["source"]["organization_population"] = None
    report["source"]["verified_work_counts_are_population"] = False
    report["source"]["finalizer"] = "MISSING_RECEIPT_FAILURE_ONLY"
    report.pop("receipt_sha256", None)
    report["receipt_sha256"] = audit.sha256_json(report)
    public = audit.public_projection(report)
    # Serialize both before creating either. Partial filesystem writes still
    # raise, never return a PASS or destroy already-retained bytes.
    encoded = tuple(json.dumps(item, indent=2, sort_keys=True, allow_nan=False) + "\n"
                    for item in (report, public))
    for path, content in zip(paths, encoded):
        with path.open("x", encoding="utf-8") as handle:
            handle.write(content)
    return "INCOMPLETE_RECEIPTS_RETAINED"


def run(argv: Sequence[str] | None = None, *, log: TextIO = sys.stderr) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--collect-outcome", required=True, choices=FAILED_OUTCOMES)
    args = parser.parse_args(argv)
    try:
        state = ensure_failure_receipts(args.directory, args.collect_outcome)
    except (OSError, ValueError, TypeError, KeyError):
        # Never persist exception text, candidate credentials, or path details.
        print("file-audit-finalizer state=FAILED reason=RECEIPT_RETENTION_FAILED", file=log)
        return 2
    print(f"file-audit-finalizer state={state} collection_success=false", file=log)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
