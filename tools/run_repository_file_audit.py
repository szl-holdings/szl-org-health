#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the private organization file audit behind an authoritative inventory gate.

The underlying collector intentionally remains reusable for bounded tests and local
inspection. This hosted entry point is stricter: it cannot claim full SZL estate
coverage unless GitHub exposes authoritative public and private repository totals,
the paginated inventory matches those totals exactly, the known estate floor is
met, and at least one private or internal repository is visible.

Both success and failure paths write machine-readable private and public receipts.
A missing organization credential therefore becomes durable INCOMPLETE evidence,
not an absent artifact or a partial green result.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from census import file_audit as audit


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _empty_summary() -> dict[str, Any]:
    return {
        "state": "INCOMPLETE",
        "state_counts": {"INCOMPLETE": 1},
        "severity_counts": {},
        "inspection_counts": {},
        "totals": {
            "repositories": 0,
            "entries": 0,
            "files": 0,
            "directories": 0,
            "submodules": 0,
            "bytes_tracked_and_verified": 0,
            "findings": 0,
        },
    }


def _safe_reconciliation(
    reconciliation: Mapping[str, Any] | None,
) -> dict[str, Any]:
    allowed = {
        "observed_repository_count",
        "observed_public_count",
        "observed_private_or_internal_count",
        "authoritative_count_available",
        "authoritative_expected_count",
        "matched",
        "error",
    }
    return {
        key: value
        for key, value in dict(reconciliation or {}).items()
        if key in allowed
    }


def failure_report(
    *,
    org: str,
    reason: str,
    reconciliation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a bounded failure receipt without private identities or secret values."""
    value: dict[str, Any] = {
        "schema": audit.SCHEMA,
        "observed_at": _now(),
        "organization": org,
        "source": {
            "credential_present": bool(audit.github_headers().get("Authorization")),
            "inventory_gate": "AUTHORITATIVE_PUBLIC_PLUS_PRIVATE_TOTALS_REQUIRED",
            "audit_semantics": (
                "no repository or file completeness claim is emitted before the "
                "authoritative inventory gate passes"
            ),
        },
        "inventory_reconciliation": _safe_reconciliation(reconciliation),
        "repositories": [],
        "summary": _empty_summary(),
        "failure": {
            "type": "AuditError",
            "message": reason[:480],
            "secret_values_recorded": False,
            "private_repository_names_recorded": False,
        },
    }
    value["receipt_sha256"] = audit.sha256_json(value)
    return value


def validate_authoritative_inventory(
    inventory: Sequence[Mapping[str, Any]],
    reconciliation: Mapping[str, Any],
    minimum_repositories: int,
) -> None:
    """Reject any inventory that cannot prove complete public and private coverage."""
    if reconciliation.get("authoritative_count_available") is not True:
        raise audit.AuditError(
            "authoritative organization public/private repository totals are unavailable"
        )
    if reconciliation.get("matched") is not True:
        raise audit.AuditError(
            "paginated repository inventory does not match authoritative organization totals"
        )
    if len(inventory) < minimum_repositories:
        raise audit.AuditError(
            f"repository inventory {len(inventory)} is below required minimum "
            f"{minimum_repositories}"
        )
    if int(reconciliation.get("observed_private_or_internal_count") or 0) < 1:
        raise audit.AuditError(
            "authoritative inventory did not expose any private/internal repository"
        )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", default=audit.DEFAULT_ORG)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument("--minimum-repositories", type=int, default=123)
    parser.add_argument("--max-workers", type=int, default=audit.DEFAULT_MAX_WORKERS)
    parser.add_argument("--max-text-bytes", type=int, default=audit.DEFAULT_MAX_TEXT_BYTES)
    parser.add_argument(
        "--max-archive-bytes",
        type=int,
        default=audit.DEFAULT_MAX_ARCHIVE_BYTES,
    )
    parser.add_argument(
        "--max-repository-bytes",
        type=int,
        default=audit.DEFAULT_MAX_REPOSITORY_BYTES,
    )
    return parser.parse_args(argv)


def run(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    reconciliation: dict[str, Any] = {}
    try:
        inventory, reconciliation = audit.list_repositories(args.org)
        validate_authoritative_inventory(
            inventory,
            reconciliation,
            args.minimum_repositories,
        )
        report = audit.run_audit(
            org=args.org,
            max_workers=args.max_workers,
            max_text_bytes=args.max_text_bytes,
            max_archive_bytes=args.max_archive_bytes,
            max_repository_bytes=args.max_repository_bytes,
            minimum_repositories=args.minimum_repositories,
            repository_provider=lambda _org: (list(inventory), dict(reconciliation)),
        )
    except audit.AuditError as exc:
        report = failure_report(
            org=args.org,
            reason=str(exc),
            reconciliation=reconciliation,
        )
        audit.write_json(args.output, report)
        audit.write_json(args.public_output, audit.public_projection(report))
        print(
            json.dumps(
                {
                    "state": "INCOMPLETE",
                    "error": str(exc)[:480],
                    "receipt_sha256": report["receipt_sha256"],
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    except Exception as exc:  # noqa: BLE001 - emit the exception class only
        reason = f"collector exception:{type(exc).__name__}"
        report = failure_report(
            org=args.org,
            reason=reason,
            reconciliation=reconciliation,
        )
        audit.write_json(args.output, report)
        audit.write_json(args.public_output, audit.public_projection(report))
        print(
            json.dumps(
                {
                    "state": "INCOMPLETE",
                    "error": reason,
                    "receipt_sha256": report["receipt_sha256"],
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2

    audit.write_json(args.output, report)
    audit.write_json(args.public_output, audit.public_projection(report))
    summary = report["summary"]
    print(
        json.dumps(
            {
                "state": summary["state"],
                "repositories": summary["totals"]["repositories"],
                "files": summary["totals"]["files"],
                "bytes_verified": summary["totals"]["bytes_tracked_and_verified"],
                "findings": summary["totals"]["findings"],
                "receipt_sha256": report["receipt_sha256"],
            },
            sort_keys=True,
        )
    )
    return 2 if summary["state"] == "INCOMPLETE" else 0


if __name__ == "__main__":
    raise SystemExit(run())
