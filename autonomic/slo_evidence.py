"""Publish the recorded SLO causes and preserve its fail-closed workflow result."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any, Sequence

from autonomic.slo_controller import RECEIPT_SCHEMA, canonical_json, sha256_hex


def evidence_text(value: Any) -> str:
    """Keep receipt fields on one escaped Markdown/log line."""
    text = " ".join(str(value).split())
    return html.escape(text).replace("|", "&#124;").replace("`", "&#96;")


def load_receipt(path: Path, exit_code: str) -> dict[str, Any]:
    report = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or report.get("schema") != RECEIPT_SCHEMA:
        raise ValueError("invalid receipt schema")
    digest = sha256_hex(canonical_json({
        key: value for key, value in report.items() if key != "receipt_sha256"
    }))
    if report.get("receipt_sha256") != digest:
        raise ValueError("invalid receipt digest")
    if path.with_suffix(path.suffix + ".sha256").read_text(encoding="ascii").strip() != digest:
        raise ValueError("invalid receipt sidecar")
    verdict = report.get("verdict")
    if (exit_code, verdict) not in {("0", "HEALTHY"), ("2", "INCIDENT")}:
        raise ValueError("controller result and receipt disagree or failed")
    reasons = report.get("reasons")
    surfaces = report.get("surfaces")
    deadman = report.get("deadman")
    if not isinstance(reasons, list) or not all(isinstance(item, str) for item in reasons):
        raise ValueError("invalid reasons")
    if not isinstance(surfaces, list) or not surfaces or not all(isinstance(row, dict) for row in surfaces):
        raise ValueError("invalid surfaces")
    if not isinstance(deadman, dict):
        raise ValueError("invalid deadman")
    if verdict == "HEALTHY":
        if report.get("severity") is not None or reasons or deadman.get("ok") is not True:
            raise ValueError("contradictory healthy receipt")
        if any(row.get("current_ok") is not True or row.get("severity") is not None for row in surfaces):
            raise ValueError("contradictory healthy surface")
    elif report.get("severity") not in {"SEV1", "SEV2", "SEV3"} or not reasons:
        raise ValueError("incident has no cause")
    return report


def render_summary(report: dict[str, Any]) -> str:
    lines = [
        "# SZL Autonomic SLO",
        "",
        f"- Verdict: `{evidence_text(report['verdict'])}`",
        f"- Severity: `{evidence_text(report.get('severity') or 'NONE')}`",
        f"- Deadman: `{evidence_text(report['deadman'].get('state', 'UNKNOWN'))}`",
        f"- Incident action: `{evidence_text((report.get('incident') or {}).get('action', 'UNKNOWN'))}`",
        f"- Receipt SHA-256: `{report['receipt_sha256']}`",
        "",
        "Current reachability and rolling reliability objectives are separate observations.",
        "A current UP probe does not clear retained error-budget burn.",
        "",
        "## Recorded verdict reasons",
        "",
    ]
    lines.extend(f"- {evidence_text(reason)}" for reason in report["reasons"])
    if not report["reasons"]:
        lines.append("- No incident reasons recorded for this cycle.")
    lines.extend([
        "",
        "| Surface | Current | Provider blocker | Max latency | Severity |",
        "|---|---|---|---:|---|",
    ])
    for row in report["surfaces"]:
        lines.append(
            f"| {evidence_text(row.get('id'))} | {'UP' if row.get('current_ok') else 'DOWN'} | "
            f"{evidence_text(row.get('provider_blocker') or 'NONE')} | "
            f"{evidence_text(row.get('maximum_latency_ms', 'UNKNOWN'))} ms | "
            f"{evidence_text(row.get('severity') or 'NONE')} |"
        )
    lines.extend([
        "",
        "| Surface | Window | Availability % | Burn | Samples observed / expected | Coverage % | Sufficient coverage |",
        "|---|---|---:|---:|---:|---:|---|",
    ])
    for row in report["surfaces"]:
        for window in row.get("windows", []):
            values = [row.get("id"), window.get("name"), window.get("availability_percent"),
                      window.get("error_budget_burn"),
                      f"{window.get('observed_samples')} / {window.get('expected_samples')}",
                      window.get("coverage_percent"), window.get("sufficient_coverage")]
            lines.append("| " + " | ".join(evidence_text(value) for value in values) + " |")
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--exit-code", default="")
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args(argv)
    try:
        report = load_receipt(args.report, args.exit_code)
        summary = render_summary(report)
        result = int(args.exit_code)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        summary = (
            "# SZL Autonomic SLO\n\n"
            "- Verdict: `FAILED`\n"
            "- SLO evidence is missing, malformed, inconsistent, or the controller failed closed.\n"
            "- Reliability is unverified; no healthy result or persisted incident is claimed.\n"
        )
        result = 1
    # Prefix each line so receipt data cannot become a workflow command.
    for line in summary.splitlines():
        print(f"SLO evidence: {line}")
    if args.summary:
        try:
            with args.summary.open("a", encoding="utf-8") as stream:
                stream.write(summary)
        except OSError:
            print("SLO evidence: FAILED to persist the workflow summary.")
            return 1
    if result == 2:
        print("::error title=SLO reliability incident::Recorded reliability objectives failed; see reasons and rolling windows above.")
    elif result == 1:
        print("::error title=SLO evidence failed closed::Reliability evidence could not be verified.")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
