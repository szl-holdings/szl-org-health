#!/usr/bin/env python3
"""Read-only public Space witness. Reachability is not release qualification.

Enumerates bounded public HF metadata, uses GET only, and records a distinct
Github main SHA, HF Space revision and *self-declared* served A11oy source.
No login, private data, provider writes, deployment, readiness promotion,
model execution, countersignatures, or claims of independent runtime proof.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import re
import sys
import urllib.error
import urllib.request
from typing import Any

ORG = "SZLHOLDINGS"
INDEX = "https://huggingface.co/api/spaces?author=SZLHOLDINGS&limit=100"
GITHUB_MAIN = "https://api.github.com/repos/szl-holdings/a11oy/commits/main"
SHA = re.compile(r"[0-9a-f]{40}\Z")
SPACE = re.compile(r"SZLHOLDINGS/[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
SAMPLED_ROUTES = frozenset({
    "a11oy", "killinchu", "counsel", "terra", "sentra", "finance",
    "lyte", "vertical-services", "anatomy", "david-leads", "immune",
    "yarqa", "nexus", "szl-constellation", "szl-frontier",
    "szl-forge-lab", "szl-model-inference-lab", "szl-second-brain",
    "agents-studio", "szl-science-gate-studio",
})
USER_AGENT = {"User-Agent": "SZL-public-readonly-space-witness/1"}
MAX_REPO_DETAIL_BYTES = 1_000_000
MAX_RESPONSE_BYTES = 12_000


def get(url: str, *, max_bytes: int = MAX_RESPONSE_BYTES, timeout: int = 8) -> dict[str, Any]:
    """Bound one anonymous GET; HTTP error codes are observations, not absence."""
    if max_bytes < 1 or max_bytes > MAX_REPO_DETAIL_BYTES:
        raise ValueError("invalid response size")
    try:
        req = urllib.request.Request(url, headers=USER_AGENT, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(max_bytes + 1)
            if len(body) > max_bytes:
                return {"http": resp.status, "error": "BODY_LIMIT", "body": None}
            return {"http": resp.status, "error": None, "body": body}
    except urllib.error.HTTPError as exc:
        return {"http": exc.code, "error": "HTTP_ERROR", "body": None}
    except (OSError, ValueError, TimeoutError) as exc:
        return {"http": None, "error": type(exc).__name__, "body": None}


def get_object(url: str, *, max_bytes: int = MAX_RESPONSE_BYTES) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    result = get(url, max_bytes=max_bytes)
    raw = result["body"]
    if result["http"] != 200 or raw is None:
        return None, result
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        return None, {**result, "error": "INVALID_JSON", "body": None}
    if not isinstance(data, dict):
        return None, {**result, "error": "JSON_OBJECT_REQUIRED", "body": None}
    return data, result


def revision(value: Any) -> str | None:
    return value if isinstance(value, str) and SHA.fullmatch(value) else None


def runtime_url(space_id: str, sdk: str | None, subdomain: str | None = None) -> str:
    if not isinstance(space_id, str) or not SPACE.fullmatch(space_id):
        raise ValueError("untrusted Space ID")
    derived = space_id.lower().replace("/", "-")
    host = subdomain if subdomain is not None else derived
    # Non-DNS Space names cannot be safely normalized by guessing hyphens.
    if not isinstance(host, str) or not HOST_LABEL.fullmatch(host):
        raise ValueError("Hub subdomain is missing or invalid")
    suffix = ".static.hf.space" if sdk == "static" else ".hf.space"
    return f"https://{host}{suffix}"


def probe_space(index_item: dict[str, Any]) -> dict[str, Any]:
    sid = index_item.get("id")
    result: dict[str, Any] = {
        "id": sid if isinstance(sid, str) else None,
        "metadata_http": None, "metadata_error": None,
        "runtime_stage": "UNKNOWN", "space_revision": None,
        "runtime_revision": None, "revision_match": "UNKNOWN",
        "sdk": None, "source_repo_declared": None,
        "root_http": None, "readyz_http": None,
        "reachability": "UNAVAILABLE", "release_qualified": False,
    }
    if not isinstance(sid, str) or not SPACE.fullmatch(sid):
        result["metadata_error"] = "INVALID_ID"
        return result
    info, witness = get_object(
        f"https://huggingface.co/api/spaces/{sid}",
        max_bytes=MAX_REPO_DETAIL_BYTES,
    )
    result["metadata_http"] = witness["http"]
    result["metadata_error"] = witness["error"]
    if info is None:
        return result
    runtime = info.get("runtime")
    runtime = runtime if isinstance(runtime, dict) else {}
    card = info.get("cardData")
    card = card if isinstance(card, dict) else {}
    sdk = info.get("sdk") or card.get("sdk")
    if not isinstance(sdk, str):
        result["metadata_error"] = "SDK_UNAVAILABLE"
        return result
    result["sdk"] = sdk
    result["runtime_stage"] = runtime.get("stage") if isinstance(runtime.get("stage"), str) else "UNKNOWN"
    result["space_revision"] = revision(info.get("sha"))
    result["runtime_revision"] = revision(runtime.get("sha"))
    if result["space_revision"] and result["runtime_revision"]:
        result["revision_match"] = (
            "MATCHED_REPOSITORY_AND_RUNTIME_METADATA"
            if result["space_revision"] == result["runtime_revision"]
            else "REPOSITORY_RUNTIME_REVISION_DRIFT"
        )
    source = card.get("source_repo")
    if isinstance(source, str) and re.fullmatch(
        r"https://github[.]com/szl-holdings/[A-Za-z0-9_.-]+/?", source
    ):
        result["source_repo_declared"] = source
    try:
        base = runtime_url(sid, sdk, info.get("subdomain"))
    except ValueError:
        result["metadata_error"] = "RUNTIME_URL_UNAVAILABLE"
        return result
    result["root_http"] = get(base + "/", max_bytes=128, timeout=7)["http"]
    result["reachability"] = "HTTP_200" if result["root_http"] == 200 else "NOT_HTTP_200_OR_UNKNOWN"
    if sid.split("/", 1)[1] in SAMPLED_ROUTES and sdk != "static":
        # HTTP status only; 404 can mean an intentionally unimplemented route.
        result["readyz_http"] = get(base + "/readyz", max_bytes=128, timeout=7)["http"]
    return result


def a11oy_source_witness(row: dict[str, Any] | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "github_main_sha": None, "github_main_http": None,
        "served_source_declared": None, "served_source_http": None,
        "space_revision": row.get("space_revision") if row else None,
        "telemetry_http": None, "release_authority": "NOT_PROVEN",
        "independent_runtime_verification": False,
        "source_claim_state": "UNAVAILABLE",
    }
    # Do not spend a GitHub request when the HF index lacks this Space.
    if row is None:
        return result
    gh, status = get_object(GITHUB_MAIN, max_bytes=24_000)
    result["github_main_http"] = status["http"]
    if gh is not None:
        result["github_main_sha"] = revision(gh.get("sha"))
    if row is None or row.get("sdk") == "static" or row.get("metadata_error"):
        return result
    base = runtime_url("SZLHOLDINGS/a11oy", row["sdk"])
    served, witness = get_object(base + "/api/a11oy/v1/honest", max_bytes=20_000)
    result["served_source_http"] = witness["http"]
    if served is not None:
        result["served_source_declared"] = revision(served.get("git_sha"))
    result["telemetry_http"] = get(base + "/api/a11oy/v1/telemetry/summary", max_bytes=128)["http"]
    observed, declared = result["github_main_sha"], result["served_source_declared"]
    if observed is not None and declared is not None:
        result["source_claim_state"] = (
            "DECLARED_MATCH_NOT_BYTE_ATTESTED"
            if observed == declared else "DECLARED_MISMATCH"
        )
    return result


def census() -> dict[str, Any]:
    fetched = get(INDEX, max_bytes=MAX_REPO_DETAIL_BYTES, timeout=15)
    snapshot = {
        "schema": "szl.public-space-runtime-witness/v1",
        "time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "index_http": fetched["http"], "index_error": fetched["error"],
        "pagination_complete": False, "space_count": None,
        "spaces": [], "a11oy": a11oy_source_witness(None),
        "production_qualified": False,
    }
    if fetched["http"] != 200 or fetched["body"] is None:
        return snapshot
    try:
        items = json.loads(fetched["body"].decode("utf-8"))
    except (UnicodeError, ValueError):
        snapshot["index_error"] = "INVALID_INDEX_JSON"
        return snapshot
    if not isinstance(items, list) or any(not isinstance(i, dict) for i in items):
        snapshot["index_error"] = "INVALID_INDEX_SHAPE"
        return snapshot
    if len(items) >= 100:
        snapshot["index_error"] = "PAGINATION_INCOMPLETE"
        return snapshot
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        rows = list(executor.map(probe_space, items))
    snapshot["pagination_complete"] = True
    snapshot["space_count"] = len(rows)
    snapshot["spaces"] = rows
    target = next((r for r in rows if r.get("id") == "SZLHOLDINGS/a11oy"), None)
    snapshot["a11oy"] = a11oy_source_witness(target)
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="-", help="JSON report file or '-' for stdout")
    args = parser.parse_args(argv)
    report = census()
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        sys.stdout.write(payload)
    else:
        # Local evidence only. No provider writes.
        from pathlib import Path
        Path(args.output).write_text(payload, encoding="utf-8")
        print(f"wrote {args.output}; source_claim={report['a11oy']['source_claim_state']}")
    return 0 if report["pagination_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
