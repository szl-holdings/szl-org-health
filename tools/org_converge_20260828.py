#!/usr/bin/env python3
"""Bounded, GitHub-native SZL organization convergence and recovery pass.

The executor inventories every repository visible to the governed organization
credential, aggregates the latest default-branch run per workflow, retries only
terminal failed runs, and records Hugging Face plus public-domain readback.
It never prints credentials and never depends on Replit.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ORG = "szl-holdings"
HF_ORG = "SZLHOLDINGS"
GH_API = "https://api.github.com"
FAILURE_CONCLUSIONS = {
    "action_required",
    "cancelled",
    "failure",
    "startup_failure",
    "timed_out",
}
PENDING_STATUSES = {"queued", "in_progress", "pending", "waiting", "requested"}
REPORT_JSON = Path("reports/org-convergence-20260828.json")
REPORT_MD = Path("reports/org-convergence-20260828.md")
MAX_BODY = 2_000_000


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_now() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def secret(name: str) -> str:
    return str(os.environ.get(name) or "").strip()


ORG_TOKEN = secret("ORG_TOKEN") or secret("SZL_GITHUB_TOKEN")
HF_TOKEN = secret("HF_TOKEN") or secret("HUGGING_FACE_HUB_TOKEN")
EXECUTE_RERUNS = secret("EXECUTE_RERUNS").lower() not in {"0", "false", "no"}


def json_headers(*, github: bool = False, hf: bool = False) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "szl-org-convergence/2026-08-28",
    }
    if github:
        headers.update(
            {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
        )
        if ORG_TOKEN:
            headers["Authorization"] = f"Bearer {ORG_TOKEN}"
    if hf and HF_TOKEN:
        headers["Authorization"] = f"Bearer {HF_TOKEN}"
    return headers


def request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    payload: bytes | None = None,
    timeout: float = 20.0,
    retries: int = 2,
) -> dict[str, Any]:
    last_error: str | None = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            url,
            data=payload,
            method=method,
            headers=headers or {},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                body = response.read(MAX_BODY + 1)
                if len(body) > MAX_BODY:
                    raise RuntimeError(f"response exceeded {MAX_BODY} bytes")
                return {
                    "ok": 200 <= response.status < 300,
                    "status": response.status,
                    "body": body,
                    "headers": {k.lower(): v for k, v in response.headers.items()},
                    "url": response.geturl(),
                    "error": None,
                }
        except urllib.error.HTTPError as exc:
            body = exc.read(MAX_BODY)
            last_error = f"HTTP {exc.code}"
            result = {
                "ok": False,
                "status": exc.code,
                "body": body,
                "headers": {k.lower(): v for k, v in exc.headers.items()},
                "url": exc.geturl(),
                "error": last_error,
            }
            if exc.code not in {408, 429, 500, 502, 503, 504} or attempt >= retries:
                return result
        except Exception as exc:  # fail closed, but preserve bounded evidence
            last_error = f"{type(exc).__name__}: {str(exc)[:240]}"
            if attempt >= retries:
                return {
                    "ok": False,
                    "status": None,
                    "body": b"",
                    "headers": {},
                    "url": url,
                    "error": last_error,
                }
        time.sleep(1.5 * (attempt + 1))
    return {
        "ok": False,
        "status": None,
        "body": b"",
        "headers": {},
        "url": url,
        "error": last_error or "request failed",
    }


def request_json(
    url: str,
    *,
    method: str = "GET",
    github: bool = False,
    hf: bool = False,
    payload: dict[str, Any] | None = None,
    timeout: float = 20.0,
    retries: int = 2,
) -> tuple[Any, dict[str, Any]]:
    raw_payload = None
    headers = json_headers(github=github, hf=hf)
    if payload is not None:
        raw_payload = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    result = request(
        url,
        method=method,
        headers=headers,
        payload=raw_payload,
        timeout=timeout,
        retries=retries,
    )
    if not result["body"]:
        return None, result
    try:
        return json.loads(result["body"].decode("utf-8")), result
    except Exception as exc:
        result["ok"] = False
        result["error"] = f"JSON decode failed: {type(exc).__name__}"
        return None, result


def gh(path: str, **kwargs: Any) -> tuple[Any, dict[str, Any]]:
    return request_json(f"{GH_API}{path}", github=True, **kwargs)


def gh_pages(path: str, *, item_key: str | None = None, max_pages: int = 20) -> tuple[list[Any], list[str]]:
    items: list[Any] = []
    errors: list[str] = []
    joiner = "&" if "?" in path else "?"
    for page in range(1, max_pages + 1):
        data, meta = gh(f"{path}{joiner}per_page=100&page={page}", timeout=25.0)
        if not meta["ok"]:
            errors.append(f"{path}: {meta['error'] or meta['status']}")
            break
        page_items = data.get(item_key) if item_key and isinstance(data, dict) else data
        if not isinstance(page_items, list):
            errors.append(f"{path}: malformed page {page}")
            break
        items.extend(page_items)
        if len(page_items) < 100:
            break
    else:
        errors.append(f"{path}: pagination capped at {max_pages} pages")
    return items, errors


def latest_per_workflow(runs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for run in runs:
        if not isinstance(run, dict):
            continue
        key = str(run.get("workflow_id") or run.get("name") or run.get("id") or "unknown")
        stamp = str(run.get("created_at") or run.get("run_started_at") or "")
        current = latest.get(key)
        current_stamp = str(
            (current or {}).get("created_at")
            or (current or {}).get("run_started_at")
            or ""
        )
        if current is None or stamp > current_stamp:
            latest[key] = run
    return latest


def protection_probe(repo: str, branch: str) -> dict[str, Any]:
    encoded_repo = urllib.parse.quote(repo, safe="")
    encoded_branch = urllib.parse.quote(branch, safe="")
    _, meta = gh(
        f"/repos/{ORG}/{encoded_repo}/branches/{encoded_branch}/protection",
        timeout=15.0,
        retries=1,
    )
    if meta["status"] == 200:
        state = "PROTECTED"
    elif meta["status"] == 404:
        state = "UNOBSERVED_OR_UNDER_SCOPED"
    else:
        state = "UNKNOWN"
    return {"state": state, "http_status": meta["status"], "error": meta["error"]}


def rerun_failed(repo: str, run: dict[str, Any]) -> dict[str, Any]:
    run_id = run.get("id")
    result = {
        "repository": repo,
        "workflow": run.get("name"),
        "run_id": run_id,
        "event": run.get("event"),
        "head_sha": run.get("head_sha"),
        "prior_conclusion": run.get("conclusion"),
        "requested": False,
        "http_status": None,
        "error": None,
    }
    if not EXECUTE_RERUNS:
        result["error"] = "EXECUTE_RERUNS disabled"
        return result
    if not isinstance(run_id, int):
        result["error"] = "run id unavailable"
        return result
    _, meta = gh(
        f"/repos/{ORG}/{urllib.parse.quote(repo, safe='')}/actions/runs/{run_id}/rerun-failed-jobs",
        method="POST",
        payload={},
        timeout=20.0,
        retries=1,
    )
    result["http_status"] = meta["status"]
    result["requested"] = meta["status"] in {201, 202}
    result["error"] = None if result["requested"] else meta["error"]
    return result


def github_inventory() -> dict[str, Any]:
    repos, errors = gh_pages(f"/orgs/{ORG}/repos?type=all&sort=full_name")
    records: list[dict[str, Any]] = []
    reruns: list[dict[str, Any]] = []
    observed_run_ids: set[int] = set()
    cutoff = utc_now() - dt.timedelta(days=30)
    stale_cutoff = utc_now() - dt.timedelta(hours=6)

    for raw_repo in sorted(
        (r for r in repos if isinstance(r, dict)),
        key=lambda item: str(item.get("name") or "").casefold(),
    ):
        name = str(raw_repo.get("name") or "")
        default_branch = str(raw_repo.get("default_branch") or "main")
        archived = bool(raw_repo.get("archived"))
        disabled = bool(raw_repo.get("disabled"))
        record: dict[str, Any] = {
            "name": name,
            "visibility": raw_repo.get("visibility") or ("private" if raw_repo.get("private") else "public"),
            "archived": archived,
            "disabled": disabled,
            "fork": bool(raw_repo.get("fork")),
            "default_branch": default_branch,
            "open_pull_requests": None,
            "workflow_count": None,
            "latest_default_branch_workflows": [],
            "failing_workflows": [],
            "pending_workflows": [],
            "stalled_workflows": [],
            "protection": None,
            "errors": [],
        }

        pulls, pull_errors = gh_pages(
            f"/repos/{ORG}/{urllib.parse.quote(name, safe='')}/pulls?state=open",
            max_pages=10,
        )
        record["open_pull_requests"] = len(pulls) if not pull_errors else None
        record["errors"].extend(pull_errors)

        workflows_data, workflows_meta = gh(
            f"/repos/{ORG}/{urllib.parse.quote(name, safe='')}/actions/workflows?per_page=100",
            timeout=20.0,
            retries=1,
        )
        workflows = workflows_data.get("workflows") if isinstance(workflows_data, dict) else None
        if isinstance(workflows, list):
            active_workflows = [w for w in workflows if isinstance(w, dict) and w.get("state") == "active"]
            record["workflow_count"] = len(active_workflows)
        else:
            record["errors"].append(
                f"workflows: {workflows_meta['error'] or workflows_meta['status'] or 'malformed'}"
            )
            active_workflows = []

        runs_data, runs_meta = gh(
            f"/repos/{ORG}/{urllib.parse.quote(name, safe='')}/actions/runs"
            f"?branch={urllib.parse.quote(default_branch, safe='')}&per_page=100",
            timeout=25.0,
            retries=1,
        )
        runs = runs_data.get("workflow_runs") if isinstance(runs_data, dict) else None
        if not isinstance(runs, list):
            record["errors"].append(
                f"runs: {runs_meta['error'] or runs_meta['status'] or 'malformed'}"
            )
            runs = []

        latest = latest_per_workflow([r for r in runs if isinstance(r, dict)])
        active_ids = {str(w.get("id")) for w in active_workflows if w.get("id") is not None}
        for key, run in sorted(latest.items(), key=lambda item: str(item[1].get("name") or item[0]).casefold()):
            # Keep disabled historical workflows out of the current health state.
            if active_ids and key not in active_ids:
                continue
            created = parse_time(run.get("created_at") or run.get("run_started_at"))
            summary = {
                "workflow_id": run.get("workflow_id"),
                "name": run.get("name"),
                "run_id": run.get("id"),
                "status": run.get("status"),
                "conclusion": run.get("conclusion"),
                "event": run.get("event"),
                "head_sha": run.get("head_sha"),
                "created_at": run.get("created_at"),
                "updated_at": run.get("updated_at"),
                "url": run.get("html_url"),
            }
            record["latest_default_branch_workflows"].append(summary)
            conclusion = str(run.get("conclusion") or "")
            status = str(run.get("status") or "")
            if conclusion in FAILURE_CONCLUSIONS:
                record["failing_workflows"].append(summary)
                run_id = run.get("id")
                is_recent = created is not None and created >= cutoff
                is_default_branch = run.get("head_branch") == default_branch
                is_terminal = status == "completed"
                is_pr_event = run.get("event") == "pull_request"
                if (
                    not archived
                    and not disabled
                    and is_recent
                    and is_default_branch
                    and is_terminal
                    and not is_pr_event
                    and isinstance(run_id, int)
                    and run_id not in observed_run_ids
                ):
                    observed_run_ids.add(run_id)
                    reruns.append(rerun_failed(name, run))
            elif status in PENDING_STATUSES or (status != "completed" and not conclusion):
                record["pending_workflows"].append(summary)
                if created is not None and created < stale_cutoff:
                    record["stalled_workflows"].append(summary)

        if not archived and not disabled:
            record["protection"] = protection_probe(name, default_branch)
        records.append(record)

    return {
        "ok": bool(repos),
        "errors": errors,
        "repository_count": len(records),
        "active_repository_count": sum(not r["archived"] and not r["disabled"] for r in records),
        "archived_repository_count": sum(r["archived"] for r in records),
        "private_repository_count": sum(r["visibility"] != "public" for r in records),
        "open_pull_request_count": sum(
            int(r["open_pull_requests"] or 0) for r in records if r["open_pull_requests"] is not None
        ),
        "repositories_with_failures": sum(bool(r["failing_workflows"]) for r in records),
        "latest_workflow_failure_count": sum(len(r["failing_workflows"]) for r in records),
        "repositories_with_pending": sum(bool(r["pending_workflows"]) for r in records),
        "stalled_workflow_count": sum(len(r["stalled_workflows"]) for r in records),
        "rerun_requests": reruns,
        "rerun_requested_count": sum(bool(r["requested"]) for r in reruns),
        "repositories": records,
    }


def hf_list(kind: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    url = f"https://huggingface.co/api/{kind}?author={urllib.parse.quote(HF_ORG)}&limit=100&full=true"
    data, meta = request_json(url, hf=True, timeout=25.0, retries=2)
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)], meta
    return [], meta


def hf_inventory(github_repo_names: set[str]) -> dict[str, Any]:
    assets: dict[str, list[dict[str, Any]]] = {}
    errors: list[str] = []
    for kind in ("models", "datasets", "spaces"):
        rows, meta = hf_list(kind)
        if not meta["ok"]:
            errors.append(f"{kind}: {meta['error'] or meta['status']}")
        assets[kind] = rows

    space_detail, space_meta = request_json(
        "https://huggingface.co/api/spaces/SZLHOLDINGS/a11oy",
        hf=True,
        timeout=25.0,
        retries=2,
    )
    if not space_meta["ok"]:
        errors.append(f"a11oy space detail: {space_meta['error'] or space_meta['status']}")

    mappings: list[dict[str, Any]] = []
    repo_lookup = {name.casefold(): name for name in github_repo_names}
    for kind, rows in assets.items():
        for item in rows:
            asset_id = str(item.get("id") or item.get("modelId") or "")
            leaf = asset_id.rsplit("/", 1)[-1]
            exact = repo_lookup.get(leaf.casefold())
            mappings.append(
                {
                    "kind": kind[:-1] if kind.endswith("s") else kind,
                    "id": asset_id,
                    "sha": item.get("sha"),
                    "last_modified": item.get("lastModified") or item.get("last_modified"),
                    "private": item.get("private"),
                    "github_exact_name": exact,
                    "mapping": "EXACT_NAME" if exact else "UNMAPPED_BY_NAME",
                }
            )

    runtime = space_detail.get("runtime") if isinstance(space_detail, dict) else None
    card_data = space_detail.get("cardData") if isinstance(space_detail, dict) else None
    return {
        "ok": any(assets.values()),
        "errors": errors,
        "counts": {kind: len(rows) for kind, rows in assets.items()},
        "mapped_by_exact_name": sum(m["mapping"] == "EXACT_NAME" for m in mappings),
        "unmapped_by_exact_name": sum(m["mapping"] == "UNMAPPED_BY_NAME" for m in mappings),
        "assets": mappings,
        "canonical_space": {
            "id": space_detail.get("id") if isinstance(space_detail, dict) else None,
            "sha": space_detail.get("sha") if isinstance(space_detail, dict) else None,
            "last_modified": space_detail.get("lastModified") if isinstance(space_detail, dict) else None,
            "private": space_detail.get("private") if isinstance(space_detail, dict) else None,
            "sdk": card_data.get("sdk") if isinstance(card_data, dict) else None,
            "app_file": card_data.get("app_file") if isinstance(card_data, dict) else None,
            "runtime_stage": runtime.get("stage") if isinstance(runtime, dict) else None,
            "hardware": runtime.get("hardware") if isinstance(runtime, dict) else None,
            "http_status": space_meta["status"],
        },
    }


def extract_identity(value: Any, *, limit: int = 30) -> list[dict[str, str]]:
    accepted = {
        "source_sha",
        "github_sha",
        "commit_sha",
        "build_sha",
        "revision",
        "sha",
        "commit",
    }
    found: list[dict[str, str]] = []

    def walk(node: Any, path: str) -> None:
        if len(found) >= limit:
            return
        if isinstance(node, dict):
            for key, child in node.items():
                child_path = f"{path}.{key}" if path else str(key)
                if str(key).casefold() in accepted and isinstance(child, (str, int)):
                    text = str(child)
                    if len(text) <= 160:
                        found.append({"path": child_path, "value": text})
                walk(child, child_path)
        elif isinstance(node, list):
            for index, child in enumerate(node[:50]):
                walk(child, f"{path}[{index}]")

    walk(value, "")
    return found


def probe(url: str) -> dict[str, Any]:
    result = request(
        url,
        headers={
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.8",
            "User-Agent": "szl-org-convergence/2026-08-28",
        },
        timeout=25.0,
        retries=2,
    )
    body = result["body"]
    content_type = result["headers"].get("content-type")
    parsed: Any = None
    if body and ("json" in str(content_type).lower() or body[:1] in {b"{", b"["}):
        try:
            parsed = json.loads(body.decode("utf-8"))
        except Exception:
            parsed = None
    return {
        "url": url,
        "final_url": result["url"],
        "ok": result["ok"],
        "http_status": result["status"],
        "content_type": content_type,
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest() if body else None,
        "identity": extract_identity(parsed) if parsed is not None else [],
        "error": result["error"],
    }


def surface_inventory() -> dict[str, Any]:
    urls = [
        "https://a-11-oy.com/",
        "https://a-11-oy.com/healthz",
        "https://a-11-oy.com/api/a11oy/v1/honest",
        "https://a-11-oy.com/api/a11oy/v1/readiness",
        "https://a-11-oy.com/api/a11oy/v1/models/series-a",
        "https://a11oy.net/",
        "https://a11oy.net/health.json",
        "https://a11oy.net/record.json",
        "https://szlholdings-a11oy.hf.space/",
        "https://szlholdings-a11oy.hf.space/healthz",
        "https://szlholdings-a11oy.hf.space/api/a11oy/v1/honest",
        "https://szlholdings-a11oy.hf.space/api/a11oy/v1/readiness",
        "https://szlholdings-a11oy.hf.space/api/a11oy/v1/models/series-a",
    ]
    probes = [probe(url) for url in urls]
    by_url = {item["url"]: item for item in probes}
    primary = by_url.get("https://a-11-oy.com/") or {}
    hf_root = by_url.get("https://szlholdings-a11oy.hf.space/") or {}
    return {
        "ok": any(item["ok"] for item in probes),
        "all_reachable": all(item["ok"] for item in probes),
        "primary_and_hf_root_byte_equal": bool(
            primary.get("body_sha256")
            and primary.get("body_sha256") == hf_root.get("body_sha256")
        ),
        "probes": probes,
    }


def write_report(report: dict[str, Any]) -> None:
    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    gh = report["github"]
    hf = report["hugging_face"]
    surfaces = report["surfaces"]
    lines = [
        "# SZL organization convergence — GitHub native, no Replit",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "## Executive readback",
        "",
        f"- Repositories observed: **{gh['repository_count']}** total; **{gh['active_repository_count']}** active; **{gh['archived_repository_count']}** archived.",
        f"- Open pull requests observed across repositories: **{gh['open_pull_request_count']}**.",
        f"- Repositories with a failing latest default-branch workflow before recovery: **{gh['repositories_with_failures']}**.",
        f"- Failing latest workflow runs observed: **{gh['latest_workflow_failure_count']}**.",
        f"- Failed-run reruns accepted by GitHub: **{gh['rerun_requested_count']}** of **{len(gh['rerun_requests'])}** attempted.",
        f"- Stalled latest workflow runs older than six hours: **{gh['stalled_workflow_count']}** (recorded, not force-cancelled).",
        f"- Hugging Face counts: models **{hf['counts'].get('models', 0)}**, datasets **{hf['counts'].get('datasets', 0)}**, Spaces **{hf['counts'].get('spaces', 0)}**.",
        f"- Exact-name GitHub↔Hub relationships: **{hf['mapped_by_exact_name']}** mapped; **{hf['unmapped_by_exact_name']}** explicitly unmapped.",
        f"- Public probes all reachable: **{surfaces['all_reachable']}**; primary/HF root byte-equal: **{surfaces['primary_and_hf_root_byte_equal']}**.",
        "",
        "## Recovery requests",
        "",
    ]
    if gh["rerun_requests"]:
        for item in gh["rerun_requests"]:
            state = "ACCEPTED" if item["requested"] else "REJECTED"
            lines.append(
                f"- `{item['repository']}` · `{item['workflow']}` · run `{item['run_id']}` · **{state}** · HTTP `{item['http_status']}`"
            )
    else:
        lines.append("- No terminal failed latest default-branch run met the bounded rerun criteria.")

    lines.extend(["", "## Remaining failing workflow observations", ""])
    remaining = []
    for repo in gh["repositories"]:
        for item in repo["failing_workflows"]:
            remaining.append((repo["name"], item))
    if remaining:
        for repo_name, item in remaining:
            lines.append(
                f"- `{repo_name}` · `{item.get('name')}` · `{item.get('conclusion')}` · run `{item.get('run_id')}` · `{item.get('created_at')}`"
            )
    else:
        lines.append("- None observed in the pre-recovery census.")

    lines.extend(["", "## Public surface probes", ""])
    for item in surfaces["probes"]:
        lines.append(
            f"- `{item['url']}` → HTTP `{item['http_status']}` · bytes `{item['body_bytes']}` · SHA-256 `{item['body_sha256'] or 'UNAVAILABLE'}`"
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "This execution retries only terminal failed latest runs on active default branches. It does not weaken rulesets, bypass protected branches, expose credentials, force-merge code, cancel current work, or infer model quality from Hub metadata.",
            "",
        ]
    )
    REPORT_MD.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    generated_at = iso_now()
    if not ORG_TOKEN:
        report = {
            "schema": "szl.org-convergence.v1",
            "generated_at": generated_at,
            "mode": "EXECUTE_RERUN_FAILED_LATEST",
            "error": "ORG_TOKEN unavailable",
        }
        REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
        REPORT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        raise SystemExit("ORG_TOKEN unavailable; refusing partial organization claims")

    github = github_inventory()
    repo_names = {str(item.get("name") or "") for item in github.get("repositories", [])}
    report = {
        "schema": "szl.org-convergence.v1",
        "generated_at": generated_at,
        "mode": "EXECUTE_RERUN_FAILED_LATEST" if EXECUTE_RERUNS else "AUDIT_ONLY",
        "replit_dependency": False,
        "github": github,
        "hugging_face": hf_inventory(repo_names),
        "surfaces": surface_inventory(),
    }
    write_report(report)
    print(
        json.dumps(
            {
                "generated_at": generated_at,
                "repositories": github["repository_count"],
                "failures": github["latest_workflow_failure_count"],
                "reruns_accepted": github["rerun_requested_count"],
                "hf_counts": report["hugging_face"]["counts"],
                "all_public_probes_reachable": report["surfaces"]["all_reachable"],
            },
            sort_keys=True,
        )
    )
    return 0 if github["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
