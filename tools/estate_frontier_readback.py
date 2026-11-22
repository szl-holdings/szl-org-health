#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded, READ-ONLY five-pass source-to-proof estate readback.

Internal reports may contain private repository metadata and must stay off
public/static routes. Graph export admits only visibility=public, private=False.
No mutation, workflow dispatch, deployment, inference, or payment calls.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ORG = "szl-holdings"
WORKFLOW_ACTIVE = {"active"}
WORKFLOW_DISABLED = {"disabled_manually", "disabled_inactivity"}
PRIORITY = ("a11oy", "szl-build-env", "szl-org-health", "szl-cram",
            "platform", "yarqa", ".github", "a11oy-net", "szl-gpu-bridge",
            "szl-evidence-mandate", "szl-receipt-attn", "szl-router",
            "szl-serve", "szl-forge", "killinchu", "szl-command-center",
            "szl-frontier", "szl-quant-witness")
FIXED_URLS = (
    "https://a-11-oy.com/",
    "https://a11oy.net/",
    "https://mcp.a-11-oy.com/healthz",  # liveness transport only, not readiness
    "https://a-11-oy.com/healthz",
    "https://a-11-oy.com/.well-known/szl-source.json",
    "https://inference.a-11-oy.com/v1/chat/completions",
    "https://huggingface.co/spaces/SZLHOLDINGS/a11oy",
    "https://pypi.org/project/szl-evidence-mandate/",
)
SHA = re.compile(r"^[0-9a-f]{40}$")


def stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def capped_budget(remaining: object, requested: int, *, floor: int = 500) -> int:
    """Reserve a real REST floor for other estate actors; unavailable is HOLD."""
    if type(remaining) is not int or remaining < 0:
        return 0
    return min(requested, max(0, remaining - floor))


def classify_error(stderr: str) -> str:
    match = re.search(r"(?:HTTP|status)\s*(401|403|404|409|422|429|500|502|503)", stderr, re.I)
    if match:
        return "HTTP_" + match.group(1)
    return "API_UNAVAILABLE"


class Reader:
    def __init__(self, maximum: int = 850):
        self.maximum, self.calls = maximum, 0
        self.errors: dict[str, int] = {}

    def get(self, path: str):
        if self.calls >= self.maximum:
            return None, "REQUEST_BUDGET_EXHAUSTED"
        # GitHub API read paths only. No raw headers or process environment emitted.
        if not (path.startswith("orgs/" + ORG) or
                path.startswith("organizations/") or
                path.startswith("repos/" + ORG + "/") or path == "rate_limit"):
            return None, "UNAPPROVED_READ_PATH"
        self.calls += 1
        try:
            result = subprocess.run(["gh", "api", "-X", "GET", path], capture_output=True,
                                    timeout=22, check=False)
        except (OSError, subprocess.TimeoutExpired):
            error = "API_TIMEOUT_OR_UNAVAILABLE"
        else:
            if result.returncode == 0:
                try:
                    return json.loads(result.stdout), None
                except (ValueError, UnicodeError):
                    error = "INVALID_JSON"
            else:
                error = classify_error(result.stderr.decode("utf-8", "replace"))
        self.errors[error] = self.errors.get(error, 0) + 1
        return None, error


def enumerate_repos(reader: Reader):
    identity, error = reader.get("orgs/" + ORG)
    if error or not isinstance(identity, dict) or identity.get("login", "").lower() != ORG:
        return [], False, error or "ORG_IDENTITY_INVALID"
    ident = identity.get("id")
    if type(ident) is not int or ident <= 0:
        return [], False, "ORG_IDENTITY_INVALID"
    rows, seen = [], set()
    for page in range(1, 6):
        response, error = reader.get(
            f"organizations/{ident}/repos?type=all&sort=full_name&direction=asc&per_page=100&page={page}")
        if error or not isinstance(response, list):
            return rows, False, error or "REPOSITORY_PAGE_INVALID"
        for row in response:
            if not isinstance(row, dict):
                return rows, False, "REPOSITORY_IDENTITY_INVALID"
            full = row.get("full_name")
            if (not isinstance(full, str) or not full.lower().startswith(ORG + "/")
                    or full.lower() in seen or type(row.get("archived")) is not bool
                    or type(row.get("private")) is not bool):
                return rows, False, "REPOSITORY_IDENTITY_INVALID"
            seen.add(full.lower())
            rows.append(row)
        if len(response) < 100:
            return rows, True, None
    return rows, False, "REPOSITORY_PAGINATION_CAP"


def summarize_workflows(response: dict | None, error: str | None):
    if error or not isinstance(response, dict):
        return {"coverage": "UNAVAILABLE", "reason": error or "INVALID_WORKFLOWS",
                "total": None, "enabled": None, "disabled": None, "unknown_state": None}
    rows = response.get("workflows")
    total = response.get("total_count")
    if not isinstance(rows, list) or type(total) is not int or total < 0:
        return summarize_workflows(None, "INVALID_WORKFLOWS")
    active = sum(row.get("state") in WORKFLOW_ACTIVE for row in rows if isinstance(row, dict))
    disabled = sum(row.get("state") in WORKFLOW_DISABLED for row in rows if isinstance(row, dict))
    unknown = len(rows) - active - disabled
    complete = len(rows) == total
    return {"coverage": "COMPLETE" if complete else "INCOMPLETE",
            "reason": None if complete else "PAGINATION_OR_UNKNOWN",
            "total": total if complete else None,
            "enabled": active if complete else None,
            "disabled": disabled if complete else None,
            "unknown_state": unknown if complete else None,
            "definitions_observed": len(rows),
            "workflows": [{"id": x.get("id"), "name": x.get("name"),
                           "path": x.get("path"), "state": x.get("state"),
                           "html_url": x.get("html_url")}
                          for x in rows if isinstance(x, dict)]}


def fetch_workflows(reader: Reader, name: str):
    gathered, expected = [], None
    for page in range(1, 9):
        data, error = reader.get(
            f"repos/{name}/actions/workflows?per_page=100&page={page}")
        if error or not isinstance(data, dict):
            return summarize_workflows(None, error or "INVALID_WORKFLOWS")
        rows = data.get("workflows")
        total = data.get("total_count")
        if not isinstance(rows, list) or type(total) is not int or total < 0:
            return summarize_workflows(None, "INVALID_WORKFLOWS")
        if expected is not None and total != expected:
            return summarize_workflows(None, "PAGINATION_TOTAL_CHANGED")
        expected = total
        gathered.extend(rows)
        if len(gathered) >= total:
            return summarize_workflows({"workflows": gathered, "total_count": total}, None)
        if len(rows) != 100:
            break
    return summarize_workflows({"workflows": gathered, "total_count": expected or 0}, None)


def source_roles(paths: list[str]):
    pathset = set(paths)
    return {
        "python": any(x.endswith(".py") for x in paths) or "pyproject.toml" in pathset,
        "frontend": any(x.endswith((".tsx", ".jsx", ".vue", ".svelte")) for x in paths)
                    or any(x.startswith(("web/", "frontend/", "console/")) for x in paths),
        "backend": any(x in pathset for x in ("pyproject.toml", "app.py", "serve.py",
                    "requirements.txt", "Dockerfile")) or any("/api/" in x for x in paths),
        "node": "package.json" in pathset or any(x.endswith(".ts") for x in paths),
        "container": "Dockerfile" in pathset or "Containerfile" in pathset,
        "github_actions": any(x.startswith(".github/workflows/") and
                              x.endswith((".yml", ".yaml")) for x in paths),
        "pypi_candidate": "pyproject.toml" in pathset,
    }


def fetch_source(reader: Reader, row: dict):
    repo = row["full_name"]
    branch = row.get("default_branch")
    if not isinstance(branch, str) or not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", branch):
        return {"coverage": "UNAVAILABLE", "reason": "INVALID_DEFAULT_BRANCH", "roles": None}
    tree, error = reader.get(f"repos/{repo}/git/trees/{urllib.parse.quote(branch, safe='')}?recursive=1")
    if error or not isinstance(tree, dict) or not isinstance(tree.get("tree"), list):
        return {"coverage": "UNAVAILABLE", "reason": error or "INVALID_TREE", "roles": None}
    paths = [x["path"] for x in tree["tree"] if isinstance(x, dict) and
             x.get("type") == "blob" and isinstance(x.get("path"), str)]
    complete = tree.get("truncated") is False
    return {"coverage": "COMPLETE" if complete else "INCOMPLETE",
            "reason": None if complete else "TREE_TRUNCATED",
            "roles": source_roles(paths) if complete else None,
            "file_paths_observed": len(paths),
            "sha": tree.get("sha") if isinstance(tree.get("sha"), str) else None}


def summarize_current_push(runs, exact_sha):
    if not isinstance(runs, list) or not SHA.fullmatch(exact_sha or ""):
        return {"coverage": "UNAVAILABLE", "matching_runs": None, "failed": None}
    matched = [x for x in runs if isinstance(x, dict) and x.get("head_sha") == exact_sha]
    fails, success, pending, skipped = [], 0, 0, 0
    for x in matched:
        if x.get("status") != "completed":
            pending += 1
        elif x.get("conclusion") == "failure":
            fails.append({"workflow": x.get("name"), "url": x.get("html_url"),
                          "run_id": x.get("id"), "job_step": "UNVERIFIED"})
        elif x.get("conclusion") == "success":
            success += 1
        elif x.get("conclusion") in ("skipped", "neutral", "cancelled"):
            skipped += 1
    return {"coverage": "SAMPLED" if matched else "NO_CURRENT_HEAD_PUSH_RUN_IN_WINDOW",
            "window_size": len(runs), "matching_runs": len(matched),
            "failed": len(fails), "success": success, "pending": pending,
            "skipped_or_neutral_or_cancelled": skipped, "failures": fails,
            "required_status": "UNVERIFIED", "release_readiness": "UNVERIFIED"}


def fetch_ci(reader: Reader, row: dict):
    repo, branch = row["full_name"], row.get("default_branch")
    commit, error = reader.get(f"repos/{repo}/commits/{urllib.parse.quote(branch or '', safe='')}")
    if error or not isinstance(commit, dict) or not SHA.fullmatch(commit.get("sha", "")):
        return {"coverage": "UNAVAILABLE", "reason": error or "HEAD_SHA_UNAVAILABLE"}
    head = commit["sha"]
    data, error = reader.get(f"repos/{repo}/actions/runs?branch={urllib.parse.quote(branch, safe='')}&event=push&per_page=100&page=1")
    if error or not isinstance(data, dict):
        return {"coverage": "UNAVAILABLE", "reason": error or "RUNS_UNAVAILABLE", "head_sha": head}
    result = summarize_current_push(data.get("workflow_runs"), head)
    result["head_sha"] = head
    result["push_run_count_total_reported"] = data.get("total_count")
    result["window_exhaustive"] = (type(data.get("total_count")) is int and
                                    data["total_count"] <= len(data.get("workflow_runs", [])))
    return result


def fetch_prs(reader: Reader, row: dict):
    repo = row["full_name"]
    data, error = reader.get(f"repos/{repo}/pulls?state=open&per_page=10&page=1")
    if error or not isinstance(data, list):
        return {"coverage": "UNAVAILABLE", "reason": error or "PRS_UNAVAILABLE"}
    results = []
    for pr in data:
        head = pr.get("head") if isinstance(pr, dict) else None
        sha = head.get("sha") if isinstance(head, dict) else None
        if not SHA.fullmatch(sha or ""):
            results.append({"number": pr.get("number"), "checks": "UNAVAILABLE"})
            continue
        checks, check_error = reader.get(f"repos/{repo}/commits/{sha}/check-runs?per_page=100")
        if check_error or not isinstance(checks, dict) or not isinstance(checks.get("check_runs"), list):
            results.append({"number": pr.get("number"), "checks": "UNAVAILABLE",
                            "reason": check_error or "CHECKS_UNAVAILABLE"})
            continue
        items = checks["check_runs"]
        results.append({"number": pr.get("number"), "sha": sha,
                        "checks": "INCOMPLETE" if checks.get("total_count", 0) > len(items) else "SAMPLED",
                        "failed": sum(c.get("conclusion") in ("failure", "timed_out", "action_required")
                                      for c in items),
                        "pending": sum(c.get("status") != "completed" for c in items),
                        "required_status": "UNVERIFIED"})
    return {"coverage": "SAMPLED", "page_size": len(data),
            "more_prs_may_exist": len(data) == 10, "prs": results}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def probe_fixed_links(probe=None):
    """Fixed anonymous HEADs; one explicit bounded GET if source identity denies HEAD.

    The GET fallback never targets paid APIs or third-party URL redirects.
    """
    rows = []
    opener = urllib.request.build_opener(NoRedirect())
    source_identity = "https://a-11-oy.com/.well-known/szl-source.json"
    for url in FIXED_URLS:
        method, head_status, schema_state = "HEAD", None, "NOT_INSPECTED"
        try:
            if probe is None:
                response = opener.open(urllib.request.Request(
                    url, method="HEAD", headers={"User-Agent": "SZL-read-only-proof-witness/1"}),
                    timeout=8)
                with response:
                    status = response.status
            else:
                status = probe(url, "HEAD")
        except urllib.error.HTTPError as e:
            status = e.code
        except (OSError, ValueError, TimeoutError):
            status = None
        head_status = status
        if url == source_identity and status == 405:
            method = "GET"
            try:
                if probe is None:
                    response = opener.open(urllib.request.Request(
                        url, method="GET", headers={"Accept": "application/json",
                            "User-Agent": "SZL-read-only-proof-witness/1"}), timeout=8)
                    with response:
                        status = response.status
                        body = response.read(32769)
                        content_type = response.headers.get("content-type", "")
                    if (len(body) > 32768 or
                            content_type.split(";", 1)[0].strip().lower() != "application/json"):
                        status, schema_state = None, "UNAVAILABLE"
                    else:
                        parsed = json.loads(body.decode("utf-8"))
                        schema_state = ("STRUCTURAL_ONLY" if isinstance(parsed, dict)
                                        and parsed.get("schema") == "szl.deployment-source/v1"
                                        else "UNKNOWN")
                else:
                    status = probe(url, "GET")
                    schema_state = "UNVERIFIED_TEST_DOUBLE"
            except urllib.error.HTTPError as e:
                status, schema_state = e.code, "UNAVAILABLE"
            except (OSError, ValueError, UnicodeError, TimeoutError):
                status, schema_state = None, "UNAVAILABLE"
        rows.append({"url": url, "method": method, "head_http_status": head_status,
                     "http_status": status, "schema_state": schema_state,
                     "transport": "OBSERVED" if type(status) is int else "UNAVAILABLE",
                     "release_readiness": "UNVERIFIED",
                     "payment_settlement": "UNVERIFIED"})
    return rows


def graph_public(repos: list[dict]):
    """Public source-declaration graph only; never include private repo identifiers."""
    nodes, edges = {}, []
    for item in repos:
        repo = item["repository"]
        if item.get("private") is not False or item.get("visibility") != "public":
            continue
        name = repo.split("/")[-1]
        root_id = "repo:" + repo
        nodes[root_id] = {"id": root_id, "kind": "github_source",
                          "label": name, "url": "https://github.com/" + repo,
                          "evidence": "REPOSITORY_METADATA_ONLY"}
        roles = item.get("source", {}).get("roles")
        if item.get("source", {}).get("coverage") != "COMPLETE" or not isinstance(roles, dict):
            continue
        for role, declared in roles.items():
            if declared is not True:
                continue
            role_id = "source-capability:" + role
            nodes.setdefault(role_id, {"id": role_id, "kind": "source_capability",
                                       "label": role, "evidence": "SOURCE_DECLARATION_ONLY"})
            edges.append({"from": root_id, "to": role_id, "relation": "declares_source",
                          "evidence": "FILE_PATHS_ONLY",
                          "runtime_verified": False, "source_deploy_parity": "UNVERIFIED"})
    return {"schema": "szl.source-evidence-graph/v1", "scope": "public-source-only",
            "release_readiness": "UNVERIFIED", "nodes": sorted(nodes.values(), key=lambda x: x["id"]),
            "edges": sorted(edges, key=lambda x: (x["from"], x["to"]))}


def collect(reader: Reader, sample_limit=24):
    rows, complete, error = enumerate_repos(reader)
    enriched = []
    # PASS 1+2: complete repository enumeration and source/workflow structure.
    for row in rows:
        item = {"repository": row["full_name"], "private": row["private"],
                "visibility": row.get("visibility"), "archived": row["archived"],
                "default_branch": row.get("default_branch"),
                "source": {"coverage": "NOT_APPLICABLE", "roles": None} if row["archived"] else fetch_source(reader, row),
                "workflows": fetch_workflows(reader, row["full_name"])}
        enriched.append(item)
    # PASS 3: rate-budgeted exact-main CI and open-PR sample.
    active = [x for x in enriched if not x["archived"]]
    priority = sorted(active, key=lambda x: (
        PRIORITY.index(x["repository"].split("/")[-1])
        if x["repository"].split("/")[-1] in PRIORITY else len(PRIORITY),
        x["repository"]))
    indexed = {r["full_name"]: r for r in rows}
    for item in priority[:sample_limit]:
        original = indexed[item["repository"]]
        item["ci"] = fetch_ci(reader, original)
        item["pull_requests"] = fetch_prs(reader, original)
    # PASS 4: fixed anonymous public links; no paid requests.
    links = probe_fixed_links()
    # PASS 5: closed accounting + explicit non-admission of release claims.
    workflow_good = [x["workflows"] for x in enriched if x["workflows"]["coverage"] == "COMPLETE"]
    workflow_unknown = [x["repository"] for x in enriched if x["workflows"]["coverage"] != "COMPLETE"]
    totals = {"repositories_observed": len(enriched),
              "repository_census_complete": complete, "census_reason": error,
              "active": sum(not x["archived"] for x in enriched),
              "archived": sum(x["archived"] for x in enriched),
              "workflow_repositories_complete": len(workflow_good),
              "workflow_repositories_unavailable": workflow_unknown,
              "workflow_definitions_observed": sum(x["total"] for x in workflow_good),
              "workflow_enabled_observed": sum(x["enabled"] for x in workflow_good),
              "workflow_disabled_observed": sum(x["disabled"] for x in workflow_good),
              "workflow_unknown_states": sum(x["unknown_state"] for x in workflow_good),
              "sampled_ci_repos": sum("ci" in x for x in enriched),
              "sampled_pr_repos": sum("pull_requests" in x for x in enriched)}
    return {"schema": "szl.estate-frontier-readback/v1",
            "observed_at": stamp(), "organization": ORG, "totals": totals,
            "passes": ["repository_identity", "source_roles_and_workflows",
                       "protected_main_ci_and_pr_sample", "fixed_public_link_transport",
                       "fail_closed_accounting_and_release_holds"],
            "release_readiness": "UNVERIFIED",
            "hf_alignment": "UNVERIFIED",
            "cloudflare_settlement": "UNVERIFIED",
            "pypi_release_admission": "UNVERIFIED",
            "evidence_signature": "UNSIGNED_OBSERVATION",
            "api": {"calls": reader.calls, "max_calls": reader.maximum, "errors": reader.errors},
            "links": links, "repositories": enriched}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-graph", type=Path, required=True)
    parser.add_argument("--max-requests", type=int, default=850)
    parser.add_argument("--sample-limit", type=int, default=24)
    args = parser.parse_args()
    if not 100 <= args.max_requests <= 1600 or not 0 <= args.sample_limit <= 50:
        parser.error("out-of-budget settings")
    reader = Reader(args.max_requests)
    rates, rate_error = reader.get("rate_limit")
    remaining = (rates.get("resources", {}).get("core", {}).get("remaining")
                 if isinstance(rates, dict) else None)
    budget = capped_budget(remaining, args.max_requests)
    if rate_error or budget < 30:
        parser.error("REST rate budget is unavailable or below the 500-request reserve; no census run")
    reader.maximum = budget
    report = collect(reader, args.sample_limit)
    report["api"]["initial_remaining"] = remaining
    report["api"]["reserved_floor"] = 500
    graph = graph_public(report["repositories"])
    report["public_graph_sha256"] = hashlib.sha256(canonical(graph)).hexdigest()
    # Never write credentialed, privately scoped inventory inside the source repo.
    for target, value in ((args.output, report), (args.public_graph, graph)):
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            parser.error("refusing to overwrite an existing evidence snapshot")
        target.write_bytes(canonical(value) + b"\n")
    # Console output is aggregate-only; internal report is not safe for public CI logs.
    summary = {k: v for k, v in report["totals"].items()
               if k != "workflow_repositories_unavailable"}
    summary["workflow_unavailable_count"] = len(report["totals"]["workflow_repositories_unavailable"])
    print(json.dumps({"time": report["observed_at"], **summary,
                      "api": report["api"], "public_graph_sha256": report["public_graph_sha256"]},
                     sort_keys=True))


if __name__ == "__main__":
    main()
