#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Hardened v2 entrypoint for the exact-source organization audit.

Version 2 keeps the file-complete scanner and evidence formats from
``deep_repository_audit.py`` while closing transport and completeness gaps:

* API requests and pagination are locked to ``https://api.github.com``;
* the one allowed cross-origin transition is the GitHub archive redirect to
  ``https://codeload.github.com`` and Authorization is removed before it occurs;
* JSON response bodies are bounded;
* every shard must observe a configured minimum organization size; and
* every shard is bound to the same canonical repository-inventory digest.

The module remains read-only.  It cannot push, merge, rerun, deploy, publish,
rotate, or change a provider setting.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

_CORE_PATH = Path(__file__).with_name("deep_repository_audit.py")
_CORE_SPEC = importlib.util.spec_from_file_location("szl_deep_repository_audit_core", _CORE_PATH)
if _CORE_SPEC is None or _CORE_SPEC.loader is None:  # pragma: no cover - import bootstrap
    raise RuntimeError("deep repository audit core is unavailable")
core = importlib.util.module_from_spec(_CORE_SPEC)
sys.modules[_CORE_SPEC.name] = core
_CORE_SPEC.loader.exec_module(core)

SCHEMA = "szl.deep-repository-audit/v2"
API_ORIGIN = ("https", "api.github.com", 443)
CODELOAD_ORIGIN = ("https", "codeload.github.com", 443)
DEFAULT_MAX_JSON_BYTES = 32 * 1024 * 1024
DEFAULT_EXPECTED_REPOSITORIES_MINIMUM = 100
LINK_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

AuditError = core.AuditError
ApiResponse = core.ApiResponse


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
        or parsed.fragment
    ):
        raise AuditError("URL does not satisfy the fixed HTTPS origin contract")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise AuditError("URL contains a malformed port") from exc
    return parsed.scheme, parsed.hostname.lower(), port


def _api_url(url_or_path: str, api_base: str) -> str:
    if url_or_path.startswith("/"):
        url = api_base.rstrip("/") + url_or_path
    else:
        url = url_or_path
    if _origin(url) != API_ORIGIN:
        raise AuditError("GitHub API request escaped the fixed api.github.com origin")
    return url


def _drop_header(request: urllib.request.Request, header: str) -> None:
    target = header.lower()
    for mapping in (request.headers, request.unredirected_hdrs):
        for key in tuple(mapping):
            if key.lower() == target:
                mapping.pop(key, None)


class LockedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow only same-origin redirects or one credential-free archive hop."""

    def __init__(self, *, allow_codeload: bool) -> None:
        super().__init__()
        self.allow_codeload = allow_codeload

    def redirect_request(  # type: ignore[override]
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Mapping[str, str],
        newurl: str,
    ) -> urllib.request.Request | None:
        absolute = urllib.parse.urljoin(req.full_url, newurl)
        old_origin = _origin(req.full_url)
        new_origin = _origin(absolute)
        same_origin = old_origin == new_origin
        archive_hop = (
            self.allow_codeload
            and old_origin == API_ORIGIN
            and new_origin == CODELOAD_ORIGIN
            and "/tarball/" in urllib.parse.urlsplit(req.full_url).path
        )
        if not same_origin and not archive_hop:
            raise AuditError(
                "redirect escaped the fixed GitHub API/archive origin contract"
            )
        redirected = super().redirect_request(req, fp, code, msg, headers, absolute)
        if redirected is None:
            return None
        if archive_hop or new_origin == CODELOAD_ORIGIN:
            _drop_header(redirected, "Authorization")
            _drop_header(redirected, "Proxy-Authorization")
        return redirected


def _split_link_header(value: str) -> list[str]:
    parts: list[str] = []
    start = 0
    quoted = False
    escaped = False
    angle_depth = 0
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quoted and char == "\\":
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            continue
        if not quoted:
            if char == "<":
                angle_depth += 1
            elif char == ">":
                angle_depth -= 1
                if angle_depth < 0:
                    raise AuditError("malformed Link header")
            elif char == "," and angle_depth == 0:
                parts.append(value[start:index].strip())
                start = index + 1
    if quoted or angle_depth != 0:
        raise AuditError("malformed Link header")
    parts.append(value[start:].strip())
    return [part for part in parts if part]


def _parse_link_parameters(raw: str) -> dict[str, list[str]]:
    parameters: dict[str, list[str]] = {}
    for segment in raw.split(";"):
        item = segment.strip()
        if not item:
            continue
        if "=" not in item:
            if not LINK_TOKEN_RE.fullmatch(item):
                raise AuditError("malformed Link parameter")
            parameters.setdefault(item.lower(), []).append("")
            continue
        key, value = item.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if not LINK_TOKEN_RE.fullmatch(key):
            raise AuditError("malformed Link parameter name")
        if value.startswith('"'):
            if len(value) < 2 or not value.endswith('"'):
                raise AuditError("malformed quoted Link parameter")
            value = value[1:-1]
        elif not LINK_TOKEN_RE.fullmatch(value):
            raise AuditError("malformed Link parameter value")
        parameters.setdefault(key, []).append(value)
    return parameters


def next_link(link_header: str | None, *, expected_path: str) -> str | None:
    """Return one exact same-path API next link; ambiguity fails closed."""
    if not link_header:
        return None
    candidates: list[str] = []
    for part in _split_link_header(link_header):
        match = re.fullmatch(r"<([^>]+)>\s*(?:;(.*))?", part)
        if not match:
            raise AuditError("malformed Link relation")
        url = match.group(1)
        parameters = _parse_link_parameters(match.group(2) or "")
        rel_values = parameters.get("rel", [])
        relations: set[str] = set()
        for value in rel_values:
            relations.update(token for token in value.split() if token)
        if "next" not in relations:
            continue
        if _origin(url) != API_ORIGIN:
            raise AuditError("pagination next link escaped api.github.com")
        parsed = urllib.parse.urlsplit(url)
        if parsed.path != expected_path:
            raise AuditError("pagination next link changed the API path")
        candidates.append(url)
    if len(candidates) > 1:
        raise AuditError("pagination exposed more than one next relation")
    return candidates[0] if candidates else None


class HardenedGitHubClient:
    def __init__(
        self,
        token: str,
        *,
        timeout: float = core.DEFAULT_TIMEOUT,
        retries: int = core.DEFAULT_RETRIES,
        api_base: str = "https://api.github.com",
        max_json_bytes: int = DEFAULT_MAX_JSON_BYTES,
    ) -> None:
        if not token:
            raise AuditError("GITHUB_TOKEN is required for the organization audit")
        if _origin(api_base.rstrip("/")) != API_ORIGIN:
            raise AuditError("api_base must be exactly https://api.github.com")
        if max_json_bytes <= 0:
            raise AuditError("max_json_bytes must be positive")
        self.token = token
        self.timeout = timeout
        self.retries = retries
        self.api_base = api_base.rstrip("/")
        self.max_json_bytes = max_json_bytes

    def _headers(self, accept: str = "application/vnd.github+json") -> dict[str, str]:
        return {
            "Accept": accept,
            "Authorization": f"Bearer {self.token}",
            "User-Agent": core.USER_AGENT,
            "X-GitHub-Api-Version": core.API_VERSION,
        }

    def request(
        self,
        url_or_path: str,
        *,
        accept: str = "application/vnd.github+json",
        stream_to: Path | None = None,
        max_bytes: int | None = None,
    ) -> ApiResponse:
        url = _api_url(url_or_path, self.api_base)
        last_error: Exception | None = None
        allow_codeload = stream_to is not None and "/tarball/" in urllib.parse.urlsplit(url).path
        opener = urllib.request.build_opener(
            LockedRedirectHandler(allow_codeload=allow_codeload)
        )
        for attempt in range(self.retries + 1):
            request = urllib.request.Request(
                url,
                headers=self._headers(accept),
                method="GET",
            )
            try:
                with opener.open(request, timeout=self.timeout) as response:
                    headers = {key.lower(): value for key, value in response.headers.items()}
                    final_origin = _origin(response.geturl())
                    if stream_to is None and final_origin != API_ORIGIN:
                        raise AuditError("JSON response escaped api.github.com")
                    if stream_to is not None and final_origin not in {
                        API_ORIGIN,
                        CODELOAD_ORIGIN,
                    }:
                        raise AuditError("archive response escaped GitHub/codeload")
                    if stream_to is not None:
                        total = 0
                        stream_to.parent.mkdir(parents=True, exist_ok=True)
                        with stream_to.open("wb") as handle:
                            while True:
                                chunk = response.read(1024 * 1024)
                                if not chunk:
                                    break
                                total += len(chunk)
                                if max_bytes is not None and total > max_bytes:
                                    raise AuditError(
                                        f"archive exceeded configured byte ceiling ({max_bytes})"
                                    )
                                handle.write(chunk)
                        return ApiResponse({"bytes": total}, headers, response.geturl())
                    raw = response.read(self.max_json_bytes + 1)
                    if len(raw) > self.max_json_bytes:
                        raise AuditError(
                            f"GitHub JSON exceeded configured byte ceiling ({self.max_json_bytes})"
                        )
                    data: Any = json.loads(raw.decode("utf-8")) if raw else None
                    return ApiResponse(data, headers, response.geturl())
            except urllib.error.HTTPError as exc:
                detail = exc.read(65536).decode("utf-8", "replace")
                retry_after = exc.headers.get("Retry-After")
                remaining = exc.headers.get("X-RateLimit-Remaining")
                reset = exc.headers.get("X-RateLimit-Reset")
                retryable = exc.code in {429, 500, 502, 503, 504}
                if exc.code == 403 and remaining == "0":
                    retryable = True
                last_error = AuditError(
                    f"GitHub HTTP {exc.code} for {url}: {core.redact(detail, self.token)}"
                )
                if not retryable or attempt >= self.retries:
                    raise last_error
                delay = min(60.0, 2.0**attempt)
                if retry_after and retry_after.isdigit():
                    delay = min(120.0, float(retry_after))
                elif remaining == "0" and reset and reset.isdigit():
                    delay = min(120.0, max(1.0, int(reset) - time.time()))
                time.sleep(delay)
            except (AuditError, OSError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = exc
                if isinstance(exc, AuditError) or attempt >= self.retries:
                    raise AuditError(
                        f"GitHub request failed for {url}: {core.redact(str(exc), self.token)}"
                    ) from exc
                time.sleep(min(30.0, 2.0**attempt))
        raise AuditError(f"GitHub request failed: {last_error}")

    def paginate(self, path: str, *, max_pages: int = 100) -> list[Any]:
        first_url = _api_url(path, self.api_base)
        expected_path = urllib.parse.urlsplit(first_url).path
        url: str | None = first_url
        results: list[Any] = []
        seen: set[str] = set()
        pages = 0
        while url:
            if url in seen:
                raise AuditError("pagination cycle observed")
            seen.add(url)
            pages += 1
            if pages > max_pages:
                raise AuditError(f"pagination exceeded {max_pages} pages for {path}")
            response = self.request(url)
            if not isinstance(response.data, list):
                raise AuditError(f"expected list response while paginating {path}")
            results.extend(response.data)
            url = next_link(response.headers.get("link"), expected_path=expected_path)
        return results

    def download_archive(
        self,
        full_name: str,
        revision: str,
        target: Path,
        max_bytes: int,
    ) -> int:
        if not core.re.fullmatch(r"[0-9a-f]{40}", revision):
            raise AuditError("archive revision must be an exact 40-character commit")
        owner, repository = full_name.split("/", 1)
        path = (
            f"/repos/{urllib.parse.quote(owner, safe='')}/"
            f"{urllib.parse.quote(repository, safe='')}/tarball/{revision}"
        )
        response = self.request(
            path,
            stream_to=target,
            max_bytes=max_bytes,
        )
        return int((response.data or {}).get("bytes") or 0)


def repository_inventory_digest(repositories: Iterable[Mapping[str, Any]]) -> str:
    names: list[str] = []
    for repository in repositories:
        full_name = repository.get("full_name")
        if not isinstance(full_name, str) or full_name.count("/") != 1:
            raise AuditError("organization inventory contains a malformed repository name")
        names.append(full_name)
    if len(names) != len(set(name.lower() for name in names)):
        raise AuditError("organization inventory contains duplicate repositories")
    names.sort(key=str.lower)
    return core.sha256_bytes(core.canonical_json_bytes(names))


def enforce_inventory_minimum(repositories: Sequence[Any], minimum: int) -> None:
    if minimum <= 0:
        raise AuditError("expected repository minimum must be positive")
    if len(repositories) < minimum:
        raise AuditError(
            f"organization inventory is incomplete: observed {len(repositories)}, expected at least {minimum}"
        )


def run_shard(args: argparse.Namespace) -> int:
    token = args.token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    client = HardenedGitHubClient(
        token or "",
        timeout=args.timeout,
        retries=args.retries,
        api_base=args.api_base,
        max_json_bytes=args.max_json_bytes,
    )
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    repositories = core._load_repo_metadata(client, args.org)
    enforce_inventory_minimum(repositories, args.expected_repositories_minimum)
    inventory_sha256 = repository_inventory_digest(repositories)
    selected = core.select_shard(repositories, args.shard_index, args.shard_count)
    archive_dir = Path(
        tempfile.mkdtemp(prefix=f"szl-deep-audit-v2-{args.shard_index}-")
    )

    repo_summaries: list[dict[str, Any]] = []
    inventory_rows: list[dict[str, Any]] = []
    findings: list[Any] = []
    errors: list[dict[str, str]] = []
    try:
        for repository in selected:
            full_name = str(repository["full_name"])
            try:
                summary, rows, repo_findings = core.audit_repository(
                    client,
                    repository,
                    archive_dir=archive_dir,
                    max_file_bytes=args.max_file_bytes,
                    max_archive_bytes=args.max_archive_bytes,
                )
                summary["collector_schema"] = SCHEMA
                repo_summaries.append(summary)
                inventory_rows.extend(rows)
                findings.extend(repo_findings)
            except Exception as exc:  # repository isolation is part of the receipt
                message = core.redact(str(exc), client.token)
                errors.append({"repository": full_name, "error": message})
                findings.append(
                    core.Finding(
                        repository=full_name,
                        severity="P0",
                        category="collector",
                        rule_id="repository-audit-failed",
                        path=None,
                        line=None,
                        message="Repository audit failed before complete evidence was emitted.",
                        evidence=message,
                    )
                )
                repo_summaries.append(
                    {
                        "schema": core.SCHEMA,
                        "collector_schema": SCHEMA,
                        "repository": full_name,
                        "state": "INCOMPLETE",
                        "error": message,
                        "file_count": None,
                        "finding_counts": {"P0": 1},
                    }
                )
    finally:
        shutil.rmtree(archive_dir, ignore_errors=True)

    repo_summaries.sort(key=lambda row: str(row["repository"]).lower())
    inventory_rows.sort(
        key=lambda row: (str(row["repository"]).lower(), str(row["path"]))
    )
    finding_dicts = sorted(
        (finding.as_dict() for finding in findings),
        key=lambda row: (
            {"P0": 0, "P1": 1, "P2": 2, "P3": 3}.get(
                str(row["severity"]), 9
            ),
            str(row["repository"]).lower(),
            str(row.get("path") or ""),
            str(row["rule_id"]),
        ),
    )

    inventory_path = output / f"file-inventory-shard-{args.shard_index}.ndjson.gz"
    inventory_count, inventory_digest = core._write_ndjson_gzip(
        inventory_path, inventory_rows
    )
    findings_path = output / f"findings-shard-{args.shard_index}.json"
    core._write_json(findings_path, finding_dicts)
    repos_path = output / f"repositories-shard-{args.shard_index}.json"
    core._write_json(repos_path, repo_summaries)

    severity_counts = Counter(row["severity"] for row in finding_dicts)
    state = (
        "INCOMPLETE"
        if errors
        else "FAILED_CLOSED"
        if severity_counts["P0"]
        else "ACTION_REQUIRED"
        if severity_counts["P1"]
        else "OBSERVED"
    )
    receipt = {
        "schema": SCHEMA,
        "generated_at": core.utc_now(),
        "organization": args.org,
        "state": state,
        "shard_index": args.shard_index,
        "shard_count": args.shard_count,
        "organization_repository_count": len(repositories),
        "organization_repository_minimum": args.expected_repositories_minimum,
        "organization_inventory_sha256": inventory_sha256,
        "selected_repository_count": len(selected),
        "audited_repository_count": len(repo_summaries),
        "inventory_row_count": inventory_count,
        "inventory_uncompressed_sha256": inventory_digest,
        "inventory_archive_sha256": core.sha256_bytes(inventory_path.read_bytes()),
        "repositories_sha256": core.sha256_bytes(repos_path.read_bytes()),
        "findings_sha256": core.sha256_bytes(findings_path.read_bytes()),
        "finding_counts": dict(sorted(severity_counts.items())),
        "errors": errors,
        "source": {
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "workflow_sha": os.environ.get("GITHUB_SHA"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        },
        "authority": {
            "read_only": True,
            "external_effectors": [],
            "production_authorization": False,
            "secret_values_emitted": False,
            "api_origin": "https://api.github.com",
            "archive_origin": "https://codeload.github.com",
            "archive_authorization_forwarded": False,
        },
    }
    core._write_json(output / f"receipt-shard-{args.shard_index}.json", receipt)
    print(json.dumps({"state": state, "receipt": receipt}, sort_keys=True))
    return 2 if errors else 0


def merge_shards(args: argparse.Namespace) -> int:
    source = Path(args.input_dir)
    digests: set[str] = set()
    counts: set[int] = set()
    minimums: set[int] = set()
    for index in range(args.shard_count):
        receipt_path = source / f"receipt-shard-{index}.json"
        if not receipt_path.is_file():
            raise AuditError(f"missing shard receipt: {receipt_path}")
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AuditError(f"shard {index} receipt is unreadable") from exc
        digest = receipt.get("organization_inventory_sha256")
        count = receipt.get("organization_repository_count")
        minimum = receipt.get("organization_repository_minimum")
        if not isinstance(digest, str) or not core.re.fullmatch(r"[0-9a-f]{64}", digest):
            raise AuditError(f"shard {index} has no valid organization inventory digest")
        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise AuditError(f"shard {index} has an invalid repository count")
        if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum <= 0:
            raise AuditError(f"shard {index} has an invalid repository minimum")
        if count < minimum:
            raise AuditError(f"shard {index} did not satisfy its repository minimum")
        digests.add(digest)
        counts.add(count)
        minimums.add(minimum)
    if len(digests) != 1 or len(counts) != 1 or len(minimums) != 1:
        raise AuditError("audit shards disagree on the organization inventory")

    result = core.merge_shards(args)
    receipt_path = Path(args.output_dir) / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["schema"] = SCHEMA
    receipt["organization_inventory_sha256"] = next(iter(digests))
    receipt["organization_repository_minimum"] = next(iter(minimums))
    receipt.setdefault("authority", {})["archive_authorization_forwarded"] = False
    receipt["authority"]["api_origin"] = "https://api.github.com"
    receipt["authority"]["archive_origin"] = "https://codeload.github.com"
    core._write_json(receipt_path, receipt)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    shard = subparsers.add_parser("shard", help="audit one deterministic repository shard")
    shard.add_argument("--org", default=core.DEFAULT_ORG)
    shard.add_argument("--shard-index", type=int, required=True)
    shard.add_argument("--shard-count", type=int, default=core.DEFAULT_SHARD_COUNT)
    shard.add_argument("--output-dir", required=True)
    shard.add_argument("--token", default=None)
    shard.add_argument("--api-base", default="https://api.github.com")
    shard.add_argument("--timeout", type=float, default=core.DEFAULT_TIMEOUT)
    shard.add_argument("--retries", type=int, default=core.DEFAULT_RETRIES)
    shard.add_argument("--max-json-bytes", type=int, default=DEFAULT_MAX_JSON_BYTES)
    shard.add_argument("--max-file-bytes", type=int, default=core.DEFAULT_MAX_FILE_BYTES)
    shard.add_argument("--max-archive-bytes", type=int, default=core.DEFAULT_MAX_ARCHIVE_BYTES)
    shard.add_argument(
        "--expected-repositories-minimum",
        type=int,
        default=int(
            os.environ.get(
                "EXPECTED_GITHUB_REPOSITORIES_MINIMUM",
                str(DEFAULT_EXPECTED_REPOSITORIES_MINIMUM),
            )
        ),
    )
    shard.set_defaults(handler=run_shard)

    merge = subparsers.add_parser("merge", help="merge and verify all shard evidence")
    merge.add_argument("--org", default=core.DEFAULT_ORG)
    merge.add_argument("--shard-count", type=int, default=core.DEFAULT_SHARD_COUNT)
    merge.add_argument("--input-dir", required=True)
    merge.add_argument("--output-dir", required=True)
    merge.set_defaults(handler=merge_shards)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except AuditError as exc:
        print(json.dumps({"state": "INCOMPLETE", "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
