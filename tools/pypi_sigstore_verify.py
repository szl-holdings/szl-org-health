#!/usr/bin/env python3
"""Verify live distribution bytes, publish attestations, and source tags.

This command shares the exact-release verifier with the release-path audit.
VERIFIED covers artifact bytes, signatures, repository/workflow identity, and
source-tag identity, including the signed deployment-environment extension.
This subset report cannot establish aggregate production readiness.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

if __package__:
    from .pypi_distribution_verification import ENVIRONMENT_EVIDENCE, MAX_RELEASE_FILES, NoRedirect, verify_release
else:
    from pypi_distribution_verification import ENVIRONMENT_EVIDENCE, MAX_RELEASE_FILES, NoRedirect, verify_release

GH_API = "https://api.github.com"
MAX_METADATA_BYTES = 16 * 1024 * 1024
VERIFICATION_SCOPE = "distribution-bytes-publish-attestations-repository-workflow-deployment-environment-source-tag"


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class FetchError(Exception):
    pass


def fetch(url: str, token: str | None = None, retries: int = 3):
    """Bounded JSON reads; no redirect may carry GitHub authorization elsewhere."""
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc not in ("pypi.org", "api.github.com")
            or parsed.query or parsed.fragment):
        raise FetchError("metadata URL rejected")
    headers = {"User-Agent": "szl-pypi-sigstore-verify/2", "Accept-Encoding": "identity"}
    if token and parsed.netloc == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    last = "unavailable"
    for attempt in range(retries):
        try:
            request = urllib.request.Request(url, headers=headers)
            opener = urllib.request.build_opener(NoRedirect())
            with opener.open(request, timeout=30) as response:
                if response.status != 200 or response.geturl() != url:
                    raise FetchError("metadata response identity changed")
                if response.headers.get("Content-Encoding", "identity") != "identity":
                    raise FetchError("encoded metadata refused")
                body = response.read(MAX_METADATA_BYTES + 1)
                if len(body) > MAX_METADATA_BYTES:
                    raise FetchError("metadata exceeds byte bound")
                return response.status, json.loads(body or b"null")
        except urllib.error.HTTPError as exc:
            return exc.code, None
        except FetchError:
            raise
        except Exception as exc:  # credentials and server response bodies never enter reports
            last = type(exc).__name__
            if attempt + 1 < retries:
                time.sleep(2 * (attempt + 1))
    raise FetchError("metadata fetch unavailable: " + last)


def release_tag_commit(org: str, repo: str, tag: str, token: str | None) -> str | None:
    status, ref = fetch(
        f"{GH_API}/repos/{org}/{repo}/git/ref/tags/{urllib.parse.quote(tag, safe='')}",
        token=token,
    )
    if status != 200 or not isinstance(ref, dict):
        return None
    obj, seen = ref.get("object"), set()
    for _ in range(8):
        if not isinstance(obj, dict):
            return None
        sha = obj.get("sha")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
            return None
        sha = sha.lower()
        if obj.get("type") == "commit":
            return sha
        if obj.get("type") != "tag" or sha in seen:
            return None
        seen.add(sha)
        status, annotated = fetch(f"{GH_API}/repos/{org}/{repo}/git/tags/{sha}", token=token)
        if status != 200 or not isinstance(annotated, dict) or annotated.get("sha") != sha:
            return None
        obj = annotated.get("object")
    return None


def verify_package(org: str, m: dict, token: str | None, results: list, verbose: bool) -> None:
    pkg, repo, environment = m["name"], m["repo"], m.get("github_environment", "pypi")
    entry = {
        "package": pkg, "repo": repo, "files": {}, "status": "UNKNOWN", "detail": "",
        "verification_scope": VERIFICATION_SCOPE,
        "publisher_environment_cryptographically_verified": False,
        "publisher_environment_evidence": "UNVERIFIED",
    }
    results.append(entry)
    try:
        status, meta = fetch(f"https://pypi.org/pypi/{norm(pkg)}/json")
        if (status != 200 or not isinstance(meta, dict) or not isinstance(meta.get("info"), dict)
                or not isinstance(meta["info"].get("version"), str) or not meta["info"]["version"]):
            entry["detail"] = f"project metadata unavailable (HTTP {status})"
            return
        version = entry["version"] = meta["info"]["version"]
        rows = meta.get("urls")
        if (not isinstance(rows, list) or not 0 < len(rows) <= MAX_RELEASE_FILES
                or any(not isinstance(row, dict) or not isinstance(row.get("filename"), str)
                       or not row["filename"] for row in rows)
                or len({row["filename"] for row in rows}) != len(rows)):
            entry.update(status="FAILED", detail="release file list empty, malformed, duplicate, or excessive")
            return
        files = {row["filename"]: row for row in rows}
        provenances = {}
        for name in sorted(files):
            url = (f"https://pypi.org/integrity/{norm(pkg)}/"
                   f"{urllib.parse.quote(version, safe='')}/{urllib.parse.quote(name, safe='')}/provenance")
            status, provenance = fetch(url)
            if status != 200 or not isinstance(provenance, dict):
                entry["detail"] = f"publish provenance unavailable (HTTP {status})"
                return
            provenances[name] = provenance
        expected = ("GitHub", f"{org}/{repo}", "publish-pypi.yml", environment)
        verified = verify_release(pkg, version, files, provenances, expected)
        entry.update(
            files=verified.get("files", {}),
            attested_digests=verified.get("source_digests", []),
            observed_at=verified.get("observed_at"),
            verifier_versions=verified.get("verifier_versions", {}),
        )
        if verified.get("status") != "VERIFIED":
            entry.update(status="FAILED" if verified.get("status") == "FAILED" else "UNKNOWN",
                         detail=verified.get("detail", "live verification unavailable"))
            return
        digests = entry["attested_digests"]
        if (set(entry["files"]) != set(files) or not isinstance(digests, list) or len(digests) != 1
                or not isinstance(digests[0], str) or not re.fullmatch(r"[0-9a-f]{40}", digests[0])
                or verified.get("publisher_environment_cryptographically_verified") is not True
                or verified.get("publisher_environment_evidence") != ENVIRONMENT_EVIDENCE
                or verified.get("publisher_environment") != environment
                or any(not isinstance(item, dict)
                       or item.get("publisher_environment") != environment
                       or item.get("publisher_environment_evidence") != ENVIRONMENT_EVIDENCE
                       for item in entry["files"].values())):
            entry.update(status="FAILED", detail="live verifier returned incomplete release or signed environment coverage")
            return
        entry.update(publisher_environment_cryptographically_verified=True,
                     publisher_environment=environment, publisher_environment_evidence=ENVIRONMENT_EVIDENCE)
        tag = m.get("tag_pattern", "v<version>").replace("<version>", version)
        entry["tag"] = tag
        commit = entry["tag_commit"] = release_tag_commit(org, repo, tag, token)
        if commit is None:
            entry["detail"] = "release tag commit unavailable"
            return
        if commit != digests[0]:
            exception = m.get("tag_exception") or {}
            if (exception.get("tag") == tag and exception.get("tag_commit") == commit
                    and exception.get("attested_commit") == digests[0]):
                entry["detail"] = "tag matches a recorded exception; exact source-tag identity remains unverified"
                return
            entry.update(status="FAILED", detail="release tag commit differs from verified source digest")
            return
        entry.update(
            status="VERIFIED",
            detail=f"{version}: exact artifacts, publish attestations, signed environment and source tag verified",
        )
        if verbose:
            for name in sorted(entry["files"]):
                print(f"[ok ] {pkg} {name}: bytes, signature, repository/workflow, signed environment and source verified", flush=True)
    except Exception as exc:
        entry.update(status="UNKNOWN", detail="verification unavailable: " + type(exc).__name__)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default="governance/pypi/pypi-packages.v1.json")
    ap.add_argument("--report", default="pypi-sigstore-report.json")
    ap.add_argument("--summary", default="pypi-sigstore-summary.md")
    ap.add_argument("--only", nargs="+", help="limit to these published package names")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    published = [m for m in manifest["packages"] if m.get("status") == "published"]
    if args.only:
        unavailable = set(args.only) - {m.get("name") for m in published}
        if unavailable:
            ap.error("not a published manifest package: " + ", ".join(sorted(unavailable)))
    org = manifest["owner"]["github_org"]
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    results = []
    for package in published:
        if args.only and package.get("name") not in args.only:
            continue
        verify_package(org, package, token, results, args.verbose)
        row = results[-1]
        print(f"[{row['status']:8}] {row['package']:28} {str(row.get('version', '?')):12} {row['detail'][:120]}", flush=True)
    counts = {s: sum(1 for row in results if row["status"] == s) for s in ("VERIFIED", "FAILED", "UNKNOWN")}
    verdict = "PASS" if results and counts["FAILED"] == 0 and counts["UNKNOWN"] == 0 else "FAIL"
    report = {
        "schema": "szl.pypi-sigstore-verify.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "verification_scope": VERIFICATION_SCOPE,
        "publisher_environment_cryptographically_verified": bool(results) and all(
            row.get("publisher_environment_cryptographically_verified") is True for row in results),
        "verdict": verdict, "counts": counts, "results": results,
    }
    Path(args.report).write_text(json.dumps(report, indent=1), encoding="utf-8")
    lines = [
        f"# PyPI sigstore verification - {verdict}", "",
        f"Generated {report['generated_at']} - VERIFIED {counts['VERIFIED']} - FAILED {counts['FAILED']} - UNKNOWN {counts['UNKNOWN']}", "",
        "Scope: exact distribution bytes, publish signatures, repository/workflow identity, signed deployment environment, and source tags.",
        "A verified environment requires the signed Fulcio extension on every attestation. This subset report does not establish production readiness.", "",
    ]
    bad = [row for row in results if row["status"] != "VERIFIED"]
    if bad:
        lines += ["| package | status | detail |", "|---|---|---|"]
        lines += [f"| {row['package']} | {row['status']} | {row['detail'][:120]} |" for row in bad]
    elif results:
        lines.append("Every selected published package passed the declared verification scope.")
    else:
        lines.append("No published packages were verified; audit fails closed.")
    Path(args.summary).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(counts), verdict)
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
