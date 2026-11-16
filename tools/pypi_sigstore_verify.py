#!/usr/bin/env python3
"""Sigstore verification of PyPI publish attestations for the szl-holdings estate.

For every published package in governance/pypi/pypi-packages.v1.json this
downloads the latest distribution files from PyPI, hashes them locally, and
cryptographically verifies each PEP 740 publish attestation with sigstore:
DSSE signature, Fulcio certificate chain, Rekor transparency inclusion, and
the GitHub Trusted Publisher identity (OIDC issuer, source repository,
workflow file, environment). It also confirms that the verified
certificate's source repository digest matches the release tag commit.

Fail-closed: any infrastructure or verification error is UNKNOWN, never
PASS. Exit code 1 if any FAILED or UNKNOWN remains. Writes a JSON report
and a Markdown summary.
"""
from __future__ import annotations

import argparse
import hashlib
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

from pypi_attestations import Attestation, Distribution, GitHubPublisher

GH_API = "https://api.github.com"
PREDICATE_PUBLISH = "https://docs.pypi.org/attestations/publish/v1"
SOURCE_DIGEST_OID = "1.3.6.1.4.1.57264.1.13"


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class FetchError(Exception):
    pass


def fetch(url: str, token: str | None = None, raw: bool = False, retries: int = 3):
    headers = {"User-Agent": "szl-pypi-sigstore-verify/1"}
    if token and urllib.parse.urlsplit(url).hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    last: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read()
                return r.status, body if raw else json.loads(body or b"null")
        except urllib.error.HTTPError as e:
            return e.code, None
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(2 * (attempt + 1))
    raise FetchError(f"{url}: {last}")


def verify_package(org: str, m: dict, token: str | None, results: list, verbose: bool) -> None:
    pkg, repo, env = m["name"], m["repo"], m.get("github_environment", "pypi")
    tag_pattern = m.get("tag_pattern", "v<version>")
    entry: dict = {"package": pkg, "repo": repo, "files": {}, "status": "UNKNOWN", "detail": ""}
    results.append(entry)
    try:
        st, meta = fetch(f"https://pypi.org/pypi/{norm(pkg)}/json")
        if st != 200 or not isinstance(meta, dict) or not isinstance((meta.get("info") or {}).get("version"), str):
            entry["detail"] = f"project fetch HTTP {st}"
            return
        version = meta["info"]["version"]
        entry["version"] = version
        files = [u for u in (meta.get("urls") or []) if isinstance(u, dict) and isinstance(u.get("filename"), str)]
        if not files:
            entry["status"] = "FAILED"
            entry["detail"] = "release metadata lists no files"
            return
        failures: list[str] = []
        unknowns: list[str] = []
        digests: set[str] = set()
        publisher_ok = True
        for u in files:
            name, url = u["filename"], u.get("url")
            meta_sha = (u.get("digests") or {}).get("sha256")
            try:
                st, body = fetch(url, raw=True)
                if st != 200 or not body:
                    unknowns.append(f"{name}: download HTTP {st}")
                    continue
                local_sha = hashlib.sha256(body).hexdigest()
                dist = Distribution(name=name, digest=local_sha)
                if not isinstance(meta_sha, str) or meta_sha.lower() != local_sha:
                    failures.append(f"{name}: local SHA-256 differs from PyPI metadata")
                prov_url = (f"https://pypi.org/integrity/{norm(pkg)}/"
                            f"{urllib.parse.quote(version, safe='')}/{urllib.parse.quote(name, safe='')}/provenance")
                st, prov = fetch(prov_url)
                if st != 200 or not isinstance(prov, dict) or not isinstance(prov.get("attestation_bundles"), list) or not prov["attestation_bundles"]:
                    failures.append(f"{name}: provenance missing or unreadable (HTTP {st})")
                    continue
                for bundle in prov["attestation_bundles"]:
                    p = bundle.get("publisher") or {}
                    observed = (p.get("kind"), p.get("repository"), p.get("workflow"), p.get("environment"))
                    expected = ("GitHub", f"{org}/{repo}", "publish-pypi.yml", env)
                    if observed != expected:
                        publisher_ok = False
                        failures.append(f"{name}: publisher={observed!r}; expected={expected!r}")
                    attestations = bundle.get("attestations") or []
                    if not attestations:
                        failures.append(f"{name}: no attestations in bundle")
                        continue
                    for raw_att in attestations:
                        att = Attestation.model_validate(raw_att)
                        identity = GitHubPublisher(repository=f"{org}/{repo}", workflow="publish-pypi.yml", environment=env)
                        predicate_type, _pred = att.verify(identity, dist)
                        if predicate_type != PREDICATE_PUBLISH:
                            failures.append(f"{name}: predicate type {predicate_type!r}")
                        for oid, value in (att.certificate_claims or {}).items():
                            if oid == SOURCE_DIGEST_OID and re.fullmatch(r"[0-9a-fA-F]{40}", str(value)):
                                digests.add(str(value).lower())
                if verbose:
                    print(f"[ok ] {pkg} {name}: signature, chain, transparency, identity verified", flush=True)
            except Exception as e:  # noqa: BLE001
                unknowns.append(f"{name}: {str(e)[:160]}")
        entry["attested_digests"] = sorted(digests)
        tag = tag_pattern.replace("<version>", version)
        entry["tag"] = tag
        tag_commit = None
        if len(digests) == 1:
            st, ref = fetch(f"{GH_API}/repos/{org}/{repo}/git/ref/tags/{urllib.parse.quote(tag, safe='')}", token=token)
            if st == 200 and isinstance(ref, dict):
                obj = ref.get("object") or {}
                if obj.get("type") in ("commit", "tag"):
                    tag_commit = obj.get("sha")
                if obj.get("type") == "tag":
                    st2, tobj = fetch(f"{GH_API}/repos/{org}/{repo}/git/tags/{obj['sha']}", token=token)
                    target = (tobj or {}).get("object") if isinstance(tobj, dict) else None
                    if isinstance(target, dict) and target.get("type") == "commit":
                        tag_commit = target.get("sha")
        entry["tag_commit"] = tag_commit
        if failures:
            entry["status"] = "FAILED"
            entry["detail"] = "; ".join((failures + unknowns)[:4])
            return
        if unknowns:
            entry["status"] = "UNKNOWN"
            entry["detail"] = "; ".join(unknowns[:4])
            return
        if not publisher_ok:
            entry["status"] = "FAILED"
            entry["detail"] = "publisher mismatch"
            return
        if len(digests) != 1:
            entry["status"] = "UNKNOWN"
            entry["detail"] = f"attested source digests {sorted(digests)}"
            return
        if tag_commit is None:
            entry["status"] = "UNKNOWN"
            entry["detail"] = f"tag {tag} lookup unavailable"
            return
        if tag_commit == digests.pop():
            entry["status"] = "VERIFIED"
            entry["detail"] = f"{version}: attestations verified; tag {tag} matches attested source commit"
            return
        exc = m.get("tag_exception") or {}
        if exc.get("tag") == tag and exc.get("tag_commit") == tag_commit and exc.get("attested_commit") in digests:
            entry["status"] = "UNKNOWN"
            entry["detail"] = f"tag {tag} matches recorded exception: {exc.get('reason', '')[:100]}"
            return
        entry["status"] = "FAILED"
        entry["detail"] = f"tag {tag} commit {str(tag_commit)[:12]} differs from attested digest"
    except FetchError as e:
        entry["detail"] = f"fetch error: {str(e)[:200]}"
    except Exception as e:  # noqa: BLE001
        entry["status"] = "UNKNOWN"
        entry["detail"] = f"unexpected error: {str(e)[:200]}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default="governance/pypi/pypi-packages.v1.json")
    ap.add_argument("--report", default="pypi-sigstore-report.json")
    ap.add_argument("--summary", default="pypi-sigstore-summary.md")
    ap.add_argument("--only", nargs="*", help="limit to these package names")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    org = manifest["owner"]["github_org"]
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    results: list[dict] = []
    for m in manifest["packages"]:
        if m.get("status") != "published":
            continue
        if args.only and m.get("name") not in args.only:
            continue
        verify_package(org, m, token, results, args.verbose)
        r = results[-1]
        print(f"[{r['status']:8}] {r['package']:28} {str(r.get('version', '?')):12} {r['detail'][:90]}", flush=True)

    counts = {s: sum(1 for r in results if r["status"] == s) for s in ("VERIFIED", "FAILED", "UNKNOWN")}
    verdict = "PASS" if counts["FAILED"] == 0 and counts["UNKNOWN"] == 0 else "FAIL"
    report = {
        "schema": "szl.pypi-sigstore-verify.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "verdict": verdict,
        "counts": counts,
        "results": results,
    }
    Path(args.report).write_text(json.dumps(report, indent=1), encoding="utf-8")
    lines = [f"# PyPI sigstore verification - {verdict}", "",
             f"Generated {report['generated_at']} - VERIFIED {counts['VERIFIED']} - FAILED {counts['FAILED']} - UNKNOWN {counts['UNKNOWN']}", ""]
    bad = [r for r in results if r["status"] != "VERIFIED"]
    if bad:
        lines += ["| package | status | detail |", "|---|---|---|"]
        lines += [f"| {r['package']} | {r['status']} | {r['detail'][:120]} |" for r in bad]
    else:
        lines.append("Every published package's publish attestations verified against live PyPI distribution bytes.")
    Path(args.summary).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(counts), verdict)
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
