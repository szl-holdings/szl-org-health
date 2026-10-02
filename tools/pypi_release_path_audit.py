#!/usr/bin/env python3
"""PyPI release-path audit for the szl-holdings estate (stdlib only, fail-closed).

For every package in governance/pypi/pypi-packages.v1.json this checks, from live sources:

  GitHub  * the repository's publish-pypi.yml and release gate are byte-identical to the canonical copies
          * no workflow in the repository references a PyPI API token secret
          * the `pypi` (or declared) environment exists and is restricted to release tags
          * a tag ruleset protects refs/tags/v* (creation/update/deletion)
          * for the latest PyPI version a git tag exists at the PyPI-attested source commit
  PyPI    * the project exists (published) or does not (queued/hold/internal/never)
          * the latest release carries PEP 740 provenance for every file
          * the provenance publisher is GitHub Actions, repo szl-holdings/<repo>, workflow publish-pypi.yml
          * project URLs point at the GitHub source (what PyPI verifies against the Trusted Publisher)
  Internal/never pyproject files carry the `Private :: Do Not Upload` classifier.

Outcomes are PASS | FAIL | UNKNOWN per check; UNKNOWN is never PASS. Exit code 1 if any
FAIL or UNKNOWN remains. Writes a JSON report and a Markdown summary.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

GH_API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
PRIVATE = "Private :: Do Not Upload"
TOKEN_MARKERS = ("PYPI_API_TOKEN", "PYPI_TOKEN", "TWINE_PASSWORD", "TWINE_USERNAME", "POETRY_PYPI_TOKEN", "UV_PUBLISH_TOKEN", "HATCH_INDEX_AUTH", "PDM_PUBLISH_PASSWORD")
OID_SOURCE_DIGEST = "1.3.6.1.4.1.57264.1.13"
REQUIRED_TAG_RULES = {"creation", "update", "deletion"}


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def exact_https_host(url: str, host: str) -> bool:
    if not isinstance(url, str):
        return False
    try:
        parsed = urllib.parse.urlsplit(url)
        return (
            parsed.scheme == "https" and parsed.hostname == host
            and parsed.username is None and parsed.password is None
            and parsed.port is None and not parsed.fragment
        )
    except ValueError:
        return False


def release_tag_family(m: dict) -> str | None:
    pattern = m.get("tag_pattern", "v<version>")
    if not isinstance(pattern, str) or pattern.count("<version>") != 1:
        return None
    prefix, suffix = pattern.split("<version>")
    if not prefix or suffix or "/" in prefix or "*" in prefix:
        return None
    return f"refs/tags/{prefix}*"


def tag_ruleset_result(http: Http, org: str, repo: str, m: dict, rulesets: object) -> tuple[str, str]:
    """Verify an active ruleset covers the whole release-tag family and its controls."""
    family = release_tag_family(m)
    if family is None:
        return "UNKNOWN", f"unsupported manifest tag_pattern={m.get('tag_pattern')!r}"
    if not isinstance(rulesets, list):
        return "UNKNOWN", "tag ruleset list response malformed"
    if any(not isinstance(r, dict) for r in rulesets):
        return "UNKNOWN", "tag ruleset list contains a malformed entry"
    active = [r for r in rulesets if isinstance(r, dict) and r.get("enforcement") == "active"]
    if not active:
        if len(rulesets) >= 100:
            return "UNKNOWN", f"first 100 tag rulesets contain no active match for {family}; more pages may exist"
        return "FAIL", f"no active tag ruleset for {family} (listed={len(rulesets)})"
    failures, unknowns = [], []
    for summary in active:
        ruleset_id = summary.get("id")
        name = summary.get("name", ruleset_id)
        if summary.get("target") != "tag":
            unknowns.append(f"{name}: tag ruleset list contains an unexpected target")
            continue
        if not isinstance(ruleset_id, int) or ruleset_id <= 0:
            unknowns.append(f"{name}: missing ruleset id")
            continue
        endpoint = f"{GH_API}/repos/{org}/{repo}/rulesets/{ruleset_id}?includes_parents=true"
        st, detail = http.get(endpoint)
        if st != 200:
            unknowns.append(f"{name} ({ruleset_id}): detail HTTP {st}; access or existence unverified")
            continue
        if not isinstance(detail, dict) or detail.get("id") != ruleset_id or detail.get("target") != "tag" or detail.get("enforcement") != "active":
            unknowns.append(f"{name} ({ruleset_id}): detail malformed or inconsistent")
            continue
        conditions = detail.get("conditions")
        ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
        if not isinstance(ref_name, dict) or not isinstance(ref_name.get("include"), list) or not isinstance(ref_name.get("exclude"), list):
            unknowns.append(f"{name} ({ruleset_id}): ref conditions unavailable")
            continue
        includes, excludes = ref_name["include"], ref_name["exclude"]
        # These patterns demonstrably cover every release tag, including future versions.
        if not any(p in (family, "refs/tags/*", "~ALL") for p in includes):
            failures.append(f"{name} ({ruleset_id}): include={includes!r} does not cover {family}")
            continue
        if excludes:
            unknowns.append(f"{name} ({ruleset_id}): exclude={excludes!r}; family coverage unverified")
            continue
        rules = detail.get("rules")
        if not isinstance(rules, list) or not all(isinstance(r, dict) and isinstance(r.get("type"), str) for r in rules):
            unknowns.append(f"{name} ({ruleset_id}): rules unavailable or malformed")
            continue
        missing = REQUIRED_TAG_RULES - {r["type"] for r in rules}
        if missing:
            failures.append(f"{name} ({ruleset_id}): missing rules {sorted(missing)} for {family}")
            continue
        bypass = detail.get("bypass_actors")
        if not isinstance(bypass, list):
            unknowns.append(f"{name} ({ruleset_id}): bypass actors not visible; admin-only control unverified")
            continue
        if any(
            not isinstance(actor, dict)
            or not (
                actor.get("actor_type") == "OrganizationAdmin"
                or (actor.get("actor_type") == "RepositoryRole" and actor.get("actor_id") == 5)
            )
            for actor in bypass
        ):
            failures.append(f"{name} ({ruleset_id}): non-admin bypass actor present")
            continue
        return "PASS", f"{name} ({ruleset_id}) covers {family}; rules={sorted(REQUIRED_TAG_RULES)}; bypass=admin-only"
    if unknowns:
        return "UNKNOWN", "; ".join(unknowns + failures)
    if len(rulesets) >= 100:
        return "UNKNOWN", f"first 100 tag rulesets contain no verified protection for {family}; more pages may exist; " + "; ".join(failures)
    return "FAIL", "; ".join(failures)


class Http:
    def __init__(self, token: str | None):
        self.token = token

    def get(self, url: str, accept: str | None = None, raw: bool = False):
        github_api = exact_https_host(url, "api.github.com")
        if github_api and not self.token and shutil.which("gh"):
            # local operator fallback: let the gh CLI supply credentials (never printed here)
            cmd = ["gh", "api", url] + (["-H", f"Accept: {accept}"] if accept else [])
            p = subprocess.run(cmd, capture_output=True, text=True)
            if p.returncode != 0:
                m = re.search(r"HTTP (\d{3})", p.stderr)
                return (int(m.group(1)) if m else -1), None
            return 200, json.loads(p.stdout or "null")
        headers = {"User-Agent": "szl-pypi-release-path-audit/1"}
        if accept:
            headers["Accept"] = accept
        if self.token and github_api:
            headers["Authorization"] = f"Bearer {self.token}"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read()
                return r.status, (body if raw else json.loads(body or b"null"))
        except urllib.error.HTTPError as e:
            return e.code, None
        except Exception as e:  # noqa: BLE001
            return -1, str(e)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def der_string(value: bytes) -> str:
    # UTF8String (0x0c) / IA5String (0x16) / PrintableString (0x13) with short or long length
    if value and value[0] in (0x0C, 0x16, 0x13):
        length = value[1]
        if length < 0x80:
            return value[2:2 + length].decode("utf-8", "replace")
        n = length & 0x7F
        real = int.from_bytes(value[2:2 + n], "big")
        return value[2 + n:2 + n + real].decode("utf-8", "replace")
    return value.decode("utf-8", "replace")


def source_digest_from_cert(cert_b64: str) -> str | None:
    """Extract the Sigstore 'Source Repository Digest' extension without non-stdlib ASN.1 libs.

    The OID is encoded as 06 0a 2b 06 01 04 01 83 bf 30 01 0d; the value follows as an
    OCTET STRING wrapping a UTF8String. We locate the OID bytes and parse forward.
    """
    der = base64.b64decode(cert_b64)
    oid = bytes.fromhex("060a2b0601040183bf30010d")  # DER of OID 1.3.6.1.4.1.57264.1.13
    i = der.find(oid)
    if i < 0:
        return None
    j = i + len(oid)
    # optional BOOLEAN critical flag
    if der[j] == 0x01:
        j += 3
    if der[j] != 0x04:
        return None
    length = der[j + 1]
    if length < 0x80:
        inner = der[j + 2:j + 2 + length]
    else:
        n = length & 0x7F
        real = int.from_bytes(der[j + 2:j + 2 + n], "big")
        inner = der[j + 2 + n:j + 2 + n + real]
    return der_string(inner)


def check(results: list, pkg: str, name: str, status: str, detail: str = "") -> None:
    results.append({"package": pkg, "check": name, "status": status, "detail": detail})
    print(f"[{status:7}] {pkg:28} {name:40} {detail}", flush=True)


def audit_release_repo(http: Http, org: str, m: dict, canon: dict[str, str], results: list, repo_cache: dict) -> None:
    pkg, repo = m["name"], m["repo"]
    # --- canonical workflow + gate bytes
    for rel, key in ((".github/workflows/publish-pypi.yml", "workflow"), (".github/scripts/szl_pypi_release_gate.py", "gate")):
        st, body = http.get(f"{RAW}/{org}/{repo}/HEAD/{rel}", raw=True)
        if st != 200:
            check(results, pkg, f"canonical:{key}", "UNKNOWN",
                  f"{rel} HTTP {st}; unauthenticated raw URL cannot verify repository content")
            continue
        if key == "workflow":
            # the canonical generator must reproduce the repository's file byte-for-byte from its own SZL_PACKAGES line
            text = body.decode("utf-8", "replace")
            spec = re.search(r'SZL_PACKAGES: "([^"]*)"', text)
            ok = bool(spec) and canon["render"](spec.group(1)) == text
            declared = [s.split("=")[0] for s in spec.group(1).split(";")] if spec else []
            if norm(pkg) not in [norm(d) for d in declared]:
                check(results, pkg, "canonical:workflow-declares-package", "FAIL", f"SZL_PACKAGES={declared}")
            else:
                check(results, pkg, "canonical:workflow-declares-package", "PASS", str(declared))
        else:
            ok = sha256(body) == canon["gate_sha256"]
        check(results, pkg, f"canonical:{key}", "PASS" if ok else "FAIL", "byte-identical" if ok else "drift from canonical")
    # --- no token secrets in any workflow
    if repo not in repo_cache:
        st, tree = http.get(f"{GH_API}/repos/{org}/{repo}/contents/.github/workflows")
        workflows = tree if st == 200 and isinstance(tree, list) and all(
            isinstance(f, dict) and isinstance(f.get("name"), str)
            and (not f["name"].endswith((".yml", ".yaml"))
                 or exact_https_host(f.get("download_url"), "raw.githubusercontent.com"))
            for f in tree
        ) else None
        repo_cache[repo] = {"workflows": workflows}
        repo_cache[repo]["workflows_status"] = st
        token_hits, workflow_errors = [], []
        if repo_cache[repo]["workflows"] is not None:
            for f in repo_cache[repo]["workflows"]:
                if not f["name"].endswith((".yml", ".yaml")):
                    continue
                st2, raw = http.get(f["download_url"], raw=True)
                if st2 != 200:
                    workflow_errors.append(f"{f['name']}: HTTP {st2}")
                elif any(t in raw.decode("utf-8", "replace") for t in TOKEN_MARKERS):
                    token_hits.append(f["name"])
            repo_cache[repo]["token_hits"] = token_hits
            repo_cache[repo]["workflow_errors"] = workflow_errors
        # environments
        st, envs = http.get(f"{GH_API}/repos/{org}/{repo}/environments")
        repo_cache[repo]["environments_status"] = st
        env_rows = envs.get("environments") if isinstance(envs, dict) else None
        repo_cache[repo]["environments"] = {e["name"]: e for e in env_rows} if (
            st == 200 and isinstance(env_rows, list)
            and all(isinstance(e, dict) and isinstance(e.get("name"), str) for e in env_rows)
        ) else None
        for env_name, e in (repo_cache[repo]["environments"] or {}).items():
            st3, pol = http.get(f"{GH_API}/repos/{org}/{repo}/environments/{env_name}/deployment-branch-policies")
            e["_policies_status"] = st3
            pol_rows = pol.get("branch_policies") if isinstance(pol, dict) else None
            e["_policies"] = [(p["name"], p.get("type")) for p in pol_rows] if (
                st3 == 200 and isinstance(pol_rows, list)
                and all(isinstance(p, dict) and isinstance(p.get("name"), str) for p in pol_rows)
            ) else None
        st, rs = http.get(f"{GH_API}/repos/{org}/{repo}/rulesets?includes_parents=true&targets=tag&per_page=100")
        repo_cache[repo]["tag_rulesets_status"] = st
        repo_cache[repo]["tag_rulesets"] = rs if st == 200 else None
    rc = repo_cache[repo]
    if rc["workflows"] is None:
        check(results, pkg, "github:no-token-secrets", "UNKNOWN",
              f"workflows list HTTP {rc['workflows_status']}; access or existence unverified")
    else:
        status = "FAIL" if rc["token_hits"] else "UNKNOWN" if rc["workflow_errors"] else "PASS"
        detail = ",".join(rc["token_hits"]) or "; ".join(rc["workflow_errors"]) or "no PyPI token references"
        check(results, pkg, "github:no-token-secrets", status, detail)
    env_name = m.get("github_environment", "pypi")
    if rc["environments"] is None:
        check(results, pkg, "github:environment", "UNKNOWN",
              f"environments list HTTP {rc['environments_status']}; access or existence unverified")
    elif env_name not in rc["environments"]:
        check(results, pkg, "github:environment", "FAIL", f"environment {env_name!r} missing")
    else:
        e = rc["environments"][env_name]
        dbp = e.get("deployment_branch_policy")
        dbp = dbp if isinstance(dbp, dict) else {}
        pols = e.get("_policies")
        if pols is None:
            check(results, pkg, "github:environment-tag-only", "UNKNOWN",
                  f"{env_name} deployment policies HTTP {e.get('_policies_status')}; access or existence unverified")
        else:
            tag_only = bool(dbp.get("custom_branch_policies")) and bool(pols) and all(t == "tag" for _, t in pols)
            check(results, pkg, "github:environment-tag-only", "PASS" if tag_only else "FAIL", f"policies={pols}")
    if rc["tag_rulesets_status"] != 200:
        check(results, pkg, "github:tag-ruleset", "UNKNOWN",
              f"tag ruleset inventory HTTP {rc['tag_rulesets_status']}; access or existence unverified")
    else:
        status, detail = tag_ruleset_result(http, org, repo, m, rc["tag_rulesets"])
        check(results, pkg, "github:tag-ruleset", status, detail)

    # --- PyPI state
    st, meta = http.get(f"https://pypi.org/pypi/{norm(pkg)}/json")
    if m["status"] == "queued":
        if st == 404:
            check(results, pkg, "pypi:not-yet-published", "PASS", "queued; project absent on PyPI")
        elif st == 200:
            check(results, pkg, "pypi:not-yet-published", "FAIL", "manifest says queued but project exists on PyPI; update manifest status")
        else:
            check(results, pkg, "pypi:not-yet-published", "UNKNOWN", f"HTTP {st}")
        return
    if st != 200:
        check(results, pkg, "pypi:project", "FAIL" if st == 404 else "UNKNOWN", f"HTTP {st}")
        return
    if not isinstance(meta, dict) or not isinstance(meta.get("info"), dict) or not isinstance(meta["info"].get("version"), str):
        check(results, pkg, "pypi:project", "UNKNOWN", "project JSON response malformed")
        return
    info = meta["info"]
    version = info["version"]
    check(results, pkg, "pypi:project", "PASS", f"latest {version}")
    urls = info.get("project_urls")
    urls = urls if isinstance(urls, dict) else {}
    src = urls.get("Source") or urls.get("Repository") or urls.get("Source Code")
    expected = f"https://github.com/{org}/{repo}"
    source_ok = isinstance(src, str) and src.rstrip("/").lower() == expected.lower()
    check(results, pkg, "pypi:source-url", "PASS" if source_ok else "FAIL",
          f"observed={src!r}; expected={expected}")
    st, simple = http.get(f"https://pypi.org/simple/{norm(pkg)}/", accept="application/vnd.pypi.simple.v1+json")
    if st != 200:
        check(results, pkg, "pypi:provenance", "UNKNOWN", f"simple API HTTP {st}")
        return
    meta_files = meta.get("urls")
    simple_entries = simple.get("files") if isinstance(simple, dict) else None
    if any(
        not isinstance(rows, list)
        or any(not isinstance(row, dict) or not isinstance(row.get("filename"), str) or not row["filename"] for row in rows)
        or len({row["filename"] for row in rows}) != len(rows)
        for rows in (meta_files, simple_entries)
    ):
        check(results, pkg, "pypi:provenance", "UNKNOWN", "release metadata or Simple API filenames malformed")
        check(results, pkg, "pypi:publisher-identity", "UNKNOWN", "distribution set unverified")
        check(results, pkg, "github:release-tag", "UNKNOWN", "distribution set unverified")
        return
    latest = {u["filename"] for u in meta_files}
    simple_files = {f["filename"]: f for f in simple_entries}
    missing_files = sorted(latest - simple_files.keys())
    missing_links = sorted(name for name in latest & simple_files.keys()
                           if not exact_https_host(simple_files[name].get("provenance"), "pypi.org"))
    has_wheel = any(name.endswith(".whl") for name in latest)
    has_sdist = any(name.endswith((".tar.gz", ".zip")) for name in latest)
    incomplete = not latest or not has_wheel or not has_sdist or bool(missing_files or missing_links)
    digests, publishers = set(), set()
    fetch_errors, incomplete_attestations = [], []
    expected_publisher = ("GitHub", f"{org}/{repo}", "publish-pypi.yml")
    for name in sorted(latest - set(missing_files) - set(missing_links)):
        st, prov = http.get(simple_files[name]["provenance"])
        if st != 200:
            fetch_errors.append(f"{name}: provenance HTTP {st}")
            continue
        if not isinstance(prov, dict) or not isinstance(prov.get("attestation_bundles"), list) or not prov["attestation_bundles"]:
            incomplete_attestations.append(f"{name}: no readable attestation bundles")
            continue
        file_publishers, file_digests = set(), set()
        for b in prov["attestation_bundles"]:
            if not isinstance(b, dict) or not isinstance(b.get("publisher"), dict) or not isinstance(b.get("attestations"), list):
                incomplete_attestations.append(f"{name}: malformed attestation bundle")
                continue
            p = b["publisher"]
            publisher = (p.get("kind"), p.get("repository"), p.get("workflow"))
            if not all(isinstance(value, str) for value in publisher):
                incomplete_attestations.append(f"{name}: malformed publisher identity")
                continue
            file_publishers.add(publisher)
            for a in b["attestations"]:
                try:
                    d = source_digest_from_cert(a["verification_material"]["certificate"])
                except (KeyError, TypeError, ValueError, IndexError, binascii.Error):
                    d = None
                if d:
                    file_digests.add(d)
        if not file_publishers or not file_digests:
            incomplete_attestations.append(f"{name}: publisher or source digest missing")
        publishers.update(file_publishers)
        digests.update(file_digests)
    evidence = []
    if not has_wheel or not has_sdist:
        evidence.append(f"release metadata wheel={has_wheel} sdist={has_sdist}")
    if missing_files:
        evidence.append(f"missing from Simple API={missing_files}")
    if missing_links:
        evidence.append(f"missing or invalid PyPI provenance link={missing_links}")
    evidence.extend(fetch_errors)
    evidence.extend(incomplete_attestations)
    provenance_status = "FAIL" if incomplete else "UNKNOWN" if fetch_errors or incomplete_attestations else "PASS"
    check(results, pkg, "pypi:provenance", provenance_status,
          "; ".join(evidence) or f"{len(latest)}/{len(latest)} wheel/sdist files attested")
    if provenance_status != "PASS":
        reason = "; ".join(evidence)
        check(results, pkg, "pypi:publisher-identity", "UNKNOWN", f"per-file identity unverified: {reason}")
        check(results, pkg, "github:release-tag", "UNKNOWN", f"per-file source digest unverified: {reason}")
        return
    pub_ok = publishers == {expected_publisher}
    check(results, pkg, "pypi:publisher-identity", "PASS" if pub_ok else "FAIL", str(sorted(publishers, key=str)))
    if len(digests) != 1:
        check(results, pkg, "github:release-tag", "UNKNOWN", f"attested digests {sorted(digests)}")
        return
    digest = digests.pop()
    tag = f"v{version}" if m.get("tag_pattern", "v<version>") == "v<version>" else f"{norm(pkg)}-v{version}"
    st, ref = http.get(f"{GH_API}/repos/{org}/{repo}/git/ref/tags/{tag}")
    if st == 404:
        check(results, pkg, "github:release-tag", "UNKNOWN",
              f"tag {tag} lookup HTTP 404; missing or inaccessible (attested source {digest[:12]})")
        return
    if st != 200 or not isinstance(ref, dict):
        check(results, pkg, "github:release-tag", "UNKNOWN", f"tag lookup HTTP {st}")
        return
    obj = ref["object"]
    commit = obj["sha"]
    if obj["type"] == "tag":
        st, tobj = http.get(f"{GH_API}/repos/{org}/{repo}/git/tags/{obj['sha']}")
        commit = (tobj or {}).get("object", {}).get("sha", commit)
    exc = m.get("tag_exception") or {}
    if commit == digest:
        check(results, pkg, "github:release-tag", "PASS", f"{tag} -> {commit[:12]} == attested")
    elif exc.get("tag") == tag and exc.get("tag_commit") == commit and exc.get("attested_commit") == digest:
        check(results, pkg, "github:release-tag", "PASS", f"{tag} -> {commit[:12]} (recorded exception: {exc.get('reason', '')[:80]})")
    else:
        check(results, pkg, "github:release-tag", "FAIL", f"{tag} -> {commit[:12]} vs attested {digest[:12]}")


def audit_private_marker(http: Http, org: str, m: dict, results: list, published_names: dict[str, str] | None = None) -> None:
    published_names = published_names or {}
    st, body = http.get(f"{RAW}/{org}/{m['repo']}/HEAD/{m['path']}", raw=True)
    if st != 200:
        check(results, m.get("name") or m["path"], "private-classifier", "UNKNOWN", f"{m['path']} HTTP {st}")
        return
    try:
        doc = tomllib.loads(body.decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        check(results, m.get("name") or m["path"], "private-classifier", "FAIL", f"TOML parse error: {e}")
        return
    cls = ((doc.get("project") or {}).get("classifiers") or [])
    check(results, m.get("name") or m["path"], "private-classifier", "PASS" if PRIVATE in cls else "FAIL", m["path"])
    st, meta = http.get(f"https://pypi.org/pypi/{norm(m.get('name') or '')}/json") if m.get("name") else (404, None)
    if st == 200 and m["status"] in ("internal", "never"):
        if norm(m["name"]) in published_names:
            check(results, m["name"], "pypi:unexpected-project", "PASS",
                  f"name is published from {published_names[norm(m['name'])]}; this copy ({m['repo']}/{m['path']}) stays private")
        else:
            check(results, m["name"], "pypi:unexpected-project", "FAIL", "internal/never package exists on PyPI")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default="governance/pypi/pypi-packages.v1.json")
    ap.add_argument("--canonical-dir", default="governance/pypi/canonical")
    ap.add_argument("--report", default="pypi-release-path-report.json")
    ap.add_argument("--summary", default="pypi-release-path-summary.md")
    ap.add_argument("--only", nargs="*", help="limit to these package names")
    args = ap.parse_args()

    manifest = json.loads(Path(args.manifest).read_text())
    org = manifest["owner"]["github_org"]
    canon_dir = Path(args.canonical_dir)
    sys.path.insert(0, str(canon_dir))
    from gen_publish_workflow import render  # canonical generator shipped next to the canonical copies

    if render("PACKAGE=.:pypi") != (canon_dir / "publish-pypi.yml").read_text():
        print("::error::canonical publish-pypi.yml does not match its generator; regenerate before auditing")
        return 1
    canon = {
        "render": render,
        "generator_sha256": sha256((canon_dir / "gen_publish_workflow.py").read_bytes()),
        "gate_sha256": sha256((canon_dir / "szl_pypi_release_gate.py").read_bytes()),
    }
    http = Http(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
    results: list[dict] = []
    repo_cache: dict = {}
    published_names = {norm(m["name"]): m["repo"] for m in manifest["packages"] if m.get("status") == "published" and m.get("name")}
    for m in manifest["packages"]:
        if args.only and m.get("name") not in args.only:
            continue
        if m["status"] in ("published", "queued"):
            audit_release_repo(http, org, m, canon, results, repo_cache)
        elif m["status"] in ("internal", "never"):
            audit_private_marker(http, org, m, results, published_names)
        else:  # hold / third-party: informational only
            check(results, m.get("name") or m["path"], "manifest:hold", "PASS", m.get("reason", ""))

    counts = {s: sum(1 for r in results if r["status"] == s) for s in ("PASS", "FAIL", "UNKNOWN")}
    verdict = "PASS" if counts["FAIL"] == 0 and counts["UNKNOWN"] == 0 else "FAIL"
    report = {"schema": "szl.pypi-release-path-audit.v1", "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "manifest_generated_at": manifest.get("generated_at"), "canonical": {k: v for k, v in canon.items() if k != "render"}, "counts": counts, "verdict": verdict, "results": results}
    Path(args.report).write_text(json.dumps(report, indent=1))
    lines = [f"# PyPI release-path audit — {verdict}", "", f"Generated {report['generated_at']} · PASS {counts['PASS']} · FAIL {counts['FAIL']} · UNKNOWN {counts['UNKNOWN']}", ""]
    bad = [r for r in results if r["status"] != "PASS"]
    if bad:
        lines += ["| package | check | status | detail |", "|---|---|---|---|"]
        lines += [f"| {r['package']} | {r['check']} | {r['status']} | {r['detail'][:120]} |" for r in bad]
    else:
        lines.append("Every check passed against live GitHub and PyPI state.")
    Path(args.summary).write_text("\n".join(lines) + "\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write("\n".join(lines) + "\n")
    print(json.dumps(counts), verdict)
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
