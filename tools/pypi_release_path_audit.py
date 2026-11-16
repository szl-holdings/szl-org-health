#!/usr/bin/env python3
"""PyPI release-path audit for the szl-holdings estate (stdlib only, fail-closed).

For every package in governance/pypi/pypi-packages.v1.json this checks, from live sources:

  GitHub  * the repository's publish-pypi.yml and release gate are byte-identical to the canonical copies
          * no workflow in the repository references a PyPI API token secret
          * the `pypi` (or declared) environment exists and is restricted to release tags
          * a tag ruleset protects refs/tags/v* (creation/update/deletion)
          * for the latest PyPI version a git tag is compared with the reported certificate source commit
  PyPI    * the project exists (published) or does not (queued/hold/internal/never)
          * every latest-release file has a matching PyPI Integrity URL, hash, and statement subject
          * reported publisher metadata names the declared GitHub repo, workflow, and environment
          * project URLs point at the GitHub source (what PyPI verifies against the Trusted Publisher)
  Internal/never pyproject files carry the `Private :: Do Not Upload` classifier.

Attestation fields are inspected for consistency. Cryptographic provenance, publisher identity,
and certificate-derived tag identity are promoted only from an exact `--sigstore-report` receipt row
with status `VERIFIED`; without that receipt they remain UNKNOWN even when metadata agrees.
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
    if suffix or not re.fullmatch(r"[A-Za-z0-9_-]+", prefix):
        return None
    return f"refs/tags/{prefix}*"


def tag_ruleset_result(http: Http, org: str, repo: str, m: dict, rulesets: object) -> tuple[str, str]:
    """Verify the combined active rules protect the whole release-tag family."""
    family = release_tag_family(m)
    if family is None:
        return "UNKNOWN", f"unsupported manifest tag_pattern={m.get('tag_pattern')!r}"
    if not isinstance(rulesets, list):
        return "UNKNOWN", "tag ruleset list response malformed"
    if any(not isinstance(r, dict) for r in rulesets):
        return "UNKNOWN", "tag ruleset list contains a malformed entry"
    malformed_summaries = sum(r.get("enforcement") not in ("active", "disabled", "evaluate") for r in rulesets)
    active = [r for r in rulesets if r.get("enforcement") == "active"]
    if not active:
        if malformed_summaries:
            return "UNKNOWN", f"{malformed_summaries} tag ruleset summaries have missing or invalid enforcement"
        if len(rulesets) >= 100:
            return "UNKNOWN", f"first 100 tag rulesets contain no active match for {family}; more pages may exist"
        return "FAIL", f"no active tag ruleset for {family} (listed={len(rulesets)})"
    failures = []
    safe_rules: set[str] = set()
    safe_sources = []
    # None means an unreadable set could contain any of the required protections.
    uncertain_rules: list[tuple[str, set[str] | None]] = []
    if malformed_summaries:
        uncertain_rules.append((f"{malformed_summaries} tag ruleset summaries have missing or invalid enforcement", None))
    for summary in active:
        ruleset_id = summary.get("id")
        name = summary.get("name", ruleset_id)
        if summary.get("target") != "tag":
            uncertain_rules.append((f"{name}: tag ruleset list contains an unexpected target", None))
            continue
        if not isinstance(ruleset_id, int) or ruleset_id <= 0:
            uncertain_rules.append((f"{name}: missing ruleset id", None))
            continue
        endpoint = f"{GH_API}/repos/{org}/{repo}/rulesets/{ruleset_id}?includes_parents=true"
        st, detail = http.get(endpoint)
        if st != 200:
            uncertain_rules.append((f"{name} ({ruleset_id}): detail HTTP {st}; access or existence unverified", None))
            continue
        if not isinstance(detail, dict) or detail.get("id") != ruleset_id or detail.get("target") != "tag" or detail.get("enforcement") != "active":
            uncertain_rules.append((f"{name} ({ruleset_id}): detail malformed or inconsistent", None))
            continue
        conditions = detail.get("conditions")
        ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
        if not isinstance(ref_name, dict) or not isinstance(ref_name.get("include"), list) or not isinstance(ref_name.get("exclude"), list):
            uncertain_rules.append((f"{name} ({ruleset_id}): ref conditions unavailable", None))
            continue
        includes, excludes = ref_name["include"], ref_name["exclude"]
        # These patterns demonstrably cover every release tag, including future versions.
        if not any(p in (family, "refs/tags/*", "~ALL") for p in includes):
            failures.append(f"{name} ({ruleset_id}): include={includes!r} does not cover {family}")
            continue
        if excludes:
            uncertain_rules.append((f"{name} ({ruleset_id}): exclude={excludes!r}; family coverage unverified", None))
            continue
        rules = detail.get("rules")
        if not isinstance(rules, list) or not all(isinstance(r, dict) and isinstance(r.get("type"), str) for r in rules):
            uncertain_rules.append((f"{name} ({ruleset_id}): rules unavailable or malformed", None))
            continue
        rule_types = REQUIRED_TAG_RULES & {r["type"] for r in rules}
        bypass = detail.get("bypass_actors")
        if not isinstance(bypass, list):
            uncertain_rules.append((f"{name} ({ruleset_id}): bypass actors not visible; admin-only control unverified", rule_types))
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
        safe_rules.update(rule_types)
        safe_sources.append(f"{name} ({ruleset_id}): {sorted(rule_types)}")
    if safe_rules == REQUIRED_TAG_RULES:
        return "PASS", f"{family} protected by admin-only rulesets: {'; '.join(safe_sources)}"
    missing = REQUIRED_TAG_RULES - safe_rules
    unknowns = [reason for reason, possible in uncertain_rules if possible is None or possible & missing]
    detail = f"missing verified admin-only rules {sorted(missing)} for {family}"
    if safe_sources:
        detail += f"; verified={'; '.join(safe_sources)}"
    if unknowns:
        return "UNKNOWN", "; ".join([detail] + unknowns + failures)
    if len(rulesets) >= 100:
        return "UNKNOWN", f"{detail}; first 100 tag rulesets may omit further pages; " + "; ".join(failures)
    return "FAIL", "; ".join([detail] + failures)


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
    """Read an unverified source-digest extension for metadata comparison only.

    The OID is encoded as 06 0a 2b 06 01 04 01 83 bf 30 01 0d; the value follows as an
    OCTET STRING wrapping a UTF8String. We locate the OID bytes and parse forward.
    """
    der = base64.b64decode(cert_b64, validate=True)
    oid = bytes.fromhex("060a2b0601040183bf30010d")  # DER of OID 1.3.6.1.4.1.57264.1.13
    i = der.find(oid)
    if i < 0:
        return None
    j = i + len(oid)
    if j >= len(der):
        return None
    # optional BOOLEAN critical flag
    if der[j] == 0x01:
        j += 3
    if j + 1 >= len(der) or der[j] != 0x04:
        return None
    length = der[j + 1]
    if length < 0x80:
        inner = der[j + 2:j + 2 + length]
    else:
        n = length & 0x7F
        real = int.from_bytes(der[j + 2:j + 2 + n], "big")
        inner = der[j + 2 + n:j + 2 + n + real]
    return der_string(inner)


def valid_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None


def provenance_url(pkg: str, version: str, filename: str) -> str:
    return (f"https://pypi.org/integrity/{norm(pkg)}/"
            f"{urllib.parse.quote(version, safe='')}/{urllib.parse.quote(filename, safe='')}/provenance")


def attested_subject(statement_b64: object) -> tuple[str, dict] | None:
    """Decode the published statement; this does not verify its DSSE signature."""
    if not isinstance(statement_b64, str):
        return None
    try:
        statement = json.loads(base64.b64decode(statement_b64, validate=True))
    except (ValueError, binascii.Error, TypeError):
        return None
    if not isinstance(statement, dict):
        return None
    if statement.get("_type") != "https://in-toto.io/Statement/v1" or statement.get("predicateType") != "https://docs.pypi.org/attestations/publish/v1":
        return None
    if statement.get("predicate") not in ({}, None):
        return None
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(subjects[0], dict):
        return None
    subject = subjects[0]
    if not isinstance(subject.get("name"), str) or not isinstance(subject.get("digest"), dict):
        return None
    return subject["name"], subject["digest"]


def check(results: list, pkg: str, name: str, status: str, detail: str = "") -> None:
    results.append({"package": pkg, "check": name, "status": status, "detail": detail})
    print(f"[{status:7}] {pkg:28} {name:40} {detail}", flush=True)


def load_sigstore_receipts(path: str | None) -> dict[str, dict]:
    """Load only exact, cryptographically verified PEP 740 receipts.

    A missing, malformed, or non-VERIFIED report produces no trusted entries.
    The release-path audit therefore remains fail-closed when the receipt is
    absent or incomplete.
    """
    if not path:
        return {}
    try:
        report = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    if report.get("schema") != "szl.pypi-sigstore-verify.v1":
        return {}
    rows = report.get("results")
    if not isinstance(rows, list):
        return {}
    verified: dict[str, dict] = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("status") != "VERIFIED":
            continue
        package = row.get("package")
        repo = row.get("repo")
        version = row.get("version")
        tag = row.get("tag")
        tag_commit = row.get("tag_commit")
        digests = row.get("attested_digests")
        if (
            not isinstance(package, str)
            or not package
            or not isinstance(repo, str)
            or not repo
            or not isinstance(version, str)
            or not version
            or not isinstance(tag, str)
            or not tag
            or not isinstance(tag_commit, str)
            or re.fullmatch(r"[0-9a-fA-F]{40}", tag_commit) is None
            or not isinstance(digests, list)
            or len(digests) != 1
            or not isinstance(digests[0], str)
            or digests[0].lower() != tag_commit.lower()
        ):
            continue
        verified[norm(package)] = row
    return verified


def apply_sigstore_receipt(results: list[dict], manifest_entry: dict, receipts: dict[str, dict]) -> None:
    """Promote only the three checks covered by an exact VERIFIED receipt."""
    package = manifest_entry.get("name")
    if not isinstance(package, str):
        return
    receipt = receipts.get(norm(package))
    if not isinstance(receipt, dict) or receipt.get("status") != "VERIFIED" or receipt.get("repo") != manifest_entry.get("repo"):
        return
    tag_commit = receipt.get("tag_commit")
    digests = receipt.get("attested_digests")
    if (
        not isinstance(tag_commit, str)
        or re.fullmatch(r"[0-9a-fA-F]{40}", tag_commit) is None
        or not isinstance(digests, list)
        or len(digests) != 1
        or not isinstance(digests[0], str)
        or digests[0].lower() != tag_commit.lower()
    ):
        return
    version = receipt.get("version")
    expected_tag = manifest_entry.get("tag_pattern", "v<version>").replace("<version>", str(version))
    if receipt.get("tag") != expected_tag:
        return
    project = next(
        (
            row for row in reversed(results)
            if row.get("package") == package and row.get("check") == "pypi:project"
        ),
        None,
    )
    if not isinstance(project, dict) or project.get("status") != "PASS" or project.get("detail") != f"latest {version}":
        return
    detail = (
        f"sigstore receipt VERIFIED: PEP 740 DSSE, Fulcio, Rekor, "
        f"Trusted Publisher, and tag {expected_tag} -> {receipt['tag_commit'][:12]}"
    )
    for check_name in ("pypi:provenance", "pypi:publisher-identity", "github:release-tag"):
        row = next(
            (
                candidate for candidate in reversed(results)
                if candidate.get("package") == package and candidate.get("check") == check_name
            ),
            None,
        )
        if isinstance(row, dict) and row.get("status") == "UNKNOWN":
            row["status"] = "PASS"
            row["detail"] = detail


def audit_release_repo(http: Http, org: str, m: dict, canon: dict[str, str], results: list, repo_cache: dict) -> None:
    pkg, repo = m["name"], m["repo"]
    env_name = m.get("github_environment", "pypi")
    # --- canonical workflow + gate bytes
    for rel, key in ((".github/workflows/publish-pypi.yml", "workflow"), (".github/scripts/szl_pypi_release_gate.py", "gate")):
        st, body = http.get(f"{RAW}/{org}/{repo}/HEAD/{rel}", raw=True)
        if st != 200:
            check(results, pkg, f"canonical:{key}", "UNKNOWN",
                  f"{rel} HTTP {st}; unauthenticated raw URL cannot verify repository content")
            if key == "workflow":
                check(results, pkg, "canonical:workflow-environment", "UNKNOWN", f"{rel} HTTP {st}")
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
            entries = []
            if spec:
                for item in (part.strip() for part in spec.group(1).split(";")):
                    if not item:
                        continue
                    name, separator, rest = item.partition("=")
                    _, _, environment = rest.partition(":")
                    if separator and name.strip():
                        entries.append((name.strip(), (environment or "pypi").strip()))
            matches = [environment for name, environment in entries if norm(name) == norm(pkg)]
            if not isinstance(env_name, str) or not env_name or len(matches) != 1 or not matches[0]:
                check(results, pkg, "canonical:workflow-environment", "UNKNOWN",
                      f"package environment ambiguous or unavailable: manifest={env_name!r}; SZL_PACKAGES={spec.group(1) if spec else None!r}")
            else:
                check(results, pkg, "canonical:workflow-environment", "PASS" if matches[0] == env_name else "FAIL",
                      f"workflow={matches[0]!r}; manifest={env_name!r}")
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
        repo_cache[repo]["environments_total_count"] = envs.get("total_count") if isinstance(envs, dict) else None
        repo_cache[repo]["environments"] = {e["name"]: e for e in env_rows} if (
            st == 200 and isinstance(env_rows, list)
            and all(isinstance(e, dict) and isinstance(e.get("name"), str) for e in env_rows)
            and len({e["name"] for e in env_rows}) == len(env_rows)
        ) else None
        for listed_env_name, e in (repo_cache[repo]["environments"] or {}).items():
            st3, pol = http.get(f"{GH_API}/repos/{org}/{repo}/environments/{listed_env_name}/deployment-branch-policies")
            e["_policies_status"] = st3
            pol_rows = pol.get("branch_policies") if isinstance(pol, dict) else None
            e["_policies_total_count"] = pol.get("total_count") if isinstance(pol, dict) else None
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
    if rc["environments"] is None:
        check(results, pkg, "github:environment", "UNKNOWN",
              f"environments list HTTP {rc['environments_status']}; access or existence unverified")
    elif env_name not in rc["environments"]:
        total = rc["environments_total_count"]
        listed = len(rc["environments"])
        complete = (type(total) is int and total == listed) or (total is None and listed < 30)
        check(results, pkg, "github:environment", "FAIL" if complete else "UNKNOWN",
              f"environment {env_name!r} not in first {listed} returned; total_count={total!r}")
    else:
        e = rc["environments"][env_name]
        dbp = e.get("deployment_branch_policy")
        dbp = dbp if isinstance(dbp, dict) else {}
        pols = e.get("_policies")
        if pols is None:
            check(results, pkg, "github:environment-tag-only", "UNKNOWN",
                  f"{env_name} deployment policies HTTP {e.get('_policies_status')}; access or existence unverified")
        elif type(e.get("_policies_total_count")) is not int or e["_policies_total_count"] != len(pols):
            check(results, pkg, "github:environment-tag-only", "UNKNOWN",
                  f"{env_name} deployment policies incomplete: returned={len(pols)} total_count={e.get('_policies_total_count')!r}")
        else:
            family = release_tag_family(m)
            if family is None:
                check(results, pkg, "github:environment-tag-only", "UNKNOWN", "release tag pattern unrecognized")
            else:
                tag_pattern = family.removeprefix("refs/tags/")
                custom_policies = dbp.get("custom_branch_policies")
                protected_branches = dbp.get("protected_branches")
                tag_only = bool(pols) and all(t == "tag" for _, t in pols)
                bare_match = any(t == "tag" and name == tag_pattern for name, t in pols)
                full_ref_match = any(t == "tag" and name == family for name, t in pols)
                unrelated = [name for name, t in pols if t == "tag" and name not in (tag_pattern, family)]
                status = (
                    "UNKNOWN" if type(custom_policies) is not bool or type(protected_branches) is not bool else
                    "FAIL" if not custom_policies or protected_branches or not tag_only or unrelated else
                    "UNKNOWN" if full_ref_match else
                    "PASS" if bare_match else "FAIL"
                )
                detail = f"policies={pols}; required release tags={tag_pattern}"
                if type(custom_policies) is not bool:
                    detail += f"; custom_branch_policies={custom_policies!r} malformed or unavailable"
                if type(protected_branches) is not bool:
                    detail += f"; protected_branches={protected_branches!r} malformed or unavailable"
                if unrelated:
                    detail += f"; unrelated tag policies={unrelated}"
                if full_ref_match:
                    detail += f"; full-ref tag policy {family!r} coverage is unverified"
                check(results, pkg, "github:environment-tag-only", status, detail)
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
        for name in ("pypi:distribution-metadata", "pypi:provenance", "pypi:publisher-identity", "github:release-tag"):
            check(results, pkg, name, "UNKNOWN", f"Simple API HTTP {st}; distribution evidence unavailable")
        return
    meta_files = meta.get("urls")
    simple_entries = simple.get("files") if isinstance(simple, dict) else None
    if any(
        not isinstance(rows, list)
        or any(not isinstance(row, dict) or not isinstance(row.get("filename"), str) or not row["filename"] for row in rows)
        or len({row["filename"] for row in rows}) != len(rows)
        for rows in (meta_files, simple_entries)
    ):
        check(results, pkg, "pypi:distribution-metadata", "UNKNOWN", "release metadata or Simple API filenames malformed")
        check(results, pkg, "pypi:provenance", "UNKNOWN", "release metadata or Simple API filenames malformed")
        check(results, pkg, "pypi:publisher-identity", "UNKNOWN", "distribution set unverified")
        check(results, pkg, "github:release-tag", "UNKNOWN", "distribution set unverified")
        return
    latest = {u["filename"] for u in meta_files}
    release_files = {u["filename"]: u for u in meta_files}
    simple_files = {f["filename"]: f for f in simple_entries}
    missing_files = sorted(latest - simple_files.keys())
    missing_links = sorted(name for name in latest & simple_files.keys()
                           if simple_files[name].get("provenance") != provenance_url(pkg, version, name))
    has_wheel = any(name.endswith(".whl") for name in latest)
    has_sdist = any(name.endswith((".tar.gz", ".zip")) for name in latest)
    digests = set()
    failures, unknowns, publisher_failures, publisher_unknowns = [], [], [], []
    if not latest or not has_wheel or not has_sdist:
        failures.append(f"release metadata wheel={has_wheel} sdist={has_sdist}")
    if missing_files:
        failures.append(f"missing from Simple API={missing_files}")
    if missing_links:
        failures.append(f"missing or noncanonical per-file PyPI provenance link={missing_links}")
    expected_publisher = ("GitHub", f"{org}/{repo}", "publish-pypi.yml", env_name)
    for name in sorted(latest - set(missing_files) - set(missing_links)):
        json_hash = release_files[name].get("digests")
        json_hash = json_hash.get("sha256") if isinstance(json_hash, dict) else None
        simple_hash = simple_files[name].get("hashes")
        simple_hash = simple_hash.get("sha256") if isinstance(simple_hash, dict) else None
        file_hash = None
        if not valid_sha256(json_hash) or not valid_sha256(simple_hash):
            unknowns.append(f"{name}: JSON or Simple SHA-256 missing or malformed")
        elif json_hash.lower() != simple_hash.lower():
            failures.append(f"{name}: JSON SHA-256 differs from Simple SHA-256")
        else:
            file_hash = json_hash.lower()
        st, prov = http.get(simple_files[name]["provenance"])
        if st != 200:
            unknowns.append(f"{name}: provenance HTTP {st}; missing or inaccessible")
            continue
        if not isinstance(prov, dict) or not isinstance(prov.get("attestation_bundles"), list) or not prov["attestation_bundles"]:
            unknowns.append(f"{name}: no readable attestation bundles")
            continue
        for b in prov["attestation_bundles"]:
            if not isinstance(b, dict) or not isinstance(b.get("publisher"), dict):
                unknowns.append(f"{name}: malformed attestation bundle")
                continue
            p = b["publisher"]
            publisher = (p.get("kind"), p.get("repository"), p.get("workflow"), p.get("environment"))
            if not all(isinstance(value, str) and value for value in publisher):
                publisher_unknowns.append(f"{name}: publisher kind/repository/workflow/environment missing or malformed")
            elif publisher != expected_publisher:
                publisher_failures.append(f"{name}: publisher={publisher!r}; expected={expected_publisher!r}")
            attestations = b.get("attestations")
            if not isinstance(attestations, list) or not attestations:
                unknowns.append(f"{name}: attestations missing or malformed")
                continue
            for a in attestations:
                if not isinstance(a, dict) or not isinstance(a.get("envelope"), dict):
                    unknowns.append(f"{name}: DSSE envelope missing or malformed")
                    continue
                envelope = a["envelope"]
                try:
                    signature = base64.b64decode(envelope.get("signature"), validate=True)
                    if not signature:
                        raise ValueError("empty signature")
                except (KeyError, TypeError, ValueError, IndexError, binascii.Error):
                    unknowns.append(f"{name}: DSSE signature missing or malformed")
                subject = attested_subject(envelope.get("statement"))
                if subject is None:
                    unknowns.append(f"{name}: publish statement or subject missing or malformed")
                elif subject[0] != name or not valid_sha256(subject[1].get("sha256")):
                    if subject[0] != name:
                        failures.append(f"{name}: statement subject filename={subject[0]!r} differs")
                    else:
                        unknowns.append(f"{name}: statement subject SHA-256 missing or malformed")
                elif file_hash is not None and subject[1]["sha256"].lower() != file_hash:
                    failures.append(f"{name}: statement subject SHA-256 differs from distribution")
                try:
                    d = source_digest_from_cert(a["verification_material"]["certificate"])
                except (KeyError, TypeError, ValueError, IndexError, binascii.Error):
                    d = None
                if isinstance(d, str) and re.fullmatch(r"[0-9a-fA-F]{40}", d):
                    digests.add(d.lower())
                else:
                    unknowns.append(f"{name}: certificate source digest missing or malformed")
    evidence = "; ".join(failures + unknowns)
    metadata_status = "FAIL" if failures else "UNKNOWN" if unknowns else "PASS"
    check(results, pkg, "pypi:distribution-metadata", metadata_status,
          evidence or f"{len(latest)}/{len(latest)} release files have matching URLs, hashes, and statement subjects (unverified metadata)")
    check(results, pkg, "pypi:provenance", "FAIL" if failures else "UNKNOWN",
          evidence or "metadata is consistent; DSSE signatures, certificates, and transparency not cryptographically verified")
    if publisher_failures:
        check(results, pkg, "pypi:publisher-identity", "FAIL", "; ".join(publisher_failures))
    else:
        reason = "; ".join(publisher_unknowns + unknowns + failures)
        check(results, pkg, "pypi:publisher-identity", "UNKNOWN",
              reason or f"reported publisher={expected_publisher!r}; cryptographic identity not verified")
    if metadata_status != "PASS":
        check(results, pkg, "github:release-tag", "UNKNOWN", f"per-file source digest unverified: {evidence}")
        return
    if len(digests) != 1:
        check(results, pkg, "github:release-tag", "UNKNOWN", f"unverified certificate source digests {sorted(digests)}")
        return
    digest = digests.pop()
    if release_tag_family(m) is None:
        check(results, pkg, "github:release-tag", "UNKNOWN",
              f"unsupported manifest tag_pattern={m.get('tag_pattern')!r}")
        return
    tag = m.get("tag_pattern", "v<version>").replace("<version>", version)
    st, ref = http.get(f"{GH_API}/repos/{org}/{repo}/git/ref/tags/{urllib.parse.quote(tag, safe='')}")
    if st == 404:
        check(results, pkg, "github:release-tag", "UNKNOWN",
              f"tag {tag} lookup HTTP 404; missing or inaccessible (attested source {digest[:12]})")
        return
    if st != 200 or not isinstance(ref, dict):
        check(results, pkg, "github:release-tag", "UNKNOWN", f"tag lookup HTTP {st}")
        return
    obj = ref.get("object")
    if not isinstance(obj, dict) or not isinstance(obj.get("sha"), str) or obj.get("type") not in ("commit", "tag"):
        check(results, pkg, "github:release-tag", "UNKNOWN", f"tag {tag} lookup HTTP 200 with malformed object")
        return
    commit = obj["sha"]
    if obj["type"] == "tag":
        st, tobj = http.get(f"{GH_API}/repos/{org}/{repo}/git/tags/{obj['sha']}")
        target = tobj.get("object") if isinstance(tobj, dict) else None
        if st != 200 or not isinstance(target, dict) or target.get("type") != "commit" or not isinstance(target.get("sha"), str):
            check(results, pkg, "github:release-tag", "UNKNOWN", f"tag {tag} target HTTP {st} with missing commit object")
            return
        commit = target["sha"]
    exc = m.get("tag_exception") or {}
    if commit == digest:
        check(results, pkg, "github:release-tag", "UNKNOWN", f"{tag} -> {commit[:12]} matches unverified certificate metadata; signature and certificate chain unverified")
    elif exc.get("tag") == tag and exc.get("tag_commit") == commit and exc.get("attested_commit") == digest:
        check(results, pkg, "github:release-tag", "UNKNOWN", f"{tag} -> {commit[:12]} matches recorded exception, but certificate metadata is unverified: {exc.get('reason', '')[:80]}")
    else:
        check(results, pkg, "github:release-tag", "FAIL", f"{tag} -> {commit[:12]} contradicts reported certificate source digest {digest[:12]} (unverified)")


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
    ap.add_argument("--sigstore-report", help="verified PEP 740 receipt report produced by pypi_sigstore_verify.py")
    ap.add_argument("--only", nargs="*", help="limit to these package names")
    args = ap.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    sigstore_receipts = load_sigstore_receipts(args.sigstore_report)
    org = manifest["owner"]["github_org"]
    canon_dir = Path(args.canonical_dir)
    sys.path.insert(0, str(canon_dir))
    from gen_publish_workflow import render  # canonical generator shipped next to the canonical copies

    if render("PACKAGE=.:pypi") != (canon_dir / "publish-pypi.yml").read_text(encoding="utf-8"):
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
            apply_sigstore_receipt(results, m, sigstore_receipts)
        elif m["status"] in ("internal", "never"):
            audit_private_marker(http, org, m, results, published_names)
        else:  # hold / third-party: informational only
            check(results, m.get("name") or m["path"], "manifest:hold", "PASS", m.get("reason", ""))

    counts = {s: sum(1 for r in results if r["status"] == s) for s in ("PASS", "FAIL", "UNKNOWN")}
    verdict = "PASS" if counts["FAIL"] == 0 and counts["UNKNOWN"] == 0 else "FAIL"
    report = {"schema": "szl.pypi-release-path-audit.v1", "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "manifest_generated_at": manifest.get("generated_at"), "canonical": {k: v for k, v in canon.items() if k != "render"},
              "sigstore_receipt": {"path": args.sigstore_report, "verified_packages": len(sigstore_receipts)},
              "counts": counts, "verdict": verdict, "results": results}
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
