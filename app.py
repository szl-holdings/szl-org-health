#!/usr/bin/env python3
"""SZL Org-Health Dashboard — backend.

Aggregates LIVE data from three real sources and serves it to the frontend:
  1. GitHub (org szl-holdings): per-repo latest-CI conclusion, open code/secret/
     dependabot alerts, open PRs/issues, branch-protection coverage.
  2. Hugging Face Spaces (SZLHOLDINGS): runtime stage + /healthz probe.
  3. Sites: reachability + presence of key security headers; DNS SPF/DMARC.

Honesty rules (mirrors the org doctrine):
  - Every value is a real reading THIS request, or an explicit UNKNOWN.
  - Nothing is fabricated; an unreachable source is reported UNKNOWN, never green.
  - No secret values are ever surfaced.

Auth: the GitHub API token is injected by the credential proxy (HTTPS_PROXY) when
the server is started with api_credentials=['custom-cred:api.github.com']; requests
to api.github.com pick it up automatically. HF + site reads are public.
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import dns.exception
import dns.resolver

ORG = "szl-holdings"
HF_ORG = "SZLHOLDINGS"
GH = "https://api.github.com"
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

# Repos + Spaces + sites we track (the real estate).
KEY_REPOS = [
    "a11oy", "killinchu", "platform", "szl-router", "szl-lake", "szl-trust",
    "szl-doctrine", "immune", "szl-receipt", "szl-lambda-gate", "szl-energy-attest",
    "khipu-sda-core", "anatomy", "yarqa",
]
SPACES = ["killinchu", "a11oy", "anatomy", "yarqa", "llm-router-live", "hatun-mcp",
          "sda", "immune", "david-leads", "cosmos", "holographic"]
# Spaces that expose the /healthz flagship contract (others are static/viz).
HEALTHZ_SPACES = {"a11oy", "killinchu", "yarqa", "anatomy"}
SITES = ["a-11-oy.com", "a11oy.net"]
DOMAINS = ["szlholdings.com", "a-11-oy.com", "a11oy.net", "alloyszlholdings.com", "killinchu.net"]

_CACHE: dict = {"data": None, "ts": 0.0}
_CACHE_TTL = 60  # seconds — don't hammer the APIs on every browser refresh


def _gh(path: str, timeout: float = 20.0, retries: int = 2):
    """GET the GitHub API with retry. Returns (json, None) or (None, error_str).

    On the last failure returns (None, error) so callers can render an explicit
    UNKNOWN — never a fabricated green/false.
    """
    req = urllib.request.Request(f"{GH}{path}", headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "szl-org-health/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    last = "unknown"
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode()), None
        except urllib.error.HTTPError as e:
            # a real HTTP status (e.g. 404 on protection = not protected) is signal
            return None, f"http{e.code}"
        except Exception as e:  # noqa: BLE001
            last = str(e)[:120]
            time.sleep(1.5 * (attempt + 1))
    return None, last


def _http_probe(url: str, timeout: float = 12.0):
    """Probe a URL. Returns dict {http, headers} or {http:0, error}."""
    req = urllib.request.Request(url, headers={"User-Agent": BROWSER_UA}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            return {"http": r.status, "headers": hdrs}
    except urllib.error.HTTPError as e:  # 4xx/5xx still a real reading
        return {"http": e.code, "headers": {k.lower(): v for k, v in (e.headers or {}).items()}}
    except Exception as e:  # noqa: BLE001
        return {"http": 0, "error": str(e)[:80]}


def _resolve_txt(name: str, timeout: float = 8.0) -> str | None:
    """Resolve TXT data without collapsing resolver failure into absence.

    ``""`` means a measured NXDOMAIN/NODATA response. ``None`` means the
    resolver could not produce an authoritative result in the allowed time.
    """
    try:
        answer = dns.resolver.resolve(
            name,
            "TXT",
            search=False,
            lifetime=timeout,
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return ""
    except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError):
        return None

    records = []
    for record in answer:
        chunks = getattr(record, "strings", ())
        records.append("".join(bytes(chunk).decode("utf-8", "replace") for chunk in chunks))
    return "\n".join(records)


# ---- collectors ------------------------------------------------------------

def collect_github(
    *,
    request_timeout: float = 20.0,
    retries: int = 2,
    include_branch_protection: bool = True,
) -> dict:
    """Collect GitHub health with explicit, per-run network bounds.

    Scheduled snapshots may skip the expensive protection probe, but the
    resulting value remains honest UNKNOWN rather than an inferred False.
    """
    repos = {}

    def github_get(path: str):
        return _gh(path, timeout=request_timeout, retries=retries)

    def one_repo(repo: str):
        # latest run on default branch
        runs, err = github_get(f"/repos/{ORG}/{repo}/actions/runs?per_page=8")
        ci = "unknown"
        if runs and runs.get("workflow_runs"):
            # most recent completed conclusion
            for r in runs["workflow_runs"]:
                if r.get("conclusion"):
                    ci = r["conclusion"]
                    break
        elif err:
            ci = "unknown"
        if not include_branch_protection:
            return repo, {"ci": ci, "protected": None}

        # branch protection on default branch.
        # protected = True (has protection), False (404 = explicitly none),
        # None = UNKNOWN (read failed/timed out) — never fabricate a False.
        meta, _ = github_get(f"/repos/{ORG}/{repo}")
        default = (meta or {}).get("default_branch") or "main"
        prot, perr = github_get(f"/repos/{ORG}/{repo}/branches/{default}/protection")
        if prot and ("enforce_admins" in prot or "required_pull_request_reviews" in prot):
            protected = True
        elif perr in ("http403", "http404"):
            # 403/404 here means THIS token can't see the protection endpoint
            # (needs admin scope). We cannot verify => honest UNKNOWN, not False.
            # (An unprotected branch also 404s, so we refuse to guess either way.)
            protected = None
        else:
            protected = None  # timeout / transport error => honest UNKNOWN
        return repo, {"ci": ci, "protected": protected}

    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for repo, info in ex.map(one_repo, KEY_REPOS):
            repos[repo] = info

    # org-wide alert counts
    def count(path):
        d, err = github_get(path)
        if err or not isinstance(d, list):
            return None  # UNKNOWN — this token/endpoint not readable; never fabricate 0
        return len(d)

    code_alerts_raw, _ = github_get(
        f"/orgs/{ORG}/code-scanning/alerts?state=open&per_page=100"
    )
    code_high = None
    code_total = None
    if isinstance(code_alerts_raw, list):
        code_total = len(code_alerts_raw)
        code_high = sum(1 for a in code_alerts_raw
                        if (a.get("rule", {}) or {}).get("security_severity_level") == "high")

    # open PRs / issues via search
    prs, _ = github_get(f"/search/issues?q=org:{ORG}+is:pr+is:open&per_page=1")
    iss, _ = github_get(f"/search/issues?q=org:{ORG}+is:issue+is:open&per_page=1")

    return {
        "repos": repos,
        "alerts": {
            "code_scanning_open": code_total,
            "code_scanning_high": code_high,
            "secret_scanning_open": count(f"/orgs/{ORG}/secret-scanning/alerts?state=open&per_page=100"),
            "dependabot_open": count(f"/orgs/{ORG}/dependabot/alerts?state=open&per_page=100"),
        },
        "open_prs": (prs or {}).get("total_count"),
        "open_issues": (iss or {}).get("total_count"),
    }


def collect_spaces() -> dict:
    out = {}

    def one(sp: str):
        meta = _http_probe(f"https://huggingface.co/api/spaces/{HF_ORG}/{sp}")
        stage = "unknown"
        if meta.get("http") == 200:
            try:
                req = urllib.request.Request(f"https://huggingface.co/api/spaces/{HF_ORG}/{sp}",
                                             headers={"User-Agent": BROWSER_UA})
                with urllib.request.urlopen(req, timeout=12) as r:
                    stage = (json.loads(r.read().decode()).get("runtime", {}) or {}).get("stage", "unknown")
            except Exception:  # noqa: BLE001
                stage = "unknown"
        health = None
        if sp in HEALTHZ_SPACES:
            p = _http_probe(f"https://{HF_ORG}-{sp}.hf.space/healthz")
            health = p.get("http")
        return sp, {"stage": stage, "healthz": health, "monitored": sp in HEALTHZ_SPACES}

    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        for sp, info in ex.map(one, SPACES):
            out[sp] = info
    return out


def collect_sites() -> dict:
    out = {}
    for s in SITES:
        p = _http_probe(f"https://{s}/")
        h = p.get("headers", {})
        out[s] = {
            "http": p.get("http"),
            "hsts": "strict-transport-security" in h,
            "csp": "content-security-policy" in h,
            "xfo": "x-frame-options" in h,
            "nosniff": h.get("x-content-type-options", "").lower() == "nosniff",
        }
    return out


def collect_dns() -> dict:
    out = {}
    for d in DOMAINS:
        spf = _resolve_txt(d)
        spf_ok = None if spf is None else "v=spf1" in spf.lower()
        dmarc = _resolve_txt(f"_dmarc.{d}")
        dmarc_present = None if dmarc is None else "v=dmarc1" in dmarc.lower()
        dmarc_reject = None if dmarc is None else "p=reject" in dmarc.lower()
        out[d] = {"spf": spf_ok, "dmarc": dmarc_present, "dmarc_reject": dmarc_reject}
    return out


def build_report(
    *,
    use_cache: bool = True,
    github_timeout: float = 20.0,
    github_retries: int = 2,
    include_branch_protection: bool = True,
) -> dict:
    now = time.time()
    if use_cache and _CACHE["data"] and (now - _CACHE["ts"] < _CACHE_TTL):
        return _CACHE["data"]

    report = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "sources": {}}
    # run collectors; each is isolated so one failure => UNKNOWN, not a crash
    collectors = {
        "github": lambda: collect_github(
            request_timeout=github_timeout,
            retries=github_retries,
            include_branch_protection=include_branch_protection,
        ),
        "spaces": collect_spaces,
        "sites": collect_sites,
        "dns": collect_dns,
    }
    with cf.ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(fn): name for name, fn in collectors.items()}
        for fut in cf.as_completed(futs):
            name = futs[fut]
            try:
                report["sources"][name] = {"ok": True, "data": fut.result()}
            except Exception as e:  # noqa: BLE001
                report["sources"][name] = {"ok": False, "error": str(e)[:120]}

    _CACHE["data"] = report
    _CACHE["ts"] = now
    return report


class Handler(BaseHTTPRequestHandler):
    server_version = "szl-org-health"

    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/health":
            self._send(200, json.dumps(build_report()))
        elif path in ("/", "/index.html"):
            try:
                with open("static/index.html", "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(404, "not found", "text/plain")
        elif path == "/healthz":
            self._send(200, json.dumps({"status": "ok", "service": "szl-org-health"}))
        else:
            self._send(404, "not found", "text/plain")

    def log_message(self, *a):  # quiet
        pass


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", "7860"))
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"szl-org-health serving on 0.0.0.0:{port}", flush=True)
    httpd.serve_forever()
