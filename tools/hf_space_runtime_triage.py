#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Finite, public-only Hugging Face Space runtime triage; never a release gate.

Only GETs the fixed SZLHOLDINGS namespace. No token, deploy, wake, restart,
training, private metadata, or filesystem writes. A RUNNING label is NOT
application readiness, source binding, or production authorization.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import re
import sys
import urllib.request
from collections import Counter
from typing import Any, Callable

BASE = "https://huggingface.co"
ORG = "SZLHOLDINGS"
LIMIT = 100
WORKERS = 4
MAX_BYTES = 1_000_000
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SPACE_ID = re.compile(r"^SZLHOLDINGS/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
ALLOWED_STAGES = {
    "RUNNING", "SLEEPING", "PAUSED", "RUNTIME_ERROR", "BUILDING",
    "RUNNING_BUILDING", "RUNNING_APP_STARTING", "STOPPED", "STOPPING",
    "STARTING", "NO_APP_FILE", "CONFIG_ERROR", "BUILD_ERROR",
}


class CensusUnavailable(Exception):
    """Closed failure with no provider exception or private data in stdout."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CensusUnavailable("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def fetch_json(url: str) -> Any:
    """Bounded, anonymous GET for two fixed Hub API endpoint shapes only."""
    prefix = f"{BASE}/api/spaces/{ORG}/"
    listing = f"{BASE}/api/spaces?author={ORG}&limit={LIMIT}&full=true"
    if url != listing and not (
        url.startswith(prefix)
        and url.endswith("?expand%5B%5D=runtime")
        and SPACE_ID.fullmatch(url[len(BASE + "/api/spaces/") :].split("?")[0])
    ):
        raise CensusUnavailable("URL_NOT_ALLOWED")
    request = urllib.request.Request(
        url, headers={"User-Agent": "SZL-HF-Space-Triage/1.0", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            if response.status != 200:
                raise CensusUnavailable("HTTP_UNAVAILABLE")
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise CensusUnavailable("RESPONSE_TOO_LARGE")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except CensusUnavailable:
        raise
    except (OSError, ValueError, UnicodeError, TypeError):
        raise CensusUnavailable("PROVIDER_UNAVAILABLE") from None


def _sha(value: Any) -> str | None:
    return value if isinstance(value, str) and SHA40.fullmatch(value) else None


def _one(item: dict[str, Any], fetch: Callable[[str], Any]) -> dict[str, str]:
    name = item["id"]
    try:
        response = fetch(f"{BASE}/api/spaces/{name}?expand%5B%5D=runtime")
        if not isinstance(response, dict):
            raise CensusUnavailable("INVALID_DETAIL")
        runtime = response.get("runtime")
        if not isinstance(runtime, dict):
            raise CensusUnavailable("INVALID_RUNTIME")
        stage = runtime.get("stage")
        if not isinstance(stage, str) or stage not in ALLOWED_STAGES:
            raise CensusUnavailable("UNKNOWN_STAGE")
        if stage == "RUNNING":
            hub_sha, runtime_sha = _sha(item.get("sha")), _sha(runtime.get("sha"))
            state = (
                "RUNNING_REVISION_UNKNOWN" if hub_sha is None or runtime_sha is None
                else "RUNNING_REVISION_MATCHED" if hub_sha == runtime_sha
                else "RUNNING_REVISION_DRIFT"
            )
        else:
            state = stage
    except Exception:
        # Never echo provider exceptions, URL, headers, or identity details.
        state = "UNAVAILABLE"
    return {"space": name, "state": state}


def audit(fetch: Callable[[str], Any] = fetch_json) -> dict[str, Any]:
    """Check a complete public page, then at most 99 runtime detail GETs."""
    listing = fetch(f"{BASE}/api/spaces?author={ORG}&limit={LIMIT}&full=true")
    if not isinstance(listing, list) or not listing or len(listing) >= LIMIT:
        raise CensusUnavailable("INCOMPLETE_OR_INVALID_LISTING")
    seen: set[str] = set()
    for item in listing:
        if not isinstance(item, dict):
            raise CensusUnavailable("INVALID_LISTING_ROW")
        name = item.get("id")
        if not isinstance(name, str) or not SPACE_ID.fullmatch(name):
            raise CensusUnavailable("INVALID_SPACE_ID")
        if item.get("private") is not False:
            raise CensusUnavailable("NONPUBLIC_OR_UNVERIFIED_VISIBILITY")
        if name in seen:
            raise CensusUnavailable("DUPLICATE_SPACE_ID")
        seen.add(name)
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(lambda item: _one(item, fetch), listing))
    results.sort(key=lambda item: item["space"])
    counts = dict(sorted(Counter(item["state"] for item in results).items()))
    nonmatching = [item for item in results if item["state"] != "RUNNING_REVISION_MATCHED"]
    return {
        "schema": "szl.hf-space-runtime-triage/v1",
        "observed_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scope": "PUBLIC_HUB_METADATA_ONLY",
        "namespace": ORG,
        "listing_complete_under_cap": True,
        "checked": len(results),
        "denominator": len(listing),
        "counts": counts,
        "nonmatching_public_spaces": nonmatching,
        "application_readiness": "UNAVAILABLE",
        "source_binding": "UNVERIFIED",
        "production_authorized": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit sanitized aggregate JSON")
    args = parser.parse_args(argv)
    try:
        report = audit()
    except CensusUnavailable as error:
        print(json.dumps({"state": "UNAVAILABLE", "reason": str(error),
                          "production_authorized": False}, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 2 if report["nonmatching_public_spaces"] else 0


if __name__ == "__main__":
    sys.exit(main())
