"""Assemble independently bounded collectors into one schema-v2 report."""
from __future__ import annotations

import concurrent.futures as cf
import time
from collections.abc import Callable
from typing import Any

from .github import collect_github
from .governance import evaluate_report
from .huggingface import collect_huggingface
from .sites import collect_dns, collect_sites

SCHEMA_VERSION = 2
_CACHE: dict[str, Any] = {"data": None, "ts": 0.0}
_CACHE_TTL = 60


def build_report(
    *,
    use_cache: bool = True,
    github_timeout: float = 20.0,
    github_retries: int = 2,
    include_branch_protection: bool = True,
) -> dict[str, Any]:
    now = time.time()
    cached = _CACHE.get("data")
    if use_cache and cached and now - float(_CACHE.get("ts") or 0) < _CACHE_TTL:
        return cached

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sources": {},
    }
    collectors: dict[str, Callable[[], Any]] = {
        "github": lambda: collect_github(
            request_timeout=github_timeout,
            retries=github_retries,
            include_branch_protection=include_branch_protection,
        ),
        "huggingface": collect_huggingface,
        "sites": collect_sites,
        "dns": collect_dns,
    }
    with cf.ThreadPoolExecutor(max_workers=len(collectors)) as executor:
        futures = {executor.submit(fn): name for name, fn in collectors.items()}
        for future in cf.as_completed(futures):
            name = futures[future]
            try:
                report["sources"][name] = {"ok": True, "data": future.result()}
            except Exception as exc:  # noqa: BLE001 - explicit source failure
                report["sources"][name] = {
                    "ok": False,
                    "error": str(exc)[:160],
                }

    # Additive schema-v2 field. Policy evaluation is bounded to this exact
    # census and fails closed without changing source evidence.
    report["governance"] = evaluate_report(report)
    _CACHE["data"] = report
    _CACHE["ts"] = now
    return report
