"""Live, fail-closed estate collectors for szl-org-health."""

from __future__ import annotations

from importlib import import_module
from typing import Any

__all__ = [
    "SCHEMA_VERSION",
    "build_report",
    "collect_dns",
    "collect_github",
    "collect_huggingface",
    "collect_sites",
]

_EXPORTS = {
    "SCHEMA_VERSION": (".report", "SCHEMA_VERSION"),
    "build_report": (".report", "build_report"),
    "collect_dns": (".sites", "collect_dns"),
    "collect_github": (".github", "collect_github"),
    "collect_huggingface": (".huggingface", "collect_huggingface"),
    "collect_sites": (".sites", "collect_sites"),
}


def __getattr__(name: str) -> Any:
    """Load live collectors only when their public export is requested."""

    try:
        module_name, attribute = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *__all__})
