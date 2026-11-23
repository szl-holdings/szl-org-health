"""Honest, class-separated status surface for the estate (propose-only).

Doctrine (leader-study card r1, docs/leader-study-r1.md aligning #422):
provider failures, evidence integrity, and freshness are THREE separate
status classes, never merged into one red/green; every observation
carries a timestamp and window; stale or absent cells are UNKNOWN, never
green; error budgets burn per class.

Propose-only, unsigned; merges are owned by the estate signature wall.
No status claims are made about any other pull request.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import List, Optional

PROVIDER_FAILURE = "PROVIDER_FAILURE"
EVIDENCE_INTEGRITY = "EVIDENCE_INTEGRITY"
FRESHNESS = "FRESHNESS"
CLASSES = (PROVIDER_FAILURE, EVIDENCE_INTEGRITY, FRESHNESS)

UNKNOWN = "UNKNOWN"


class ObservationError(ValueError):
    """An observation is malformed."""


@dataclass
class Observation:
    kind: str
    label: str
    ok: bool
    observed_ts: float
    window_s: float

    def __post_init__(self):
        if self.kind not in CLASSES:
            raise ObservationError("kind must be one of %r" % (CLASSES,))
        if not self.label or not isinstance(self.label, str):
            raise ObservationError("label must be a non-empty string")
        if type(self.ok) is not bool:
            raise ObservationError("ok must be a boolean")
        if not (math.isfinite(self.observed_ts) and math.isfinite(self.window_s)):
            raise ObservationError("observed_ts and window_s must be finite")
        if not self.window_s or self.window_s <= 0:
            raise ObservationError("window_s must be positive")
        if self.observed_ts < 0:
            raise ObservationError("observed_ts must be non-negative")

    def is_stale(self, now_ts: float) -> bool:
        return now_ts - self.observed_ts > self.window_s


@dataclass
class Cell:
    label: str
    ok: bool
    fresh: bool
    cell_result: str  # OK | FAILING | UNKNOWN

    def as_dict(self) -> dict:
        return {"label": self.label, "ok": self.ok, "fresh": self.fresh,
                "cell_result": self.cell_result}


@dataclass
class StatusSection:
    kind: str
    cells: List[Cell] = field(default_factory=list)
    burn: Optional[float] = None  # None = UNKNOWN burn

    def as_dict(self) -> dict:
        return {"kind": self.kind, "burn": self.burn,
                "cells": [c.as_dict() for c in self.cells]}


@dataclass
class StatusReport:
    provider_failure: StatusSection
    evidence_integrity: StatusSection
    freshness: StatusSection

    def as_dict(self) -> dict:
        return {
            "provider_failure": self.provider_failure.as_dict(),
            "evidence_integrity": self.evidence_integrity.as_dict(),
            "freshness": self.freshness.as_dict(),
            "no_merged_status": True,  # no overall red/green key, by doctrine
        }


def _fail_fraction(observations: List[Observation]) -> Optional[float]:
    """Fraction of failing observations; None when no samples."""
    if not observations:
        return None
    failing = sum(1 for o in observations if not o.ok)
    return failing / len(observations)


class ErrorBudget:
    """Burn per class, in-window samples only, never cross-class."""

    def burn(self, kind: str, observations: List[Observation],
             now_ts: Optional[float] = None) -> Optional[float]:
        if kind not in CLASSES:
            raise ObservationError("unknown class %r" % kind)
        now = now_ts if now_ts is not None else time.time()
        in_window = [o for o in observations
                     if o.kind == kind and not o.is_stale(now)]
        # Honest limitation, disclosed: stale samples are excluded rather
        # than guessed - an empty window yields UNKNOWN burn (None).
        return _fail_fraction(in_window)


def _section(kind: str, observations: List[Observation], now_ts: float,
             budget: ErrorBudget) -> StatusSection:
    rows = [o for o in observations if o.kind == kind]
    cells = []
    for o in rows:
        stale = o.is_stale(now_ts)
        if stale:
            result = UNKNOWN  # stale cells are never green
        else:
            result = "OK" if o.ok else "FAILING"
        cells.append(Cell(o.label, o.ok, not stale, result))
    burn = budget.burn(kind, observations, now_ts)
    return StatusSection(kind=kind, cells=cells, burn=burn)


def classify(observations: List[Observation],
             now_ts: Optional[float] = None) -> StatusReport:
    """Classify into THREE separate sections; never one merged status."""
    obs = list(observations or [])
    for o in obs:
        if not isinstance(o, Observation):
            raise ObservationError("classify requires Observation instances")
    budget = ErrorBudget()
    now = now_ts if now_ts is not None else time.time()
    return StatusReport(
        provider_failure=_section(PROVIDER_FAILURE, obs, now, budget),
        evidence_integrity=_section(EVIDENCE_INTEGRITY, obs, now, budget),
        freshness=_section(FRESHNESS, obs, now, budget),
    )
