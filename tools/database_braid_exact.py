#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Float-free weighted geometric-mean decision for the SZL Ouroboros braid v2.

Decides ``G >= tau`` for ``G = (prod x_i^w_i)^(1/W)`` with exact rationals and
positive integer weights by comparing two integers, so the verdict is the same
on every machine and anyone can re-multiply it by hand. The classical ordering
harmonic <= geometric <= arithmetic mean is used only to EXPLAIN a verdict and
is re-checked against the integer comparison on every call.

Prior art, not ours: the three Pythagorean means and their ordering are
classical; non-compensating (geometric) aggregation is standard. This module
is an exact re-statement of the estate's locked admit rule
(``admit <=> G >= tau and min(x) > 0``; ``dang <=> AM >= tau and GM < tau``).

It computes a number. It does NOT grant authority, admit anything to
production, call a model, or sign. A passing aggregate here means only that
the supplied ratios cleared a threshold fixed before the run.
"""
from __future__ import annotations

from fractions import Fraction
from pathlib import Path
import sys

try:
    from tools.database_braid_common import (
        canonical, closed, parse_rational, rational_text, require,
    )
    from tools.database_catalog_admission import InputError
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tools.database_braid_common import (
        canonical, closed, parse_rational, rational_text, require,
    )
    from tools.database_catalog_admission import InputError

SCHEMA = "szl.database-braid-exact-decision/v1"
AGGREGATE = "WEIGHTED_GEOMETRIC_MEAN_ZERO_PINNED_EXACT_RATIONAL"
PATH_NONE = "NONE"
PATH_ZERO_PINNED = "ZERO_PINNED"
PATH_BELOW = "BELOW_THRESHOLD"
RUNG_ZERO = "ZERO_AXIS_PINS_AGGREGATE"
RUNG_HM = "HARMONIC_MEAN_SUFFICES"
RUNG_AM = "ARITHMETIC_MEAN_REFUTES"
RUNG_POWER = "EXACT_POWER_COMPARISON"
MAX_AXES = 64
MAX_WEIGHT = 64
MAX_AXIS_BITS = 1400
MAX_OPERAND_BITS = 13000
PPM = 10 ** 6
_FIELDS = (
    "schema", "aggregate", "tau", "axes", "weights", "weight_sum", "min_axis",
    "arithmetic_mean", "harmonic_mean", "geometric_mean_meets_tau",
    "geometric_mean_ppm_floor", "rung", "power_comparison", "dang",
    "refusal_path", "authority_granted",
)


def ratio(numerator, denominator) -> Fraction:
    """An axis value from two counted integers. Refuses 0/0 and values above one."""
    require(type(numerator) is int and type(denominator) is int, "EXACT_RATIO_INVALID")
    require(denominator > 0 and 0 <= numerator <= denominator, "EXACT_RATIO_INVALID")
    return Fraction(numerator, denominator)


def iroot(value: int, degree: int) -> int:
    """Floor of the ``degree``-th root of a non-negative integer, exactly."""
    require(type(value) is int and type(degree) is int and value >= 0 and degree >= 1,
            "EXACT_ROOT_INVALID")
    if value < 2 or degree == 1:
        return value
    low, high = 1, 1 << (value.bit_length() // degree + 1)
    while low < high:
        mid = (low + high + 1) // 2
        if mid ** degree <= value:
            low = mid
        else:
            high = mid - 1
    return low


def _small(value: Fraction) -> bool:
    return max(value.numerator.bit_length(), value.denominator.bit_length()) <= MAX_AXIS_BITS


def _bounded_text(value: Fraction) -> str:
    """Text of a derived rational, refused before it could exceed Python's int-to-str limit."""
    require(max(value.numerator.bit_length(), value.denominator.bit_length()) <= MAX_OPERAND_BITS,
            "EXACT_OPERAND_TOO_LARGE")
    try:
        return rational_text(value)
    except InputError as exc:
        if exc.code != "RATIONAL_TOO_LARGE":
            raise
        raise InputError("EXACT_OPERAND_TOO_LARGE") from None


def _int_text(value: int) -> str:
    # The digit limit can be lowered by PYTHONINTMAXSTRDIGITS; a lower limit refuses, typed.
    try:
        return str(value)
    except ValueError:
        raise InputError("EXACT_OPERAND_TOO_LARGE") from None


def _inputs(axes, weights, tau):
    require(type(axes) is dict and 0 < len(axes) <= MAX_AXES, "EXACT_AXES_INVALID")
    require(all(type(name) is str and 0 < len(name) <= 64 for name in axes), "EXACT_AXES_INVALID")
    require(type(weights) is dict and set(weights) == set(axes), "EXACT_WEIGHTS_INVALID")
    require(type(tau) is Fraction and 0 < tau <= 1 and _small(tau), "EXACT_TAU_INVALID")
    names = sorted(axes)
    for name in names:
        value, weight = axes[name], weights[name]
        require(type(value) is Fraction and 0 <= value <= 1 and _small(value),
                "EXACT_AXIS_OUT_OF_RANGE")
        require(type(weight) is int and 1 <= weight <= MAX_WEIGHT, "EXACT_WEIGHTS_INVALID")
    return names


def decide(axes, weights, tau) -> dict:
    """Exact verdict for ``axes`` (name -> Fraction in [0,1]) at threshold ``tau``."""
    names = _inputs(axes, weights, tau)
    total = sum(weights[n] for n in names)
    low_name = min(names, key=lambda n: (axes[n], n))
    arithmetic = sum((axes[n] * weights[n] for n in names), Fraction(0)) / total
    record = {
        "schema": SCHEMA,
        "aggregate": AGGREGATE,
        "tau": rational_text(tau),
        "axes": {n: rational_text(axes[n]) for n in names},
        "weights": {n: weights[n] for n in names},
        "weight_sum": total,
        "min_axis": {"id": low_name, "value": rational_text(axes[low_name])},
        "arithmetic_mean": _bounded_text(arithmetic),
        "authority_granted": False,
    }
    if axes[low_name] == 0:
        # A zero axis is a veto, never an average. No power comparison is formed.
        record.update({
            "harmonic_mean": None,
            "geometric_mean_meets_tau": False,
            "geometric_mean_ppm_floor": 0,
            "rung": RUNG_ZERO,
            "power_comparison": None,
            "dang": arithmetic >= tau,
            "refusal_path": PATH_ZERO_PINNED,
        })
        return record
    harmonic = total / sum((Fraction(weights[n]) / axes[n] for n in names), Fraction(0))
    # Bit-length bounds before any product is formed: each side has at least its bound
    # minus 2W - 1 bits, so this never refuses an input the exact check below would accept.
    bound_left = (sum(weights[n] * axes[n].numerator.bit_length() for n in names) +
                  total * tau.denominator.bit_length())
    bound_right = (sum(weights[n] * axes[n].denominator.bit_length() for n in names) +
                   total * tau.numerator.bit_length())
    require(max(bound_left, bound_right) - 2 * total + 1 <= MAX_OPERAND_BITS,
            "EXACT_OPERAND_TOO_LARGE")
    left_num = left_den = 1
    for name in names:
        left_num *= axes[name].numerator ** weights[name]
        left_den *= axes[name].denominator ** weights[name]
    left = left_num * tau.denominator ** total
    right = tau.numerator ** total * left_den
    require(max(left.bit_length(), right.bit_length()) <= MAX_OPERAND_BITS,
            "EXACT_OPERAND_TOO_LARGE")
    meets = left >= right
    if harmonic >= tau:
        rung = RUNG_HM
    elif arithmetic < tau:
        rung = RUNG_AM
    else:
        rung = RUNG_POWER
    # HM <= GM <= AM must agree with the integer comparison on every input.
    if (rung == RUNG_HM and not meets) or (rung == RUNG_AM and meets) or not (
            harmonic <= arithmetic):
        raise InputError("EXACT_MEAN_ORDER_VIOLATED")
    # floor(GM * 10^6) = floor(((left_num * 10^(6W)) // left_den) ** (1/W)), exactly.
    ppm_floor = iroot((left_num * PPM ** total) // left_den, total)
    record.update({
        "harmonic_mean": _bounded_text(harmonic),
        "geometric_mean_meets_tau": meets,
        "geometric_mean_ppm_floor": ppm_floor,
        "rung": rung,
        "power_comparison": {
            "left": _int_text(left), "right": _int_text(right),
            "relation": "LEFT_AT_LEAST_RIGHT" if meets else "LEFT_BELOW_RIGHT",
            "meaning": "prod(num_i^w_i)*tau_den^W versus tau_num^W*prod(den_i^w_i)",
        },
        "dang": (arithmetic >= tau) and not meets,
        "refusal_path": PATH_NONE if meets else PATH_BELOW,
    })
    return record


def verify_decision(record) -> bool:
    """Re-derive a decision record from its own axes, weights and tau."""
    closed(record, _FIELDS, "EXACT_DECISION_FIELDS_INVALID")
    require(record["schema"] == SCHEMA and record["aggregate"] == AGGREGATE and
            record["authority_granted"] is False, "EXACT_DECISION_SCHEMA_INVALID")
    require(type(record["axes"]) is dict and type(record["weights"]) is dict,
            "EXACT_DECISION_FIELDS_INVALID")
    axes = {}
    for name, text in record["axes"].items():
        require(type(name) is str, "EXACT_DECISION_FIELDS_INVALID")
        axes[name] = parse_rational(text)
    expected = decide(axes, record["weights"], parse_rational(record["tau"]))
    # Byte comparison, not ==: Python's == treats True as 1 and 0 as False.
    require(canonical(expected) == canonical(record), "EXACT_DECISION_DRIFT")
    return True
