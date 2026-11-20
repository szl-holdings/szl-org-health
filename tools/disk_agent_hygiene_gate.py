#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pure, read-only triage of *supplied* disk/agent metadata; no device access.

The caller is responsible for gathering observations without reading process
command lines or protected files. This module never authenticates evidence,
identifies disposable caches, launches workloads, or performs any cleanup.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import stat
from pathlib import Path
import re
import sys

SCHEMA = 'szl.disk-agent-hygiene-input/v1'
RESULT_SCHEMA = 'szl.disk-agent-hygiene-triage/v1'
GIB = 1024 ** 3
FLOOR_BYTES = 50 * GIB
HISTORICAL_DROP_BYTES = 5 * GIB
SHORT_DROP_BYTES = 2 * GIB
LARGE_PROCESS_BYTES = 512 * 1024 ** 2
MAX_INPUT_BYTES = 65536
MAX_PROCESSES = 256
MAX_SCRATCH = 64
MAX_OBSERVATIONS = 12
REPARSE = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
PROTECTED_PARTS = frozenset({'.ssh', '.gnupg', '.git', 'onedrive', 'appdata',
                              'private', 'secrets', 'credentials', 'keys',
                              'models', 'weights', 'huggingface', '.cache'})
NAME = re.compile(r'[A-Za-z0-9_. -]{1,64}\Z')


class InvalidInput(ValueError):
    """Stable error codes without exposing supplied file names or secrets."""


def require(test: bool, code: str) -> None:
    if not test:
        raise InvalidInput(code)


def keys(obj: object, allowed: set[str], code: str) -> dict:
    require(type(obj) is dict and set(obj) == allowed, code)
    return obj


def bounded_int(value: object, lo: int, hi: int, code: str) -> int:
    require(type(value) is int and lo <= value <= hi, code)
    return value


def timestamp(value: object) -> datetime:
    require(type(value) is str and len(value) <= 40, 'UTC_INVALID')
    try:
        t = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise InvalidInput('UTC_INVALID') from None
    require(t.utcoffset() is not None, 'UTC_UNZONED')
    return t.astimezone(timezone.utc)


def assess(source: dict) -> dict:
    """Classify *untrusted supplied metadata* without granting authority.

    Historical comparisons with a caller-asserted upstream-verified baseline
    are labeled as ASSERTED, never independently signature-verified here.
    Missing historical data remains UNKNOWN, not an implicit zero delta.
    """
    s = keys(source, {'schema', 'device', 'observations', 'historical',
                      'processes', 'scratch', 'cache_growth'}, 'INPUT_FIELDS_INVALID')
    require(s['schema'] == SCHEMA and s['device'] == 'BETTERWITHAGE',
            'SCHEMA_OR_DEVICE_MISMATCH')
    samples = s['observations']
    require(type(samples) is list and 1 <= len(samples) <= MAX_OBSERVATIONS,
            'OBSERVATIONS_INVALID')
    reads = []
    for item in samples:
        row = keys(item, {'utc', 'drive', 'total_bytes', 'free_bytes'},
                   'DISK_FIELDS_INVALID')
        require(row['drive'] == 'C:', 'DRIVE_MISMATCH')
        t = timestamp(row['utc'])
        total = bounded_int(row['total_bytes'], 1, 2**64 - 1,
                            'TOTAL_INVALID')
        free = bounded_int(row['free_bytes'], 0, total, 'FREE_INVALID')
        reads.append((t, total, free))
    require(len({r[1] for r in reads}) == 1, 'DISK_GEOMETRY_CHANGED')
    require(all(a[0] < b[0] for a, b in zip(reads, reads[1:])),
            'OBSERVATIONS_UNSORTED_OR_DUPLICATED')
    require((reads[-1][0] - reads[0][0]).total_seconds() <= 600,
            'OBSERVATION_WINDOW_TOO_WIDE')

    historical = s['historical']
    require(type(historical) is dict and type(historical.get('state')) is str
            and historical.get('state') in {'UNAVAILABLE', 'UPSTREAM_ASSERTED_VERIFIED'},
            'BASELINE_STATE_INVALID')
    baseline_drop = None
    baseline_state = 'UNAVAILABLE'
    if historical['state'] == 'UNAVAILABLE':
        keys(historical, {'state'}, 'MISSING_BASELINE_MUST_NOT_HAVE_VALUES')
    else:
        keys(historical, {'state', 'utc', 'drive', 'total_bytes', 'free_bytes',
                          'upstream_reference'}, 'BASELINE_FIELDS_INVALID')
        require(historical['drive'] == 'C:', 'BASELINE_DRIVE_MISMATCH')
        reference = historical['upstream_reference']
        require(type(reference) is str and 12 <= len(reference) <= 128 and
                NAME.fullmatch(reference) is not None,
                'BASELINE_REFERENCE_INVALID')
        prior_utc = timestamp(historical['utc'])
        prior_total = bounded_int(historical['total_bytes'], 1, 2**64 - 1,
                                  'BASELINE_TOTAL_INVALID')
        prior_free = bounded_int(historical['free_bytes'], 0, prior_total,
                                 'BASELINE_FREE_INVALID')
        require(prior_utc < reads[0][0] and prior_total == reads[0][1],
                'BASELINE_NOT_COMPARABLE')
        baseline_drop = max(0, prior_free - min(row[2] for row in reads))
        baseline_state = 'UPSTREAM_ASSERTED_NOT_CRYPTOGRAPHICALLY_CHECKED'

    processes = s['processes']
    require(type(processes) is list and len(processes) <= MAX_PROCESSES,
            'PROCESS_COUNT_INVALID')
    proc_ids = set()
    large = 0
    for p in processes:
        p = keys(p, {'name', 'pid', 'working_set_bytes'},
                 'PROCESS_FIELDS_INVALID')
        require(type(p['name']) is str and NAME.fullmatch(p['name']) is not None,
                'PROCESS_NAME_INVALID')
        pid = bounded_int(p['pid'], 1, 2**32 - 1, 'PID_INVALID')
        require(pid not in proc_ids, 'DUPLICATE_PID')
        proc_ids.add(pid)
        working_set = bounded_int(p['working_set_bytes'], 0, 2**64 - 1,
                                  'WORKING_SET_INVALID')
        large += working_set >= LARGE_PROCESS_BYTES

    scratch = s['scratch']
    require(type(scratch) is list and len(scratch) <= MAX_SCRATCH,
            'SCRATCH_COUNT_INVALID')
    unclaimed = 0
    scratch_ids = set()
    for item in scratch:
        row = keys(item, {'id', 'exists', 'size_bytes', 'owner_state'},
                   'SCRATCH_FIELDS_INVALID')
        require(type(row['id']) is str and NAME.fullmatch(row['id']) is not None,
                'SCRATCH_ID_INVALID')
        require(row['id'].casefold() not in scratch_ids, 'SCRATCH_ID_DUPLICATED')
        scratch_ids.add(row['id'].casefold())
        require(type(row['exists']) is bool, 'SCRATCH_EXISTS_INVALID')
        require(row['owner_state'] in ('UNVERIFIED', 'VERIFIED_CLAIMED'),
                'SCRATCH_OWNER_INVALID')
        bounded_int(row['size_bytes'], 0, 2**64 - 1, 'SCRATCH_SIZE_INVALID')
        if row['exists'] and row['owner_state'] != 'VERIFIED_CLAIMED':
            unclaimed += 1

    growth = s['cache_growth']
    require(type(growth) is dict and type(growth.get('state')) is str
            and growth.get('state') in ('UNOBSERVED', 'TWO_MEASUREMENTS'),
            'CACHE_STATE_INVALID')
    measured_growth = None
    if growth['state'] == 'UNOBSERVED':
        keys(growth, {'state'}, 'CACHE_UNKNOWN_FIELDS')
    else:
        keys(growth, {'state', 'before_bytes', 'after_bytes', 'seconds',
                      'source_bound'}, 'CACHE_FIELDS_INVALID')
        before = bounded_int(growth['before_bytes'], 0, 2**64 - 1,
                             'CACHE_BEFORE_INVALID')
        after = bounded_int(growth['after_bytes'], 0, 2**64 - 1,
                            'CACHE_AFTER_INVALID')
        seconds = bounded_int(growth['seconds'], 1, 600,
                              'CACHE_INTERVAL_INVALID')
        require(growth['source_bound'] is True, 'CACHE_SOURCE_NOT_BOUND')
        measured_growth = max(0, after - before)

    reasons = []
    if min(r[2] for r in reads) < FLOOR_BYTES:
        reasons.append('FREE_BELOW_50_GIB')
    if baseline_drop is not None and baseline_drop >= HISTORICAL_DROP_BYTES:
        reasons.append('SUPPLIED_BASELINE_DROP_AT_LEAST_5_GIB')
    for older, newer in zip(reads, reads[1:]):
        if ((newer[0] - older[0]).total_seconds() <= 120
                and older[2] - newer[2] >= SHORT_DROP_BYTES):
            reasons.append('RAPID_FREE_DROP_UNATTRIBUTED')
            break
    if measured_growth is not None and measured_growth >= SHORT_DROP_BYTES:
        reasons.append('SUPPLIED_CACHE_GROWTH_AT_LEAST_2_GIB')
    if unclaimed:
        reasons.append('SCRATCH_OWNER_UNVERIFIED')
    return {
        'schema': RESULT_SCHEMA,
        'source': 'CALLER_SUPPLIED_METADATA_NOT_INDEPENDENTLY_SENSED',
        'device': 'BETTERWITHAGE',
        'last_observed_utc': reads[-1][0].isoformat(),
        'drive_total_bytes': reads[-1][1],
        'latest_free_bytes': reads[-1][2],
        'minimum_sampled_free_bytes': min(r[2] for r in reads),
        'baseline_state': baseline_state,
        'historical_drop_bytes': baseline_drop,
        'baseline_signature_independently_verified': False,
        'large_agent_process_count': large,
        'supplied_process_count': len(processes),
        'unclaimed_scratch_count': unclaimed,
        'cache_growth_bytes': measured_growth,
        'cache_growth_claim_independently_verified': False,
        'cache_disposable_confirmed': False,
        'disposable_cache_path': None,
        'notification_recommended': bool(reasons),
        'status': 'ALERT' if reasons else 'NO_THRESHOLD_CONFIRMED',
        'reasons': sorted(set(reasons)),
        'files_deleted': False,
        'processes_stopped': False,
        'command_lines_read': False,
        'credentials_read': False,
        'source_recovery_performed': False,
        'cleanup_authorized': False,
        'training_or_release_authorized': False,
    }


def _distinct_pairs(pairs):
    d = {}
    for key, value in pairs:
        require(key not in d, 'DUPLICATE_JSON_KEY')
        d[key] = value
    return d


def check_input_path(path: Path) -> int:
    """Do not follow symlinks/reparse or open known protected credential roots."""
    require(path.suffix.casefold() == '.json', 'INPUT_EXTENSION_INVALID')
    require(not any(part.casefold() in PROTECTED_PARTS for part in path.parts),
            'INPUT_PROTECTED_PATH')
    try:
        for part in (path, *path.parents):
            info = part.lstat()
            require(not stat.S_ISLNK(info.st_mode) and not
                    (getattr(info, 'st_file_attributes', 0) & REPARSE),
                    'INPUT_REPARSE_PATH')
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode), 'INPUT_NOT_REGULAR')
        require(0 < info.st_size <= MAX_INPUT_BYTES, 'INPUT_BYTES_EXCEEDED')
        return info.st_size
    except OSError as exc:
        raise InvalidInput('INPUT_UNAVAILABLE') from exc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', required=True, type=Path,
                   help='Explicit caller-sanitized small JSON metadata file')
    a = p.parse_args(argv)
    try:
        check_input_path(a.input)
        raw = a.input.read_bytes()
        require(len(raw) <= MAX_INPUT_BYTES, 'INPUT_BYTES_EXCEEDED')
        obj = json.loads(raw.decode('utf-8'), object_pairs_hook=_distinct_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(
                             InvalidInput('NONFINITE_NUMBER')))
        report = assess(obj)
    except (InvalidInput, OSError, UnicodeError, ValueError) as exc:
        report = {'schema': RESULT_SCHEMA, 'status': 'HOLD_INVALID_OR_UNAVAILABLE',
                  'reason': str(exc) if isinstance(exc, InvalidInput)
                  else 'INPUT_UNAVAILABLE_OR_INVALID',
                  'notification_recommended': False,
                  'cleanup_authorized': False,
                  'training_or_release_authorized': False}
        print(json.dumps(report, sort_keys=True))
        return 3
    print(json.dumps(report, sort_keys=True))
    return 2 if report['notification_recommended'] else 0


if __name__ == '__main__':
    sys.exit(main())
