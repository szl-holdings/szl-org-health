#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic tests: no devices, credentials, files to remove, or agent stops."""
from __future__ import annotations

from copy import deepcopy
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import disk_agent_hygiene_gate as gate

T = 1021821579264
F = 688198324224
U = '2026-11-20T05:21:01Z'
V = '2026-11-20T05:21:08Z'


def example():
    return {'schema': gate.SCHEMA, 'device': 'BETTERWITHAGE',
            'observations': [{'utc': U, 'drive': 'C:', 'total_bytes': T,
                              'free_bytes': F + 8192},
                             {'utc': V, 'drive': 'C:', 'total_bytes': T,
                              'free_bytes': F}],
            'historical': {'state': 'UNAVAILABLE'},
            'processes': [{'name': 'llama-server', 'pid': 12572,
                           'working_set_bytes': 745 * 1024**2}],
            'scratch': [], 'cache_growth': {'state': 'UNOBSERVED'}}


class TriageTests(unittest.TestCase):
    def test_healthy_no_notification_and_missing_baseline_still_unknown(self):
        x = gate.assess(example())
        self.assertEqual(x['status'], 'NO_THRESHOLD_CONFIRMED')
        self.assertEqual(x['baseline_state'], 'UNAVAILABLE')
        self.assertIsNone(x['historical_drop_bytes'])
        self.assertEqual(x['large_agent_process_count'], 1)
        self.assertFalse(x['notification_recommended'])
        self.assertFalse(x['cleanup_authorized'])

    def test_unclaimed_scratch_alert_no_disposability(self):
        x = example()
        x['scratch'] = [{'id': 'gh_scan_err', 'exists': True,
                         'size_bytes': 5306, 'owner_state': 'UNVERIFIED'}]
        r = gate.assess(x)
        self.assertIn('SCRATCH_OWNER_UNVERIFIED', r['reasons'])
        self.assertEqual(r['unclaimed_scratch_count'], 1)
        self.assertFalse(r['cache_disposable_confirmed'])
        self.assertIsNone(r['disposable_cache_path'])

    def test_verified_claim_does_not_mean_disposal(self):
        x = example()
        x['scratch'] = [{'id': 'log1', 'exists': True, 'size_bytes': 100,
                         'owner_state': 'VERIFIED_CLAIMED'}]
        r = gate.assess(x)
        self.assertFalse(r['cleanup_authorized'])
        self.assertFalse(r['notification_recommended'])

    def test_exact_50_gib_is_not_below_threshold(self):
        x = example()
        x['observations'][0]['free_bytes'] = 50 * gate.GIB
        x['observations'][1]['free_bytes'] = 50 * gate.GIB
        self.assertNotIn('FREE_BELOW_50_GIB', gate.assess(x)['reasons'])

    def test_below_50_gib_alerts(self):
        x = example()
        x['observations'][0]['free_bytes'] = 49 * gate.GIB
        x['observations'][1]['free_bytes'] = 49 * gate.GIB
        self.assertIn('FREE_BELOW_50_GIB', gate.assess(x)['reasons'])

    def test_declared_upstream_baseline_drop_five_gib(self):
        x = example()
        x['historical'] = {'state': 'UPSTREAM_ASSERTED_VERIFIED',
                           'utc': '2026-11-20T03:00:00Z', 'drive': 'C:',
                           'total_bytes': T, 'free_bytes': F + 5*gate.GIB,
                           'upstream_reference': 'receipt-20261120-a1'}
        r = gate.assess(x)
        self.assertIn('SUPPLIED_BASELINE_DROP_AT_LEAST_5_GIB', r['reasons'])
        self.assertEqual(r['historical_drop_bytes'], 5*gate.GIB)
        self.assertFalse(r['baseline_signature_independently_verified'])

    def test_untrusted_baseline_without_ref_does_not_fake_verification(self):
        x = example()
        x['historical'] = {'state': 'UPSTREAM_ASSERTED_VERIFIED',
                           'utc': '2026-11-20T03:00:00Z', 'drive': 'C:',
                           'total_bytes': T, 'free_bytes': F + 7*gate.GIB}
        with self.assertRaises(gate.InvalidInput):
            gate.assess(x)

    def test_missing_baseline_cannot_contain_fake_zero_delta(self):
        x = example(); x['historical']['free_bytes'] = 0
        with self.assertRaises(gate.InvalidInput):
            gate.assess(x)

    def test_geometry_change_rejected(self):
        x = example(); x['observations'][1]['total_bytes'] += 1
        with self.assertRaises(gate.InvalidInput):
            gate.assess(x)

    def test_reverse_clock_rejected(self):
        x = example(); x['observations'] = list(reversed(x['observations']))
        with self.assertRaises(gate.InvalidInput):
            gate.assess(x)

    def test_rapid_disk_drop_is_not_cause_attribution(self):
        x = example()
        x['observations'][0]['free_bytes'] += 3 * gate.GIB
        r = gate.assess(x)
        self.assertIn('RAPID_FREE_DROP_UNATTRIBUTED', r['reasons'])
        self.assertIsNone(r['cache_growth_bytes'])
        self.assertFalse(r['cache_disposable_confirmed'])

    def test_source_bound_cache_growth_alerts_but_no_delete(self):
        x = example()
        x['cache_growth'] = {'state': 'TWO_MEASUREMENTS', 'before_bytes': 400,
                             'after_bytes': 3 * gate.GIB + 400,
                             'seconds': 7, 'source_bound': True}
        r = gate.assess(x)
        self.assertIn('SUPPLIED_CACHE_GROWTH_AT_LEAST_2_GIB', r['reasons'])
        self.assertFalse(r['cleanup_authorized'])

    def test_unbound_cache_claim_rejected(self):
        x = example()
        x['cache_growth'] = {'state': 'TWO_MEASUREMENTS', 'before_bytes': 400,
                             'after_bytes': 3 * gate.GIB + 400,
                             'seconds': 7, 'source_bound': False}
        with self.assertRaises(gate.InvalidInput):
            gate.assess(x)

    def test_no_command_line_fields_allowed(self):
        x = example(); x['processes'][0]['command_line'] = 'SECRET'
        with self.assertRaises(gate.InvalidInput):
            gate.assess(x)

    def test_no_path_or_credential_fields_allowed(self):
        x = example(); x['scratch'] = [{'id': 'log', 'exists': True,
                     'size_bytes': 1, 'owner_state': 'UNVERIFIED', 'path': 'SECRET'}]
        with self.assertRaises(gate.InvalidInput):
            gate.assess(x)

    def test_boolean_bytes_rejected(self):
        x = example(); x['observations'][0]['free_bytes'] = True
        with self.assertRaises(gate.InvalidInput):
            gate.assess(x)

    def test_large_process_count_does_not_include_below_threshold(self):
        x = example(); x['processes'].append({'name': 'node', 'pid': 1234,
                                             'working_set_bytes': 511*1024**2})
        self.assertEqual(gate.assess(x)['large_agent_process_count'], 1)

    def test_duplicate_scratch_id_rejected(self):
        x = example()
        x['scratch'] = [{'id': 'err', 'exists': True, 'size_bytes': 2,
                         'owner_state': 'UNVERIFIED'}] * 2
        with self.assertRaises(gate.InvalidInput):
            gate.assess(x)

    def test_invalid_baseline_state_type_fails_closed(self):
        x = example(); x['historical']['state'] = []
        with self.assertRaises(gate.InvalidInput):
            gate.assess(x)

    def test_invalid_cache_state_type_fails_closed(self):
        x = example(); x['cache_growth']['state'] = {}
        with self.assertRaises(gate.InvalidInput):
            gate.assess(x)

    def test_duplicate_pid_rejected(self):
        x = example(); x['processes'].append(deepcopy(x['processes'][0]))
        with self.assertRaises(gate.InvalidInput):
            gate.assess(x)

    def test_duplicate_json_keys_and_nan_hold(self):
        for raw in ('{"schema":1,"schema":2}', '{"x":NaN}'):
            with tempfile.TemporaryDirectory() as td:
                p = Path(td) / 'x.json';p.write_text(raw)
                out = io.StringIO()
                with redirect_stdout(out):
                    exit_code = gate.main(['--input', str(p)])
                self.assertEqual(exit_code, 3)
                self.assertEqual(json.loads(out.getvalue())['status'],
                                 'HOLD_INVALID_OR_UNAVAILABLE')

    def test_symlink_input_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / 'source.json'
            dst = Path(td) / 'link.json'
            src.write_text(json.dumps(example()))
            try:
                dst.symlink_to(src)
            except (OSError, NotImplementedError):
                self.skipTest('symlink not available')
            with self.assertRaises(gate.InvalidInput):
                gate.check_input_path(dst)

    def test_protected_input_path_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'secrets'
            root.mkdir(); p = root / 'metadata.json'; p.write_text('{}')
            with self.assertRaises(gate.InvalidInput):
                gate.check_input_path(p)

    def test_missing_input_holds(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(gate.main(['--input', 'definitely-not-a-real-file-443329']), 3)
        self.assertNotIn('definitely-not-a-real-file', out.getvalue())

    def test_cli_alert_exit_and_no_side_effects(self):
        x = example()
        x['scratch'] = [{'id': 'err', 'exists': True, 'size_bytes': 20,
                         'owner_state': 'UNVERIFIED'}]
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'input.json';p.write_text(json.dumps(x))
            before=p.read_bytes();o=io.StringIO()
            with redirect_stdout(o):
                code=gate.main(['--input', str(p)])
            self.assertEqual(code, 2)
            self.assertEqual(p.read_bytes(), before)
            r=json.loads(o.getvalue())
            self.assertFalse(r['cleanup_authorized'])
            self.assertFalse(r['command_lines_read'])


if __name__ == '__main__':
    unittest.main()
