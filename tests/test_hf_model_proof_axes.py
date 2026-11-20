"""Pure model proof-axes regressions; no Hub, training, publication, or credentials."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.hf_model_proof_axes import ProofHold, evaluate, main  # noqa: E402

SHA = 'a' * 40


def row(name: str = 'sample', **changes):
    result = dict(id='SZLHOLDINGS/' + name, sha=SHA, private=False,
                  weight_files_observed=[], weight_state='no-weight-file-observed',
                  contract='unclassified', artifact_state='no-model-artifact-observed',
                  license_declared=False, pipeline_tag=None)
    result.update(changes)
    return result


def snap(*rows):
    return {'huggingface': {'organization': 'SZLHOLDINGS', 'assets': {
        'models': {'ok': True, 'partial': False, 'count': len(rows), 'items': list(rows)}
    }}}


class ModelProofAxesTests(unittest.TestCase):
    def evaluate(self, *rows, scope='public'):
        return evaluate(snap(*rows), scope=scope, source_revision=SHA)

    def test_config_only_with_pipeline_tag_is_not_training(self):
        r = self.evaluate(row(pipeline_tag='text-generation'))
        self.assertEqual(r['status_counts'], {'NO_WEIGHT_FILE_OBSERVED': 1})
        self.assertEqual(r['training_verified_count'], 0)
        self.assertEqual(r['production_qualified_count'], 0)

    def test_weights_and_readme_claims_do_not_prove_training(self):
        r = self.evaluate(row(weight_files_observed=['adapter_model.safetensors'],
                              weight_state='weights-present',
                              artifact_state='artifact-present',
                              license_declared=True))
        self.assertEqual(r['status_counts'], {'WEIGHT_ARTIFACT_UNQUALIFIED': 1})
        self.assertFalse(r['training_and_release_authorized'])

    def test_model_with_eval_filename_cannot_be_called_qualified(self):
        a = row(weight_files_observed=['model.safetensors'],
                weight_state='weights-present', artifact_state='artifact-present')
        a['evaluation_filename'] = 'eval_pass.json'
        r = self.evaluate(a)
        self.assertEqual(r['training_verified_count'], 0)
        self.assertEqual(r['evaluation_verified_count'], 0)

    def test_kernel_does_not_need_training_weights(self):
        r = self.evaluate(row(contract='huggingface-kernel',
                              artifact_state='not-required-by-contract'))
        self.assertEqual(r['status_counts'], {'NON_TRAINING_ARTIFACT': 1})
        self.assertEqual(r['training_verified_count'], 0)

    def test_non_training_contract_cannot_hide_weight_evidence(self):
        suspicious = row(contract='huggingface-kernel',
                         weight_files_observed=['adapter_model.safetensors'],
                         weight_state='weights-present',
                         artifact_state='artifact-present')
        result = self.evaluate(suspicious)
        self.assertEqual(result['status_counts'], {'UNKNOWN': 1})
        self.assertEqual(result['reason_counts'],
                         {'NON_TRAINING_CONTRACT_WEIGHT_CONTRADICTION': 1})
        self.assertEqual(result['training_verified_count'], 0)
        self.assertFalse(result['training_and_release_authorized'])

    def test_non_training_contract_requires_observed_empty_weights(self):
        for changes, reason in (
            ({'weight_files_observed': None, 'weight_state': 'unknown'},
             'NON_TRAINING_CONTRACT_WEIGHT_UNOBSERVED'),
            ({'weight_files_observed': ['model.safetensors']},
             'NON_TRAINING_CONTRACT_WEIGHT_CONTRADICTION'),
            ({'weight_state': 'unknown'},
             'NON_TRAINING_CONTRACT_WEIGHT_CONTRADICTION'),
        ):
            with self.subTest(changes=changes):
                result = self.evaluate(row(contract='huggingface-kernel',
                                           artifact_state='not-required-by-contract',
                                           **changes))
                self.assertEqual(result['status_counts'], {'UNKNOWN': 1})
                self.assertEqual(result['reason_counts'], {reason: 1})

    def test_missing_license_metadata_is_independent_gate(self):
        r = self.evaluate(row(weight_files_observed=['model.safetensors'],
                              weight_state='weights-present',
                              artifact_state='artifact-present'))
        self.assertEqual(r['license_metadata_absent'], 1)
        self.assertEqual(r['status_counts'], {'WEIGHT_ARTIFACT_UNQUALIFIED': 1})

    def test_unknown_weight_observation_is_not_absent(self):
        r = self.evaluate(row(weight_files_observed=[], weight_state='unknown',
                              artifact_state='unknown', sha=None))
        self.assertEqual(r['status_counts'], {'UNKNOWN': 1})
        self.assertNotIn('NO_WEIGHT_FILE_OBSERVED', r['status_counts'])

    def test_public_private_visibility_is_not_proven(self):
        for private in (True, None, "unknown"):
            with self.subTest(private=private):
                with self.assertRaisesRegex(ProofHold, 'PUBLIC_SCOPE_VISIBILITY_UNVERIFIED'):
                    self.evaluate(row(private=private))
        r2 = self.evaluate(row(private=True), scope='authenticated')
        self.assertEqual(r2['status_counts'], {'NO_WEIGHT_FILE_OBSERVED': 1})
        self.assertEqual(r2['scope'], 'authenticated')

    def test_duplicate_ids_hold_without_a_success_report(self):
        with self.assertRaisesRegex(ProofHold, 'DUPLICATE_MODEL_ID'):
            self.evaluate(row(), row())

    def test_count_and_organization_mismatch_are_holds(self):
        data = snap(row())
        data['huggingface']['assets']['models']['count'] = 100
        with self.assertRaisesRegex(ProofHold, 'MODEL_DENOMINATOR_MISMATCH'):
            evaluate(data, scope='public', source_revision=SHA)
        data = snap(row())
        data['huggingface']['organization'] = 'OTHER'
        with self.assertRaisesRegex(ProofHold, 'HF_ORGANIZATION_MISMATCH'):
            evaluate(data, scope='public', source_revision=SHA)

    def test_contradictory_weight_fields_become_unknown(self):
        r = self.evaluate(row(weight_state='weights-present'))
        self.assertEqual(r['status_counts'], {'UNKNOWN': 1})

    def test_malformed_row_counted_as_unknown_not_an_artifact(self):
        r = self.evaluate(None)
        self.assertEqual(r['status_counts'], {'UNKNOWN': 1})
        self.assertEqual(r['reason_counts'], {'MALFORMED_MODEL_ROW': 1})

    def test_an_authenticated_evidence_copy_cannot_be_upgraded_by_scope(self):
        r = self.evaluate(row(weight_files_observed=['model.safetensors'],
                              weight_state='weights-present', artifact_state='artifact-present'),
                          scope='authenticated')
        self.assertFalse(r['training_and_release_authorized'])

    def test_zero_revisions_cannot_be_counted_as_model_artifact_proof(self):
        suspicious = row(sha='0' * 40,
                         weight_files_observed=['model.safetensors'],
                         weight_state='weights-present',
                         artifact_state='artifact-present')
        report = self.evaluate(suspicious)
        self.assertEqual(report['status_counts'], {'UNKNOWN': 1})
        self.assertEqual(report['per_repository_private'][0]['model_revision'], None)
        self.assertEqual(report['training_verified_count'], 0)
        with self.assertRaisesRegex(ProofHold, 'SOURCE_REVISION_UNAVAILABLE'):
            evaluate(snap(row()), scope='public', source_revision='0' * 40)

    def test_duplicate_json_keys_fail_before_any_aggregate_stdout(self):
        import io
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'duplicate.json'
            source.write_text(
                '{"huggingface":{"organization":"SZLHOLDINGS",'
                '"assets":{"models":{"ok":false,"ok":true,'
                '"partial":false,"count":0,"items":[]}}}}',
                encoding='utf-8',
            )
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                exit_code = main([
                    '--snapshot', str(source), '--scope', 'public',
                    '--source-revision', SHA,
                ])
            self.assertEqual(exit_code, 78)
            self.assertIn('DUPLICATE_JSON_KEY', buffer.getvalue())
            self.assertNotIn('"repository_count"', buffer.getvalue())

    def test_actual_snapshot_read_rejects_oversized_input(self):
        import io
        from contextlib import redirect_stdout
        from tools.hf_model_proof_axes import MAX_INPUT_BYTES
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'oversized.json'
            # Does not require network or any real model content.
            with source.open('wb') as out:
                out.write(b'x' * (MAX_INPUT_BYTES + 2))
            capture = io.StringIO()
            with redirect_stdout(capture):
                code = main(['--snapshot', str(source), '--scope', 'public',
                             '--source-revision', SHA])
            self.assertEqual(code, 78)
            self.assertIn('SNAPSHOT_BYTE_BUDGET', capture.getvalue())

    def test_private_receipt_is_exclusive(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp) / 'snapshot.json', Path(tmp) / 'receipt.json'
            src.write_text(json.dumps(snap(row())), encoding='utf-8')
            args = ['--snapshot', str(src), '--source-revision', SHA,
                    '--scope', 'public', '--private-receipt', str(dst)]
            self.assertEqual(main(args), 0)
            preserved = dst.read_bytes()
            self.assertEqual(main(args), 78)
            self.assertEqual(dst.read_bytes(), preserved)


if __name__ == '__main__':
    unittest.main()
