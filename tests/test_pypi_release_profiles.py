"""Canonical consumer security controls survive regeneration; no network or publishing."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'governance/pypi/canonical/gen_publish_workflow.py'
SPEC = importlib.util.spec_from_file_location('release_profiles', PATH)
gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gen)


class ReleaseProfileTests(unittest.TestCase):
    def test_default_canonical_is_unchanged(self):
        self.assertEqual(gen.render('PACKAGE=.:pypi'), (PATH.parent / 'publish-pypi.yml').read_text(encoding='utf-8'))

    def test_provctl_keeps_hashed_build_dependencies(self):
        text = gen.render('szl-provctl=.:pypi')
        self.assertIn('pip install --disable-pip-version-check --require-hashes -r requirements/ci/pypi-release.txt', text)
        self.assertNotIn('--upgrade', text)
        self.assertNotIn('CycloneDX', text)
        self.assertEqual(text.count('      - "requirements/ci/pypi-release.txt"'), 2)
        self.assertEqual(text.count('      - "requirements/ci/pypi-release.in"'), 2)

    def test_evidence_profile_requires_separate_sbom(self):
        text = gen.render('szl-evidence-mandate=.:pypi')
        self.assertIn('Generate CycloneDX SBOM', text)
        self.assertIn('python .github/scripts/szl_pypi_sbom.py generate', text)
        self.assertIn('          path: sbom/\n          if-no-files-found: error\n          retention-days: 90', text)
        self.assertEqual(text.count('      - ".github/scripts/szl_pypi_sbom.py"'), 2)
        dist = text.split('      - name: Upload distributions (release only)', 1)[1].split('      - name: Generate CycloneDX SBOM', 1)[0]
        self.assertIn('dist/*.whl', dist)
        self.assertIn('dist/*.tar.gz', dist)
        self.assertNotIn('sbom', dist)
        sbom = text.split('      - name: Generate CycloneDX SBOM', 1)[1].split('\n  publish:', 1)[0]
        self.assertNotIn('if:', sbom)
        self.assertNotIn('continue-on-error', sbom)

    def test_profiles_keep_publication_and_permission_guards(self):
        for name in gen.RELEASE_PROFILES:
            with self.subTest(name=name):
                text = gen.render(name + '=.:pypi')
                build, publish = text.split('\n  publish:', 1)
                self.assertIn('\npermissions: {}\n', build)
                self.assertNotIn('id-token:', build)
                self.assertIn("    if: github.event_name == 'release'", publish)
                self.assertIn('          attestations: true', publish)
                self.assertIn('          skip-existing: false', publish)
                self.assertIn('          verify-metadata: true', publish)
                self.assertEqual(text.count('id-token: write'), 1)
                self.assertNotIn('workflow_dispatch', text)
                self.assertNotIn('pull_request_target', text)

    def test_profile_uploads_follow_shared_pin(self):
        ref = 'actions/upload-artifact@' + 'a' * 40
        with patch.dict(gen.PINS, {'upload': (ref, 'v9.9.9')}):
            text = gen.render('szl-evidence-mandate=.:pypi')
            self.assertEqual(text.count('uses: ' + ref), 3)
            self.assertEqual(text.count('# actions/upload-artifact v9.9.9'), 3)

    def test_whitespace_cannot_disable_profile(self):
        for name in gen.RELEASE_PROFILES:
            self.assertIn('--require-hashes', gen.render('  ' + name + ' = . : pypi ; '))

    def test_profile_requires_admitted_layout_and_environment(self):
        for spec in ('szl-provctl=other:pypi', 'szl-provctl=.:other', 'szl-provctl=.:pypi;other=.:pypi', 'szl-evidence-mandate=other:pypi'):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                gen.render(spec)

    def test_changed_install_anchor_fails_generation(self):
        plain = gen.render('PACKAGE=.:pypi').replace('"build>=1.2"', '"build>=99"')
        with self.assertRaisesRegex(ValueError, 'build-tooling anchor'):
            gen.apply_release_profile(plain, gen.parse('szl-provctl=.:pypi'))

    def test_changed_trigger_anchor_fails_generation(self):
        plain = gen.render('PACKAGE=.:pypi').replace('      - ".github/scripts/szl_pypi_release_gate.py"\n', '', 1)
        with self.assertRaisesRegex(ValueError, 'trigger anchors'):
            gen.apply_release_profile(plain, gen.parse('szl-provctl=.:pypi'))

    def test_changed_publish_anchor_fails_generation(self):
        plain = gen.render('PACKAGE=.:pypi').replace('\n  publish:\n', '\n  renamed:\n')
        with self.assertRaisesRegex(ValueError, 'publish anchor'):
            gen.apply_release_profile(plain, gen.parse('szl-evidence-mandate=.:pypi'))


class ProfileContractNegativeTests(unittest.TestCase):
    def test_missing_sbom_upload_is_rejected_by_cross_consumer_pin_contract(self):
        from tests.test_pypi_canonical_generator import pin_contract_errors
        text = gen.render('szl-evidence-mandate=.:pypi')
        text = text.replace('      - name: Upload CycloneDX SBOM', '      - name: Wrong SBOM upload')
        self.assertTrue(pin_contract_errors(text, [('szl-evidence-mandate', 'pypi')]))

    def test_missing_hash_requirement_is_rejected_by_cross_consumer_contract(self):
        from tests.test_pypi_canonical_generator import release_contract_errors
        name = 'szl-provctl'
        text = gen.render(name + '=.:pypi').replace('--require-hashes ', '')
        errors = release_contract_errors(text, name + '=.:pypi', [(name, 'pypi')])
        self.assertTrue(any('hash-locked' in e for e in errors))

    def test_missing_sbom_generation_is_rejected_by_cross_consumer_contract(self):
        from tests.test_pypi_canonical_generator import release_contract_errors
        name = 'szl-evidence-mandate'
        text = gen.render(name + '=.:pypi').replace('      - name: Generate CycloneDX SBOM', '      - name: Omitted')
        errors = release_contract_errors(text, name + '=.:pypi', [(name, 'pypi')])
        self.assertTrue(any('SBOM contract missing' in e for e in errors))


if __name__ == '__main__':
    unittest.main()
