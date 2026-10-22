"""Publisher profile selection, batch completeness and immutable releases."""
import importlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_dependency_artifact_bundles import fixture_identity

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'deps/artifacts'))


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('publish')
        self.identity = importlib.import_module('identity')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def candidate(self, profile='ubuntu24-amd64-gcc', dep='openssl'):
        identity = fixture_identity(dep)
        identity['profile'] = profile
        archive = self.root / (profile + '-' + dep + '.tar.gz')
        archive.write_bytes(b'archive')
        entry = {'dependency': dep, 'identity': identity,
                 'fingerprint': self.identity.fingerprint(identity),
                 'sha256': self.identity.digest_file(archive), 'size': archive.stat().st_size,
                 'url': 'https://github.com/sysown/proxysql/releases/download/dependency-artifacts-v1-1-1/' + archive.name,
                 'provenance': {'commit': 'b' * 40, 'profile': profile}}
        (self.root / (profile + '-' + dep + '.entry.json')).write_text(json.dumps(entry))
        return entry

    def test_profile_matrix_uses_real_services_and_native_architectures(self):
        matrix = self.api.build_matrix('all', 'both')
        self.assertEqual(18, len(matrix['include']))
        for profile in matrix['include']:
            if profile['system'] == 'Linux':
                self.assertIn(profile['service'] + ':', (ROOT / 'docker-compose.yml').read_text())
                self.assertEqual(profile['arch'] == 'arm64', profile['runner'].endswith('-arm'))
            else:
                self.assertEqual(('macos-14', 'arm64'), (profile['runner'], profile['arch']))
        self.assertEqual(4, len(self.api.build_matrix('ubuntu24', 'openssl')['include']))
        for group in ('missing', 'ubuntu24;bad'):
            with self.assertRaises(ValueError):
                self.api.build_matrix(group, 'both')

    def test_merge_requires_exact_selected_batch(self):
        entry = self.candidate()
        matrix = {'include': [{'profile': 'ubuntu24-amd64-gcc', 'dependency': 'openssl'}]}
        (self.root / 'expected-matrix.json').write_text(json.dumps(matrix))
        result = self.api.merge_entries(self.root)
        self.assertEqual([entry], result['artifacts'])
        matrix['include'].append({'profile': 'ubuntu24-arm64-gcc', 'dependency': 'openssl'})
        (self.root / 'expected-matrix.json').write_text(json.dumps(matrix))
        with self.assertRaisesRegex(ValueError, 'batch'):
            self.api.merge_entries(self.root)

    def test_merge_rejects_duplicates_and_damaged_archives(self):
        entry = self.candidate()
        duplicate = self.root / 'duplicate.entry.json'
        duplicate.write_text(json.dumps(entry))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.api.merge_entries(self.root)
        duplicate.unlink()
        (self.root / 'ubuntu24-amd64-gcc-openssl.tar.gz').write_bytes(b'bad')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.api.merge_entries(self.root)

    def test_existing_release_is_never_changed(self):
        self.candidate()
        with patch.object(self.api.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{}', '')) as run:
            with self.assertRaisesRegex(ValueError, 'exists'):
                self.api.publish_batch(self.root, 'sysown/proxysql', 'dependency-artifacts-v1-1-1')
        self.assertEqual(1, run.call_count)

    def test_publication_stages_then_publishes_without_clobber(self):
        self.candidate()
        responses = [subprocess.CompletedProcess([], 1, '', 'HTTP 404'),
                     subprocess.CompletedProcess([], 0, '', '')]
        with patch.object(self.api.subprocess, 'run', side_effect=lambda *a, **k: responses.pop(0) if responses else subprocess.CompletedProcess([], 0, '', '')) as run:
            self.api.publish_batch(self.root, 'sysown/proxysql', 'dependency-artifacts-v1-1-1')
        commands = [call.args[0] for call in run.call_args_list]
        self.assertTrue(any('create' in c and '--draft' in c and '--latest=false' in c for c in commands))
        self.assertTrue(any('edit' in c and '--draft=false' in c for c in commands))
        self.assertFalse(any('--clobber' in c for c in commands))

    def test_workflow_publication_permissions_and_dependencies(self):
        workflow = (ROOT / '.github/workflows/CI-dependency-artifacts.yml').read_text()
        self.assertIn('workflow_dispatch:', workflow)
        self.assertNotRegex(workflow, r'(?m)^  (pull_request|push|workflow_run):')
        self.assertEqual(1, workflow.count('contents: write'))
        self.assertIn('needs: [plan, build]', workflow)
        self.assertIn('fetch-depth: 0', workflow)
        for action in re.findall(r'uses:\s*([^\s#]+)', workflow):
            self.assertRegex(action, r'@[0-9a-f]{40}$')
        self.assertIn('- DEPS_MODE', (ROOT / 'docker-compose.yml').read_text())
        checks = (ROOT / '.github/workflows/CI-dependency-artifacts-checks.yml').read_text()
        self.assertIn('source-validation:', checks)
        self.assertIn('test_dependency_artifact_', checks)

    def test_workflow_does_not_mix_artifacts_from_different_attempts(self):
        workflow = (ROOT / '.github/workflows/CI-dependency-artifacts.yml').read_text()
        self.assertIn('name: dependency-plan-${{ github.run_attempt }}', workflow)
        self.assertIn('pattern: dependency-bundle-${{ github.run_attempt }}-*', workflow)

    def test_build_script_restores_before_runtime_smoke(self):
        script = (ROOT / 'deps/artifacts/build.bash').read_text()
        self.assertLess(script.index('DEPS_MODE=source'), script.index('manage.py" package'))
        self.assertLess(script.index('restore_bundle'), script.index('dependency-artifacts-smoke.bash'))
        smoke = (ROOT / 'test/infra/control/dependency-artifacts-smoke.bash').read_text()
        self.assertIn('duckdb_query', smoke)
        self.assertIn('TLS_method()', smoke)
        self.assertIn('OPENSSL_VERSION_NUMBER', smoke)


if __name__ == '__main__':
    unittest.main()
