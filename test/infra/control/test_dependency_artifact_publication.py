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

    def expected_matrix(self):
        (self.root / 'expected-matrix.json').write_text(json.dumps(
            {'include': [{'profile': 'ubuntu24-amd64-gcc', 'dependency': 'openssl'}]}))

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

    def test_registration_merges_entries_and_rejects_existing_keys(self):
        candidate = self.root / 'lock-entries.json'
        registry = self.root / 'registered.json'
        first = self.candidate()
        candidate.write_text(json.dumps({'format_version': 1, 'artifacts': [first]}))
        registry.write_text('{"format_version":1,"artifacts":[]}')
        self.api.register_entries(candidate, registry)
        second = self.candidate('ubuntu24-arm64-gcc')
        candidate.write_text(json.dumps({'format_version': 1, 'artifacts': [second]}))
        self.api.register_entries(candidate, registry)
        self.assertEqual(2, len(self.identity.load_registry(registry)['artifacts']))
        with self.assertRaisesRegex(ValueError, 'already registered'):
            self.api.register_entries(candidate, registry)
        self.assertEqual(2, len(self.identity.load_registry(registry)['artifacts']))

    def test_existing_release_is_never_changed(self):
        self.candidate()
        self.expected_matrix()
        with patch.object(self.api.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{}', '')) as run:
            with self.assertRaisesRegex(ValueError, 'exists'):
                self.api.publish_batch(self.root, 'sysown/proxysql', 'dependency-artifacts-v1-1-1', 'b' * 40)
        self.assertEqual(1, run.call_count)

    def test_publication_stages_then_publishes_without_clobber(self):
        self.candidate()
        self.expected_matrix()
        responses = [subprocess.CompletedProcess([], 1, '', 'HTTP 404'),
                     subprocess.CompletedProcess([], 0, '', '')]
        with patch.object(self.api.subprocess, 'run', side_effect=lambda *a, **k: responses.pop(0) if responses else subprocess.CompletedProcess([], 0, '', '')) as run:
            self.api.publish_batch(self.root, 'sysown/proxysql', 'dependency-artifacts-v1-1-1', 'b' * 40)
        commands = [call[0][0] for call in run.call_args_list]
        self.assertEqual(['api', 'release', 'release', 'release'], [c[1] for c in commands])
        self.assertEqual(['create', 'upload', 'edit'], [c[2] for c in commands[1:]])
        self.assertIn('--draft', commands[1])
        self.assertIn('--latest=false', commands[1])
        self.assertIn('--draft=false', commands[3])
        self.assertIn(str(self.root / 'ubuntu24-amd64-gcc-openssl.tar.gz'), commands[2])
        self.assertIn(str(self.root / 'lock-entries.json'), commands[2])
        self.assertFalse(any('--clobber' in c for c in commands))

    def test_publish_requires_plan_before_any_release_request(self):
        self.candidate()
        with patch.object(self.api.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'expected-matrix'):
                self.api.publish_batch(self.root, 'sysown/proxysql', 'dependency-artifacts-v1-1-1', 'b' * 40)
        self.assertFalse(run.called)

    def test_publish_rejects_nested_and_query_archive_urls(self):
        entry = self.candidate()
        self.expected_matrix()
        path = self.root / 'ubuntu24-amd64-gcc-openssl.entry.json'
        original = entry['url']
        for url in (original.rsplit('/', 1)[0] + '/nested/' + original.rsplit('/', 1)[1],
                    original + '?download=1'):
            entry['url'] = url
            path.write_text(json.dumps(entry))
            with self.subTest(url=url), patch.object(self.api.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'URL'):
                    self.api.publish_batch(self.root, 'sysown/proxysql', 'dependency-artifacts-v1-1-1', 'b' * 40)
                self.assertFalse(run.called)

    def test_publish_rejects_build_provenance_outside_trusted_source(self):
        self.candidate()
        self.expected_matrix()
        with patch.object(self.api.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'source commit'):
                self.api.publish_batch(self.root, 'sysown/proxysql', 'dependency-artifacts-v1-1-1',
                                       expected_source_sha='c' * 40)
        self.assertFalse(run.called)

    def test_upload_failure_keeps_release_as_draft(self):
        self.candidate()
        self.expected_matrix()
        responses = [subprocess.CompletedProcess([], 1, '', 'HTTP 404'),
                     subprocess.CompletedProcess([], 0, '', ''),
                     subprocess.CompletedProcess([], 1, '', 'upload failed')]
        with patch.object(self.api.subprocess, 'run', side_effect=responses) as run:
            with self.assertRaisesRegex(ValueError, 'upload failed'):
                self.api.publish_batch(self.root, 'sysown/proxysql', 'dependency-artifacts-v1-1-1', 'b' * 40)
        self.assertEqual(['create', 'upload'], [call[0][0][2] for call in run.call_args_list[1:]])

    def test_external_command_honors_requested_timeout(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.api.run([sys.executable, '-c', 'import time; time.sleep(2)'], timeout=0.05)

    def test_workflow_declares_reviewed_publication_guards(self):
        workflow = (ROOT / '.github/workflows/CI-dependency-artifacts.yml').read_text()
        for event in ('pull_request:', 'push:', 'workflow_dispatch:'):
            self.assertIn(event, workflow)
        self.assertEqual(1, workflow.count('contents: write'))
        plan = workflow.split('  plan:', 1)[1].split('  build:', 1)[0]
        self.assertIn('ref: refs/heads/v3.0', plan)
        self.assertIn('working-directory: profile-control', plan)
        self.assertIn('git merge-base --is-ancestor "$source_sha" HEAD', plan)
        self.assertIn('inputs.source_ref || github.event.pull_request.head.sha || github.sha', plan)
        for job in ('publication-plan', 'publish'):
            body = workflow.split('  ' + job + ':', 1)[1].split('\n  publish:', 1)[0]
            self.assertIn("github.ref == 'refs/heads/v3.0'", body)
            self.assertIn("github.event_name != 'pull_request'", body)
            self.assertIn('ref: ${{ needs.plan.outputs.control_sha }}', body)
            self.assertIn('--source-sha "$SOURCE_SHA"', body)
        self.assertIn('pattern: dependency-candidate-a${{ github.run_attempt }}-*', workflow)
        self.assertIn('dependency-publication-${{ matrix.dependency }}-${{ matrix.fingerprint }}', workflow)
        for action in re.findall(r'uses:\s*([^\s#]+)', workflow):
            if not action.startswith('./'):
                self.assertRegex(action, r'@[0-9a-f]{40}$')


if __name__ == '__main__':
    unittest.main()
