"""Publisher profile selection, batch completeness and immutable releases."""
import importlib
import json
import os
import shutil
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

    def test_registration_merges_verified_metadata_without_downloads(self):
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
        self.assertEqual([60, 60, 600, 60], [c[1].get('timeout') for c in run.call_args_list])
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

    def test_build_operations_have_distinct_bounded_timeouts(self):
        profile = self.api.build_matrix('ubuntu24-amd64-gcc', 'openssl')['include'][0]
        def respond(command, **kwargs):
            stdout = json.dumps({'services': {profile['service']: {'image': 'build:fixture'}}}) if command[:3] == ['docker', 'compose', 'config'] else 'build@sha256:fixture'
            return subprocess.CompletedProcess(command, 0, stdout, '')
        with patch.object(self.api, 'ROOT', self.root), \
                patch.object(self.api, 'profiles', return_value=[profile]), \
                patch.object(self.api.platform, 'machine', return_value='x86_64'), \
                patch.object(self.api.platform, 'system', return_value='Linux'), \
                patch.object(self.api.subprocess, 'run', side_effect=respond) as run, \
                patch.object(self.api.subprocess, 'check_call') as build:
            self.api.build_profile(profile['profile'], 'openssl', self.root / 'output',
                                   'sysown/proxysql', 'dependency-artifacts-v1-1-1')
        self.assertEqual([60, 600, 60], [call[1].get('timeout') for call in run.call_args_list])
        self.assertEqual(5400, build.call_args[1].get('timeout'))

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

    def test_external_command_timeout_terminates_the_command(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.api.run([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=0.05)

    def test_automatic_workflow_prepares_pr_and_reviewed_dependency_changes(self):
        import yaml
        workflow = yaml.safe_load((ROOT / '.github/workflows/CI-dependency-artifacts.yml').read_text())
        events = workflow.get('on', workflow.get(True))
        self.assertIn('pull_request', events)
        self.assertEqual(['v3.0'], events['push']['branches'])
        self.assertEqual(events['pull_request']['paths'], events['push']['paths'])
        for source in ('deps/libssl/**', 'deps/duckdb/**', 'deps/artifacts/**',
                       'common_mk/openssl_flags.mk', 'docker-compose.yml'):
            self.assertIn(source, events['pull_request']['paths'])
        plan = workflow['jobs']['plan']
        checkout = plan['steps'][0]['with']
        self.assertIn('github.event.pull_request.head.sha', checkout['ref'])
        self.assertFalse(checkout['persist-credentials'])
        planner = next(step for step in plan['steps'] if step.get('id') == 'matrix')
        self.assertEqual('profile-control', planner['working-directory'])
        trusted = next(step['with'] for step in plan['steps']
                       if step.get('with', {}).get('path') == 'profile-control')
        self.assertEqual('sysown/proxysql', trusted['repository'])
        self.assertEqual('refs/heads/v3.0', trusted['ref'])
        self.assertEqual('deps/artifacts', trusted['sparse-checkout'])
        self.assertFalse(trusted['persist-credentials'])
        self.assertIn('python3 -E deps/artifacts/publish.py matrix', planner['run'])
        self.assertIn('git -C ../source rev-parse HEAD', planner['run'])
        build = workflow['jobs']['build']
        action = next(step for step in build['steps'] if step.get('id') == 'dependencies')
        self.assertEqual('./ci-control/.github/actions/dependency-cache', action['uses'])
        control = next(step['with'] for step in build['steps']
                       if step.get('with', {}).get('path') == 'ci-control')
        self.assertRegex(control['ref'], r'^[0-9a-f]{40}$')
        self.assertEqual('.github/actions/dependency-cache', control['sparse-checkout'])
        self.assertFalse(control['persist-credentials'])
        self.assertEqual('${{ matrix.dependency }}', action['with']['dependencies'])
        self.assertEqual('${{ matrix.service || \'native\' }}', action['with']['service'])

    def test_prewarm_planner_never_executes_pr_source_or_uses_its_runners(self):
        import yaml
        workflow = yaml.safe_load((ROOT / '.github/workflows/CI-dependency-artifacts.yml').read_text())
        planner = next(step for step in workflow['jobs']['plan']['steps'] if step.get('id') == 'matrix')
        source = self.root / 'source'
        source.mkdir()
        (source / 'deps/artifacts').mkdir(parents=True)
        for name in ('deps/artifacts/publish.py', 'json.py'):
            (source / name).write_text('raise RuntimeError("PR code must not execute in planner")\n')
        (source / 'deps/artifacts/profiles.json').write_text(json.dumps({
            'profiles': [{'runner': ['self-hosted', 'proxysql-ci']}]}))
        for args in (('init', '-q'), ('add', '.'),
                     ('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                      'commit', '-qm', 'untrusted source')):
            subprocess.run(['git', '-C', str(source)] + list(args), check=True)
        control = self.root / 'profile-control'
        shutil.copytree(str(ROOT / 'deps/artifacts'), str(control / 'deps/artifacts'))
        output = self.root / 'output'
        environment = dict(os.environ, PROFILE_GROUP='ubuntu24', DEPENDENCY='both',
                           RUNNER_TEMP=str(self.root), GITHUB_OUTPUT=str(output), PYTHONPATH=str(source),
                           DISPATCH_EVENT='pull_request', DISPATCH_REF='refs/pull/1/merge')
        subprocess.run(['bash', '-e', '-c', planner['run']], cwd=str(control),
                       env=environment, check=True)
        values = dict(line.split('=', 1) for line in output.read_text().splitlines())
        matrix = json.loads(values['matrix'])['include']
        self.assertEqual(8, len(matrix))
        self.assertTrue(all(item['runner'] in ('ubuntu-24.04', 'ubuntu-24.04-arm') for item in matrix))
        self.assertEqual(subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'],
                                                universal_newlines=True).strip(), values['source_sha'])

    def test_protected_dispatch_rejects_unreviewed_source_before_planning_or_building(self):
        import yaml
        workflow = yaml.safe_load((ROOT / '.github/workflows/CI-dependency-artifacts.yml').read_text())
        plan = workflow['jobs']['plan']
        planner = next(step for step in plan['steps'] if step.get('id') == 'matrix')
        trusted = next(step['with'] for step in plan['steps']
                       if step.get('with', {}).get('path') == 'profile-control')
        self.assertEqual(0, trusted['fetch-depth'])
        source = self.root / 'source'
        source.mkdir()
        def git(root, *args):
            return subprocess.check_output(['git', '-C', str(root)] + list(args),
                                           stderr=subprocess.PIPE, universal_newlines=True).strip()
        def commit(root, message):
            git(root, 'add', '.')
            git(root, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                'commit', '-qm', message)
        git(source, 'init', '-q')
        (source / 'readme').write_text('reviewed source')
        commit(source, 'reviewed source')
        control = self.root / 'profile-control'
        subprocess.run(['git', 'clone', '-q', str(source), str(control)], check=True)
        shutil.copytree(str(ROOT / 'deps/artifacts'), str(control / 'deps/artifacts'))
        commit(control, 'reviewed planner')
        output = self.root / 'output'
        environment = dict(os.environ, PROFILE_GROUP='ubuntu24', DEPENDENCY='both',
                           RUNNER_TEMP=str(self.root), GITHUB_OUTPUT=str(output),
                           DISPATCH_EVENT='workflow_dispatch', DISPATCH_REF='refs/heads/v3.0')
        subprocess.run(['bash', '-e', '-c', planner['run']], cwd=str(control),
                       env=environment, check=True)
        self.assertTrue(output.exists())
        output.unlink()
        (self.root / 'dependency-matrix.json').unlink()
        (source / 'unreviewed').write_text('topic change')
        commit(source, 'unreviewed topic')
        result = subprocess.run(['bash', '-e', '-c', planner['run']], cwd=str(control),
                                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('requires source from reviewed history', result.stderr)
        self.assertFalse(output.exists())
        self.assertFalse((self.root / 'dependency-matrix.json').exists())

    def test_automatic_workflow_isolates_publisher_and_current_attempt_candidates(self):
        import yaml
        workflow = yaml.safe_load((ROOT / '.github/workflows/CI-dependency-artifacts.yml').read_text())
        self.assertEqual({'contents': 'read'}, workflow['permissions'])
        build = workflow['jobs']['build']
        self.assertNotIn('permissions', build)
        candidates = [step for step in build['steps'] if '/upload-artifact@' in step.get('uses', '')]
        self.assertEqual(2, len(candidates))
        for step in candidates:
            self.assertIn('dependency-candidate-a${{ github.run_attempt }}-', step['with']['name'])
            self.assertIn('/entry.json', step['with']['path'])
            self.assertIn('/bundle.tar.gz', step['with']['path'])
        publish = workflow['jobs']['publish']
        self.assertEqual(['plan', 'build'], publish['needs'])
        self.assertIn("github.event_name != 'pull_request'", publish['if'])
        self.assertIn("github.ref == 'refs/heads/v3.0'", publish['if'])
        self.assertIn('/ci-publish-dependency-cache.yml@', publish['uses'])
        self.assertEqual('${{ needs.plan.outputs.source_sha }}', publish['with']['source_sha'])
        self.assertEqual({'contents': 'write', 'actions': 'read'}, publish['permissions'])
        self.assertNotIn('secrets', publish)

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
