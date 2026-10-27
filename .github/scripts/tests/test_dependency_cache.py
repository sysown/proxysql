"""Check the shared cache boundary without compiling dependencies or using Docker."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('dependency_cache', ROOT / '.github/actions/dependency-cache/cache.py')
CACHE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CACHE)
FP = 'a' * 64
KEY = 'proxysql-deps-v1-openssl-' + FP
RELATIVE = '.cache/dependency-artifacts/bundles/openssl/' + FP


class DependencyCacheTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / 'source'
        (self.source / 'deps/artifacts').mkdir(parents=True)
        (self.source / 'deps/artifacts/ci.py').touch()
        self.metadata = self.source / '.cache/dependency-artifacts/ci-keys.json'
        self.metadata.parent.mkdir(parents=True)
        self.item = {'eligible': True, 'fingerprint': FP, 'key': 'untrusted', 'path': '../../untrusted'}
        self.write_keys()
        self.output = self.root / 'output'
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, GITHUB_WORKSPACE=str(self.root), GITHUB_OUTPUT=str(self.output),
                   GITHUB_RUN_ID='123', DEPS_BUILD_JOBS='2', GH_TOKEN='sensitive',
                   ACTIONS_RUNTIME_TOKEN='sensitive', AWS_SECRET_ACCESS_KEY='sensitive',
                   OPENAI_API_KEY='sensitive', SSH_AUTH_SOCK='/secret').start()

    def write_keys(self):
        self.metadata.write_text(json.dumps({'openssl': self.item}))

    def run_cache(self, command='keys', **options):
        arguments = ['cache.py', command, '--source-path', 'source', '--dependencies', 'openssl']
        for name, value in options.items():
            arguments += ['--' + name.replace('_', '-'), value]
        with patch.object(sys, 'argv', arguments):
            CACHE.main()

    def test_control_derives_paths_and_keys_from_fingerprint(self):
        with patch.object(CACHE, 'run_build', side_effect=lambda *args: self.write_keys()):
            self.run_cache()
        self.assertIn('openssl-key=' + KEY, self.output.read_text())
        self.assertIn('openssl-path=source/' + RELATIVE, self.output.read_text())
        for value in ['../bad', '', None]:
            self.item['fingerprint'] = value
            self.write_keys()
            with self.assertRaisesRegex(ValueError, 'fingerprint'):
                CACHE.load_keys(self.source, ['openssl'])

    def test_corrupt_metadata_fails_and_ineligible_uses_source(self):
        for data in ['[]', '{', '{"openssl": {}}']:
            self.metadata.write_text(data)
            with self.assertRaises(ValueError):
                CACHE.load_keys(self.source, ['openssl'])
        self.item = {'eligible': False}
        self.write_keys()
        with patch.dict(os.environ, CACHE_DEPENDENCY='openssl'), patch.object(CACHE, 'run_build') as build:
            self.run_cache('prepare')
        self.assertEqual(build.call_args.args[-1], ['openssl'])
        self.assertFalse(self.output.exists())

    def test_exact_hit_preserved_and_prefix_or_missed_restore_discarded(self):
        destination = self.source / RELATIVE
        for hit, matched, requested, preserved in [('true', KEY, KEY, True), ('false', KEY, KEY, False),
                ('true', KEY + '-prefix', KEY, False), ('true', KEY, 'wrong', False)]:
            destination.mkdir(parents=True, exist_ok=True)
            (destination / 'stale').touch()
            def prepare(*args):
                self.assertEqual((destination / 'stale').exists(), preserved)
                destination.mkdir(parents=True, exist_ok=True)
                (destination / 'entry.json').write_text(json.dumps({'dependency': 'openssl', 'fingerprint': FP}))
                (destination / 'bundle.tar.gz').write_bytes(b'bundle')
            with patch.dict(os.environ, CACHE_DEPENDENCY='openssl', CACHE_HIT=hit,
                            CACHE_MATCHED_KEY=matched, CACHE_REQUESTED_KEY=requested), patch.object(CACHE, 'run_build', prepare):
                self.run_cache('prepare')
            self.assertIn('ready=true', self.output.read_text())
        (destination / 'entry.json').write_text('[]')
        with patch.dict(os.environ, CACHE_DEPENDENCY='openssl', CACHE_HIT='true', CACHE_MATCHED_KEY=KEY,
                        CACHE_REQUESTED_KEY=KEY), patch.object(CACHE, 'run_build'), self.assertRaisesRegex(ValueError, 'identity'):
            self.run_cache('prepare')

    def test_actual_build_modes_and_credentials_filter_for_docker_and_native(self):
        for service, tier, sanitizer in [('ubuntu24_dbg_build', 'v31', 'tsan'), ('native', 'v40', 'asan')]:
            with patch.object(CACHE.subprocess, 'run', side_effect=lambda *args, **kwargs: self.write_keys()) as run:
                self.run_cache(service=service, tier=tier, sanitizer=sanitizer, coverage='true')
            command, environment = run.call_args.args[0], run.call_args.kwargs['env']
            for name in ['GH_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'AWS_SECRET_ACCESS_KEY', 'OPENAI_API_KEY', 'SSH_AUTH_SOCK']:
                self.assertNotIn(name, environment)
            expected = {'PROXYSQL40': str(int(tier == 'v40')), 'PROXYSQL31': str(int(tier == 'v31')),
                        'WITHTSAN': str(int(sanitizer == 'tsan')), 'WITHASAN': str(int(sanitizer == 'asan')),
                        'WITHGCOV': '1', 'DEPS_MODE': 'auto', 'DEPS_ARTIFACT_PROFILE': service}
            for name, value in expected.items():
                if service == 'native':
                    self.assertEqual(environment[name], value)
                else:
                    self.assertIn(name + '=' + value, command)
            self.assertIn('dependency-artifact-keys', ' '.join(command))
        for options in [{'service': 'invalid;command'}, {}]:
            with patch.dict(os.environ, DEPS_BUILD_JOBS='0'), patch.object(CACHE.subprocess, 'run') as run:
                with self.assertRaises(ValueError):
                    self.run_cache(**options)
                run.assert_not_called()

    def test_older_source_skips_only_cache_and_action_keeps_exact_restore_and_save(self):
        (self.source / 'deps/artifacts/ci.py').unlink()
        with patch.object(CACHE, 'run_build') as build:
            self.run_cache()
        build.assert_not_called()
        self.assertIn('enabled=false', self.output.read_text())
        action = yaml.safe_load((ROOT / '.github/actions/dependency-cache/action.yml').read_text())
        restores = [s for s in action['runs']['steps'] if 'actions/cache/restore@' in s.get('uses', '')]
        saves = [s for s in action['runs']['steps'] if 'actions/cache/save@' in s.get('uses', '')]
        self.assertEqual((len(restores), len(saves)), (2, 2))
        self.assertTrue(all('restore-keys' not in s['with'] for s in restores))
        for step in saves:
            for guard in ["inputs.cache-write == 'true'", "github.event_name != 'workflow_run'", "outputs.ready == 'true'"]:
                self.assertIn(guard, step['if'])
        workflow = yaml.safe_load((ROOT / '.github/workflows/ci-builds.yml').read_text())
        self.assertTrue(all('permissions' not in job for job in workflow['jobs'].values()))
        builds = workflow['jobs']['builds']['steps']
        for name in ['Verify vendored source archives', 'Build']:
            self.assertEqual(next(s for s in builds if s.get('name') == name)['if'], '${{ success() }}')


if __name__ == '__main__':
    unittest.main()
