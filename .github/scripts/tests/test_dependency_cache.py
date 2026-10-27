"""Exercise the cache action boundary without network or dependency compilation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / '.github/actions/dependency-cache/cache.py'
FP = 'a' * 64
KEY = 'proxysql-deps-v1-openssl-' + FP
RELATIVE = '.cache/dependency-artifacts/bundles/openssl/' + FP


class DependencyCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'
        (self.source / 'deps/artifacts').mkdir(parents=True)
        (self.source / 'deps/artifacts/ci.py').write_text('# supported\n')
        (self.root / 'bin').mkdir()
        fake = self.root / 'bin/docker'
        fake.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['FIXTURE_ROOT'])
source = root / 'source'
args = sys.argv[1:]
with (root / 'calls.jsonl').open('a') as out:
 out.write(json.dumps({'args':args,'env':dict(os.environ)})+'\\n')
if 'dependency-artifact-keys' in args[-1]:
 target = source / '.cache/dependency-artifacts/ci-keys.json'
 target.parent.mkdir(parents=True,exist_ok=True)
 target.write_text((root/'keys.json').read_text())
else:
 cache = source / '.cache/dependency-artifacts/bundles/openssl' / ('a'*64)
 (root/'stale-observed').write_text(str((cache/'stale').exists()))
 cache.mkdir(parents=True,exist_ok=True)
 (cache/'entry.json').write_text(json.dumps({'dependency':'openssl','fingerprint':'a'*64}))
 (cache/'bundle.tar.gz').write_bytes(b'fixture bundle')
''')
        fake.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.root/'bin')+os.pathsep+os.environ['PATH'],
                        FIXTURE_ROOT=str(self.root), GITHUB_WORKSPACE=str(self.root), GITHUB_RUN_ID='424242',
                        GITHUB_OUTPUT=str(self.root/'outputs'), GH_TOKEN='must-not-reach-docker',
                        ACTIONS_RUNTIME_TOKEN='must-not-reach-docker',
                        AWS_SECRET_ACCESS_KEY='must-not-reach-docker',
                        OPENAI_API_KEY='must-not-reach-docker',
                        SSH_AUTH_SOCK='/sensitive/agent.sock')
        self.keys = {'openssl': {'eligible': True, 'fingerprint': FP, 'key': KEY, 'path': RELATIVE}}
        self.write_keys()

    def write_keys(self):
        (self.root/'keys.json').write_text(json.dumps(self.keys))

    def run_cache(self, command, **extra):
        env = dict(self.env, **extra)
        return subprocess.run([sys.executable, str(SCRIPT), command,
            '--source-path', 'source', '--service', 'ubuntu24_dbg_build',
            '--tier', 'v40', '--sanitizer', 'asan', '--coverage', 'true',
            '--dependencies', 'openssl'], cwd=self.root, env=env,
            capture_output=True, text=True)

    def test_keys_probe_actual_container_and_strip_credentials(self):
        result = self.run_cache('keys')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        outputs = dict(line.split('=',1) for line in (self.root/'outputs').read_text().splitlines())
        self.assertEqual(outputs['openssl-key'], KEY)
        self.assertEqual(outputs['openssl-path'], 'source/'+RELATIVE)
        call = json.loads((self.root/'calls.jsonl').read_text().splitlines()[0])
        self.assertIn('ubuntu24_dbg_build', call['args'])
        for setting in ['PROXYSQL40=1', 'WITHASAN=1', 'WITHGCOV=1',
                        'DEPS_ARTIFACT_RUN_ID=424242', 'DEPS_ARTIFACT_PROFILE=ubuntu24_dbg_build']:
            self.assertIn(setting, call['args'])
        for secret in ['GH_TOKEN','GITHUB_RUN_ID','ACTIONS_RUNTIME_TOKEN','AWS_SECRET_ACCESS_KEY','OPENAI_API_KEY','SSH_AUTH_SOCK']:
            self.assertTrue(secret not in call['env'], secret+' leaked into Docker environment')

    def test_untrusted_metadata_cannot_choose_cache_path_or_key(self):
        for field, value in [('path','../../outside'),('key','arbitrary-prefix'),('fingerprint','../bad')]:
            with self.subTest(field=field):
                original = self.keys['openssl'][field]
                self.keys['openssl'][field] = value
                self.write_keys()
                result = self.run_cache('keys')
                self.assertNotEqual(result.returncode, 0)
                self.keys['openssl'][field] = original

    def test_partial_or_wrong_cache_restore_is_deleted_before_prepare(self):
        self.assertEqual(self.run_cache('keys').returncode, 0)
        for hit, matched, want in [('false',KEY,'False'),('true','wrong-key','False'),('true',KEY,'True')]:
            with self.subTest(hit=hit, matched=matched):
                cache = self.source/RELATIVE
                cache.mkdir(parents=True,exist_ok=True)
                (cache/'stale').write_text('bad partial payload')
                result = self.run_cache('prepare', CACHE_DEPENDENCY='openssl', CACHE_HIT=hit,
                                        CACHE_MATCHED_KEY=matched, CACHE_REQUESTED_KEY=KEY)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertEqual((self.root/'stale-observed').read_text(), want)
                self.assertIn('ready=true', (self.root/'outputs').read_text())

    def test_legacy_product_source_skips_only_dependency_cache(self):
        (self.source/'deps/artifacts/ci.py').unlink()
        result = self.run_cache('keys')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('enabled=false', (self.root/'outputs').read_text())
        self.assertFalse((self.root/'calls.jsonl').exists())

    def test_action_never_saves_into_workflow_run_default_branch_scope(self):
        action = yaml.safe_load((ROOT/'.github/actions/dependency-cache/action.yml').read_text())
        restores = [s for s in action['runs']['steps'] if 'actions/cache/restore@' in s.get('uses','')]
        saves = [s for s in action['runs']['steps'] if 'actions/cache/save@' in s.get('uses','')]
        self.assertEqual(len(restores),2)
        self.assertEqual(len(saves),2)
        for step in restores:
            self.assertNotIn('restore-keys',step['with'])
        for step in saves:
            self.assertIn("github.event_name != 'workflow_run'",step['if'])
            self.assertIn('ready',step['if'])

    def test_publication_jobs_isolate_credentials_and_keep_candidate_artifacts_separate(self):
        workflow = yaml.safe_load((ROOT/'.github/workflows/ci-builds.yml').read_text())
        builds = workflow['jobs']['builds']
        self.assertEqual(builds['permissions']['contents'],'read')
        checkout = next(s for s in builds['steps'] if s.get('name')=='Checkout repository')
        self.assertFalse(checkout['with']['persist-credentials'])
        aggregate = workflow['jobs']['dependency-publication-plan']
        self.assertEqual(aggregate['permissions']['contents'],'read')
        download = next(s for s in aggregate['steps'] if 'actions/download-artifact@' in s.get('uses',''))
        self.assertFalse(download['with']['merge-multiple'])
        self.assertIn('github.run_attempt',download['with']['pattern'])
        publisher = workflow['jobs']['dependency-publication']
        self.assertEqual(publisher['permissions']['contents'],'write')
        self.assertIn('matrix.fingerprint',publisher['concurrency']['group'])
        self.assertFalse(publisher['concurrency']['cancel-in-progress'])
        self.assertIn('control_sha',aggregate['outputs'])
        for job in [aggregate,publisher]:
            for step in job['steps']:
                if 'actions/checkout@' in step.get('uses',''):
                    expected = 'v3.0' if job is aggregate else '${{ needs.dependency-publication-plan.outputs.control_sha }}'
                    self.assertEqual(step['with']['ref'],expected)
                    self.assertFalse(step['with']['persist-credentials'])


if __name__ == '__main__':
    unittest.main()
