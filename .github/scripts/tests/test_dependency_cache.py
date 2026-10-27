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
 (root/'seed-observed').write_text((cache/'bundle.tar.gz').read_text() if (cache/'bundle.tar.gz').is_file() else '')
 cache.mkdir(parents=True,exist_ok=True)
 (cache/'entry.json').write_text(json.dumps({'dependency':'openssl','fingerprint':'a'*64}))
 (cache/'bundle.tar.gz').write_bytes(b'fixture bundle')
''')
        fake.chmod(0o755)
        native = self.root/'bin/make'
        native.write_text(fake.read_text())
        native.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.root/'bin')+os.pathsep+os.environ['PATH'],
                        FIXTURE_ROOT=str(self.root), GITHUB_WORKSPACE=str(self.root), GITHUB_RUN_ID='424242', DEPS_BUILD_JOBS='2',
                        GITHUB_OUTPUT=str(self.root/'outputs'), GH_TOKEN='must-not-reach-docker',
                        ACTIONS_RUNTIME_TOKEN='must-not-reach-docker',
                        AWS_SECRET_ACCESS_KEY='must-not-reach-docker',
                        OPENAI_API_KEY='must-not-reach-docker',
                        SSH_AUTH_SOCK='/sensitive/agent.sock')
        self.keys = {'openssl': {'eligible': True, 'fingerprint': FP, 'key': KEY, 'path': RELATIVE}}
        self.write_keys()

    def write_keys(self):
        (self.root/'keys.json').write_text(json.dumps(self.keys))

    def run_cache(self, command, service='ubuntu24_dbg_build', candidate_path='', **extra):
        env = dict(self.env, **extra)
        return subprocess.run([sys.executable, str(SCRIPT), command,
            '--source-path', 'source', '--service', service,
            '--tier', 'v40', '--sanitizer', 'asan', '--coverage', 'true',
            '--dependencies', 'openssl', '--candidate-path', candidate_path], cwd=self.root, env=env,
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

    def test_native_build_uses_host_keyfile_and_sanitized_make_environment(self):
        result = self.run_cache('keys',service='native')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        call = json.loads((self.root/'calls.jsonl').read_text().splitlines()[0])
        self.assertEqual(call['args'], ['--no-print-directory','--jobs=2','-C',str(self.source/'deps'),'NPROCS=2','dependency-artifact-keys'])
        self.assertEqual(call['env']['DEPS_ARTIFACT_KEYS_FILE'], str(self.source/'.cache/dependency-artifacts/ci-keys.json'))
        self.assertEqual(call['env']['DEPS_ARTIFACT_RUN_ID'],'424242')
        self.assertEqual(call['env']['DEPS_ARTIFACT_PROFILE'],'native')
        self.assertTrue('GH_TOKEN' not in call['env'])
        self.assertTrue('ACTIONS_RUNTIME_TOKEN' not in call['env'])

    def test_prepare_job_budget_is_explicit_and_invalid_values_never_start_builds(self):
        result=self.run_cache('keys',DEPS_BUILD_JOBS='3')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        call=json.loads((self.root/'calls.jsonl').read_text().splitlines()[0])
        self.assertIn('--jobs=3',call['args'][-1])
        self.assertIn('NPROCS=3',call['args'][-1])
        for invalid in ['0','-1','unbounded']:
            (self.root/'calls.jsonl').unlink(missing_ok=True)
            result=self.run_cache('keys',DEPS_BUILD_JOBS=invalid)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse((self.root/'calls.jsonl').exists())

    def test_only_protected_source_events_can_start_publication(self):
        shared=yaml.safe_load((ROOT/'.github/workflows/ci-publish-dependency-cache.yml').read_text())
        gate=shared['jobs']['dependency-publication-plan']['if']
        cases=[('push','refs/heads/v3.0','','',True),
               ('push','refs/heads/v3.1','','',False),
               ('workflow_dispatch','refs/heads/v3.0','','',True),
               ('workflow_dispatch','refs/heads/v4.0','','',False),
               ('workflow_run','refs/heads/default','v3.0','sysown/proxysql',True),
               ('workflow_run','refs/heads/default','v3.1','sysown/proxysql',False),
               ('workflow_run','refs/heads/default','v3.0','outside/fork',False),
               ('pull_request','refs/pull/1/merge','','',False)]
        import re
        for event,ref,branch,repository,want in cases:
            with self.subTest(event=event,ref=ref,branch=branch,repository=repository):
                facts={'inputs.enabled':True,'github.repository':'sysown/proxysql',
                       'github.event_name':event,'github.ref':ref,
                       'github.event.workflow_run.event':'push',
                       'github.event.workflow_run.head_branch':branch,
                       'github.event.workflow_run.head_repository.full_name':repository}
                expression=re.sub(r'\b(?:github|inputs)(?:\.[a-z_]+)+',lambda m:repr(facts[m[0]]),gate[3:-2])
                expression=expression.replace('&&',' and ').replace('||',' or ')
                self.assertEqual(eval(expression,{'__builtins__':{}},{}),want)

    def test_untrusted_metadata_cannot_choose_cache_path_or_key(self):
        for field, value in [('path','../../outside'),('key','arbitrary-prefix'),('fingerprint','../bad')]:
            with self.subTest(field=field):
                original = self.keys['openssl'][field]
                self.keys['openssl'][field] = value
                self.write_keys()
                result = self.run_cache('keys')
                self.assertNotEqual(result.returncode, 0)
                error = ('invalid dependency fingerprint' if field == 'fingerprint' else
                         'dependency key/path does not match fingerprint')
                self.assertEqual(result.stderr.strip(), 'Dependency cache failed: ' + error)
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

    def test_producer_bundle_seeds_exact_identity_after_cache_miss(self):
        self.assertEqual(self.run_cache('keys').returncode,0)
        candidates=self.root/'producer/dependency-candidate-a1-v40-normal-openssl'
        candidates.mkdir(parents=True)
        (candidates/'entry.json').write_text(json.dumps({'dependency':'openssl','fingerprint':FP}))
        (candidates/'bundle.tar.gz').write_text('accepted producer bundle')
        result=self.run_cache('prepare',candidate_path='producer', CACHE_DEPENDENCY='openssl',
                              CACHE_HIT='false',CACHE_MATCHED_KEY='',CACHE_REQUESTED_KEY=KEY)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual((self.root/'seed-observed').read_text(),'accepted producer bundle')

    def test_nonobject_producer_metadata_fails_cleanly_without_rebuilding(self):
        self.assertEqual(self.run_cache('keys').returncode, 0)
        candidates = self.root/'producer/dependency-candidate-a1-v40-normal-openssl'
        candidates.mkdir(parents=True)
        (candidates/'bundle.tar.gz').write_text('accepted producer bundle')
        for entry in [[], None, 'metadata', 42, True]:
            with self.subTest(entry=entry):
                (candidates/'entry.json').write_text(json.dumps(entry))
                (self.root/'calls.jsonl').unlink(missing_ok=True)
                result = self.run_cache('prepare', candidate_path='producer', CACHE_DEPENDENCY='openssl',
                                        CACHE_HIT='false', CACHE_MATCHED_KEY='', CACHE_REQUESTED_KEY=KEY)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr.strip(),
                                 'Dependency cache failed: producer candidate metadata must be a JSON object')
                self.assertFalse((self.root/'calls.jsonl').exists())
                self.assertFalse((self.source/RELATIVE).exists())

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

    def test_cache_write_opt_out_preserves_restores_and_preparation(self):
        import re
        action = yaml.safe_load((ROOT/'.github/actions/dependency-cache/action.yml').read_text())
        steps = action['runs']['steps']
        restores = [step for step in steps if 'actions/cache/restore@' in step.get('uses', '')]
        saves = [step for step in steps if 'actions/cache/save@' in step.get('uses', '')]
        prepares = [step for step in steps if step.get('id', '').startswith('prepare-')]
        self.assertEqual(len(restores), 2)
        self.assertEqual(len(saves), 2)
        self.assertEqual(len(prepares), 2)
        facts = {'github.event_name': 'workflow_dispatch'}
        for dependency in ['openssl', 'duckdb']:
            facts.update({'steps.keys.outputs.'+dependency+'-key': 'requested-'+dependency,
                          'steps.keys.outputs.selected-'+dependency: 'true',
                          'steps.prepare-'+dependency+'.outputs.ready': 'true',
                          'steps.'+dependency+'.outputs.cache-hit': 'false',
                          'steps.'+dependency+'.outputs.cache-matched-key': ''})
        def enabled(step, value):
            values = dict(facts, **{'inputs.cache-write': value})
            expression = re.sub(r'\b(?:steps|github|inputs)(?:\.[a-z_-]+)+',
                                lambda match: repr(values[match[0]]), step['if'][3:-2])
            expression = expression.replace('success()', 'True').replace('&&', ' and ').replace('||', ' or ')
            return eval(expression, {'__builtins__': {}}, {})
        for value, want_save in [('true', True), ('false', False), ('', False), ('1', False), ('invalid', False)]:
            with self.subTest(cache_write=value):
                self.assertTrue(all(enabled(step, value) for step in restores+prepares))
                self.assertEqual([enabled(step, value) for step in saves], [want_save, want_save])
        facts['github.event_name'] = 'workflow_run'
        self.assertFalse(any(enabled(step, 'true') for step in saves))
        self.assertEqual(action['inputs'].get('cache-write', {}).get('default'), 'true')

    def test_publication_jobs_isolate_credentials_and_keep_candidate_artifacts_separate(self):
        workflow = yaml.safe_load((ROOT/'.github/workflows/ci-builds.yml').read_text())
        builds = workflow['jobs']['builds']
        self.assertEqual(builds['permissions']['contents'],'read')
        checkout = next(s for s in builds['steps'] if s.get('name')=='Checkout repository')
        self.assertFalse(checkout['with']['persist-credentials'])
        shared = yaml.safe_load((ROOT/'.github/workflows/ci-publish-dependency-cache.yml').read_text())
        self.assertEqual(workflow['jobs']['dependency-publication']['uses'],'./.github/workflows/ci-publish-dependency-cache.yml')
        aggregate = shared['jobs']['dependency-publication-plan']
        self.assertEqual(aggregate['permissions']['contents'],'read')
        download = next(s for s in aggregate['steps'] if 'actions/download-artifact@' in s.get('uses',''))
        self.assertFalse(download['with']['merge-multiple'])
        self.assertIn('github.run_attempt',download['with']['pattern'])
        publisher = shared['jobs']['dependency-publication']
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


    def test_active_source_builders_cache_before_build_and_publish_from_fresh_jobs(self):
        cases = [('ci-unit-tests-asan-coverage.yml','unit-tests','asan','true'),
                 ('ci-unit-tests-tsan.yml','unit-tests-tsan','tsan','false'),
                 ('ci-package-build.yml','build','none','false')]
        for name,job_name,sanitizer,coverage in cases:
            with self.subTest(workflow=name):
                doc=yaml.safe_load((ROOT/'.github/workflows'/name).read_text())
                job=doc['jobs'][job_name]
                cache=next(s for s in job['steps'] if s.get('id')=='dependencies')
                self.assertEqual(cache['with']['sanitizer'],sanitizer)
                self.assertEqual(cache['with']['coverage'],coverage)
                cache_index=job['steps'].index(cache)
                build_index=next(i for i,s in enumerate(job['steps']) if s.get('name') in
                                 ('Build selected product inside Docker','Build package','Build ProxySQL'))
                self.assertLess(cache_index,build_index)
                candidates=[s for s in job['steps'] if s.get('name','').startswith('Retain ') and 'dependency publication candidate' in s['name']]
                self.assertEqual(len(candidates),2)
                self.assertTrue(all(s['with'].get('include-hidden-files') is True for s in candidates))
                self.assertEqual(doc['jobs']['dependency-publication']['uses'],'./.github/workflows/ci-publish-dependency-cache.yml')
                self.assertEqual(doc['jobs']['dependency-publication']['permissions']['contents'],'write')
                self.assertEqual(job['permissions']['contents'],'read')



    def test_sanitizer_candidates_publish_independently_after_unrelated_failures(self):
        import re
        for name, job_name in [('ci-unit-tests-asan-coverage.yml', 'unit-tests'),
                               ('ci-unit-tests-tsan.yml', 'unit-tests-tsan')]:
            with self.subTest(workflow=name):
                doc = yaml.safe_load((ROOT/'.github/workflows'/name).read_text())
                job = doc['jobs'][job_name]
                steps = job['steps']
                build_index = next(i for i, step in enumerate(steps)
                                   if step.get('name') == 'Build selected product inside Docker')
                candidates = [step for step in steps if step.get('name', '').startswith('Retain ')
                              and 'dependency publication candidate' in step['name']]
                for step in candidates:
                    self.assertLess(steps.index(step), build_index)
                publisher = doc['jobs']['dependency-publication']
                for context, result, cancelled, want in [
                        ('success', 'success', False, True),
                        ('success', 'failure', False, True),
                        ('failure', 'failure', False, False),
                        ('success', 'skipped', False, False),
                        ('success', 'cancelled', False, False),
                        ('success', 'success', True, False)]:
                    facts = {'needs.tier-context.result': context, 'needs.'+job_name+'.result': result}
                    expression = re.sub(r'needs\.[a-z-]+\.result', lambda m: repr(facts[m[0]]),
                                        publisher['if'][3:-2])
                    expression = expression.replace('always()', 'True').replace('!cancelled()', str(not cancelled))
                    expression = expression.replace('&&', ' and ').replace('||', ' or ')
                    self.assertEqual(eval(expression, {'__builtins__': {}}, {}), want)

    def test_fork_snapshot_cannot_widen_contents_read_or_skip_actual_build(self):
        normal=yaml.safe_load((ROOT/'.github/workflows/ci-builds.yml').read_text())
        fork=yaml.safe_load((ROOT/'.github/workflows/ci-builds-untrusted.yml').read_text())
        events=fork.get('on',fork.get(True))
        self.assertFalse(events['workflow_call']['inputs']['trusted']['default'])
        self.assertEqual(fork['permissions'],{'contents':'read'})
        self.assertNotIn('dependency-publication',fork['jobs'])
        for job in fork['jobs'].values():
            self.assertNotIn('permissions',job)
            self.assertNotIn('uses',job)
        for name in ['Verify vendored source archives','Configure product build',
                     'Restore or build exact dependency bundles','Build']:
            primary=next(s for s in normal['jobs']['builds']['steps'] if s.get('name')==name)
            isolated=next(s for s in fork['jobs']['builds']['steps'] if s.get('name')==name)
            self.assertEqual(primary,isolated)
        planner=next(s for s in fork['jobs']['plan']['steps'] if s.get('id')=='plan')
        self.assertEqual(planner['env']['TRUSTED'],'${{ false }}')

    def test_package_upload_never_checks_out_or_executes_product_source(self):
        doc=yaml.safe_load((ROOT/'.github/workflows/ci-package-build.yml').read_text())
        build=doc['jobs']['build']
        self.assertEqual(build['permissions']['contents'],'read')
        self.assertFalse(any(s.get('name')=='Push packages' for s in build['steps']))
        upload=doc['jobs']['upload']
        self.assertEqual(upload['strategy'],build['strategy'])
        self.assertEqual(upload['permissions']['contents'],'write')
        self.assertFalse(any('checkout@' in s.get('uses','') for s in upload['steps']))
        self.assertEqual(upload['steps'][0]['with']['name'],
                         'package-${{ matrix.arch }}-${{ matrix.dist }}${{ matrix.type }}')
        self.assertIn('upload',doc['jobs']['finalize']['needs'])
        self.assertIn('build',doc['jobs']['finalize']['needs'])



    def test_package_artifact_identity_survives_retained_build_attempts(self):
        doc=yaml.safe_load((ROOT/'.github/workflows/ci-package-build.yml').read_text())
        retain=next(s for s in doc['jobs']['build']['steps'] if s.get('name')=='Retain package for isolated upload')
        download=next(s for s in doc['jobs']['upload']['steps'] if s.get('name')=="Download this matrix leg's package")
        def resolve(template,attempt):
            for context,value in [('matrix.arch','amd64'),('matrix.dist','ubuntu24'),
                                  ('matrix.type','-dbg'),('github.run_attempt',str(attempt))]:
                template=template.replace('${{ '+context+' }}',value)
            return template
        retained={resolve(retain['with']['name'],1):'successful first-attempt package'}
        self.assertEqual(retained.get(resolve(download['with']['name'],2)),'successful first-attempt package')
        self.assertTrue(retain['with']['overwrite'])
        self.assertEqual(resolve(retain['with']['name'],1),resolve(retain['with']['name'],2))
        self.assertGreaterEqual(retain['with']['retention-days'],30)

    def test_successful_packages_upload_after_other_leg_fails_but_missing_package_blocks_final_success(self):
        doc=yaml.safe_load((ROOT/'.github/workflows/ci-package-build.yml').read_text())
        upload=doc['jobs']['upload']
        import re
        for build_result,cancelled,want in [('failure',False,True),('success',False,True),
                                            ('cancelled',False,False),('success',True,False)]:
            facts={'needs.clean.result':'success','needs.select.result':'success','needs.build.result':build_result}
            expression=re.sub(r'\bneeds(?:\.[a-z_]+)+',lambda m:repr(facts[m[0]]),upload['if'][3:-2])
            expression=expression.replace('always()','True').replace('!cancelled()',str(not cancelled))
            expression=expression.replace('&&',' and ').replace('||',' or ')
            self.assertEqual(eval(expression,{'__builtins__':{}},{}),want)
        download=next(s for s in upload['steps'] if s.get('id')=='package')
        self.assertTrue(download['continue-on-error'])
        push=next(s for s in upload['steps'] if s.get('name')=='Push package without executing source code')
        self.assertEqual(push['if'],"${{ steps.package.outcome == 'success' }}")
        require=next(s for s in upload['steps'] if s.get('name')=='Require package artifact after successful builds')
        self.assertEqual(require['if'],"${{ needs.build.result == 'success' }}")
        for outcome,want in [('success',0),('failure',1),('skipped',1)]:
            result=subprocess.run(['bash','-e','-c',require['run']],env=dict(os.environ,DOWNLOAD_OUTCOME=outcome))
            self.assertEqual(result.returncode,want)



if __name__ == '__main__':
    unittest.main()
