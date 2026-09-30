import json,subprocess,sys,unittest
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[3]
def workflow(name):return yaml.safe_load((ROOT/'.github/workflows'/name).read_text())
class WorkflowTests(unittest.TestCase):
 def test_explicit_context_permissions_allow_stale_run_cancellation(self):
  for file in (ROOT/'.github/workflows').glob('*.yml'):
   doc=workflow(file.name)
   for job in doc.get('jobs',{}).values():
    if 'ci-tier-context.yml' not in job.get('uses',''):continue
    permissions=job.get('permissions',doc.get('permissions'))
    if isinstance(permissions,dict):
     with self.subTest(file=file.name):
      self.assertEqual(permissions.get('actions'),'write')
      self.assertEqual(permissions.get('pull-requests'),'read')
 def test_cancellation_never_executes_pr_code_or_waits_for_self_hosted(self):
  d=workflow('ci-cancel-superseded.yml');job=d['jobs']['cancel']
  self.assertEqual(d['permissions'],{'actions':'write','contents':'read','pull-requests':'read'})
  self.assertEqual(job['runs-on'],'ubuntu-24.04')
  self.assertEqual(job['if'],"github.event_name == 'pull_request_target'")
  checkout=job['steps'][0]
  self.assertEqual(checkout['with']['repository'],'sysown/proxysql')
  self.assertEqual(checkout['with']['ref'],'GH-Actions')
  self.assertFalse(checkout['with']['persist-credentials'])
  self.assertEqual(job['steps'][1]['run'],'python3 .github/scripts/ci_cancel_superseded.py')
 def test_plugin_handoff_contracts(self):
  for script in ['test-genai-plugin-handoff.py','test-runtime-handoff.py']:
   with self.subTest(script=script):
    result=subprocess.run([sys.executable,str(ROOT/'.github/scripts/tests'/script)],
                          cwd=ROOT,capture_output=True,text=True)
    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
 def test_build_matrix_uses_single_snapshot(self):
  d=workflow('ci-builds.yml');self.assertIn('plan',d['jobs'])
  self.assertIn('needs.plan.outputs.matrix',str(d['jobs']['builds']['strategy']['matrix']))
  self.assertFalse(d['jobs']['builds']['strategy']['fail-fast'])
 def test_consumers_have_tier_identity(self):
  cat=json.loads((ROOT/'.github/ci-tier-consumers.json').read_text())
  for item in cat['consumers']:
   d=workflow(item['file']);j=d['jobs'][item['job']]
   with self.subTest(file=item['file'],job=item['job']):
    self.assertIn('tier-context',d['jobs'])
    self.assertIn('matrix.check_name',j.get('name',''))
    if item.get('build_from_source'):
     build_name={'ci-codeql.yml':'Build C++','ci-maketest.yml':'Make-test'}.get(item['file'],'Build selected product inside Docker')
     build=next(s for s in j['steps'] if s.get('name')==build_name)
     self.assertRegex(build.get('run',''),r'(?m)^\s*make\s+')
     self.assertEqual(build['env']['PROXYSQL40'], "${{ matrix.tier == 'v40' && '1' || '' }}")
     self.assertEqual(build['env']['PROXYSQL31'], "${{ matrix.tier == 'v31' && '1' || '' }}")
    else:
     self.assertTrue(any('ci_tier_runtime.py restore' in s.get('run','') for s in j['steps']))
    self.assertFalse(any('repos/${REPO}/actions/artifacts?name=' in s.get('run','') for s in j['steps']))
 def test_no_producer_only_test_runner(self):
  self.assertNotIn('ci_tier_runtime.py units', (ROOT/'.github/workflows/ci-builds.yml').read_text())
  cat=json.loads((ROOT/'.github/ci-tier-consumers.json').read_text())
  self.assertFalse(any(row['job']=='tier-units' for row in cat['consumers']))
 def test_sanitizers_use_shared_consumers_for_every_tier(self):
  cat=json.loads((ROOT/'.github/ci-tier-consumers.json').read_text())
  for suffix,job in [('asan-coverage','unit-tests'),('tsan','unit-tests-tsan')]:
   rows=[r for r in cat['consumers'] if r['workflow']=='CI-unit-tests-'+suffix]
   self.assertEqual(len(rows),1)
   self.assertEqual(set(rows[0]['tiers']),{'v30','v31','v40'})
   self.assertTrue(rows[0]['automatic'])
   d=workflow(rows[0]['file']);j=d['jobs'][job]
   self.assertIn('needs.tier-context.outputs.matrices',str(j['strategy']))
   run=next(s['run'] for s in j['steps'] if s.get('name','').startswith('Run '))
   self.assertIn('docker compose run --rm',run)
   self.assertIn('ubuntu24_dbg_build',run)
   self.assertNotIn('matrix.tier',run)
   self.assertNotIn('TIER',run)
 def test_other_compiled_workflows_use_the_same_selected_tiers(self):
  cat=json.loads((ROOT/'.github/ci-tier-consumers.json').read_text())
  for name in ['CI-CodeQL']:
   rows=[r for r in cat['consumers'] if r['workflow']==name]
   self.assertEqual(len(rows),1)
   self.assertEqual(set(rows[0]['tiers']),{'v30','v31','v40'})
   self.assertTrue(rows[0]['automatic'])
 def test_maketest_is_not_planned_for_pull_requests(self):
  cat=json.loads((ROOT/'.github/ci-tier-consumers.json').read_text())
  self.assertFalse(any(row['workflow']=='CI-maketest' for row in cat['consumers']))
 def test_catalogue_does_not_choose_different_workflows_by_tier(self):
  cat=json.loads((ROOT/'.github/ci-tier-consumers.json').read_text())
  for row in cat['consumers']:
   with self.subTest(workflow=row['workflow']):
    self.assertEqual(set(row['tiers']),{'v30','v31','v40'})
 def test_specialty_trigger_unchanged(self):
  for file in ['ci-unit-group.yml','ci-ai-gcov.yml']:
   d=workflow(file);events=d.get('on',d.get(True,{}))
   self.assertNotIn('pull_request',events)
 def test_test_execution_is_independent_of_coverage(self):
  for file in (ROOT/'.github/workflows').glob('*.yml'):
   doc=workflow(file.name)
   for job in doc.get('jobs',{}).values():
    for step in job.get('steps',[]):
     if 'run-tests-isolated.bash' in step.get('run',''):
      with self.subTest(file=file.name):self.assertNotIn('matrix.coverage',str(step.get('if','')))
 def test_runner_picker_does_not_wait_on_its_target_pool(self):
  for file in (ROOT/'.github/workflows').glob('*.yml'):
   picker=workflow(file.name).get('jobs',{}).get('pick-runner')
   if picker:
    with self.subTest(file=file.name):self.assertNotIn('self-hosted',str(picker['runs-on']))
 def test_coverage_uses_tested_sha_and_infrastructure_path(self):
  for file in (ROOT/'.github/workflows').glob('*.yml'):
   for job in workflow(file.name).get('jobs',{}).values():
    if 'CI_BINDING' not in job.get('env',{}):continue
    for step in job.get('steps',[]):
     if 'codecov' in step.get('uses',''):
      with self.subTest(file=file.name):self.assertEqual(step.get('with',{}).get('override_commit'),'${{ env.SHA }}')
  text=(ROOT/'.github/workflows/ci-set_parser_algorithm_3-g1.yml').read_text()
  self.assertNotIn('ci_infra_logs/ci-set_parser_algorithm_3-g1/',text)

if __name__=='__main__':unittest.main()
