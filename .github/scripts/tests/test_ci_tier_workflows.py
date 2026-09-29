import json,unittest
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[3]
def workflow(name):return yaml.safe_load((ROOT/'.github/workflows'/name).read_text())
class WorkflowTests(unittest.TestCase):
 def test_build_matrix_uses_single_snapshot(self):
  d=workflow('ci-builds.yml');self.assertIn('plan',d['jobs'])
  self.assertIn('needs.plan.outputs.matrix',str(d['jobs']['builds']['strategy']['matrix']))
  self.assertFalse(d['jobs']['builds']['strategy']['fail-fast'])
 def test_consumers_have_tier_identity(self):
  cat=json.loads((ROOT/'.github/ci-tier-consumers.json').read_text())
  for item in cat['consumers']:
   if item['job']=='tier-units':continue
   d=workflow(item['file']);j=d['jobs'][item['job']]
   with self.subTest(file=item['file'],job=item['job']):
    self.assertIn('tier-context',d['jobs'])
    self.assertIn('matrix.check_name',j.get('name',''))
    self.assertTrue(any('ci_tier_runtime.py restore' in s.get('run','') for s in j['steps']))
    self.assertFalse(any('repos/${REPO}/actions/artifacts?name=' in s.get('run','') for s in j['steps']))
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
