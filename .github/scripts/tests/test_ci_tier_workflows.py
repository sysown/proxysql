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
if __name__=='__main__':unittest.main()
