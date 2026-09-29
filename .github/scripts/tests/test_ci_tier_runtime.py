import contextlib,io,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch,Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import ci_tier_runtime as runtime
from ci_tier_plan import make_plan

class RuntimeTests(unittest.TestCase):
 def ctx(self):return dict(repository='sysown/proxysql',sha='a'*40,control_sha='b'*40,trigger_id=1,trigger_attempt=1,build_id=2,build_attempt=1,event='pull_request',pull_requests=[{'number':42}],variables={})
 def test_untrusted_plan_never_calls_api(self):
  with tempfile.TemporaryDirectory() as folder:
   prior=os.getcwd();os.chdir(folder)
   try:
    with patch.object(runtime,'context',return_value=self.ctx()),patch.object(runtime,'GitHubAPI') as api,patch.dict(os.environ,{'TRUSTED':'false','GITHUB_OUTPUT':str(Path(folder)/'out')}):
     runtime.plan_command();api.return_value.request.assert_not_called()
     plan=json.loads(Path('plan.json').read_text());self.assertEqual(plan['selection']['tiers'],['v40'])
   finally:os.chdir(prior)
 def test_large_plan_uses_artifact_not_environment(self):
  plan=make_plan(self.ctx(),dict(tiers=['v40'],mode='normal',pr_number=42),{'consumers':[]})
  binding={k:v for k,v in plan.items() if k in ['repository','sha','trigger_id','trigger_attempt','build_id','build_attempt','execution_id','control_sha']}
  with patch.dict(os.environ,{'CI_PLAN':json.dumps(binding)}),patch.object(runtime,'api_for') as api:
   api.return_value.json_artifact.return_value=plan
   self.assertEqual(runtime.read_plan(),plan)
   api.return_value.json_artifact.assert_called_once_with(2,'ci-plan-t1-a1-b2-a1','plan.json')
 def test_binary_metadata_uses_actual_version(self):
  with tempfile.TemporaryDirectory() as folder:
   prior=os.getcwd();os.chdir(folder)
   try:
    root=Path('proxysql');(root/'src').mkdir(parents=True);(root/'test/tap/groups').mkdir(parents=True)
    (root/'test/tap/groups/groups.json').write_text(json.dumps({'core-t':['g1'],'plugin-t':['g1','@proxysql_min_version:4.0.0']}))
    plan=make_plan(self.ctx(),dict(tiers=['v40','v30'],mode='normal',pr_number=42),{'consumers':[dict(workflow='CI-g1',file='ci-g1.yml',job='tests',automatic=True,tiers=['v30','v40'],groups=['g1'],cells=[{}])]})
    with patch.object(runtime,'read_plan',return_value=plan),patch.dict(os.environ,{'CI_LEG':json.dumps(plan['legs'][1])}),patch.object(runtime.subprocess,'check_output',return_value='ProxySQL version 3.0.12'):
     runtime.stamp()
     meta=json.loads((root/'src/ci-tier.json').read_text());self.assertTrue(all(meta['applicable'].values()))
   finally:os.chdir(prior)
 def test_failed_setup_does_not_wait_for_registration_forever(self):
  gh=dict(repository='sysown/proxysql',sha='a'*40,run_id='1',run_attempt='1',event={})
  api=Mock();api.request.return_value={'workflow_runs':[dict(display_title='branch CI-builds sha trigger=1/1',status='completed',conclusion='failure')]}
  with patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh)}),patch.object(runtime,'api_for',return_value=api),patch.object(runtime,'resolve_producer',side_effect=ValueError('missing')):
   with self.assertRaisesRegex(RuntimeError,'before publishing'):runtime.producer_lookup()

if __name__=='__main__':unittest.main()
