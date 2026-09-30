import contextlib,io,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch,Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import ci_tier_runtime as runtime
from ci_tier_plan import make_plan

class RuntimeTests(unittest.TestCase):
 def ctx(self):return dict(repository='sysown/proxysql',sha='a'*40,control_sha='b'*40,trigger_id=1,trigger_attempt=1,build_id=2,build_attempt=1,event='pull_request',pull_requests=[{'number':42}],variables={})
 def test_failed_producer_marks_unrun_units_and_consumers_skipped(self):
  plan={'repository':'sysown/proxysql','checks':[
   dict(check_id=1,workflow='CI-builds',job='builds'),
   dict(check_id=2,workflow='CI-unit-tests-tsan',job='unit-tests-tsan'),
   dict(check_id=3,workflow='CI-tests',job='tests')]}
  api=Mock();api.request.return_value={'status':'queued'}
  with patch.object(runtime,'read_plan',return_value=plan),patch.object(runtime,'api_for',return_value=api),patch.object(runtime,'reconcile'),patch.dict(os.environ,{'BUILD_RESULT':'failure'}):
   with self.assertRaisesRegex(RuntimeError,'required producer job failed'):runtime.finalize()
  writes=[call.args[2] for call in api.request.call_args_list if len(call.args)>1 and call.args[1]=='PATCH']
  self.assertEqual([p['conclusion'] for p in writes],['failure','skipped','skipped'])

 def test_failed_producer_does_not_call_started_units_blocked(self):
  plan={'repository':'sysown/proxysql','checks':[dict(check_id=1,workflow='CI-unit-tests-tsan',job='unit-tests-tsan')]}
  api=Mock();api.request.return_value={'status':'in_progress'}
  with patch.object(runtime,'read_plan',return_value=plan),patch.object(runtime,'api_for',return_value=api),patch.object(runtime,'reconcile'),patch.dict(os.environ,{'BUILD_RESULT':'failure'}):
   with self.assertRaisesRegex(RuntimeError,'required producer job failed'):runtime.finalize()
  self.assertEqual(api.request.call_args.args[2]['conclusion'],'failure')
  self.assertNotIn('blocked',api.request.call_args.args[2]['output']['summary'])

 def test_standalone_selection_snapshots_labels_and_reuses_them_on_rerun(self):
  gh=dict(repository='sysown/proxysql',sha='a'*40,run_id='9',run_attempt='1',event_name='pull_request',event={'pull_request':{'number':42}})
  api=Mock();api.request.return_value={'labels':[{'name':'ci:v3.0'},{'name':'ci:v3.1'}]}
  with tempfile.TemporaryDirectory() as folder:
   prior=os.getcwd();os.chdir(folder)
   try:
    with patch.object(runtime,'GitHubAPI',return_value=api),patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh),'GITHUB_OUTPUT':str(Path(folder)/'out')}):
     self.assertTrue(hasattr(runtime,'standalone_selection'))
     runtime.standalone_selection()
     snapshot=json.loads(Path('selection.json').read_text())
     self.assertEqual(snapshot['selection']['tiers'],['v40','v30','v31'])
    gh['run_attempt']='2';api.reset_mock();api.json_artifact.return_value=snapshot
    with patch.object(runtime,'GitHubAPI',return_value=api),patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh),'GITHUB_OUTPUT':str(Path(folder)/'out')}):
     runtime.standalone_selection();api.request.assert_not_called()
     self.assertEqual(json.loads(Path('selection.json').read_text()),snapshot)
     api.json_artifact.assert_called_once_with(9,'ci-tier-selection','selection.json')
   finally:os.chdir(prior)
 def test_standalone_rerun_rejects_a_foreign_snapshot(self):
  gh=dict(repository='sysown/proxysql',sha='a'*40,run_id='9',run_attempt='2')
  api=Mock();api.json_artifact.return_value=dict(repository='sysown/proxysql',sha='b'*40,run_id=9,selection={'tiers':['v40'],'mode':'normal'})
  with patch.object(runtime,'GitHubAPI',return_value=api),patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh)}):
   self.assertTrue(hasattr(runtime,'standalone_selection'))
   with self.assertRaisesRegex(ValueError,'selection identity mismatch'):runtime.standalone_selection()
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
    with patch.object(runtime,'read_plan',return_value=plan),patch.dict(os.environ,{'CI_LEG':json.dumps(plan['legs'][1])}),patch.object(runtime,'binary_version',return_value='ProxySQL version 3.0.12'):
     runtime.stamp()
     meta=json.loads((root/'src/ci-tier.json').read_text());self.assertTrue(all(meta['applicable'].values()))
   finally:os.chdir(prior)
 def test_failed_setup_does_not_wait_for_registration_forever(self):
  gh=dict(repository='sysown/proxysql',sha='a'*40,run_id='1',run_attempt='1',event={})
  api=Mock();api.request.return_value={'workflow_runs':[dict(display_title='branch CI-builds sha trigger=1/1',status='completed',conclusion='failure')]}
  with patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh)}),patch.object(runtime,'api_for',return_value=api),patch.object(runtime,'resolve_producer',side_effect=ValueError('missing')):
   with self.assertRaisesRegex(RuntimeError,'before publishing'):runtime.producer_lookup()

 def test_legacy_multi_instance_caller_matches_its_original_cells(self):
  plan=make_plan(self.ctx(),dict(tiers=['v40'],mode='normal'),{'consumers':[
   dict(workflow='CI-3p',job='test',automatic=True,instance='run-'+db,tiers=['v40'],groups=[],cells=[dict(infradb=db)]) for db in ['mysql','mariadb']]})
  self.assertEqual(runtime.consumer_instance(plan,'CI-3p','run',{'infradb':"['mariadb']"}),'run-mariadb')
  with self.assertRaisesRegex(ValueError,'ambiguous'):
   runtime.consumer_instance(plan,'CI-3p','run',{})
 def test_source_artifact_token_is_separate_from_reporting_token(self):
  with patch.dict(os.environ,{'SOURCE_ARTIFACTS_TOKEN':'fixture-read-token'}),patch.object(runtime,'GitHubAPI') as api:
   runtime.api_for(self.ctx())
   api.assert_called_once_with('sysown/proxysql',token='fixture-read-token')

 def test_delayed_consumers_use_trigger_acceptance_not_mutable_registration(self):
  plan=make_plan(self.ctx(),dict(tiers=['v40'],mode='normal'),{'consumers':[
   dict(workflow='CI-3p',job='test',automatic=True,instance='run-'+db,tiers=['v40'],groups=[],cells=[dict(infradb=db)]) for db in ['mysql','mariadb']]})
  producer={k:plan[k] for k in ['repository','sha','trigger_id','trigger_attempt','build_id','build_attempt','execution_id','control_sha']}
  gh=dict(repository='sysown/proxysql',sha='a'*40,workflow='CI-3p',run_id='8',run_attempt='1')
  with tempfile.TemporaryDirectory() as folder:
   prior=os.getcwd();os.chdir(folder)
   try:
    names=[]
    for db in ['mysql','mariadb']:
     api=Mock();api.json_artifact.return_value=producer
     with patch.object(runtime,'context',return_value=self.ctx()),patch.object(runtime,'api_for',return_value=api),patch.object(runtime,'load_bound',return_value=plan),patch.object(runtime,'resolve_producer',side_effect=AssertionError('mutable registration queried')),patch.object(runtime,'emit') as output,patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh),'CONSUMER_INPUTS':json.dumps(dict(infradb=json.dumps([db]))),'CONSUMER_INSTANCE':'run'}):
      runtime.consumer()
      api.json_artifact.assert_called_once_with(1,'ci-accepted-producer-a1','producer.json')
      names.append(output.call_args.kwargs['binding_name'])
      self.assertEqual(output.call_args.kwargs['matrices']['test'][0]['ci_instance'],'run-'+db)
    self.assertEqual(len(set(names)),2)
   finally:os.chdir(prior)
 def test_partial_producer_retry_preserves_published_artifacts(self):
  plan=make_plan(self.ctx(),dict(tiers=['v40'],mode='normal'),{'consumers':[]})
  api=Mock();api.artifacts.return_value=[dict(name=plan['legs'][0]['artifact_name']),dict(name='ci-leg-'+plan['execution_id']+'-v40')]
  with patch.object(runtime,'read_plan',return_value=plan),patch.object(runtime,'api_for',return_value=api),patch.object(runtime,'emit') as output,patch.dict(os.environ,{'CI_LEG':json.dumps(plan['legs'][0])}):
   runtime.artifact_status()
   self.assertEqual(output.call_args.kwargs,dict(publish_metadata=False,publish_handoff=False))
 def test_manual_foreign_consumer_keeps_source_read_only(self):
  row=dict(workflow='CI-g1',file='ci-g1.yml',job='tests',automatic=True,tiers=['v40','v30'],groups=['g1'],cells=[{}])
  plan=make_plan(self.ctx(),dict(tiers=['v40','v30'],mode='normal'),{'consumers':[row]})
  for leg in plan['legs']:leg['applicable_groups']=['g1'] if leg['tier']=='v40' else []
  gh=dict(repository='consumer/tests',sha='c'*40,workflow='manual-g1',run_id='8',run_attempt='1')
  with tempfile.TemporaryDirectory() as folder:
   prior=os.getcwd();os.chdir(folder)
   try:
    Path('ci-tier-consumers.json').write_text(json.dumps({'consumers':[row]}))
    source=Mock();source.artifacts.return_value=[dict(name='ci-manifest-'+plan['execution_id'])];source.json_artifact.return_value=plan
    with patch.object(runtime,'ROOT',Path(folder)),patch.object(runtime,'context',return_value=dict(self.ctx(),event='workflow_dispatch')),patch.object(runtime,'api_for',return_value=source),patch.object(runtime,'load_bound',return_value=plan),patch.object(runtime,'reporting_api') as reporter,patch.object(runtime,'register') as register,patch.object(runtime,'emit') as output,patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh),'PRODUCER_RUN_ID':'2','PRODUCER_ATTEMPT':'1','CONSUMER_INPUTS':'{}','CONSUMER_INSTANCE':'run','CONSUMER_FILE':'ci-g1.yml'}):
     runtime.consumer()
     derived=register.call_args.args[0]
     self.assertEqual(derived['reporting']['repository'],'consumer/tests')
     self.assertNotEqual(derived['reporting']['identity'],plan['execution_id'])
     self.assertTrue(all(c['name'].startswith('Manual / ') for c in derived['checks']))
     self.assertEqual(len(output.call_args.kwargs['matrices']['tests']),1)
     source.request.assert_not_called()
   finally:os.chdir(prior)

 def test_explicit_producer_requires_an_attempt(self):
  gh=dict(repository='sysown/proxysql',run_id='8',run_attempt='1')
  with patch.object(runtime,'context',return_value=dict(self.ctx(),event='workflow_dispatch')),patch.object(runtime,'api_for') as api,patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh),'PRODUCER_RUN_ID':'2','PRODUCER_ATTEMPT':''}):
   with self.assertRaisesRegex(ValueError,'requires producer_attempt'):runtime.consumer()
   api.return_value.artifacts.assert_not_called()

if __name__=='__main__':unittest.main()
