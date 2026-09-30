import contextlib,io,json,os,sys,tempfile,unittest,zipfile
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
    api.artifacts.return_value=[dict(id=1,name='ci-tier-selection',expired=False)]
    with patch.object(runtime,'GitHubAPI',return_value=api),patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh),'GITHUB_OUTPUT':str(Path(folder)/'out')}):
     runtime.standalone_selection();api.request.assert_not_called()
     self.assertEqual(json.loads(Path('selection.json').read_text()),snapshot)
     api.json_artifact.assert_called_once_with(9,'ci-tier-selection','selection.json')
   finally:os.chdir(prior)
 def test_standalone_rerun_rejects_a_foreign_snapshot(self):
  gh=dict(repository='sysown/proxysql',sha='a'*40,run_id='9',run_attempt='2')
  api=Mock();api.json_artifact.return_value=dict(repository='sysown/proxysql',sha='b'*40,run_id=9,selection={'tiers':['v40'],'mode':'normal'})
  api.artifacts.return_value=[dict(id=1,name='ci-tier-selection',expired=False)]
  with patch.object(runtime,'GitHubAPI',return_value=api),patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh)}):
   self.assertTrue(hasattr(runtime,'standalone_selection'))
   with self.assertRaisesRegex(ValueError,'selection identity mismatch'):runtime.standalone_selection()
 def test_standalone_retry_recovers_missing_snapshot_then_freezes_selection(self):
  gh=dict(repository='sysown/proxysql',sha='a'*40,run_id='9',run_attempt='1',event_name='pull_request',event={'pull_request':{'number':42}})
  api=runtime.GitHubAPI(gh['repository']);records=[];archive=None;labels=[{'name':'ci:v3.0'}]
  def request(path,**kwargs):
   if '/artifacts?' in path:return {'artifacts':records}
   if path.endswith('/zip'):return archive
   if path.endswith('/pulls/42'):return {'labels':labels}
   self.fail('unexpected API request: '+path)
  with tempfile.TemporaryDirectory() as folder:
   prior=os.getcwd();os.chdir(folder)
   try:
    output=Path(folder)/'out'
    with patch.object(runtime,'GitHubAPI',return_value=api),patch.object(api,'request',side_effect=request),patch.dict(os.environ,{'GITHUB_OUTPUT':str(output)}):
     # Selection succeeded, but the first attempt failed before artifact upload.
     with patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh)}):runtime.standalone_selection()
     gh['run_attempt']='2';output.write_text('')
     with patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh)}):runtime.standalone_selection()
     recovered=json.loads(Path('selection.json').read_text())
     self.assertEqual(recovered['selection']['tiers'],['v40','v30'])
     self.assertIn('publish_selection=true',output.read_text().splitlines())
     # The successful retry uploads its snapshot; later label edits cannot alter it.
     payload=io.BytesIO()
     with zipfile.ZipFile(payload,'w') as z:z.writestr('selection.json',json.dumps(recovered))
     archive=payload.getvalue();records.append(dict(id=17,name='ci-tier-selection',expired=False))
     gh['run_attempt']='3';labels[:]=[{'name':'ci:v3.1'}];output.write_text('')
     with patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh)}):runtime.standalone_selection()
     self.assertEqual(json.loads(Path('selection.json').read_text()),recovered)
     self.assertIn('publish_selection=false',output.read_text().splitlines())
   finally:os.chdir(prior)
 def test_standalone_retry_does_not_replace_unreadable_existing_snapshot(self):
  gh=dict(repository='sysown/proxysql',sha='a'*40,run_id='9',run_attempt='2',event_name='pull_request',event={'pull_request':{'number':42}})
  live=dict(id=17,name='ci-tier-selection',expired=False)
  for records,error in [([live,dict(live,id=18)],ValueError),([dict(live,expired=True)],ValueError),([live],zipfile.BadZipFile)]:
   with self.subTest(records=records),tempfile.TemporaryDirectory() as folder:
    api=runtime.GitHubAPI(gh['repository'])
    def request(path,**kwargs):
     if '/artifacts?' in path:return {'artifacts':records}
     if path.endswith('/zip'):return b'corrupt archive'
     self.fail('must not resolve fresh labels after finding a snapshot')
    prior=os.getcwd();os.chdir(folder)
    try:
     with patch.object(runtime,'GitHubAPI',return_value=api),patch.object(api,'request',side_effect=request),patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh),'GITHUB_OUTPUT':str(Path(folder)/'out')}):
      with self.assertRaises(error):runtime.standalone_selection()
     self.assertFalse(Path('selection.json').exists())
    finally:os.chdir(prior)
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

 def test_manual_consumer_resolves_axes_from_repository_variables(self):
  # a manual dispatch without infradb/connector: the catalogue axes are variable references, resolved from the
  # consumer repository's variables (CI_VARIABLES), not from the producer manifest (which carries none), and
  # from the row of the requested instance (a file has one row per instance, with the same job)
  rows=[dict(workflow='CI-3p-x',file='ci-3p-x.yml',job='test',automatic=False,tiers=['v40'],groups=[],cells=[],
   axes=dict(infradb={'var':'MATRIX_3P_X_infradb_'+db},connector={'var':'MATRIX_3P_X_connector_'+db}),instance='run-'+db) for db in ['mysql','mariadb']]
  variables={'MATRIX_3P_X_INFRADB_MYSQL':"['mysql8.0','mysql8.4']",'MATRIX_3P_X_CONNECTOR_MYSQL':"['x']",
   'MATRIX_3P_X_INFRADB_MARIADB':"['mariadb11.4']",'MATRIX_3P_X_CONNECTOR_MARIADB':"['x','y']"}
  plan=make_plan(self.ctx(),dict(tiers=['v40'],mode='normal'),{'consumers':[]})
  gh=dict(repository='consumer/tests',sha='c'*40,workflow='CI-3p-x',run_id='8',run_attempt='1')
  def run(instance,variables,supplied=dict(infradb='',connector='')):
   with tempfile.TemporaryDirectory() as folder:
    prior=os.getcwd();os.chdir(folder)
    try:
     Path('ci-tier-consumers.json').write_text(json.dumps({'consumers':rows}))
     source=Mock();source.artifacts.return_value=[dict(name='ci-manifest-'+plan['execution_id'])];source.json_artifact.return_value=plan
     with patch.object(runtime,'ROOT',Path(folder)),patch.object(runtime,'context',return_value=dict(self.ctx(),event='workflow_dispatch',variables=variables)),patch.object(runtime,'api_for',return_value=source),patch.object(runtime,'load_bound',return_value=plan),patch.object(runtime,'reporting_api'),patch.object(runtime,'register'),patch.object(runtime,'emit') as output,patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh),'PRODUCER_RUN_ID':'2','PRODUCER_ATTEMPT':'1','CONSUMER_INPUTS':json.dumps(supplied),'CONSUMER_INSTANCE':instance,'CONSUMER_FILE':'ci-3p-x.yml'}):
      runtime.consumer()
      return sorted((c['infradb'],c['connector'],c['ci_instance']) for c in output.call_args.kwargs['matrices']['test'])
    finally:os.chdir(prior)
  self.assertEqual(run('run-mysql',variables),[('mysql8.0','x','run-mysql'),('mysql8.4','x','run-mysql')])
  self.assertEqual(run('run-mariadb',variables),[('mariadb11.4','x','run-mariadb'),('mariadb11.4','y','run-mariadb')])
  # no consumer_id ('run'): only a dispatch that supplies every axis is unambiguous
  self.assertEqual(run('run',{},dict(infradb='["mysql9.1"]',connector='["z"]')),[('mysql9.1','z','run')])
  with self.assertRaisesRegex(ValueError,'ambiguous consumer instance run: pass consumer_id \\(one of run-mariadb, run-mysql\\)'):run('run',variables)
  with self.assertRaisesRegex(ValueError,'consumer matrix variable not set: MATRIX_3P_X_infradb_mysql, MATRIX_3P_X_connector_mysql'):run('run-mysql',{})

 def test_explicit_producer_requires_an_attempt(self):
  gh=dict(repository='sysown/proxysql',run_id='8',run_attempt='1')
  with patch.object(runtime,'context',return_value=dict(self.ctx(),event='workflow_dispatch')),patch.object(runtime,'api_for') as api,patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh),'PRODUCER_RUN_ID':'2','PRODUCER_ATTEMPT':''}):
   with self.assertRaisesRegex(ValueError,'requires producer_attempt'):runtime.consumer()
   api.return_value.artifacts.assert_not_called()

if __name__=='__main__':unittest.main()
