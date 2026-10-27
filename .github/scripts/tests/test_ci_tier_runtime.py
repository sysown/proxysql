import contextlib,io,json,os,sys,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch,Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import ci_tier_runtime as runtime
from ci_tier_plan import make_plan

class RuntimeTests(unittest.TestCase):
 def ctx(self):return dict(repository='sysown/proxysql',sha='a'*40,control_sha='b'*40,trigger_id=1,trigger_attempt=1,build_id=2,build_attempt=1,event='pull_request',pull_requests=[{'number':42}],variables={})
 def test_direct_pr_build_uses_source_head_and_labels(self):
  gh=dict(repository='sysown/proxysql',sha='b'*40,run_id='17',run_attempt='2',event_name='pull_request',
          event={'pull_request':{'number':42,'head':{'sha':'a'*40}}})
  with patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh),'TRIGGER_JSON':json.dumps(gh)}):ctx=runtime.context()
  self.assertEqual(ctx['sha'],'a'*40)
  self.assertEqual(ctx['pull_requests'],[{'number':42}])
  self.assertEqual((ctx['trigger_id'],ctx['build_id'],ctx['trigger_attempt'],ctx['build_attempt']),(17,17,2,2))

 def test_successful_finalization_writes_accepted_producer(self):
  ctx=dict(self.ctx(),trigger_id=2)
  plan=make_plan(ctx,dict(tiers=['v40'],mode='normal'),{'consumers':[]})
  leg=plan['legs'][0];api=Mock()
  api.artifacts.return_value=[dict(id=17,name=leg['artifact_name'],expired=False)]
  api.json_artifact.return_value=dict(execution_id=plan['execution_id'],sha=plan['sha'],version='ProxySQL version 4.0.12',
      applicable_groups=[],applicable={c['key']:True for c in plan['checks']})
  with tempfile.TemporaryDirectory() as folder:
   prior=os.getcwd();os.chdir(folder)
   try:
    with patch.object(runtime,'read_plan',return_value=plan),patch.object(runtime,'api_for',return_value=api),patch.dict(os.environ,{'BUILD_RESULT':'success','GITHUB_OUTPUT':str(Path(folder)/'out')}):runtime.finalize()
    accepted=json.loads(Path('producer.json').read_text());manifest=json.loads(Path('manifest.json').read_text())
    self.assertEqual(accepted,{k:manifest[k] for k in ('repository','sha','trigger_id','trigger_attempt','build_id','build_attempt','execution_id','control_sha')})
   finally:os.chdir(prior)
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
 def test_superseded_producer_stops_before_registering_checks(self):
  api=Mock();api.repository='sysown/proxysql'
  api.request.side_effect=[{'head':{'sha':'c'*40}},{'status':'in_progress'},{}]
  with patch.object(runtime,'context',return_value=self.ctx()),patch.object(runtime,'api_for',return_value=api),patch.object(runtime,'register') as register,patch.dict(os.environ,{'TRUSTED':'true'}):
   with self.assertRaisesRegex(RuntimeError,'superseded'):runtime.plan_command()
   register.assert_not_called()
   api.request.assert_called_with('repos/sysown/proxysql/actions/runs/2/cancel','POST')
 def test_superseded_consumer_stops_before_any_artifact_lookup(self):
  gh=dict(repository='sysown/proxysql',run_id='8',run_attempt='1')
  api=Mock();api.repository=gh['repository']
  api.request.side_effect=[{'head':{'sha':'c'*40}},{'status':'in_progress'},{}]
  with patch.object(runtime,'context',return_value=self.ctx()),patch.object(runtime,'GitHubAPI',return_value=api),patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh)}):
   with self.assertRaisesRegex(RuntimeError,'superseded'):runtime.consumer()
   api.artifacts.assert_not_called();api.json_artifact.assert_not_called()
   api.request.assert_called_with('repos/sysown/proxysql/actions/runs/8/cancel','POST')
 def test_binary_metadata_uses_the_build_container_version(self):
  # The host executable deliberately fails like an artifact built for a newer
  # libc. Exercise stamp and its real subprocess boundary, not a version mock.
  for tier,version in [('v30','3.0.12'),('v31','3.1.12'),('v40','4.0.12'),('v30','4.0.12')]:
   with self.subTest(tier=tier,version=version),tempfile.TemporaryDirectory() as folder:
    prior=os.getcwd();os.chdir(folder)
    try:
     root=Path('proxysql');(root/'src').mkdir(parents=True);(root/'test/tap/groups').mkdir(parents=True)
     binary=root/'src/proxysql'
     binary.write_text('#!/bin/sh\necho host-called > "$HOST_PROBE"\necho "GLIBC_2.38 not found" >&2\nexit 97\n')
     binary.chmod(0o755)
     tools=Path(folder)/'tools';tools.mkdir();docker=tools/'docker'
     docker.write_text('#!/bin/sh\nprintf "%s\\n" "$PWD" "$@" > "$CONTAINER_PROBE"\necho "daemon diagnostic 9.9.9" >&2\nprintf "ProxySQL version %s\\n" "$FIXTURE_VERSION"\n')
     docker.chmod(0o755)
     (root/'test/tap/groups/groups.json').write_text(json.dumps({'core-t':['g1'],'plugin-t':['g2','@proxysql_min_version:4.0.0']}))
     consumers=[dict(workflow='CI-'+g,file='ci-'+g+'.yml',job='tests',automatic=True,tiers=[tier],groups=[g],cells=[{}]) for g in ['g1','g2']]
     plan=make_plan(self.ctx(),dict(tiers=[tier],mode='normal',pr_number=42),{'consumers':consumers})
     probe=Path(folder)/'container-probe';host=Path(folder)/'host-probe'
     env={'CI_LEG':json.dumps(plan['legs'][0]),'PATH':str(tools)+os.pathsep+os.environ['PATH'],
          'HOST_PROBE':str(host),'CONTAINER_PROBE':str(probe),'FIXTURE_VERSION':version}
     with patch.object(runtime,'read_plan',return_value=plan),patch.dict(os.environ,env):
      if tier=='v30' and version.startswith('4.'):
       with self.assertRaisesRegex(ValueError,'requested product tier'):runtime.stamp()
       self.assertFalse((root/'src/ci-tier.json').exists());self.assertFalse(Path('metadata.json').exists())
      else:
       runtime.stamp()
       meta=json.loads((root/'src/ci-tier.json').read_text())
       self.assertEqual(meta['version'],'ProxySQL version '+version+'\n')
       self.assertEqual(meta['tier'],tier)
       self.assertEqual(meta['applicable_groups'],['g1','g2'] if tier=='v40' else ['g1'])
       self.assertEqual(json.loads(Path('metadata.json').read_text()),meta)
     self.assertFalse(host.exists(),'the artifact must never execute on the host')
     self.assertEqual(probe.read_text().splitlines(),[str(root.resolve()),'compose','run','--rm','--no-deps',
                      '--entrypoint','/opt/proxysql/src/proxysql','ubuntu24_dbg_build','--version'])
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
     api=Mock();api.json_artifact.return_value=producer;api.request.return_value={'head':{'sha':self.ctx()['sha']}}
     with patch.object(runtime,'context',return_value=self.ctx()),patch.object(runtime,'GitHubAPI',return_value=api),patch.object(runtime,'api_for',return_value=api),patch.object(runtime,'load_bound',return_value=plan),patch.object(runtime,'resolve_producer',side_effect=AssertionError('mutable registration queried')),patch.object(runtime,'emit') as output,patch.dict(os.environ,{'GITHUB_JSON':json.dumps(gh),'CONSUMER_INPUTS':json.dumps(dict(infradb=json.dumps([db]))),'CONSUMER_INSTANCE':'run'}):
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

class ConsumerRerunTests(unittest.TestCase):
 def archive(self,filename,payload):
  output=io.BytesIO()
  with zipfile.ZipFile(output,'w') as z:z.writestr(filename,json.dumps(payload))
  return output.getvalue()

 @contextlib.contextmanager
 def fixture(self,event='pull_request',foreign=False,workflow='CI-g1',native=False,consumer_attempt=3):
  ctx=dict(repository='source/tests' if foreign else 'sysown/proxysql',sha='a'*40,control_sha='b'*40,
           trigger_id=1,trigger_attempt=2,build_id=2,build_attempt=1,event=event,pull_requests=[{'number':42}],variables={})
  if native:ctx.update(trigger_id=2,trigger_attempt=1)
  plan=make_plan(ctx,dict(tiers=['v40'],mode='normal'),{'consumers':[
   dict(workflow='CI-g1',file='ci-g1.yml',job='tests',automatic=True,tiers=['v40'],groups=[],cells=[{}])]})
  producer={k:plan[k] for k in ('repository','sha','trigger_id','trigger_attempt','build_id','build_attempt','execution_id','control_sha')}
  gh=dict(repository='sysown/proxysql',sha='a'*40,workflow=workflow,run_id='8',run_attempt=str(consumer_attempt))
  if native:
   gh['event_name']='workflow_run'
   gh['event']={'workflow_run':{'name':'feature CI-builds '+ctx['sha'], 'path':'.github/workflows/CI-builds.yml','event':event}}
  state=dict(own=[],binding=dict(producer),accepted=dict(producer),manifest=plan,requests=[],deny_acceptance=False)
  api=runtime.GitHubAPI(gh['repository'])
  def request(path,**kwargs):
   state['requests'].append(path)
   if path.endswith('/pulls/42'):return {'state':'open','head':{'sha':'a'*40}}
   if '/runs/8/artifacts?' in path:
    if state.get('list_error'):raise RuntimeError('fixture artifact API unavailable')
    return {'artifacts':state['own']}
   if '/runs/1/artifacts?' in path:
    if state['deny_acceptance']:self.fail('existing/manual binding must not be replaced with acceptance')
    return {'artifacts':state.get('acceptance_records',[dict(id=32,name='ci-accepted-producer-a2',expired=False)])}
   if '/runs/2/artifacts?' in path:
    records=[dict(id=33,name='ci-manifest-'+plan['execution_id'],expired=False)]
    if native:records+=state.get('acceptance_records',[dict(id=32,name='ci-accepted-producer-a2',expired=False)])
    return {'artifacts':records}
   if path.endswith('/artifacts/31/zip'):return state.get('binding_bytes',self.archive('binding.json',state['binding']))
   if path.endswith('/artifacts/32/zip'):return state.get('accepted_bytes',self.archive('producer.json',state['accepted']))
   if path.endswith('/artifacts/33/zip'):return self.archive('manifest.json',state['manifest'])
   self.fail('unexpected API request: '+path)
  with tempfile.TemporaryDirectory() as folder:
   prior=os.getcwd();os.chdir(folder)
   try:
    consumer_ctx=dict(ctx,trigger_attempt=2) if native else ctx
    with patch.object(runtime,'context',return_value=consumer_ctx),patch.object(runtime,'GitHubAPI',return_value=api),patch.object(api,'request',side_effect=request),patch.dict(os.environ,{
     'GITHUB_JSON':json.dumps(gh),'GITHUB_OUTPUT':str(Path(folder)/'out'),'CONSUMER_INPUTS':'{}','CONSUMER_INSTANCE':'run',
     'CONSUMER_FILE':'not-in-current-catalogue.yml','PRODUCER_RUN_ID':'' if native else '99','PRODUCER_ATTEMPT':'' if native else '9'}):
     yield state
   finally:os.chdir(prior)

 def test_native_build_completion_preserves_retained_execution_on_consumer_retry(self):
  for attempt in [1,3]:
   with self.subTest(attempt=attempt),self.fixture(native=True,consumer_attempt=attempt):
    runtime.consumer()
    binding=json.loads(Path('binding.json').read_text())
    self.assertEqual((binding['trigger_id'],binding['trigger_attempt'],binding['build_id'],binding['build_attempt']),(2,1,2,1))
    outputs=dict(line.split('=',1) for line in Path(os.environ['GITHUB_OUTPUT']).read_text().splitlines())
    self.assertEqual(json.loads(outputs['matrices'])['tests'][0]['execution_id'],'t2-a1-b2-a1')

 def test_native_manual_producer_still_fans_out_automatically(self):
  with self.fixture(event='workflow_dispatch',native=True,consumer_attempt=1):
   runtime.consumer()
   self.assertEqual(json.loads(Path('binding.json').read_text())['build_id'],2)

 def test_native_completion_rejects_foreign_build_and_source(self):
  for key,value in [('build_id',99),('sha','c'*40),('repository','other/repo'),('trigger_attempt',3)]:
   with self.subTest(key=key),self.fixture(native=True) as state:
    state['accepted'][key]=value
    with self.assertRaises(ValueError):runtime.consumer()
    self.assertFalse(Path('binding.json').exists())

 def test_native_completion_requires_its_acceptance_artifact(self):
  with self.fixture(native=True) as state:
   state['acceptance_records']=[]
   with self.assertRaises(ValueError):runtime.consumer()
   self.assertFalse(Path('binding.json').exists())

 def test_automatic_rerun_recovers_original_accepted_producer(self):
  with self.fixture() as state:
   runtime.consumer()
   binding=json.loads(Path('binding.json').read_text())
   self.assertEqual((binding['trigger_id'],binding['trigger_attempt'],binding['build_id'],binding['build_attempt']),(1,2,2,1))
   outputs=dict(line.split('=',1) for line in Path(os.environ['GITHUB_OUTPUT']).read_text().splitlines())
   cells=json.loads(outputs['matrices'])['tests']
   self.assertEqual([(c['tier'],c['build_id'],c['execution_id']) for c in cells],[('v40',2,'t1-a2-b2-a1')])

 def test_existing_binding_takes_precedence(self):
  with self.fixture() as state:
   state['own']=[dict(id=31,name='ci-tier-binding-run',expired=False)]
   state['deny_acceptance']=True
   runtime.consumer()
   self.assertEqual(json.loads(Path('binding.json').read_text())['build_id'],2)

 def test_existing_unreadable_binding_does_not_recover(self):
  live=dict(id=31,name='ci-tier-binding-run',expired=False)
  cases=[([dict(live,expired=True)],None,ValueError),([live,dict(live,id=34)],None,ValueError),([live],b'bad zip',zipfile.BadZipFile)]
  for records,raw,error in cases:
   with self.subTest(records=records),self.fixture() as state:
    state['own']=records;state['deny_acceptance']=True
    if raw is not None:state['binding_bytes']=raw
    with self.assertRaises(error):runtime.consumer()
    self.assertFalse(Path('binding.json').exists())

 def test_existing_mismatched_binding_does_not_recover(self):
  with self.fixture() as state:
   state['own']=[dict(id=31,name='ci-tier-binding-run',expired=False)]
   state['binding']['sha']='c'*40;state['deny_acceptance']=True
   with self.assertRaisesRegex(ValueError,'producer binding mismatch: sha'):runtime.consumer()

 def test_recovery_rejects_wrong_original_identity(self):
  for key,value in [('repository','other/repo'),('sha','c'*40),('trigger_id',9),('trigger_attempt',9)]:
   with self.subTest(key=key),self.fixture() as state:
    state['accepted'][key]=value
    with self.assertRaisesRegex(ValueError,'producer binding mismatch: '+key):runtime.consumer()

 def test_recovery_preserves_acceptance_validation(self):
  cases=[([],None,ValueError),([dict(id=32,name='ci-accepted-producer-a2',expired=True)],None,ValueError),
         ([dict(id=32,name='ci-accepted-producer-a2',expired=False)],b'bad zip',zipfile.BadZipFile)]
  for records,raw,error in cases:
   with self.subTest(records=records),self.fixture() as state:
    state['acceptance_records']=records
    if raw is not None:state['accepted_bytes']=raw
    with self.assertRaises(error):runtime.consumer()

 def test_missing_manual_or_foreign_snapshot_does_not_recover(self):
  for event,foreign in [('workflow_dispatch',False),('pull_request',True)]:
   with self.subTest(event=event,foreign=foreign),self.fixture(event,foreign) as state:
    state['deny_acceptance']=True
    with self.assertRaisesRegex(ValueError,'ci-tier-binding-run'):runtime.consumer()

 def test_artifact_api_error_does_not_recover(self):
  with self.fixture() as state:
   state['list_error']=True;state['deny_acceptance']=True
   with self.assertRaisesRegex(RuntimeError,'fixture artifact API unavailable'):runtime.consumer()

 def test_recovery_cannot_rebuild_a_missing_original_consumer(self):
  with self.fixture(workflow='CI-new'):
   with self.assertRaisesRegex(ValueError,'rerun has no original consumer manifest'):runtime.consumer()

if __name__=='__main__':unittest.main()
