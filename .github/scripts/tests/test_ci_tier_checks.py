import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ci_tier_checks import aggregate_state, publish_result, reconcile
class CheckTests(unittest.TestCase):
 def plan(self):return {'execution_id':'run','checks':[{'key':'a','required':True,'applicable':True},{'key':'b','required':True,'applicable':True}]}
 def test_all_success_only(self):
  p=self.plan()
  for states in [[],[{'key':'a','status':'completed','conclusion':'success'}]]:
   self.assertNotEqual(aggregate_state(p,states).get('conclusion'),'success')
  states=[dict(key=k,status='completed',conclusion='success',execution_id='run') for k in ['a','b']]
  self.assertEqual(aggregate_state(p,states)['conclusion'],'success')
  for outcome in ['failure','cancelled','timed_out','skipped','neutral']:
   states[1]['conclusion']=outcome
   self.assertEqual(aggregate_state(p,states)['conclusion'],'failure')
 def test_blocked_checks_are_not_counted_as_test_failures(self):
  p=self.plan()
  states=[dict(key='a',status='completed',conclusion='failure',execution_id='run'),
          dict(key='b',status='completed',conclusion='skipped',execution_id='run')]
  result=aggregate_state(p,states)
  self.assertEqual(result['conclusion'],'failure')
  self.assertEqual(result['output']['summary'],'0/2 passed; 0 pending; 1 failed; 1 blocked/skipped')
  states[0]['conclusion']='success'
  result=aggregate_state(p,states)
  self.assertEqual(result['conclusion'],'failure')
  self.assertEqual(result['output']['summary'],'1/2 passed; 0 pending; 0 failed; 1 blocked/skipped')

 def test_old_attempt_and_wrong_execution_do_not_count(self):
  states=[dict(key=k,status='completed',conclusion='success',execution_id='other') for k in ['a','b']]
  self.assertNotEqual(aggregate_state(self.plan(),states).get('conclusion'),'success')
 def test_not_applicable_is_explicit(self):
  p=self.plan();p['checks'][1]['applicable']=False
  self.assertEqual(aggregate_state(p,[dict(key='a',status='completed',conclusion='success',execution_id='run')])['conclusion'],'success')
 def test_old_attempt_cannot_overwrite_new_attempt(self):
  from unittest.mock import Mock
  api=Mock();api.request.return_value={'run_attempt':2}
  plan={'repository':'sysown/proxysql','checks':[dict(key='a',check_id=9,name='test')],'execution_id':'run','build_id':3}
  with self.assertRaisesRegex(ValueError,'stale'):publish_result(plan,'a','success',api,7,1)
  self.assertEqual(api.request.call_count,1)

 def test_result_retry_rejects_a_new_consumer_attempt(self):
  import subprocess
  from unittest.mock import patch
  from ci_tier_artifacts import GitHubAPI
  plan={'repository':'sysown/proxysql','checks':[dict(key='a',check_id=9,name='test')],'execution_id':'run','build_id':3}
  replies=[subprocess.CompletedProcess([],0,b'{"run_attempt":1}',b''),
           subprocess.CompletedProcess([],1,b'',b'HTTP 503 upstream unavailable'),
           subprocess.CompletedProcess([],0,b'{"run_attempt":2}',b'')]
  with patch('ci_tier_artifacts.subprocess.run',side_effect=replies) as run,patch('ci_tier_artifacts.time.sleep'):
   with self.assertRaisesRegex(ValueError,'stale'):publish_result(plan,'a','success',GitHubAPI('sysown/proxysql'),7,1)
   writes=[c for c in run.call_args_list if c.args[0][c.args[0].index('--method')+1]=='PATCH']
   self.assertEqual(len(writes),1)

 def test_result_retry_publishes_the_same_state_for_the_current_attempt(self):
  import subprocess,json
  from unittest.mock import patch
  from ci_tier_artifacts import GitHubAPI
  plan={'repository':'sysown/proxysql','checks':[dict(key='a',check_id=9,name='test')],'execution_id':'run','build_id':3}
  replies=[subprocess.CompletedProcess([],0,b'{"run_attempt":1}',b''),
           subprocess.CompletedProcess([],1,b'',b'HTTP 503 upstream unavailable'),
           subprocess.CompletedProcess([],0,b'{"run_attempt":1}',b''),
           subprocess.CompletedProcess([],0,b'{"id":9}',b'')]
  with patch('ci_tier_artifacts.subprocess.run',side_effect=replies) as run,patch('ci_tier_artifacts.time.sleep'):
   publish_result(plan,'a','success',GitHubAPI('sysown/proxysql'),7,1)
   writes=[c for c in run.call_args_list if c.args[0][c.args[0].index('--method')+1]=='PATCH']
   self.assertEqual(len(writes),2)
   self.assertEqual(writes[0].kwargs['input'],writes[1].kwargs['input'])
   self.assertEqual(json.loads(writes[1].kwargs['input'])['conclusion'],'success')

 def test_start_retry_recovers_summary_update_after_individual_check_succeeds(self):
  import subprocess,json
  from unittest.mock import patch
  from ci_tier_artifacts import GitHubAPI
  plan={'repository':'sysown/proxysql','checks':[dict(key='a',check_id=9,name='test')],'execution_id':'run','build_id':3,'summary_check_id':10}
  replies=[subprocess.CompletedProcess([],0,b'{"run_attempt":1}',b''),
           subprocess.CompletedProcess([],0,b'{"id":9}',b''),
           subprocess.CompletedProcess([],1,b'',b'HTTP 503 upstream unavailable'),
           subprocess.CompletedProcess([],0,b'{"run_attempt":1}',b''),
           subprocess.CompletedProcess([],0,b'{"id":10}',b'')]
  with patch('ci_tier_artifacts.subprocess.run',side_effect=replies) as run,patch('ci_tier_artifacts.time.sleep'):
   publish_result(plan,'a','in_progress',GitHubAPI('sysown/proxysql'),7,1)
   writes=[c for c in run.call_args_list if c.args[0][c.args[0].index('--method')+1]=='PATCH']
   self.assertEqual([c.args[0][2] for c in writes],['repos/sysown/proxysql/check-runs/9','repos/sysown/proxysql/check-runs/10','repos/sysown/proxysql/check-runs/10'])
   self.assertEqual(writes[1].kwargs['input'],writes[2].kwargs['input'])
   self.assertEqual(json.loads(writes[2].kwargs['input'])['status'],'in_progress')

 def test_partial_rerun_preserves_jobs_not_rerun(self):
  import json
  from unittest.mock import Mock
  plan=dict(self.plan(),repository='sysown/proxysql',sha='a'*40,summary_check_id=99)
  for i,c in enumerate(plan['checks']):c.update(check_id=i+1,name='cell '+c['key'])
  checks=[dict(id=c['check_id'],external_id='run:'+c['key'],status='completed',conclusion='success',output={'text':json.dumps(dict(run_id=7,attempt=i+1))}) for i,c in enumerate(plan['checks'])]
  api=Mock();api.request.return_value={'run_attempt':2}
  api.pages.side_effect=lambda path,key: checks if key=='check_runs' else [dict(name='run / cell b',run_attempt=2,status='completed',conclusion='success')]
  self.assertEqual(reconcile(plan,api)['conclusion'],'success')
 def test_rerun_of_same_cell_invalidates_old_success(self):
  import json
  from unittest.mock import Mock
  plan=dict(self.plan(),repository='sysown/proxysql',sha='a'*40,summary_check_id=99)
  for i,c in enumerate(plan['checks']):c.update(check_id=i+1,name='cell '+c['key'])
  checks=[dict(id=c['check_id'],external_id='run:'+c['key'],status='completed',conclusion='success',output={'text':json.dumps(dict(run_id=7,attempt=1))}) for c in plan['checks']]
  api=Mock();api.request.return_value={'run_attempt':2}
  api.pages.side_effect=lambda path,key: checks if key=='check_runs' else [dict(name='run / cell b',run_attempt=2,status='in_progress',conclusion=None)]
  self.assertEqual(reconcile(plan,api)['status'],'in_progress')

 def test_start_during_summary_write_cannot_leave_stale_success(self):
  import copy,json
  from unittest.mock import Mock
  plan=dict(self.plan(),repository='sysown/proxysql',sha='a'*40,summary_check_id=99)
  for i,c in enumerate(plan['checks']):c.update(check_id=i+1,name='cell '+c['key'])
  checks=[dict(id=c['check_id'],external_id='run:'+c['key'],status='completed',conclusion='success',output={}) for c in plan['checks']]
  api=Mock();api.pages.side_effect=lambda *args:copy.deepcopy(checks)
  def request(path,method='GET',payload=None):
   if method=='PATCH' and payload.get('conclusion')=='success':checks[1]['status']='in_progress'
   return {}
  api.request.side_effect=request
  self.assertEqual(reconcile(plan,api)['status'],'in_progress')
  self.assertEqual(api.request.call_args.args[2]['status'],'in_progress')
 def test_foreign_consumer_reports_on_caller_with_distinct_identity(self):
  from ci_tier_checks import register
  from unittest.mock import Mock
  plan=dict(self.plan(),repository='sysown/proxysql',sha='a'*40,build_id=3,
            selection=dict(tiers=['v40'],mode='normal'),reporting=dict(repository='consumer/tests',sha='b'*40,identity='manual-7',name='CI / manual consumer 7'))
  for c in plan['checks']:c['name']='cell '+c['key']
  api=Mock();api.request.return_value={'id':9,'run_attempt':1}
  register(plan,api,origin=False)
  self.assertEqual(api.request.call_args_list[0].args[0],'repos/consumer/tests/check-runs')
  self.assertEqual(api.request.call_args_list[0].args[2]['external_id'],'manual-7:summary')
  publish_result(plan,'a','success',api,7,1,run_repository='consumer/tests')
  self.assertEqual(api.request.call_args_list[-2].args[0],'repos/consumer/tests/actions/runs/7')
  self.assertEqual(api.request.call_args.args[2]['details_url'],'https://github.com/consumer/tests/actions/runs/7')

 def test_new_producer_attempt_does_not_invalidate_accepted_build(self):
  import json
  from unittest.mock import Mock
  plan=dict(self.plan(),repository='sysown/proxysql',sha='a'*40,summary_check_id=99)
  for i,c in enumerate(plan['checks']):c.update(check_id=i+1,name='cell '+c['key'],workflow='CI-builds')
  checks=[dict(id=c['check_id'],external_id='run:'+c['key'],status='completed',conclusion='success',output={'text':json.dumps(dict(run_id=7,attempt=1))}) for c in plan['checks']]
  api=Mock();api.request.return_value={'run_attempt':2};api.pages.return_value=checks
  self.assertEqual(reconcile(plan,api)['conclusion'],'success')

class RetainedNativeTests(unittest.TestCase):
 def fixture(self):
  import copy,json
  from unittest.mock import Mock
  plan=dict(repository='sysown/proxysql',sha='a'*40,execution_id='run',checks=[
   dict(key=k,name='cell '+k,check_id=i+1,workflow='CI-tests',required=True,applicable=True) for i,k in enumerate(('a','b'))])
  original=[dict(id=10+i,name='run / cell '+k,run_attempt=1,status='completed',conclusion='success',
                 started_at='2026-10-23T09:54:51Z',completed_at='2026-10-23T11:00:05Z') for i,k in enumerate(('a','b'))]
  state=dict(plan=plan,previous=original,current=[dict(j,id=j['id']+10,run_attempt=2) for j in original],history_reads=0)
  state['checks']=[dict(id=i+1,external_id='run:'+k,status='completed',conclusion='success',
                        output={'text':json.dumps(dict(run_id=7,attempt=1))}) for i,k in enumerate(('a','b'))]
  api=Mock();api.request.return_value={'run_attempt':2}
  def pages(path,key):
   if key=='check_runs':return copy.deepcopy(state['checks'])
   if path.endswith('/attempts/2/jobs'):return copy.deepcopy(state['current'])
   if path.endswith('/attempts/1/jobs'):
    state['history_reads']+=1
    return copy.deepcopy(state['previous'])
   self.fail('unexpected historical job lookup: '+path)
  api.pages.side_effect=pages;state['api']=api
  return state

 def result(self,state):
  from ci_tier_checks import observations
  return aggregate_state(state['plan'],observations(state['plan'],state['api']))

 def set_attempt(self,state,index,attempt):
  import json
  state['checks'][index]['output']['text']=json.dumps(dict(run_id=7,attempt=attempt))

 def test_retained_native_clones_preserve_success(self):
  state=self.fixture()
  self.assertEqual(self.result(state).get('conclusion'),'success')
  self.assertEqual(state['history_reads'],1)

 def test_fresh_native_success_cannot_reuse_old_custom_success(self):
  state=self.fixture()
  state['current'][0].update(started_at='2026-10-23T11:17:40Z',completed_at='2026-10-23T11:18:00Z')
  self.assertEqual(self.result(state)['status'],'in_progress')

 def test_retained_peer_survives_a_current_cell_result(self):
  state=self.fixture();self.set_attempt(state,0,2)
  state['current'][0].update(started_at='2026-10-23T11:17:40Z',completed_at='2026-10-23T11:18:00Z')
  self.assertEqual(self.result(state).get('conclusion'),'success')

 def test_retained_success_requires_unambiguous_execution_intervals(self):
  for mutation in ('missing','duplicate','old_start','old_end','new_start','new_end','prefix','old_failure'):
   with self.subTest(mutation=mutation):
    state=self.fixture()
    if mutation=='missing':state['previous']=[]
    elif mutation=='duplicate':state['previous'].append(dict(state['previous'][0],id=99))
    elif mutation=='old_start':state['previous'][0]['started_at']=None
    elif mutation=='old_end':state['previous'][0]['completed_at']=''
    elif mutation=='new_start':state['current'][0]['started_at']=''
    elif mutation=='new_end':state['current'][0]['completed_at']=None
    elif mutation=='prefix':state['current'][0]['name']='different / cell a'
    elif mutation=='old_failure':state['previous'][0]['conclusion']='failure'
    self.assertEqual(self.result(state)['status'],'in_progress')

 def test_native_failure_always_overrides_retained_custom_success(self):
  for outcome in ('failure','cancelled','timed_out','skipped','neutral'):
   with self.subTest(outcome=outcome):
    state=self.fixture();state['current'][0]['conclusion']=outcome
    self.assertEqual(self.result(state).get('conclusion'),'failure')
    self.assertEqual(state['history_reads'],1)  # Only the other, successful cell needs history.

 def test_unfinished_native_rerun_does_not_reuse_old_success(self):
  for status in ('queued','in_progress'):
   with self.subTest(status=status):
    state=self.fixture();state['current'][0].update(status=status,conclusion=None)
    self.assertEqual(self.result(state)['status'],'in_progress')

 def test_current_native_success_does_not_need_history(self):
  state=self.fixture();self.set_attempt(state,0,2);self.set_attempt(state,1,2)
  state['previous']=[]
  self.assertEqual(self.result(state).get('conclusion'),'success')
  self.assertEqual(state['history_reads'],0)

 def test_future_or_invalid_attempt_cannot_qualify_as_retained(self):
  for attempt in (3,None,'1',True,0,-1):
   with self.subTest(attempt=attempt):
    state=self.fixture();self.set_attempt(state,0,attempt)
    self.assertEqual(self.result(state)['status'],'in_progress')

if __name__=='__main__':unittest.main()
