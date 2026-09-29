import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ci_tier_checks import aggregate_state, publish_result
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

if __name__=='__main__':unittest.main()
