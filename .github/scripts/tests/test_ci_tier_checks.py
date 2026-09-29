import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ci_tier_checks import aggregate_state
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
if __name__=='__main__':unittest.main()
