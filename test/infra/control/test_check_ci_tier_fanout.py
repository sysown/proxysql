import copy,unittest
from check_ci_tier_fanout import validate_routes, version
class RouteTests(unittest.TestCase):
 def fixture(self):
  rows=[dict(workflow='CI-g1',file='ci-g1.yml',job='tests',instance='run',automatic=True,tiers=['v40','v30','v31'],groups=['g1'],cells=[{}])]
  callers={'CI-g1':{'on':{'workflow_run':{'workflows':['CI-trigger']}},'jobs':{'run':{'uses':'sysown/proxysql/.github/workflows/ci-g1.yml@GH-Actions'}}}}
  engines={'ci-g1.yml':{'jobs':{'tier-context':{},'tests':{'steps':[{'run':'python3 ci_tier_runtime.py restore'}]}}}}
  return rows,callers,engines
 def test_good_and_missing(self):
  rows,c,e=self.fixture();self.assertEqual(validate_routes(rows,c,e,{'g1'},{'g1'}),[])
  self.assertTrue(validate_routes([],c,e,{'g1'},{'g1'}))
 def test_manual_does_not_cover_automatic(self):
  rows,c,e=self.fixture();c['CI-g1']['on']={'workflow_dispatch':None}
  self.assertTrue(validate_routes(rows,c,e,{'g1'},{'g1'}))
 def test_unknown_missing_nested_and_duplicate(self):
  rows,c,e=self.fixture();self.assertTrue(validate_routes(rows,c,{}, {'g1'},{'g1'}))
  self.assertTrue(validate_routes(rows,c,e,{}, {'g1'}))
  self.assertTrue(validate_routes(rows+rows,c,e,{'g1'},{'g1'}))
 def test_version_is_numeric(self):self.assertGreater(version('3.10.0'),version('3.9.0'))
if __name__=='__main__':unittest.main()
