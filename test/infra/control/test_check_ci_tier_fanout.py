import copy,unittest
from check_ci_tier_fanout import validate_routes, version
class RouteTests(unittest.TestCase):
 def fixture(self):
  rows=[dict(workflow='CI-g1',file='ci-g1.yml',job='tests',instance='run',automatic=True,tiers=['v40','v30','v31'],groups=['g1'],cells=[{}])]
  callers={'CI-g1':{'on':{'workflow_run':{'workflows':['CI-trigger']}},'jobs':{'run':{'uses':'sysown/proxysql/.github/workflows/ci-g1.yml@GH-Actions'}}}}
  engines={'ci-g1.yml':{'jobs':{'tier-context':{},'tests':{'needs':['tier-context'],'strategy':{'matrix':{'include':"${{ fromJson(needs.tier-context.outputs.matrices)['tests'] || fromJson('[{}]') }}"}},'steps':[{'run':'python3 ci_tier_runtime.py restore'}, {'run':'export TAP_GROUP=g1\ntest/infra/control/run-tests-isolated.bash'}]}}}}
  return rows,callers,engines
 def test_good_and_missing(self):
  rows,c,e=self.fixture();self.assertEqual(validate_routes(rows,c,e,{'g1'},{'g1'}),[])
  self.assertIn('lower-tier coverage lost: v30/g1',validate_routes([],c,e,{'g1'},{'g1'}))
 def test_manual_does_not_cover_automatic(self):
  rows,c,e=self.fixture();c['CI-g1']['on']={'workflow_dispatch':None}
  self.assertIn('automatic/manual mismatch CI-g1',validate_routes(rows,c,e,{'g1'},{'g1'}))
 def test_unknown_missing_nested_and_duplicate(self):
  rows,c,e=self.fixture();self.assertIn('missing reusable ci-g1.yml',validate_routes(rows,c,{}, {'g1'},{'g1'}))
  self.assertIn('unknown group g1',validate_routes(rows,c,e,{}, {'g1'}))
  self.assertIn("duplicate consumer ('CI-g1', 'run', 'tests')",validate_routes(rows+rows,c,e,{'g1'},{'g1'}))
 def test_version_is_numeric(self):self.assertGreater(version('3.10.0'),version('3.9.0'))
 def test_each_lower_tier_and_executed_group_are_required(self):
  for tier in ['v30','v31']:
   rows,c,e=self.fixture();rows[0]['tiers'].remove(tier)
   self.assertIn('lower-tier coverage lost: '+tier+'/g1',validate_routes(rows,c,e,{'g1'},{'g1'}))
  rows,c,e=self.fixture();e['ci-g1.yml']['jobs']['tests']['steps'][1]['run']='export TAP_GROUP=wrong\ntest/infra/control/run-tests-isolated.bash'
  self.assertIn('lower-tier coverage lost: v30/g1',validate_routes(rows,c,e,{'g1'},{'g1'}))
 def test_disabled_conditions_and_tier_matrix_are_not_coverage(self):
  for tier in ['v30','v31']:
   for where in ['caller','wrapper','job','step','matrix','dependency']:
    with self.subTest(tier=tier,where=where):
     rows,c,e=self.fixture();job=e['ci-g1.yml']['jobs']['tests']
     condition="${{ matrix.tier != '"+tier+"' }}"
     if where=='caller':c['CI-g1']['jobs']['run']['if']='${{ false }}'
     if where=='wrapper':
      c['CI-g1']['jobs']['run']['uses']='./.github/workflows/wrapper.yml'
      e['wrapper.yml']={'jobs':{'run':{'uses':'./.github/workflows/ci-g1.yml','if':'${{ false }}'}}}
     if where=='job':job['if']='${{ false }}'
     if where=='step':job['steps'][1]['if']=condition
     if where=='matrix':job['strategy']['matrix']={'tier':['v40']}
     if where=='dependency':job.pop('needs')
     errors=validate_routes(rows,c,e,{'g1'},{'g1'})
     self.assertIn('lower-tier coverage lost: '+tier+'/g1',errors)
 def test_mode_gating_and_unknown_expressions_fail_closed(self):
  for condition in ["${{ matrix.coverage }}", "${{ matrix.mode == 'normal' }}", '${{ unrecognised() }}']:
   rows,c,e=self.fixture();e['ci-g1.yml']['jobs']['tests']['steps'][1]['if']=condition
   self.assertIn('lower-tier coverage lost: v30/g1',validate_routes(rows,c,e,{'g1'},{'g1'}))
 def unit_fixture(self):
  row=dict(workflow='CI-builds',file='ci-unit-group.yml',job='tier-units',automatic=True,tiers=['v30','v31'],groups=['unit-tests-g1'],cells=[{}])
  callers={'CI-builds':{'on':{'workflow_run':{'workflows':['CI-trigger']}},'jobs':{'run':{'uses':'sysown/proxysql/.github/workflows/ci-builds.yml@GH-Actions'}}}}
  engines={'ci-builds.yml':{'jobs':{'builds':{'needs':['plan'],'strategy':{'matrix':'${{ fromJson(needs.plan.outputs.matrix) }}'},'steps':[{'run':'python3 ci_tier_runtime.py units','env':{'TAP_GROUP':'unit-tests-g1'},'if':"${{ inputs.trusted && success() && matrix.tier != 'v40' }}"}]}}}}
  return [row],callers,engines
 def test_unit_route_requires_automatic_execution_and_group(self):
  rows,c,e=self.unit_fixture();self.assertEqual(validate_routes(rows,c,e,{'unit-tests-g1'},{'unit-tests-g1'}),[])
  for what in ['caller','catalogue','condition','group','matrix']:
   rows,c,e=self.unit_fixture();job=e['ci-builds.yml']['jobs']['builds']
   if what=='caller':c['CI-builds']['on']={'workflow_dispatch':None}
   if what=='catalogue':rows[0]['automatic']=False
   if what=='condition':job['steps'][0]['if']='${{ false }}'
   if what=='group':job['steps'][0]['env']['TAP_GROUP']='wrong'
   if what=='matrix':job['strategy']['matrix']={'tier':['v40']}
   self.assertIn('lower-tier coverage lost: v30/unit-tests-g1',validate_routes(rows,c,e,{'unit-tests-g1'},{'unit-tests-g1'}),what)
if __name__=='__main__':unittest.main()
