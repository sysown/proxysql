import copy,unittest
from check_ci_tier_fanout import validate_routes, version
from ci_tier_conditions import condition_allows
class RouteTests(unittest.TestCase):
 def fixture(self):
  rows=[dict(workflow='CI-g1',file='ci-g1.yml',job='tests',instance='run',automatic=True,tiers=['v40','v30','v31'],groups=['g1'],cells=[{}])]
  callers={'CI-g1':{'on':{'workflow_run':{'workflows':['CI-trigger']}},'jobs':{'run':{'uses':'sysown/proxysql/.github/workflows/ci-g1.yml@GH-Actions'}}}}
  engines={'ci-g1.yml':{'jobs':{'tier-context':{},'tests':{'needs':['tier-context'],'strategy':{'matrix':{'include':"${{ fromJson(needs.tier-context.outputs.matrices)['tests'] || fromJson('[{}]') }}"}},'steps':[{'run':'python3 ci_tier_runtime.py restore'}, {'run':'export TAP_GROUP=g1\ntest/infra/control/run-tests-isolated.bash'}]}}}}
  engines['ci-g1.yml']['jobs']['tier-context']={'uses':'./.github/workflows/ci-tier-context.yml','with':{'consumer_file':'ci-g1.yml'}}
  engines['ci-tier-context.yml']={'on':{'workflow_call':{'outputs':{'matrices':{'value':'${{ jobs.context.outputs.matrices }}'}}}},'jobs':{'context':{'outputs':{'matrices':'${{ steps.context.outputs.matrices }}'},'steps':[{'id':'context','run':'python3 ci-control/.github/scripts/ci_tier_runtime.py consumer','env':{'CONSUMER_FILE':'${{ inputs.consumer_file }}'}}]}}}
  return rows,callers,engines
 def test_good_and_missing(self):
  rows,c,e=self.fixture();self.assertEqual(validate_routes(rows,c,e,{'g1'},{'g1'}),[])
  self.assertIn('lower-tier coverage lost: v30/g1',validate_routes([],c,e,{'g1'},{'g1'}))
 def test_manual_does_not_cover_automatic(self):
  rows,c,e=self.fixture();c['CI-g1']['on']={'workflow_dispatch':None}
  self.assertIn('automatic/manual mismatch CI-g1',validate_routes(rows,c,e,{'g1'},{'g1'}))
 def test_external_manual_consumer_needs_no_local_caller(self):
  """External manual consumers may omit a caller in this repository."""
  rows,_,e=self.fixture()
  rows[0]['automatic']=False
  self.assertEqual(validate_routes(rows,{},e,{'g1'},set()),[])
 def test_external_manual_consumer_still_validates_reusable_contract(self):
  """A missing caller must not hide a broken reusable consumer."""
  for mutation,expected in [
   ('workflow','missing reusable ci-g1.yml'),
   ('job','missing consumer job ci-g1.yml/tests'),
   ('context','missing tier context ci-g1.yml'),
   ('matrix',"consumer matrix bypasses selected tiers: ('CI-g1', 'run', 'tests')"),
   ('execution',"group-less consumer lacks a valid execution_step: ('CI-g1', 'run', 'tests')"),
  ]:
   with self.subTest(mutation=mutation):
    rows,_,e=self.fixture()
    rows[0]['automatic']=False
    if mutation=='workflow':
     del e['ci-g1.yml']
    if mutation=='job':
     del e['ci-g1.yml']['jobs']['tests']
    if mutation=='context':
     del e['ci-g1.yml']['jobs']['tier-context']
    if mutation=='matrix':
     e['ci-g1.yml']['jobs']['tests']['strategy']['matrix']={'tier':['v40']}
    if mutation=='execution':
     rows[0]['groups']=[]
    self.assertIn(expected,validate_routes(rows,{},e,{'g1'},set()))
 def test_automatic_consumer_still_requires_local_caller(self):
  """Automatic catalogue entries require a local trigger."""
  rows,_,e=self.fixture()
  self.assertIn('missing caller CI-g1',validate_routes(rows,{},e,{'g1'},set()))
 def test_external_manual_execution_step_must_exist_and_do_work(self):
  """A declared execution step must name an actual command or action."""
  for content in [{'run':'run-tests'}, {'uses':'owner/action@v1'}]:
   for mutation in ['missing','renamed','empty','whitespace']:
    with self.subTest(content=content,mutation=mutation):
     rows,_,e=self.fixture()
     rows[0].update(automatic=False,groups=[],execution_step='Run suite')
     step=dict(name='Run suite',**content)
     e['ci-g1.yml']['jobs']['tests']['steps']=[step]
     self.assertEqual(validate_routes(rows,{},e,{'g1'},set()),[])
     if mutation=='missing':
      e['ci-g1.yml']['jobs']['tests']['steps']=[]
     if mutation=='renamed':
      step['name']='Wrong name'
     if mutation=='empty':
      step.pop(next(iter(content)))
     if mutation=='whitespace':
      step[next(iter(content))]='   '
     self.assertIn("consumer execution step missing or empty: ('CI-g1', 'run', 'tests')",validate_routes(rows,{},e,{'g1'},set()))
 def test_external_manual_consumer_does_not_supply_migrated_coverage(self):
  """External manual suites cannot replace automatic tier coverage."""
  rows,_,e=self.fixture()
  rows[0]['automatic']=False
  errors=validate_routes(rows,{},e,{'g1'},{'g1'})
  for tier in ['v30','v31']:
   self.assertIn('lower-tier coverage lost: '+tier+'/g1',errors)
 def test_local_manual_caller_still_validates_its_route(self):
  """Local manual callers must reach the catalogued reusable workflow."""
  rows,c,e=self.fixture()
  rows[0]['automatic']=False
  c['CI-g1']['on']={'workflow_dispatch':None}
  self.assertEqual(validate_routes(rows,c,e,{'g1'},set()),[])
  c['CI-g1']['jobs']['run']['uses']='./.github/workflows/missing.yml'
  self.assertIn('missing reusable missing.yml',validate_routes(rows,c,e,{'g1'},set()))
 def test_local_manual_caller_still_validates_execution(self):
  """Local manual routes must execute their promised test groups."""
  rows,c,e=self.fixture()
  rows[0]['automatic']=False
  c['CI-g1']['on']={'workflow_dispatch':None}
  e['ci-g1.yml']['jobs']['tests']['steps'][1]['if']='${{ false }}'
  self.assertTrue(any(error.startswith('group not executed by ') for error in validate_routes(rows,c,e,{'g1'},set())))
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
  for condition in ["${{ !matrix.coverage }}", "${{ matrix.mode == 'normal' }}", '${{ unrecognised() }}']:
   rows,c,e=self.fixture();e['ci-g1.yml']['jobs']['tests']['steps'][1]['if']=condition
   self.assertIn('lower-tier coverage lost: v30/g1',validate_routes(rows,c,e,{'g1'},{'g1'}))
 def test_group_less_consumers_must_execute_on_every_selected_tier(self):
  for mutation in ['disabled','missing','empty']:
   rows,c,e=self.fixture();rows[0]['groups']=[];rows[0]['execution_step']='Run directory suite'
   step=e['ci-g1.yml']['jobs']['tests']['steps'][1]
   step.update(name='Run directory suite',run='docker compose run --rm build run-unit-tests-asan-coverage.bash')
   self.assertEqual(validate_routes(rows,c,e,{'g1'},set()),[])
   if mutation=='disabled':step['if']="${{ matrix.tier == 'v40' }}"
   if mutation=='missing':step['name']='Wrong step'
   if mutation=='empty':step.pop('run')
   self.assertTrue(validate_routes(rows,c,e,{'g1'},set()),mutation)
 def test_group_less_consumers_require_a_named_execution_contract(self):
  for value in [None, '', '   ', 123]:
   for unnamed_step in [{'run':'python3 ci_tier_runtime.py restore'}, {'uses':'actions/checkout@v4'}]:
    with self.subTest(value=value,step=unnamed_step):
     rows,c,e=self.fixture();rows[0]['groups']=[]
     if value is not None:rows[0]['execution_step']=value
     e['ci-g1.yml']['jobs']['tests']['steps']=[unnamed_step]
     errors=validate_routes(rows,c,e,{'g1'},set())
     self.assertIn("group-less consumer lacks a valid execution_step: ('CI-g1', 'run', 'tests')",errors)
 def test_instrumentation_is_the_same_for_every_tier(self):
  for tier in ['v30','v31','v40']:
   self.assertTrue(condition_allows('matrix.coverage',tier,'normal'))
 def test_a_producer_unit_side_path_is_not_a_consumer(self):
  rows,c,e=self.fixture();rows[0].update(workflow='CI-builds',file='ci-builds.yml',job='tier-units')
  c['CI-builds']=c.pop('CI-g1')
  c['CI-builds']['jobs']['run']['uses']='./.github/workflows/ci-builds.yml'
  e['ci-builds.yml']=e.pop('ci-g1.yml');jobs=e['ci-builds.yml']['jobs']
  jobs['tier-context']['with']['consumer_file']='ci-builds.yml'
  jobs['tier-units']=jobs.pop('tests')
  jobs['tier-units']['strategy']['matrix']['include']="${{ fromJson(needs.tier-context.outputs.matrices)['tier-units'] || fromJson('[{}]') }}"
  self.assertEqual(validate_routes(rows,c,e,{'g1'},{'g1'}),[])
  # A producer side path running the same group cannot substitute for a
  # consumer whose matrix comes from the selected-tier execution contract.
  jobs['tier-units']['strategy']['matrix']={'tier':['v30','v31','v40']}
  self.assertEqual(validate_routes(rows,c,e,{'g1'},{'g1'}),[
   "consumer matrix bypasses selected tiers: ('CI-builds', 'run', 'tier-units')",
   'lower-tier coverage lost: v30/g1', 'lower-tier coverage lost: v31/g1'])
 def test_group_less_matrix_failures_report_only_the_source_for_each_cell(self):
  for condition in ['${{ false }}', "${{ matrix.mode == 'normal' }}"]:
   with self.subTest(condition=condition):
    rows,c,e=self.fixture();rows[0]['groups']=[];rows[0]['execution_step']='Run suite'
    e['ci-g1.yml']['jobs']['tests']['steps'][1]['name']='Run suite'
    self.assertEqual(validate_routes(rows,c,e,{'g1'},set()),[])
    e['ci-tier-context.yml']['jobs']['context']['steps'][0]['if']=condition
    errors=validate_routes(rows,c,e,{'g1'},set())
    modes=['normal','asan'] if condition=='${{ false }}' else ['asan']
    self.assertEqual(errors,[
     "matrix output source is disabled or miswired: ('CI-g1', 'run', 'tests') on "+tier+'/'+mode
     for tier in ['v40','v30','v31'] for mode in modes])
 def test_group_less_disabled_job_remains_an_execution_failure(self):
  rows,c,e=self.fixture();rows[0]['groups']=[];rows[0]['execution_step']='Run suite'
  e['ci-g1.yml']['jobs']['tests']['steps'][1]['name']='Run suite'
  e['ci-g1.yml']['jobs']['tests']['if']='${{ false }}'
  # Source failures affect ASAN only; the disabled job must still be diagnosed
  # on normal cells, where a valid source does not prove suite execution.
  e['ci-tier-context.yml']['jobs']['context']['steps'][0]['if']="${{ matrix.mode == 'normal' }}"
  errors=validate_routes(rows,c,e,{'g1'},set())
  for tier in ['v40','v30','v31']:
   self.assertIn("consumer execution missing or disabled: ('CI-g1', 'run', 'tests') on "+tier+'/normal',errors)
   self.assertIn("matrix output source is disabled or miswired: ('CI-g1', 'run', 'tests') on "+tier+'/asan',errors)
  self.assertEqual(len(errors),6)
 def test_negation_with_comparisons_fails_closed(self):
  for gate in ["!matrix.tier == 'v40'", "!matrix.tier != 'v30'", "!(matrix.tier) == 'v40'"]:
   with self.subTest(gate=gate):
    with self.assertRaisesRegex(ValueError,'negation.*comparison'):
     condition_allows(gate,'v30','normal')
  self.assertTrue(condition_allows('!cancelled()','v30','normal'))
  self.assertTrue(condition_allows("!cancelled() && matrix.tier != 'v40'",'v30','normal'))
  self.assertFalse(condition_allows('!matrix.coverage','v40','normal'))
 def test_matrix_output_chain_must_be_enabled_and_wired(self):
  for what in ['disabled-call','wrong-callee','wrong-file','workflow-output','job-output','disabled-job','disabled-step','wrong-command','missing-step','missing-env']:
   with self.subTest(what=what):
    rows,c,e=self.fixture(); call=e['ci-g1.yml']['jobs']['tier-context']
    shared=e['ci-tier-context.yml']; job=shared['jobs']['context']; step=job['steps'][0]
    if what=='disabled-call':call['if']='${{ false }}'
    if what=='wrong-callee':call['uses']='./.github/workflows/other.yml'
    if what=='wrong-file':call['with']['consumer_file']='ci-wrong.yml'
    if what=='workflow-output':shared['on']['workflow_call']['outputs']['matrices']['value']='{}'
    if what=='job-output':job['outputs']['matrices']='{}'
    if what=='disabled-job':job['if']='${{ false }}'
    if what=='disabled-step':step['if']='${{ false }}'
    if what=='wrong-command':step['run']='echo no matrix'
    if what=='missing-step':job['steps']=[]
    if what=='missing-env':step['env']={}
    self.assertIn('lower-tier coverage lost: v30/g1',validate_routes(rows,c,e,{'g1'},{'g1'}))
 def dependency_fixture(self, location):
  rows,c,e=self.fixture(); groups={'g1'}
  if location=='context':jobs=e['ci-tier-context.yml']['jobs']; job=jobs['context']
  elif location=='call':jobs=e['ci-g1.yml']['jobs']; job=jobs['tier-context']
  elif location=='tests':jobs=e['ci-g1.yml']['jobs']; job=jobs['tests']
  elif location=='wrapper':
   c['CI-g1']['jobs']['run']['uses']='./.github/workflows/wrapper.yml'
   e['wrapper.yml']={'jobs':{'run':{'uses':'./.github/workflows/ci-g1.yml'}}}
   jobs=e['wrapper.yml']['jobs'];job=jobs['run']
  else:jobs=c['CI-g1']['jobs']; job=jobs['run']
  jobs['blocked']={'if':'${{ false }}','steps':[{'run':'true'}]}
  job['needs']=job.get('needs',[])+['blocked']
  return rows,c,e,groups,jobs,job
 def test_skipped_dependencies_remove_coverage_at_every_boundary(self):
  for location in ['context','call','tests','caller','wrapper']:
   for condition in [None, '${{ true }}', '${{ success() }}', "${{ needs.blocked.result == 'skipped' }}", "${{ contains('always()', 'always') }}"]:
    with self.subTest(location=location,condition=condition):
     rows,c,e,groups,jobs,job=self.dependency_fixture(location)
     if condition is not None:job['if']=condition
     errors=validate_routes(rows,c,e,groups,groups)
     for tier in ['v30','v31']:
      self.assertIn('lower-tier coverage lost: '+tier+'/'+next(iter(groups)), errors)
 def test_status_overrides_can_run_after_skipped_dependency(self):
  for location in ['context','call','tests','caller','wrapper']:
   for condition in ['${{ always() }}', '${{ !cancelled() }}', "${{ always() && needs.blocked.result == 'skipped' }}"]:
    with self.subTest(location=location,condition=condition):
     rows,c,e,groups,jobs,job=self.dependency_fixture(location);job['if']=condition
     self.assertEqual(validate_routes(rows,c,e,groups,groups),[])
 def test_transitive_missing_and_cyclic_dependencies_fail_closed(self):
  for mutation in ['transitive','missing','cycle']:
   rows,c,e,groups,jobs,job=self.dependency_fixture('context')
   if mutation=='transitive':
    jobs['middle']={'needs':'blocked','steps':[{'run':'true'}]};job['needs']='middle'
   if mutation=='missing':job['needs']='missing';job['if']='${{ always() }}'
   if mutation=='cycle':jobs['blocked']['needs']='context';job['if']='${{ always() }}'
   self.assertIn('lower-tier coverage lost: v30/g1',validate_routes(rows,c,e,groups,groups))
 def test_status_checks_do_not_turn_skips_into_failures(self):
  for condition in ['${{ failure() }}','${{ cancelled() }}','${{ always() && success() }}', "${{ always() && needs.blocked.result == 'success' }}"]:
   rows,c,e,groups,jobs,job=self.dependency_fixture('context');job['if']=condition
   self.assertIn('lower-tier coverage lost: v30/g1',validate_routes(rows,c,e,groups,groups))
if __name__=='__main__':unittest.main()
