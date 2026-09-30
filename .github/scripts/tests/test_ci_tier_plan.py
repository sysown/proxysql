import itertools
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ci_tier_plan import resolve_selection, make_plan, consumer_matrix, validate_manifest, applicable_tests

class SelectionTests(unittest.TestCase):
    def context(self):
        return dict(repository='sysown/proxysql', sha='a'*40, trigger_id=12,
                    trigger_attempt=1, build_id=34, build_attempt=1,
                    control_sha='b'*40, event='pull_request', pull_requests=[{'number':42}])

    def test_eight_combinations(self):
        for v30,v31,asan in itertools.product([False,True], repeat=3):
            labels=[n for n,b in [('ci:v3.0',v30),('ci:v3.1',v31),('ci:asan',asan)] if b]
            fetch=Mock(return_value={'labels':[{'name':n} for n in labels]})
            got=resolve_selection(self.context(),True,fetch)
            self.assertEqual(got['tiers'],['v40']+(['v30'] if v30 else [])+(['v31'] if v31 else []))
            self.assertEqual(got['mode'],'asan' if asan else 'normal')
            fetch.assert_called_once_with(42)

    def test_exact_and_deduplicated(self):
        fetch=Mock(return_value={'labels':[{'name':n} for n in ['ci:v3.0-extra','ci:asan-extra','ci:v3.1','ci:v3.1']]})
        self.assertEqual(resolve_selection(self.context(),True,fetch)['tiers'],['v40','v31'])

    def test_non_pr_and_untrusted_never_query(self):
        for event,trusted in [('push',True),('workflow_dispatch',True),('pull_request',False)]:
            c=self.context(); c['event']=event
            fetch=Mock(side_effect=AssertionError('must not query'))
            self.assertEqual(resolve_selection(c,trusted,fetch)['tiers'],['v40'])
            fetch.assert_not_called()

    def test_association_and_api_failure_are_errors(self):
        for prs in [[],[{'number':1},{'number':2}],[{}]]:
            c=self.context();c['pull_requests']=prs
            with self.assertRaises(ValueError): resolve_selection(c,True,Mock())
        with self.assertRaises(RuntimeError):
            resolve_selection(self.context(),True,Mock(side_effect=RuntimeError('API failed')))

    def test_plan_identity_and_consumer_axes(self):
        cat={'consumers':[{'workflow':'CI-example','file':'ci-example.yml','job':'tests','automatic':True,'tiers':['v40','v30','v31'],'groups':['g1'],'cells':[{'infradb':'mysql84'},{'infradb':'mysql57'}]},
                          {'workflow':'CI-manual','file':'ci-manual.yml','job':'tests','automatic':False,'tiers':['v40'],'groups':[],'cells':[{}]}]}
        p=make_plan(self.context(),{'tiers':['v40','v30'],'mode':'asan','pr_number':42},cat)
        self.assertEqual(p['execution_id'],'t12-a1-b34-a1')
        self.assertEqual(len(p['checks']),6) # two builds, four tests; manual excluded
        self.assertEqual(len(consumer_matrix(p,'CI-example','tests')),4)
        self.assertTrue(all(leg['coverage'] for leg in p['legs']))
        self.assertTrue(all(cell['coverage'] for cell in consumer_matrix(p,'CI-example','tests')))
        self.assertNotEqual(p['legs'][0]['artifact_name'],p['legs'][1]['artifact_name'])
        validate_manifest(p)
        p['schema']=900
        with self.assertRaises(ValueError):validate_manifest(p)

    def test_variable_names_follow_github_case_insensitivity(self):
        c=self.context();c['variables']={'MATRIX_MYSQL':"[ 'mysql84' ]"}
        cat={'consumers':[dict(workflow='CI-example',file='ci-example.yml',job='tests',automatic=True,tiers=['v40'],groups=[],cells=[],axes={'infradb':{'var':'MATRIX_mysql'}},instance='run')]}
        plan=make_plan(c,dict(tiers=['v40'],mode='normal',pr_number=42),cat)
        self.assertEqual(plan['checks'][1]['cell']['infradb'],'mysql84')

    def test_feature_applicability_does_not_claim_an_unexecuted_tap_group(self):
        row=dict(workflow='CI-plugin',file='ci-plugin.yml',job='e2e',automatic=True,
                 tiers=['v40','v30','v31'],groups=[],applicability_groups=['plugin-g1'],cells=[{}])
        plan=make_plan(self.context(),dict(tiers=['v40','v30','v31'],mode='normal'),{'consumers':[row]})
        checks=[check for check in plan['checks'] if check['workflow']=='CI-plugin']
        self.assertEqual(len(checks),3)
        self.assertTrue(all(check['groups']==['plugin-g1'] for check in checks))

    def test_repository_short_minimum_version_tags(self):
        groups={'core-t':['g1'],'innovative-t':['g1','@proxysql_min_version:3.1'],'plugin-t':['g1','@proxysql_min_version:4.0']}
        self.assertEqual(applicable_tests(groups,'g1','3.0.12'),['core-t'])
        self.assertEqual(applicable_tests(groups,'g1','3.1.12'),['core-t','innovative-t'])
        self.assertEqual(applicable_tests(groups,'g1','4.0.12'),sorted(groups))

if __name__=='__main__':unittest.main()
