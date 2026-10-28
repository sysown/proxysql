"""Long MySQL 8.4 workloads use existing callers and distinct matrix cells."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ci_tier_runtime as runtime
from ci_tier_plan import consumer_matrix, make_plan, validate_manifest

ROOT = Path(__file__).resolve().parents[3]
PARTITIONS = {'mysql84-g1': 'mysql84-g10', 'mysql84-g4': 'mysql84-g11'}


class Mysql84ShardWorkflowTests(unittest.TestCase):
    def catalogue(self):
        document = json.loads((ROOT / '.github/ci-tier-consumers.json').read_text())
        return {'consumers': [row for row in document['consumers']
                              if row['workflow'] in {'CI-' + group for group in PARTITIONS}]}

    def context(self):
        return dict(repository='sysown/proxysql', sha='a' * 40, trigger_id=12,
                    trigger_attempt=1, build_id=34, build_attempt=1,
                    control_sha='b' * 40, event='pull_request', pull_requests=[{'number': 42}])

    def test_all_partitions_are_planned_on_all_tiers_and_modes(self):
        catalogue = self.catalogue()
        self.assertEqual(len(catalogue['consumers']), 2)
        for mode in ('normal', 'asan'):
            plan = make_plan(self.context(), dict(tiers=['v40', 'v30', 'v31'], mode=mode), catalogue)
            validate_manifest(plan)
            for original, added in PARTITIONS.items():
                with self.subTest(mode=mode, group=original):
                    row = next(row for row in catalogue['consumers'] if row['workflow'] == 'CI-' + original)
                    # Older source validators still see their existing caller/group contract.
                    self.assertEqual(row['groups'], [original])
                    self.assertEqual(row['group_axis'], 'tap_group')
                    self.assertTrue(row['automatic'])
                    matrix = consumer_matrix(plan, 'CI-' + original, 'tests')
                    self.assertEqual({(cell['tier'], cell['tap_group']) for cell in matrix},
                                     {(tier, group) for tier in ('v40', 'v30', 'v31') for group in (original, added)})
                    self.assertEqual(len(matrix), 6)
                    self.assertTrue(all(cell['mode'] == mode for cell in matrix))
                    checks = [check for check in plan['checks'] if check['workflow'] == 'CI-' + original]
                    self.assertTrue(all(check['groups'] == [check['cell']['tap_group']] for check in checks))

    def test_group_axis_rejects_missing_or_invalid_group_cells(self):
        row = dict(workflow='CI-test', file='ci-test.yml', job='tests', automatic=True,
                   tiers=['v40'], groups=['test-g1'], group_axis='tap_group')
        for cell in ({}, {'tap_group': None}, {'tap_group': ''}, {'tap_group': ['test-g1']}):
            with self.subTest(cell=cell), self.assertRaises(ValueError):
                make_plan(self.context(), dict(tiers=['v40'], mode='normal'),
                          {'consumers': [dict(row, cells=[cell])]})

    def test_manual_dispatch_preserves_shards_and_can_select_one_group(self):
        for original, added in PARTITIONS.items():
            for selected in (None, original, added):
                with self.subTest(original=original, selected=selected), patch.dict(
                    os.environ, {'CONSUMER_FILE': 'ci-' + original + '.yml'}):
                    rows = runtime.manual_consumer_rows('CI-' + original, 'run',
                                                       {'tap_group': selected} if selected else {})
                    self.assertEqual(len(rows), 1)
                    plan = make_plan(self.context(), dict(tiers=['v31'], mode='normal'), {'consumers': rows})
                    matrix = consumer_matrix(plan, 'CI-' + original, 'tests')
                    self.assertEqual({cell['tap_group'] for cell in matrix},
                                     {selected} if selected else {original, added})

    def test_real_product_stamping_excludes_absent_shards_before_startup(self):
        catalogue = self.catalogue()
        for old_product in (True, False):
            for tier, version in (('v30', '3.0.12'), ('v31', '3.1.12'), ('v40', '4.0.12')):
                for mode in ('normal', 'asan'):
                    with self.subTest(old_product=old_product, tier=tier, mode=mode), tempfile.TemporaryDirectory() as folder:
                        root = Path(folder)
                        product = root / 'proxysql'
                        (product / 'src').mkdir(parents=True)
                        (product / 'test/tap/groups').mkdir(parents=True)
                        selected = set(PARTITIONS) | (set() if old_product else set(PARTITIONS.values()))
                        groups = {group + '-t': [group] for group in selected}
                        (product / 'test/tap/groups/groups.json').write_text(json.dumps(groups))
                        tools = root / 'tools'
                        tools.mkdir()
                        docker = tools / 'docker'
                        docker.write_text('#!/bin/sh\nprintf "ProxySQL version %s\\n" "$FIXTURE_VERSION"\n')
                        docker.chmod(0o755)
                        plan = make_plan(self.context(), dict(tiers=[tier], mode=mode), catalogue)
                        previous = Path.cwd()
                        try:
                            os.chdir(root)
                            with patch.object(runtime, 'read_plan', return_value=plan), patch.dict(os.environ, {
                                'CI_LEG': json.dumps(plan['legs'][0]), 'FIXTURE_VERSION': version,
                                'PATH': str(tools) + os.pathsep + os.environ['PATH'],
                            }):
                                runtime.stamp()
                            metadata = json.loads((product / 'src/ci-tier.json').read_text())
                        finally:
                            os.chdir(previous)
                        plan = copy.deepcopy(plan)
                        for check in plan['checks']:
                            check['applicable'] = metadata['applicable'][check['key']]
                        for original, added in PARTITIONS.items():
                            matrix = consumer_matrix(plan, 'CI-' + original, 'tests')
                            self.assertEqual({cell['tap_group'] for cell in matrix},
                                             {original} if old_product else {original, added})

    def test_actual_workflow_shells_use_disjoint_infrastructure_and_old_manifest_fallback(self):
        for original, added in PARTITIONS.items():
            document = yaml.safe_load((ROOT / '.github/workflows' / ('ci-' + original + '.yml')).read_text())
            job = document['jobs']['tests']
            self.assertEqual(job['timeout-minutes'], 200)
            steps = job['steps']
            phases = [step for step in steps if any(command in step.get('run', '') for command in
                      ('ensure-infras.bash', 'run-tests-isolated.bash', 'destroy-infras.bash'))]
            self.assertEqual(len(phases), 3)
            test = next(step for step in phases if 'run-tests-isolated.bash' in step['run'])
            self.assertEqual(test['timeout-minutes'], 90)
            for selected in ('', original, added):
                for step in phases:
                    with self.subTest(original=original, selected=selected, phase=step['name']), tempfile.TemporaryDirectory() as folder:
                        root = Path(folder)
                        scripts = root / 'proxysql/test/infra/control'
                        scripts.mkdir(parents=True)
                        tools = root / 'tools'
                        tools.mkdir()
                        docker = tools / 'docker'
                        docker.write_text('#!/bin/sh\nexit 0\n')
                        docker.chmod(0o755)
                        for name in ('ensure-infras.bash', 'run-tests-isolated.bash',
                                     'stop-proxysql-isolated.bash', 'destroy-infras.bash'):
                            script = scripts / name
                            script.write_text('#!/bin/sh\nprintf "%s/%s\\n" "$TAP_GROUP" "$INFRA_ID"\n')
                            script.chmod(0o755)
                        body = step['run'].replace('${{ matrix.tap_group }}', selected)
                        body = body.replace('${{ matrix.tier }}', 'v31').replace('${{ github.run_id }}', '123')
                        result = subprocess.run(['bash', '-e', '-c', body], cwd=root, text=True,
                                                capture_output=True, timeout=5,
                                                env=dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH']))
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        group = selected or original
                        self.assertTrue(result.stdout.strip())
                        self.assertEqual(set(result.stdout.splitlines()), {group + '/ci-' + group + '-v31-123'})
            identity = "ci-${{ matrix.tap_group || '" + original + "' }}-${{ matrix.tier }}-${{ github.run_id }}"
            capture = next(step for step in steps if step.get('with', {}).get('phase') == 'capture')
            self.assertEqual(capture['with']['infra-id'], identity)
            for step in steps:
                for key in ('files', 'path'):
                    value = step.get('with', {}).get(key, '')
                    if 'coverage-report/' in value:
                        self.assertIn(identity, value)


if __name__ == '__main__':
    unittest.main()
