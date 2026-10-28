"""Keep diagnostics reachable when infrastructure or a test consumes its deadline."""
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]
DIAGNOSTICS_ACTION = './ci-control/.github/actions/infrastructure-diagnostics'


def infrastructure_jobs():
    for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
        workflow = yaml.safe_load(path.read_text())
        for name, job in workflow.get('jobs', {}).items():
            steps = job.get('steps', [])
            runs = '\n'.join(step.get('run', '') for step in steps)
            if steps and (any(marker in runs for marker in
                              ('ensure-infras.bash', 'destroy-infras.bash', 'stop-proxysql-isolated.bash'))
                          or path.name.startswith('ci-3p-')
                          or any(step.get('name') == 'Cleanup sandbox' for step in steps)):
                yield path.name, name, job


def diagnostics_index(steps, phase):
    return next(index for index, step in enumerate(steps)
                if step.get('uses') == DIAGNOSTICS_ACTION
                and step.get('with', {}).get('phase') == phase)


class InfrastructureWorkflowBudgetTests(unittest.TestCase):
    def test_test_execution_releases_the_job_within_90_minutes(self):
        for workflow, name, job in infrastructure_jobs():
            for step in job['steps']:
                if not step.get('name', '').startswith('Run '):
                    continue
                with self.subTest(workflow=workflow, job=name, step=step['name']):
                    self.assertLessEqual(step.get('timeout-minutes', float('inf')), 90)

    def test_every_step_through_diagnostics_upload_has_a_deadline(self):
        for workflow, name, job in infrastructure_jobs():
            steps = job['steps']
            upload = diagnostics_index(steps, 'upload')
            for step in steps[:upload + 1]:
                with self.subTest(workflow=workflow, job=name, step=step.get('name')):
                    timeout = step.get('timeout-minutes')
                    self.assertIs(type(timeout), int, 'an unbounded step can exhaust the job before diagnostics')
                    self.assertGreater(timeout, 0)

    def test_job_budget_covers_all_deadlines_through_upload_with_shutdown_margin(self):
        for workflow, name, job in infrastructure_jobs():
            with self.subTest(workflow=workflow, job=name):
                upload = diagnostics_index(job['steps'], 'upload')
                deadlines = [step.get('timeout-minutes') for step in job['steps'][:upload + 1]]
                self.assertTrue(all(type(timeout) is int and timeout > 0 for timeout in deadlines),
                                'cannot reserve diagnostics time while preceding steps are unbounded')
                # Include setup/checkouts/pulls and any report steps before capture.
                # Five additional minutes cover runner step cancellation/termination.
                self.assertGreaterEqual(job['timeout-minutes'], sum(deadlines) + 5)

    def test_teardown_cannot_consume_the_upload_budget(self):
        for workflow, name, job in infrastructure_jobs():
            steps = job['steps']
            capture = diagnostics_index(steps, 'capture')
            upload = diagnostics_index(steps, 'upload')
            with self.subTest(workflow=workflow, job=name):
                self.assertEqual(steps[capture]['if'], '${{ !cancelled() }}')
                self.assertEqual(steps[upload]['if'], '${{ !cancelled() }}')
                for index, step in enumerate(steps):
                    run = step.get('run', '')
                    if not (any(marker in run for marker in
                                ('destroy-infras.bash', 'stop-proxysql-isolated.bash', 'dbdeployer delete'))
                            or step.get('name') == 'Cleanup sandbox'):
                        continue
                    self.assertLess(capture, index)
                    self.assertLess(index, upload)
                    self.assertEqual(step['if'], 'always()')
                    self.assertLessEqual(step.get('timeout-minutes', float('inf')), 2,
                                         'hung cleanup must release the following upload step')


if __name__ == '__main__':
    unittest.main()
