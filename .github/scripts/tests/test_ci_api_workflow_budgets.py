"""Workflow deadlines must leave API recovery and the existing work enough time."""
from pathlib import Path
import re
import sys
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / '.github/scripts'))
import ci_tier_runtime as runtime
API_STEP_MINUTES = 30  # Twenty minutes of retry waits plus requests and processing.
RESTORE_STEP_MINUTES = 60  # Shared API recovery plus the existing transfer window.
RUNTIME_COMMAND = re.compile(r'ci_tier_runtime\.py\s+(\S+)')


def workflows():
    for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
        for name, job in yaml.safe_load(path.read_text()).get('jobs', {}).items():
            yield path.name, name, job


def api_steps(job):
    for step in job.get('steps', []):
        run = step.get('run', '')
        commands = RUNTIME_COMMAND.findall(run)
        if ('ci_cancel_superseded.py' in run
                or any(command != 'wait-build' for command in commands)):
            yield step


class ApiWorkflowBudgetTests(unittest.TestCase):
    def test_api_steps_allow_retry_waits_and_request_processing(self):
        for workflow, name, job in workflows():
            for step in api_steps(job):
                with self.subTest(workflow=workflow, job=name, step=step.get('name')):
                    self.assertGreaterEqual(step.get('timeout-minutes', 0), API_STEP_MINUTES,
                                            'API recovery needs an explicit step deadline')

    def test_restore_preserves_transfer_time_after_api_recovery(self):
        for workflow, name, job in workflows():
            for step in api_steps(job):
                commands = RUNTIME_COMMAND.findall(step.get('run', ''))
                if not {'restore', 'restore-unit'}.intersection(commands):
                    continue
                with self.subTest(workflow=workflow, job=name, step=step.get('name')):
                    self.assertGreaterEqual(step.get('timeout-minutes', 0),
                                            RESTORE_STEP_MINUTES,
                                            'API recovery must leave the transfer window intact')

    def test_preceding_steps_cannot_starve_terminal_check_publication(self):
        for workflow, name, job in workflows():
            steps = job.get('steps', [])
            completion = next((i for i, step in enumerate(steps)
                               if step.get('name') == 'Complete selected product test check'), None)
            if completion is None:
                continue
            for step in steps[:completion + 1]:
                with self.subTest(workflow=workflow, job=name, step=step.get('name')):
                    self.assertGreater(step.get('timeout-minutes', 0), 0,
                                       'every phase before terminal publication needs a deadline')
            with self.subTest(workflow=workflow, job=name):
                self.assertGreaterEqual(steps[completion].get('timeout-minutes', 0),
                                        API_STEP_MINUTES)

    def test_parent_jobs_allow_all_step_deadlines_and_cleanup_margin(self):
        for workflow, name, job in workflows():
            if not list(api_steps(job)):
                continue
            with self.subTest(workflow=workflow, job=name):
                self.assertGreaterEqual(job.get('timeout-minutes', 360),
                                        sum(step.get('timeout-minutes', 0)
                                            for step in job.get('steps', [])) + 5,
                                        'the parent must leave every bounded phase time to finish')
                self.assertLessEqual(job.get('timeout-minutes', 360), 360)

    def test_coordination_steps_preserve_artifact_handoff_time(self):
        for workflow, name, job in workflows():
            if workflow not in {'ci-tier-context.yml', 'ci-tier-summary.yml',
                                'ci-tier-selection.yml'}:
                continue
            for step in job.get('steps', []):
                with self.subTest(workflow=workflow, job=name, step=step.get('name')):
                    self.assertGreater(step.get('timeout-minutes', 0), 0,
                                       'coordination checkout and artifact handoff need deadlines')

    def test_job_budget_preserves_existing_work_and_reporting(self):
        # Work reserved before increasing API deadlines. Retain the full previous
        # job envelope, subtracting only API steps that already had a deadline.
        reserves = {
            ('ci-builds.yml', 'builds'): 120,
            ('ci-maketest.yml', 'builds'): 120,
            ('ci-unit-tests-tsan.yml', 'unit-tests-tsan'): 120,
            ('ci-unit-tests-asan-coverage.yml', 'unit-tests'): 120,
            ('ci-unittests.yml', 'tests'): 120,
            ('ci-unit-group.yml', 'tests'): 120,
            ('ci-selftests.yml', 'tests'): 118,
            ('ci-shuntest.yml', 'tests'): 45,
            ('ci-repltests.yml', 'tests'): 45,
        }
        for workflow, name, job in workflows():
            steps = list(api_steps(job))
            if not steps:
                continue
            diagnostics = any('infrastructure-diagnostics' in step.get('uses', '')
                              for step in job.get('steps', []))
            reserve = reserves.get((workflow, name))
            if diagnostics and reserve is None:
                reserve = 208 if (workflow, name) == ('ci-mysqlx.yml', 'e2e-tests') else 168
            with self.subTest(workflow=workflow, job=name):
                required = sum(step.get('timeout-minutes', 0) for step in steps)
                # Coordination jobs also need checkout and artifact handoff time.
                required += reserve if reserve is not None else 5
                self.assertGreaterEqual(job.get('timeout-minutes', 360), required,
                                        'API waits must not consume the existing work budget')

    def test_infrastructure_can_finish_diagnostics_and_report_after_api_waits(self):
        for workflow, name, job in workflows():
            if not any('infrastructure-diagnostics' in step.get('uses', '')
                       for step in job.get('steps', [])):
                continue
            with self.subTest(workflow=workflow, job=name):
                # Completion reporting follows diagnostics upload and needs its
                # own recovery window even when the preceding work times out.
                deadlines = [step.get('timeout-minutes', 0) for step in job['steps']]
                self.assertGreaterEqual(job['timeout-minutes'], sum(deadlines) + 5)

    def test_build_wait_outlasts_the_entire_producer_pipeline(self):
        producer = yaml.safe_load((ROOT / '.github/workflows/ci-builds.yml').read_text())['jobs']
        for phase in ('plan', 'builds', 'finalize'):
            self.assertIn('timeout-minutes', producer[phase], 'each producer phase needs a finite envelope')
        pipeline = sum(producer[phase].get('timeout-minutes', 360) for phase in ('plan', 'builds', 'finalize'))
        self.assertGreaterEqual(runtime.PRODUCER_WAIT_SECONDS, (pipeline+4)*60,
                                'waiter must cover all producer phases and maximum polling delay')
        trigger = yaml.safe_load((ROOT / '.github/workflows/ci-trigger.yml').read_text())['jobs']['trigger']
        wait = next(step for step in trigger['steps'] if 'wait-build' in RUNTIME_COMMAND.findall(step.get('run', '')))
        self.assertGreaterEqual(wait.get('timeout-minutes', 0)*60, runtime.PRODUCER_WAIT_SECONDS)
        self.assertTrue(all('timeout-minutes' in step for step in trigger['steps']))
        self.assertGreaterEqual(trigger['timeout-minutes'], sum(step['timeout-minutes'] for step in trigger['steps'])+5)


if __name__ == '__main__':
    unittest.main()
