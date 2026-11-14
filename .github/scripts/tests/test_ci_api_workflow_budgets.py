"""Workflow deadlines must leave API recovery and the existing work enough time."""
from pathlib import Path
import re
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]
API_STEP_MINUTES = 30  # Twenty minutes of retry waits plus requests and processing.
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

    def test_build_wait_keeps_its_four_hour_envelope(self):
        found = False
        for workflow, name, job in workflows():
            for step in job.get('steps', []):
                if 'wait-build' not in RUNTIME_COMMAND.findall(step.get('run', '')):
                    continue
                found = True
                with self.subTest(workflow=workflow, job=name):
                    self.assertGreaterEqual(job.get('timeout-minutes', 360), 240)
                    self.assertGreaterEqual(step.get('timeout-minutes', job.get('timeout-minutes', 360)), 240)
        self.assertTrue(found, 'the trigger must retain its producer build wait')


if __name__ == '__main__':
    unittest.main()
