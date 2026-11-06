"""Exercise actual upload conditions, including every paired engine retry."""
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import yaml

from ci_tier_conditions import FUNCTIONS, condition_allows


ROOT = Path(__file__).resolve().parents[3]
REPOSITORY = 'sysown/proxysql'


def workflows():
    for path in sorted((ROOT / '.github/workflows').rglob('*.yml')):
        yield str(path.relative_to(ROOT)), yaml.safe_load(path.read_text())
    # CI lint resolves this ref for its existing paired workflow checks. Read
    # it as data; never execute scripts from the selected engine revision.
    ref = os.environ.get('CI_ENGINE_REF')
    if ref and subprocess.run(
            ['git', 'rev-parse', '--verify', '--quiet', ref], cwd=ROOT,
            stdout=subprocess.DEVNULL).returncode:
        print(f'Paired Codecov conditions: SKIPPED ({ref} not fetched)')
        return
    if ref:
        paths = subprocess.check_output(
            ['git', 'ls-tree', '-r', '--name-only', ref, '.github/workflows'],
            cwd=ROOT, text=True).splitlines()
        for path in paths:
            if path.endswith(('.yml', '.yaml')):
                content = subprocess.check_output(
                    ['git', 'show', f'{ref}:{path}'], cwd=ROOT, text=True)
                yield f'{ref}:{path}', yaml.safe_load(content)


def allows(step, event, coverage_file=True, **overrides):
    context = {
        'github.repository': REPOSITORY,
        'github.event.pull_request': None,
        'github.event.pull_request.head.repo.full_name': '',
        'github.event.workflow_run': None,
        'github.event.workflow_run.head_repository.full_name': '',
        'steps.require-lcov.outcome': 'success',
        'steps.require_lcov.outcome': 'success',
        'steps.cov.outputs.found': '1',
        'steps.coverage.outputs.available': 'true',
        # Exercise retries independently, even if an earlier attempt failed.
        'steps.codecov_1.outcome': 'failure',
        'steps.codecov_2.outcome': 'failure',
    }
    context.update(event)
    context.update(overrides)
    with patch.dict(FUNCTIONS, hashfiles=lambda *_: 'lcov-hash' if coverage_file else ''):
        return condition_allows(step.get('if'), 'v30', 'coverage', event_context=context)


def pr(repository):
    return {'github.event.pull_request': True,
            'github.event.pull_request.head.repo.full_name': repository}


def upstream(repository):
    return {'github.event.workflow_run': True,
            'github.event.workflow_run.head_repository.full_name': repository}


class CodecovForkUploads(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.uploads = []
        for path, workflow in workflows():
            for job_name, job in (workflow or {}).get('jobs', {}).items():
                for step in job.get('steps', []):
                    if str(step.get('uses', '')).startswith('codecov/codecov-action@'):
                        cls.uploads.append((path, job_name, step))
        if not cls.uploads:
            raise AssertionError('No Codecov upload steps discovered')

    def test_external_forks_skip_all_upload_attempts(self):
        for path, job, step in self.uploads:
            for event in (pr('contributor/proxysql'), upstream('contributor/proxysql')):
                with self.subTest(workflow=path, job=job, step=step['name'], event=event):
                    self.assertFalse(allows(step, event))

    def test_missing_head_repository_cannot_enable_uploads(self):
        for path, job, step in self.uploads:
            for event in (pr(''), upstream('')):
                with self.subTest(workflow=path, job=job, step=step['name'], event=event):
                    self.assertFalse(allows(step, event))

    def test_internal_and_non_pr_events_keep_uploads(self):
        events = (pr(REPOSITORY), upstream(REPOSITORY),
                  {'github.event_name': 'push'}, {'github.event_name': 'schedule'},
                  {'github.event_name': 'workflow_dispatch'})
        for path, job, step in self.uploads:
            for event in events:
                with self.subTest(workflow=path, job=job, step=step['name'], event=event):
                    self.assertTrue(allows(step, event))

    def test_coverage_and_retry_prerequisites_still_apply(self):
        prerequisites = {
            'matrix.coverage': False,
            'steps.cov.outputs.found': '0',
            'steps.coverage.outputs.available': 'false',
            'steps.require-lcov.outcome': 'failure',
            'steps.require_lcov.outcome': 'failure',
            'steps.codecov_1.outcome': 'success',
            'steps.codecov_2.outcome': 'success',
        }
        for path, job, step in self.uploads:
            for key, value in prerequisites.items():
                if key in step.get('if', ''):
                    with self.subTest(workflow=path, job=job, step=step['name'], prerequisite=key):
                        self.assertFalse(allows(step, pr(REPOSITORY), **{key: value}))
            if 'hashFiles(' in step.get('if', ''):
                with self.subTest(workflow=path, step=step['name'], prerequisite='LCOV absent'):
                    self.assertFalse(allows(step, pr(REPOSITORY), coverage_file=False))
            if '!cancelled()' in step.get('if', ''):
                with self.subTest(workflow=path, step=step['name'], prerequisite='cancelled'):
                    with patch.dict(FUNCTIONS, cancelled=lambda: True):
                        self.assertFalse(allows(step, pr(REPOSITORY)))

    def test_successful_fork_simulator_run_retains_coverage(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/CI-cluster-simulator.yml').read_text())
        job = workflow['jobs']['test']
        self.assertEqual(job['env']['COVERAGE'], '1')
        steps = job['steps']
        self.assertTrue(any(step.get('run') == 'test/infra/control/run-tests-isolated.bash'
                            for step in steps))
        require = next(step for step in steps if step.get('id') == 'require-lcov')
        self.assertTrue(allows(require, pr('contributor/proxysql')))
        artifacts = [step for step in steps
                     if str(step.get('uses', '')).startswith('actions/upload-artifact@')
                     and 'coverage-report' in step.get('with', {}).get('path', '')]
        self.assertTrue(artifacts, 'Retain LCOV even when tests succeed and Codecov is skipped')
        for step in artifacts:
            self.assertTrue(allows(step, pr('contributor/proxysql')))
            self.assertFalse(allows(step, pr('contributor/proxysql'),
                                    **{'steps.require-lcov.outcome': 'failure'}))


if __name__ == '__main__':
    unittest.main()
