"""Cancellation runs from trusted control code for every new PR head and push."""
from pathlib import Path
import json
import os
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]


class CancelSupersededTests(unittest.TestCase):
    def test_catalogued_consumer_callers_allow_head_lookup_and_cancellation(self):
        engine_ref = os.environ.get('CI_ENGINE_REF', 'origin/GH-Actions')
        catalogue = json.loads(subprocess.check_output(
            ['git', 'show', engine_ref + ':.github/ci-tier-consumers.json'], cwd=ROOT))
        consumer_files = {row['file'] for row in catalogue['consumers']}
        consumer_names = {row['workflow'] for row in catalogue['consumers']}
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            workflow = yaml.safe_load(path.read_text())
            for name, job in workflow.get('jobs', {}).items():
                uses = job.get('uses', '')
                if not uses.startswith('sysown/proxysql/.github/workflows/'):
                    continue
                if (uses.rsplit('/', 1)[-1].split('@')[0] not in consumer_files
                        and workflow.get('name') not in consumer_names):
                    continue
                permissions = job.get('permissions', workflow.get('permissions'))
                if permissions == 'write-all':
                    continue
                with self.subTest(workflow=path.name, job=name):
                    self.assertIsInstance(permissions, dict)
                    self.assertEqual(permissions.get('actions'), 'write')
                    self.assertIn(permissions.get('pull-requests'), ('read', 'write'))

    def test_every_pr_update_calls_trusted_cancellation_with_write_permission(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/CI-cancel-superseded.yml').read_text())
        events = workflow.get('on', workflow.get(True, {}))
        self.assertEqual(events['pull_request_target'],
                         {'types': ['opened', 'reopened', 'synchronize']})
        self.assertEqual(workflow['permissions'], {'actions': 'write', 'contents': 'read', 'pull-requests': 'read'})
        self.assertEqual(workflow['jobs'], {'cancel': {
            'uses': 'sysown/proxysql/.github/workflows/ci-cancel-superseded.yml@GH-Actions'}})

    def test_push_sweep_mirrors_ci_trigger_filters(self):
        """The push sweeper must fire exactly when CI-trigger starts a cascade.

        Without the same branch pattern and paths-ignore, a docs-only or
        .github-only push would run the sweeper, which would then cancel the
        previous commit's still-relevant in-flight CI.
        """
        sweeper = yaml.safe_load((ROOT / '.github/workflows/CI-cancel-superseded.yml').read_text())
        trigger = yaml.safe_load((ROOT / '.github/workflows/CI-trigger.yml').read_text())
        sweeper_events = sweeper.get('on', sweeper.get(True, {}))
        trigger_events = trigger.get('on', trigger.get(True, {}))
        self.assertIn('push', sweeper_events)
        self.assertEqual(sweeper_events['push'], trigger_events['push'])

    def test_push_and_pr_sweeps_use_separate_concurrency_groups(self):
        """A push sweep must never cancel an unrelated PR's in-flight sweep."""
        workflow = yaml.safe_load((ROOT / '.github/workflows/CI-cancel-superseded.yml').read_text())
        group = workflow['concurrency']['group']
        self.assertTrue(workflow['concurrency']['cancel-in-progress'])
        self.assertIn('github.event_name', group)
        self.assertIn('github.event.after', group)
        self.assertIn('github.event.pull_request.number', group)


if __name__ == '__main__':
    unittest.main()
