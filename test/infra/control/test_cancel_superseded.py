"""PR cancellation runs from trusted control code for every new head."""
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[3]


class CancelSupersededTests(unittest.TestCase):
    def test_every_pr_update_calls_trusted_cancellation_with_write_permission(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/CI-cancel-superseded.yml').read_text())
        events = workflow.get('on', workflow.get(True, {}))
        self.assertEqual(events, {'pull_request_target': {'types': ['opened', 'reopened', 'synchronize']}})
        self.assertEqual(workflow['permissions'], {'actions': 'write', 'contents': 'read', 'pull-requests': 'read'})
        self.assertEqual(workflow['jobs'], {'cancel': {
            'uses': 'sysown/proxysql/.github/workflows/ci-cancel-superseded.yml@GH-Actions'}})
        self.assertEqual(workflow['concurrency'], {
            'group': 'cancel-superseded-pr-${{ github.event.pull_request.number }}-${{ github.event.pull_request.head.sha }}',
            'cancel-in-progress': True})


if __name__ == '__main__':
    unittest.main()
