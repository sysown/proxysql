"""Build waiters should poll slowly without replaying exhausted API retries."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ci_tier_runtime as runtime


class Clock:
    def __init__(self):
        self.now = 0
        self.waits = []

    def sleep(self, seconds):
        self.waits.append(seconds)
        self.now += seconds


class ProducerPollingTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        prior = os.getcwd()
        os.chdir(self.folder.name)
        self.addCleanup(os.chdir, prior)
        self.clock = Clock()
        self.producer = dict(repository='owner/repo', build_id=2, build_attempt=1)
        self.api = Mock()
        gh = dict(repository='owner/repo', sha='a'*40, run_id='1', run_attempt='1', event={})
        for patcher in (
                patch.dict(os.environ, {'GITHUB_JSON': json.dumps(gh)}),
                patch.object(runtime, 'api_for', return_value=self.api),
                patch.object(runtime.time, 'monotonic', side_effect=lambda: self.clock.now),
                patch.object(runtime.time, 'sleep', side_effect=self.clock.sleep)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_completion_polling_uses_fresh_two_to_four_minute_jitter(self):
        self.api.request.side_effect = [dict(status='in_progress'), dict(status='in_progress'),
                                        dict(status='completed', conclusion='success')]
        with patch.object(runtime, 'resolve_producer', return_value=self.producer), \
                patch('random.uniform', side_effect=[120, 240]) as jitter:
            runtime.producer_lookup()
        self.assertEqual(self.clock.waits, [120, 240])
        self.assertEqual(jitter.call_count, 2)
        for call in self.api.request.call_args_list:
            self.assertEqual(call.args, ('repos/owner/repo/actions/runs/2/attempts/1',))
        self.assertEqual(json.loads(Path('producer.json').read_text()), self.producer)

    def test_completed_build_needs_no_polling_delay(self):
        self.api.request.return_value = dict(status='completed', conclusion='success')
        with patch.object(runtime, 'resolve_producer', return_value=self.producer):
            runtime.producer_lookup()
        self.assertEqual(self.clock.waits, [])

    def test_poll_delay_does_not_extend_the_build_deadline(self):
        def run_status(*args):
            if self.api.request.call_count == 1:
                self.clock.now = 20650
                return dict(status='in_progress')
            return dict(status='completed', conclusion='success')
        self.api.request.side_effect = run_status
        with patch.object(runtime, 'resolve_producer', return_value=self.producer), \
                patch('random.uniform', return_value=240):
            with self.assertRaisesRegex(RuntimeError, 'timed out waiting for producer completion'):
                runtime.producer_lookup()
        self.assertEqual(self.clock.waits, [50])
        self.assertEqual(self.api.request.call_count, 1)

    def test_waiter_covers_planning_build_and_finalization(self):
        def run_status(*args):
            self.clock.now = 245*60
            if self.api.request.call_count == 1:
                return dict(status='in_progress')
            return dict(status='completed', conclusion='success')
        self.api.request.side_effect = run_status
        with patch.object(runtime, 'resolve_producer', return_value=self.producer), \
                patch('random.uniform', return_value=120):
            runtime.producer_lookup()
        self.assertEqual(json.loads(Path('producer.json').read_text()), self.producer)

    def test_late_success_cannot_publish_an_accepted_producer(self):
        def run_status(*args):
            self.clock.now = 346*60
            return dict(status='completed', conclusion='success')
        self.api.request.side_effect = run_status
        with patch.object(runtime, 'resolve_producer', return_value=self.producer):
            with self.assertRaisesRegex(RuntimeError, 'timed out waiting for producer completion'):
                runtime.producer_lookup()
        self.assertFalse(Path('producer.json').exists())

    def test_waiter_supplies_its_deadline_to_the_api_client(self):
        self.api.request.return_value = dict(status='completed', conclusion='success')
        with patch.object(runtime, 'api_for', return_value=self.api) as api_for, \
                patch.object(runtime, 'resolve_producer', return_value=self.producer):
            runtime.producer_lookup()
        self.assertEqual(api_for.call_args.kwargs.get('deadline'), 20700)

    def test_exhausted_transport_budget_is_not_restarted_by_the_waiter(self):
        with patch.object(runtime, 'resolve_producer', side_effect=RuntimeError('retry wait budget exceeded')) as resolve:
            with self.assertRaisesRegex(RuntimeError, 'retry wait budget exceeded'):
                runtime.producer_lookup()
        self.assertEqual(resolve.call_count, 1)
        self.assertEqual(self.clock.waits, [])


if __name__ == '__main__':
    unittest.main()
