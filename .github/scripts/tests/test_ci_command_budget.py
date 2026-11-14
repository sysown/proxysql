"""Command budgets cover real orchestration across API clients and workers."""
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ci_github_transport as transport
from ci_tier_artifacts import ArtifactLocation, GitHubAPI
from ci_tier_checks import publish_result
from test_ci_github_transport import response
from test_ci_tier_download import artifact_server


class Clock:
    def __init__(self):
        self.now = 0
        self.waits = []
    def sleep(self, seconds):
        self.waits.append(seconds)
        self.now += seconds


class CommandBudgetTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(transport.time, 'monotonic', side_effect=lambda: self.clock.now))
        self.stack.enter_context(patch.object(transport.time, 'sleep', side_effect=self.clock.sleep))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))

    def test_metadata_fetch_and_publisher_cannot_each_spend_twenty_minutes(self):
        # Previously this command could wait 20 minutes on metadata and 11 on PATCH.
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as packed:
            packed.writestr('plan.json', '{"execution_id":"e"}')
        replies = [response(429, ['Retry-After: 1200'], code=1),
                   response(body=b'{"artifacts":[{"id":7,"name":"ci-plan"}]}'),
                   response(body=archive.getvalue()), response(body=b'{"run_attempt":1}'),
                   response(429, ['Retry-After: 660'], code=1), response()]
        plan = {'repository':'org/repo', 'execution_id':'e', 'checks':[
            {'key':'unit', 'check_id':7, 'name':'Unit'}]}
        with patch.object(transport.subprocess, 'run', side_effect=replies) as run:
            with transport.command_budget():
                self.assertEqual(GitHubAPI('org/repo').json_artifact(9, 'ci-plan', 'plan.json'),
                                 {'execution_id':'e'})
                with self.assertRaisesRegex(RuntimeError, 'budget'):
                    publish_result(plan, 'unit', 'success', GitHubAPI('org/repo'), 10, 1)
        self.assertEqual(self.clock.waits, [1200])
        self.assertEqual(run.call_count, 5)
        self.assertLess(self.clock.now, 1800)

    def test_nested_before_retry_reads_use_the_same_wait_allowance(self):
        replies = [response(429, ['Retry-After: 600'], code=1),
                   response(429, ['Retry-After: 600'], code=1), response(),
                   response(429, ['Retry-After: 1'], code=1)]
        api = GitHubAPI('org/repo')
        with patch.object(transport.subprocess, 'run', side_effect=replies):
            with transport.command_budget():
                with self.assertRaisesRegex(RuntimeError, 'budget'):
                    api.request('checks/7', 'PATCH', retry_safe=True,
                                before_retry=lambda: GitHubAPI('org/repo').request('runs/10'))
        self.assertEqual(self.clock.waits, [600, 600])

    def test_explicit_deadline_rejects_long_wait_without_command_scope(self):
        with patch.object(transport.subprocess, 'run', return_value=response(
                429, ['Retry-After: 720'], code=1)):
            with self.assertRaisesRegex(RuntimeError, 'deadline'):
                GitHubAPI('repo', deadline=50).request('checks')
        self.assertEqual(self.clock.waits, [])

    def test_json_and_raw_process_timeouts_fit_remaining_command_time(self):
        for raw in (False, True):
            with self.subTest(raw=raw), transport.command_budget(timeout_seconds=50):
                def run(args, **options):
                    self.assertEqual(options['timeout'], 50)
                    return response()
                with patch.object(transport.subprocess, 'run', side_effect=run):
                    GitHubAPI('repo').request('checks', raw=raw)

    def test_success_received_after_deadline_is_rejected(self):
        def run(*args, **options):
            self.clock.now = 51
            return response()
        with patch.object(transport.subprocess, 'run', side_effect=run):
            with self.assertRaisesRegex(RuntimeError, 'deadline'):
                with transport.command_budget(timeout_seconds=50):
                    GitHubAPI('repo').request('checks')

    def test_command_processing_cannot_finish_after_overall_deadline(self):
        with self.assertRaisesRegex(RuntimeError, 'deadline'):
            with transport.command_budget(timeout_seconds=50):
                self.clock.now = 51

    def test_direct_http_redirect_in_worker_shares_prior_api_waits(self):
        with artifact_server('plain', api_failures=(429,),
                             api_headers={'Retry-After':'1'}) as (url, _, requests):
            with transport.command_budget():
                with patch.object(transport.subprocess, 'run', side_effect=[
                        response(429, ['Retry-After: 1200'], code=1), response()]):
                    GitHubAPI('repo').request('checks')
                locations = ArtifactLocation(url, 'secret')
                failures = []
                def resolve():
                    try:locations.get(3600, threading.Event())
                    except RuntimeError as error:failures.append(str(error))
                worker = threading.Thread(target=resolve)
                worker.start(); worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
        self.assertEqual(len(requests), 1)
        self.assertEqual(len(failures), 1)
        self.assertIn('budget', failures[0])

    def test_cancelled_redirect_sleep_only_charges_elapsed_wait(self):
        with transport.command_budget() as budget:
            class Cancelled:
                def wait(inner, delay):
                    self.clock.now += 2
                    return True
            with self.assertRaisesRegex(RuntimeError, 'cancelled'):
                budget.wait(1200, cancelled=Cancelled())
            budget.wait(1198)
        self.assertEqual(self.clock.now, 1200)

    def test_download_rejects_late_redirect_for_scope_and_explicit_deadlines(self):
        for explicit in (False, True):
            self.clock.now = 0
            def expire():self.clock.now = 51
            with self.subTest(explicit=explicit), artifact_server('plain', on_api_request=expire) as (url, payload, requests):
                with tempfile.TemporaryDirectory() as folder:
                    api = GitHubAPI('repo', token='secret', deadline=50 if explicit else None)
                    target = Path(folder)/'handoff.zip'
                    with self.assertRaisesRegex(RuntimeError, 'TimeoutError'), contextlib.ExitStack() as scope:
                        if not explicit:scope.enter_context(transport.command_budget(timeout_seconds=50))
                        api.download(url, target, len(payload))
                    self.assertFalse(target.exists())
                    self.assertEqual(list(Path(folder).iterdir()), [])
                self.assertEqual([path for path, _, _ in requests], ['/api'])


if __name__ == '__main__':
    unittest.main()
