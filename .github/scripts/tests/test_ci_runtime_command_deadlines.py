"""The CLI command owns the deadline used by all of its API calls."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ci_github_transport as transport
import ci_tier_runtime as runtime


def reply(status, body=b'{}', delay=None):
    headers = f'HTTP/2.0 {status} Response\r\n'
    if delay is not None:
        headers += f'Retry-After: {delay}\r\n'
    return subprocess.CompletedProcess([], int(status >= 400), (headers+'\r\n').encode()+body, b'')


class RuntimeCommandDeadlineTests(unittest.TestCase):
    def test_result_shares_retry_allowance_between_verification_and_publication(self):
        now = [0]
        waits = []
        def sleep(seconds):
            waits.append(seconds)
            now[0] += seconds
        plan = dict(repository='owner/repo', execution_id='example', build_id=1,
                    checks=[dict(key='k', check_id=7, name='test')])
        env = dict(CI_PLAN=json.dumps(plan), GITHUB_JSON=json.dumps(dict(repository='owner/repo', run_id='2', run_attempt='1')),
                   CHECK_KEY='k', CHECK_STATUS='success')
        replies = [reply(429, delay=1200), reply(200, b'{"run_attempt":1}'), reply(429, delay=660)]
        with patch.dict(os.environ, env), patch.object(transport.subprocess, 'run', side_effect=replies) as run, \
                patch.object(transport.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(transport.time, 'sleep', side_effect=sleep), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'budget'):
                runtime.run_command('result')
        self.assertEqual(now[0], 1200, 'a later request must not restart the command retry allowance')
        self.assertEqual(waits, [1200])
        self.assertEqual(run.call_count, 3)

    def test_wait_and_restore_commands_get_their_longer_overall_deadlines(self):
        cases = [('wait-build', 'producer_lookup', 20700), ('restore', 'restore', 3300),
                 ('restore-unit', 'restore_unit', 3300)]
        for command, function, seconds in cases:
            seen = []
            def inspect_budget():
                seen.append(transport.current_budget().deadline)
            with self.subTest(command=command), patch.object(runtime, function, side_effect=inspect_budget), \
                    patch.object(transport.time, 'monotonic', return_value=100):
                runtime.run_command(command)
            self.assertEqual(seen, [100+seconds])


if __name__ == '__main__':
    unittest.main()
