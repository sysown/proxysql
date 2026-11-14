"""Exercise gh's process boundary without contacting GitHub."""
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ci_github_transport as transport


def response(status=200, headers=(), body=b'{"id":7}', code=0, stderr=b''):
    lines = [f'HTTP/2.0 {status} Status', *headers, '', '']
    return subprocess.CompletedProcess([], code, '\r\n'.join(lines).encode() + body, stderr)


class TransportTests(unittest.TestCase):
    def test_direct_response_metrics_hide_credentials_and_signed_urls(self):
        with contextlib.redirect_stderr(io.StringIO()) as log:
            transport.record_response('GET', 'https://user:password@api.invalid/artifacts/9/zip?secret=hidden',
                302, {'X-RateLimit-Remaining': '17', 'Location': 'https://storage.invalid/?sig=secret'}, token='password')
        self.assertIn('GET /artifacts/9/zip status=302', log.getvalue())
        self.assertIn('x-ratelimit-remaining=17', log.getvalue())
        for secret in ('password', 'hidden', 'storage.invalid', 'secret', 'user:'):
            self.assertNotIn(secret, log.getvalue())

    def invoke(self, replies, **kwargs):
        calls = []
        waits = []
        def run(args, **options):
            calls.append((args, options))
            reply = replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply
        with patch.object(transport.subprocess, 'run', side_effect=run), \
             patch.object(transport.time, 'sleep', side_effect=waits.append), \
             patch.object(transport.time, 'time', return_value=1000), \
             contextlib.redirect_stderr(io.StringIO()) as log:
            result = transport.request('repos/org/repo/check-runs', **kwargs)
        return result, calls, waits, log.getvalue()

    def test_shared_retry_policy_accepts_urllib_header_names(self):
        self.assertTrue(transport.is_rate_limited(403, {'Retry-After': '9'}))
        self.assertFalse(transport.is_rate_limited(403, {}))
        self.assertTrue(transport.is_rate_limited(429, {}))
        self.assertEqual(transport.retry_delay({'Retry-After': '9'}, True, 0), 9)
        with patch.object(transport.time, 'time', return_value=1000):
            self.assertEqual(transport.retry_delay({'X-RateLimit-Remaining': '0',
                'X-RateLimit-Reset': '1040'}, True, 0), 40)

    def test_json_headers_are_removed_and_payload_goes_to_stdin(self):
        result, calls, _, log = self.invoke([response(headers=['X-RateLimit-Remaining: 42'])],
                                          method='POST', payload={'name': 'build'}, token='secret')
        self.assertEqual(result, {'id': 7})
        args, options = calls[0]
        self.assertIn('--include', args)
        self.assertIn('--input', args)
        self.assertEqual(options['input'], b'{"name": "build"}')
        self.assertEqual(options['env']['GH_TOKEN'], 'secret')
        self.assertIn('status=200', log)
        self.assertIn('x-ratelimit-remaining=42', log)

    def test_redirect_headers_are_removed_without_decoding_binary(self):
        binary = b'PK\x00\xff\r\nHTTP/2.0 200 OK\r\n\r\narchive'
        reply = response(302, ['Location: https://storage.invalid/?sig=secret'], body=b'')
        reply.stdout += response(body=binary).stdout
        result, _, _, log = self.invoke([reply], raw=True)
        self.assertEqual(result, binary)
        self.assertNotIn('storage.invalid', log)

    def test_redirect_preserves_github_quota_metrics(self):
        reply = response(302, ['X-RateLimit-Remaining: 39'], body=b'')
        reply.stdout += response(body=b'PKarchive').stdout
        _, _, _, log = self.invoke([reply], raw=True)
        self.assertIn('x-ratelimit-remaining=39', log)

    def test_final_rate_limit_quota_overrides_redirect_quota(self):
        reply = response(302, ['X-RateLimit-Remaining: 42',
                               'X-RateLimit-Reset: 1000'], body=b'')
        reply.stdout += response(403, ['X-RateLimit-Remaining: 0',
                                       'X-RateLimit-Reset: 1030']).stdout
        reply.returncode = 1
        try:
            result, calls, waits, log = self.invoke([reply, response()])
        except RuntimeError as error:
            self.fail(f'Final quota must allow the rate-limit retry: {error}')
        self.assertEqual(result, {'id': 7})
        self.assertEqual(len(calls), 2)
        self.assertEqual(waits, [30])
        self.assertIn('status=403 x-ratelimit-remaining=0 x-ratelimit-reset=1030', log)

    def test_http_status_is_available_in_safe_failure_message(self):
        with self.assertRaisesRegex(RuntimeError, 'HTTP 422'):
            self.invoke([response(422, code=1)])

    def test_body_that_looks_like_http_is_preserved_after_final_headers(self):
        binary = b'HTTP/1.1 200 OK\r\n\r\nnot another response'
        result, _, _, _ = self.invoke([response(body=binary)], raw=True)
        self.assertEqual(result, binary)

    def test_headerless_stdout_remains_compatible(self):
        result, _, _, _ = self.invoke([subprocess.CompletedProcess([], 0, b'{"id":7}', b'')])
        self.assertEqual(result, {'id': 7})

    def test_retry_after_seconds_controls_rate_limit_wait(self):
        result, _, waits, _ = self.invoke([response(429, ['Retry-After: 12'], code=1), response()])
        self.assertEqual(result, {'id': 7})
        self.assertEqual(waits, [12])

    def test_retry_after_http_date_controls_rate_limit_wait(self):
        _, _, waits, _ = self.invoke([response(429, ['Retry-After: Thu, 01 Jan 1970 00:17:00 GMT'], code=1), response()])
        self.assertEqual(waits, [20])

    def test_primary_limit_waits_for_reset(self):
        _, _, waits, _ = self.invoke([response(403, ['X-RateLimit-Remaining: 0', 'X-RateLimit-Reset: 1030'], code=1), response()])
        self.assertEqual(waits, [30])

    def test_secondary_limit_backs_off_for_at_least_a_minute(self):
        _, _, waits, _ = self.invoke([response(403, code=1, stderr=b'secondary rate limit')] * 2 + [response()])
        self.assertEqual(waits, [60, 120])

    def test_secondary_limit_with_retry_after_header_needs_no_error_text(self):
        _, _, waits, _ = self.invoke([response(403, ['Retry-After: 10'], code=1), response()])
        self.assertEqual(waits, [10])

    def test_headerless_rate_limit_diagnostic_can_retry_a_read(self):
        _, _, waits, _ = self.invoke([subprocess.CompletedProcess([], 1, b'', b'API rate limit exceeded'), response()])
        self.assertEqual(waits, [60])

    def test_secondary_retries_stop_when_cumulative_wait_budget_is_exhausted(self):
        waits = []
        with patch.object(transport.subprocess, 'run', return_value=response(429, code=1)) as run, \
             patch.object(transport.time, 'sleep', side_effect=waits.append):
            with self.assertRaisesRegex(RuntimeError, 'budget'):
                transport.request('checks')
        self.assertEqual(run.call_count, 3)
        self.assertEqual(waits, [60, 120])

    def test_lf_headers_and_empty_success_body(self):
        reply = subprocess.CompletedProcess([], 0, b'HTTP/2.0 204 No Content\nX-RateLimit-Remaining: 12\n\n', b'')
        result, _, _, _ = self.invoke([reply])
        self.assertEqual(result, {})

    def test_non_rate_limit_forbidden_is_not_retried(self):
        with self.assertRaisesRegex(RuntimeError, 'after 1 attempts'):
            self.invoke([response(403, code=1, stderr=b'resource not accessible')])

    def test_wait_beyond_budget_fails_without_sleeping(self):
        with patch.object(transport.subprocess, 'run', return_value=response(429, ['Retry-After: 3600'], code=1)) as run, \
             patch.object(transport.time, 'sleep') as sleep:
            with self.assertRaisesRegex(RuntimeError, 'budget'):
                transport.request('repos/org/repo/check-runs')
        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()

    def test_unknown_post_outcome_is_not_replayed(self):
        for failure in [response(503, code=1), subprocess.TimeoutExpired('gh', 60)]:
            with self.subTest(failure=failure), self.assertRaisesRegex(RuntimeError, 'after 1 attempts'):
                self.invoke([failure], method='POST', payload={'name': 'build'})

    def test_explicitly_rate_limited_post_can_be_replayed(self):
        result, _, waits, _ = self.invoke([response(429, code=1), response()], method='POST')
        self.assertEqual(result, {'id': 7})
        self.assertEqual(waits, [60])

    def test_safe_patch_guard_can_abort_before_replay(self):
        def guard():
            raise ValueError('stale attempt')
        with patch.object(transport.subprocess, 'run', return_value=response(503, code=1)) as run, \
             patch.object(transport.time, 'sleep'):
            with self.assertRaisesRegex(ValueError, 'stale attempt'):
                transport.request('checks/7', 'PATCH', retry_safe=True, before_retry=guard)
        self.assertEqual(run.call_count, 1)

    def test_safe_patch_recovers_after_timeout(self):
        guarded = []
        result, _, waits, _ = self.invoke([subprocess.TimeoutExpired('gh', 60), response()],
            method='PATCH', retry_safe=True, before_retry=lambda: guarded.append(True))
        self.assertEqual(result, {'id': 7})
        self.assertEqual(guarded, [True])
        self.assertEqual(waits, [1])

    def test_retry_safe_is_restricted_to_patch(self):
        with self.assertRaisesRegex(ValueError, 'PATCH'):
            transport.request('checks', 'POST', retry_safe=True)

    def test_repeated_transient_failures_stop_after_six_attempts(self):
        with self.assertRaisesRegex(RuntimeError, 'after 6 attempts'):
            self.invoke([response(503, code=1)] * 6)

    def test_diagnostics_never_echo_query_credentials_payload_or_signed_url(self):
        leak = b'ghp_secret https://storage.invalid/?sig=private payload-private'
        reply = response(400, ['Location: https://storage.invalid/?sig=private',
                              'X-RateLimit-Remaining: ghp_secret'], code=1, stderr=leak)
        with patch.object(transport.subprocess, 'run', return_value=reply), \
             contextlib.redirect_stderr(io.StringIO()) as log:
            with self.assertRaises(RuntimeError) as error:
                transport.request('https://username:password@api.github.com/repos/org/repo?token=query-private',
                                  'POST', {'text': 'payload-private'}, token='ghp_secret')
        diagnostic = log.getvalue() + str(error.exception)
        for secret in ['ghp_secret', 'query-private', 'payload-private', 'storage.invalid', 'password', 'username']:
            self.assertNotIn(secret, diagnostic)
        self.assertIn('/repos/org/repo', diagnostic)


if __name__ == '__main__':
    unittest.main()
