"""Exercise artifact transfers over real HTTP, including broken connections."""
import contextlib
import hashlib
import http.client
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import time
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ci_tier_artifacts import ArtifactLocation, GitHubAPI


@contextlib.contextmanager
def artifact_server(mode, on_api_request=None, extra_payload=b'', expiry_status=403,
                    api_failures=(), api_headers=None, api_body=b''):
    payload = b''.join(bytes([n])*65536 for n in range(32))+extra_payload
    parallel_ready = threading.Event()
    refreshed = threading.Event()
    barrier = threading.Barrier(8, action=parallel_ready.set)
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            requests.append((self.path, self.headers.get('Range'), self.headers.get('Authorization')))
            if self.path == '/api':
                if on_api_request:
                    on_api_request()
                attempt = sum(path == '/api' for path, _, _ in requests)
                if attempt <= len(api_failures):
                    if api_failures[attempt-1] == 0:
                        self.close_connection = True
                        return
                    self.send_response(api_failures[attempt-1])
                    for name, value in (api_headers or {}).items():
                        self.send_header(name, value)
                    self.send_header('Content-Length', str(len(api_body)))
                    self.end_headers()
                    self.wfile.write(api_body)
                    return
                self.send_response(302)
                for name, value in (api_headers or {}).items():
                    self.send_header(name, value)
                suffix = f'={2 if parallel_ready.is_set() else 1}' if mode == 'parallel-expiry' else ''
                self.send_header('Location', f'http://127.0.0.1:{self.server.server_port}/blob?secret{suffix}')
                self.end_headers()
                return
            start, end = self.headers.get('Range', 'bytes=0-')[6:].split('-')
            offset = int(start)
            limit = int(end)+1 if end else len(payload)
            first = sum(path.startswith('/blob') for path, _, _ in requests) == 1
            if mode == 'parallel-expiry' and self.path == '/blob?secret=1':
                barrier.wait(timeout=5)
                # Deliver one stale rejection after peers already use the new URL.
                if offset == 0:
                    refreshed.wait(timeout=5)
                self.send_error(expiry_status)
                return
            if mode == 'parallel-expiry':
                refreshed.set()
            if mode == 'denied' or (mode == 'parallel-failure' and offset == 0):
                self.send_error(403)
                return
            if mode == 'ignore-range':
                offset = 0
                limit = len(payload)
            # Synchronize the first wave only; resumed parts arrive independently.
            if mode in ('parallel', 'parallel-resume', 'parallel-resume-nonzero') and not parallel_ready.is_set():
                barrier.wait(timeout=5)
            self.send_response(200 if mode == 'ignore-range' else 206)
            self.send_header('Content-Length', str(limit - offset))
            if mode != 'ignore-range':
                start = 0 if mode == 'wrong-range' else offset
                self.send_header('Content-Range', f'bytes {start}-{limit-1}/{len(payload)}')
            self.end_headers()
            # Disconnect once, after a complete write chunk, with an incomplete body.
            end = limit
            if first and mode in ('resume', 'ignore-range', 'wrong-range'):
                end = min(offset+1048576, limit)
            if mode == 'parallel-resume' and offset == 0:
                end = 131072
            if mode == 'parallel-resume-nonzero' and offset == 786432:
                end = 917504
            try:
                self.wfile.write(payload[offset:end])
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                # Rejection/deadline tests intentionally close the response early.
                pass
            self.close_connection = True
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}/api', payload, requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


def no_retry_delay_event():
    event = threading.Event()
    event.wait = lambda timeout=None: event.is_set()
    return event


class DownloadTests(unittest.TestCase):
    def test_redirect_metrics_include_quota_without_signed_url_or_token(self):
        output = io.StringIO()
        with artifact_server('plain', api_headers={'X-RateLimit-Remaining': '4999'}) as (url, payload, _), tempfile.TemporaryDirectory() as folder:
            with contextlib.redirect_stderr(output):
                GitHubAPI('repo', token='private-token').download(url, Path(folder)/'handoff.zip', len(payload))
        metric = output.getvalue()
        self.assertIn('GET /api status=302', metric)
        self.assertIn('x-ratelimit-remaining=4999', metric)
        self.assertNotIn('secret', metric)
        self.assertNotIn('private-token', metric)
        self.assertNotIn('127.0.0.1', metric)

    def test_broken_download_resumes_and_does_not_forward_api_token(self):
        with artifact_server('resume') as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                GitHubAPI('repo', token='private-token').download(url, target, len(payload))
            self.assertEqual(target.read_bytes(), payload)
            blob_requests = [r for r in requests if r[0].startswith('/blob')]
            self.assertEqual(blob_requests[1][1], 'bytes=1048576-')
            self.assertTrue(all(auth is None for _, _, auth in blob_requests))
            self.assertTrue(all(auth == 'Bearer private-token' for path, _, auth in requests if path == '/api'))
            self.assertEqual(sum(path == '/api' for path, _, _ in requests), 1)

    def test_range_ignored_restarts_instead_of_appending_duplicate_bytes(self):
        with artifact_server('ignore-range') as (url, payload, _), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                GitHubAPI('repo', token='token').download(url, target, len(payload))
            self.assertEqual(target.read_bytes(), payload)

    def test_repeated_failure_is_bounded_without_exposing_signed_url(self):
        with artifact_server('denied') as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
            with patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                with self.assertRaises(RuntimeError) as failure:
                    GitHubAPI('repo', token='private-token').download(url, Path(folder)/'handoff.zip', len(payload))
            self.assertNotIn('secret', str(failure.exception))
            self.assertNotIn('private-token', str(failure.exception))
            self.assertLessEqual(len(requests), 12)

    def test_wrong_range_is_rejected_before_appending(self):
        with artifact_server('wrong-range') as (url, payload, _), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                with self.assertRaisesRegex(ValueError, 'byte range'):
                    GitHubAPI('repo', token='token').download(url, target, len(payload))
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_expired_deadline_does_not_start_api_request(self):
        with artifact_server('resume') as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
            clock = iter([0])
            with patch('ci_tier_artifacts.time.monotonic', side_effect=lambda: next(clock, 3601)):
                with self.assertRaisesRegex(RuntimeError, 'TimeoutError'):
                    GitHubAPI('repo', token='token').download(url, Path(folder)/'handoff.zip', len(payload))
            self.assertEqual(requests, [])

    def test_deadline_consumed_by_api_request_does_not_start_storage_request(self):
        now = [0]
        def expire_deadline():
            now[0] = 3601
        with artifact_server('resume', expire_deadline) as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
            with patch('ci_tier_artifacts.time.monotonic', side_effect=lambda: now[0]):
                with self.assertRaisesRegex(RuntimeError, 'TimeoutError'):
                    GitHubAPI('repo', token='token').download(url, Path(folder)/'handoff.zip', len(payload))
            self.assertEqual([path for path, _, _ in requests], ['/api'])


    def test_large_download_uses_eight_concurrent_ranges_and_verifies_digest(self):
        with artifact_server('parallel') as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536, create=True):
                GitHubAPI('repo', token='token').download(url, target, len(payload),
                    digest='sha256:'+hashlib.sha256(payload).hexdigest())
            self.assertEqual(target.read_bytes(), payload)
            ranges = [r for path, r, _ in requests if path.startswith('/blob')]
            self.assertEqual(len(ranges), 8)
            self.assertEqual(sum(path == '/api' for path, _, _ in requests), 1)
            self.assertEqual(set(ranges), {f'bytes={i*262144}-{(i+1)*262144-1}' for i in range(8)})
            self.assertTrue(all(auth is None for path, _, auth in requests if path.startswith('/blob')))
            self.assertEqual(list(Path(folder).iterdir()), [target])

    def test_only_interrupted_parallel_part_is_resumed(self):
        with artifact_server('parallel-resume') as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536, create=True), patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                GitHubAPI('repo', token='token').download(url, target, len(payload),
                    digest='sha256:'+hashlib.sha256(payload).hexdigest())
            self.assertEqual(target.read_bytes(), payload)
            ranges = [r for path, r, _ in requests if path.startswith('/blob')]
            self.assertEqual(len(ranges), 9)
            self.assertEqual(ranges.count('bytes=131072-262143'), 1)
            self.assertEqual(ranges.count('bytes=0-262143'), 1)
            self.assertEqual(sum(path == '/api' for path, _, _ in requests), 1)

    def test_concurrent_expired_urls_share_one_refresh(self):
        for status in (401, 403):
            with self.subTest(status=status), artifact_server('parallel-expiry', expiry_status=status) as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
                target = Path(folder)/'handoff.zip'
                with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536), \
                     patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                    GitHubAPI('repo', token='private-token').download(url, target, len(payload))
                self.assertEqual(target.read_bytes(), payload)
                self.assertEqual(sum(path == '/api' for path, _, _ in requests), 2)
                self.assertEqual(sum(path == '/blob?secret=1' for path, _, _ in requests), 8)
                self.assertEqual(sum(path == '/blob?secret=2' for path, _, _ in requests), 8)
                self.assertTrue(all(auth is None for path, _, auth in requests if path.startswith('/blob')))

    def test_parallel_api_failure_is_shared_without_exposing_credentials(self):
        cases = [(403, {}), (403, {'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': '9999999999'}),
                 (429, {'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': '9999999999'})]
        for status, headers in cases:
            with self.subTest(status=status, headers=headers), artifact_server('plain',
                    api_failures=(status,), api_headers=headers) as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
                with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536), \
                     patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                    with self.assertRaises(RuntimeError) as failure:
                        GitHubAPI('repo', token='private-token').download(url, Path(folder)/'handoff.zip', len(payload))
                self.assertEqual([path for path, _, _ in requests], ['/api'])
                self.assertNotIn('secret', str(failure.exception))
                self.assertNotIn('private-token', str(failure.exception))

    def test_parallel_api_retry_is_shared_by_all_workers(self):
        for status, headers in [(429, {'Retry-After': '0'}), (0, {})]:
            with self.subTest(status=status), artifact_server('parallel', api_failures=(status,), api_headers=headers) as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
                target = Path(folder)/'handoff.zip'
                with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536), \
                     patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                    GitHubAPI('repo', token='private-token').download(url, target, len(payload))
                self.assertEqual(target.read_bytes(), payload)
                self.assertEqual(sum(path == '/api' for path, _, _ in requests), 2)

    def test_secondary_api_limit_without_retry_headers_retries_for_all_workers(self):
        with artifact_server('parallel', api_failures=(403,), api_headers={'X-RateLimit-Remaining': '4999'},
                api_body=b'{"message":"You have exceeded a secondary rate limit."}') as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536), \
                 patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                GitHubAPI('repo', token='private-token').download(url, target, len(payload))
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(sum(path == '/api' for path, _, _ in requests), 2)

    def test_parallel_api_retries_stop_at_attempt_and_wait_limits(self):
        for status, headers, expected in [(500, {}, 6), (429, {'Retry-After': '90'}, 4)]:
            with self.subTest(status=status), artifact_server('plain', api_failures=(status,)*6,
                    api_headers=headers) as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
                with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536), \
                     patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                    with self.assertRaisesRegex(RuntimeError, f'HTTP {status}'):
                        GitHubAPI('repo', token='private-token').download(url, Path(folder)/'handoff.zip', len(payload))
                self.assertEqual([path for path, _, _ in requests], ['/api']*expected)

    def test_cancelled_redirect_retry_does_not_poison_fallback_location(self):
        cancelled = threading.Event()
        with artifact_server('plain', on_api_request=cancelled.set,
                api_failures=(500,)) as (url, _, requests):
            locations = ArtifactLocation(url, 'private-token')
            deadline = time.monotonic()+60
            with self.assertRaisesRegex(RuntimeError, 'cancelled'):
                locations.get(deadline, cancelled)
            # Range fallback reuses this resolver with a fresh cancellation event.
            try:
                location = locations.get(deadline, threading.Event())
            except RuntimeError as error:
                self.fail(f'fallback resolver inherited an earlier cancellation: {error}')
            self.assertTrue(location.endswith('/blob?secret'))
            self.assertEqual([path for path, _, _ in requests], ['/api', '/api'])

    def test_parallel_range_ignored_falls_back_to_single_download(self):
        with artifact_server('ignore-range') as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536, create=True), patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                GitHubAPI('repo', token='token').download(url, target, len(payload),
                    digest='sha256:'+hashlib.sha256(payload).hexdigest())
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(list(Path(folder).iterdir()), [target])
            self.assertEqual(sum(path == '/api' for path, _, _ in requests), 1)

    def test_interrupted_nonzero_range_resumes_at_its_absolute_offset(self):
        with artifact_server('parallel-resume-nonzero') as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536), \
                 patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                GitHubAPI('repo', token='token').download(url, target, len(payload),
                    digest='sha256:'+hashlib.sha256(payload).hexdigest())
            self.assertEqual(target.read_bytes(), payload)
            ranges = [r for path, r, _ in requests if path.startswith('/blob')]
            self.assertEqual(len(ranges), 9)
            self.assertEqual(ranges.count('bytes=917504-1048575'), 1)
            self.assertEqual(ranges.count('bytes=786432-1048575'), 1)

    def test_wrong_checksum_preserves_existing_destination_and_removes_parts(self):
        with artifact_server('parallel-resume') as (url, payload, _), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            target.write_bytes(b'existing file')
            with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536, create=True), patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                with self.assertRaisesRegex(ValueError, 'checksum'):
                    GitHubAPI('repo', token='token').download(url, target, len(payload), digest='sha256:'+'0'*64)
            self.assertEqual(target.read_bytes(), b'existing file')
            self.assertEqual(list(Path(folder).iterdir()), [target])


    def test_parallel_download_includes_uneven_final_part(self):
        with artifact_server('parallel', extra_payload=b'end') as (url, payload, _), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536, create=True):
                GitHubAPI('repo', token='token').download(url, target, len(payload),
                    digest='sha256:'+hashlib.sha256(payload).hexdigest())
            self.assertEqual(target.read_bytes(), payload)

    def test_failed_parallel_part_does_not_publish_or_leave_scratch_files(self):
        with artifact_server('parallel-failure') as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536, create=True), patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                with self.assertRaisesRegex(RuntimeError, 'HTTP 403'):
                    GitHubAPI('repo', token='token').download(url, target, len(payload))
            self.assertEqual(list(Path(folder).iterdir()), [])
            self.assertEqual(sum(r == 'bytes=0-262143' for path, r, _ in requests if path.startswith('/blob')), 6)


    def test_deadline_during_transfer_stops_without_retry(self):
        now = [0]
        read1 = http.client.HTTPResponse.read1
        def expire_after_read(response, amount):
            data = read1(response, amount)
            now[0] = 3601
            return data
        with artifact_server('resume') as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.time.monotonic', side_effect=lambda: now[0]), \
                 patch('ci_tier_artifacts.http.client.HTTPResponse.read1', new=expire_after_read):
                with self.assertRaisesRegex(RuntimeError, 'TimeoutError'):
                    GitHubAPI('repo', token='token').download(url, target, len(payload))
            self.assertEqual([path for path, _, _ in requests], ['/api', '/blob?secret'])
            self.assertEqual(list(Path(folder).iterdir()), [])


    def test_parallel_download_writes_only_one_archive_copy(self):
        written = []
        original_open = Path.open
        @contextlib.contextmanager
        def count_writes(path, mode='r', *args, **kwargs):
            with original_open(path, mode, *args, **kwargs) as stream:
                if any(flag in mode for flag in ('w', 'a', '+')):
                    class Writer:
                        def __getattr__(self, name):
                            return getattr(stream, name)
                        def write(self, data):
                            size = stream.write(data)
                            written.append(size)
                            return size
                    yield Writer()
                else:
                    yield stream
        with artifact_server('parallel') as (url, payload, _), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536), \
                 patch('ci_tier_artifacts.Path.open', new=count_writes):
                GitHubAPI('repo', token='token').download(url, target, len(payload),
                    digest='sha256:'+hashlib.sha256(payload).hexdigest())
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(sum(written), len(payload), 'download must not copy ranges into a second archive')


if __name__ == '__main__':
    unittest.main()
