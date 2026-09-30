"""Exercise artifact transfers over real HTTP, including broken connections."""
import contextlib
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ci_tier_artifacts import GitHubAPI


@contextlib.contextmanager
def artifact_server(mode, on_api_request=None, extra_payload=b''):
    payload = b''.join(bytes([n])*65536 for n in range(32))+extra_payload
    barrier = threading.Barrier(8)
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            requests.append((self.path, self.headers.get('Range'), self.headers.get('Authorization')))
            if self.path == '/api':
                if on_api_request:
                    on_api_request()
                self.send_response(302)
                self.send_header('Location', f'http://127.0.0.1:{self.server.server_port}/blob?secret')
                self.end_headers()
                return
            start, end = self.headers.get('Range', 'bytes=0-')[6:].split('-')
            offset = int(start)
            limit = int(end)+1 if end else len(payload)
            first = sum(path.startswith('/blob') for path, _, _ in requests) == 1
            if mode == 'denied' or (mode == 'parallel-failure' and offset == 0):
                self.send_error(403)
                return
            if mode == 'ignore-range':
                offset = 0
                limit = len(payload)
            if mode == 'parallel':
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
            with patch('ci_tier_artifacts.time.monotonic', side_effect=[0, 3601, 3601]):
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

    def test_parallel_range_ignored_falls_back_to_single_download(self):
        with artifact_server('ignore-range') as (url, payload, _), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536, create=True), patch('ci_tier_artifacts.Event', side_effect=no_retry_delay_event):
                GitHubAPI('repo', token='token').download(url, target, len(payload),
                    digest='sha256:'+hashlib.sha256(payload).hexdigest())
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(list(Path(folder).iterdir()), [target])

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


    def test_assembly_reclaims_each_copied_part_before_reading_the_next(self):
        scratch_sizes = []
        original_open = Path.open
        def measure_scratch(path, mode='r', *args, **kwargs):
            if path.name.startswith('part-') and mode == 'rb':
                scratch_sizes.append(sum(p.stat().st_size for p in path.parent.iterdir()))
            return original_open(path, mode, *args, **kwargs)
        with artifact_server('parallel') as (url, payload, _), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.MIN_DOWNLOAD_PART_BYTES', 65536), \
                 patch('ci_tier_artifacts.Path.open', new=measure_scratch):
                GitHubAPI('repo', token='token').download(url, target, len(payload),
                    digest='sha256:'+hashlib.sha256(payload).hexdigest())
            self.assertEqual(target.read_bytes(), payload)
            self.assertEqual(len(scratch_sizes), 8)
            self.assertLessEqual(max(scratch_sizes), len(payload))


if __name__ == '__main__':
    unittest.main()
