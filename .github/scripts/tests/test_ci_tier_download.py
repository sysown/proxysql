"""Exercise artifact transfers over real HTTP, including broken connections."""
import contextlib
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
def artifact_server(mode):
    payload = b'0123456789abcdef' * 131072
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            requests.append((self.path, self.headers.get('Range'), self.headers.get('Authorization')))
            if self.path == '/api':
                self.send_response(302)
                self.send_header('Location', f'http://127.0.0.1:{self.server.server_port}/blob?secret')
                self.end_headers()
                return
            offset = int(self.headers.get('Range', 'bytes=0-')[6:-1])
            first = sum(path.startswith('/blob') for path, _, _ in requests) == 1
            if mode == 'denied':
                self.send_error(403)
                return
            if mode == 'ignore-range':
                offset = 0
            self.send_response(206 if offset else 200)
            self.send_header('Content-Length', str(len(payload) - offset))
            if offset:
                start = 0 if mode == 'wrong-range' else offset
                self.send_header('Content-Range', f'bytes {start}-{len(payload)-1}/{len(payload)}')
            self.end_headers()
            # Disconnect once, after a complete write chunk, with an incomplete body.
            end = 1048576 if first else len(payload)
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


class DownloadTests(unittest.TestCase):
    def test_broken_download_resumes_and_does_not_forward_api_token(self):
        with artifact_server('resume') as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.time.sleep'):
                GitHubAPI('repo', token='private-token').download(url, target, len(payload))
            self.assertEqual(target.read_bytes(), payload)
            blob_requests = [r for r in requests if r[0].startswith('/blob')]
            self.assertEqual(blob_requests[1][1], 'bytes=1048576-')
            self.assertTrue(all(auth is None for _, _, auth in blob_requests))
            self.assertTrue(all(auth == 'Bearer private-token' for path, _, auth in requests if path == '/api'))

    def test_range_ignored_restarts_instead_of_appending_duplicate_bytes(self):
        with artifact_server('ignore-range') as (url, payload, _), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.time.sleep'):
                GitHubAPI('repo', token='token').download(url, target, len(payload))
            self.assertEqual(target.read_bytes(), payload)

    def test_repeated_failure_is_bounded_without_exposing_signed_url(self):
        with artifact_server('denied') as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
            with patch('ci_tier_artifacts.time.sleep'):
                with self.assertRaises(RuntimeError) as failure:
                    GitHubAPI('repo', token='private-token').download(url, Path(folder)/'handoff.zip', len(payload))
            self.assertNotIn('secret', str(failure.exception))
            self.assertNotIn('private-token', str(failure.exception))
            self.assertLessEqual(len(requests), 12)

    def test_wrong_range_is_rejected_before_appending(self):
        with artifact_server('wrong-range') as (url, payload, _), tempfile.TemporaryDirectory() as folder:
            target = Path(folder)/'handoff.zip'
            with patch('ci_tier_artifacts.time.sleep'):
                with self.assertRaisesRegex(ValueError, 'byte range'):
                    GitHubAPI('repo', token='token').download(url, target, len(payload))
            self.assertEqual(target.read_bytes(), payload[:1048576])

    def test_deadline_exhaustion_stops_without_another_retry(self):
        with artifact_server('resume') as (url, payload, requests), tempfile.TemporaryDirectory() as folder:
            with patch('ci_tier_artifacts.time.monotonic', side_effect=[0, 3601, 3601]):
                with self.assertRaisesRegex(RuntimeError, 'TimeoutError'):
                    GitHubAPI('repo', token='token').download(url, Path(folder)/'handoff.zip', len(payload))
            self.assertEqual(len(requests), 2)
