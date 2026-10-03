#!/usr/bin/env python3
"""Exercise the built vendored HTTP transport using literal wire bytes."""
import http.client
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import unittest


class RawRequestTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.listener = socket.socket()
        cls.listener.bind(("127.0.0.1", 0))
        cls.listener.listen(8)
        cls.address = cls.listener.getsockname()
        driver = os.environ.get("HTTP_RAW_REQUEST_DRIVER", str(
            Path(__file__).with_name("http_raw_request_driver")))
        cls.server = subprocess.Popen(
            [driver, str(cls.listener.fileno())], pass_fds=(cls.listener.fileno(),),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        ready, _, _ = select.select([cls.server.stdout], [], [], 10)
        if not ready or cls.server.stdout.readline().strip() != "ready":
            cls.server.kill()
            cls.server.wait()
            cls.listener.close()
            raise RuntimeError("HTTP fixture did not start")
        cls.listener.close()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.server.communicate("stop\n", timeout=10)
        except subprocess.TimeoutExpired:
            cls.server.kill()
            cls.server.communicate()
            raise
        if cls.server.returncode != 0:
            raise RuntimeError(f"HTTP fixture exited {cls.server.returncode}")

    def request(self, raw):
        with socket.create_connection(self.address, timeout=5) as connection:
            connection.sendall(raw)
            reply = http.client.HTTPResponse(connection)
            reply.begin()
            return reply.status, json.loads(reply.read())

    def test_raw_percent_encoding_and_duplicate_query_preserved(self):
        status, result = self.request(
            b"GET /aws/rds?x=%2F&x=%2f HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertEqual(status, 200)
        self.assertEqual(result["target"], "/aws/rds?x=%2F&x=%2f")

    def test_duplicate_headers_not_collapsed(self):
        status, result = self.request(
            b"GET /aws/rds HTTP/1.1\r\nHost: localhost\r\n"
            b"X-Test: first\r\nx-test: second  value\r\n\r\n")
        self.assertEqual(status, 200)
        self.assertEqual([h for h in result["headers"] if h[0].lower() == "x-test"],
                         [["X-Test", "first"], ["x-test", "second  value"]])

    def test_original_form_body_preserved(self):
        status, result = self.request(
            b"POST /aws/rds HTTP/1.1\r\nHost: localhost\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 12\r\n\r\ndata=%2F+%2f")
        self.assertEqual(status, 200)
        self.assertEqual(result["body"], "data=%2F+%2f")
        self.assertEqual(result["arg"], "/ /")

    def test_exact_limit_is_accepted(self):
        status, result = self.request(
            b"POST /aws/rds HTTP/1.1\r\nHost: localhost\r\n"
            b"Content-Length: 16\r\n\r\n1234567890123456")
        self.assertEqual(status, 200)
        self.assertEqual(result["body"], "1234567890123456")

    def test_oversized_body_rejected_without_dispatch(self):
        _, before = self.request(b"GET /aws/rds HTTP/1.1\r\nHost: localhost\r\n\r\n")
        status, result = self.request(
            b"POST /aws/rds HTTP/1.1\r\nHost: localhost\r\n"
            b"Content-Length: 17\r\n\r\n12345678901234567")
        self.assertEqual(status, 413)
        self.assertEqual(result["dispatched"], before["dispatched"])

    def test_chunked_overflow_remains_rejected(self):
        _, before = self.request(b"GET /aws/rds HTTP/1.1\r\nHost: localhost\r\n\r\n")
        status, result = self.request(
            b"POST /aws/rds HTTP/1.1\r\nHost: localhost\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"10\r\n1234567890123456\r\n1\r\nx\r\n1\r\ny\r\n0\r\n\r\n")
        self.assertEqual(status, 413)
        self.assertEqual(result["dispatched"], before["dispatched"])

    def test_legacy_path_query_and_method(self):
        status, result = self.request(
            b"GET /aws/rds?data=hello%20world HTTP/1.1\r\nHost: localhost\r\n\r\n")
        self.assertEqual(status, 200)
        self.assertEqual(result["path"], "/aws/rds")
        self.assertEqual(result["method"], "GET")
        # This fixture leaves the existing optional unescaper unset.
        self.assertEqual(result["arg"], "hello%20world")


if __name__ == "__main__":
    unittest.main()
