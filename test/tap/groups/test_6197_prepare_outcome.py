#!/usr/bin/env python3
"""Exercise the #6197 TAP result classifier through real libpq wire responses."""

import socket
import struct
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "test/tap/tests/pgsql-reg_test_6197_ps_name_collision-t.cpp"
OFFLINE_MESSAGE = (
    "Backend server went offline during query (hostgroup 6197, s1.example:5432); "
    "query cannot be retried"
)


def packet(kind, payload):
    return kind + struct.pack("!I", len(payload) + 4) + payload


def error(state, severity="ERROR", message="unrelated error"):
    fields = f"S{severity}\0V{severity}\0C{state}\0M{message}\0\0".encode()
    return packet(b"E", fields)


def read_exact(conn, size):
    data = b""
    while len(data) < size:
        part = conn.recv(size - len(data))
        if not part:
            raise EOFError("client closed before completing its request")
        data += part
    return data


class PrepareOutcomeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        source = SOURCE.read_text()
        helper = "struct PrepareOutcome" + (
            source.split("struct PrepareOutcome", 1)[1].split("static bool cleanup", 1)[0]
        )
        probe = Path(cls.tmp.name) / "probe.cpp"
        probe.write_text('''#include <cstdio>
#include <cstdlib>
#include <string>
#include "libpq-fe.h"
''' + helper + '''
int main(int, char** argv) {
    PGconn* c=PQconnectdb(argv[1]);
    if (PQstatus(c)!=CONNECTION_OK || !PQsendPrepare(c,"","SELECT 15",0,nullptr)) return 2;
    const auto result=read_prepare_result(c,argv[2]);
    printf("%d %d %d %d\\n%s",result.succeeded(),result.expected_refusal(atol(argv[3]),atol(argv[4])),
        !result.first_collision.empty(),result.other_error,result.first_error.c_str());
    PQfinish(c);
}
''')
        cls.binary = Path(cls.tmp.name) / "probe"
        include = subprocess.check_output(["pg_config", "--includedir"], text=True).strip()
        libdir = subprocess.check_output(["pg_config", "--libdir"], text=True).strip()
        subprocess.run(["c++", "-std=c++11", "-Wall", "-Wextra", f"-I{include}", str(probe),
                        f"-L{libdir}", "-lpq", "-o", str(cls.binary)], check=True, capture_output=True)

    def classify(self, responses, s2_before=100, s2_after=100):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(5)
            failures = []

            def serve():
                try:
                    with listener.accept()[0] as conn:
                        conn.settimeout(5)
                        startup_size = struct.unpack("!I", read_exact(conn, 4))[0]
                        read_exact(conn, startup_size - 4)
                        conn.sendall(packet(b"R", struct.pack("!I", 0)) +
                                     packet(b"S", b"server_version\0" + b"16.0\0") +
                                     packet(b"Z", b"I"))
                        # Consume Parse and Sync completely before closing, so
                        # unread client bytes cannot reset the socket and lose FATAL.
                        while True:
                            kind = read_exact(conn, 1)
                            size = struct.unpack("!I", read_exact(conn, 4))[0]
                            read_exact(conn, size - 4)
                            if kind == b"S":
                                break
                        conn.sendall(responses)
                        conn.shutdown(socket.SHUT_WR)
                except Exception as exc:
                    failures.append(exc)

            server = threading.Thread(target=serve, daemon=True)
            server.start()
            result = subprocess.run(
                [str(self.binary), f"host=127.0.0.1 port={listener.getsockname()[1]} user=test sslmode=disable",
                 OFFLINE_MESSAGE, str(s2_before), str(s2_after)], capture_output=True, text=True, timeout=10)
            server.join(timeout=6)
            self.assertFalse(server.is_alive(), "wire server did not finish")
            self.assertFalse(failures, failures)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        counts, _, first_error = result.stdout.partition("\n")
        return tuple(map(int, counts.split())), first_error

    def test_offline_fatal_then_eof_is_expected_and_preserves_the_reason(self):
        counts, first = self.classify(error("57P01", "FATAL", OFFLINE_MESSAGE))
        self.assertEqual(counts, (0, 1, 0, 0))
        self.assertIn(OFFLINE_MESSAGE, first)
        self.assertNotIn("server closed", first)

    def test_bare_eof_fails(self):
        counts, _ = self.classify(b"")
        self.assertEqual(counts, (0, 0, 0, 1))

    def test_wrong_shutdown_reason_or_severity_fails(self):
        for response in (error("57P01", "FATAL", "backend restart"),
                         error("57P01", "ERROR", OFFLINE_MESSAGE),
                         error("57P01", "FATAL", OFFLINE_MESSAGE.replace("6197", "6198")),
                         error("57P01", "FATAL", OFFLINE_MESSAGE.replace("s1.example", "s2.example")),
                         error("57P01", "FATAL", OFFLINE_MESSAGE.replace("5432", "5433"))):
            with self.subTest(response=response):
                counts, _ = self.classify(response)
                self.assertEqual(counts, (0, 0, 0, 1))

    def test_refusal_after_s2_work_is_not_accepted(self):
        for before, after in ((100, 101), (-1, 100), (100, -1), (100, 99)):
            with self.subTest(before=before, after=after):
                counts, _ = self.classify(error("57P01", "FATAL", OFFLINE_MESSAGE),
                                          s2_before=before, s2_after=after)
                self.assertEqual(counts[:3], (0, 0, 0))

    def test_collisions_and_other_errors_fail_in_either_order(self):
        refusal = error("57P01", "FATAL", OFFLINE_MESSAGE)
        for state, message in (("42P05", 'prepared statement "proxysql_ps_1" already exists'),
                               ("XX000", "unrelated error")):
            problem = error(state, message=message)
            for responses in (problem + refusal, refusal + problem):
                with self.subTest(state=state, responses=responses):
                    counts, _ = self.classify(responses)
                    self.assertEqual(counts[:2], (0, 0))
                    self.assertTrue(counts[2] if state == "42P05" else counts[3])

    def test_command_complete_succeeds(self):
        counts, _ = self.classify(packet(b"1", b"") + packet(b"Z", b"I"))
        self.assertEqual(counts, (1, 0, 0, 0))


if __name__ == "__main__":
    unittest.main()
