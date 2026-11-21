#!/usr/bin/env python3
"""Focused self-checks for the mapped monitor fixtures using installed clients.

Exercises the controlled PostgreSQL wire fixture with the real ``psql`` client
(``sslmode=disable`` and ``prefer``), fragmented startup framing, opaque binary
echo, and the task-owned MySQL fixture lifecycle.  No product daemon or
existing service is used.
"""

from __future__ import annotations

import argparse
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import daemon_admin_smoke as base
from mapped_monitor_fixtures import (
    FOUR_TABLE_SCHEMA,
    REMOVED_SCHEMA,
    MysqlFixture,
    PgWireFixture,
    configure_mapped,
    require_mapping_schema,
    validate_source_namespaces,
)

TESTS_DIR = Path(__file__).resolve().parent
DEFAULT_PSQL = "/usr/lib/postgresql/16/bin/psql"


def psql_path():
    return (shutil.which("psql")
            or (DEFAULT_PSQL if Path(DEFAULT_PSQL).is_file() else ""))


def recv_until_ready(sock, timeout=5.0):
    sock.settimeout(timeout)
    data = bytearray()
    while not data.endswith(b"Z\x00\x00\x00\x05I"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def check(name, condition, detail=""):
    print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f" ({detail})" if detail else ""))
    if not condition:
        raise AssertionError(f"{name}: {detail}")


def check_pg(psql, skip_psql):
    fixture = PgWireFixture()
    try:
        # Opaque binary echo, including NUL and 0xff first bytes.
        for first in (b"\x00", b"\xff"):
            payload = first + b"opaque\x00binary\xff" * 32
            with socket.create_connection(("127.0.0.1", fixture.port), timeout=3) as sock:
                sock.sendall(payload)
                got = bytearray()
                while len(got) < len(payload):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    got.extend(chunk)
            check(f"raw echo first byte 0x{first.hex()}", bytes(got) == payload,
                  f"{len(got)}/{len(payload)} bytes")

        # Fragmented StartupMessage: header split across two writes.
        tail = b"user\x00tester\x00database\x00test\x00\x00"
        startup = struct.pack("!ii", 8 + len(tail), 196608) + tail
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=3) as sock:
            sock.sendall(startup[:4])
            time.sleep(0.08)
            sock.sendall(startup[4:])
            reply = recv_until_ready(sock)
        check("fragmented PG startup accepted", reply.startswith(b"R") and b"Z" in reply,
              f"{len(reply)} reply bytes")

        if skip_psql:
            print("[SKIP] psql checks (--skip-psql)")
        else:
            check("psql client found", bool(psql), psql or "not found")
            dsn = (f"host=127.0.0.1 port={fixture.port} user=tester dbname=test "
                   "connect_timeout=3")
            for mode in ("disable", "prefer"):
                for value in ("f", "t"):
                    fixture.set_recovery(value == "t")
                    cp = subprocess.run(
                        [psql, f"{dsn} sslmode={mode}", "-XAt", "-c",
                         "SELECT pg_is_in_recovery()"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                        timeout=15)
                    check(f"psql sslmode={mode} recovery={value}",
                          cp.returncode == 0 and cp.stdout.strip() == value,
                          f"rc={cp.returncode} out={cp.stdout.strip()!r} "
                          f"err={cp.stderr.strip()[:200]!r}")
    finally:
        fixture.close()
    check("PG fixture accept thread joined", not fixture._thread.is_alive(), "")
    check("PG fixture worker threads joined",
          all(not thread.is_alive() for thread in fixture._threads), "")


def check_mysql(mysql_cli):
    if not shutil.which("mysqld"):
        print("[SKIP] mysqld unavailable")
        return
    base = tempfile.mkdtemp(prefix="mapped-fixture-selfcheck-", dir="/tmp")
    fixture = None
    try:
        fixture = MysqlFixture.create(base, mysql_cli)
        value = fixture.sql("SELECT 1").stdout.strip()
        check("own mysqld fixture SELECT 1", value == "1", value)
        check("read_only initial 0",
              fixture.sql("SELECT @@global.read_only").stdout.strip() == "0", "")
        fixture.set_read_only(True)
        check("read_only toggled 1",
              fixture.sql("SELECT @@global.read_only").stdout.strip() == "1", "")
        fixture.set_read_only(False)
        check("read_only restored 0",
              fixture.sql("SELECT @@global.read_only").stdout.strip() == "0", "")
        proc = fixture.proc
        fixture.close()
        fixture = None
        check("own mysqld reaped after close", proc.poll() is not None,
              f"poll={proc.poll()}")
    finally:
        if fixture is not None:
            fixture.close()
        shutil.rmtree(base, ignore_errors=True)


def check_schema_and_sql():
    """Pure four-table SQL-shape check; no daemon or socket is started."""
    assert FOUR_TABLE_SCHEMA == (
        "tcp_settings", "tcp_hostgroups", "tcp_listeners", "tcp_routing_rules")
    for removed in ("tcp_servers", "tcp_hostgroup_mappings",
                    "runtime_tcp_servers", "runtime_tcp_hostgroup_mappings",
                    "stats_tcp_servers", "stats_tcp_hostgroup_mappings"):
        assert removed in REMOVED_SCHEMA

    class FakeResult:
        def __init__(self, returncode=0, stdout="", stderr=""):
            self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

    class FakeDaemon:
        def __init__(self):
            self.sql = []

        def query(self, sql, timeout=10):
            self.sql.append(sql)
            for removed in REMOVED_SCHEMA:
                if f"FROM {removed}" in sql or f"INTO {removed}" in sql:
                    return FakeResult(1, "", f"no such table: {removed}")
            return FakeResult(0, "", "")

    fake = FakeDaemon()
    assert require_mapping_schema(fake) == "tcp_hostgroups"
    configure_mapped(fake, "MYSQL", 10, 20, 12345,
                     [{"port": 3306, "max_connections": 7}],
                     mapping_comment="schema-check")
    joined = "\n".join(fake.sql)
    check("four-table schema probes run", len(fake.sql) >= len(FOUR_TABLE_SCHEMA))
    check("mandatory mapping insert has exactly four columns",
          "INTO tcp_hostgroups(hostgroup_id,source_protocol,source_hostgroup,comment)"
          in joined)
    check("no TCP server/mapping SQL is generated",
          all(f"INTO {removed}" not in joined for removed in REMOVED_SCHEMA))
    check("source protocol load precedes TCP config load",
          joined.index("LOAD MYSQL SERVERS TO RUNTIME")
          < joined.index("LOAD TCP CONFIG TO RUNTIME"))
    check("listener references the TCP mapping",
          "INTO tcp_listeners" in joined and ",20," in joined)

    source_fake = FakeDaemon()
    source_fake.query = lambda sql, timeout=10: FakeResult(
        0, "20\tMYSQL\t10\n21\tMYSQL\t10\n", "")
    rows = validate_source_namespaces(source_fake)
    check("source namespace rows parsed", rows == [
        {"hostgroup_id": 20, "source_protocol": "MYSQL", "source_hostgroup": 10},
        {"hostgroup_id": 21, "source_protocol": "MYSQL", "source_hostgroup": 10},
    ], str(rows))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-mysql", action="store_true")
    parser.add_argument("--skip-psql", action="store_true")
    parser.add_argument("--mysql", default=shutil.which("mysql") or "")
    parser.add_argument("--psql", default=psql_path())
    args = parser.parse_args(argv)
    if args.psql and not (shutil.which(args.psql) or Path(args.psql).is_file()):
        parser.error(f"--psql executable not found: {args.psql}")
    check_schema_and_sql()
    check_pg(args.psql, args.skip_psql)
    if args.skip_mysql:
        print("[SKIP] MySQL fixture (--skip-mysql)")
    else:
        check_mysql(args.mysql)
    print("mapped fixture selfcheck: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
