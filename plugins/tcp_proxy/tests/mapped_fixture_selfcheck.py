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
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import daemon_admin_smoke as base
import upgrade_fixtures as upgrade
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
            return
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


def _make_current_database(path, constants):
    connection = sqlite3.connect(path)
    try:
        connection.execute(constants["NEW_HOSTGROUPS_DDL"])
        connection.execute(constants["OLD_TCP_SETTINGS_DDL"])
        connection.execute(constants["OLD_LISTENERS_DDL"])
        connection.execute(constants["OLD_RULES_DDL"])
        connection.execute(
            "CREATE TABLE mysql_servers(hostgroup_id INTEGER,hostname TEXT,port INTEGER,"
            "status TEXT,weight INTEGER,max_connections INTEGER,comment TEXT)")
        connection.execute(
            "CREATE TABLE upgrade_sentinel(id INTEGER PRIMARY KEY,payload TEXT)")
        connection.execute(
            "CREATE TABLE global_variables(variable_name TEXT PRIMARY KEY,variable_value TEXT)")
        connection.execute(
            "INSERT INTO global_variables VALUES('admin-mysql_ifaces','127.0.0.1:19999')")
        connection.execute(
            "INSERT INTO tcp_settings(id,worker_threads,max_connections,buffer_size,"
            "shutdown_timeout_ms,half_close_timeout_ms) VALUES(1,2,10000,16384,5000,30000)")
        connection.execute(
            "INSERT INTO tcp_listeners VALUES(1,1,'127.0.0.1',16033,20,10000,2000,"
            "60000,3,'selfcheck listener')")
        connection.execute(
            "INSERT INTO tcp_routing_rules VALUES(1,1,1,NULL,'ROUTE',20,"
            "'selfcheck rule')")
        connection.execute(
            "INSERT INTO tcp_hostgroups VALUES(20,'MYSQL',10,'current base')")
        connection.execute(
            "INSERT INTO mysql_servers VALUES(10,'127.0.0.1',3306,'ONLINE',1,100,"
            "'source')")
        connection.execute(
            "INSERT INTO upgrade_sentinel(id,payload) VALUES(1,'preserve-me')")
        connection.commit()
    finally:
        connection.close()


def check_upgrade_fixtures(converter):
    constants = upgrade.read_converter_constants(Path(converter))
    check("converter constants extracted without import",
          "CREATE TABLE tcp_hostgroups (" in constants["NEW_HOSTGROUPS_DDL"])
    groups = [
        {"hostgroup_id": 20, "hostgroup_comment": "",
         "mapping_comment": "mapped nonempty"},
        {"hostgroup_id": 21, "hostgroup_comment": "equal comment",
         "mapping_comment": "equal comment"},
        {"hostgroup_id": 22, "hostgroup_comment": "host 'quoted'\tline1\nline2",
         "mapping_comment": "map 'quoted'\tline1\nline2"},
        {"hostgroup_id": 23, "hostgroup_comment": "host-only",
         "mapping_comment": ""},
    ]
    with tempfile.TemporaryDirectory(prefix="upgrade-fixture-selfcheck-") as tmp:
        tmp = Path(tmp)
        current = tmp / "current.db"
        _make_current_database(current, constants)
        unrelated_before = upgrade.unrelated_snapshot(current)

        mapped = tmp / "legacy-mapped.db"
        fixture = upgrade.create_legacy_mapped_fixture(
            current, mapped, constants, groups)
        snapshot = upgrade.logical_database_snapshot(mapped)
        check("legacy mapped fixture has exactly six config tables",
              tuple(sorted(name for name in snapshot["tables"]
                           if name.startswith("tcp"))) ==
              tuple(sorted(upgrade.LEGACY_SIX_TABLES)),
              str(sorted(snapshot["tables"])))
        check("legacy tcp_servers is empty",
              snapshot["tables"]["tcp_servers"]["rows"] == [], "")
        mapped_rows = snapshot["tables"]["tcp_hostgroups"]["rows"]
        mapping_rows = snapshot["tables"]["tcp_hostgroup_mappings"]["rows"]
        expected_old = [group["hostgroup_comment"] for group in groups]
        expected_mapping = [group["mapping_comment"] for group in groups]
        check("legacy hostgroup comments preserved exactly",
              [row[6] for row in mapped_rows] == expected_old, "")
        check("legacy mapping comments preserved exactly",
              [row[3] for row in mapping_rows] == expected_mapping, "")
        check("approved merged comment examples",
              [row["comment"] for row in fixture["hostgroups"]] == [
                  "mapped nonempty", "equal comment",
                  "host 'quoted'\tline1\nline2\nmap 'quoted'\tline1\nline2",
                  "host-only"], "")
        check("unrelated source/sentinel tables preserved",
              upgrade.unrelated_snapshot(mapped) == unrelated_before, "")

        static = tmp / "legacy-static.db"
        upgrade.create_legacy_static_fixture(current, static, constants, 3307)
        static_snapshot = upgrade.logical_database_snapshot(static)
        check("legacy static fixture has five tables and nonempty server",
              "tcp_hostgroup_mappings" not in static_snapshot["tables"]
              and static_snapshot["tables"]["tcp_servers"]["rows"], "")

        unmapped = tmp / "legacy-unmapped.db"
        upgrade.create_legacy_unmapped_fixture(current, unmapped, constants)
        unmapped_snapshot = upgrade.logical_database_snapshot(unmapped)
        check("legacy unmapped fixture has empty servers and no mappings",
              "tcp_hostgroup_mappings" not in unmapped_snapshot["tables"]
              and unmapped_snapshot["tables"]["tcp_servers"]["rows"] == [], "")

        unknown = tmp / "unknown-layout.db"
        upgrade.create_unknown_layout_fixture(mapped, unknown)
        check("unknown layout fixture adds an unexpected TCP object",
              "tcp_unexpected_fixture" in
              upgrade.logical_database_snapshot(unknown)["tables"], "")

        # Actual-clone preservation oracle: mutate the child DB and prove the
        # comparison fails while the original fixture remains untouched.
        child_clone = tmp / "cloned-child.db"
        upgrade.clone_database(mapped, child_clone)
        original_before = upgrade.logical_database_snapshot(mapped)
        child_before = upgrade.logical_database_snapshot(child_clone)
        child_connection = sqlite3.connect(child_clone)
        try:
            child_connection.execute(
                "UPDATE upgrade_sentinel SET payload='mutated-child-only' WHERE id=1")
            child_connection.commit()
        finally:
            child_connection.close()
        check("preservation oracle detects mutated cloned daemon DB",
              upgrade.logical_database_snapshot(child_clone) != child_before, "")
        check("child clone mutation leaves original fixture untouched",
              upgrade.logical_database_snapshot(mapped) == original_before, "")

        # Editable Admin oracle: unrestored memory must differ from saved rows.
        import daemon_mapped_smoke as mapped_module

        base_datadir = tmp / "base-datadir"
        base_datadir.mkdir()
        upgrade.clone_database(current, base_datadir / "proxysql.db")
        clone_context = SimpleNamespace(host="/bin/false", plugin="/bin/false",
                                        mysql="/bin/false", run_dir=str(tmp))
        prepared = mapped_module._clone_datadir_for_database(
            clone_context, SimpleNamespace(datadir=str(base_datadir)), mapped,
            "prepared-child")
        with sqlite3.connect(Path(prepared.datadir) / "proxysql.db") as connection:
            saved_endpoint = connection.execute(
                "SELECT variable_value FROM global_variables "
                "WHERE variable_name='admin-mysql_ifaces'").fetchone()[0]
        check("cloned saved Admin endpoint matches child helper port",
              saved_endpoint == f"{base.HOST}:{prepared.admin_port}", saved_endpoint)
        with sqlite3.connect(mapped) as connection:
            original_endpoint = connection.execute(
                "SELECT variable_value FROM global_variables "
                "WHERE variable_name='admin-mysql_ifaces'").fetchone()[0]
        check("preparing child Admin endpoint leaves original fixture unchanged",
              original_endpoint == "127.0.0.1:19999", original_endpoint)

        class FakeResult:
            def __init__(self, stdout=""):
                self.returncode = 0
                self.stdout = stdout
                self.stderr = ""

        class FakeAdmin:
            def __init__(self, tables):
                self.tables = tables

            def query(self, sql, timeout=10):
                for table, rows in self.tables.items():
                    if f"FROM {table}" in sql:
                        return FakeResult("".join(
                            "\t".join(row) + "\n" for row in rows))
                return FakeResult("")

        saved_admin = {
            "tcp_settings": (("1", "3", "10000", "16384", "5000", "30000"),),
            "tcp_hostgroups": (("21", "MYSQL", "10", "5341564544"),),
            "tcp_listeners": (("1", "1", "127.0.0.1", "16033", "20",
                               "10000", "2000", "60000", "3", "5341564544"),),
            "tcp_routing_rules": (("1", "1", "1", "NULL", "ROUTE", "20",
                                   "5341564544"),),
        }
        mutated_admin = dict(saved_admin)
        mutated_admin["tcp_settings"] = (("1", "1", "10000", "16384", "5000",
                                         "30000"),)
        mutated_admin["tcp_routing_rules"] = ()
        check("Admin editable oracle rejects unrestored/mutated memory",
              mapped_module._editable_admin_snapshot(FakeAdmin(mutated_admin))
              != saved_admin, "")
        restored_admin = dict(saved_admin)
        check("Admin editable oracle accepts exact restored rows",
              mapped_module._editable_admin_snapshot(FakeAdmin(restored_admin))
              == saved_admin, "")

        core_guard = (
            "Plugin config_db schema preflight detected a schema mismatch for "
            "table 'tcp_hostgroups'; stop ProxySQL and run the owning plugin's "
            "offline schema-migration tool before restarting.")
        check("refusal log oracle accepts core guard context",
              mapped_module._core_schema_refusal_log(core_guard), "")
        check("refusal log oracle rejects unrelated startup crash",
              not mapped_module._core_schema_refusal_log(
                  "fatal: unrelated plugin load crash in tcp runtime"), "")

        class MutatingRefusalChild:
            datadir = prepared.datadir

            def start_expect_refusal(self, timeout=25):
                with sqlite3.connect(Path(self.datadir) / "proxysql.db") as connection:
                    connection.execute(
                        "UPDATE upgrade_sentinel SET payload='child-start-mutation' WHERE id=1")
                return {"argv": ["task-owned-fake-child"], "timed_out": False,
                        "returncode": 1, "log_segment": core_guard}

            def close(self):
                pass

        negative_case = mapped_module.Case("mutation-probe", str(tmp))
        with patch.object(mapped_module, "_clone_datadir_for_database",
                          return_value=MutatingRefusalChild()), \
                patch.object(base, "can_connect", return_value=False):
            mapped_module._legacy_startup_refusal(
                negative_case, clone_context, SimpleNamespace(), mapped,
                16033, "mutation-probe")
        check("startup-refusal integration oracle detects actual child DB mutation",
              len(negative_case.failures) == 1
              and "actual cloned daemon DB unchanged" in negative_case.failures[0],
              str(negative_case.failures))

        fake = base.Daemon("/bin/false", "/bin/false", "/bin/false", str(tmp),
                           "fake-refusal", initial=False)
        Path(fake.datadir).mkdir(parents=True, exist_ok=True)
        Path(fake.log_path).write_text(
            core_guard + "\nOLD LOG MUST NOT COUNT\n", encoding="utf-8")
        try:
            refused = fake.start_expect_refusal(timeout=3)
        finally:
            fake.close()
        check("expected-refusal helper omits --initial",
              "--initial" not in refused["argv"], str(refused["argv"]))
        check("expected-refusal helper observes nonzero bounded exit",
              not refused["timed_out"] and refused["returncode"] != 0, str(refused))
        check("expected-refusal log segment excludes copied old log",
              "old log must not count" not in
              (refused.get("log_segment") or "").lower(), str(refused))


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
    check("no legacy TCP server/mapping SQL is generated",
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
    parser.add_argument("--converter", default=str(upgrade.resolve_converter_path()),
                        help="offline migrate_tcp_config.py (read-only constants)")
    args = parser.parse_args(argv)
    check_schema_and_sql()
    check_upgrade_fixtures(args.converter)
    check_pg(args.psql, args.skip_psql)
    if args.skip_mysql:
        print("[SKIP] MySQL fixture (--skip-mysql)")
    else:
        check_mysql(args.mysql)
    print("mapped fixture selfcheck: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
