#!/usr/bin/env python3
"""Focused tests for the offline TCP four-table configuration converter.

Run with:
    python3 -m unittest discover -s plugins/tcp_proxy/tools -p 'test_*.py' -v
"""

from __future__ import annotations

import ast
import hashlib
import io
import os
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
import unittest
import urllib.parse
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import migrate_tcp_config as migration  # noqa: E402

# Real root fixtures are opt-in only; all required coverage is synthetic.
FIXTURES = os.environ.get("TCP_PROXY_LEGACY_FIXTURES")
FIXTURES_AVAILABLE = bool(FIXTURES) and all(
    os.path.isfile(os.path.join(FIXTURES, name))
    for name in ("mapped-original.db", "static-original.db")
)
SPEC_PATH = os.path.join(
    REPO_ROOT, "docs/superpowers/specs/2026-11-11-tcp-four-table-design.md"
)
DEFAULT_PLUGIN_SCHEMA_SOURCE = os.path.join(
    REPO_ROOT, "plugins/tcp_proxy/src/admin.cpp"
)
OLD_HOSTGROUPS_COMMENT = "owner's legacy note\nsecond line\tUTF-8: λ"


def _parse_concatenated_cpp_literals(text: str, position: int) -> str:
    parts = []
    while True:
        match = re.match(r'\s*("(?:[^"\\]|\\.)*")', text[position:])
        if match is None:
            break
        parts.append(ast.literal_eval(match.group(1)))
        position += match.end()
    if not parts:
        raise ValueError("no concatenated C++ string literals found")
    return "".join(parts)


def parse_plugin_hostgroups_ddl(path: str) -> str:
    """Extract tcp_hostgroups DDL from the plugin's kPersistentTables block."""
    with open(path, "r", encoding="utf-8") as handle:
        source = handle.read()
    begin = source.find("const TableDefinition kPersistentTables[]")
    end = source.find("const TableDefinition kRuntimeTables[]", begin + 1)
    if begin < 0 or end < 0:
        raise ValueError("cannot locate kPersistentTables/kRuntimeTables blocks")
    block = source[begin:end]
    name_match = re.search(r'"tcp_hostgroups"', block)
    if name_match is None:
        raise ValueError("tcp_hostgroups is not in kPersistentTables")
    comma = block.find(",", name_match.end())
    if comma < 0:
        raise ValueError("tcp_hostgroups table entry has no comma after its name")
    return _parse_concatenated_cpp_literals(block, comma + 1)


def authoritative_spec_ddl() -> str:
    with open(SPEC_PATH, "r", encoding="utf-8") as handle:
        spec = handle.read()
    matches = re.findall(r"^CREATE TABLE tcp_hostgroups \(.*$", spec, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one authoritative tcp_hostgroups DDL line, found {len(matches)}"
        )
    return matches[0].strip()


def rewrite_stored_sql(path: str, table: str, sql: str) -> None:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA writable_schema=ON")
    conn.execute(
        "UPDATE sqlite_master SET sql=? WHERE type='table' AND name=?",
        (sql, table),
    )
    conn.commit()
    conn.execute("PRAGMA writable_schema=OFF")
    conn.close()


def stored_sql(path: str, table: str) -> str:
    conn = sqlite3.connect(path)
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    conn.close()
    if row is None or row[0] is None:
        raise AssertionError(f"missing stored SQL for {table}")
    return row[0]


def _connect(path):
    return sqlite3.connect(
        "file:" + urllib.parse.quote(path, safe="/") + "?mode=ro",
        uri=True,
        timeout=5.0,
    )


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def database_state(path):
    conn = _connect(path)
    conn.text_factory = bytes
    schema = tuple(
        conn.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
    )
    tables = [row[1] for row in schema if row[0] == b"table"]
    rows = {}
    for table in tables:
        name = table.decode("utf-8")
        escaped = name.replace('"', '""')
        rows[name] = tuple(conn.execute(f'SELECT * FROM "{escaped}"').fetchall())
    conn.close()
    return schema, rows


def metadata_state(path):
    conn = _connect(path)
    conn.text_factory = bytes
    rows = tuple(
        conn.execute(
            "SELECT typeof(type), type, typeof(name), name,"
            " typeof(tbl_name), tbl_name, typeof(sql), sql"
            " FROM sqlite_master ORDER BY rowid"
        ).fetchall()
    )
    conn.close()
    return rows


def rewrite_metadata(path, table, **columns):
    names = list(columns)
    assignments = ", ".join(f'"{name}"=?' for name in names)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA writable_schema=ON")
    conn.execute(
        f"UPDATE sqlite_master SET {assignments} WHERE type='table' AND name=?",
        [columns[name] for name in names] + [table],
    )
    conn.commit()
    conn.execute("PRAGMA writable_schema=OFF")
    conn.close()


def non_tcp_rows(state):
    _, rows = state
    return {
        name: values
        for name, values in rows.items()
        if not any(name.lower().startswith(prefix) for prefix in migration.TCP_NAME_PREFIXES)
    }


def create_legacy(
    path,
    *,
    hostgroups=(),
    mappings=None,
    servers=(),
    listeners=(),
    rules=(),
    settings=(1, 2, 10000, 16384, 20, 30000),
):
    conn = sqlite3.connect(path)
    conn.execute(migration.OLD_TCP_SETTINGS_DDL)
    conn.execute(migration.OLD_HOSTGROUPS_DDL)
    conn.execute(migration.OLD_SERVERS_DDL)
    conn.execute(migration.OLD_LISTENERS_DDL)
    conn.execute(migration.OLD_RULES_DDL)
    if mappings is not None:
        conn.execute(migration.OLD_MAPPINGS_DDL)
    conn.execute(
        "INSERT INTO tcp_settings"
        " (id, worker_threads, max_connections, buffer_size, shutdown_timeout_ms, half_close_timeout_ms)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        settings,
    )
    conn.executemany(
        "INSERT INTO tcp_hostgroups"
        " (hostgroup_id, balance, health_check_interval_ms, health_check_timeout_ms,"
        "  health_check_rise, health_check_fall, comment)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        hostgroups,
    )
    if mappings is not None:
        conn.executemany(
            "INSERT INTO tcp_hostgroup_mappings"
            " (hostgroup_id, source_protocol, source_hostgroup, comment) VALUES (?, ?, ?, ?)",
            mappings,
        )
    conn.executemany(
        "INSERT INTO tcp_servers"
        " (server_id, hostgroup_id, hostname, port, status, weight, max_connections, backup, comment)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        servers,
    )
    conn.executemany(
        "INSERT INTO tcp_listeners"
        " (listener_id, active, bind_address, bind_port, default_hostgroup,"
        "  max_connections, connect_timeout_ms, idle_timeout_ms, max_connect_attempts, comment)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        listeners,
    )
    conn.executemany(
        "INSERT INTO tcp_routing_rules"
        " (rule_id, active, listener_id, source_cidr, action, destination_hostgroup, comment)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        rules,
    )
    conn.execute(
        "CREATE TABLE unrelated_payload"
        " (id INTEGER PRIMARY KEY, payload BLOB, note TEXT)"
    )
    conn.execute(
        "INSERT INTO unrelated_payload(id, payload, note) VALUES (?, ?, ?)",
        (1, sqlite3.Binary(b"\x00\x01\xfe\xffblob"), "apostrophe's λ\tline\nend"),
    )
    conn.commit()
    conn.close()


def create_current(path, *, hostgroups=(), listeners=(), rules=()):
    conn = sqlite3.connect(path)
    conn.execute(migration.OLD_TCP_SETTINGS_DDL)
    conn.execute(migration.NEW_HOSTGROUPS_DDL)
    conn.execute(migration.OLD_LISTENERS_DDL)
    conn.execute(migration.OLD_RULES_DDL)
    conn.execute(
        "INSERT INTO tcp_settings"
        " (id, worker_threads, max_connections, buffer_size, shutdown_timeout_ms, half_close_timeout_ms)"
        " VALUES (1, 2, 10000, 16384, 20, 30000)"
    )
    conn.executemany(
        "INSERT INTO tcp_hostgroups"
        " (hostgroup_id, source_protocol, source_hostgroup, comment) VALUES (?, ?, ?, ?)",
        hostgroups,
    )
    conn.executemany(
        "INSERT INTO tcp_listeners"
        " (listener_id, active, bind_address, bind_port, default_hostgroup,"
        "  max_connections, connect_timeout_ms, idle_timeout_ms, max_connect_attempts, comment)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        listeners,
    )
    conn.executemany(
        "INSERT INTO tcp_routing_rules"
        " (rule_id, active, listener_id, source_cidr, action, destination_hostgroup, comment)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        rules,
    )
    conn.commit()
    conn.close()


def standard_legacy(path):
    create_legacy(
        path,
        hostgroups=[(20, "roundrobin", 0, 500, 2, 3, "hostgroup note")],
        mappings=[(20, "MYSQL", 10, "mapping note")],
        listeners=[(5, 0, "127.0.0.1", 38371, 20, 10000, 2000, 60000, 3, "listener")],
        rules=[(7, 0, 5, "127.0.0.0/8", "ROUTE", 20, "rule")],
    )


def run_main(args):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        rc = migration.main(args)
    return rc, stdout.getvalue(), stderr.getvalue()


def backup_path(database):
    return os.path.abspath(database) + migration.DEFAULT_BACKUP_SUFFIX


def backup_tcp_schema(path):
    conn = _connect(path)
    conn.text_factory = bytes
    objects = tuple(
        conn.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master"
            " WHERE name LIKE 'tcp%' ORDER BY name"
        ).fetchall()
    )
    conn.close()
    return objects


class ConverterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tcp-migrate-test-")
        self.addCleanup(self.temp.cleanup)

    def db(self, name="proxysql.db"):
        return os.path.join(self.temp.name, name)

    def test_converter_ddl_matches_authoritative_spec(self):
        self.assertEqual(migration.NEW_HOSTGROUPS_DDL, authoritative_spec_ddl())

    def test_plugin_source_parser_reads_new_definition(self):
        ddl = migration.NEW_HOSTGROUPS_DDL
        first = ddl[:37]
        second = ddl[37:]
        snippet = (
            "const TableDefinition kPersistentTables[] {\n"
            "{\n"
            '"tcp_hostgroups",\n'
            f'"{first}"\n'
            f'"{second}"\n'
            "},\n"
            "};\n"
            "const TableDefinition kRuntimeTables[] {\n"
            "};\n"
        )
        path = self.db("admin_schema.cpp")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(snippet)
        self.assertEqual(parse_plugin_hostgroups_ddl(path), ddl)

    def test_converter_ddl_matches_plugin_source(self):
        source = os.environ.get("TCP_PROXY_SCHEMA_SOURCE", DEFAULT_PLUGIN_SCHEMA_SOURCE)
        if not os.path.isfile(source):
            self.skipTest(f"plugin schema source is not present: {source}")
        ddl = parse_plugin_hostgroups_ddl(source)
        explicit_source = os.environ.get("TCP_PROXY_SCHEMA_SOURCE")
        if (
            not explicit_source
            and migration.canonical_table_definition(ddl)
            == migration.canonical_table_definition(migration.OLD_HOSTGROUPS_DDL)
        ):
            self.skipTest(
                "private worktree admin.cpp still has the legacy tcp_hostgroups DDL; "
                "run with TCP_PROXY_SCHEMA_SOURCE pointing at the final four-table source"
            )
        self.assertEqual(ddl, migration.NEW_HOSTGROUPS_DDL)

    @unittest.skipUnless(
        FIXTURES_AVAILABLE,
        "set TCP_PROXY_LEGACY_FIXTURES to run optional real-fixture tests",
    )
    def test_fixtures_recognized(self):
        mapped = os.path.join(self.temp.name, "mapped.db")
        static = os.path.join(self.temp.name, "static.db")
        shutil.copy2(os.path.join(FIXTURES, "mapped-original.db"), mapped)
        shutil.copy2(os.path.join(FIXTURES, "static-original.db"), static)
        original_hashes = {
            path: file_sha256(path) for path in (mapped, static)
        }
        rc, output, _ = run_main(["--database", mapped, "--check"])
        self.assertEqual(rc, 0, output)
        self.assertIn("migration required", output)
        rc, _, error = run_main(["--database", static, "--check"])
        self.assertEqual(rc, 1)
        self.assertIn("tcp_servers", error)
        for path, digest in original_hashes.items():
            self.assertEqual(file_sha256(path), digest, "read-only check modified a fixture copy")

    def test_missing_database_is_never_created(self):
        missing = self.db("missing.db")
        rc, _, error = run_main(["--database", missing, "--apply"])
        self.assertEqual(rc, 1)
        self.assertIn("refusing to create", error)
        self.assertFalse(os.path.exists(missing))
        self.assertFalse(os.path.exists(backup_path(missing)))

    def test_noncanonical_stored_sql_is_rejected_without_mutation(self):
        def lower_create(ddl):
            return ddl.replace("CREATE TABLE", "create table", 1)

        def if_not_exists(ddl):
            return ddl.replace("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1)

        cases = (
            ("legacy lowercase CREATE", "legacy", "tcp_settings", lower_create),
            ("legacy stored IF NOT EXISTS", "legacy", "tcp_settings", if_not_exists),
            ("current lowercase CREATE", "current", "tcp_settings", lower_create),
            (
                "current embedded NUL stored SQL",
                "current",
                "tcp_hostgroups",
                lambda ddl: ddl + "\x00tail",
            ),
        )
        for label, layout, table, mutate in cases:
            with self.subTest(case=label):
                path = self.db(label.replace(" ", "_") + ".db")
                if layout == "legacy":
                    standard_legacy(path)
                else:
                    create_current(path, hostgroups=[(20, "MYSQL", 10, "")])
                rewrite_stored_sql(path, table, mutate(stored_sql(path, table)))
                before = database_state(path)
                rc, _, error = run_main(["--database", path, "--check"])
                self.assertEqual(rc, 1, f"{label} check accepted: {error}")
                self.assertEqual(database_state(path), before)
                rc, _, error = run_main(["--database", path, "--apply"])
                self.assertEqual(rc, 1, f"{label} apply accepted: {error}")
                self.assertEqual(database_state(path), before)
                self.assertFalse(os.path.exists(backup_path(path)))

    def test_metadata_storage_and_name_identity_are_rejected(self):
        cases = (
            (
                "SQL BLOB with identical bytes",
                "current",
                "tcp_hostgroups",
                lambda stored: {"sql": stored.encode("utf-8")},
            ),
            (
                "case-only object name with unchanged SQL",
                "current",
                "tcp_settings",
                lambda stored: {"name": "TCP_SETTINGS", "tbl_name": "TCP_SETTINGS"},
            ),
            (
                "BLOB object name with identical bytes",
                "legacy",
                "tcp_settings",
                lambda stored: {"name": b"tcp_settings"},
            ),
            (
                "NUL-suffixed object name",
                "legacy",
                "tcp_settings",
                lambda stored: {"name": "tcp_settings\x00tail"},
            ),
            (
                "BLOB object type",
                "legacy",
                "tcp_settings",
                lambda stored: {"type": b"table"},
            ),
            (
                "NUL-suffixed object type",
                "legacy",
                "tcp_settings",
                lambda stored: {"type": "table\x00tail"},
            ),
        )
        for label, layout, table, mutation in cases:
            with self.subTest(case=label):
                path = self.db(label.replace(" ", "_") + ".db")
                if layout == "legacy":
                    standard_legacy(path)
                else:
                    create_current(path, hostgroups=[(20, "MYSQL", 10, "")])
                rewrite_metadata(
                    path,
                    table,
                    **mutation(stored_sql(path, table)),
                )
                before_metadata = metadata_state(path)
                before_hash = file_sha256(path)
                rc, _, error = run_main(["--database", path, "--check"])
                self.assertEqual(rc, 1, f"{label} check accepted: {error}")
                self.assertEqual(metadata_state(path), before_metadata)
                self.assertEqual(file_sha256(path), before_hash)
                rc, _, error = run_main(["--database", path, "--apply"])
                self.assertEqual(rc, 1, f"{label} apply accepted: {error}")
                self.assertEqual(metadata_state(path), before_metadata)
                self.assertEqual(file_sha256(path), before_hash)
                self.assertFalse(os.path.exists(backup_path(path)))

    def test_check_is_default_read_only(self):
        path = self.db()
        standard_legacy(path)
        before_hash = file_sha256(path)
        before_state = database_state(path)
        rc, output, _ = run_main(["--database", path])
        self.assertEqual(rc, 0)
        self.assertIn("migration required", output)
        self.assertEqual(file_sha256(path), before_hash)
        self.assertEqual(database_state(path), before_state)
        self.assertFalse(os.path.exists(backup_path(path)))

    def test_apply_mapped_multiple_hostgroups_preserves_everything(self):
        path = self.db()
        create_legacy(
            path,
            hostgroups=[
                (20, "roundrobin", 0, 500, 2, 3, OLD_HOSTGROUPS_COMMENT),
                (21, "leastconn", 500, 500, 2, 3, ""),
                (22, "roundrobin", 1000, 500, 2, 3, "same"),
                (23, "roundrobin", 0, 500, 2, 3, ""),
            ],
            mappings=[
                (20, "MYSQL", 10, "separate mapping note"),
                (21, "PGSQL", 10, "only mapping"),
                (22, "MYSQL", 11, "same"),
                (23, "PGSQL", 12, ""),
            ],
            listeners=[
                (5, 0, "127.0.0.1", 38371, 20, 10000, 2000, 60000, 3, "inactive listener preserved"),
                (6, 0, "::1", 38372, 21, 10000, 2000, 0, 3, "second listener"),
            ],
            rules=[
                (7, 0, 5, "127.0.0.0/8", "ROUTE", 20, "inactive rule preserved"),
                (8, 1, None, None, "REJECT", None, "reject all"),
            ],
        )
        before = database_state(path)
        rc, output, error = run_main(["--database", path, "--apply"])
        self.assertEqual(rc, 0, error)
        self.assertIn("migration committed", output)
        self.assertIn("hostgroups: 4 migrated", output)
        after = database_state(path)

        # Only the TCP tables changed. Settings, listeners, rules, and all
        # unrelated rows (including the arbitrary BLOB) are byte/content exact.
        before_unrelated = non_tcp_rows(before)
        after_unrelated = non_tcp_rows(after)
        for table in ("tcp_settings", "tcp_listeners", "tcp_routing_rules"):
            self.assertEqual(before[1][table], after[1][table], table)
        self.assertEqual(before_unrelated, after_unrelated)

        conn = _connect(path)
        conn.row_factory = sqlite3.Row
        conn.text_factory = str
        schema = {
            row["name"]: row["sql"]
            for row in conn.execute("SELECT name, sql FROM sqlite_master WHERE name LIKE 'tcp%'")
        }
        self.assertEqual(set(schema), set(migration.CURRENT_TCP_TABLES))
        self.assertEqual(schema["tcp_hostgroups"], migration.NEW_HOSTGROUPS_DDL)
        rows = {
            row["hostgroup_id"]: dict(row)
            for row in conn.execute("SELECT * FROM tcp_hostgroups")
        }
        self.assertEqual(rows[20]["source_protocol"], "MYSQL")
        self.assertEqual(rows[20]["source_hostgroup"], 10)
        self.assertEqual(
            rows[20]["comment"],
            OLD_HOSTGROUPS_COMMENT + "\n" + "separate mapping note",
        )
        self.assertEqual(rows[21]["source_protocol"], "PGSQL")
        self.assertEqual(rows[21]["source_hostgroup"], 10)
        self.assertEqual(rows[21]["comment"], "only mapping")
        self.assertEqual(rows[22]["comment"], "same")
        self.assertEqual(rows[23]["comment"], "")
        conn.close()

        backup = backup_path(path)
        self.assertTrue(os.path.exists(backup))
        self.assertEqual(stat.S_IMODE(os.stat(backup).st_mode), 0o600)
        backup_names = {row[1].decode() for row in backup_tcp_schema(backup)}
        self.assertEqual(backup_names, set(migration.OLD_SIX_SET))
        backup_conn = _connect(backup)
        self.assertEqual(
            backup_conn.execute("SELECT COUNT(*) FROM tcp_hostgroup_mappings").fetchone()[0],
            4,
        )
        backup_conn.close()

    @unittest.skipUnless(
        FIXTURES_AVAILABLE,
        "set TCP_PROXY_LEGACY_FIXTURES to run optional real-fixture tests",
    )
    def test_real_mapped_fixture_conversion_and_backup(self):
        path = self.db()
        shutil.copy2(os.path.join(FIXTURES, "mapped-original.db"), path)
        before = database_state(path)
        rc, output, error = run_main(["--database", path, "--apply"])
        self.assertEqual(rc, 0, error)
        self.assertIn("backup:", output)
        after = database_state(path)
        self.assertEqual(non_tcp_rows(before), non_tcp_rows(after))
        for table in ("tcp_settings", "tcp_listeners", "tcp_routing_rules"):
            self.assertEqual(before[1][table], after[1][table])

        conn = _connect(path)
        conn.text_factory = str
        comment = conn.execute("SELECT comment FROM tcp_hostgroups WHERE hostgroup_id=20").fetchone()[0]
        self.assertEqual(
            comment,
            "owner's legacy note\nsecond line\tUTF-8: λ\nseparate mapping note",
        )
        self.assertEqual(
            conn.execute("SELECT source_protocol, source_hostgroup FROM tcp_hostgroups").fetchone(),
            ("MYSQL", 10),
        )
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM root_upgrade_probe").fetchone()[0], 1
        )
        conn.close()

        backup = backup_path(path)
        backup_names = {row[1].decode() for row in backup_tcp_schema(backup)}
        self.assertEqual(backup_names, set(migration.OLD_SIX_SET))
        backup_conn = _connect(backup)
        self.assertEqual(
            backup_conn.execute("PRAGMA integrity_check").fetchone()[0], "ok"
        )
        backup_conn.close()

    @unittest.skipUnless(
        FIXTURES_AVAILABLE,
        "set TCP_PROXY_LEGACY_FIXTURES to run optional real-fixture tests",
    )
    def test_static_fixture_is_rejected_without_mutation(self):
        path = self.db()
        shutil.copy2(os.path.join(FIXTURES, "static-original.db"), path)
        before_hash = file_sha256(path)
        before_state = database_state(path)
        rc, _, error = run_main(["--database", path, "--apply"])
        self.assertEqual(rc, 1)
        self.assertIn("tcp_servers", error)
        self.assertEqual(file_sha256(path), before_hash)
        self.assertEqual(database_state(path), before_state)
        self.assertFalse(os.path.exists(backup_path(path)))

    def test_empty_five_table_is_supported_nonempty_is_not(self):
        empty = self.db("empty.db")
        create_legacy(empty, mappings=None)
        rc, output, error = run_main(["--database", empty, "--apply"])
        self.assertEqual(rc, 0, error)
        conn = _connect(empty)
        self.assertEqual(
            conn.execute("SELECT COUNT(*) FROM tcp_hostgroups").fetchone()[0], 0
        )
        conn.close()

        mapped = self.db("mapped-five.db")
        create_legacy(
            mapped,
            mappings=None,
            hostgroups=[(20, "roundrobin", 0, 500, 2, 3, "unmapped")],
        )
        before = database_state(mapped)
        rc, _, error = run_main(["--database", mapped, "--apply"])
        self.assertEqual(rc, 1)
        self.assertIn("no source mapping", error)
        self.assertEqual(database_state(mapped), before)
        self.assertFalse(os.path.exists(backup_path(mapped)))

    def test_current_schema_is_idempotent_no_backup(self):
        path = self.db()
        create_current(
            path,
            hostgroups=[(20, "MYSQL", 10, "current")],
            listeners=[(5, 1, "127.0.0.1", 38371, 20, 10000, 2000, 60000, 3, "")],
            rules=[(7, 1, 5, "127.0.0.0/8", "ROUTE", 20, "")],
        )
        before_hash = file_sha256(path)
        rc, output, error = run_main(["--database", path, "--apply"])
        self.assertEqual(rc, 0, error)
        self.assertIn("no migration required", output)
        self.assertEqual(file_sha256(path), before_hash)
        self.assertFalse(os.path.exists(backup_path(path)))

    def test_idempotent_second_apply_keeps_backup(self):
        path = self.db()
        standard_legacy(path)
        rc, _, error = run_main(["--database", path, "--apply"])
        self.assertEqual(rc, 0, error)
        backup = backup_path(path)
        backup_hash = file_sha256(backup)
        after_first = database_state(path)
        after_first_hash = file_sha256(path)
        rc, output, error = run_main(["--database", path, "--apply"])
        self.assertEqual(rc, 0, error)
        self.assertIn("no migration required", output)
        self.assertEqual(database_state(path), after_first)
        self.assertEqual(file_sha256(path), after_first_hash)
        self.assertEqual(file_sha256(backup), backup_hash)

    def test_unexpected_artifacts_even_with_current_hostgroups_are_rejected(self):
        current = self.db("current.db")
        create_current(current, hostgroups=[(20, "MYSQL", 10, "")])
        conn = sqlite3.connect(current)
        conn.execute(migration.OLD_SERVERS_DDL)
        conn.commit()
        conn.close()
        before = database_state(current)
        rc, _, error = run_main(["--database", current, "--check"])
        self.assertEqual(rc, 1)
        self.assertIn("mixed TCP table layout", error)
        self.assertEqual(database_state(current), before)

        for name, sql in (
            ("temporary", "CREATE TABLE tcp_hostgroups_new (id INTEGER)"),
            ("prefixed-legacy", "CREATE TABLE old_tcp_hostgroups (id INTEGER)"),
            ("view", "CREATE VIEW tcp_settings_view AS SELECT 1"),
            ("index", "CREATE INDEX tcp_idx ON tcp_settings(id)"),
        ):
            with self.subTest(artifact=name):
                path = self.db(name + ".db")
                create_current(path)
                conn = sqlite3.connect(path)
                conn.execute(sql)
                conn.commit()
                conn.close()
                rc, _, error = run_main(["--database", path, "--check"])
                self.assertEqual(rc, 1)
                self.assertIn("unknown or temporary TCP object", error)

    def test_partial_or_unknown_layout_is_rejected(self):
        path = self.db("partial.db")
        standard_legacy(path)
        conn = sqlite3.connect(path)
        conn.execute("DROP TABLE tcp_routing_rules")
        conn.commit()
        conn.close()
        before = database_state(path)
        rc, _, error = run_main(["--database", path, "--check"])
        self.assertEqual(rc, 1)
        self.assertIn("unknown TCP table layout", error)
        self.assertEqual(database_state(path), before)

        empty = self.db("no-tcp.db")
        sqlite3.connect(empty).close()
        rc, _, error = run_main(["--database", empty, "--check"])
        self.assertEqual(rc, 1)
        self.assertIn("no recognized TCP", error)

    def test_strict_row_validation(self):
        def mutate(sql, params=()):
            def apply(path):
                conn = sqlite3.connect(path)
                conn.execute("PRAGMA ignore_check_constraints=ON")
                conn.execute(sql, params)
                conn.commit()
                conn.close()

            return apply

        cases = [
            ("settings range", mutate("UPDATE tcp_settings SET worker_threads=65")),
            ("settings storage type", mutate("UPDATE tcp_settings SET worker_threads='two'")),
            ("listener address", mutate("UPDATE tcp_listeners SET bind_address='host.example'")),
            ("listener mapped v6", mutate("UPDATE tcp_listeners SET bind_address='::ffff:127.0.0.1'")),
            ("listener port", mutate("UPDATE tcp_listeners SET bind_port=0")),
            ("listener dangling hostgroup", mutate("UPDATE tcp_listeners SET default_hostgroup=99")),
            ("listener comment NUL", mutate("UPDATE tcp_listeners SET comment=?", ("bad\x00comment",))),
            ("rule noncanonical CIDR", mutate("UPDATE tcp_routing_rules SET source_cidr='10.0.0.1/8'")),
            ("rule malformed CIDR", mutate("UPDATE tcp_routing_rules SET source_cidr='10.0.0.0'")),
            ("rule ROUTE without destination", mutate("UPDATE tcp_routing_rules SET destination_hostgroup=NULL")),
            ("rule REJECT with destination", mutate("UPDATE tcp_routing_rules SET action='REJECT'")),
            ("rule dangling listener", mutate("UPDATE tcp_routing_rules SET listener_id=99")),
            ("rule action", mutate("UPDATE tcp_routing_rules SET action='DROP'")),
            ("mapping protocol", mutate("UPDATE tcp_hostgroup_mappings SET source_protocol='OTHER'")),
            ("mapping comment NUL", mutate("UPDATE tcp_hostgroup_mappings SET comment=?", ("bad\x00comment",))),
            ("hostgroup comment NUL", mutate("UPDATE tcp_hostgroups SET comment=?", ("bad\x00comment",))),
            (
                "orphan mapping",
                mutate(
                    "INSERT INTO tcp_hostgroup_mappings"
                    " (hostgroup_id, source_protocol, source_hostgroup, comment)"
                    " VALUES (99, 'MYSQL', 10, '')"
                ),
            ),
            (
                "unmapped hostgroup",
                mutate(
                    "INSERT INTO tcp_hostgroups"
                    " (hostgroup_id, balance, health_check_interval_ms, health_check_timeout_ms,"
                    "  health_check_rise, health_check_fall, comment)"
                    " VALUES (30, 'roundrobin', 0, 500, 2, 3, '')"
                ),
            ),
            (
                "nonempty servers",
                mutate(
                    "INSERT INTO tcp_servers"
                    " (server_id, hostgroup_id, hostname, port, status, weight,"
                    "  max_connections, backup, comment)"
                    " VALUES (9, 20, '127.0.0.1', 3306, 'ONLINE', 1, 1000, 0, '')"
                ),
            ),
        ]
        for label, mutate_fn in cases:
            with self.subTest(case=label):
                path = self.db(label.replace(" ", "_") + ".db")
                standard_legacy(path)
                mutate_fn(path)
                before = database_state(path)
                rc, _, error = run_main(["--database", path, "--check"])
                self.assertEqual(rc, 1, f"{label}: {error}")
                self.assertEqual(database_state(path), before)
                self.assertFalse(os.path.exists(backup_path(path)))

    def test_backup_collision_and_permissions(self):
        path = self.db()
        standard_legacy(path)
        collision = backup_path(path)
        with open(collision, "wb") as handle:
            handle.write(b"do-not-overwrite")
        before = database_state(path)
        rc, _, error = run_main(["--database", path, "--apply"])
        self.assertEqual(rc, 1)
        self.assertIn("refusing to overwrite", error)
        with open(collision, "rb") as handle:
            self.assertEqual(handle.read(), b"do-not-overwrite")
        self.assertEqual(database_state(path), before)

        override = self.db("custom.bak")
        with open(override, "wb") as handle:
            handle.write(b"also-keep")
        rc, _, error = run_main(["--database", path, "--apply", "--backup", override])
        self.assertEqual(rc, 1)
        self.assertIn("refusing to overwrite", error)
        with open(override, "rb") as handle:
            self.assertEqual(handle.read(), b"also-keep")

        os.unlink(collision)
        rc, _, error = run_main(["--database", path, "--apply"])
        self.assertEqual(rc, 0, error)
        self.assertEqual(stat.S_IMODE(os.stat(collision).st_mode), 0o600)

        custom_db = self.db("custom.db")
        standard_legacy(custom_db)
        chosen = self.db("chosen.bak")
        rc, output, error = run_main(
            ["--database", custom_db, "--apply", "--backup", chosen]
        )
        self.assertEqual(rc, 0, error)
        self.assertIn(f"backup: {chosen}", output)
        self.assertTrue(os.path.exists(chosen))
        self.assertFalse(os.path.exists(backup_path(custom_db)))

    def test_transaction_fault_rolls_back_and_backup_fault_aborts(self):
        path = self.db()
        standard_legacy(path)
        before = database_state(path)

        with mock.patch.object(
            migration, "_verify_migrated", side_effect=migration.MigrationError("injected verify fault")
        ):
            rc, _, error = run_main(["--database", path, "--apply"])
        self.assertEqual(rc, 1)
        self.assertIn("injected verify fault", error)
        self.assertEqual(database_state(path), before)
        self.assertTrue(os.path.exists(backup_path(path)), "a pre-mutation backup should remain usable")

        os.unlink(backup_path(path))
        with mock.patch.object(
            migration, "_write_backup", side_effect=migration.MigrationError("injected backup fault")
        ):
            rc, _, error = run_main(["--database", path, "--apply"])
        self.assertEqual(rc, 1)
        self.assertIn("injected backup fault", error)
        self.assertEqual(database_state(path), before)
        self.assertFalse(os.path.exists(backup_path(path)))

    def test_wal_backup_contains_committed_data(self):
        path = self.db()
        standard_legacy(path)
        keeper = sqlite3.connect(path, isolation_level=None)
        keeper.execute("PRAGMA journal_mode=WAL")
        keeper.execute("INSERT INTO unrelated_payload(id, payload, note) VALUES (2, ?, ?)",
                       (sqlite3.Binary(b"wal-blob"), "written into WAL"))
        self.assertTrue(os.path.exists(path + "-wal"), "test requires a live WAL file")

        rc, _, error = run_main(["--database", path, "--apply"])
        self.assertEqual(rc, 0, error)
        backup = backup_path(path)
        backup_conn = _connect(backup)
        self.assertEqual(
            backup_conn.execute(
                "SELECT note FROM unrelated_payload WHERE id=2"
            ).fetchone()[0],
            "written into WAL",
        )
        self.assertEqual(
            backup_conn.execute("SELECT COUNT(*) FROM tcp_hostgroup_mappings").fetchone()[0], 1
        )
        backup_conn.close()
        keeper.close()

    def test_backup_option_requires_apply(self):
        path = self.db()
        standard_legacy(path)
        with self.assertRaises(SystemExit) as raised:
            migration.main(["--database", path, "--check", "--backup", self.db("x.bak")])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
