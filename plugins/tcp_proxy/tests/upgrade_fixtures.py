#!/usr/bin/env python3
"""Portable, task-owned legacy TCP database fixtures for upgrade tests.

The module reads only literal DDL/schema constants from the real converter
source with ``ast``.  It never imports or executes the converter and performs no
daemon/SQLite service work beyond the task-owned files passed by the caller.
"""

from __future__ import annotations

import ast
import os
import shutil
import sqlite3
import stat
from pathlib import Path
from typing import Iterable, Optional

CONSTANT_NAMES = (
    "NEW_HOSTGROUPS_DDL",
    "OLD_TCP_SETTINGS_DDL",
    "OLD_HOSTGROUPS_DDL",
    "OLD_SERVERS_DDL",
    "OLD_LISTENERS_DDL",
    "OLD_RULES_DDL",
    "OLD_MAPPINGS_DDL",
    "CURRENT_TCP_TABLES",
)

CURRENT_TABLES = ("tcp_settings", "tcp_hostgroups", "tcp_listeners", "tcp_routing_rules")
LEGACY_SIX_TABLES = CURRENT_TABLES + ("tcp_servers", "tcp_hostgroup_mappings")
LEGACY_FIVE_TABLES = CURRENT_TABLES + ("tcp_servers",)
TCP_PREFIXES = ("tcp", "runtime_tcp", "stats_tcp")


def default_converter_path() -> Path:
    return (Path(__file__).resolve().parent.parent / "tools"
            / "migrate_tcp_config.py")


def resolve_converter_path(explicit: str = "") -> Path:
    value = explicit or os.environ.get("TCP_PROXY_CONVERTER", "")
    return Path(value).expanduser().resolve() if value else default_converter_path()


def read_converter_constants(converter: Path) -> dict:
    """Extract literal constants without importing or executing the converter."""
    converter = Path(converter)
    tree = ast.parse(converter.read_text(encoding="utf-8"), filename=str(converter))
    found = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in CONSTANT_NAMES:
            continue
        try:
            found[target.id] = ast.literal_eval(node.value)
        except (ValueError, SyntaxError) as exc:
            raise ValueError(f"{converter}: {target.id} is not a literal constant") from exc
    missing = [name for name in CONSTANT_NAMES if name not in found]
    if missing:
        raise ValueError(f"{converter}: missing converter constants: {missing}")
    return found


def merge_comment(hostgroup_comment: str, mapping_comment: str) -> str:
    """Approved merge rule, mirrored for fixture/selfcheck expectations."""
    if not hostgroup_comment:
        return mapping_comment
    if not mapping_comment:
        return hostgroup_comment
    if hostgroup_comment == mapping_comment:
        return hostgroup_comment
    return hostgroup_comment + "\n" + mapping_comment


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(path), timeout=10.0, isolation_level=None)
    connection.execute("PRAGMA foreign_keys=OFF")
    return connection


def clone_database(source: Path, target: Path) -> Path:
    source, target = Path(source), Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()
    source_conn = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    target_conn = sqlite3.connect(str(target))
    try:
        source_conn.backup(target_conn)
    finally:
        target_conn.close()
        source_conn.close()
    os.chmod(target, 0o600)
    return target


def clone_datadir(source: Path, target: Path) -> Path:
    source, target = Path(source), Path(target)
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(target / "proxysql.db") + suffix)
        if sidecar.exists():
            sidecar.unlink()
    return target


def _current_rows(connection: sqlite3.Connection) -> dict:
    settings = connection.execute(
        "SELECT id,worker_threads,max_connections,buffer_size,"
        "shutdown_timeout_ms,half_close_timeout_ms FROM tcp_settings").fetchall()
    listeners = connection.execute(
        "SELECT listener_id,active,bind_address,bind_port,default_hostgroup,"
        "max_connections,connect_timeout_ms,idle_timeout_ms,"
        "max_connect_attempts,comment FROM tcp_listeners").fetchall()
    rules = connection.execute(
        "SELECT rule_id,active,listener_id,source_cidr,action,"
        "destination_hostgroup,comment FROM tcp_routing_rules").fetchall()
    return {"settings": settings, "listeners": listeners, "rules": rules}


def _drop_known(connection: sqlite3.Connection) -> None:
    for table in set(CURRENT_TABLES) | set(LEGACY_SIX_TABLES):
        connection.execute(f'DROP TABLE IF EXISTS "{table}"')


def _create_common(connection: sqlite3.Connection, constants: dict) -> None:
    connection.execute(constants["OLD_TCP_SETTINGS_DDL"])
    connection.execute(constants["OLD_LISTENERS_DDL"])
    connection.execute(constants["OLD_RULES_DDL"])


def _insert_common(connection: sqlite3.Connection, rows: dict) -> None:
    connection.executemany(
        "INSERT INTO tcp_settings(id,worker_threads,max_connections,buffer_size,"
        "shutdown_timeout_ms,half_close_timeout_ms) VALUES(?,?,?,?,?,?)",
        rows["settings"])
    connection.executemany(
        "INSERT INTO tcp_listeners(listener_id,active,bind_address,bind_port,"
        "default_hostgroup,max_connections,connect_timeout_ms,idle_timeout_ms,"
        "max_connect_attempts,comment) VALUES(?,?,?,?,?,?,?,?,?,?)",
        rows["listeners"])
    connection.executemany(
        "INSERT INTO tcp_routing_rules(rule_id,active,listener_id,source_cidr,"
        "action,destination_hostgroup,comment) VALUES(?,?,?,?,?,?,?)",
        rows["rules"])


def create_legacy_mapped_fixture(current_db: Path, target_db: Path, constants: dict,
                                 hostgroups: Iterable[dict],
                                 source_protocol: str = "MYSQL",
                                 source_hostgroup: int = 10) -> dict:
    """Clone a fresh current DB and turn only its TCP tables into legacy six."""
    current_db, target_db = Path(current_db), Path(target_db)
    clone_database(current_db, target_db)
    connection = _connect(target_db)
    try:
        rows = _current_rows(connection)
        connection.execute("BEGIN IMMEDIATE")
        _drop_known(connection)
        _create_common(connection, constants)
        connection.execute(constants["OLD_HOSTGROUPS_DDL"])
        connection.execute(constants["OLD_SERVERS_DDL"])
        connection.execute(constants["OLD_MAPPINGS_DDL"])
        _insert_common(connection, rows)
        expected = []
        for group in hostgroups:
            identifier = int(group["hostgroup_id"])
            old_comment = group.get("hostgroup_comment", "")
            mapping_comment = group.get("mapping_comment", "")
            connection.execute(
                "INSERT INTO tcp_hostgroups(hostgroup_id,balance,"
                "health_check_interval_ms,health_check_timeout_ms,"
                "health_check_rise,health_check_fall,comment) "
                "VALUES(?,?,?,?,?,?,?)",
                (identifier, group.get("balance", "roundrobin"),
                 group.get("health_check_interval_ms", 0),
                 group.get("health_check_timeout_ms", 500),
                 group.get("health_check_rise", 2),
                 group.get("health_check_fall", 3), old_comment))
            connection.execute(
                "INSERT INTO tcp_hostgroup_mappings(hostgroup_id,source_protocol,"
                "source_hostgroup,comment) VALUES(?,?,?,?)",
                (identifier, source_protocol, source_hostgroup, mapping_comment))
            expected.append({
                "hostgroup_id": identifier,
                "source_protocol": source_protocol,
                "source_hostgroup": source_hostgroup,
                "comment": merge_comment(old_comment, mapping_comment),
            })
        connection.execute("COMMIT")
    except BaseException:
        try:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        connection.close()
    return {"database": str(target_db), "hostgroups": expected}


def create_legacy_static_fixture(current_db: Path, target_db: Path, constants: dict,
                                 server_port: int, hostgroup: int = 20) -> dict:
    current_db, target_db = Path(current_db), Path(target_db)
    clone_database(current_db, target_db)
    connection = _connect(target_db)
    try:
        rows = _current_rows(connection)
        connection.execute("BEGIN IMMEDIATE")
        _drop_known(connection)
        _create_common(connection, constants)
        connection.execute(constants["OLD_HOSTGROUPS_DDL"])
        connection.execute(constants["OLD_SERVERS_DDL"])
        _insert_common(connection, rows)
        connection.execute(
            "INSERT INTO tcp_hostgroups(hostgroup_id,balance,"
            "health_check_interval_ms,health_check_timeout_ms,"
            "health_check_rise,health_check_fall,comment) "
            "VALUES(?,?,?,?,?,?,?)",
            (hostgroup, "roundrobin", 0, 500, 2, 3, "static legacy"))
        connection.execute(
            "INSERT INTO tcp_servers(server_id,hostgroup_id,hostname,port,"
            "status,weight,max_connections,backup,comment) "
            "VALUES(1,?,'127.0.0.1',?,'ONLINE',1,10,0,'static endpoint')",
            (hostgroup, int(server_port)))
        connection.execute("COMMIT")
    except BaseException:
        try:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        connection.close()
    return {"database": str(target_db), "hostgroup": hostgroup}


def create_legacy_unmapped_fixture(current_db: Path, target_db: Path, constants: dict,
                                   hostgroup: int = 20) -> dict:
    current_db, target_db = Path(current_db), Path(target_db)
    clone_database(current_db, target_db)
    connection = _connect(target_db)
    try:
        rows = _current_rows(connection)
        connection.execute("BEGIN IMMEDIATE")
        _drop_known(connection)
        _create_common(connection, constants)
        connection.execute(constants["OLD_HOSTGROUPS_DDL"])
        connection.execute(constants["OLD_SERVERS_DDL"])
        _insert_common(connection, rows)
        connection.execute(
            "INSERT INTO tcp_hostgroups(hostgroup_id,balance,"
            "health_check_interval_ms,health_check_timeout_ms,"
            "health_check_rise,health_check_fall,comment) "
            "VALUES(?,?,?,?,?,?,?)",
            (hostgroup, "roundrobin", 0, 500, 2, 3, "unmapped legacy"))
        connection.execute("COMMIT")
    except BaseException:
        try:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        connection.close()
    return {"database": str(target_db), "hostgroup": hostgroup}


def create_unknown_layout_fixture(source_db: Path, target_db: Path) -> dict:
    clone_database(source_db, target_db)
    connection = _connect(Path(target_db))
    try:
        connection.execute("CREATE TABLE tcp_unexpected_fixture (payload TEXT)")
        connection.execute(
            "INSERT INTO tcp_unexpected_fixture(payload) VALUES('unknown layout')")
    finally:
        connection.close()
    return {"database": str(target_db)}


def _table_names(connection: sqlite3.Connection) -> list:
    return [row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()]


def _table_rows(connection: sqlite3.Connection, table: str) -> list:
    quoted = '"' + table.replace('"', '""') + '"'
    try:
        return connection.execute(f"SELECT * FROM {quoted} ORDER BY rowid").fetchall()
    except sqlite3.OperationalError:
        return connection.execute(f"SELECT * FROM {quoted}").fetchall()


def logical_database_snapshot(database: Path) -> dict:
    connection = sqlite3.connect(f"file:{Path(database)}?mode=ro", uri=True)
    try:
        schema = [tuple(row) for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "ORDER BY type,name,tbl_name").fetchall()]
        tables = {}
        for table in _table_names(connection):
            columns = [row[1] for row in connection.execute(
                f'PRAGMA table_info("{table}")').fetchall()]
            tables[table] = {"columns": columns,
                             "rows": [tuple(row) for row in _table_rows(connection, table)]}
        return {"schema": schema, "tables": tables}
    finally:
        connection.close()


def _is_tcp_table(name: str) -> bool:
    lower = name.lower()
    return any(lower.startswith(prefix) for prefix in TCP_PREFIXES)


def tcp_table_snapshot(database: Path) -> dict:
    snapshot = logical_database_snapshot(database)
    return {
        "schema": [row for row in snapshot["schema"] if _is_tcp_table(str(row[1]))],
        "tables": {name: value for name, value in snapshot["tables"].items()
                   if _is_tcp_table(name)},
    }


def unrelated_snapshot(database: Path) -> dict:
    snapshot = logical_database_snapshot(database)
    return {
        "schema": [row for row in snapshot["schema"] if not _is_tcp_table(str(row[1]))],
        "tables": {name: value for name, value in snapshot["tables"].items()
                   if not _is_tcp_table(name)},
    }


def file_sha256(path: Path) -> str:
    import hashlib
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def backup_mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)
