#!/usr/bin/env python3
"""Offline migration of the TCP proxy plugin to its four-table schema.

STOP ProxySQL BEFORE RUNNING THIS TOOL.  The tool takes a SQLite write
reservation, but only an offline daemon guarantees that no other writer is
active while the saved configuration is validated and replaced.

The database path is explicit and must already exist; this tool never creates
a database.  The default mode is read-only ``--check``.  ``--apply``:

* opens the existing database read/write and acquires ``BEGIN IMMEDIATE``;
* revalidates every legacy row while the reservation is held;
* writes an independent full SQLite backup through the SQLite backup API,
  including committed WAL contents, to an exclusive mode-0600 file that is
  never overwritten;
* replaces only ``tcp_hostgroups`` with the canonical four-table definition,
  inserts the validated mapping projection, and drops the empty
  ``tcp_servers`` and legacy ``tcp_hostgroup_mappings`` tables in one
  transaction;
* verifies stored DDL, rows, references, untouched configuration rows,
  integrity, and foreign keys before committing; any failure rolls back all
  schema/data changes.

Default backup path: ``<database>.tcp-four-table-before-migration.bak``.
Use ``--backup PATH`` to choose another path.  The file is created exclusively
with permissions 0600 and is never overwritten.  It contains the complete
pre-migration database (including retired hostgroup health/balance columns and
static servers).

Rollback: stop ProxySQL, then replace the database with the backup and remove
any stale ``-wal``/``-shm`` sidecars that belonged to the converted database
before restarting.  Keep ProxySQL stopped for both migration and rollback.

Exit status: 0 when check succeeds (current or supported migration) or apply
commits; 1 for validation/IO/migration failures; 2 for command-line misuse.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sqlite3
import stat
import sys
import urllib.parse
from dataclasses import dataclass
from typing import Iterable, Optional

INT32_MIN = -(2**31)
INT32_MAX = 2**31 - 1

# This is the authoritative four-table hostgroup definition.  It must remain
# byte-for-byte identical to the plugin's register_schemas hostgroup DDL and
# to docs/superpowers/specs/2026-11-11-tcp-four-table-design.md.  The apply
# path creates this exact string so the core preflight accepts the result.
NEW_HOSTGROUPS_DDL = (
    "CREATE TABLE tcp_hostgroups ("
    " hostgroup_id INTEGER PRIMARY KEY CHECK(hostgroup_id >= 0),"
    " source_protocol TEXT NOT NULL CHECK(source_protocol IN ('MYSQL','PGSQL')),"
    " source_hostgroup INTEGER NOT NULL CHECK(source_hostgroup >= 0),"
    " comment TEXT NOT NULL DEFAULT '')"
)

CURRENT_TCP_TABLES = (
    "tcp_settings",
    "tcp_hostgroups",
    "tcp_listeners",
    "tcp_routing_rules",
)

OLD_TCP_SETTINGS_DDL = (
    "CREATE TABLE tcp_settings ("
    " id INTEGER PRIMARY KEY CHECK(id=1),"
    " worker_threads INTEGER NOT NULL DEFAULT 2 CHECK(worker_threads BETWEEN 1 AND 64),"
    " max_connections INTEGER NOT NULL DEFAULT 10000 CHECK(max_connections BETWEEN 1 AND 1000000),"
    " buffer_size INTEGER NOT NULL DEFAULT 16384 CHECK(buffer_size BETWEEN 1024 AND 1048576),"
    " shutdown_timeout_ms INTEGER NOT NULL DEFAULT 5000 CHECK(shutdown_timeout_ms BETWEEN 0 AND 60000),"
    " half_close_timeout_ms INTEGER NOT NULL DEFAULT 30000 CHECK(half_close_timeout_ms BETWEEN 1 AND 3600000)"
    ")"
)

OLD_HOSTGROUPS_DDL = (
    "CREATE TABLE tcp_hostgroups ("
    " hostgroup_id INTEGER PRIMARY KEY CHECK(hostgroup_id >= 0),"
    " balance TEXT NOT NULL DEFAULT 'roundrobin' CHECK(balance IN ('roundrobin','leastconn')),"
    " health_check_interval_ms INTEGER NOT NULL DEFAULT 1000 CHECK(health_check_interval_ms=0 OR (health_check_interval_ms BETWEEN 100 AND 3600000)),"
    " health_check_timeout_ms INTEGER NOT NULL DEFAULT 500 CHECK(health_check_timeout_ms BETWEEN 1 AND 60000),"
    " health_check_rise INTEGER NOT NULL DEFAULT 2 CHECK(health_check_rise BETWEEN 1 AND 100),"
    " health_check_fall INTEGER NOT NULL DEFAULT 3 CHECK(health_check_fall BETWEEN 1 AND 100),"
    " comment TEXT NOT NULL DEFAULT ''"
    ")"
)

OLD_SERVERS_DDL = (
    "CREATE TABLE tcp_servers ("
    " server_id INTEGER PRIMARY KEY CHECK(server_id >= 0),"
    " hostgroup_id INTEGER NOT NULL CHECK(hostgroup_id >= 0),"
    " hostname TEXT NOT NULL CHECK(length(hostname) > 0),"
    " port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),"
    " status TEXT NOT NULL DEFAULT 'ONLINE' CHECK(status IN ('ONLINE','OFFLINE_SOFT','OFFLINE_HARD')),"
    " weight INTEGER NOT NULL DEFAULT 1 CHECK(weight BETWEEN 1 AND 1000),"
    " max_connections INTEGER NOT NULL DEFAULT 1000 CHECK(max_connections BETWEEN 1 AND 1000000),"
    " backup INTEGER NOT NULL DEFAULT 0 CHECK(backup IN (0,1)),"
    " comment TEXT NOT NULL DEFAULT ''"
    ")"
)

OLD_LISTENERS_DDL = (
    "CREATE TABLE tcp_listeners ("
    " listener_id INTEGER PRIMARY KEY CHECK(listener_id >= 0),"
    " active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),"
    " bind_address TEXT NOT NULL DEFAULT '0.0.0.0' CHECK(length(bind_address) > 0),"
    " bind_port INTEGER NOT NULL CHECK(bind_port BETWEEN 1 AND 65535),"
    " default_hostgroup INTEGER NOT NULL CHECK(default_hostgroup >= 0),"
    " max_connections INTEGER NOT NULL DEFAULT 10000 CHECK(max_connections BETWEEN 1 AND 1000000),"
    " connect_timeout_ms INTEGER NOT NULL DEFAULT 2000 CHECK(connect_timeout_ms BETWEEN 1 AND 60000),"
    " idle_timeout_ms INTEGER NOT NULL DEFAULT 60000 CHECK(idle_timeout_ms=0 OR (idle_timeout_ms BETWEEN 1 AND 86400000)),"
    " max_connect_attempts INTEGER NOT NULL DEFAULT 3 CHECK(max_connect_attempts BETWEEN 1 AND 16),"
    " comment TEXT NOT NULL DEFAULT ''"
    ")"
)

OLD_RULES_DDL = (
    "CREATE TABLE tcp_routing_rules ("
    " rule_id INTEGER PRIMARY KEY CHECK(rule_id >= 0),"
    " active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),"
    " listener_id INTEGER NULL CHECK(listener_id IS NULL OR listener_id >= 0),"
    " source_cidr TEXT NULL,"
    " action TEXT NOT NULL DEFAULT 'ROUTE' CHECK(action IN ('ROUTE','REJECT')),"
    " destination_hostgroup INTEGER NULL CHECK(destination_hostgroup IS NULL OR destination_hostgroup >= 0),"
    " comment TEXT NOT NULL DEFAULT ''"
    ")"
)

OLD_MAPPINGS_DDL = (
    "CREATE TABLE tcp_hostgroup_mappings ("
    " hostgroup_id INTEGER PRIMARY KEY CHECK(hostgroup_id >= 0),"
    " source_protocol TEXT NOT NULL CHECK(source_protocol IN ('MYSQL','PGSQL')),"
    " source_hostgroup INTEGER NOT NULL CHECK(source_hostgroup >= 0),"
    " comment TEXT NOT NULL DEFAULT ''"
    ")"
)

OLD_FIVE_SET = frozenset(
    ("tcp_settings", "tcp_hostgroups", "tcp_servers", "tcp_listeners", "tcp_routing_rules")
)
OLD_SIX_SET = OLD_FIVE_SET | {"tcp_hostgroup_mappings"}
KNOWN_TCP_TABLES = frozenset(CURRENT_TCP_TABLES) | OLD_SIX_SET
TCP_NAME_PREFIXES = ("tcp", "runtime_tcp", "stats_tcp")

DEFAULT_BACKUP_SUFFIX = ".tcp-four-table-before-migration.bak"


class MigrationError(Exception):
    """A validation, schema, or IO condition that must abort the migration."""


@dataclass(frozen=True)
class Column:
    name: str
    kind: str
    nullable: bool = False
    minimum: Optional[int] = None
    maximum: Optional[int] = None


@dataclass(frozen=True)
class ProjectedHostgroup:
    hostgroup_id: int
    source_protocol: str
    source_hostgroup: int
    comment: str


@dataclass(frozen=True)
class MigrationPlan:
    schema: str
    hostgroups: tuple
    has_mappings_table: bool


@dataclass(frozen=True)
class SchemaObject:
    object_type: str
    name: str
    table_name: str
    sql: Optional[str]


def _text(value: bytes, label: str) -> str:
    try:
        decoded = value.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise MigrationError(f"{label} is not valid UTF-8: {exc}") from exc
    if "\x00" in decoded:
        raise MigrationError(f"{label} contains an embedded NUL byte")
    return decoded


def _schema_text(value, label: str) -> str:
    if not isinstance(value, bytes):
        raise MigrationError(f"{label} is not SQLite TEXT")
    return _text(value, label)


def canonical_table_definition(sql: str) -> str:
    """Match SQLite3DB::canonical_table_definition() exactly.

    SQLite stores an uppercase CREATE TABLE prefix without IF NOT EXISTS.  Only
    the leading keywords and whitespace between them are normalized; the name
    and body are preserved.
    """
    match = re.match(r"^[ \t\n\r\f]*CREATE[ \t\n\r\f]+TABLE[ \t\n\r\f]+(?:IF[ \t\n\r\f]+NOT[ \t\n\r\f]+EXISTS[ \t\n\r\f]+)?", sql, re.IGNORECASE)
    if match is None:
        return sql
    return "CREATE TABLE " + sql[match.end():]


def _ddl_matches(stored: str, expected: str) -> bool:
    # The core builder/preflight canonicalizes only the registered definition
    # and compares the complete stored sqlite_master.sql value exactly.  Do not
    # normalize stored SQL here: a noncanonical stored prefix (or an embedded
    # NUL, rejected earlier) must be refused rather than silently accepted and
    # then rejected by startup after a "successful" conversion.
    return stored == canonical_table_definition(expected)


def _connect(path: str, mode: str) -> sqlite3.Connection:
    uri = "file:" + urllib.parse.quote(os.path.abspath(path), safe="/") + "?mode=" + mode
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=5.0, isolation_level=None)
    except sqlite3.Error as exc:
        raise MigrationError(f"cannot open database '{path}': {exc}") from exc
    conn.text_factory = bytes
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _require_existing_database(path: str) -> None:
    if not os.path.exists(path):
        raise MigrationError(
            f"database file does not exist (refusing to create it): {path}"
        )
    if not os.path.isfile(path):
        raise MigrationError(f"database path is not a regular file: {path}")


def _execute(conn: sqlite3.Connection, sql: str, params: Iterable = ()) -> list:
    try:
        return conn.execute(sql, tuple(params)).fetchall()
    except sqlite3.Error as exc:
        raise MigrationError(f"SQLite error while running {sql!r}: {exc}") from exc


def _read_rows(conn: sqlite3.Connection, table: str, columns: tuple) -> list:
    type_exprs = ", ".join(f'typeof("{column.name}")' for column in columns)
    value_exprs = ", ".join(f'"{column.name}"' for column in columns)
    sql = f'SELECT rowid, {type_exprs}, {value_exprs} FROM "{table}"'
    try:
        raw_rows = conn.execute(sql).fetchall()
    except sqlite3.Error as exc:
        raise MigrationError(f"cannot read required table {table}: {exc}") from exc

    rows = []
    for raw in raw_rows:
        rowid = raw[0]
        storage_types = raw[1:1 + len(columns)]
        values = raw[1 + len(columns):]
        row = {}
        for column, storage_type, value in zip(columns, storage_types, values):
            label = f"{table}.{column.name} (rowid {rowid})"
            if storage_type == b"null":
                if not column.nullable:
                    raise MigrationError(f"{label} must not be NULL")
                row[column.name] = None
                continue
            if column.kind == "integer":
                if storage_type != b"integer" or type(value) is not int:
                    raise MigrationError(
                        f"{label} must be stored as INTEGER (found {storage_type!r})"
                    )
                if value < INT32_MIN or value > INT32_MAX:
                    raise MigrationError(f"{label} is outside signed 32-bit range")
                if column.minimum is not None and value < column.minimum:
                    raise MigrationError(f"{label} must be at least {column.minimum}")
                if column.maximum is not None and value > column.maximum:
                    raise MigrationError(f"{label} must be at most {column.maximum}")
                row[column.name] = value
            elif column.kind == "text":
                if storage_type != b"text" or not isinstance(value, bytes):
                    raise MigrationError(
                        f"{label} must be stored as TEXT (found {storage_type!r})"
                    )
                row[column.name] = _text(value, label)
            else:
                raise MigrationError(f"internal error: unknown column kind {column.kind!r}")
        rows.append(row)
    return rows


SETTINGS_COLUMNS = (
    Column("id", "integer", minimum=1, maximum=1),
    Column("worker_threads", "integer", minimum=1, maximum=64),
    Column("max_connections", "integer", minimum=1, maximum=1000000),
    Column("buffer_size", "integer", minimum=1024, maximum=1048576),
    Column("shutdown_timeout_ms", "integer", minimum=0, maximum=60000),
    Column("half_close_timeout_ms", "integer", minimum=1, maximum=3600000),
)

OLD_HOSTGROUP_COLUMNS = (
    Column("hostgroup_id", "integer", minimum=0),
    Column("balance", "text"),
    Column("health_check_interval_ms", "integer", minimum=0, maximum=3600000),
    Column("health_check_timeout_ms", "integer", minimum=1, maximum=60000),
    Column("health_check_rise", "integer", minimum=1, maximum=100),
    Column("health_check_fall", "integer", minimum=1, maximum=100),
    Column("comment", "text"),
)

CURRENT_HOSTGROUP_COLUMNS = (
    Column("hostgroup_id", "integer", minimum=0),
    Column("source_protocol", "text"),
    Column("source_hostgroup", "integer", minimum=0),
    Column("comment", "text"),
)

MAPPING_COLUMNS = (
    Column("hostgroup_id", "integer", minimum=0),
    Column("source_protocol", "text"),
    Column("source_hostgroup", "integer", minimum=0),
    Column("comment", "text"),
)

LISTENER_COLUMNS = (
    Column("listener_id", "integer", minimum=0),
    Column("active", "integer", minimum=0, maximum=1),
    Column("bind_address", "text"),
    Column("bind_port", "integer", minimum=1, maximum=65535),
    Column("default_hostgroup", "integer", minimum=0),
    Column("max_connections", "integer", minimum=1, maximum=1000000),
    Column("connect_timeout_ms", "integer", minimum=1, maximum=60000),
    Column("idle_timeout_ms", "integer", minimum=0, maximum=86400000),
    Column("max_connect_attempts", "integer", minimum=1, maximum=16),
    Column("comment", "text"),
)

RULE_COLUMNS = (
    Column("rule_id", "integer", minimum=0),
    Column("active", "integer", minimum=0, maximum=1),
    Column("listener_id", "integer", nullable=True, minimum=0),
    Column("source_cidr", "text", nullable=True),
    Column("action", "text"),
    Column("destination_hostgroup", "integer", nullable=True, minimum=0),
    Column("comment", "text"),
)


def _table_count(conn: sqlite3.Connection, table: str) -> int:
    rows = _execute(conn, f'SELECT COUNT(*) FROM "{table}"')
    return int(rows[0][0])


def _validate_settings(conn: sqlite3.Connection) -> dict:
    rows = _read_rows(conn, "tcp_settings", SETTINGS_COLUMNS)
    if len(rows) != 1:
        raise MigrationError("tcp_settings must contain exactly one row")
    if rows[0]["id"] != 1:
        raise MigrationError("tcp_settings.id must be 1")
    return rows[0]


def _validate_old_hostgroups(conn: sqlite3.Connection) -> list:
    rows = _read_rows(conn, "tcp_hostgroups", OLD_HOSTGROUP_COLUMNS)
    for row in rows:
        identifier = row["hostgroup_id"]
        if row["balance"] not in ("roundrobin", "leastconn"):
            raise MigrationError(f"tcp_hostgroups.balance is invalid for hostgroup {identifier}")
        interval = row["health_check_interval_ms"]
        if interval != 0 and interval < 100:
            raise MigrationError(
                f"tcp_hostgroups.health_check_interval_ms must be 0 or at least 100 for hostgroup {identifier}"
            )
    return rows


def _validate_current_hostgroups(conn: sqlite3.Connection) -> list:
    rows = _read_rows(conn, "tcp_hostgroups", CURRENT_HOSTGROUP_COLUMNS)
    projected = []
    for row in rows:
        identifier = row["hostgroup_id"]
        if row["source_protocol"] not in ("MYSQL", "PGSQL"):
            raise MigrationError(
                f"tcp_hostgroups.source_protocol is invalid for hostgroup {identifier}"
            )
        projected.append(
            ProjectedHostgroup(
                identifier,
                row["source_protocol"],
                row["source_hostgroup"],
                row["comment"],
            )
        )
    projected.sort(key=lambda hostgroup: hostgroup.hostgroup_id)
    return projected


def _validate_mappings(conn: sqlite3.Connection) -> list:
    rows = _read_rows(conn, "tcp_hostgroup_mappings", MAPPING_COLUMNS)
    for row in rows:
        if row["source_protocol"] not in ("MYSQL", "PGSQL"):
            raise MigrationError(
                "tcp_hostgroup_mappings.source_protocol is invalid for hostgroup "
                f"{row['hostgroup_id']}"
            )
    return rows


def _validate_ip_address(text: str, label: str) -> ipaddress._BaseAddress:
    if not text:
        raise MigrationError(f"{label} must not be empty")
    if "%" in text:
        raise MigrationError(f"{label} must be a numeric IP address without a zone identifier")
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise MigrationError(
            f"{label} must be a numeric IPv4 or IPv6 address: {exc}"
        ) from exc
    if address.version == 6 and address.ipv4_mapped is not None:
        raise MigrationError(
            f"{label} must not use an IPv4-mapped IPv6 address; use numeric IPv4"
        )
    return address


def _validate_cidr(text: str, label: str) -> ipaddress._BaseNetwork:
    if not text:
        raise MigrationError(f"{label} must not be empty")
    if text.count("/") != 1:
        raise MigrationError(f"{label} must contain exactly one '/'")
    address_text, prefix_text = text.split("/", 1)
    if not prefix_text or not prefix_text.isascii() or not prefix_text.isdigit():
        raise MigrationError(f"{label} has an invalid numeric prefix")
    _validate_ip_address(address_text, label)
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise MigrationError(f"{label} is not a canonical CIDR network: {exc}") from exc
    if network.version == 6 and getattr(network.network_address, "ipv4_mapped", None) is not None:
        raise MigrationError(f"{label} must not use an IPv4-mapped IPv6 network")
    return network


def _endpoint_overlaps(lhs: tuple, rhs: tuple) -> bool:
    family, address, port, wildcard = lhs
    other_family, other_address, other_port, other_wildcard = rhs
    if family != other_family or port != other_port:
        return False
    return wildcard or other_wildcard or address == other_address


def _validate_listeners(conn: sqlite3.Connection) -> list:
    rows = _read_rows(conn, "tcp_listeners", LISTENER_COLUMNS)
    active_endpoints = []
    for row in rows:
        identifier = row["listener_id"]
        address = _validate_ip_address(
            row["bind_address"], f"tcp_listeners.bind_address for listener {identifier}"
        )
        if row["comment"] is None:
            raise MigrationError(f"tcp_listeners.comment is NULL for listener {identifier}")
        if row["active"] == 1:
            endpoint = (
                address.version,
                int(address),
                row["bind_port"],
                address.is_unspecified,
            )
            for existing in active_endpoints:
                if _endpoint_overlaps(existing, endpoint):
                    raise MigrationError(
                        f"active listeners overlap at {address}:{row['bind_port']}"
                    )
            active_endpoints.append(endpoint)
    return rows


def _validate_rules(conn: sqlite3.Connection, listener_ids: set, hostgroup_ids: set) -> list:
    rows = _read_rows(conn, "tcp_routing_rules", RULE_COLUMNS)
    for row in rows:
        identifier = row["rule_id"]
        if row["listener_id"] is not None and row["listener_id"] not in listener_ids:
            raise MigrationError(
                f"tcp_routing_rules.listener_id {row['listener_id']} does not reference "
                f"a configured listener (rule {identifier})"
            )
        if row["source_cidr"] is not None:
            _validate_cidr(
                row["source_cidr"],
                f"tcp_routing_rules.source_cidr for rule {identifier}",
            )
        action = row["action"]
        if action not in ("ROUTE", "REJECT"):
            raise MigrationError(
                f"tcp_routing_rules.action must be ROUTE or REJECT (rule {identifier})"
            )
        destination = row["destination_hostgroup"]
        if action == "ROUTE":
            if destination is None:
                raise MigrationError(
                    f"tcp_routing_rules.destination_hostgroup is required for ROUTE rule {identifier}"
                )
            if destination not in hostgroup_ids:
                raise MigrationError(
                    f"tcp_routing_rules.destination_hostgroup {destination} does not "
                    f"reference a configured TCP hostgroup (rule {identifier})"
                )
        elif destination is not None:
            raise MigrationError(
                f"tcp_routing_rules.destination_hostgroup must be NULL for REJECT rule {identifier}"
            )
    return rows


def _validate_references(listeners: list, hostgroup_ids: set) -> None:
    for listener in listeners:
        if listener["default_hostgroup"] not in hostgroup_ids:
            raise MigrationError(
                "tcp_listeners.default_hostgroup "
                f"{listener['default_hostgroup']} does not reference a configured TCP "
                f"hostgroup (listener {listener['listener_id']})"
            )


def _merge_comments(hostgroup_comment: str, mapping_comment: str) -> str:
    if not hostgroup_comment:
        return mapping_comment
    if not mapping_comment:
        return hostgroup_comment
    if hostgroup_comment == mapping_comment:
        return hostgroup_comment
    return hostgroup_comment + "\n" + mapping_comment


TCP_NAME_MARKER = re.compile(r"(?:^|[^a-z0-9])tcp(?:[^a-z0-9]|$)")


def _is_tcp_name(name: str) -> bool:
    lower = name.lower()
    # Catch the known plugin prefixes plus temporary/legacy names such as
    # old_tcp_hostgroups or tmp_tcp_servers, without treating an arbitrary
    # word like "mytcplog" as a TCP artifact.
    return (
        any(lower.startswith(prefix) for prefix in TCP_NAME_PREFIXES)
        or TCP_NAME_MARKER.search(lower) is not None
    )


def _require_metadata_text(storage, label: str) -> None:
    if storage != b"text":
        raise MigrationError(f"{label} must be stored as SQLite TEXT (found {storage!r})")


def _schema_objects(conn: sqlite3.Connection) -> list:
    try:
        raw = conn.execute(
            "SELECT typeof(type), type, typeof(name), name,"
            " typeof(tbl_name), tbl_name, typeof(sql), sql"
            " FROM sqlite_master"
        ).fetchall()
    except sqlite3.Error as exc:
        raise MigrationError(f"cannot inspect sqlite_master: {exc}") from exc
    objects = []
    for (
        type_storage,
        object_type,
        name_storage,
        name,
        table_storage,
        table_name,
        sql_storage,
        sql,
    ) in raw:
        _require_metadata_text(type_storage, "sqlite_master.type")
        _require_metadata_text(name_storage, "sqlite_master.name")
        _require_metadata_text(table_storage, "sqlite_master.tbl_name")
        type_text = _schema_text(object_type, "sqlite_master.type")
        name_text = _schema_text(name, "sqlite_master.name")
        table_text = _schema_text(table_name, "sqlite_master.tbl_name")
        if sql_storage == b"null":
            if type_text == "table":
                raise MigrationError(
                    f"sqlite_master.sql for table {name_text} must not be NULL"
                )
            sql_text = None
        elif sql_storage == b"text":
            sql_text = _schema_text(sql, f"sqlite_master.sql for {name_text}")
        else:
            raise MigrationError(
                f"sqlite_master.sql for {name_text} must be stored as SQLite TEXT"
                f" (found {sql_storage!r})"
            )
        objects.append(SchemaObject(type_text, name_text, table_text, sql_text))
    return objects


def _classify_schema(conn: sqlite3.Connection) -> tuple:
    tcp_objects = {}
    for obj in _schema_objects(conn):
        if not (_is_tcp_name(obj.name) or _is_tcp_name(obj.table_name)):
            continue
        lower_name = obj.name.lower()
        if lower_name not in KNOWN_TCP_TABLES:
            raise MigrationError(
                f"unknown or temporary TCP object '{obj.name}' ({obj.object_type}); "
                "refusing an unknown layout"
            )
        if obj.object_type != "table":
            raise MigrationError(
                f"TCP object '{obj.name}' is a {obj.object_type}, not the expected table"
            )
        if obj.table_name.lower() != lower_name:
            raise MigrationError(f"TCP object '{obj.name}' is not a normal table")
        if lower_name in tcp_objects:
            raise MigrationError(f"duplicate TCP object name '{obj.name}'")
        tcp_objects[lower_name] = obj

    present = frozenset(tcp_objects)
    if present == frozenset(CURRENT_TCP_TABLES):
        return "current", tcp_objects
    if present in (OLD_FIVE_SET, OLD_SIX_SET):
        stored = tcp_objects["tcp_hostgroups"].sql
        if stored is None or not _ddl_matches(stored, OLD_HOSTGROUPS_DDL):
            raise MigrationError(
                "unknown or mixed TCP table layout: the four-table tcp_hostgroups "
                "definition coexists with legacy tcp_servers/tcp_hostgroup_mappings artifacts"
            )
        return "legacy-five" if present == OLD_FIVE_SET else "legacy-six", tcp_objects
    if not present:
        raise MigrationError("database contains no recognized TCP plugin tables")
    missing = sorted(KNOWN_TCP_TABLES - present)
    extra = sorted(present - KNOWN_TCP_TABLES)
    detail = []
    if missing:
        detail.append("missing " + ", ".join(missing))
    if extra:
        detail.append("unexpected " + ", ".join(extra))
    raise MigrationError(
        "unknown TCP table layout (" + "; ".join(detail) + "); expected exactly the "
        "current four tables or the recognized old five/six-table schema"
    )


def _require_ddl(tcp_objects: dict, name: str, expected: str) -> None:
    obj = tcp_objects[name]
    # The lower-case dictionary key is for layout classification only. The
    # accepted object must satisfy the builder's exact type/name/SQL equality;
    # a case-variant sqlite_master.name is resolved by SQLite but not by the
    # builder's name=? query.
    if obj.object_type != "table" or obj.name != name:
        raise MigrationError(
            f"{name} has non-exact object metadata (unknown or mixed schema layout)"
        )
    stored = obj.sql
    if stored is None:
        raise MigrationError(f"{name} has no stored DDL")
    if not _ddl_matches(stored, expected):
        raise MigrationError(
            f"{name} has an unsupported definition (unknown or mixed schema layout)"
        )


def _inspect_and_plan(conn: sqlite3.Connection) -> MigrationPlan:
    layout, tcp_objects = _classify_schema(conn)
    if layout == "current":
        for name, expected in (
            ("tcp_settings", OLD_TCP_SETTINGS_DDL),
            ("tcp_hostgroups", NEW_HOSTGROUPS_DDL),
            ("tcp_listeners", OLD_LISTENERS_DDL),
            ("tcp_routing_rules", OLD_RULES_DDL),
        ):
            _require_ddl(tcp_objects, name, expected)
        _validate_settings(conn)
        hostgroups = _validate_current_hostgroups(conn)
        listeners = _validate_listeners(conn)
        hostgroup_ids = {hostgroup.hostgroup_id for hostgroup in hostgroups}
        _validate_references(listeners, hostgroup_ids)
        _validate_rules(
            conn,
            {listener["listener_id"] for listener in listeners},
            hostgroup_ids,
        )
        return MigrationPlan("current", tuple(hostgroups), False)

    for name, expected in (
        ("tcp_settings", OLD_TCP_SETTINGS_DDL),
        ("tcp_hostgroups", OLD_HOSTGROUPS_DDL),
        ("tcp_servers", OLD_SERVERS_DDL),
        ("tcp_listeners", OLD_LISTENERS_DDL),
        ("tcp_routing_rules", OLD_RULES_DDL),
    ):
        _require_ddl(tcp_objects, name, expected)
    has_mappings = layout == "legacy-six"
    if has_mappings:
        _require_ddl(tcp_objects, "tcp_hostgroup_mappings", OLD_MAPPINGS_DDL)

    _validate_settings(conn)
    old_hostgroups = _validate_old_hostgroups(conn)
    server_rows = _table_count(conn, "tcp_servers")
    if server_rows != 0:
        raise MigrationError(
            f"tcp_servers contains {server_rows} static endpoint row(s); static endpoints "
            "cannot be converted to source-hostgroup mappings. Remove them explicitly first."
        )
    mappings = _validate_mappings(conn) if has_mappings else []

    hostgroup_ids = {row["hostgroup_id"] for row in old_hostgroups}
    mapping_by_id = {}
    for mapping in mappings:
        identifier = mapping["hostgroup_id"]
        if identifier in mapping_by_id:
            raise MigrationError(f"duplicate mapping for TCP hostgroup {identifier}")
        mapping_by_id[identifier] = mapping
        if identifier not in hostgroup_ids:
            raise MigrationError(
                f"orphan tcp_hostgroup_mappings row for missing TCP hostgroup {identifier}"
            )
    for hostgroup in old_hostgroups:
        identifier = hostgroup["hostgroup_id"]
        if identifier not in mapping_by_id:
            raise MigrationError(
                f"TCP hostgroup {identifier} has no source mapping; refusing to guess one"
            )

    projected = []
    for hostgroup in old_hostgroups:
        identifier = hostgroup["hostgroup_id"]
        mapping = mapping_by_id[identifier]
        projected.append(
            ProjectedHostgroup(
                identifier,
                mapping["source_protocol"],
                mapping["source_hostgroup"],
                _merge_comments(hostgroup["comment"] or "", mapping["comment"] or ""),
            )
        )
    projected.sort(key=lambda hostgroup: hostgroup.hostgroup_id)

    listeners = _validate_listeners(conn)
    projected_ids = {hostgroup.hostgroup_id for hostgroup in projected}
    _validate_references(listeners, projected_ids)
    _validate_rules(
        conn,
        {listener["listener_id"] for listener in listeners},
        projected_ids,
    )
    return MigrationPlan(layout, tuple(projected), has_mappings)


def _snapshot_rows(conn: sqlite3.Connection, table: str) -> tuple:
    try:
        return tuple(conn.execute(f'SELECT * FROM "{table}"').fetchall())
    except sqlite3.Error as exc:
        raise MigrationError(f"cannot snapshot {table}: {exc}") from exc


def _snapshot_non_tcp_schema(conn: sqlite3.Connection) -> tuple:
    snapshot = []
    for obj in _schema_objects(conn):
        if _is_tcp_name(obj.name) or _is_tcp_name(obj.table_name):
            continue
        snapshot.append((obj.object_type, obj.name, obj.table_name, obj.sql))
    return tuple(sorted(snapshot))


def _table_counts(conn: sqlite3.Connection) -> dict:
    counts = {}
    for obj in _schema_objects(conn):
        if obj.object_type != "table":
            continue
        escaped = obj.name.replace('"', '""')
        try:
            counts[obj.name] = int(conn.execute(f'SELECT COUNT(*) FROM "{escaped}"').fetchone()[0])
        except sqlite3.Error as exc:
            raise MigrationError(f"cannot count rows in {obj.name}: {exc}") from exc
    return counts


def _create_backup_file(path: str) -> None:
    parent = os.path.dirname(path) or "."
    if not os.path.isdir(parent):
        raise MigrationError(f"backup directory does not exist: {parent}")
    if os.path.lexists(path):
        raise MigrationError(
            f"refusing to overwrite existing backup destination: {path}"
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise MigrationError(f"cannot create exclusive backup file '{path}': {exc}") from exc
    try:
        os.fchmod(fd, 0o600)
    except OSError as exc:
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise MigrationError(f"cannot restrict backup file '{path}' to mode 0600: {exc}") from exc
    os.close(fd)


def _write_backup(database: str, backup_path: str, locked_source: sqlite3.Connection) -> None:
    created = False
    source = None
    destination = None
    try:
        _create_backup_file(backup_path)
        created = True
        source = _connect(database, "ro")
        destination = _connect(backup_path, "rw")
        source.backup(destination)
        check = destination.execute("PRAGMA integrity_check").fetchall()
        if check != [(b"ok",)]:
            raise MigrationError(f"backup integrity check failed: {check!r}")
        if _table_counts(source) != _table_counts(destination):
            raise MigrationError("backup table counts do not match the locked source")
        if _table_counts(locked_source) != _table_counts(destination):
            raise MigrationError("backup does not match the reserved source snapshot")
        source_schema = tuple(
            (obj.object_type, obj.name, obj.table_name, obj.sql) for obj in _schema_objects(source)
        )
        backup_schema = tuple(
            (obj.object_type, obj.name, obj.table_name, obj.sql) for obj in _schema_objects(destination)
        )
        if source_schema != backup_schema:
            raise MigrationError("backup schema does not match the source")
    except (MigrationError, sqlite3.Error, OSError) as exc:
        if created:
            try:
                os.unlink(backup_path)
            except OSError:
                pass
        if isinstance(exc, MigrationError):
            raise
        raise MigrationError(f"failed to create backup '{backup_path}': {exc}") from exc
    finally:
        if destination is not None:
            destination.close()
        if source is not None:
            source.close()
    mode = stat.S_IMODE(os.stat(backup_path).st_mode)
    if mode != 0o600:
        try:
            os.unlink(backup_path)
        except OSError:
            pass
        raise MigrationError(
            f"backup '{backup_path}' has permissions {mode:o}, expected 600"
        )


def _verify_migrated(
    conn: sqlite3.Connection,
    plan: MigrationPlan,
    unchanged_rows: dict,
    non_tcp_schema: tuple,
) -> None:
    layout, tcp_objects = _classify_schema(conn)
    if layout != "current":
        raise MigrationError("post-migration schema is not the current four-table layout")
    stored = tcp_objects["tcp_hostgroups"].sql
    if stored != NEW_HOSTGROUPS_DDL:
        raise MigrationError(
            "post-migration tcp_hostgroups DDL does not exactly match the registered definition"
        )
    final_plan = _inspect_and_plan(conn)
    if final_plan.hostgroups != plan.hostgroups:
        raise MigrationError("post-migration hostgroup rows do not match the validated projection")
    for table, before in unchanged_rows.items():
        after = _snapshot_rows(conn, table)
        if after != before:
            raise MigrationError(f"unchanged table {table} was modified during migration")
    if _snapshot_non_tcp_schema(conn) != non_tcp_schema:
        raise MigrationError("an unrelated schema object was modified during migration")
    integrity = _execute(conn, "PRAGMA integrity_check")
    if integrity != [(b"ok",)]:
        raise MigrationError(f"post-migration integrity_check failed: {integrity!r}")
    if _execute(conn, "PRAGMA foreign_key_check"):
        raise MigrationError("post-migration foreign_key_check reported violations")


def _default_backup_path(database: str) -> str:
    return os.path.abspath(database) + DEFAULT_BACKUP_SUFFIX


def check_database(database: str) -> int:
    database = os.path.abspath(database)
    _require_existing_database(database)
    conn = _connect(database, "ro")
    try:
        plan = _inspect_and_plan(conn)
    finally:
        conn.close()
    print(f"database: {database}")
    if plan.schema == "current":
        print("schema: current four-table")
        print("status: no migration required")
    else:
        print(f"schema: legacy {plan.schema.replace('legacy-', '')}-table")
        print("status: migration required (re-run with --apply)")
    return 0


def apply_database(database: str, backup_path: Optional[str]) -> int:
    database = os.path.abspath(database)
    _require_existing_database(database)
    selected_backup = os.path.abspath(backup_path) if backup_path else _default_backup_path(database)
    if os.path.abspath(selected_backup) == database:
        raise MigrationError("backup path must differ from the database path")

    read_only = _connect(database, "ro")
    try:
        preflight_plan = _inspect_and_plan(read_only)
    finally:
        read_only.close()

    if preflight_plan.schema == "current":
        print(f"database: {database}")
        print("schema: current four-table")
        print("status: no migration required")
        return 0

    conn = _connect(database, "rw")
    committed = False
    try:
        try:
            conn.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise MigrationError(f"cannot acquire BEGIN IMMEDIATE write reservation: {exc}") from exc

        # Revalidate while the write reservation is held.  The read-only
        # preflight is only used to select the fast current-schema path.
        plan = _inspect_and_plan(conn)
        if plan.schema == "current":
            conn.execute("ROLLBACK")
            print(f"database: {database}")
            print("schema: current four-table")
            print("status: no migration required")
            return 0

        unchanged_rows = {
            table: _snapshot_rows(conn, table)
            for table in ("tcp_settings", "tcp_listeners", "tcp_routing_rules")
        }
        non_tcp_schema = _snapshot_non_tcp_schema(conn)

        _write_backup(database, selected_backup, conn)

        conn.execute("DROP TABLE tcp_hostgroups")
        conn.execute(NEW_HOSTGROUPS_DDL)
        conn.executemany(
            "INSERT INTO tcp_hostgroups"
            " (hostgroup_id, source_protocol, source_hostgroup, comment)"
            " VALUES (?, ?, ?, ?)",
            [
                (
                    hostgroup.hostgroup_id,
                    hostgroup.source_protocol,
                    hostgroup.source_hostgroup,
                    hostgroup.comment,
                )
                for hostgroup in plan.hostgroups
            ],
        )
        conn.execute("DROP TABLE tcp_servers")
        if plan.has_mappings_table:
            conn.execute("DROP TABLE tcp_hostgroup_mappings")

        _verify_migrated(conn, plan, unchanged_rows, non_tcp_schema)
        conn.execute("COMMIT")
        committed = True
    except (MigrationError, sqlite3.Error, OSError):
        if not committed:
            try:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise
    finally:
        conn.close()

    print(f"database: {database}")
    print(f"backup: {selected_backup}")
    print(f"schema: {plan.schema.replace('legacy-', 'legacy ')}-table -> current four-table")
    print(f"hostgroups: {len(plan.hostgroups)} migrated")
    print("status: migration committed")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline TCP proxy four-table schema migration. Stop ProxySQL first.",
        epilog=(
            "Stop ProxySQL before --apply. The backup is a complete pre-migration database "
            "created exclusively with mode 0600 and never overwritten. "
            "Rollback: with ProxySQL stopped, replace the database with that backup and "
            "remove any stale -wal/-shm sidecars that belonged to the converted database."
        ),
    )
    parser.add_argument(
        "--database",
        required=True,
        metavar="FILE",
        help="existing ProxySQL config database (proxysql.db); never created",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="read-only validation (default)",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="create a backup and migrate the existing database",
    )
    parser.add_argument(
        "--backup",
        metavar="PATH",
        help=(
            "apply-only backup destination; default "
            "<database>.tcp-four-table-before-migration.bak; created 0600 and never overwritten"
        ),
    )
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.backup and not args.apply:
        parser.error("--backup is only valid with --apply")
    try:
        if args.apply:
            return apply_database(args.database, args.backup)
        return check_database(args.database)
    except MigrationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
