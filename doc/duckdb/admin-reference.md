# DuckDB Admin Reference

Run these commands through ProxySQL Admin, normally MySQL protocol on port
6032. Do not send them to the DuckDB listeners.

## Standard variable tables

DuckDB scalar configuration follows the same namespace convention as other
ProxySQL modules. It has no dedicated scalar-variable tables.

```sql
-- Editable intended configuration (Main)
SELECT variable_name, variable_value FROM global_variables
WHERE variable_name LIKE 'duckdb-%' ORDER BY variable_name;

-- Effective running configuration (Runtime)
SELECT variable_name, variable_value FROM runtime_global_variables
WHERE variable_name LIKE 'duckdb-%' ORDER BY variable_name;

-- Restart-persistent intended configuration (Disk)
SELECT variable_name, variable_value FROM disk.global_variables
WHERE variable_name LIKE 'duckdb-%' ORDER BY variable_name;
```

Fresh installations seed all eight `duckdb-*` defaults into Main. Runtime is
refreshed from the actual engine and listener configuration whenever it is
queried. Do not update Runtime directly.

On the first startup after upgrading, recognized values from the former
dedicated DuckDB tables are imported only where a `duckdb-*` value is absent;
disk-only legacy values are also made available to that first startup. The
obsolete Main, Runtime, and Disk tables are then removed transactionally.

```sql
UPDATE global_variables SET variable_value='4'
WHERE variable_name='duckdb-threads';
LOAD DUCKDB VARIABLES TO RUNTIME;
```

## Commands

```sql
-- Main to Runtime
LOAD DUCKDB VARIABLES TO RUNTIME;
LOAD DUCKDB VARIABLES FROM MEMORY; -- alias

-- Runtime to Main
SAVE DUCKDB VARIABLES TO MEMORY;
SAVE DUCKDB VARIABLES TO MEM; -- alias
SAVE DUCKDB VARIABLES FROM RUNTIME; -- alias
SAVE DUCKDB VARIABLES FROM RUNTIME TO MEMORY; -- legacy alias

-- Main to Disk
SAVE DUCKDB VARIABLES TO DISK;
SAVE DUCKDB VARIABLES FROM MEMORY; -- alias
SAVE DUCKDB VARIABLES FROM MEMORY TO DISK; -- legacy alias

-- Disk to Main only
LOAD DUCKDB VARIABLES FROM DISK;
LOAD DUCKDB VARIABLES TO MEMORY; -- alias
```

All copies replace only rows matching `duckdb-%`; other module namespaces are
untouched. LOAD overlays a legitimate sparse Main slice on effective state,
validates the complete candidate, and rejects unknown variables, invalid
values, and unsupported live transitions. Main is not silently repaired on
failure.

## Immediate and lifecycle-dependent settings

These apply live:

- `duckdb-memory_limit`
- `duckdb-threads`
- `duckdb-max_connections`
- `duckdb-enable_external_access` only from `true` to `false`

These require the corresponding database/listener lifecycle to reopen:

- `duckdb-database_path`
- `duckdb-read_only`
- `duckdb-mysql_ifaces`
- `duckdb-pgsql_ifaces`
- `duckdb-enable_external_access` from `false` to `true`

The current interface has no independent DuckDB reload command, so a process
restart normally reaches the next open. ProxySQL never restarts itself,
terminates sessions, reopens an in-memory database, or discards data for LOAD.

## Pending differences

```sql
SELECT m.variable_name, m.variable_value AS main_value,
       r.variable_value AS runtime_value
FROM global_variables AS m
LEFT JOIN runtime_global_variables AS r USING (variable_name)
WHERE m.variable_name LIKE 'duckdb-%'
ORDER BY m.variable_name;
```

Runtime memory units are DuckDB's canonical readback; DuckDB 1.4.5 reports an
input of `512MB` as `488.2 MiB`.

## Replica

The replica is part of this plugin. It is not a separate process and it does
not reuse `proxysql_binlog_reader`. `START DUCKDB REPLICA` checks one MySQL
source, takes a short `FLUSH TABLES WITH READ LOCK`, copies the opted-in
tables into DuckDB, and then follows the binary log from that position.
Committed source transactions are applied in batches. A restart resumes from
`proxysql_replica.position`; it does not snapshot again unless the position is
missing.

```sql
INSERT INTO duckdb_replica_sources
  (source_id, hostname, port, username, password, server_id, enabled)
VALUES ('oltp', '10.0.0.8', 3306, 'repl', 'secret', 100, 1);

INSERT INTO duckdb_replica_tables (source_id, schema_name, table_name, active)
VALUES ('oltp', 'app', 'events', 1);

LOAD DUCKDB REPLICA TO RUNTIME;
SAVE DUCKDB REPLICA TO DISK;
START DUCKDB REPLICA;
```

`START DUCKDB REPLICA` reads the Main tables, so `LOAD` is optional before
start. The source address is the MySQL server itself, not a ProxySQL
listener. A file-backed read-write DuckDB database is required. At most one
source may be enabled.

`stats_duckdb_replica` is projected from the replica thread. `applying`
means the dump is being followed; `seconds_behind_source` is the age of the
last applied event. `error` is sticky until `STOP`. `RESET DUCKDB REPLICA` is
legal only while stopped. It drops the snapshot tables and
`proxysql_replica.position`, not the source definition.

The source user needs `REPLICATION CLIENT`, `REPLICATION SLAVE`, `SELECT` on
the opted-in tables, and `RELOAD` for the snapshot lock. A table without a
primary key, or a column outside the supported type and charset set, fails
the snapshot. JSON, `ENUM`, and `SET` columns are refused: the vendored
replication API either does not decode them or would return a different
representation than the snapshot. Non-transactional tables are not
supported.

v1 stops on any DDL in the binlog (`ALTER`, `RENAME`, and so on) rather than
applying it. Stop the replica, `RESET DUCKDB REPLICA`, and `START` again to
resnapshot. Online schema-change tools therefore require an explicit
resnapshot. `TRUNCATE` and `DROP`/`CREATE` are also treated as DDL in v1.

`STOP DUCKDB REPLICA` can take up to the dump read timeout (5 seconds) when
the source is idle, and longer if the thread is waiting on the snapshot lock.
It releases the Admin query mutex while it waits.

Passwords are stored in the admin database in the clear, same as monitor
credentials. Do not put a superuser here.

## Failure contract

LOAD validates before mutation and has no warning-style partial success.
Reversible engine changes are restored if a later reversible step fails.
Disabling external access is irreversible while open and is applied last.

The operation is not advertised as atomic across Admin SQLite and DuckDB. If
an error occurs after a setting changed, the error identifies that fact. The
next Runtime query reconstructs effective state from the engine rather than
repeating cached intent.
