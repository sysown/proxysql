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

## Failure contract

LOAD validates before mutation and has no warning-style partial success.
Reversible engine changes are restored if a later reversible step fails.
Disabling external access is irreversible while open and is applied last.

The operation is not advertised as atomic across Admin SQLite and DuckDB. If
an error occurs after a setting changed, the error identifies that fact. The
next Runtime query reconstructs effective state from the engine rather than
repeating cached intent.
