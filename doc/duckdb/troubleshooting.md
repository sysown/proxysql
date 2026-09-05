# DuckDB Plugin Troubleshooting

## Plugin does not load

### `cannot open shared object file`

Confirm the `plugins` entry uses the installed absolute path and that the
ProxySQL service account can read the `.so` and traverse its parent directories.

### ABI or DEBUG mismatch

Build the core and plugin together with the same tier and build mode. A DEBUG
core requires a DEBUG plugin; release requires release. Clean stale objects
when switching modes, then rebuild with `PROXYSQL40=1` on every invocation.

Do not hard-code `abi_version`. Plugin code must use
`PROXYSQL_PLUGIN_ABI_VERSION`.

### DuckDB archive is an LFS pointer

Fetch and verify it:

```bash
git lfs pull --include="deps/duckdb/duckdb-1.4.5.tar.gz"
deps/duckdb/verify-source.bash
```

The verifier also reports checksum or corrupt-archive failures.

## Engine fails to open

### File or directory permission error

Check `database_path`, parent-directory existence, ownership, service sandbox
rules, and read/write permissions for the ProxySQL operating-system account.

### Read-only in-memory configuration

`read_only=true` cannot use `:memory:` or an empty effective path. Configure an
existing file-backed database or disable read-only mode.

### Invalid memory limit or engine setting

Inspect the startup log for `duckdb_set_config` failures. `memory_limit` is
accepted as a string by the Admin store but validated by DuckDB when the engine
opens.

## Listener does not start

Check whether the configured address exists locally and whether another
process is using the port. Remember:

- 6031: default DuckDB MySQL protocol
- 6032: ProxySQL Admin
- 6033: normal ProxySQL MySQL listener
- 6034: default DuckDB PostgreSQL protocol

After changing `mysql_ifaces` or `pgsql_ifaces`, save the values to disk and
restart. LOAD alone does not rebind sockets.

## Authentication fails

Use a credential in the correct frontend table:

- MySQL endpoint: `mysql_users`
- PostgreSQL endpoint: `pgsql_users`

Confirm the user is active and that user changes have been loaded to runtime.
Testing a MySQL user on the PostgreSQL endpoint, or vice versa, will not work
unless a corresponding entry exists in both tables.

## Connection resets immediately

Check `max_connections` and the number of active plugin sessions. At the cap,
the listener closes newly accepted sockets before protocol setup, so the client
may show EOF or reset rather than a descriptive server error.

Also inspect ProxySQL logs for startup-readiness or shutdown activity.

## Query syntax works in MySQL/PostgreSQL but fails here

The endpoint protocol does not select the SQL dialect. Write DuckDB SQL. Only a
small set of discovery and session commands is intercepted for compatibility.

Run a minimal control query:

```sql
SELECT 42;
```

Then reduce the failing statement to distinguish dialect syntax, missing
objects, permissions, and unsupported wire behavior.

## Prepared statement or parameterized query fails

Client-visible prepared statements are not supported. PostgreSQL extended
query messages receive SQLSTATE `0A000` and resynchronize at `Sync`.

Configure the driver for simple-query mode or use its non-prepared text-query
API. Do not solve this by concatenating untrusted values into SQL.

## Multiple SQL statements are rejected

Send one statement per request. The rejection is intentional and prevents
hidden side effects from earlier statements in a packet.

`SET NAMES utf8; SELECT 1` is also a multi-statement request; it is not accepted
as a compatibility no-op.

## Values arrive as strings

This is current behavior. Both protocol serializers advertise text columns.
Applications must parse values based on the query contract rather than rely on
MySQL/PostgreSQL type metadata.

## A special DuckDB value arrives as NULL

Most unsupported direct types are re-rendered through a VARCHAR wrapper.
However, some DML `RETURNING` shapes cannot be wrapped. In that degraded path,
an unsupported result type can appear as NULL even though the underlying value
is not SQL NULL. Cast the returned expression explicitly to `VARCHAR` in the
original SQL as a workaround:

```sql
INSERT INTO t VALUES (...) RETURNING special_column::VARCHAR;
```

## Configuration changed but behavior did not

First compare:

```sql
SELECT * FROM duckdb_variables ORDER BY variable_name;
SELECT * FROM runtime_duckdb_variables ORDER BY variable_name;
```

If they differ, run LOAD. If they match but the engine or listener behavior is
unchanged, check the apply matrix in the
[Configuration reference](configuration-reference.md). Only
`max_connections` currently applies to its live resource immediately; most
settings require restart.

## Configuration disappears after restart

`LOAD ... TO RUNTIME` does not persist the editable table. Run:

```sql
SAVE DUCKDB VARIABLES TO DISK;
```

On a truly fresh install the editable table is empty until defaults are
materialized with `SAVE DUCKDB VARIABLES TO MEMORY` or disk rows exist.

## External file access is denied

That is the secure default. Before enabling it, read the
[Security guide](security.md). If it is deliberately enabled, LOAD and save the
setting, restart the engine, and verify filesystem permissions. A runtime row
showing `true` does not mean an already-open engine adopted it.

## A query consumes excessive resources

There is no query timeout in the initial plugin. Restrict endpoint access,
lower `memory_limit`, choose a conservative `threads` value, and reduce
`max_connections`. Restart is required for the memory and startup thread
defaults. If a live query must be stopped and the client cannot cancel it,
controlled process recovery may be required; assess the impact on normal
ProxySQL traffic before acting.
