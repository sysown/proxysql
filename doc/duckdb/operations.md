# Operating the DuckDB Plugin

## Startup lifecycle

At ProxySQL startup the plugin:

1. restores saved DuckDB rows from the disk configuration database into the
   editable Admin table;
2. installs recognized rows into the plugin configuration store;
3. validates and opens one DuckDB database;
4. binds the configured MySQL and PostgreSQL listeners;
5. begins accepting client connections.

An engine-open or listener-bind failure prevents the plugin from starting.
Inspect the ProxySQL log for the concrete path, setting, or address involved.

## Runtime configuration workflow

Use this sequence for changes:

```sql
-- Edit
UPDATE duckdb_variables
SET variable_value='200'
WHERE variable_name='max_connections';

-- Install recognized values into the module
LOAD DUCKDB VARIABLES TO RUNTIME;

-- Confirm the module view
SELECT * FROM runtime_duckdb_variables ORDER BY variable_name;

-- Persist the editable table
SAVE DUCKDB VARIABLES TO DISK;
```

Only `max_connections` changes the live accept cap immediately. Schedule a
restart for listener addresses and engine-open settings.

## Health checks

Use protocol-level checks from the same network path as clients:

```bash
mysql -h 127.0.0.1 -P 6031 -u CHECK_USER -p -e 'SELECT 42'
psql -h 127.0.0.1 -p 6034 -U CHECK_USER main -c 'SELECT 42'
```

A TCP connect alone proves only that a socket is listening. A useful check
authenticates and completes a query.

Plugin sessions reuse the `PROXYSQL_SESSION_SQLITE` session type and can appear
under that identity in ProxySQL logs and process-list views. Account for this
when building dashboards or alerts.

## Capacity planning

Three settings interact:

- `memory_limit` constrains the embedded DuckDB engine.
- `threads` controls DuckDB query parallelism.
- `max_connections` caps concurrent accepted plugin sessions.

DuckDB executes in the ProxySQL process, so do not allocate the full host to
DuckDB. Leave headroom for ProxySQL core, client buffers, monitoring, plugins,
the kernel, and temporary workload spikes.

The listener uses a thread per connection. A high connection cap therefore
also consumes thread stacks and scheduling capacity even when queries are
idle.

## Connection-limit behavior

When the reservation count reaches `max_connections`, the listener closes a
newly accepted socket before constructing a protocol session. Existing
connections remain active. Reducing the limit below the current count does not
disconnect them; new admissions resume after the count drops below the cap.

Client errors can look like a connection reset or unexpected EOF rather than a
structured MySQL/PostgreSQL error.

## Backup and restore

For `:memory:` there is no restart-persistent database file to back up. Export
needed data before stopping ProxySQL, subject to the external-access policy.

For a file-backed database, the conservative backup procedure is:

1. stop new plugin traffic;
2. allow active queries and transactions to finish;
3. stop ProxySQL cleanly so the plugin joins sessions and closes DuckDB;
4. copy or snapshot the database file and its containing storage;
5. restart and run a read/write smoke test.

Use DuckDB-supported online backup/export facilities only after validating
them against the pinned DuckDB version and the configured external-access
policy. Do not assume copying a live file during active writes is a complete
backup procedure.

To restore, stop ProxySQL, preserve the current file, place the restored file
at the configured path with correct ownership, then start and verify it.

## Restart changes

Before restarting for `database_path`, `memory_limit`, `threads`, `read_only`,
external access, or listener changes:

1. save the intended editable configuration to disk;
2. record the current runtime view;
3. drain or notify clients;
4. restart ProxySQL;
5. inspect logs;
6. reconnect and verify the engine/database you expected.

Changing `database_path` does not copy the old database. A successful restart
against a new empty path can look like data loss if the path change was not
intentional.

## Shutdown

Plugin shutdown stops listeners, signals connection loops, joins connection
threads, disconnects their DuckDB handles, and only then closes the shared
database. Prefer normal service shutdown over killing the process when data
durability matters.

## Upgrade checks

After upgrading the core/plugin pair:

- confirm no ABI mismatch appears in logs;
- verify the expected DuckDB file opens;
- compare `runtime_duckdb_variables` with the saved disk rows;
- run simple queries through both protocols;
- test a transaction and an expected error path;
- confirm connection and memory limits remain appropriate.
