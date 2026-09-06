# DuckDB Configuration Reference

DuckDB plugin settings are stored as rows in `duckdb_variables`. The plugin's
in-memory configuration store is exposed through the read-only
`runtime_duckdb_variables` projection.

## Variable summary

| Variable | Default | Accepted value | Applied by LOAD |
|---|---|---|---|
| `mysql_ifaces` | `0.0.0.0:6031` | semicolon-separated `addr:port` | Restart required |
| `pgsql_ifaces` | `0.0.0.0:6034` | semicolon-separated `addr:port` | Restart required |
| `database_path` | `:memory:` | DuckDB path or `:memory:` | Restart required |
| `memory_limit` | `1GB` | DuckDB memory-limit string | Restart required |
| `threads` | `2` | integer `1..INT_MAX` | Restart required for engine default |
| `max_connections` | `100` | integer `1..INT_MAX` | Immediate |
| `read_only` | `false` | `true/false`, `1/0`, `on/off` | Restart required |
| `enable_external_access` | `false` | `true/false`, `1/0`, `on/off` | Restart required |

`LOAD DUCKDB VARIABLES TO RUNTIME` always updates the plugin configuration
store for valid rows. “Restart required” means the already-created engine or
listener continues using its old resource-level value until ProxySQL restarts.
The new value is nevertheless visible in `runtime_duckdb_variables` after
LOAD.

## `mysql_ifaces`

MySQL-protocol listener addresses. Multiple entries are separated with `;`:

```text
127.0.0.1:6031;10.0.0.10:6031
```

Bracket IPv6 literals:

```text
[::1]:6031
```

Ports must be between 1 and 65535. Listener sockets are created only at plugin
startup; LOAD does not rebind them.

## `pgsql_ifaces`

PostgreSQL-protocol listener addresses, using the same syntax as
`mysql_ifaces`. The default is deliberately 6034. Port 6032 is ProxySQL Admin
and must not be used as the DuckDB default.

Listener sockets are created only at startup.

## `database_path`

The database passed to `duckdb_open_ext`:

- Empty or `:memory:` selects the shared process-lifetime in-memory database.
- Any other value is treated as a file path.

The ProxySQL service account needs suitable directory and file permissions.
Changing this value does not migrate data. The engine opens the path only at
plugin startup.

## `memory_limit`

A DuckDB memory-limit setting such as `512MB`, `1GB`, or `8GB`. It is passed to
DuckDB when the engine opens. The configuration store accepts the string; an
invalid DuckDB value causes engine startup to fail with a configuration error.

This is an important containment setting because DuckDB runs inside the
ProxySQL process. Leave memory for ProxySQL core workloads, connections, and
the operating system.

## `threads`

The DuckDB worker-thread count used for query parallelism. The value must be an
integer from 1 through `INT_MAX`.

The configured startup default requires an engine restart. A connected client
can independently issue a DuckDB-native `SET threads=N` for its session where
that behavior is appropriate.

## `max_connections`

Maximum reserved DuckDB client connections across both listeners. The value
must be an integer from 1 through `INT_MAX`.

This is the only current variable applied directly to a live engine/listener
control path during LOAD. Reducing it does not terminate existing sessions. It
prevents new reservations until the count falls below the new cap. A rejected
socket is closed before a protocol session is created.

## `read_only`

When true, the engine is opened with DuckDB `access_mode=READ_ONLY`. It applies
to the main database and requires restart.

`read_only=true` cannot be combined with an effective `:memory:` path. That
cross-field combination is rejected when the engine opens. Read-only mode is
not a substitute for disabling external access: the two settings protect
different surfaces.

## `enable_external_access`

Controls DuckDB's `enable_external_access` setting. ProxySQL overrides
DuckDB's own permissive default and uses `false` unless the operator opts in.

When false, DuckDB blocks external-state features such as local file readers,
COPY to or from paths, and attaching arbitrary external files. When true,
every authenticated plugin endpoint user can exercise those features with the
operating-system permissions of the ProxySQL process.

This setting is applied only when the engine opens. A LOAD from false to true
does not enable access in the already-open engine. Restart is required. Read
the [Security guide](security.md) first.

## Validation behavior

During LOAD:

- Recognized, valid rows are installed.
- Unknown names and invalid individual values are skipped.
- The command succeeds for the valid rows and includes skipped-row details in
  its message.

Cross-field and DuckDB-engine validation occurs at engine open. Always inspect
logs after restarting with a changed database path, memory limit, or read-only
combination.
