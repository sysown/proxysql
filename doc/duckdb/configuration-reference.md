# DuckDB Configuration Reference

DuckDB settings are rows in `global_variables` named with the `duckdb-`
prefix. Effective values use the same names in `runtime_global_variables`.

| Variable | Default | Accepted value | Live behavior |
|---|---|---|---|
| `duckdb-mysql_ifaces` | `0.0.0.0:6031` | semicolon-separated `addr:port` | changed value rejected; reopen listener |
| `duckdb-pgsql_ifaces` | `0.0.0.0:6034` | semicolon-separated `addr:port` | changed value rejected; reopen listener |
| `duckdb-database_path` | `:memory:` | DuckDB path or `:memory:` | changed value rejected; reopen database |
| `duckdb-memory_limit` | `1GB` | DuckDB memory-limit string | immediate, validated and read back |
| `duckdb-threads` | `2` | integer `1..INT_MAX` | immediate, visible to existing connections |
| `duckdb-max_connections` | `100` | integer `1..INT_MAX` | immediate for new admission |
| `duckdb-read_only` | `false` | boolean aliases | changed value rejected; reopen database |
| `duckdb-enable_external_access` | `false` | boolean aliases | live `true` to `false`; reverse rejected |

Boolean aliases (`true/false`, `1/0`, `on/off`) are stored canonically. An
empty database path becomes `:memory:`. Runtime engine values come from
DuckDB `current_setting()`, including its canonical memory units.

## Listener variables

Multiple entries are separated with `;`; IPv6 literals are bracketed:

```text
127.0.0.1:6031;10.0.0.10:6031
[::1]:6031
```

Ports are 1 through 65535. Unchanged listener values do not block unrelated
live changes. A changed value returns an error and remains pending in Main.

## `duckdb-database_path`

Empty or `:memory:` selects the process-lifetime in-memory database. Any other
value is a path accessible by the ProxySQL account. Changing it never copies
data. LOAD rejects replacement of an open database; Runtime and status keep
naming the path actually open.

## `duckdb-memory_limit`

Examples are `512MB`, `1GB`, and `8GB`. LOAD validates and applies the setting
using an internal control connection, then reads it back. Invalid syntax fails
the complete candidate before another valid edit can apply.

DuckDB shares ProxySQL's process. Leave memory for core, connection buffers,
other plugins, the operating system, and workload spikes.

## `duckdb-threads`

Controls query parallelism. LOAD applies it globally and existing connections
observe it. Direct client `SET threads=N` is routed through the same internal
control connection, outside the client's transaction.

## `duckdb-max_connections`

Caps reservations across both listeners. Reducing it preserves existing
sessions and rejects new ones until the count falls below the limit.

## `duckdb-read_only`

Maps to access mode at database open. `true` with effective `:memory:` is
rejected during candidate validation. It does not replace external-access
security.

## `duckdb-enable_external_access`

ProxySQL overrides DuckDB's permissive default and starts disabled. Tightening
`true` to `false` works live and is applied last because it cannot be rolled
back while open. Loosening `false` to `true` waits for the next database open.

Direct managed SET follows the same restrictions. Other DuckDB session SET
statements continue through the ordinary client connection.
