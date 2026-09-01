# ProxySQL DuckDB Plugin

The ProxySQL DuckDB plugin embeds DuckDB in the ProxySQL process and exposes it
through MySQL and PostgreSQL client protocols. Applications and operators can
use familiar clients such as `mysql` and `psql` while queries execute directly
inside the embedded DuckDB engine. No MySQL or PostgreSQL backend is involved.

The plugin is intended for embedded analytical workloads, local operational
data, prototyping, and cases where a SQL endpoint is more convenient than
linking DuckDB into each client application.

## Availability

The plugin is part of the ProxySQL v4.0 Plugin Chassis tier and is built only
with `PROXYSQL40=1`. It is not compiled into the ProxySQL core executable. A
shared object is loaded at ProxySQL startup and owns its DuckDB engine and two
independent listener endpoints.

Default endpoints:

| Protocol | Address | Port | Credentials |
|---|---:|---:|---|
| MySQL | `0.0.0.0` | `6031` | `mysql_users` |
| PostgreSQL | `0.0.0.0` | `6034` | `pgsql_users` |

These ports are separate from ProxySQL Admin on 6032 and the normal MySQL
proxy listener on 6033.

## Start here

- [Five-minute tutorial](quickstart.md) — build, load, connect, and run the
  first analytical query.
- [Installation](installation.md) — source prerequisites, plugin loading, and
  upgrade considerations.
- [User guide](user-guide.md) — connections, SQL workflows, persistence, and
  session behavior.
- [Configuration reference](configuration-reference.md) — every DuckDB
  variable, default, validation rule, and apply behavior.
- [Admin reference](admin-reference.md) — tables, runtime projection, and
  LOAD/SAVE commands.
- [Protocol compatibility](protocol-compatibility.md) — supported client
  behavior and current limitations.
- [Security](security.md) — authentication, filesystem access, network
  exposure, and the trust model.
- [Operations](operations.md) — monitoring, backups, capacity, restart, and
  recovery.
- [Troubleshooting](troubleshooting.md) — symptom-based diagnosis.

## Architecture at a glance

One `duckdb_database` is opened when the plugin starts. Every accepted client
connection receives its own `duckdb_connection`, stored for the lifetime of
that connection's dedicated thread. All sessions therefore see the same
in-memory database when `database_path=:memory:` and the same file-backed
database when a path is configured. DuckDB provides concurrency control among
those connections.

The plugin uses ProxySQL's existing frontend authentication and protocol
implementation, but it does not route queries to a backend server. After
authentication, supported text queries go directly to DuckDB. Results pass
through ProxySQL's existing SQLite-compatible result container and are exposed
as text columns on both protocols.

## Important initial limitations

- Client-visible prepared statements and PostgreSQL extended-query execution
  are not supported. Use simple text-query APIs.
- One request may contain only one SQL statement.
- Result metadata identifies every column as text.
- There is no plugin query timeout; a runaway DuckDB query is not interrupted.
- Users authenticated through either endpoint share the same DuckDB database
  and have no separate per-table DuckDB authorization layer.
- External filesystem access is disabled by default and should remain disabled
  unless every endpoint user is trusted with the ProxySQL process's filesystem
  permissions.

Read [Protocol compatibility](protocol-compatibility.md) and
[Security](security.md) before exposing the listeners outside a trusted
environment.

## Maintainer material

Operator documentation is canonical in this directory. Plugin build notes are
kept in [`plugins/duckdb/README.md`](../../plugins/duckdb/README.md), dependency
vendoring details in [`deps/duckdb/README.md`](../../deps/duckdb/README.md), and
the implementation design in
[`docs/superpowers/specs/2026-08-26-duckdb-server-plugin-design.md`](../../docs/superpowers/specs/2026-08-26-duckdb-server-plugin-design.md).
