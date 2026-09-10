# DuckDB Global Variables and Effective Runtime Design

Date: 2026-09-06
Base revision: `v3.0` at `80941ae5e2cb29963c8bb14c46a7a441ae4f08d2`

## Scope

Correct DuckDB configuration application and reporting in ProxySQL core and the
DuckDB plugin. Remove the non-standard `duckdb_variables` and
`runtime_duckdb_variables` tables. DuckDB scalar settings use ProxySQL's
standard `global_variables` and `runtime_global_variables` tables with a
`duckdb-` prefix.

This change does not modify MySQLX, the WebUI repositories, Router/plugin
chassis behavior, or MCP behavior. Removing `mysqlx_variables` and
`runtime_mysqlx_variables` requires a separate PR.

## Root cause

The merged plugin has two independent defects:

1. It introduced dedicated scalar-variable tables instead of using the
   established prefixed rows in `global_variables`.
2. `LOAD DUCKDB VARIABLES TO RUNTIME` copied rows into an in-memory
   `DuckDBConfigStore`, but only applied `max_connections`. The runtime table
   then projected that desired store, not the database and listeners actually
   running.

Consequently a successful LOAD could advertise unapplied or invalid settings.
Direct DuckDB `SET` statements could change engine-global settings in the
opposite direction while the runtime table remained stale. Status also used
the desired database path instead of the path actually opened.

## Standard variable model

The eight settings are stored as these rows:

| Variable | Main | Runtime | Disk |
| --- | --- | --- | --- |
| MySQL listener | `duckdb-mysql_ifaces` | effective bound setting | same key |
| PostgreSQL listener | `duckdb-pgsql_ifaces` | effective bound setting | same key |
| Database path | `duckdb-database_path` | actual opened path | same key |
| Memory limit | `duckdb-memory_limit` | DuckDB canonical value | same key |
| Threads | `duckdb-threads` | DuckDB effective value | same key |
| Connection limit | `duckdb-max_connections` | effective admission limit | same key |
| Read-only mode | `duckdb-read_only` | actual access mode | same key |
| External access | `duckdb-enable_external_access` | DuckDB effective value | same key |

- Main means intended editable configuration in `main.global_variables`.
- Runtime means effective running state in `main.runtime_global_variables`.
- Disk means restart-persistent intent in `disk.global_variables`.
- A sparse Main DuckDB slice is legitimate. Missing keys inherit the current
  effective setting during a runtime LOAD and compiled defaults at first
  startup.
- Values are normalized at the boundary: boolean aliases become `true` or
  `false`; an empty database path becomes `:memory:`; engine settings use
  DuckDB's own canonical `current_setting()` representation.

The plugin registers no DuckDB scalar table. It registers a refresh callback
for the existing `runtime_global_variables` table. That callback transactionally
replaces only rows matching `duckdb-%`, leaving every other module's namespace
untouched. It reads effective state from the engine/listeners, so a query of
the runtime table cannot silently return a cached desired value.

## Compatibility migration

At startup, if legacy `main.duckdb_variables` or `disk.duckdb_variables`
tables exist, copy recognized values to the corresponding `duckdb-*` rows only
when that prefixed destination key is absent. Then drop those legacy tables and
`main.runtime_duckdb_variables` if present. The non-persistent runtime table is
not registered or recreated. This preserves existing operator intent while
ensuring the removed tables do not remain visible after upgrade.

Unknown legacy names are logged and not imported. Migration is transactional;
failure prevents DuckDB startup rather than discarding configuration or
starting with an ambiguous mix.

## LOAD contract

`LOAD DUCKDB VARIABLES TO RUNTIME` and `LOAD DUCKDB VARIABLES FROM MEMORY`:

1. Read the complete `duckdb-*` candidate from Main and overlay sparse rows on
   the effective snapshot (or defaults before initial open).
2. Reject unknown names and validate the entire candidate before changing live
   state. Main is never silently repaired, deleted, or overwritten on failure.
3. Compare normalized effective values. Unchanged startup-only settings do not
   block live changes.
4. Reject changed startup-only settings: database path, read-only/access mode,
   and either listener address. The error says that the requested value remains
   in Main and takes effect the next time the DuckDB plugin/database is opened.
   With no independent plugin-reload command currently exposed, that normally
   occurs at ProxySQL process restart; the implementation does not conflate
   the underlying database requirement with a hot-reload redesign.
5. Reject external-access `false -> true` while the database is open. Permit
   `true -> false` as an irreversible security tightening.
6. Apply reversible engine changes (`memory_limit`, `threads`) through a
   dedicated internal DuckDB control connection, then apply
   `max_connections`, and apply external-access disabling last.
7. Read back engine state and transactionally publish the effective
   `duckdb-*` runtime slice only after application succeeds.

The operation is serialized against other DuckDB configuration operations,
configuration reads, and shutdown. Existing sessions survive a lower
`max_connections`; the new limit governs subsequent admission.

LOAD is not advertised as fully atomic across SQLite, DuckDB, and listener
state. Complete validation precedes mutation. If a reversible live step fails,
the plugin attempts to restore already changed reversible settings and reports
both the original failure and any rollback failure. Because disabling external
access cannot be undone on an open database, it is ordered last. If runtime
publication fails after effective settings changed, LOAD returns an error that
names the settings already applied; the next runtime-table read reconstructs
truth from the engine.

Invalid memory syntax and mixed valid/invalid candidates fail before any live
change. There is no warning-style partial success.

## Direct DuckDB SQL

Client SQL that changes a managed engine-global setting must not execute in the
client's transaction/session context. Recognized direct `SET` forms for
`memory_limit`, `threads`, and disabling `enable_external_access` are routed
through the same serialized internal control path and read back after success.
Re-enabling external access and changing access mode are rejected with the
same lifecycle guidance as Admin LOAD. Other DuckDB session settings continue
to pass through normally.

Every Admin query referencing `runtime_global_variables` refreshes the
`duckdb-*` slice from effective state, so permitted direct SQL changes are
visible to existing and new connections and agree with the runtime table.

## SAVE and persistence commands

- `SAVE DUCKDB VARIABLES TO MEMORY` and `SAVE DUCKDB VARIABLES FROM RUNTIME TO
  MEMORY` replace the `duckdb-*` Main slice with the effective snapshot.
- `SAVE DUCKDB VARIABLES TO DISK` copies only `duckdb-*` Main rows to Disk.
  `SAVE DUCKDB VARIABLES FROM MEMORY TO DISK` is an alias.
- `LOAD DUCKDB VARIABLES FROM DISK` copies only `duckdb-*` Disk rows to Main,
  then leaves the copied values pending in Main; run `LOAD DUCKDB VARIABLES TO
  RUNTIME` separately to apply them. `LOAD DUCKDB VARIABLES TO MEMORY` is an
  alias. A rejected live transition remains in Main and does not falsify
  Runtime.
- Normal process startup restores `disk.global_variables` to Main before the
  plugin opens, so saved database, access, listener, memory, thread, and
  connection settings take effect on the new DuckDB lifecycle.

## Status

Plugin status reports `DuckDBEngine::database_path()`, never the pending Main
path. A rejected path edit therefore leaves both status and Runtime naming the
database that is actually open.

## Concurrency and lifecycle

`DuckDBEngine` owns a configuration mutex and an internal control connection.
Opening, live application, effective-setting reads, client-routed managed SET,
and close use that ownership boundary. Session query execution keeps its own
connection, while DuckDB provides visibility of global settings across
connections. Shutdown first stops listeners and joins sessions, then closes the
control connection and database.

The Admin runtime refresh runs while the plugin manager holds its shared
lifecycle lock, preventing unload during projection. SQLite publication uses a
short transaction and modifies only the `duckdb-%` namespace.

## Verification

Tests are written before implementation and cover:

- absence of the two dedicated DuckDB tables and presence of all standard
  prefixed rows;
- one-time legacy migration without overwriting newer prefixed values;
- live threads and memory changes verified using `current_setting()` through
  two real plugin connections;
- runtime-table agreement after Admin LOAD and permitted direct SET;
- invalid and mixed candidates producing no misleading success;
- rejected startup-only changes, unchanged startup-only values, both external
  access directions, actual status path, and connection admission behavior;
- Main/Runtime/Disk separation, runtime-to-memory save, disk persistence, and
  a real process restart;
- concurrent effective reads, LOAD, client SET, and shutdown failure paths.

Focused unit tests and isolated end-to-end plugin tests use disposable
credentials, loopback listeners, temporary databases, and matching core/plugin
build modes. Both `PROXYSQL40=1` release and debug configurations are checked.
Native DuckDB probes are reported separately from tests that traverse the full
ProxySQL Admin and plugin protocols.

## Documentation and WebUI handoff

DuckDB repository documentation must use only `global_variables` and
`runtime_global_variables`, describe immediate versus lifecycle-dependent
settings, state the non-atomic failure contract, and show the LOAD/SAVE/Disk
commands above.

The WebUI needs no workaround or dedicated DuckDB scalar-table support. It can
edit/filter `global_variables` by `variable_name LIKE 'duckdb-%'`, read the
effective values from the same prefix in `runtime_global_variables`, and show
Admin command errors verbatim. Pending Main values may intentionally differ
from Runtime when an unsupported live transition is rejected.
