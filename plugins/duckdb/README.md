# ProxySQL DuckDB Server Plugin — Reference

## 1. Overview

The **duckdb plugin** embeds a [DuckDB](https://duckdb.org/) instance
inside ProxySQL and serves it over both the MySQL and PostgreSQL wire
protocols. Clients connect with an ordinary `mysql` or `psql` client (or
any MySQL/PostgreSQL driver) and run DuckDB SQL directly against an
in-process analytical engine — no backend database is involved.

This is the SQLite3 Server's role — an embedded engine behind a
protocol gateway — rebuilt as a v4.0 Plugin Chassis plugin instead of
being compiled into the core binary. It is **not** part of the core
`proxysql` binary; it loads as a `.so` at runtime, only when configured.

Design background: `docs/superpowers/specs/2026-08-26-duckdb-server-plugin-design.md`.

## 2. Building

```bash
git lfs pull --include "deps/duckdb/duckdb-1.4.5.tar.gz"   # first build only
PROXYSQL40=1 make
```

`deps/duckdb/duckdb-1.4.5.tar.gz` is vendored via git LFS (see
`deps/duckdb/README.md`). A plain `git clone`/`git checkout` without LFS
support leaves a pointer file in its place; `deps/duckdb/verify-source.bash`
detects that case and prints fetch instructions instead of a confusing
`tar` error, but you still need to have actually run `git lfs pull` (or
have LFS-enabled `actions/checkout` in CI) before the first build.

`PROXYSQL40=1` cascades to `PROXYSQL31=1` → `PROXYSQLFFTO=1` +
`PROXYSQLTSDB=1`. `duckdb` is only added to the deps build (and
`plugins/duckdb` only built) under `PROXYSQL40`; a bare `make` skips both
entirely. If you built under a different tier previously, `make clean`
first — see the tier-mismatch warning in the repo's top-level
`CLAUDE.md`.

The plugin `.so` lands at `plugins/duckdb/ProxySQL_DuckDB_Plugin.so` in
the build tree, and installs to `/usr/lib/proxysql/ProxySQL_DuckDB_Plugin.so`.

## 3. Loading

Add the plugin path to the `plugins` array in `proxysql.cnf` **before**
starting ProxySQL — plugins cannot be loaded after startup, and removing
the line and restarting unloads the plugin cleanly:

```
plugins = (
    "/usr/lib/proxysql/ProxySQL_DuckDB_Plugin.so"
)
```

## 4. Configure

Settings live in the admin table `duckdb_variables` (one row per
setting, `variable_name` / `variable_value`, both `VARCHAR`). The
in-memory module (`DuckDBConfigStore`) is the runtime source of truth
once the plugin has started; the table is how you edit it.

**`duckdb_variables` is empty after a fresh start, until something
populates it.** The module boots with compiled-in defaults regardless
(so the plugin itself always comes up correctly configured), but nothing
`INSERT`s rows into the editable `duckdb_variables` admin table on boot.
An operator who opens Admin right after a fresh install or restart and
runs `SELECT * FROM duckdb_variables` expecting to see the seven defaults
listed below will get zero rows, not the defaults. Two ways to get rows
into the table: `SAVE DUCKDB VARIABLES TO MEMORY` dumps the module's
current (default, if untouched) state into it; or, on a restart where
`disk.duckdb_variables` already has rows from a prior `SAVE DUCKDB
VARIABLES TO DISK`, the plugin's own startup sequence copies
`disk.duckdb_variables` into `main.duckdb_variables` before installing it
into the module (`duckdb_sync_variables_disk_to_memory`, run from
`duckdb_start()`) — so a previously-persisted config reappears in the
editable table automatically, but a truly first-ever boot does not.

| Variable | Default | Notes |
|---|---|---|
| `mysql_ifaces` | `0.0.0.0:6031` | MySQL-protocol listener. `addr:port` entries separated by `;`; IPv6 literals bracketed (`[::1]:6031`). |
| `pgsql_ifaces` | `0.0.0.0:6034` | PostgreSQL-protocol listener. **Not** `6032` — that is ProxySQL's own Admin interface (`admin_variables.mysql_ifaces`). Because the plugin's listener binds with `SO_REUSEPORT`, defaulting to 6032 would not fail loudly; it would silently split incoming Admin connections between the real Admin interface and this plugin. Do not reintroduce 6032 as the pgsql default or example port. |
| `database_path` | `:memory:` | A file path opens (and creates, if absent) a persistent database; `:memory:` is process-lifetime only and shared by every connection to this process. |
| `memory_limit` | `1GB` | Passed to DuckDB at open. |
| `threads` | `2` | DuckDB's own internal worker-thread count for parallelizing a single query. Integer ≥ 1. |
| `max_connections` | `100` | Enforced in the accept loop; rejected with a protocol-correct error before a session object is constructed. |
| `read_only` | `false` | `true` sets `access_mode=READ_ONLY`. Rejected at validation time if combined with `database_path=:memory:` (a read-only in-memory database cannot be usefully opened). |

### LOAD / SAVE commands

Issued over the Admin interface (`mysql -P 6032`, **not** the plugin's own
ports). Canonical spellings plus their registered aliases:

| Command | Alias | Effect |
|---|---|---|
| `LOAD DUCKDB VARIABLES TO RUNTIME` | `LOAD DUCKDB VARIABLES FROM MEMORY` | Reads the editable `duckdb_variables` table and installs every recognised row into the module. Unknown/invalid rows are skipped (reported in the command's message) rather than failing the whole load. |
| `SAVE DUCKDB VARIABLES TO MEMORY` | `SAVE DUCKDB VARIABLES FROM RUNTIME TO MEMORY` | Dumps the module's current state back into the editable `duckdb_variables` table (full replace, not a merge). |
| `SAVE DUCKDB VARIABLES TO DISK` | — | Copies `main.duckdb_variables` → `disk.duckdb_variables` for persistence across restarts. Does not touch the module or the runtime view. |

`runtime_duckdb_variables` is a **read-only projection** of the module,
refreshed on demand whenever it is queried through the Admin handler —
per the chassis's separation-of-duties contract (`include/ProxySQL_Plugin.h`):
`LOAD` reads the editable table and installs into the module; `SAVE`
dumps the module into the editable table; neither command touches the
runtime view directly, and an edit to `duckdb_variables` is not visible
in `runtime_duckdb_variables` until a `LOAD ... TO RUNTIME`.

## 5. Connect

The plugin's listeners are independent of ProxySQL's own MySQL (6033)
and Admin (6032) interfaces. With the defaults above:

```bash
# MySQL protocol, port 6031 — authenticates against mysql_users
mysql -h 127.0.0.1 -P 6031 -u <mysql_users user> -p

# PostgreSQL protocol, port 6034 — authenticates against pgsql_users
psql -h 127.0.0.1 -p 6034 -U <pgsql_users user> main
```

Once connected, run DuckDB SQL directly:

```sql
CREATE OR REPLACE TABLE t(a INTEGER);
INSERT INTO t VALUES (1), (2), (3);
SELECT * FROM t;
```

## 6. Limitations

Stated plainly, not buried:

- **Every column arrives as text.** MySQL clients see `MYSQL_TYPE_VAR_STRING`
  for every column; PostgreSQL clients see `TEXTOID`. This is identical to
  what ProxySQL's own Admin interface and the SQLite3 Server do today.
  Typed (non-text) result columns are deferred to a later sub-project.
- **Some DuckDB types cannot render through the deprecated
  `duckdb_value_varchar()` accessor**, and are handled by a re-query, not
  a silent gap: `LIST`, `STRUCT`, `MAP`, `ARRAY`, `UNION`, `UUID`, `ENUM`,
  `BIT`, and `TIMESTAMP_S`/`MS`/`NS` all render as NULL through the direct
  path. When a result contains any such column, the plugin transparently
  re-runs the query wrapped as `SELECT COLUMNS(*)::VARCHAR FROM (<query>)`,
  which casts every column (nested values included) to a renderable
  VARCHAR. **This re-executes the statement a second time**, including any
  side effects — so the plugin only does this for statements it can prove
  are safe to run twice (a lexical read: `SELECT`/`WITH`/`TABLE`/`VALUES`/
  `DESCRIBE`/`SHOW`/`PRAGMA`/`EXPLAIN`, with a `RETURNING` anywhere in the
  statement, including inside a CTE, disqualifying it). It deliberately
  refuses to re-execute anything that is not a read — in particular,
  `INSERT ... RETURNING` / `UPDATE ... RETURNING` / `DELETE ... RETURNING`
  are never re-run, even if their result contains an unrenderable column;
  such a result falls back to its original (possibly NULL-rendering) form
  rather than risking a double write.
- **No prepared statements.** Every statement is a one-shot text query.
- **No query timeout.** A runaway query is not interrupted; `duckdb_interrupt()`-based
  timeouts are deferred to a later sub-project.
- **Sessions report as `PROXYSQL_SESSION_SQLITE`** in ProxySQL logs and in
  `stats_*_processlist` — the plugin reuses that session type rather than
  adding a dedicated one (see the design note below). This is documented,
  not worked around.
- **Clients must write DuckDB SQL, not MySQL SQL**, beyond a small
  compatibility intercept table (`duckdb_classify_query` in
  `src/duckdb_session.cpp`): `SELECT @@version` / `SELECT VERSION()`,
  `SELECT DATABASE()` / `SELECT CURRENT_DATABASE()`, `SHOW TABLES`,
  `SHOW DATABASES` / `SHOW SCHEMAS`, and `SET ...` (accepted and silently
  ignored, matching what the SQLite3 Server does for session-state
  statements DuckDB has no equivalent for). Anything else goes to DuckDB
  as-is.
- **Known open defect — intermittent MySQL-path crash, unresolved.** Twice
  during this plugin's development, a malformed query on the MySQL
  listener (port 6031) triggered `assert(0)` at
  `lib/MySQL_Protocol.cpp:434` inside `generate_pkt_ERR`, aborting the
  **entire ProxySQL process** (including the Admin port on 6032) via the
  plugin's MySQL error emitter. Since those two occurrences, roughly 500
  further executions of the same code path — a stress campaign, a
  50-iteration control run against core's own SQLite3 Server on port 6030
  using the identical emitter pattern, and several TAP harness runs — have
  all been clean, with the data-stream state instrumented and confirmed
  correct on every one of them. The leading (unproven) hypothesis is that
  the two early crashes ran against a stale `dlopen`'d `.so` inode from a
  bind-mounted container that was not recreated after a rebuild, i.e.
  pre-fix code. **This is not resolved and must not be described as
  flaky.** Anyone hitting it should capture a full backtrace (see
  `docker logs`, `crash_handler` output) and compare it against the two
  on record before assuming it is the same defect. See the design spec's
  risks section for the evidence on both sides.

## 7. Design note: session → connection mapping

- **One shared `duckdb_database`.** `DuckDBEngine` opens the database
  once (a file path or `:memory:`) at plugin start; DuckDB's own
  concurrency control handles concurrent access from multiple connections.
- **One `duckdb_connection` per connection thread, in `thread_local`
  storage** (`DuckDBSessionState`, `include/duckdb_session.h`). The
  listener is thread-per-connection — every accepted socket gets its own
  OS thread running the accept/read/`handler()` loop — so a `thread_local`
  is exactly session-scoped here; there is no worker pool multiplexing
  many client sessions over fewer DuckDB connections.
- **Why `stop()` joins connection threads before closing the engine.**
  `SQLite3_Server`'s equivalent connection threads are fire-and-forget and
  exit only at process shutdown, which is fine for something that only
  dies at process exit. "The plugin can be unloaded without crashing" is a
  requirement here, and a detached thread still holding a
  `duckdb_connection` after `duckdb_close()` is a use-after-free. The
  listener therefore tracks every connection thread in a vector under a
  mutex and joins all of them — in `stop()`, and opportunistically as they
  finish via `reap_finished_threads()` — before the engine is allowed to
  close the database.
