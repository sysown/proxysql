# DuckDB Server Plugin — External Design

Date: 2026-08-26
Status: approved design, pending implementation plan
Tier: v4.0 (Plugin Chassis, `PROXYSQL40=1`)

## 1. Goal

Expose an embedded DuckDB instance over the MySQL and PostgreSQL wire
protocols as a first-class ProxySQL 4.0 plugin. Clients connect with ordinary
`mysql` / `psql` clients (or any MySQL/PostgreSQL driver) and run DuckDB SQL
against an in-process analytical engine.

This is the SQLite3 Server's role — an embedded engine behind a protocol
gateway — rebuilt on the Plugin Chassis instead of compiled into the core
binary.

## 2. Scope

This document specifies **sub-project 1 of 3**. The overall work was
decomposed because it spans several independent subsystems.

**In scope (this spec):**

- `deps/duckdb` vendoring and build integration
- `plugins/duckdb/` scaffold and the four-phase plugin descriptor
- MySQL protocol listener and session path
- PostgreSQL protocol listener and session path
- Query execution, result conversion, type mapping, error mapping
- A minimal Admin surface: `duckdb_variables`, its runtime view, and
  `LOAD`/`SAVE` commands
- Lifecycle, clean shutdown, and unload safety
- Unit and end-to-end tests for both protocols
- Plugin and deps documentation

**Deferred to sub-project 2:** deeper Admin and observability surface —
`stats_duckdb_processlist`, Prometheus counters on the shared registry,
richer runtime views.

**Deferred to sub-project 3:** hardening — query timeouts via
`duckdb_interrupt()`, prepared statements, and typed (non-text) result
columns.

**Explicit non-goals for v1** (carried from the original request): HTAP
routing or data synchronisation from remote backends; a DuckDB extension
management UI; MySQL dialect emulation beyond a small compatibility
intercept table; multi-process isolation.

## 3. Findings the design rests on

These were verified in-tree and are what make the design small. Each is
load-bearing; if one turns out to be wrong, revisit the section that cites it.

| # | Finding | Evidence |
|---|---|---|
| F1 | The proxysql binary exports its symbols, and plugins are `dlopen`ed such that undefined symbols resolve against the executable. A plugin can therefore call core classes directly. | `src/Makefile:140` (`-Wl,--export-dynamic`); `lib/ProxySQL_PluginManager.cpp:356` (`dlopen(RTLD_NOW\|RTLD_LOCAL)`) |
| F2 | `handler_function` is a plain function pointer on both session classes, set by whoever creates the session. | `include/MySQL_Session.h:636`; `include/PgSQL_Session.h:594` |
| F3 | `session_type = PROXYSQL_SESSION_SQLITE` already means "authenticate against `mysql_users`/`pgsql_users` via `USERNAME_FRONTEND`, no hostgroup, no backend" in ~25 places in the protocol layer. | `include/proxysql_structs.h:808-813` (`cred_scope_for_session`); `lib/MySQL_Protocol.cpp:1608,1665,2955,3363` |
| F4 | The only two core sites that cast `thread->gen_args` to `SQLite3_Session*` null-check it first, so leaving `gen_args` null is safe. | `lib/MySQL_Session.cpp:796`; `lib/PgSQL_Session.cpp:370` |
| F5 | `SQLite3_result` can be constructed from strings alone — no `sqlite3_stmt` required — and a `NULL` field pointer round-trips as SQL NULL. | `include/sqlite3db.h:190-201`; `lib/sqlite3db.cpp:132-160` |
| F6 | Both wire serializers accept a `SQLite3_result*` and emit every column as text. | MySQL: `lib/MySQL_Session.cpp:9117-9177` (`MYSQL_TYPE_VAR_STRING`). PG: `lib/PgSQL_Protocol.cpp:228-300` (`TEXTOID`) |
| F7 | The PG path is the **free function** `SQLite3_to_Postgres()`, not the `SQLite3_to_MySQL` override on `PgSQL_Session` (which emits MySQL packets and is not the PG path). | `include/PgSQL_Protocol.h:1192`; `lib/PgSQL_Session.cpp:5639` |
| F8 | Plugins `start()` before `GloMTH`/`GloPTH` are running, so connection threads must wait. | `src/main.cpp:1592-1595` vs. phase 3 at `src/main.cpp:1644`; `include/proxysql_utils.h:421` (`wait_for_glo_mth`) |
| F9 | Extracting the SQL text from a packet is already solved for both protocols in one templated function. | `lib/Admin_Handler.cpp:3067,3084-3125` |
| F10 | `deps/Makefile` performs no network fetches; all 25 deps are committed source archives built from source. | `grep -n "wget\|curl -\|git clone" deps/Makefile` returns nothing |
| F11 | Vendoring large dep sources via git LFS is an established (in-flight) pattern, including CI enablement across 177 workflow files and pointer-file detection in a verify script. | `ea6fbe159` (openssl, branch `feature/issue-6115-vendored-openssl`); `b4e48f1e` (aws-sdk-cpp) |

The consequence of F1, F2, F5, F6, F7 and F9 together is that **v1 writes no
wire-protocol code**. That is the central simplification of this design.

## 4. Decisions and rationale

### D1 — Dependency: LFS-vendored source, built from source, linked statically

`deps/duckdb/duckdb-<version>.tar.gz` is committed via git LFS and built from
source by a `deps/Makefile` recipe.

Rejected: downloading an official prebuilt `libduckdb` at build time. It would
be the only dep fetched from the network and the only third-party `.so` shipped
in a package (F10), and no FreeBSD bundle exists while `deps/Makefile:113`
shows FreeBSD is an accommodated platform. (For the record: macOS *is* covered
by upstream prebuilts, so platform coverage alone was not the deciding factor —
build hermeticity was.)

Rejected: committing the tarball as a plain blob. The DuckDB source archive is
~97 MB. Plain git warns above 50 MB and hard-rejects pushes above 100 MB, so a
plain commit would sit 3 MB from a wall a single version bump could cross. LFS
caps at 2 GB.

Static linking of `libduckdb_static.a` into `ProxySQL_DuckDB_Plugin.so` means
nothing new ships in the package beyond the plugin itself, and removes the
`-Wl,-rpath` and library-packaging concerns entirely.

The **C API** (`duckdb.h`) is used rather than the C++ API: a much smaller and
more stable surface, and it insulates `duckdb_engine.cpp` from DuckDB version
churn.

The exact DuckDB version is pinned during implementation to the newest stable
release that builds on every distro in the package matrix (section 14). The
pinned version and its SHA-256 are recorded in `deps/duckdb/README.md` and the
`.sha256` sidecar; `<version>` / `<ver>` throughout this document stands for it.

Follow `deps/libssl` as the template (F11):

- `.gitattributes` += `deps/duckdb/duckdb-<ver>.tar.gz filter=lfs diff=lfs merge=lfs -text`
- `deps/duckdb/duckdb-<ver>.tar.gz.sha256` sidecar
- `deps/duckdb/verify-source.bash` — detects an unfetched LFS pointer file,
  verifies the checksum, checks the expected archive root
- `deps/duckdb/README.md` — version-bump and LFS maintenance procedure
- `lfs: true` added to the 66 workflows that reference `PROXYSQL40` (all 66
  already run `actions/checkout`)

Consider repacking the archive as `.tar.xz` — precedent exists
(`aws-sdk-cpp-1.11.869-with-crt.tar.xz`) and it would materially cut LFS
bandwidth across those 66 jobs.

### D2 — Build gating: part of the standard `PROXYSQL40` build

`duckdb` is added to `$(targets)` under `ifeq ($(PROXYSQL40),1)`
(`deps/Makefile:65-67`), and `plugins/duckdb` is built in the same Makefile
stanzas as mysqlx (`Makefile:280,294,427,433,539,593,639`). The plugin ships in
every v4.0 package and gets CI coverage immediately.

Accepted cost: every `PROXYSQL40` build absorbs the DuckDB dep build, which
will be the largest compile in the tree (estimated 10–30 minutes). **Action:**
measure the actual CI wall-clock delta on the first green build and report it,
so the decision can be revisited with data rather than an estimate.

### D3 — Core seam: reuse `PROXYSQL_SESSION_SQLITE`, zero core changes

The plugin sets `session_type = PROXYSQL_SESSION_SQLITE` and its own
`handler_function`, leaves `thread->gen_args = nullptr` (F4), and ignores the
`_pa` argument that core's dispatch passes, reaching its context through a
static in the `.so` instead.

By F3 this inherits the correct authentication and protocol semantics for free.
The diff outside `plugins/duckdb/`, `deps/duckdb/` and build glue is empty,
which satisfies the "no impact on core when the plugin is not loaded"
criterion by construction.

Rejected: adding `PROXYSQL_SESSION_DUCKDB` — ~25 edits across the protocol,
logger and session layers, all of which would have to treat it identically to
`SQLITE`, for a cosmetic gain and a large regression surface in the auth path.

Rejected: adding a generic `handler_arg` seam to `Base_Session` — defensible
and only ~6 lines, but it is a core change that this sub-project does not
need. It remains the natural first step whenever the "SQLite3 Server as a
plugin" refactor happens.

**Known cost:** DuckDB sessions report as `PROXYSQL_SESSION_SQLITE` in logs and
in `stats_*_processlist`. Documented, not worked around.

## 5. Architecture

### 5.1 File layout

```
deps/duckdb/
  duckdb-<ver>.tar.gz          (LFS)
  duckdb-<ver>.tar.gz.sha256
  verify-source.bash
  README.md
plugins/duckdb/
  Makefile
  README.md
  include/   duckdb_plugin.h duckdb_config.h duckdb_engine.h
             duckdb_result.h duckdb_session.h duckdb_listener.h
             duckdb_admin_schema.h
  src/       duckdb_plugin.cpp duckdb_config.cpp duckdb_engine.cpp
             duckdb_result.cpp duckdb_session.cpp duckdb_listener.cpp
             duckdb_admin_schema.cpp
```

`plugins/duckdb/Makefile` is derived from `plugins/mysqlx/Makefile`, keeping
`-fvisibility=hidden -fvisibility-inlines-hidden` with only
`proxysql_plugin_descriptor_v1` exported, and the tier-flag cascade block
verbatim — a flag mismatch silently changes the descriptor layout the core and
the plugin each see.

### 5.2 Component responsibilities

| Unit | Does | Depends on |
|---|---|---|
| `duckdb_plugin` | Descriptor, the four lifecycle callbacks, `status_json`, the exported entry point | all below |
| `duckdb_config` | `DuckDBConfigStore`: typed variables under one mutex, iface parsing, validation | admindb |
| `duckdb_engine` | `DuckDBEngine`: owns the single `duckdb_database`, opens/closes it, hands out `duckdb_connection` | libduckdb only |
| `duckdb_result` | `duckdb_result` → `SQLite3_result` conversion | libduckdb, `sqlite3db.h` |
| `duckdb_session` | `DuckDBSessionState`, the templated `handler_function`, compatibility intercepts | engine, result |
| `duckdb_listener` | Accept loop, per-connection thread bootstrap, connection accounting | core session classes |
| `duckdb_admin_schema` | Table defs, runtime view, `LOAD`/`SAVE` command callbacks | chassis services |

Only `duckdb_engine.cpp` and `duckdb_result.cpp` include `duckdb.h`; only
`duckdb_listener.cpp` touches core session internals. That boundary is what
makes a later "SQLite3 Server as a plugin" refactor cheap — the listener is
generic over `(engine, handler_function)` and nothing else needs to move.

### 5.3 Session model

Thread-per-connection, following `SQLite3_Server::child_mysql`
(`src/SQLite3_Server.cpp:1252`). Each accepted socket gets a thread that:

1. calls `wait_for_glo_mth()` (F8) and bails out immediately on shutdown;
2. constructs a `MySQL_Thread` / `PgSQL_Thread` and one session via
   `create_new_session_and_client_data_stream<>()`;
3. sets `session_type = PROXYSQL_SESSION_SQLITE` and `handler_function`;
4. leaves `thread->gen_args = nullptr` (F4);
5. runs the `poll` / `read_from_net` / `read_pkts` / `sess->handler()` loop.

Per-session DuckDB state lives in a **`thread_local DuckDBSessionState`** in
the plugin, holding one `duckdb_connection`. This is sound precisely because
the model is thread-per-connection, and it avoids the `gen_args` type
confusion.

**No worker pool in v1**, despite the original request suggesting one. DuckDB
already parallelises a single query across its own internal thread pool, sized
by the `threads` setting the plugin exposes; a pool in front of it would add a
queue and a handoff without adding parallelism. Resource isolation is delivered
by DuckDB's `threads` and `memory_limit` plus a `max_connections` cap, not by
owning threads. If accept-thread pressure ever shows up in profiling, the
listener is the only unit that changes.

**One DuckDB instance.** `DuckDBEngine` opens the database once (a file path or
`:memory:`) and `duckdb_connect()`s per session; DuckDB's own concurrency
control does the rest.

## 6. Data flow

A single templated `duckdb_session_handler<S>` is registered for both session
classes, mirroring `admin_session_handler<S>` (F9):

1. **Extract SQL.** `if constexpr (std::is_same_v<S, MySQL_Session>)` skips
   `mysql_hdr` plus the command byte. The `PgSQL_Session` branch calls
   `myprot.get_header()`, rejects `PG_PKT_STARTUP`, `PG_PKT_STARTUP_V2`,
   `PG_PKT_CANCEL`, `PG_PKT_SSLREQ` and `PG_PKT_GSSENCREQ`, and validates the
   trailing NUL. Modelled on `lib/Admin_Handler.cpp:3084-3125`.
2. **Compatibility intercepts.** A small table answering `SELECT @@version`,
   `SELECT DATABASE()`, `SHOW TABLES`, `SHOW DATABASES`, `SET ...`
   (accept-and-ignore) and driver handshake probes without touching DuckDB.
   Same role as `src/SQLite3_Server.cpp:412-880`, but a fraction of the size —
   no Aurora/Galera/monitor simulation.
3. **Execute.** `duckdb_query(state.conn, sql, &res)`.
4. **Convert.** `duckdb_result` → `SQLite3_result` (section 7).
5. **Serialize.**
   - MySQL: `sess->SQLite3_to_MySQL(r, error, affected_rows, &sess->client_myds->myprot)`
   - PG: `SQLite3_to_Postgres(&sess->client_myds->PSarrayOUT, r, error, affected_rows, sql)`

The PG `query_type` argument must be the original SQL text: `SQLite3_to_Postgres`
derives the `CommandComplete` tag from its first whitespace-delimited word
(`lib/PgSQL_Protocol.cpp:231-234`).

## 7. Type mapping

Both serializers already flatten every column to text (F6). v1 therefore
converts each value with `duckdb_value_varchar()` and releases it with
`duckdb_free()`; a SQL NULL becomes a `nullptr` field, which F5 confirms
round-trips correctly and which `SQLite3_to_Postgres` emits as a `-1` length.

This yields DuckDB's own rendering of `DECIMAL`, `TIMESTAMP`, `INTERVAL`,
`UUID`, and the nested `LIST` / `STRUCT` / `MAP` types at no cost, and is
correct on the wire because both text protocols transmit values as strings
regardless.

Column names come from `duckdb_column_name()` into `add_column_definition()`.
A DDL or DML statement produces a NULL resultset with `duckdb_rows_changed()`
as `affected_rows`.

**Documented limitation:** typed client accessors see VARCHAR (MySQL) and
`TEXTOID` (PG) for every column — identical to what the Admin interface and
SQLite3 Server do today. Emitting real types from `duckdb_column_type()` is
sub-project 3.

## 8. Error handling

`duckdb_result_error()` supplies the message.

- **MySQL:** `send_MySQL_ERR()`, matching `SQLite3_Server`'s error path.
- **PostgreSQL:** the plugin emits its own `ErrorResponse` via `PG_pkt` with
  SQLSTATE `42601` / `42000`. Passing `result=NULL, error=msg` to
  `SQLite3_to_Postgres` would work, but it hardcodes SQLSTATE `28000`
  (`lib/PgSQL_Protocol.cpp:283`), which means *invalid authorization* rather
  than *syntax error*. That is a pre-existing core wart; the plugin keeps the
  fix local rather than changing core, consistent with D3.

Malformed packets, unsupported PG packet types, and connection-limit rejections
all produce a protocol-correct error before any DuckDB work is attempted.

## 9. Admin surface (v1)

Registered in Phase B, following `plugins/mysqlx/src/mysqlx_admin_schema.cpp`:

```sql
CREATE TABLE duckdb_variables (
  variable_name  VARCHAR NOT NULL PRIMARY KEY,
  variable_value VARCHAR NOT NULL DEFAULT ''
)
```

Seeded variables: `mysql_ifaces`, `pgsql_ifaces`, `database_path` (default
`:memory:`), `memory_limit`, `threads`, `max_connections`, `read_only`.

- `LOAD DUCKDB VARIABLES TO RUNTIME` and `SAVE DUCKDB VARIABLES TO DISK` via
  `register_command`, plus `LOAD DUCKDB VARIABLES FROM MEMORY` and
  `SAVE DUCKDB VARIABLES FROM RUNTIME TO MEMORY` registered against those
  canonical spellings via `register_command_alias` — the pattern the ABI header
  documents for mysqlx.
- `runtime_duckdb_variables` projected on demand via `register_runtime_view`
  (ABI 3), per the separation-of-duties contract in `include/ProxySQL_Plugin.h`:
  `LOAD` reads the editable table and installs into the module; `SAVE` dumps the
  module into the editable table; neither touches the runtime view.

`status_json` reports `{"name":"duckdb","state":...}` plus database path and
open connection count.

## 10. Lifecycle and shutdown

| Phase | Action |
|---|---|
| B `register_schemas` | Register table def, runtime view, commands. DB handle getters return nullptr by contract — do not touch them here. |
| D `init` | Allocate `DuckDBPluginContext` and `DuckDBConfigStore`. Nothing expensive or failure-prone. |
| E `start` | disk→memory sync of `duckdb_variables`, install into the config store, `duckdb_open_ext()` with the configured options, bind listeners, spawn the accept thread. |
| `stop` | Signal the accept thread, join it, close listener fds, join every live connection thread, then `duckdb_close()`. |

`stop()` pairs with `init()`, not `start()`: `include/ProxySQL_Plugin.h` states
that any plugin whose `init()` returned true receives exactly one `stop()`,
even if its own `start()` failed. `stop()` must therefore tolerate an unbound
listener and a null database handle.

**Unload safety — a deliberate divergence from `SQLite3_Server`.** Its
`child_mysql` threads are fire-and-forget and exit on `glovars.shutdown`, which
is adequate for something that only dies at process exit. "The plugin can be
unloaded without crashing" is a success criterion here, and a detached thread
holding a `duckdb_connection` after `duckdb_close()` is a use-after-free. The
plugin therefore tracks connection threads in a vector under a mutex and joins
them all before closing the database.

Wakeup uses the self-pipe plus `poll` pattern from `Mysqlx_Thread`
(`plugins/mysqlx/include/mysqlx_thread.h:71`, `plugins/mysqlx/src/mysqlx_thread.cpp:96`)
rather than `SQLite3_Server`'s poll-timeout-and-check-a-flag loop, so unload is
prompt instead of up to one `refresh_interval` late.

## 11. Resource governance (v1)

- `memory_limit` and `threads` — passed to `duckdb_config` at open.
- `read_only` — `access_mode=READ_ONLY`. Valid only for file-backed databases;
  combined with `:memory:` it must be **rejected at config-validation time with
  a clear message**, not left to fail at open.
- `max_connections` — enforced in the accept loop, rejecting with a
  protocol-correct error *before* a session object is constructed.
- Query timeouts — require `duckdb_interrupt()` on a watchdog thread. Deferred
  to sub-project 3 rather than half-built here.

## 12. Testing

**Unit** — sources in `test/tap/tests/unit/`, using the `test_globals.h` /
`test_init.h` harness required there, registered in group `unit-tests-g1` and
annotated `@proxysql_min_version:4.0`, mirroring
`test/tap/groups/groups.json:133-142`:

- `duckdb_result_unit-t` — conversion across integer, float, decimal,
  timestamp, blob, `LIST` and `STRUCT`; NULL handling; empty resultsets.
- `duckdb_config_unit-t` — variable and iface parsing; the `read_only` plus
  `:memory:` rejection.
- `test_duckdb_plugin_load-t` — dlopen, descriptor, ABI version, clean unload.
  Modelled on `test_mysqlx_plugin_load-t`.

**End-to-end** — a new `duckdb-e2e-g1` group whose `setup-infras.bash` injects
`plugins=("/usr/lib/proxysql/plugins/ProxySQL_DuckDB_Plugin.so")`, per the
mechanism documented at `test/infra/control/start-proxysql-isolated.bash:138`:

- `test_duckdb_e2e_mysql-t` — connect, authenticate via `mysql_users`, `SELECT`
  over each type family, NULL rendering, `CREATE`/`INSERT` affected-rows, error
  text and code, and rejection of a wrong password.
- `test_duckdb_e2e_pgsql-t` — the libpq equivalent, additionally asserting
  `CommandComplete` tags and that errors carry `42601`/`42000` rather than
  core's `28000`.
- `test_duckdb_admin_tables-t` — `duckdb_variables`, `LOAD`/`SAVE`, and the
  runtime view projection.

Tests are registered in `groups.json` only; the pattern rule in
`test/tap/tests/Makefile` builds `<name>-t` from `<name>-t.cpp` with no
Makefile change.

No test is required for "no impact when the plugin is not loaded": by D3
nothing outside `plugins/duckdb/`, `deps/duckdb/` and build glue changes, so
the existing suites cover it by construction.

## 13. Documentation deliverables

- `plugins/duckdb/README.md` — build, load, configure, client connection
  strings, SQL-dialect caveats, and the v1 limitations from sections 7 and 11.
- `deps/duckdb/README.md` — version-bump and LFS maintenance, mirroring
  `deps/libssl/README.md`.
- A design note covering session → DuckDB connection mapping (section 5.3) and
  the reuse of `PROXYSQL_SESSION_SQLITE` (D3).

## 14. Risks and open items

| Risk | Handling |
|---|---|
| DuckDB dep build time inflates every v4.0 CI job | Measure the delta on the first green build and report it (D2). |
| AlmaLinux 8 — the oldest distro in the package matrix — may not have a new enough GCC for the pinned DuckDB version | Verify during implementation; if it fails, pin an older DuckDB or raise the toolchain for the plugin only. |
| Whether the DuckDB amalgamation build is still supported upstream, and whether it beats the CMake build | Check during implementation. It trades parallelism for several GB of RAM in one TU, so it may well be worse. Not a design-blocking question. |
| Merge conflicts with the two in-flight LFS branches, which create `.gitattributes` and edit up to 177 of the same workflow files | Sequence deliberately. If `feature/issue-6115-vendored-openssl` lands first, this diff shrinks to one `.gitattributes` line plus the `PROXYSQL40` workflows it did not already cover. |
| `duckdb_value_varchar()` allocates per value, so wide analytical resultsets do many small allocations | Acceptable for v1 and no worse than the existing Admin path. Typed conversion in sub-project 3 removes it. |
