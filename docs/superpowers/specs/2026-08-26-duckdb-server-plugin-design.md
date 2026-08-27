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

### D3 — Core seam: reuse `PROXYSQL_SESSION_SQLITE`

**Corrected by Task 11 (post-implementation) — see §15 for the full
account.** This decision originally read "zero core changes" and claimed
the diff outside `plugins/duckdb/`, `deps/duckdb/` and build glue was
empty. That was true for the MySQL path only. The PostgreSQL path
required two core changes, both narrow and both load-bearing; the text
below is corrected to say so plainly rather than leave the false
guarantee standing.

The plugin sets `session_type = PROXYSQL_SESSION_SQLITE` and its own
`handler_function`, leaves `thread->gen_args = nullptr` (F4), and ignores the
`_pa` argument that core's dispatch passes, reaching its context through a
static in the `.so` instead.

By F3 this inherits the correct authentication and protocol semantics for free.
**On the MySQL path this genuinely needed zero core changes**, and F9's
templated-SQL-extraction claim held there without modification.

**On the PostgreSQL path it did not.** Two core changes were required:

1. **`include/PgSQL_Protocol.h` — `PgSQL_Protocol::get_header()` made
   public.** It was private. It is the only route to the SQL text on this
   path: unlike the MySQL path, `PgSQL_Session::CurrentQuery` is not
   populated before `handler_function` runs (the `PROXYSQL_SESSION_SQLITE`
   dispatch gate is `lib/PgSQL_Session.cpp:2279-2293`, the same site item 2
   below modifies; `CurrentQuery.begin()` only happens on other branches,
   at `:2384`). Reimplementing `get_header()`'s v2/v3
   packet-format parsing in the plugin instead of exposing it would have
   duplicated 60+ lines of wire-format logic that core already gets
   right.
2. **`lib/PgSQL_Session.cpp` (~line 2279) — `PROXYSQL_SESSION_SQLITE`
   added to the gate that routes query packets to the non-backend query
   handler.** Without it, a `'Q'` packet arriving on a
   `PROXYSQL_SESSION_SQLITE` PostgreSQL session fell through unhandled:
   the packet leaked and the client hung forever waiting for a response
   that was never generated. Worth recording as an irony: the handler
   this gate dispatches to
   (`handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___not_mysql`)
   already had a `case PROXYSQL_SESSION_SQLITE:` arm — it was simply
   unreachable dead code, because the SQLite3 Server has always been
   MySQL-only and nothing PostgreSQL-side had ever used this session type
   before this plugin.

Both changes are header-visibility / dispatch-condition level, not new
logic: `get_header()`'s body is unchanged, and the gate addition is one
enum value in an existing `||` chain. Neither has any behavioural, ABI,
or codegen effect on a build where the duckdb plugin is not loaded — the
gate is reachable but a `PROXYSQL_SESSION_SQLITE` PostgreSQL session
never existed before this plugin created one, and `get_header()` being
public rather than private changes nothing at the call sites that already
used it as a member function. So **the practical property behind the "no
impact on core when the plugin is not loaded" criterion survives** —
existing behavior for every other session type is provably unchanged —
**but the literal claim of an empty diff outside `plugins/duckdb/` does
not**, and this document said the literal thing. That was the error.

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

**Corrected by Task 11 (post-implementation) — see §15.** This section
originally claimed `duckdb_value_varchar()` renders `UUID` and the nested
`LIST` / `STRUCT` / `MAP` types "at no cost". That is false and was never
verified against the actual DuckDB C API before being written; the
correction below describes what was actually built once it was checked.

Both serializers already flatten every column to text (F6). v1 converts
each value with the deprecated `duckdb_value_varchar()` accessor and
releases it with `duckdb_free()`; a SQL NULL becomes a `nullptr` field,
which F5 confirms round-trips correctly and which `SQLite3_to_Postgres`
emits as a `-1` length.

**`duckdb_value_varchar()` does not render every type.** Verified both by
reading `GetInternalCValue`'s switch on `deprecated_type` in
`duckdb/src/include/duckdb/main/capi/cast/generic.hpp` (the sole
authoritative source for which `duckdb_type` values this accessor can
actually cast) and empirically, by probing the built library: for `LIST`,
`STRUCT`, `MAP`, `ARRAY`, `UNION`, `UUID`, `ENUM`, `BIT`, and
`TIMESTAMP_S`/`MS`/`NS`, it returns `nullptr` regardless of
`duckdb_value_is_null()` — indistinguishable, downstream, from a genuine
SQL NULL. There is no free ride here for nested or composite types, nor
for `UUID`; only the flat scalar types DuckDB can cast through its
deprecated string-cast path render correctly (`BOOLEAN`, the integer and
unsigned-integer families, `FLOAT`/`DOUBLE`, `DATE`/`TIME`/`TIMESTAMP`,
`HUGEINT`/`UHUGEINT`, `DECIMAL`, `INTERVAL`, `VARCHAR`, `BLOB`).

**What was actually built: an allowlist predicate plus a guarded
re-query**, not a denylist (`duckdb_result_has_unrenderable_column()` in
`plugins/duckdb/src/duckdb_result.cpp`, called from
`duckdb_execute_effective()` in `plugins/duckdb/src/duckdb_session.cpp`):

1. `duckdb_type_renders_as_text()` mirrors the C API's positive list
   exactly — a type not on the list (including a hypothetical future
   DuckDB type this file's author never considered) is treated as
   unrenderable by default, the opposite failure mode from a
   hand-maintained denylist that would silently pass an unrecognised type
   through unrendered.
2. When any result column is unrenderable **and** the original statement
   is provably safe to run a second time (`duckdb_is_safe_to_rewrap()` —
   lexically a read: `SELECT`/`WITH`/`TABLE`/`VALUES`/`DESCRIBE`/`SHOW`/
   `PRAGMA`/`EXPLAIN`, with a whole-word `RETURNING` anywhere in the
   statement — including inside a CTE — disqualifying it), the plugin
   re-executes the statement wrapped as
   `SELECT COLUMNS(*)::VARCHAR FROM (<statement>)`, which casts every
   column, nested values included, to a renderable VARCHAR, and converts
   that result instead.
3. **This re-executes the entire statement a second time, side effects
   included.** The safety gate exists specifically because
   `INSERT ... RETURNING` / `UPDATE ... RETURNING` / `DELETE ... RETURNING`
   all classify as a query result in DuckDB 1.4.5 and would otherwise be
   eligible for the same wrap-and-rerun treatment as a `SELECT` — which
   would write twice for one client statement. The plugin refuses to
   rewrap anything that is not lexically a read, full stop, regardless of
   whether today's DuckDB grammar happens to also reject wrapping a bare
   DML statement in a `FROM`-clause subquery (it does, in 1.4.5 — but
   that is incidental parser behaviour, not something this code relies
   on).
4. The wrap trims trailing semicolons from the original statement first
   (`trim_trailing_semicolons()`) — DuckDB's parser errors on a trailing
   `;` inside the wrapping subquery, and essentially every interactive
   client sends one — and wraps with newlines around the original text
   rather than straight concatenation, so a trailing `-- comment`
   immediately before the closing `)` cannot swallow it.
5. If the statement isn't safe to rewrap, or the wrapped re-query itself
   fails (e.g. a type `COLUMNS(*)::VARCHAR` genuinely cannot cast), the
   plugin falls back to sending the original, possibly NULL-rendering
   result rather than erroring out on a query that already succeeded.

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

Seeded variables: `mysql_ifaces` (default `0.0.0.0:6031`), `pgsql_ifaces`
(default `0.0.0.0:6034` — **corrected by Task 11, see §15**: an earlier
implementation draft of this plan defaulted `pgsql_ifaces` to `6032`,
which is ProxySQL's own Admin interface; since the plugin's listener
binds with `SO_REUSEPORT`, that default would not have failed the bind
outright, it would have silently split incoming Admin connections between
the real Admin interface and this plugin. `6034` is what shipped and is
the only value this document should ever show), `database_path` (default
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
  timestamp, and blob; NULL handling; empty resultsets; and (**corrected
  by Task 11, see §15** — this originally implied `LIST`/`STRUCT` convert
  like the scalar types, which §7's correction shows is false) that
  `LIST`, `STRUCT`, and `UUID` columns correctly degrade to a null field
  through `duckdb_value_varchar()` and are flagged by
  `duckdb_result_has_unrenderable_column()`, not that their values
  convert.
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

**Corrected by Task 11 (post-implementation) — see §15.** This paragraph
originally read the same way D3 originally did: "by D3 nothing outside
`plugins/duckdb/`, `deps/duckdb/` and build glue changes, so the existing
suites cover it by construction." That premise is false for the same
reason D3's is — two core files did change
(`include/PgSQL_Protocol.h`, `lib/PgSQL_Session.cpp`) — so an argument
built on "nothing changed" cannot stand here either.

The surviving argument is narrower: both core changes are inert for
every session that isn't this plugin's. Making `get_header()` public
changes no behavior at any existing call site (its body is untouched);
adding `PROXYSQL_SESSION_SQLITE` to the PostgreSQL query-dispatch gate
only matters for a session of that type on the PostgreSQL path, and no
such session existed before this plugin created one (the SQLite3 Server
has always been MySQL-only). So the existing test suites — which
exercise every session type and code path that predates this plugin —
still cover "no impact when the plugin is not loaded" by construction,
just not for the reason ("nothing changed") originally given. No new
test was added for this criterion; the reasoning above is why one still
isn't required, not the original (false) "empty diff" premise.

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
| **Resolved (final fix wave, I1): unrestricted filesystem access, default on.** `DuckDBEngine::open()` originally set only `memory_limit`/`threads`/`access_mode`, leaving DuckDB's own `enable_external_access` at its default of `true`. Any `mysql_users`/`pgsql_users` credential could run `read_csv()`/`COPY TO`/`ATTACH` against arbitrary local paths as the ProxySQL process user; `read_only=true` does not prevent this (it governs `access_mode`, not external-state access). | Added `duckdb_variables.enable_external_access`, default `false` (deny by default — overriding DuckDB's own default), applied in `DuckDBEngine::open()`. Loosening it requires the engine to reopen (DuckDB throws changing `false`→`true` on a running database); tightening could be applied live. Documented in `plugins/duckdb/README.md` §5 (Security), including that extension autoload/autoinstall are already off and unaffected by this setting. Covered by a unit test asserting the default denies `read_csv()` of a local file. |
| **Resolved (final fix wave, C1): intermittent `assert(0)` crash in `generate_pkt_ERR`, added by Task 11 (§15).** A malformed query on the plugin's MySQL listener had twice triggered `assert(0)` at `lib/MySQL_Protocol.cpp:434`, inside `generate_pkt_ERR`, reached via the plugin's MySQL error emitter, aborting the entire ProxySQL process, Admin port included. | **Root-caused: a plugin/core `-DDEBUG` build-tier mismatch, not flakiness.** The bind-mounted-stale-`.so` hypothesis recorded here originally (and in §15 item D) was investigated and is **superseded — it was wrong.** `include/MySQL_Protocol.h`'s `bool dump_pkt;` (DEBUG-only) changes `sizeof(MySQL_Protocol)` (80 bytes release vs. 88 `-DDEBUG`); `MySQL_Data_Stream` embeds `MySQL_Protocol` **by value**, so every field after it — including `DSS`, the field `generate_pkt_ERR`'s switch reads — shifts offset (`offsetof(DSS)`: 768 vs. 776) between a release and a `-DDEBUG` build. `plugins/duckdb/Makefile`'s object rule didn't depend on `$(CXXFLAGS)`, so a plugin built with different flags than the last build silently reused stale objects instead of recompiling — the mechanism that let a release-flavoured plugin end up loaded into a `-DDEBUG` core. Fixed in two parts: the chassis loader (`lib/ProxySQL_PluginManager.cpp`) now refuses to `dlopen` a plugin whose `-DDEBUG` setting disagrees with the core's (`PROXYSQL_PLUGIN_ABI_DEBUG_BIT` in `include/ProxySQL_Plugin.h`), protecting every chassis plugin, not just this one; and the Makefile's `.o` rule now depends on a `$(ODIR)/.buildflags` stamp so a flag change forces recompilation. Reproduced and verified end-to-end before and after the fix — see `plugins/duckdb/README.md` §7 for the full writeup, including a second confirmed symptom (a silent per-connection hang via `fill_client_addr()`, not only the `assert(0)`) of the same root cause. |

## 15. Post-implementation corrections (Task 11)

This is a committed design document, written before implementation, and
several of its claims turned out to be wrong once the plugin was actually
built and tested end-to-end (Tasks 1–10). Per this sub-project's own
standards on test/documentation honesty, those claims are corrected in
place above rather than left standing — but a design doc should not
silently rewrite its own history either, so this section records what
changed and why, addressed by the implementation task that discovered
each gap.

**C1 — §4 D3 ("zero core changes").** False as originally written. The
PostgreSQL path required two core changes: `PgSQL_Protocol::get_header()`
made public (`include/PgSQL_Protocol.h`), and `PROXYSQL_SESSION_SQLITE`
added to the query-dispatch gate in `lib/PgSQL_Session.cpp` (~line 2279)
— without which a `'Q'` packet on such a session leaked and the client
hung forever. Discovered building and testing the PostgreSQL e2e path
(Tasks 7–9). The MySQL path genuinely needed zero core changes; only the
PostgreSQL claim was wrong. §4 D3 now describes both changes, why each
was necessary, and why the practical "no impact on core when unloaded"
property still holds even though the literal "empty diff" claim does
not.

**C2 — §7 (type mapping, "at no cost").** False as originally written.
`duckdb_value_varchar()` cannot render `LIST`, `STRUCT`, `MAP`, `ARRAY`,
`UNION`, `UUID`, `ENUM`, `BIT`, or `TIMESTAMP_S`/`MS`/`NS` — it returns
`nullptr` for all of them, indistinguishable from a genuine SQL NULL,
confirmed both against the DuckDB C API source and empirically. This was
never checked against the actual API before this document asserted it.
Discovered implementing result conversion (Task 5) and hardened with the
allowlist predicate and guarded re-query (Task 5/6). §7 now describes the
`duckdb_result_has_unrenderable_column()` allowlist and the
`SELECT COLUMNS(*)::VARCHAR FROM (...)` re-query it triggers, including
why the re-query is gated to lexical reads only (it re-executes the
statement, side effects included) and its trailing-`;` handling.

**C3 — §9 (`pgsql_ifaces` default).** An earlier implementation draft of
this sub-project defaulted `pgsql_ifaces` to `6032` — ProxySQL's own
Admin interface. Because the plugin's listener binds with
`SO_REUSEPORT`, that default would not have failed the bind outright; it
would have silently split incoming Admin connections between the real
Admin interface and this plugin. Caught before merge; the shipped default
is `6034`. §9 now states the port defaults explicitly so this ambiguity
cannot recur.

**D — Known open defect added to §14, later resolved in the final fix
wave (C1).** An intermittent `assert(0)` in `generate_pkt_ERR`
(`lib/MySQL_Protocol.cpp:434`), reached via the plugin's MySQL error
emitter, aborted the entire ProxySQL process twice during Task 9. The
bind-mounted-stale-`.so` hypothesis recorded here at the time was
investigated and is **superseded — it was wrong.** The real root cause
is a plugin/core `-DDEBUG` build-tier mismatch that shifts
`MySQL_Data_Stream`'s member offsets (`MySQL_Protocol` is embedded by
value and gains a DEBUG-only field), silently reproducible whenever
`plugins/duckdb` is built with different flags than the core it loads
into. See §14's table entry and `plugins/duckdb/README.md` §7 for the
full mechanism and the fix (a chassis-level ABI guard plus a build-flag
freshness check in the plugin Makefile).

**E — Build-cost measurement (§4 D2).** `deps/duckdb/README.md` now
carries a "Build cost" section. It is an **observation**, not a
controlled from-scratch measurement: the DuckDB build tree could not be
destroyed and rebuilt under `/usr/bin/time -v` in the same session
without risking the working tree that later verification depends on, so
the recorded wall-clock times (~10 minutes and ~7 minutes, both on 32
cores) are read back from the two occasions this dep genuinely was built
from scratch earlier in the sub-project, not freshly measured. A real
controlled measurement on an actual CI runner is still owed before D2's
gating decision can be considered settled with real data.

**F — Follow-up sweep (post-review).** A first pass at this section
fixed D3, §7, and §9 directly but missed that §12 (Testing) repeated
D3's original "nothing outside `plugins/duckdb/`... changes" premise
almost verbatim to justify skipping a test — leaving the document
correcting the claim in one place while still asserting it, unchanged,
a few sections later. Fixed: §12 now states the same correction and
gives the narrower, still-true argument (both core changes are inert
for every session type that predates this plugin) for why no test was
still added, rather than repeating the false "nothing changed" premise.
A full-document sweep for every other repetition of the corrected
claims turned up two more, both now fixed:

- §12's `duckdb_result_unit-t` bullet described that unit test as
  covering "conversion across ... `LIST` and `STRUCT`", the same
  overclaim §7 makes about `duckdb_value_varchar()` itself. Corrected to
  say what the test actually asserts (checked directly against
  `test/tap/tests/unit/duckdb_result_unit-t.cpp`): that `LIST`,
  `STRUCT`, and `UUID` degrade to a null field and get flagged by
  `duckdb_result_has_unrenderable_column()`, not that their values
  convert.
- The `include/PgSQL_Protocol.h` bullet in D3's numbered list cited
  `lib/PgSQL_Session.cpp:2282` and `:2370` for the dispatch gate and
  `CurrentQuery.begin()` respectively — both copied from the task brief
  without checking them against the file as it stands. Verified against
  the current source: the gate is `2279-2293` (matching the range item 2
  already used) and `CurrentQuery.begin()` for this branch is at `2384`.
  Both citations corrected and now consistent with each other.

The 6032/6034 port correction (C3) and the §7 nested-types correction
(C2) were each already applied everywhere they occurred in the document
at the time of the original pass — the sweep found no further
uncorrected instance of either. Confirmed by re-reading every `grep -n`
hit for `"6032"`, `"renders"`, `"at no cost"`, `"for free"`, and `"UUID"`
in the document: every remaining `6032` hit is a correction explaining
the earlier draft's mistake (§9, and this section), not a live default
or example; the one remaining `"for free"` hit (§4, on F3/authentication
semantics) is unrelated to the type-mapping claim and is accurate as
written.
