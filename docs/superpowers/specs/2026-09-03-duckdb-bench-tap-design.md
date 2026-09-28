# DuckDB Plugin TAP Benchmark — Design

Date: 2026-09-03
Status: approved
Tier: v4.0 (Plugin Chassis, `PROXYSQL40=1`)
Branch: `feature/duckdb-server-plugin` (PR 6133)

## 1. Goal

A local-only TAP harness that measures connect churn, point-query latency,
and aggregation throughput for four targets in one process, and prints one
comparison table:

| Target | How it is reached |
|---|---|
| `native` | DuckDB C API in the TAP binary (`:memory:`) |
| `plugin-mysql` | libmysqlclient → DuckDB plugin MySQL listener `:6031` |
| `plugin-pgsql` | libpq → DuckDB plugin PostgreSQL listener `:6034` |
| `sqlite3` | libmysqlclient → ProxySQL SQLite3 Server `:6030` |

Numbers are diagnostic. TAP `ok()` means "this cell finished with zero
errors", never "this latency beat a threshold".

## 2. Scope

**In scope**

- `test/tap/tests/test_duckdb_bench-t.cpp`
- A custom link recipe in `test/tap/tests/Makefile` (DuckDB C API + existing
  TAP mysql/libpq libs). Do not link `plugins/duckdb/src/*.cpp`.
- `test/tap/groups/groups.json` registration on `duckdb-e2e-g1`
- Forward bench env vars through `test/infra/control/run-tests-isolated.bash`
- A short "Local benchmark TAP" section in `doc/duckdb/operations.md`

**Out of scope**

- CI scoreboards, latency gates, Prometheus export
- sysbench / pgbench wrappers
- Multi-node or HTAP workloads
- Changing plugin or SQLite3 Server behavior

## 3. Why `duckdb-e2e-g1`

That group already:

- loads `ProxySQL_DuckDB_Plugin.so` (`PROXYSQL_LOAD_DUCKDB_PLUGIN=1`)
- starts ProxySQL with `--sqlite3-server` (see
  `test/infra/control/start-proxysql-isolated.bash`)
- binds SQLite3 Server on `:6030` (`sqliteserver_variables.mysql_ifaces`)
- seeds `testuser`/`testuser` into `mysql_users` and `pgsql_users`
- needs no backend containers

Reusing it avoids a cloned TAP group. CI still lists the binary; the skip
gate below makes the run a no-op there.

## 4. Skip gate (local-only)

Startup order matches the existing duckdb e2e tests:

1. `cl.getEnv()` — on failure `diag` and return `-1` (no `plan()`).
2. `plan(12)`.
3. If `RUN_DUCKDB_BENCH` is not exactly `"1"`:

```cpp
skip(12, "set RUN_DUCKDB_BENCH=1 to run the DuckDB bench");
return exit_status();
```

`skip_all()` is gone from this tree (`test/tap/tap/tap.h`). Do not reintroduce
it.

CI never sets `RUN_DUCKDB_BENCH`, so duckdb-e2e-g1 stays fast.

## 5. Isolated-harness env forwarding

`run-tests-isolated.bash` `docker run`s a test-runner with an explicit `-e`
whitelist. Without an addition, `RUN_DUCKDB_BENCH=1` on the host never
reaches the binary.

Add these `-e` lines next to the existing `TEST_PY_TAP_INCL` pass-through,
defaulting to empty so CI is unchanged:

- `RUN_DUCKDB_BENCH`
- `BENCH_WARMUP`
- `BENCH_ITERS`
- `BENCH_ROWS`
- `BENCH_THREADS`

No other infra scripts change. Do not create Docker networks, containers, or
a throwaway TAP group.

## 6. Configuration

| Env | Default | Role |
|---|---|---|
| `RUN_DUCKDB_BENCH` | unset | must be `1` or the test skips |
| `BENCH_WARMUP` | `50` | untimed iterations discarded |
| `BENCH_ITERS` | `500` | timed iterations |
| `BENCH_ROWS` | `10000` | aggregation table size |
| `BENCH_THREADS` | `1` | pthread count for `connect` and `point` only |

Reject non-positive integers by `diag()` + `BAIL_OUT`. `BENCH_THREADS` applies
only to `connect` and `point`. Aggregation is always one thread so the two
analytical engines are not fighting themselves.

Host/user/password come from `CommandLine` (`cl.getEnv()`), same as
`test_duckdb_e2e_mysql-t.cpp`. Ports are constants, not env:

- SQLite3 Server: `6030`
- DuckDB MySQL: `6031`
- DuckDB PostgreSQL: `6034`

PostgreSQL `conninfo` matches the e2e test: `dbname=main connect_timeout=10`.

## 7. Targets

A small `Target` interface (connect / exec+drain / close). Four implementations.

### 7.1 `native`

`duckdb_open(":memory:", &db)` once. `duckdb_open` failure is `BAIL_OUT` —
without a native engine the comparison table is meaningless.

- connect workload: `duckdb_connect` + `duckdb_disconnect` on that shared db
- point / agg: one long-lived `duckdb_connection`; `duckdb_query` +
  `duckdb_destroy_result` after reading every row

Do not go through `DuckDBEngine` or the plugin. The native baseline is the C
API the plugin itself uses, without wire, auth, or `SQLite3_result`.

### 7.2 `plugin-mysql`

`mysql_real_connect(cl.host, cl.username, cl.password, NULL, 6031, ...)`.
`mysql_query` + `mysql_store_result` + fetch every row + `mysql_free_result`.
DDL/DML with no result set: `mysql_store_result` returning NULL is success
when `mysql_errno` is 0.

### 7.3 `plugin-pgsql`

`PQconnectdb` as in `test_duckdb_e2e_pgsql-t.cpp`. `PQexec` + check
`PGRES_TUPLES_OK` or `PGRES_COMMAND_OK` + `PQclear`.

### 7.4 `sqlite3`

Same MySQL client path as 7.2, port `6030`.

A wire-target connect failure during setup fails that target's remaining
`ok()`s with `diag()` of the client error, and does not abort other targets.

## 8. Workloads

Same SQL on every target. SQLite-compatible subset only. No `CREATE OR
REPLACE`, no `generate_series`, no DuckDB `range()`.

Table name: `bench_<target>_<pid>` so plugin-mysql and plugin-pgsql (same
embedded DuckDB) cannot collide, and a leftover table from a previous run
cannot collide either.

### 8.1 `connect`

Open + close. No query.

### 8.2 `point`

One persistent connection. Loop `SELECT 1 AS x`. Drain the single row.

### 8.3 `agg`

Setup once per target (not timed):

```sql
DROP TABLE IF EXISTS bench_<target>_<pid>;
CREATE TABLE bench_<target>_<pid> (k INTEGER, v INTEGER);
```

Insert `BENCH_ROWS` rows in batches of 100:

```sql
INSERT INTO bench_<target>_<pid> VALUES (k0,v0),(k1,v1),...;
```

`k = i % 10`, `v = i` for `i` in `[0, BENCH_ROWS)`. Ten groups, so `GROUP BY`
is real aggregation, not a unique-key pass-through.

Then loop, draining every row:

```sql
SELECT k, SUM(v) FROM bench_<target>_<pid> GROUP BY k;
```

Teardown: `DROP TABLE IF EXISTS bench_<target>_<pid>` (best-effort, not timed).

Setup SQL failure: fail that target's remaining workloads, continue other
targets.

## 9. Timing and metrics

`clock_gettime(CLOCK_MONOTONIC)`. Each timed iteration records microseconds
as `double`, same arithmetic as `tools/bench_connect.c`.

Warmup iterations are discarded and do not increment `errors`. A warmup
failure is `diag()`'d at most three times per cell.

Per `(target, workload)` after join:

- `ops/s` = successful iterations / wall seconds of the measurement window
- `p50_us` / `p99_us` = percentile of the successful samples only
- `errors` = failed measurement iterations

Percentile: sort the successful samples, index `(int)(n * p)` clamped to
`n-1`, identical to `tools/bench_connect.c`. If `n == 0`, print `p50`/`p99`
as `-` and `ops/s` as `0`.

`BENCH_THREADS > 1`: each thread has its own connection (point) or does its
own connect/close (connect). Concatenate successful samples, then percentile.
Wall clock for `ops/s` is the time from first thread start to last thread
join.

## 10. TAP plan and output

12 cells: 4 targets × 3 workloads, in this order:

1. native/connect, native/point, native/agg
2. plugin-mysql/connect, plugin-mysql/point, plugin-mysql/agg
3. plugin-pgsql/connect, plugin-pgsql/point, plugin-pgsql/agg
4. sqlite3/connect, sqlite3/point, sqlite3/agg

Each cell: `ok(errors == 0, "<target> <workload> errors=0")`.

After all cells, always `diag()` the table, including partial results:

```
# fairness: native = DuckDB C API in the test-runner (no wire, no auth).
#           plugin-* = DuckDB in the ProxySQL container, all-text SQLite3_result.
#           sqlite3  = different engine, same MySQL wire path as plugin-mysql.
# target        workload  threads  iters  ops/s     p50_us    p99_us    errors
# native        connect         1    500   1234.5     800.1    1200.4         0
```

Column widths are not sacred; the header names are. Print the fairness
comment every time, even on skip? No — only when the bench actually runs.

`cl.getEnv()` failure is handled in §4 (return `-1`, no `plan()`).

## 11. Build

`test/tap/tests/Makefile` already includes `include/makefiles_paths.mk`, so
`DUCKDB_IDIR` / `DUCKDB_LDIR` / `DUCKDB_PATH` are available.

1. Always `filter-out test_duckdb_bench-t` from `TESTS_CPP` when
   `PROXYSQL40_DETECTED` is 0 (v3 `make tests` must not compile it).
2. When `PROXYSQL40_DETECTED != 0`, keep it in `TESTS_CPP` and give it a
   specific recipe that beats `%-t: %-t.cpp`.
3. Recipe links TAP helpers + `libtap` + mysql/libpq (`MYLIBS`) + the full
   DuckDB archive set. Copy the `DUCKDB_AR` / `DUCKDB_ARS` /
   `DUCKDB_LINK_GROUP_*` pattern from `test/tap/tests/unit/Makefile`
   (libduckdb_static.a alone does not satisfy DuckDB's symbols).
4. Compile with `-I$(DUCKDB_IDIR)`. Do not add plugin include paths.
5. Prerequisite `$(DUCKDB_AR)` so `PROXYSQL40=1` builds DuckDB if needed.
6. Wrap the recipe so a v3 `make test_duckdb_bench-t` prints that the
   binary is PROXYSQL40-only and exits non-zero, instead of compiling
   against a missing `duckdb.h`.

`test_duckdb_plugin_load-t` is built via `unit/Makefile` because it needs
`--whole-archive libproxysql`. This bench does not: it talks to DuckDB and
to wire clients only. Keep the recipe in `test/tap/tests/Makefile`.

## 12. groups.json

```
"test_duckdb_bench-t" : [ "duckdb-e2e-g1","@proxysql_min_version:4.0" ]
```

No new group. No CI workflow edit.

## 13. operations.md

Add a section **Local benchmark TAP** after Capacity planning, covering:

- it is local-only; CI skips unless `RUN_DUCKDB_BENCH=1`
- required DEBUG + `PROXYSQL40=1` TAP build
- the exact isolated-harness invocation:

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=duckdb-e2e-g1 \
  TEST_PY_TAP_INCL="test_duckdb_bench-t" \
  RUN_DUCKDB_BENCH=1 \
  test/infra/control/run-tests-isolated.bash
```

- optional `BENCH_*` knobs
- how to read the fairness header
- do not treat ops/s from a laptop as a product claim

## 14. Error handling (summary)

| Condition | Behavior |
|---|---|
| `RUN_DUCKDB_BENCH` != `1` | `skip(12, ...)`, exit 0 |
| `cl.getEnv()` fails | `diag`, return `-1`, no `plan()` |
| `duckdb_open` fails | `BAIL_OUT` |
| wire connect fails at setup | fail remaining cells for that target, continue others |
| setup SQL fails | same as wire connect fail for that target |
| measurement query/connect fails | `errors++`, continue the loop |
| any mix of failures | still print the table |

## 15. Testing the test

No nested TAP around the bench. Verification after implementation:

1. Unset `RUN_DUCKDB_BENCH`, run via `run-tests-isolated.bash` with
   `TEST_PY_TAP_INCL="test_duckdb_bench-t"` — 12 skipped, exit 0.
2. `RUN_DUCKDB_BENCH=1` on a quiet machine — 12 `ok`, table printed, four
   targets present.
3. Confirm CI duckdb-e2e-g1 does not set `RUN_DUCKDB_BENCH` (no workflow
   change is the confirmation).

## 16. Non-goals recap

Do not add pass/fail latency numbers. Do not add a scan/`SELECT *` workload
in v1. Do not apply `BENCH_THREADS` to aggregation. Do not shell out to
`mysql`/`psql`/`duckdb` CLIs.
