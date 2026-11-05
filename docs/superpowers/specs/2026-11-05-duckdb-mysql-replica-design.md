# DuckDB MySQL Replica — Design and Handoff

Date: 2026-11-05
Status: implementation in progress
Branch: `feature/duckdb-mysql-replica`
Worktree: `/mnt/data/rene/proxysql3/worktrees/duckdb-mysql-replica`
Base: `v3.0` at `e2f317aba`

## 1. Goal

Compete with [MyDuck Server](https://github.com/apecloud/myduckserver) by
putting the analytical MySQL replica inside ProxySQL instead of beside it.

MyDuck's published HTAP demo uses ProxySQL as a router in front of a separate
MyDuck hostgroup: `SELECT ... FOR UPDATE` and all DML go to MySQL, plain
`SELECT`s go to MyDuck. The target here is the same topology with the second
server deleted. ProxySQL keeps one client listener, one set of credentials,
one query-rule table, and one Admin interface. An embedded DuckDB replica is
fed from the MySQL binlog and is addressable from the same query rules.

This document covers **sub-project 1: the MySQL replica applier**. Routing
`SELECT`s to the replica (an internal query-rule destination) and the MySQL
dialect translator are explicitly **not** part of this document. They are the
next sub-projects and are listed in section 10.

The plugin itself (DuckDB engine, MySQL/PostgreSQL listeners, `duckdb-*`
variables, snapshot loader) already exists on `v3.0`. This branch extends it;
it does not create a second plugin.

## 2. Why the applier lives in the plugin

- `proxysql_binlog_reader` is a separate binary that tracks GTID positions for
  causal reads. It never decodes row images and is not an applier.
- The DuckDB plugin already owns the engine, the Admin tables, the stats
  projection, and the shutdown order. The applier is one more thread in that
  lifecycle.
- Core changes are limited to the existing plugin seam. No new session type,
  no new core thread, no `PROXYSQL_SESSION_DUCKDB`.

## 3. Architecture

```
Admin SQLite (main/disk)
  duckdb_replica_sources ─┐
  duckdb_replica_tables  ─┴─ LOAD/START ──> DuckDBReplica (plugin)
                                              │
                       ┌──────────────────────┴──────────────────────┐
                       │ replica thread (one, owns no Admin mutex)   │
                       │                                             │
                       │ 1. probe source (SHOW GLOBAL VARIABLES,     │
                       │    SHOW BINARY LOG STATUS)                  │
                       │ 2. snapshot: FTWRL -> consistent snapshot ->│
                       │    read GTID -> UNLOCK -> copy tables       │
                       │ 3. applier: COM_BINLOG_DUMP from that       │
                       │    position, decode rows, batch, commit     │
                       └──────────────────────┬──────────────────────┘
                                              │
                                    DuckDB (file-backed)
                                      <source schema>.<table>
                                      proxysql_replica.position
                                      proxysql_replica.tables
```

One DuckDB database, one replica thread, one source. Client sessions connect
through the existing DuckDB listeners; they do not see the replica thread's
DuckDB connection.

## 4. Admin surface

Tables (registered in both `admin_db` and `config_db`, so `SAVE ... TO DISK`
works):

```sql
CREATE TABLE duckdb_replica_sources (
  source_id  VARCHAR NOT NULL PRIMARY KEY,
  hostname   VARCHAR NOT NULL,
  port       INT NOT NULL DEFAULT 3306,
  username   VARCHAR NOT NULL,
  password   VARCHAR NOT NULL DEFAULT '',
  server_id  INT NOT NULL,
  enabled    INT NOT NULL DEFAULT 0
);

CREATE TABLE duckdb_replica_tables (
  source_id   VARCHAR NOT NULL,
  schema_name VARCHAR NOT NULL,
  table_name  VARCHAR NOT NULL,
  active      INT NOT NULL DEFAULT 1,
  PRIMARY KEY (source_id, schema_name, table_name)
);
```

Commands:

- `LOAD DUCKDB REPLICA TO RUNTIME` — validate and install the Main tables.
- `LOAD DUCKDB REPLICA FROM DISK` — copy Disk to Main, then install.
- `SAVE DUCKDB REPLICA TO DISK` — copy Main to Disk.
- `START DUCKDB REPLICA` — re-read Main, snapshot if needed, then apply.
- `STOP DUCKDB REPLICA` — flush committed work, join the thread.
- `RESET DUCKDB REPLICA` — legal only while stopped; drops the replicated
  tables, `proxysql_replica.tables`, and `proxysql_replica.position`.

`stats_duckdb_replica` is projected from the replica thread. Columns:
`source_id, state, hostname, port, server_id, gtid_executed, binlog_file,
binlog_pos, seconds_behind_source, last_error, detail, snapshot_table,
rows_applied, batches`.

States: `stopped`, `checking`, `snapshotting`, `snapshotted`, `applying`,
`error`. `error` is sticky until `STOP`.

## 5. Source requirements

Checked by `duckdb_replica_probe_mysql` before any snapshot:

- `log_bin=ON`
- `binlog_format=ROW`
- `gtid_mode=ON`
- `enforce_gtid_consistency=ON`
- `binlog_row_image=FULL`
- `binlog_row_value_options=''`
- `binlog_transaction_compression=OFF` (accepted if the variable is absent)
- source `server_id` != replica `server_id`

The applier additionally re-checks the row-event column bitmap, because
`binlog_row_image` can change at runtime and the connector's row decoder
ignores partial images.

Privileges: `REPLICATION CLIENT`, `REPLICATION SLAVE`, `SELECT` on the
opted-in tables, `RELOAD` for the snapshot lock.

Rejected at snapshot: tables without a primary key, `JSON`, `ENUM`, `SET`,
geometry, non-`utf8mb4`/`utf8`/`ascii`/`binary` charsets, decimal width > 38.
`TIME` is stored as `VARCHAR` (MySQL time can be negative or exceed 24h).

## 6. Snapshot semantics

1. `FLUSH TABLES WITH READ LOCK`
2. `START TRANSACTION WITH CONSISTENT SNAPSHOT`
3. Read `SHOW BINARY LOG STATUS` (file, position, `Executed_Gtid_Set`)
4. `UNLOCK TABLES`
5. For each opted-in table: map `information_schema.COLUMNS`, create the
   DuckDB table, stream rows through `duckdb_appender`, flush every 1000 rows.
6. In one DuckDB transaction: insert `proxysql_replica.tables` metadata, insert
   `proxysql_replica.position`, commit.

If the position row exists, the snapshot is skipped (`already_loaded`). A
crash before the position commit leaves no position; the next start drops the
partial tables and snapshots again. The MySQL read transaction stays open for
the whole copy and is committed after the DuckDB commit.

A source `server_uuid` change since the snapshot is an error; the operator must
`RESET` and snapshot again.

## 7. Apply semantics

- `COM_BINLOG_DUMP` starts at the stored file/position. The classic
  file/position protocol is used deliberately: the vendored connector's
  `MARIADB_RPL` has no portable GTID-start field.
- `TABLE_MAP` metadata is copied because the connector's event object is reused
  by the next fetch.
- Rows are decoded with `mariadb_rpl_extract_rows`, which returns typed values
  (`MARIADB_RPL_VALUE`). We do not hand-parse row images.
- `UPDATE_ROWS` is assumed to yield before/after pairs in that order. **This is
  one of the two things the end-to-end test must confirm.**
- Row statements are buffered per source transaction and only appended to the
  apply batch on `XID`/`COMMIT`. `ROLLBACK` discards the buffer.
- Flush triggers: 50,000 statements, 64 MB of SQL, or 200 ms since the last
  flush (checked on events/heartbeats).
- One DuckDB transaction per flush: all row statements, then
  `UPDATE proxysql_replica.position` with the union GTID set, file, and
  position. Commit is atomic. A failure rolls back and leaves the previous
  position.
- DDL (`ALTER`, `RENAME`, `TRUNCATE`, `DROP`/`CREATE`, XA) stops the replica
  with the statement in `last_error`. It is not applied and not skipped.
- `seconds_behind_source` is the age of the last event timestamp.

### Value representation

Values are rendered as DuckDB SQL literals, not bound parameters:

- integers / unsigned integers -> numeric literal
- float/double -> `%.17g`
- decimal -> validated numeric text
- date/datetime/time -> quoted text (DuckDB casts)
- text -> quoted, `'` doubled; NUL is refused
- blob -> `from_hex('...')`
- NULL -> `NULL`

This is deliberately simple and testable. It is not the long-term performance
path; prepared statements with bound values are the follow-up.

## 8. File map

| Path | Responsibility |
|---|---|
| `plugins/duckdb/include/duckdb_replica.h` | Config, status, type mapping, thread |
| `plugins/duckdb/include/duckdb_replica_binlog.h` | Value/GTID types, apply entry point |
| `plugins/duckdb/src/duckdb_replica.cpp` | Lifecycle, probe, thread state machine |
| `plugins/duckdb/src/duckdb_replica_admin.cpp` | Admin tables, commands, stats projection |
| `plugins/duckdb/src/duckdb_replica_types.cpp` | MySQL -> DuckDB column mapping |
| `plugins/duckdb/src/duckdb_replica_snapshot.cpp` | Locked snapshot, appender load, position |
| `plugins/duckdb/src/duckdb_replica_values.cpp` | SQL literals, GTID interval set |
| `plugins/duckdb/src/duckdb_replica_binlog.cpp` | Dump stream, row decode, batching, apply |
| `test/tap/tests/unit/duckdb_replica_unit-t.cpp` | Type mapping, literals, GTID, lifecycle |

Wiring: `duckdb_plugin.cpp` registers the replica admin schema, installs the
config at start, joins the replica in `stop()` before the engine closes, and
reports the replica state in `status_json`.

Build: `plugins/duckdb/Makefile` adds the new sources and links
`-L$(MARIADB_LDIR) -lmariadbclient` (the core does not export
`mariadb_rpl_*`; `--gc-sections` drops it from the executable).

## 9. Validation status

Done in this branch:

- `duckdb_replica_values.cpp`, `duckdb_replica_types.cpp`,
  `duckdb_replica.cpp`, `duckdb_replica_snapshot.cpp`,
  `duckdb_replica_binlog.cpp`, `duckdb_replica_admin.cpp`, and
  `duckdb_plugin.cpp` compile with `-fsyntax-only` against the real DuckDB
  1.4.5 and MariaDB Connector/C 3.3.8 headers.
- The unit test file compiles.
- A standalone run of the pure logic asserts:
  - `'O''Reilly'` escaping
  - `from_hex('01ff')` for blobs
  - non-numeric decimal text is refused
  - NUL in VARCHAR is refused
  - GTID interval compression (`u:1-2,u:4`)
  - `u:1-1000000000` parses in constant time
  - `int unsigned` -> `UINTEGER`
  - JSON is refused

**Not done:** a live MySQL 8.4 run. The applier has never decoded a real
binlog event in this environment. The update before/after pairing and
`ROTATE`/position handling are assumptions until the end-to-end test below
passes.

## 10. Next steps, in order

### 10.1 End-to-end replica test (blocking)

Add `test/tap/tests/test_duckdb_replica-t.cpp` to `duckdb-e2e-g1`:

1. Start the existing MySQL 8.4 infra with GTID + ROW + FULL.
2. Create `app.events` with a primary key and a few types (int, decimal,
   varchar, datetime, blob).
3. Configure `duckdb_replica_sources` / `_tables`, `START`.
4. Wait for `stats_duckdb_replica.state = 'applying'`.
5. `INSERT`/`UPDATE`/`DELETE` on the source; poll the DuckDB listener until
   the row set matches.
6. Restart ProxySQL; assert `state = 'applying'`, the position did not move
   backwards, and no row is duplicated.
7. Assert `ALTER TABLE` puts the replica in `error` and leaves the position
   unchanged.
8. `RESET`, `START`, assert a fresh snapshot matches the source.

Acceptance: no gap, no duplicate, and the position is never ahead of the
applied data.

### 10.2 Fixes the test is expected to force

- Confirm `mariadb_rpl_extract_rows` update row ordering.
- Confirm `ROTATE` handling when a binlog file rolls during the test.
- Confirm `TIMESTAMP2` text format from the connector.
- Decide whether `binlog_row_metadata=FULL` should be required (it would make
  `signed_indicator` and enum labels available).

### 10.3 After the applier is trusted

1. **Internal query-rule destination.** A rule action that sends a statement
   to the embedded engine instead of a backend, with lag-aware fallback to the
   primary. Acceptance: MyDuck's three-rule demo works with no `myduck`
   server.
2. **MySQL analytical translator.** The bounded `SELECT` subset; fail or fall
   back on anything else.
3. **Typed results and prepared statements** on the proxy listener path.
4. **Bulk load** (`LOAD DATA LOCAL INFILE`, `COPY FROM STDIN`).
5. **Postgres logical replication** into the same engine.

## 11. Known risks

| Risk | Handling |
|---|---|
| `next_event_pos` is `unsigned int` in the connector | Positions above 4 GB truncate; document and test with a rotated file. Long-term: track file/pos from raw event headers. |
| `STOP` can block up to the 5 s dump read timeout, longer on the snapshot lock | `STOP` releases the Admin mutex during the join; documented. |
| SQL-literal apply is slower than bound parameters | Acceptable for v1; measure before optimizing. |
| Client writes to a replicated table diverge it | v1 has no per-table authorization. Documented; a read-only listener mode is a follow-up. |
| Snapshot `RELOAD` is unavailable on some managed MySQL | v1 refuses to start rather than taking a racy snapshot. An idempotent-overlap mode is a follow-up. |
| The plugin now links `libmariadbclient` | Needed because the core does not export `mariadb_rpl_*`; verify the package on each platform. |

## 12. Commands

```bash
# build (from the worktree root)
PROXYSQL40=1 make

# unit test
make -C test/tap/tests/unit duckdb_replica_unit-t
./test/tap/tests/unit/duckdb_replica_unit-t

# syntax check used during development (headers extracted from deps)
g++ -std=c++17 -fsyntax-only -Iplugins/duckdb/include -I/tmp/opencode/duckdbinc \
  -I/tmp/opencode/mdbinc plugins/duckdb/src/duckdb_replica_binlog.cpp
```

The dependency headers are not extracted in a clean checkout. `make` extracts
them; the `/tmp/opencode/*` paths above are only the local scratch copies used
for the compile check.

## 13. Handoff checklist

- [x] Dedicated branch and worktree
- [x] Admin tables, commands, stats projection
- [x] Source prerequisite checks
- [x] Consistent snapshot with GTID position
- [x] Binlog dump and batched apply
- [x] Position committed with the batch
- [x] DDL stops the replica
- [x] Type mapping and value literals
- [x] Unit test for pure logic
- [ ] Live MySQL 8.4 end-to-end test
- [ ] Query-rule destination
- [ ] MySQL translator
