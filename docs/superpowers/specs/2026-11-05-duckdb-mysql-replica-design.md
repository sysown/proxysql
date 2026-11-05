# DuckDB MySQL Replica — Design and Handoff

Date: 2026-11-05
Status: applier live-validated; compatibility and hardening next; internal routing deferred
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

This document covers **sub-project 1: the MySQL replica applier**. Existing
query rules can route analytical reads to a backend hostgroup pointing to the
same ProxySQL instance's DuckDB MySQL listener on a different port. A dedicated
internal query-rule destination and automatic lag-aware fallback are deferred
and may never be needed. MySQL dialect compatibility and further applier
hardening are the next workstreams listed in section 10.

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
`error`. `error` is sticky until `STOP`. On ProxySQL startup, an enabled source
restored from Disk starts automatically and resumes its durable position.

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

The applier additionally re-checks both UPDATE row-image bitmaps (and the
single INSERT/DELETE bitmap), because
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
- `UPDATE_ROWS` yields before/after pairs in that order, confirmed by the live
  multi-row primary-key-changing UPDATE test.
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
| `test/tap/tests/unit/duckdb_replica_unit-t.cpp` | Type mapping, literals, GTID, lifecycle, decoder regressions |
| `test/tap/tests/test_duckdb_replica-t.cpp` | Live MySQL 8.4 snapshot, apply, rotation, restart and failure recovery |
| `deps/mariadb-client-library/mariadb_rpl_rows.patch` | Connector row decoding and ROTATE fixes |

Wiring: `duckdb_plugin.cpp` registers the replica admin schema, installs the
config at start, joins the replica in `stop()` before the engine closes, and
reports the replica state in `status_json`.

Build: `plugins/duckdb/Makefile` adds the new sources and links
`-L$(MARIADB_LDIR) -lmariadbclient` (the core does not export
`mariadb_rpl_*`; `--gc-sections` drops it from the executable).

## 9. Validation status

Validated on 2026-11-05 against a dedicated MySQL **8.4.8** InnoDB source
and the real DuckDB **1.4.5** / MariaDB Connector/C **3.3.8** libraries:

- The PROXYSQL40 core, DuckDB plugin, replica TAP test and seven DuckDB unit
  binaries build and link.
- The live replica TAP scenario passes **24 assertions**, separately with
  `binlog_checksum=NONE` and `binlog_checksum=CRC32`.
- The seven DuckDB unit binaries pass **290 assertions** in total, including
  **55** in `duckdb_replica_unit-t`.
- Existing Admin-table TAP coverage passes 22 assertions; the MySQL listener
  TAP test passes 17. The PostgreSQL listener TAP test still fails assertions
  19..24 (extended-query rejection). The same six failures reproduce with
  the plugin built from base revision `e2f317aba`; they predate this work.
- Live coverage includes typed snapshot and DML, multi-row UPDATE pairing,
  primary-key changes, rollback, filtering an unrelated JSON table, binlog
  rotation, source file/position/GTID agreement, committed Admin statistics,
  automatic restart without duplicates, continued apply, sticky DDL error
  with an unchanged checkpoint, RESET/resnapshot, and rejection of a partial
  UPDATE after image with a full before image.
- Decoder regressions cover every TIMESTAMP2 fractional precision (0..6),
  negative DECIMAL groups, and YEAR zero. Existing mapping, literal, GTID and
  lifecycle coverage remains in place.

The live run forced fixes for bitmap padding, heartbeat v2, signed integers,
checksum negotiation, committed statistics and automatic startup. The
connector patch fixes TIMESTAMP2 byte order/fractional widths, UPDATE v2's
second bitmap, signed three-byte decimal groups, YEAR zero, and checksum-aware
ROTATE filename lengths. Both images are validated before connector decoding.
Unselected tables retain their TABLE_MAP even when their types are unsupported.
The existing listener/admin-schema unit targets now link the replica sources.

This is functional validation of the tested source and types; crash injection,
large positions above 4 GB, load/performance tests, and platform packaging
validation remain outstanding. A source schema matching the DuckDB file's
catalog name can trigger DuckDB's two-part-name ambiguity; use a distinct
DuckDB database filename until qualification is hardened.

## 10. Next steps, in order

### 10.1 End-to-end replica test (completed)

Implemented `test/tap/tests/test_duckdb_replica-t.cpp` in `duckdb-e2e-g1`.
The group now provisions `infra-dbdeployer-mysql84-binlog`:

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

### 10.2 Decoder and position assumptions (resolved for tested cases)

- UPDATE before/after ordering and primary-key changes pass live validation.
- ROTATE is tested with both NONE and CRC32 checksums, followed by restart
  from the new file's durable position.
- TIMESTAMP2 is rendered by the patched connector as seconds plus six-digit
  microseconds; precision 0..6 has direct decoder tests.
- `binlog_row_metadata=FULL` is not required for the supported type subset:
  signedness comes from snapshot column types, and ENUM/SET remain rejected.

### 10.3 Next workstreams

Routing decision (2026-11-05): use regular `mysql_servers` hostgroups and query
rules to target this instance's DuckDB MySQL listener. Internal query-rule
routing with automatic lag-aware fallback is deferred indefinitely; it is not
a prerequisite for the work below. This topology still needs an integration
check through the regular ProxySQL listener, including backend authentication
and session setup.

1. **Applier hardening.** Fix catalog/schema-name ambiguity; test abrupt crash
   recovery and concurrent writes during snapshot; validate large positions,
   read-only protection, performance, and platform packaging.
2. **MySQL analytical compatibility.** Define and implement a bounded
   `SELECT` subset on the DuckDB listener, with explicit errors for unsupported
   statements. The initial workload still needs to be selected.
3. **Typed results and prepared statements** on the DuckDB MySQL listener,
   carried through ordinary backend routing.
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

# replica unit test
make -C test/tap/tests/unit duckdb_replica_unit-t
./test/tap/tests/unit/duckdb_replica_unit-t

# live test (dedicated source; restarts ProxySQL during the test)
make -C test/tap/tests test_duckdb_replica-t
# Supply the standard TAP_* listener and TAP_MYSQL* source credentials.
./test/tap/tests/test_duckdb_replica-t

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
- [x] Live MySQL 8.4 end-to-end test (NONE and CRC32 checksums)
- [ ] Applier hardening
- [ ] MySQL compatibility
- [ ] Internal query-rule destination (deferred indefinitely)
