# DuckDB MySQL Replica — Design and Handoff

Date: 2026-11-05
Status: applier, core SELECT compatibility, storage hardening and process-crash recovery validated; internal routing deferred
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
  tables recorded in the persisted ownership manifest, `proxysql_replica.tables`,
  and `proxysql_replica.position` in one DuckDB transaction. Editable Main
  configuration does not determine ownership. Unrelated tables survive. Any
  DROP/commit failure returns an error and rolls back storage; published status
  clears only after successful commit.

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
5. Begin one DuckDB transaction. For each opted-in table: map
   `information_schema.COLUMNS`, create the DuckDB table, stream rows through
   `duckdb_appender`, flush every 1000 rows.
6. In the same transaction: insert `proxysql_replica.tables` metadata, insert
   `proxysql_replica.position`, commit.

If the position row exists, the snapshot is skipped (`already_loaded`). A
crash before the position commit leaves no position; the next start drops the
partial tables and snapshots again. An ordinary failure rolls back DuckDB
DDL, data and metadata together; it never issues further DROP statements
after rollback. The MySQL read transaction stays open for the whole copy and
is committed after the DuckDB commit.

Snapshot, apply and RESET fully qualify targets with the actual catalog from
their own DuckDB connection, including appender creation and metadata
introspection. A catalog matching the source schema or `proxysql_replica` is
supported. Native client SQL may still require three-part names when a
catalog and schema collide; SELECT compatibility does not rewrite namespaces.

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

- The PROXYSQL40 core, DuckDB plugin, replica TAP test and nine DuckDB unit
  binaries build and link.
- The live replica TAP scenario passes **31 assertions**, separately with
  `binlog_checksum=NONE` and `binlog_checksum=CRC32`.
- The separate recovery TAP scenario passes **19 assertions** with each
  checksum mode. It owns its ProxySQL process and uses SIGKILL, including
  while snapshot rows are uncommitted and while a large transaction is being
  caught up. Startup with replication disabled exposes the recovered data
  and checkpoint before further apply can hide a partial commit.
- Concurrent snapshot coverage commits insert/update/delete in one source
  transaction across a table already being copied and a later table. It
  requires positive copy progress and snapshotting state after COMMIT, then
  compares every row and the exact file/position/GTID after catch-up.
- Recovery includes an incomplete snapshot restarted from scratch, offline
  commits and a rolled-back source transaction. Revoking the fixture account's
  RELOAD privilege proves a committed checkpoint resumes without silently
  resnapshotting. Temporary mutations omitting the consistent source
  transaction and ignoring the durable checkpoint fail the intended checks.
- The opt-in replica load harness passes **11 assertions** per enabled run,
  with three repeats each at 100 and 1,000 requested changed data rows/s.
  Exact row/coordinate audits pass after every phase; a stopped applier
  fails the marker deadline. Recovery still passes **19 assertions** after
  extracting the common fixture. See the
  [measured baseline](../benchmarks/2026-11-05-duckdb-replica-load.md).
- The nine DuckDB unit binaries pass **371 assertions** in total, including
  **61** in `duckdb_replica_unit-t`, **16** in
  `duckdb_replica_storage_unit-t`, and **53** in the SELECT translator unit.
- Existing Admin-table TAP coverage passes 22 assertions; the MySQL listener
  TAP test passes 17. The PostgreSQL listener TAP test still fails assertions
  19..24 (extended-query rejection). The same six failures reproduce with
  the plugin built from base revision `e2f317aba`; they predate this work.
- Live coverage includes typed snapshot and DML, multi-row UPDATE pairing,
  primary-key changes, rollback, filtering an unrelated JSON table, binlog
  rotation, source file/position/GTID agreement, committed Admin statistics,
  automatic restart without duplicates, continued apply, sticky DDL error
  with an unchanged checkpoint, RESET/resnapshot, and rejection of a partial
  UPDATE after image with a full before image. It also covers colliding
  catalog/schema names, failed RESET preserving durable and published
  checkpoints, retry after removing a foreign-key dependency, manifest
  ownership after configuration edits, and failed-snapshot rollback
  preserving an unrelated inactive table.
- The opt-in SELECT compatibility differential test passes **39 assertions**
  against MySQL, direct DuckDB and ordinary same-instance hostgroup routing.
- Config and snapshot reject case variants of the reserved metadata schema
  before storage/source access. Quoted identifiers, metadata catalog-name
  collisions, missing targets and fresh RESET idempotence have storage coverage.
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

This is functional validation of the tested source and types, including
Linux process-crash recovery. Power loss/torn writes, exact interruption
inside DuckDB COMMIT, broader/long-running load tests and platform packaging
validation remain outstanding. A first update-heavy load baseline is now
measured; see section 10.5. Catalog/schema collisions
are covered by storage tests and the live scenario, whose database filename now matches the
source schema.

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
a prerequisite for the work below. The compatibility differential test
validates this topology through the regular ProxySQL listener, including
backend authentication and session setup.

1. **Further applier hardening.** Catalog qualification, transactional
   manifest-owned RESET, and failed-snapshot rollback safety are implemented.
   Process-crash recovery and concurrent writes during snapshot are now
   validated. A first load baseline is measured in section 10.5. Next:
   add read-only protection, profile/optimize apply throughput, broaden
   workload coverage, and validate platform packaging.
2. **MySQL analytical compatibility.** The opt-in core SELECT pass is
   implemented and differential-tested through direct and ordinary backend
   routing. Expand the bounded subset as needed; see
   `2026-11-05-duckdb-mysql-select-compatibility-design.md`.
3. **Typed results and prepared statements** on the DuckDB MySQL listener,
   carried through ordinary backend routing.
4. **Bulk load** (`LOAD DATA LOCAL INFILE`, `COPY FROM STDIN`).
5. **Postgres logical replication** into the same engine.

### 10.4 Process crash and snapshot concurrency (completed)

`test/tap/tests/test_duckdb_replica_recovery-t.cpp` runs in `duckdb-e2e-g1`
against its own child ProxySQL, private temporary data directory and dynamic
loopback ports. It never kills or reconfigures the group's normal server.
A 200,000-row InnoDB table makes copy progress observable; missed overlap
windows fail explicitly. SIGKILL bypasses graceful replica flushing.

The fixture bootstraps custom DuckDB variables in Disk before enabling the
plugin, then reuses those files through each crash. A disabled startup lets
it inspect an interrupted snapshot (no visible partial tables/metadata) and
an interrupted apply (complete old or complete new rows with the matching
checkpoint). Subsequent START must converge exactly with the source.

The test uses administrative `TAP_MYSQL*` credentials to create its own
schema/account and grant/revoke privileges; account setup is excluded from
the workload binlog with session `sql_log_bin=0`. This adds no production
replica privilege requirement. On normal exit it reaps its child and removes
only its own source objects and files; failed runs retain their logs. On
Linux, parent-death SIGKILL prevents an abruptly killed TAP runner from
leaving its ProxySQL child alive, including the fork/registration race.

The test observes active catch-up and validates atomic recovery; it does not
pin the kill to a specific instruction inside DuckDB COMMIT or simulate
power loss. Linux is the platform validated so far.

### 10.5 Load characterization (first baseline completed)

`test_duckdb_replica_bench-t` is opt-in through
`RUN_DUCKDB_REPLICA_BENCH=1`; default runs skip before creating resources.
It reuses the isolated recovery fixture, times a 200,001-row snapshot, then
runs paced writes without and with two aggregate readers, followed by a
5,000-row source transaction. Distinct replicated transaction markers
measure observed commit-to-visible latency, including coalesced apply
batches. Full row and coordinate audits happen outside timed intervals.

On the measured shared Linux host, six runs gave a median snapshot time of
about 1.79 s. With 1,000 requested changed data rows/s, completion throughput
was about 485 rows/s without readers and 456 rows/s with two readers,
accumulating seconds of backlog. At 100 requested rows/s, median visibility
latency was about 0.3 s and per-run p99 about 1.3 s. These are workload/host
observations, not capacity or latency guarantees. The
[report and raw results](../benchmarks/2026-11-05-duckdb-replica-load.md)
record source flush settings, sample intervals, marker overhead and cache
history limits. Broader workloads and long-duration memory behavior remain
unmeasured. The current per-row SQL execution path is a candidate for
profiling before choosing an optimization.

## 11. Known risks

| Risk | Handling |
|---|---|
| `STOP` can block up to the 5 s dump read timeout, longer on the snapshot lock | `STOP` releases the Admin mutex during the join; documented. |
| SQL-literal apply is slower than bound parameters | Acceptable for v1; measure before optimizing. |
| Client writes to a replicated table diverge it | v1 has no per-table authorization. Documented; a read-only listener mode is a follow-up. |
| Snapshot `RELOAD` is unavailable on some managed MySQL | v1 refuses to start rather than taking a racy snapshot. An idempotent-overlap mode is a follow-up. |
| The plugin now links `libmariadbclient` | Needed because the core does not export `mariadb_rpl_*`; verify the package on each platform. |

The earlier claim that the connector has a known truncation defect above
4 GB was unsupported and has been withdrawn. MySQL's
[`max_binlog_size`](https://dev.mysql.com/doc/refman/9.7/en/replication-options-binary-log.html#sysvar_max_binlog_size)
has a maximum/default of 1 GiB. A single transaction can exceed that rotation
threshold, but no truncation failure has been reproduced here. The connector's
32-bit event-position field alone does not establish a bug; inspecting raw
headers would not widen the four-byte field it already decodes. Oversized
transactions belong in workload characterization, not a claimed known-defect
priority.

## 12. Commands

```bash
# build (from the worktree root)
PROXYSQL40=1 make

# replica unit tests
make -C test/tap/tests/unit duckdb_replica_unit-t duckdb_replica_storage_unit-t
./test/tap/tests/unit/duckdb_replica_unit-t
./test/tap/tests/unit/duckdb_replica_storage_unit-t

# live test (dedicated source; restarts ProxySQL during the test)
make -C test/tap/tests test_duckdb_replica-t
# Supply the standard TAP_* listener and TAP_MYSQL* source credentials.
./test/tap/tests/test_duckdb_replica-t

# isolated SIGKILL/concurrent-snapshot scenario (administrative source credentials)
make -C test/tap/tests test_duckdb_replica_recovery-t
./test/tap/tests/test_duckdb_replica_recovery-t
# Optional path overrides: TAP_PROXYSQL_BINARY and TAP_DUCKDB_PLUGIN.

# opt-in load characterization (same dedicated administrative TAP_MYSQL* source)
make -C test/tap/tests test_duckdb_replica_bench-t
RUN_DUCKDB_REPLICA_BENCH=1 ./test/tap/tests/test_duckdb_replica_bench-t

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
- [x] Catalog qualification, atomic manifest-owned RESET and rollback safety
- [x] SIGKILL recovery and concurrent writes during snapshot (NONE and CRC32)
- [x] First replica load baseline (snapshot, paced updates, reader concurrency, lag and RSS)
- [ ] Further applier hardening (read-only protection, apply performance, broader load, packaging)
- [x] Core MySQL analytical SELECT compatibility (opt-in)
- [ ] Internal query-rule destination (deferred indefinitely)
