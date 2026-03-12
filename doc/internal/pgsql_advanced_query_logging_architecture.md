# PostgreSQL Advanced Query Logging Architecture

## Document Status
- Status: Implemented (as-built)
- Scope: PostgreSQL advanced events logging parity with MySQL, including buffer, SQLite sinks, dump commands, scheduler sync, and metrics
- Branch: `v3.0_pgsql_advanced_logging`

## 1. Objective and Delivered Outcome
The PostgreSQL logging pipeline now supports advanced query events logging with the same operational model already used by MySQL:
- query event capture at request completion
- in-memory circular buffering
- manual dump from buffer to `stats` and/or `stats_history`
- optional periodic auto-dump to disk
- logger metrics in `stats_pgsql_global` and Prometheus

This implementation is additive. Existing PostgreSQL file-based events log and audit log behavior remains available.

## 2. As-Built Runtime Architecture

### 2.1 Capture path
1. PostgreSQL sessions call query logging at request completion.
2. `PgSQL_Logger::log_request()` builds a `PgSQL_Event` from session/backend state.
3. If file logging is enabled, the event is written to events log file.
4. If `pgsql-eventslog_buffer_history_size > 0`, the event is deep-copied and inserted into the PostgreSQL events circular buffer.

Implemented in:
- `lib/PgSQL_Logger.cpp`
- `include/PgSQL_Logger.hpp`

### 2.2 Buffering model
A dedicated `PgSQL_Logger_CircularBuffer` provides:
- thread-safe insertion/drain using mutex
- bounded size via runtime variable
- event drop accounting when the buffer is full or resized smaller

Runtime resizing is wired in PostgreSQL thread variable refresh:
- `PgSQL_Thread::refresh_variables()` applies `eventslog_buffer_history_size` changes to the live circular buffer.

Implemented in:
- `include/PgSQL_Logger.hpp`
- `lib/PgSQL_Logger.cpp`
- `lib/PgSQL_Thread.cpp`

### 2.3 Drain and persistence pipeline
`PgSQL_Logger::processEvents(SQLite3DB* statsdb, SQLite3DB* statsdb_disk)` drains the buffer and persists events to:
- memory table: `stats_pgsql_query_events` when `statsdb != nullptr`
- disk table: `history_pgsql_query_events` when `statsdb_disk != nullptr`

Behavior:
- batched SQLite inserts with prepared statements
- in-memory retention bound by `pgsql-eventslog_table_memory_size`
- query digest serialized as hex text (`0x...`), matching MySQL table style
- `sqlstate` and textual `error` persisted for failed queries

Implemented in:
- `lib/PgSQL_Logger.cpp`

## 3. Data Model

### 3.1 Memory table
`stats.stats_pgsql_query_events`

Columns:
- `id`
- `thread_id`
- `username`
- `database`
- `start_time`
- `end_time`
- `query_digest`
- `query`
- `server`
- `client`
- `event_type`
- `hid`
- `extra_info`
- `affected_rows`
- `rows_sent`
- `client_stmt_name`
- `sqlstate`
- `error`

Implemented in:
- `include/ProxySQL_Admin_Tables_Definitions.h`
- `lib/Admin_Bootstrap.cpp`

### 3.2 Disk history table
`stats_history.history_pgsql_query_events`

Columns match `stats_pgsql_query_events`.

Indexes:
- `idx_history_pgsql_query_events_start_time` on `start_time`
- `idx_history_pgsql_query_events_query_digest` on `query_digest`

Implemented in:
- `include/ProxySQL_Statistics.hpp`
- `lib/ProxySQL_Statistics.cpp`

## 4. Admin Interface and Control Surface

### 4.1 Dump commands
PostgreSQL-specific dump commands are now available:
- `DUMP PGSQL EVENTSLOG FROM BUFFER TO MEMORY`
- `DUMP PGSQL EVENTSLOG FROM BUFFER TO DISK`
- `DUMP PGSQL EVENTSLOG FROM BUFFER TO BOTH`

Command handling executes `GloPgSQL_Logger->processEvents(...)` with the selected sink targets.

These commands are exposed by the shared Admin module and are available from both Admin protocol endpoints:
- MySQL protocol on port `6032`
- PostgreSQL protocol on port `6132`

Implemented in:
- `lib/Admin_Handler.cpp`

### 4.2 Runtime/config variables
PostgreSQL thread variables used by advanced logging:
- `pgsql-eventslog_buffer_history_size`
- `pgsql-eventslog_table_memory_size`
- `pgsql-eventslog_buffer_max_query_length`

Admin scheduling variable:
- `admin-stats_pgsql_eventslog_sync_buffer_to_disk`

Implemented in:
- `include/PgSQL_Thread.h`
- `include/proxysql_structs.h`
- `include/proxysql_admin.h`
- `lib/ProxySQL_Admin.cpp`

## 5. Scheduler Integration

### 5.1 PostgreSQL auto-dump to disk
Admin main loop now periodically flushes PostgreSQL buffered events to `history_pgsql_query_events` when:
- `stats_pgsql_eventslog_sync_buffer_to_disk > 0`
- timer interval is elapsed

### 5.2 MySQL symmetry fix
The same scheduler loop now also invokes MySQL buffered events dump to disk based on `stats_mysql_eventslog_sync_buffer_to_disk`, ensuring symmetric behavior across both protocols.

Implemented in:
- `lib/ProxySQL_Admin.cpp`

## 6. Metrics Architecture

### 6.1 Logger internal metrics
PostgreSQL logger tracks:
- memory/disk copy counts
- total copy time (memory/disk)
- get-all-events calls/time/count
- total events copied (memory/disk)
- circular buffer added/dropped totals
- circular buffer current size

Implemented in:
- `include/PgSQL_Logger.hpp`
- `lib/PgSQL_Logger.cpp`

### 6.2 Stats table exposure
Metrics are exported to `stats_pgsql_global` with `PgSQL_Logger_` prefix.

Implemented in:
- `lib/ProxySQL_Admin_Stats.cpp`

### 6.3 Prometheus exposure
Prometheus metric family `proxysql_pgsql_logger_*` is exposed through the serial metrics updater path.

Implemented in:
- `lib/PgSQL_Logger.cpp`
- `lib/ProxySQL_Admin.cpp`

## 7. Compatibility and Semantics
- Existing `DUMP EVENTSLOG ...` remains MySQL behavior for compatibility.
- New PostgreSQL syntax is explicit: `DUMP PGSQL EVENTSLOG ...`.
- PostgreSQL event error fields use `sqlstate + error` (textual message).
- PostgreSQL event table uses `database` column naming.

## 8. Code Touchpoint Summary
- Logger core:
  - `include/PgSQL_Logger.hpp`
  - `lib/PgSQL_Logger.cpp`
- Thread/runtime integration:
  - `lib/PgSQL_Thread.cpp`
- Admin commands and scheduler:
  - `lib/Admin_Handler.cpp`
  - `lib/ProxySQL_Admin.cpp`
- Table definitions/bootstrap:
  - `include/ProxySQL_Admin_Tables_Definitions.h`
  - `include/ProxySQL_Statistics.hpp`
  - `lib/Admin_Bootstrap.cpp`
  - `lib/ProxySQL_Statistics.cpp`
- Stats/Prometheus metrics:
  - `lib/ProxySQL_Admin_Stats.cpp`

## 9. Validation and Acceptance Mapping
Implemented acceptance validation via TAP test:
- `test/tap/tests/pgsql_query_logging_memory-t.cpp`
- `test/tap/tests/pgsql_query_logging_autodump-t.cpp`

Coverage:
- table schema shape validation (`stats_pgsql_query_events`, `history_pgsql_query_events`)
- buffer dump command execution
- success/error event accounting in memory and history tables
- `sqlstate` capture for representative PostgreSQL errors
- non-empty textual `error` capture for error rows
- scheduler-driven periodic dump to `history_pgsql_query_events` via `admin-stats_pgsql_eventslog_sync_buffer_to_disk`

TAP group registration:
- `test/tap/groups/groups.json` (`pgsql_query_logging_memory-t`, `pgsql_query_logging_autodump-t`)
