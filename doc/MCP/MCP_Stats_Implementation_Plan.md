# ProxySQL Stats MCP Tools - Implementation Guide

This document provides implementation guidance for the `/stats` endpoint tools, including database access patterns, table mappings, SQL queries, data flow documentation, and design rationale.

## Table of Contents

- [1. Database Access Patterns](#1-database-access-patterns)
- [2. Table-to-Tool Mapping](#2-table-to-tool-mapping)
- [3. Data Flow Patterns](#3-data-flow-patterns)
- [4. Interval-to-Table Resolution](#4-interval-to-table-resolution)
- [5. Tool Implementation Details](#5-tool-implementation-details)
- [6. Helper Functions](#6-helper-functions)
- [7. Error Handling Patterns](#7-error-handling-patterns)
- [8. Testing Strategies](#8-testing-strategies)

---

## 1. Database Access Patterns

### 1.1 Database Types

ProxySQL maintains several SQLite databases:

| Database | Variable | Purpose | Schema Prefix |
|---|---|---|---|
| `admindb` | `GloAdmin->admindb` | Configuration and admin interface | (none) |
| `statsdb` | `GloAdmin->statsdb` | In-memory real-time statistics | `stats.` |
| `statsdb_disk` | `GloAdmin->statsdb_disk` | Persistent historical statistics | `stats_history.` |
| `statsdb_mem` | Internal | Internal metrics collection | N/A (not directly accessible) |

### 1.2 Access Rules

**Real-time stats tables:** Access through `GloAdmin->admindb` with the `stats.` schema prefix.

```cpp
// Example: Query stats_mysql_connection_pool
GloAdmin->admindb->execute_statement(
    "SELECT * FROM stats.stats_mysql_connection_pool",
    &error, &cols, &affected_rows, &resultset
);
```

**Historical data tables:** Access through `GloAdmin->statsdb_disk` directly (no prefix needed as it's the default schema).

```cpp
// Example: Query mysql_connections history (direct access - preferred)
GloAdmin->statsdb_disk->execute_statement(
    "SELECT * FROM mysql_connections WHERE timestamp > ?",
    &error, &cols, &affected_rows, &resultset
);
```

Alternatively, historical tables can be accessed through `GloAdmin->admindb` using the `stats_history.` prefix, as `statsdb_disk` is attached to both databases:

```cpp
// Example: Query mysql_connections history (via admindb with prefix)
GloAdmin->admindb->execute_statement(
    "SELECT * FROM stats_history.mysql_connections WHERE timestamp > ?",
    &error, &cols, &affected_rows, &resultset
);
```

Direct access via `statsdb_disk` is preferred for performance.

**Never use `GloAdmin->statsdb` directly** — it's for internal ProxySQL use only.

### 1.3 Admin Commands vs. Direct Function Calls

Some ProxySQL operations are exposed as admin commands (e.g., `DUMP EVENTSLOG FROM BUFFER TO MEMORY`, `SAVE MYSQL DIGEST TO DISK`). These commands are intercepted by `Admin_Handler.cpp` when received via the MySQL admin interface and routed to the appropriate C++ functions.

When implementing MCP tools, these admin commands cannot be executed via `admindb->execute_statement()` because SQLite doesn't recognize them as valid SQL. Instead, call the underlying C++ functions directly:

| Admin Command | Direct Function Call | Returns |
|---------------|---------------------|---------|
| `DUMP EVENTSLOG FROM BUFFER TO MEMORY` | `GloMyLogger->processEvents(statsdb, nullptr)` | Event count |
| `DUMP EVENTSLOG FROM BUFFER TO DISK` | `GloMyLogger->processEvents(nullptr, statsdb_disk)` | Event count |
| `DUMP EVENTSLOG FROM BUFFER TO BOTH` | `GloMyLogger->processEvents(statsdb, statsdb_disk)` | Event count |
| `SAVE MYSQL DIGEST TO DISK` | `GloAdmin->FlushDigestTableToDisk<SERVER_TYPE_MYSQL>(statsdb_disk)` | Digest count |
| `SAVE PGSQL DIGEST TO DISK` | `GloAdmin->FlushDigestTableToDisk<SERVER_TYPE_PGSQL>(statsdb_disk)` | Digest count |

Both functions are thread-safe:
- `processEvents()` uses `std::mutex` internally for the circular buffer
- `FlushDigestTableToDisk()` uses `pthread_rwlock` for the digest hash map

Required includes for these functions:
```cpp
#include "proxysql_admin.h"
#include "MySQL_Logger.hpp"

extern MySQL_Logger *GloMyLogger;
```

### 1.4 Query Execution Pattern

```cpp
json Stats_Tool_Handler::execute_query(const std::string& sql, SQLite3DB* db) {
    SQLite3_result* resultset = NULL;
    char* error = NULL;
    int cols = 0;
    int affected_rows = 0;

    int rc = db->execute_statement(sql.c_str(), &error, &cols, &affected_rows, &resultset);

    if (rc != SQLITE_OK) {
        std::string err_msg = error ? error : "Query execution failed";
        if (error) free(error);
        return create_error_response(err_msg);
    }

    json rows = resultset_to_json(resultset, cols);
    delete resultset;

    return rows;
}
```

---

## 2. Table-to-Tool Mapping

### 2.1 Live Data Tools

| Tool | MySQL Tables | PostgreSQL Tables |
|---|---|---|
| `show_status` | `stats.stats_mysql_global`, `stats.stats_memory_metrics` | `stats.stats_pgsql_global`, `stats.stats_memory_metrics` |
| `show_processlist` | `stats.stats_mysql_processlist` | `stats.stats_pgsql_processlist` |
| `show_queries` | `stats.stats_mysql_query_digest` | `stats.stats_pgsql_query_digest` |
| `show_commands` | `stats.stats_mysql_commands_counters` | `stats.stats_pgsql_commands_counters` |
| `show_connections` | `stats.stats_mysql_connection_pool`, `stats.stats_mysql_free_connections` | `stats.stats_pgsql_connection_pool`, `stats.stats_pgsql_free_connections` |
| `show_errors` | `stats.stats_mysql_errors` | `stats.stats_pgsql_errors` (uses `sqlstate` instead of `errno`) |
| `show_users` | `stats.stats_mysql_users` | `stats.stats_pgsql_users` |
| `show_client_cache` | `stats.stats_mysql_client_host_cache` | `stats.stats_pgsql_client_host_cache` |
| `show_query_rules` | `stats.stats_mysql_query_rules` | `stats.stats_pgsql_query_rules` |
| `show_prepared_statements` | `stats.stats_mysql_prepared_statements_info` | `stats.stats_pgsql_prepared_statements_info` |
| `show_gtid` | `stats.stats_mysql_gtid_executed` | N/A |
| `show_cluster` | `stats.stats_proxysql_servers_status`, `stats.stats_proxysql_servers_metrics`, `stats.stats_proxysql_servers_checksums`, `stats.stats_proxysql_servers_clients_status` | Same (shared) |

### 2.2 Historical Data Tools

| Tool | MySQL Tables | PostgreSQL Tables |
|---|---|---|
| `show_system_history` | `system_cpu`, `system_cpu_hour`, `system_memory`, `system_memory_hour` | Same (shared) |
| `show_query_cache_history` | `mysql_query_cache`, `mysql_query_cache_hour` | N/A |
| `show_connection_history` | `mysql_connections`, `mysql_connections_hour`, `myhgm_connections`, `myhgm_connections_hour`, `history_stats_mysql_connection_pool` | N/A |
| `show_query_history` | `history_mysql_query_digest` | `history_pgsql_query_digest` |

### 2.3 Utility Tools

| Tool | MySQL Tables | PostgreSQL Tables |
|---|---|---|
| `flush_query_log` | `stats.stats_mysql_query_events`, `history_mysql_query_events` | N/A |
| `show_query_log` | `stats.stats_mysql_query_events`, `history_mysql_query_events` | N/A |
| `flush_queries` | `history_mysql_query_digest` | `history_pgsql_query_digest` |

### 2.4 Column Naming: MySQL vs PostgreSQL

ProxySQL uses different column names for the same concept between MySQL and PostgreSQL:

| Concept | MySQL Column | PostgreSQL Column | API Field |
|---------|--------------|-------------------|-----------|
| Database/Schema | `schemaname` | `database` | `database` |
| Error Code | `errno` | `sqlstate` | `errno`/`sqlstate` |
| Process DB | `db` | `database` | `database` |

**Implementation Note:** The history table `history_pgsql_query_digest` uses `schemaname` (matching MySQL convention) rather than `database`, creating an inconsistency with the live `stats_pgsql_query_digest` table. Implementation must handle this when building queries for PostgreSQL.

---

## 3. Data Flow Patterns

### 3.1 Query Events Flow

Query events use a circular buffer that must be explicitly flushed to tables.

```text
┌─────────────────────────────────────────────────────────────────┐
│                     Query Execution                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              MySQL_Logger::log_request()                         │
│              Creates MySQL_Event, adds to circular buffer        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Circular Buffer (MyLogCB)                           │
│              Size controlled by eventslog_table_memory_size      │
│              Events accumulate until flushed                     │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
    DUMP TO MEMORY    DUMP TO DISK    DUMP TO BOTH
              │               │               │
              ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ stats_mysql_    │ │ history_mysql_  │ │     Both        │
│ query_events    │ │ query_events    │ │    tables       │
│ (in-memory,     │ │ (on-disk,       │ │                 │
│  capped size)   │ │  append-only)   │ │                 │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

**Implementation for `flush_query_log`:**

This tool calls `GloMyLogger->processEvents()` directly (see [Section 1.3](#13-admin-commands-vs-direct-function-calls)).

```cpp
json Stats_Tool_Handler::handle_flush_query_log(const json& arguments) {
    std::string destination = arguments.value("destination", "memory");

    if (destination != "memory" && destination != "disk" && destination != "both") {
        return create_error_response("Invalid destination");
    }

    if (!GloMyLogger || !GloAdmin) {
        return create_error_response("Required components not available");
    }

    SQLite3DB* statsdb = nullptr;
    SQLite3DB* statsdb_disk = nullptr;

    if (destination == "memory" || destination == "both") {
        statsdb = GloAdmin->statsdb;
    }
    if (destination == "disk" || destination == "both") {
        statsdb_disk = GloAdmin->statsdb_disk;
    }

    int events_flushed = GloMyLogger->processEvents(statsdb, statsdb_disk);

    json result;
    result["events_flushed"] = events_flushed;
    result["destination"] = destination;
    return create_success_response(result);
}
```

### 3.2 Query Digest Flow

Query digest statistics are maintained in an in-memory hash map, not SQLite.

```text
┌─────────────────────────────────────────────────────────────────┐
│                     Query Completes                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Query_Processor::update_query_digest()              │
│              Updates digest_umap (hash map in memory)            │
│              Aggregates: count_star, sum_time, min/max, rows     │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┴─────────────────────┐
        │                                           │
   SELECT query                           SAVE TO DISK
   (non-destructive)                      (destructive)
        │                                           │
        ▼                                           ▼
┌─────────────────────────┐         ┌─────────────────────────────┐
│ get_query_digests_v2()  │         │ FlushDigestTableToDisk()    │
│ - Swap map with empty   │         │ - get_query_digests_reset() │
│ - Serialize to SQLite   │         │ - Atomic swap (empties map) │
│ - Merge back            │         │ - Write to history table    │
│ - Data preserved        │         │ - Delete swapped data       │
└─────────────────────────┘         │ - Map starts fresh          │
                                    └─────────────────────────────┘
```

**Key Implementation Notes:**

1. **Reading live data (`show_queries`):** Non-destructive. ProxySQL handles the swap-serialize-merge internally when you query `stats_mysql_query_digest`.

2. **Saving to history (`flush_queries`):** Destructive. The live map is emptied. This tool calls `FlushDigestTableToDisk()` directly (see [Section 1.3](#13-admin-commands-vs-direct-function-calls)).

```cpp
json Stats_Tool_Handler::handle_flush_queries(const json& arguments) {
    std::string db_type = arguments.value("db_type", "mysql");

    if (db_type != "mysql" && db_type != "pgsql") {
        return create_error_response("Invalid db_type");
    }

    if (!GloAdmin || !GloAdmin->statsdb_disk) {
        return create_error_response("Stats disk database not available");
    }

    int digests_saved;
    if (db_type == "mysql") {
        digests_saved = GloAdmin->FlushDigestTableToDisk<SERVER_TYPE_MYSQL>(GloAdmin->statsdb_disk);
    } else {
        digests_saved = GloAdmin->FlushDigestTableToDisk<SERVER_TYPE_PGSQL>(GloAdmin->statsdb_disk);
    }

    json result;
    result["db_type"] = db_type;
    result["digests_saved"] = digests_saved;
    result["dump_time"] = (long long)time(NULL);
    return create_success_response(result);
}
```

### 3.3 Historical Tables Flow

Historical tables are populated by periodic timers and aggregated into hourly tables.

```text
┌─────────────────────────────────────────────────────────────────┐
│              Admin Thread Timer Check                            │
│              (every poll cycle)                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              *_timetoget(curtime) returns true?                  │
│              (checks if interval has elapsed)                    │
└─────────────────────────────────────────────────────────────────┘
                              │ yes
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Collect current metrics                             │
│              (e.g., system_cpu from times())                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              INSERT INTO raw table                               │
│              (e.g., system_cpu)                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              Check if hourly aggregation needed                  │
│              (current time >= last_hour_entry + 3600)            │
└─────────────────────────────────────────────────────────────────┘
                              │ yes
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              INSERT INTO *_hour SELECT ... GROUP BY              │
│              (aggregation: SUM/AVG/MAX depending on column)      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              DELETE old data                                     │
│              - Raw: older than 7 days                            │
│              - Hourly: older than 365 days                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Interval-to-Table Resolution

Historical tools accept user-friendly interval parameters and automatically select the appropriate table.

### 4.1 Interval Mapping

| User Interval | Seconds | Table Type | Rationale |
|---|---|---|---|
| `30m` | 1800 | Raw | Fine-grained, small dataset |
| `1h` | 3600 | Raw | Fine-grained, small dataset |
| `2h` | 7200 | Raw | Fine-grained, moderate dataset |
| `4h` | 14400 | Raw | Raw data still manageable |
| `6h` | 21600 | Raw | Raw data still manageable |
| `8h` | 28800 | Hourly | Hourly aggregation preferred |
| `12h` | 43200 | Hourly | Hourly aggregation preferred |
| `1d` | 86400 | Hourly | Raw would have ~1440 rows, hourly has 24 |
| `3d` | 259200 | Hourly | Hourly aggregation more efficient |
| `7d` | 604800 | Hourly | Raw data may not exist (7-day retention) |
| `30d` | 2592000 | Hourly | Raw data doesn't exist this far back |
| `90d` | 7776000 | Hourly | Raw data doesn't exist this far back |

### 4.2 Implementation

```cpp
struct IntervalConfig {
    int seconds;
    bool use_hourly;
};

std::map<std::string, IntervalConfig> interval_map = {
    {"30m",  {1800, false}},
    {"1h",   {3600, false}},
    {"2h",   {7200, false}},
    {"4h",   {14400, false}},
    {"6h",   {21600, false}},
    {"8h",   {28800, true}},
    {"12h",  {43200, true}},
    {"1d",   {86400, true}},
    {"3d",   {259200, true}},
    {"7d",   {604800, true}},
    {"30d",  {2592000, true}},
    {"90d",  {7776000, true}}
};

std::string get_table_name(const std::string& base_table, const std::string& interval) {
    auto it = interval_map.find(interval);
    if (it == interval_map.end()) {
        return base_table; // Default to raw
    }

    if (it->second.use_hourly) {
        return base_table + "_hour";
    }
    return base_table;
}

std::string build_time_range_query(const std::string& table, int seconds) {
    time_t now = time(NULL);
    time_t start = now - seconds;

    return "SELECT * FROM " + table +
           " WHERE timestamp BETWEEN " + std::to_string(start) +
           " AND " + std::to_string(now) +
           " ORDER BY timestamp";
}
```

---

## 5. Tool Implementation Details

### 5.1 show_status

**Source Tables:**
- MySQL: `stats.stats_mysql_global`, `stats.stats_memory_metrics`
- PostgreSQL: `stats.stats_pgsql_global`, `stats.stats_memory_metrics`

**Category Mapping:**

```cpp
std::map<std::string, std::vector<std::string>> category_prefixes = {
    {"connections", {"Client_Connections_", "Server_Connections_", "Active_Transactions"}},
    {"queries", {"Questions", "Slow_queries", "GTID_", "Queries_", "Query_Processor_", "Backend_query_time_"}},
    {"commands", {"Com_"}},
    {"pool_ops", {"ConnPool_", "MyHGM_"}},
    {"monitor", {"MySQL_Monitor_", "PgSQL_Monitor_"}},
    {"query_cache", {"Query_Cache_"}},
    {"prepared_stmts", {"Stmt_"}},
    {"security", {"automatic_detected_sql_injection", "ai_", "mysql_whitelisted_"}},
    {"memory", {"_buffers_bytes", "_internal_bytes", "SQLite3_memory_bytes", "ConnPool_memory_bytes",
                "jemalloc_", "Auth_memory", "query_digest_memory", "query_rules_memory",
                "prepare_statement_", "firewall_", "stack_memory_"}},
    {"errors", {"generated_error_packets", "Access_Denied_", "client_host_error_", "mysql_unexpected_"}},
    {"logger", {"MySQL_Logger_"}},
    {"system", {"ProxySQL_Uptime", "MySQL_Thread_Workers", "PgSQL_Thread_Workers",
                "Servers_table_version", "mysql_listener_paused", "pgsql_listener_paused", "OpenSSL_"}},
    {"mirror", {"Mirror_"}}
};
```

**SQL Query:**

```sql
-- For category filter
SELECT Variable_Name, Variable_Value
FROM stats.stats_mysql_global
WHERE Variable_Name LIKE 'Client_Connections_%'
   OR Variable_Name LIKE 'Server_Connections_%'
   OR Variable_Name = 'Active_Transactions';

-- For variable_name filter (using LIKE)
SELECT Variable_Name, Variable_Value
FROM stats.stats_mysql_global
WHERE Variable_Name LIKE ?;

-- Also query memory_metrics for 'memory' category
SELECT Variable_Name, Variable_Value
FROM stats.stats_memory_metrics;
```

**Description Lookup:**

Maintain a static map of variable descriptions:

```cpp
std::map<std::string, std::string> variable_descriptions = {
    {"Client_Connections_connected", "Currently connected clients"},
    {"Client_Connections_created", "Total client connections ever created"},
    {"Questions", "Total queries processed"},
    // ... etc
};
```

### 5.2 show_processlist

**Source Tables:**
- MySQL: `stats.stats_mysql_processlist`
- PostgreSQL: `stats.stats_pgsql_processlist`

**SQL Query:**

```sql
SELECT ThreadID, SessionID, user, db, cli_host, cli_port,
       hostgroup, l_srv_host, l_srv_port, srv_host, srv_port,
       command, time_ms, info, status_flags, extended_info
FROM stats.stats_mysql_processlist
WHERE (user = ? OR ? IS NULL)
  AND (hostgroup = ? OR ? IS NULL)
  AND (time_ms >= ? OR ? IS NULL)
ORDER BY time_ms DESC
LIMIT ? OFFSET ?;
```

**Note:** The `l_srv_host` and `l_srv_port` columns represent the local ProxySQL interface, while `srv_host` and `srv_port` represent the backend server.

**Summary Aggregation:**

```cpp
json build_summary(const json& sessions) {
    std::map<std::string, int> by_user, by_hostgroup, by_command;

    for (const auto& session : sessions) {
        by_user[session["user"].get<std::string>()]++;
        by_hostgroup[std::to_string(session["hostgroup"].get<int>())]++;
        by_command[session["command"].get<std::string>()]++;
    }

    json summary;
    summary["by_user"] = by_user;
    summary["by_hostgroup"] = by_hostgroup;
    summary["by_command"] = by_command;
    return summary;
}
```

### 5.3 show_queries

**Source Tables:**
- MySQL: `stats.stats_mysql_query_digest` (uses `schemaname` column)
- PostgreSQL: `stats.stats_pgsql_query_digest` (uses `database` column)

**SQL Query (MySQL):**

```sql
SELECT hostgroup, schemaname AS database, username, client_address, digest,
       digest_text, count_star, first_seen, last_seen,
       sum_time AS sum_time_us, min_time AS min_time_us, max_time AS max_time_us,
       sum_rows_affected, sum_rows_sent
FROM stats.stats_mysql_query_digest
WHERE (count_star >= ? OR ? IS NULL)
  AND (hostgroup = ? OR ? IS NULL)
  AND (username = ? OR ? IS NULL)
  AND (schemaname = ? OR ? IS NULL)  -- database parameter maps to schemaname column
  AND (digest = ? OR ? IS NULL)
  AND (sum_time / count_star >= ? OR ? IS NULL)
ORDER BY count_star DESC
LIMIT ? OFFSET ?;
```

**SQL Query (PostgreSQL):**

```sql
SELECT hostgroup, database, username, client_address, digest,
       digest_text, count_star, first_seen, last_seen,
       sum_time AS sum_time_us, min_time AS min_time_us, max_time AS max_time_us,
       sum_rows_affected, sum_rows_sent
FROM stats.stats_pgsql_query_digest
WHERE (count_star >= ? OR ? IS NULL)
  AND (hostgroup = ? OR ? IS NULL)
  AND (username = ? OR ? IS NULL)
  AND (database = ? OR ? IS NULL)  -- database parameter maps to database column
  AND (digest = ? OR ? IS NULL)
  AND (sum_time / count_star >= ? OR ? IS NULL)
ORDER BY count_star DESC
LIMIT ? OFFSET ?;
```

**Calculated Fields:**

```cpp
for (auto& query : queries) {
    int count = query["count_star"].get<int>();
    int sum_time = query["sum_time_us"].get<int>();
    query["avg_time_us"] = count > 0 ? sum_time / count : 0;
}
```

### 5.4 show_commands

**Source Tables:**
- MySQL: `stats.stats_mysql_commands_counters`
- PostgreSQL: `stats.stats_pgsql_commands_counters`

**SQL Query:**

```sql
SELECT Command, Total_Time_us, Total_cnt,
       cnt_100us, cnt_500us, cnt_1ms, cnt_5ms, cnt_10ms, cnt_50ms,
       cnt_100ms, cnt_500ms, cnt_1s, cnt_5s, cnt_10s, cnt_INFs
FROM stats.stats_mysql_commands_counters
WHERE Command = ? OR ? IS NULL;
```

**Percentile Calculation:**

See [Section 6.1](#61-percentile-calculation-from-histograms).

### 5.5 show_connections

**Source Tables:**
- MySQL: `stats.stats_mysql_connection_pool`, `stats.stats_mysql_free_connections`
- PostgreSQL: `stats.stats_pgsql_connection_pool`, `stats.stats_pgsql_free_connections`

**SQL Query (main):**

```sql
SELECT hostgroup, srv_host, srv_port, status,
       ConnUsed, ConnFree, ConnOK, ConnERR, MaxConnUsed,
       Queries, Queries_GTID_sync, Bytes_data_sent, Bytes_data_recv, Latency_us
FROM stats.stats_mysql_connection_pool
WHERE (hostgroup = ? OR ? IS NULL)
  AND (status = ? OR ? IS NULL)
ORDER BY hostgroup, srv_host, srv_port;
```

**SQL Query (detail - MySQL):**

```sql
SELECT fd, hostgroup, srv_host, srv_port, user, schema AS database,
       init_connect, time_zone, sql_mode, autocommit, idle_ms
FROM stats.stats_mysql_free_connections
WHERE (hostgroup = ? OR ? IS NULL);
```

**SQL Query (detail - PostgreSQL):**

```sql
SELECT fd, hostgroup, srv_host, srv_port, user, database,
       init_connect, time_zone, sql_mode, idle_ms
FROM stats.stats_pgsql_free_connections
WHERE (hostgroup = ? OR ? IS NULL);
```

**PostgreSQL Notes:**
- The `stats_pgsql_free_connections` table uses `database` column (MySQL uses `schema`)
- The `stats_pgsql_free_connections` table does not have the `autocommit` column
- The `stats_pgsql_connection_pool` table does not have the `Queries_GTID_sync` column

**Calculated Fields:**

```cpp
for (auto& server : servers) {
    int used = server["conn_used"].get<int>();
    int free = server["conn_free"].get<int>();
    int total = used + free;

    server["utilization_pct"] = total > 0 ? (double)used / total * 100 : 0;

    int ok = server["conn_ok"].get<int>();
    int err = server["conn_err"].get<int>();
    int total_conns = ok + err;

    server["error_rate"] = total_conns > 0 ? (double)err / total_conns : 0;
}
```

### 5.6 show_errors

**Source Tables:**
- MySQL: `stats.stats_mysql_errors` (uses `schemaname` column, `errno` for error codes)
- PostgreSQL: `stats.stats_pgsql_errors` (uses `database` column, `sqlstate` for error codes)

**SQL Query (MySQL):**

```sql
SELECT hostgroup, hostname, port, username, client_address,
       schemaname AS database, errno, count_star, first_seen, last_seen, last_error
FROM stats.stats_mysql_errors
WHERE (count_star >= ? OR ? IS NULL)
  AND (errno = ? OR ? IS NULL)
  AND (username = ? OR ? IS NULL)
  AND (schemaname = ? OR ? IS NULL)  -- database parameter maps to schemaname column
ORDER BY count_star DESC
LIMIT ? OFFSET ?;
```

**SQL Query (PostgreSQL):**

```sql
SELECT hostgroup, hostname, port, username, client_address,
       database, sqlstate, count_star, first_seen, last_seen, last_error
FROM stats.stats_pgsql_errors
WHERE (count_star >= ? OR ? IS NULL)
  AND (sqlstate = ? OR ? IS NULL)
  AND (username = ? OR ? IS NULL)
  AND (database = ? OR ? IS NULL)  -- database parameter maps to database column
ORDER BY count_star DESC
LIMIT ? OFFSET ?;
```

**Note:** The tool normalizes to `database` field name in responses for consistency across both databases. Error codes use `errno` for MySQL and `sqlstate` for PostgreSQL as these are fundamentally different concepts.

**Calculated Fields:**

```cpp
for (auto& error : errors) {
    int count = error["count_star"].get<int>();
    int first = error["first_seen"].get<int>();
    int last = error["last_seen"].get<int>();

    double hours = (last - first) / 3600.0;
    error["frequency_per_hour"] = hours > 0 ? count / hours : count;
}
```

### 5.7 show_cluster

**Source Tables (shared):**
- `stats.stats_proxysql_servers_status`
- `stats.stats_proxysql_servers_metrics`
- `stats.stats_proxysql_servers_checksums`

**SQL Queries:**

```sql
-- Node status
SELECT hostname, port, weight, master, global_version,
       check_age_us, ping_time_us, checks_OK, checks_ERR
FROM stats.stats_proxysql_servers_status
WHERE hostname = ? OR ? IS NULL;

-- Node metrics
SELECT hostname, port, weight, response_time_ms, Uptime_s,
       last_check_ms, Queries, Client_Connections_connected, Client_Connections_created
FROM stats.stats_proxysql_servers_metrics;

-- Configuration checksums
SELECT hostname, port, name, version, epoch, checksum,
       changed_at, updated_at, diff_check
FROM stats.stats_proxysql_servers_checksums;
```

**Health Calculation:**

```cpp
std::string calculate_cluster_health(const json& nodes) {
    int total = nodes.size();
    int healthy = 0;

    for (const auto& node : nodes) {
        int ok = node["checks_ok"].get<int>();
        int err = node["checks_err"].get<int>();
        double success_rate = (ok + err) > 0 ? (double)ok / (ok + err) : 0;

        if (success_rate >= 0.95) healthy++;
    }

    if (healthy == total) return "healthy";
    if (healthy >= total / 2) return "degraded";
    return "unhealthy";
}
```

### 5.8 show_connection_history

**Source Tables:**
- Global: `mysql_connections`, `mysql_connections_hour`, `myhgm_connections`, `myhgm_connections_hour`
- Per-server: `history_stats_mysql_connection_pool`

**SQL Queries:**

```sql
-- Global connections (raw)
SELECT timestamp, Client_Connections_aborted, Client_Connections_connected,
       Client_Connections_created, Server_Connections_aborted, Server_Connections_connected,
       Server_Connections_created, ConnPool_get_conn_failure, ConnPool_get_conn_immediate,
       ConnPool_get_conn_success, Questions, Slow_queries, GTID_consistent_queries
FROM mysql_connections
WHERE timestamp BETWEEN ? AND ?
ORDER BY timestamp;

-- Global connections (hourly)
SELECT timestamp, Client_Connections_aborted, Client_Connections_connected,
       Client_Connections_created, Server_Connections_aborted, Server_Connections_connected,
       Server_Connections_created, ConnPool_get_conn_failure, ConnPool_get_conn_immediate,
       ConnPool_get_conn_success, Questions, Slow_queries, GTID_consistent_queries
FROM mysql_connections_hour
WHERE timestamp BETWEEN ? AND ?
ORDER BY timestamp;

-- MyHGM connections (raw)
SELECT timestamp, MyHGM_myconnpoll_destroy, MyHGM_myconnpoll_get,
       MyHGM_myconnpoll_get_ok, MyHGM_myconnpoll_push, MyHGM_myconnpoll_reset
FROM myhgm_connections
WHERE timestamp BETWEEN ? AND ?
ORDER BY timestamp;

-- Per-server history
SELECT timestamp, hostgroup, srv_host, srv_port, status,
       ConnUsed, ConnFree, ConnOK, ConnERR, MaxConnUsed,
       Queries, Queries_GTID_sync, Bytes_data_sent, Bytes_data_recv, Latency_us
FROM history_stats_mysql_connection_pool
WHERE timestamp BETWEEN ? AND ?
  AND (hostgroup = ? OR ? IS NULL)
ORDER BY timestamp, hostgroup, srv_host;
```

### 5.9 show_query_history

**Source Tables:**
- MySQL: `history_mysql_query_digest` (uses `schemaname` column)
- PostgreSQL: `history_pgsql_query_digest` (uses `schemaname` column)

**Note:** Both MySQL and PostgreSQL history tables use `schemaname` column. This differs from the live `stats_pgsql_query_digest` table which uses `database`. The tool normalizes to `database` in responses.

**SQL Query (MySQL):**

```sql
SELECT dump_time, hostgroup, schemaname AS database, username, client_address,
       digest, digest_text, count_star, first_seen, last_seen,
       sum_time AS sum_time_us, min_time AS min_time_us, max_time AS max_time_us,
       sum_rows_affected, sum_rows_sent
FROM history_mysql_query_digest
WHERE (dump_time = ? OR ? IS NULL)
  AND (dump_time >= ? OR ? IS NULL)
  AND (dump_time <= ? OR ? IS NULL)
  AND (digest = ? OR ? IS NULL)
  AND (username = ? OR ? IS NULL)
  AND (schemaname = ? OR ? IS NULL)  -- database parameter maps to schemaname column
ORDER BY dump_time DESC, count_star DESC
LIMIT ? OFFSET ?;
```

**SQL Query (PostgreSQL):**

```sql
-- Note: history_pgsql_query_digest uses 'schemaname' (unlike live stats_pgsql_query_digest which uses 'database')
SELECT dump_time, hostgroup, schemaname AS database, username, client_address,
       digest, digest_text, count_star, first_seen, last_seen,
       sum_time AS sum_time_us, min_time AS min_time_us, max_time AS max_time_us,
       sum_rows_affected, sum_rows_sent
FROM history_pgsql_query_digest
WHERE (dump_time = ? OR ? IS NULL)
  AND (dump_time >= ? OR ? IS NULL)
  AND (dump_time <= ? OR ? IS NULL)
  AND (digest = ? OR ? IS NULL)
  AND (username = ? OR ? IS NULL)
  AND (schemaname = ? OR ? IS NULL)  -- database parameter maps to schemaname column
ORDER BY dump_time DESC, count_star DESC
LIMIT ? OFFSET ?;
```

**Grouping by Snapshot:**

```cpp
json group_by_snapshot(SQLite3_result* resultset) {
    std::map<int, json> snapshots;

    for (each row in resultset) {
        int dump_time = atoi(row->fields[0]);
        if (snapshots.find(dump_time) == snapshots.end()) {
            snapshots[dump_time] = json::array();
        }
        snapshots[dump_time].push_back(row_to_json(row));
    }

    json result = json::array();
    for (const auto& [dump_time, queries] : snapshots) {
        json snapshot;
        snapshot["dump_time"] = dump_time;
        snapshot["queries"] = queries;
        result.push_back(snapshot);
    }
    return result;
}
```

### 5.10 show_query_log

**Source Tables:**
- Memory: `stats.stats_mysql_query_events`
- Disk: `history_mysql_query_events`

**Note:** This tool is MySQL-only. The `id` column is used internally for row management and is not exposed in the response.

**SQL Query:**

```sql
SELECT thread_id, username, schemaname AS database, start_time, end_time,
       query_digest, query, server, client, event_type, hid,
       extra_info, affected_rows, last_insert_id, rows_sent,
       client_stmt_id, gtid, errno, error
FROM stats.stats_mysql_query_events  -- or history_mysql_query_events for disk
WHERE (username = ? OR ? IS NULL)
  AND (schemaname = ? OR ? IS NULL)  -- database parameter maps to schemaname column
  AND (query_digest = ? OR ? IS NULL)
  AND (server = ? OR ? IS NULL)
  AND (errno = ? OR ? IS NULL)
  AND (errno != 0 OR ? = 0)  -- errors_only filter
  AND (start_time >= ? OR ? IS NULL)
  AND (start_time <= ? OR ? IS NULL)
ORDER BY start_time DESC
LIMIT ? OFFSET ?;
```

---

## 6. Helper Functions

### 6.1 Percentile Calculation from Histograms

The `stats_mysql_commands_counters` table provides latency histograms. To calculate percentiles:

```cpp
struct HistogramBucket {
    int threshold_us;
    int count;
};

std::vector<int> bucket_thresholds = {
    100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000, 5000000, 10000000, INT_MAX
};

int calculate_percentile(const std::vector<int>& bucket_counts, double percentile) {
    if (bucket_counts.empty() || bucket_thresholds.empty()) {
        return 0;
    }

    if (percentile < 0.0) {
        percentile = 0.0;
    } else if (percentile > 1.0) {
        percentile = 1.0;
    }

    long long total = 0;
    for (int count : bucket_counts) {
        if (count > 0) {
            total += count;
        }
    }

    if (total == 0) {
        return 0;
    }

    if (percentile == 0.0) {
        for (size_t i = 0; i < bucket_counts.size() && i < bucket_thresholds.size(); i++) {
            if (bucket_counts[i] > 0) {
                return bucket_thresholds[i];
            }
        }
        return 0;
    }

    long long target = std::ceil(total * percentile);
    if (target < 1) target = 1;
    long long cumulative = 0;

    for (size_t i = 0; i < bucket_counts.size() && i < bucket_thresholds.size(); i++) {
        if (bucket_counts[i] > 0) {
            cumulative += bucket_counts[i];
        }
        if (cumulative >= target) {
            return bucket_thresholds[i];
        }
    }

    return bucket_thresholds.empty() ? 0 : bucket_thresholds.back();
}

json calculate_percentiles(SQLite3_row* row) {
    std::vector<int> counts = {
        atoi(row->fields[3]),   // cnt_100us
        atoi(row->fields[4]),   // cnt_500us
        atoi(row->fields[5]),   // cnt_1ms
        atoi(row->fields[6]),   // cnt_5ms
        atoi(row->fields[7]),   // cnt_10ms
        atoi(row->fields[8]),   // cnt_50ms
        atoi(row->fields[9]),   // cnt_100ms
        atoi(row->fields[10]),  // cnt_500ms
        atoi(row->fields[11]),  // cnt_1s
        atoi(row->fields[12]),  // cnt_5s
        atoi(row->fields[13]),  // cnt_10s
        atoi(row->fields[14])   // cnt_INFs
    };

    json percentiles;
    percentiles["p50_us"] = calculate_percentile(counts, 0.50);
    percentiles["p90_us"] = calculate_percentile(counts, 0.90);
    percentiles["p95_us"] = calculate_percentile(counts, 0.95);
    percentiles["p99_us"] = calculate_percentile(counts, 0.99);

    return percentiles;
}
```

### 6.2 SQLite Result to JSON Conversion

```cpp
json resultset_to_json(SQLite3_result* resultset, int cols) {
    json rows = json::array();

    if (!resultset || resultset->rows_count == 0) {
        return rows;
    }

    for (size_t i = 0; i < resultset->rows_count; i++) {
        SQLite3_row* row = resultset->rows[i];
        json obj;

        for (int j = 0; j < cols; j++) {
            const char* field = row->fields[j];
            const char* column = resultset->column_definition[j]->name;

            if (field == nullptr) {
                obj[column] = nullptr;
            } else if (is_numeric(field)) {
                // Try to parse as integer first, then as double
                char* endptr;
                long long ll = strtoll(field, &endptr, 10);
                if (*endptr == '\0') {
                    obj[column] = ll;
                } else {
                    obj[column] = std::stod(field);
                }
            } else {
                obj[column] = field;
            }
        }
        rows.push_back(obj);
    }

    return rows;
}

bool is_numeric(const char* str) {
    if (str == nullptr || *str == '\0') return false;

    char* endptr;
    strtod(str, &endptr);
    return *endptr == '\0';
}
```

### 6.3 Time Range Builder

```cpp
std::pair<time_t, time_t> get_time_range(const std::string& interval) {
    auto it = interval_map.find(interval);
    if (it == interval_map.end()) {
        throw std::invalid_argument("Invalid interval: " + interval);
    }

    time_t now = time(NULL);
    time_t start = now - it->second.seconds;

    return {start, now};
}
```

---

## 7. Error Handling Patterns

### 7.1 Standard Error Response

```cpp
json create_error_response(const std::string& message) {
    json response;
    response["success"] = false;
    response["error"] = message;
    return response;
}

json create_success_response(const json& result) {
    json response;
    response["success"] = true;
    response["result"] = result;
    return response;
}
```

### 7.2 Common Error Scenarios

**Database Query Failure:**

```cpp
if (rc != SQLITE_OK) {
    std::string err_msg = error ? error : "Query execution failed";
    if (error) free(error);
    return create_error_response(err_msg);
}
```

**Invalid Parameters:**

```cpp
if (!arguments.contains("required_param")) {
    return create_error_response("Missing required parameter: required_param");
}

std::string value = arguments["param"];
if (!is_valid_value(value)) {
    return create_error_response("Invalid value for parameter 'param': " + value);
}
```

**PostgreSQL Not Supported:**

```cpp
std::string db_type = arguments.value("db_type", "mysql");
if (db_type == "pgsql") {
    return create_error_response("PostgreSQL is not supported for this tool. Historical connection data is only available for MySQL.");
}
```

**Empty Result Set:**

```cpp
if (!resultset || resultset->rows_count == 0) {
    json result;
    result["message"] = "No data found";
    result["data"] = json::array();
    return create_success_response(result);
}
```

---

## 8. Testing Strategies

### 8.1 Unit Tests

Test each handler function independently:

```cpp
TEST(StatsToolHandler, ShowStatus) {
    Stats_Tool_Handler handler(GloMCPH);
    handler.init();

    json args;
    args["db_type"] = "mysql";
    args["category"] = "connections";

    json response = handler.execute_tool("show_status", args);

    ASSERT_TRUE(response["success"].get<bool>());
    ASSERT_TRUE(response["result"].contains("variables"));
    ASSERT_GT(response["result"]["variables"].size(), 0);
}

TEST(StatsToolHandler, ShowStatusWithVariableFilter) {
    Stats_Tool_Handler handler(GloMCPH);
    handler.init();

    json args;
    args["db_type"] = "mysql";
    args["variable_name"] = "Client_Connections_%";

    json response = handler.execute_tool("show_status", args);

    ASSERT_TRUE(response["success"].get<bool>());
    for (const auto& var : response["result"]["variables"]) {
        std::string name = var["variable_name"].get<std::string>();
        ASSERT_TRUE(name.find("Client_Connections_") == 0);
    }
}
```

### 8.2 Integration Tests

Test with actual ProxySQL instance:

```bash
# Start ProxySQL with test configuration
proxysql -f -c test_proxysql.cnf &

# Generate some traffic
mysql -h 127.0.0.1 -P6033 -utest -ptest -e "SELECT 1" &

# Test MCP endpoint
curl -X POST http://localhost:6071/mcp/stats \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-token" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "show_queries",
      "arguments": {"db_type": "mysql", "limit": 10}
    },
    "id": 1
  }'

# Verify response structure
# ...
```

### 8.3 Test Data Setup

```sql
-- Populate test data via admin interface
-- (Note: Most stats tables are read-only and populated by ProxySQL internally)

-- For testing historical tables, wait for timer-based collection
-- or manually trigger collection via internal mechanisms

-- For testing query events, generate queries and then flush
SELECT 1;
SELECT 2;
-- Admin: DUMP EVENTSLOG FROM BUFFER TO MEMORY;
```

### 8.4 Edge Cases to Test

1. **Empty tables** — Ensure graceful handling when no data exists
2. **Large result sets** — Test with limit parameter, verify truncation
3. **Invalid parameters** — Test error responses for bad input
4. **PostgreSQL fallback** — Test error messages for unsupported PostgreSQL operations
5. **Time range boundaries** — Test historical queries at retention boundaries (7 days, 365 days)
6. **Concurrent access** — Test behavior under concurrent tool calls
