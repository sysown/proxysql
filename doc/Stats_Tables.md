# ProxySQL Statistics and Metrics Tables

This document provides a comprehensive analysis of ProxySQL statistics and metrics table schemas. ProxySQL exposes statistics through its admin interface (default port 6032) backed by in-memory SQLite tables.

## Table of Contents

- [1. MySQL Statistics Tables](#1-mysql-statistics-tables)
- [2. PostgreSQL Statistics Tables](#2-postgresql-statistics-tables)
- [3. Cluster Statistics Tables](#3-cluster-statistics-tables)
- [4. Historical Statistics Tables](#4-historical-statistics-tables)
- [5. System Statistics Tables](#5-system-statistics-tables)
- [6. Table Reset Pattern](#6-table-reset-pattern)
- [7. Database Architecture](#7-database-architecture)
- [8. Data Characteristics and Example Queries](#8-data-characteristics-and-example-queries)
- [9. Common Notes](#9-common-notes)
- [10. File References](#10-file-references)

## 1. MySQL Statistics Tables

### 1.1 stats_mysql_query_rules

Tracks hit counts for query rules.

```sql
CREATE TABLE stats_mysql_query_rules (
    rule_id INTEGER PRIMARY KEY,
    hits INT NOT NULL
)
```

**Columns:**
- `rule_id` - Reference to the query rule in `mysql_query_rules`
- `hits` - Number of times this rule was matched

### 1.2 stats_mysql_users

Monitors frontend user connections and limits.

```sql
CREATE TABLE stats_mysql_users (
    username VARCHAR PRIMARY KEY,
    frontend_connections INT NOT NULL,
    frontend_max_connections INT NOT NULL
)
```

**Columns:**
- `username` - MySQL username
- `frontend_connections` - Current number of active frontend connections
- `frontend_max_connections` - Maximum allowed connections (from `mysql_users` config)

### 1.3 stats_mysql_commands_counters

Aggregates command execution statistics with latency distribution.

```sql
CREATE TABLE stats_mysql_commands_counters (
    Command VARCHAR NOT NULL PRIMARY KEY,
    Total_Time_us INT NOT NULL,
    Total_cnt INT NOT NULL,
    cnt_100us INT NOT NULL,
    cnt_500us INT NOT NULL,
    cnt_1ms INT NOT NULL,
    cnt_5ms INT NOT NULL,
    cnt_10ms INT NOT NULL,
    cnt_50ms INT NOT NULL,
    cnt_100ms INT NOT NULL,
    cnt_500ms INT NOT NULL,
    cnt_1s INT NOT NULL,
    cnt_5s INT NOT NULL,
    cnt_10s INT NOT NULL,
    cnt_INFs INT NOT NULL
)
```

**Columns:**
- `Command` - MySQL command type (SELECT, INSERT, etc.)
- `Total_Time_us` - Total execution time in microseconds
- `Total_cnt` - Total number of executions
- `cnt_100us` - Count of queries with latency ≤100μs
- `cnt_500us` - Count of queries with latency ≤500μs
- `cnt_1ms` - Count of queries with latency ≤1ms
- `cnt_5ms` - Count of queries with latency ≤5ms
- `cnt_10ms` - Count of queries with latency ≤10ms
- `cnt_50ms` - Count of queries with latency ≤50ms
- `cnt_100ms` - Count of queries with latency ≤100ms
- `cnt_500ms` - Count of queries with latency ≤500ms
- `cnt_1s` - Count of queries with latency ≤1s
- `cnt_5s` - Count of queries with latency ≤5s
- `cnt_10s` - Count of queries with latency ≤10s
- `cnt_INFs` - Count of queries with unknown/undefined latency

### 1.4 stats_mysql_processlist

Shows active MySQL sessions, similar to MySQL's `PROCESSLIST`.

```sql
CREATE TABLE stats_mysql_processlist (
    ThreadID INT NOT NULL,
    SessionID INTEGER PRIMARY KEY,
    user VARCHAR,
    db VARCHAR,
    cli_host VARCHAR,
    cli_port INT,
    hostgroup INT,
    l_srv_host VARCHAR,
    l_srv_port INT,
    srv_host VARCHAR,
    srv_port INT,
    command VARCHAR,
    time_ms INT NOT NULL,
    info VARCHAR,
    status_flags INT,
    extended_info VARCHAR
)
```

**Columns:**
- `ThreadID` - Internal thread identifier
- `SessionID` - Unique session identifier (primary key)
- `user` - Username
- `db` - Database/schema name
- `cli_host` - Client host address
- `cli_port` - Client port
- `hostgroup` - Target hostgroup
- `l_srv_host` - Local (proxysql) server hostname
- `l_srv_port` - Local server port
- `srv_host` - Backend MySQL server hostname
- `srv_port` - Backend MySQL server port
- `command` - Current command type
- `time_ms` - Query execution time in milliseconds
- `info` - Query text or status message
- `status_flags` - Internal status flags
- `extended_info` - Extended session information (JSON)

### 1.5 stats_mysql_connection_pool

Backend connection pool metrics per server.

```sql
CREATE TABLE stats_mysql_connection_pool (
    hostgroup INT,
    srv_host VARCHAR,
    srv_port INT,
    status VARCHAR,
    ConnUsed INT,
    ConnFree INT,
    ConnOK INT,
    ConnERR INT,
    MaxConnUsed INT,
    Queries INT,
    Queries_GTID_sync INT,
    Bytes_data_sent INT,
    Bytes_data_recv INT,
    Latency_us INT
)
```

**Columns:**
- `hostgroup` - Hostgroup ID
- `srv_host` - Backend server hostname
- `srv_port` - Backend server port
- `status` - Server status (ONLINE, SHUNNED, OFFLINE_SOFT, OFFLINE_HARD)
- `ConnUsed` - Currently used connections
- `ConnFree` - Free/available connections in pool
- `ConnOK` - Total successful connections
- `ConnERR` - Total connection errors
- `MaxConnUsed` - Maximum concurrent connections used
- `Queries` - Total queries sent to this server
- `Queries_GTID_sync` - Queries synchronized with GTID
- `Bytes_data_sent` - Total bytes sent to server
- `Bytes_data_recv` - Total bytes received from server
- `Latency_us` - Ping latency in microseconds

**stats_mysql_connection_pool_reset** - Identical schema to `stats_mysql_connection_pool` but allows resetting stats.

### 1.6 stats_mysql_free_connections

Details about idle connections available in the pool.

```sql
CREATE TABLE stats_mysql_free_connections (
    fd INT NOT NULL,
    hostgroup INT NOT NULL,
    srv_host VARCHAR NOT NULL,
    srv_port INT NOT NULL,
    user VARCHAR NOT NULL,
    schema VARCHAR,
    init_connect VARCHAR,
    time_zone VARCHAR,
    sql_mode VARCHAR,
    autocommit VARCHAR,
    idle_ms INT,
    statistics VARCHAR,
    mysql_info VARCHAR
)
```

**Columns:**
- `fd` - File descriptor for the connection
- `hostgroup` - Hostgroup ID
- `srv_host` - Backend server hostname
- `srv_port` - Backend server port
- `user` - Backend username
- `schema` - Default schema
- `init_connect` - INIT_CONNECT string
- `time_zone` - Timezone setting
- `sql_mode` - SQL mode
- `autocommit` - Autocommit status
- `idle_ms` - Idle time in milliseconds
- `statistics` - Connection statistics (JSON)
- `mysql_info` - Additional MySQL-specific info (JSON)

### 1.7 stats_mysql_query_digest

Aggregated query performance statistics.

```sql
CREATE TABLE stats_mysql_query_digest (
    hostgroup INT,
    schemaname VARCHAR NOT NULL,
    username VARCHAR NOT NULL,
    client_address VARCHAR NOT NULL,
    digest VARCHAR NOT NULL,
    digest_text VARCHAR NOT NULL,
    count_star INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    sum_time INTEGER NOT NULL,
    min_time INTEGER NOT NULL,
    max_time INTEGER NOT NULL,
    sum_rows_affected INTEGER NOT NULL,
    sum_rows_sent INTEGER NOT NULL,
    PRIMARY KEY(hostgroup, schemaname, username, client_address, digest)
)
```

**Columns:**
- `hostgroup` - Hostgroup where query was executed
- `schemaname` - Database/schema name
- `username` - Username who executed query
- `client_address` - Client IP address
- `digest` - Query digest hash
- `digest_text` - Representative query text (normalized)
- `count_star` - Total executions
- `first_seen` - Unix timestamp of first execution
- `last_seen` - Unix timestamp of last execution
- `sum_time` - Total execution time in microseconds
- `min_time` - Minimum execution time in microseconds
- `max_time` - Maximum execution time in microseconds
- `sum_rows_affected` - Total rows affected
- `sum_rows_sent` - Total rows sent to client

**stats_mysql_query_digest_reset** - Identical schema to `stats_mysql_query_digest` for resetting stats.

### 1.8 stats_mysql_global

Global ProxySQL metrics.

```sql
CREATE TABLE stats_mysql_global (
    Variable_Name VARCHAR NOT NULL PRIMARY KEY,
    Variable_Value VARCHAR NOT NULL
)
```

**Complete Variable List:**

This table uses a key-value format where each row is a different metric. The variables are populated from multiple sources in the codebase (see [Source References](#source-references) below).

**System / Uptime**

| Variable Name | Description | Type |
|---|---|---|
| `ProxySQL_Uptime` | Seconds since ProxySQL started | Gauge |

**Client Connection Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `Active_Transactions` | Currently active transactions | Gauge |
| `Client_Connections_aborted` | Total aborted client connections | Counter |
| `Client_Connections_connected` | Currently connected clients | Gauge |
| `Client_Connections_connected_prim_pass` | Clients connected via primary password | Gauge |
| `Client_Connections_connected_addl_pass` | Clients connected via additional password | Gauge |
| `Client_Connections_created` | Total client connections ever created | Counter |
| `Client_Connections_sha2cached` | Connections using SHA2 cached authentication | Counter |
| `Client_Connections_non_idle` | Non-idle client connections (requires `IDLE_THREADS`) | Gauge |
| `Client_Connections_hostgroup_locked` | Connections locked to a specific hostgroup | Gauge |

**Server Connection Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `Server_Connections_aborted` | Total aborted server connections | Counter |
| `Server_Connections_connected` | Currently connected backend servers | Gauge |
| `Server_Connections_created` | Total server connections ever created | Counter |
| `Server_Connections_delayed` | Connections delayed due to throttling | Counter |

**Memory Buffer Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `mysql_backend_buffers_bytes` | Memory used by backend connection buffers | Gauge |
| `mysql_frontend_buffers_bytes` | Memory used by frontend connection buffers | Gauge |
| `mysql_session_internal_bytes` | Memory used by internal session structures | Gauge |

**Command Counters (Com_\*)**

| Variable Name | Description | Type |
|---|---|---|
| `Com_autocommit` | Autocommit statements executed | Counter |
| `Com_autocommit_filtered` | Autocommit statements filtered | Counter |
| `Com_commit` | COMMIT statements executed | Counter |
| `Com_commit_filtered` | COMMIT statements filtered | Counter |
| `Com_rollback` | ROLLBACK statements executed | Counter |
| `Com_rollback_filtered` | ROLLBACK statements filtered | Counter |
| `Com_backend_change_user` | Backend CHANGE USER commands | Counter |
| `Com_backend_init_db` | Backend INIT_DB commands | Counter |
| `Com_backend_set_names` | Backend SET NAMES commands | Counter |
| `Com_frontend_init_db` | Frontend INIT_DB commands | Counter |
| `Com_frontend_set_names` | Frontend SET NAMES commands | Counter |
| `Com_frontend_use_db` | Frontend USE DB commands | Counter |

**Prepared Statement Counters**

| Variable Name | Description | Type |
|---|---|---|
| `Com_backend_stmt_prepare` | Backend PREPARE statements | Counter |
| `Com_backend_stmt_execute` | Backend EXECUTE statements | Counter |
| `Com_backend_stmt_close` | Backend CLOSE statements | Counter |
| `Com_frontend_stmt_prepare` | Frontend PREPARE statements | Counter |
| `Com_frontend_stmt_execute` | Frontend EXECUTE statements | Counter |
| `Com_frontend_stmt_close` | Frontend CLOSE statements | Counter |

**Query Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `Questions` | Total queries processed | Counter |
| `Slow_queries` | Number of slow queries | Counter |
| `GTID_consistent_queries` | Queries requiring GTID consistency | Counter |
| `GTID_session_collected` | GTID sessions collected | Counter |
| `Queries_backends_bytes_recv` | Bytes received from backends | Counter |
| `Queries_backends_bytes_sent` | Bytes sent to backends | Counter |
| `Queries_frontends_bytes_recv` | Bytes received from frontends | Counter |
| `Queries_frontends_bytes_sent` | Bytes sent to frontends | Counter |
| `Query_Processor_time_nsec` | Time spent in query processor (nanoseconds) | Counter |
| `Backend_query_time_nsec` | Time spent executing on backends (nanoseconds) | Counter |

**Connection Pool Operation Counters**

| Variable Name | Description | Type |
|---|---|---|
| `ConnPool_get_conn_latency_awareness` | Connections obtained via latency-aware routing | Counter |
| `ConnPool_get_conn_immediate` | Connections obtained immediately from pool | Counter |
| `ConnPool_get_conn_success` | Successful connection pool gets | Counter |
| `ConnPool_get_conn_failure` | Failed connection pool gets | Counter |
| `MyHGM_myconnpoll_get` | Total connection pool get operations | Counter |
| `MyHGM_myconnpoll_get_ok` | Successful pool get operations | Counter |
| `MyHGM_myconnpoll_push` | Connections returned to pool | Counter |
| `MyHGM_myconnpoll_destroy` | Connections destroyed from pool | Counter |
| `MyHGM_myconnpoll_reset` | Connection pool resets | Counter |

**Backend Health Counters**

| Variable Name | Description | Type |
|---|---|---|
| `mysql_killed_backend_connections` | Backend connections killed | Counter |
| `mysql_killed_backend_queries` | Backend queries killed | Counter |
| `backend_lagging_during_query` | Queries affected by backend lag | Counter |
| `backend_offline_during_query` | Queries affected by backend going offline | Counter |
| `get_aws_aurora_replicas_skipped_during_query` | Aurora replicas skipped during query | Counter |
| `max_connect_timeouts` | Maximum connect timeouts reached | Counter |

**Hostgroup Locking Counters**

| Variable Name | Description | Type |
|---|---|---|
| `hostgroup_locked_set_cmds` | SET commands on locked hostgroup sessions | Counter |
| `hostgroup_locked_queries` | Queries on locked hostgroup sessions | Counter |

**Unexpected Frontend Counters**

| Variable Name | Description | Type |
|---|---|---|
| `mysql_unexpected_frontend_com_quit` | Unexpected COM_QUIT from frontend | Counter |
| `mysql_unexpected_frontend_com_ping` | Unexpected COM_PING from frontend | Counter |
| `mysql_unexpected_frontend_packets` | Unexpected packets from frontend | Counter |

**Max Lag Throttling Counters**

| Variable Name | Description | Type |
|---|---|---|
| `queries_with_max_lag_ms` | Queries subject to max lag check | Counter |
| `queries_with_max_lag_ms__delayed` | Queries delayed due to max lag | Counter |
| `queries_with_max_lag_ms__total_wait_time_us` | Total wait time from max lag delays (μs) | Counter |

**Security Counters**

| Variable Name | Description | Type |
|---|---|---|
| `automatic_detected_sql_injection` | Automatically detected SQL injection attempts | Counter |
| `mysql_whitelisted_sqli_fingerprint` | Whitelisted SQL injection fingerprints | Counter |
| `ai_detected_anomalies` | AI-detected query anomalies | Counter |
| `ai_blocked_queries` | Queries blocked by AI detection | Counter |

**Error and Miscellaneous Counters**

| Variable Name | Description | Type |
|---|---|---|
| `generated_error_packets` | Error packets generated by ProxySQL | Counter |
| `client_host_error_killed_connections` | Connections killed due to client host errors | Counter |
| `mysql_set_wait_timeout_commands` | SET wait_timeout commands processed | Counter |
| `mysql_timeout_terminated_connections` | Connections terminated due to timeout | Counter |

**Mirror Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `Mirror_concurrency` | Current number of mirror sessions | Gauge |
| `Mirror_queue_length` | Current mirror queue length | Gauge |

**Miscellaneous Status**

| Variable Name | Description | Type |
|---|---|---|
| `Selects_for_update__autocommit0` | SELECT FOR UPDATE with autocommit=0 | Counter |
| `Servers_table_version` | Current version of the servers table | Gauge |
| `MySQL_Thread_Workers` | Number of MySQL thread workers | Gauge |
| `new_req_conns_count` | New request connections count from query processor | Counter |
| `mysql_listener_paused` | Whether the MySQL listener is paused (0/1) | Gauge |
| `OpenSSL_Version_Num` | OpenSSL version number | Gauge |

**Access Denied Counters**

| Variable Name | Description | Type |
|---|---|---|
| `Access_Denied_Wrong_Password` | Access denied due to wrong password | Counter |
| `Access_Denied_Max_Connections` | Access denied due to max connections | Counter |
| `Access_Denied_Max_User_Connections` | Access denied due to max user connections | Counter |

**MySQL Monitor Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `MySQL_Monitor_Workers` | Number of monitor worker threads | Gauge |
| `MySQL_Monitor_Workers_Aux` | Number of auxiliary monitor workers | Gauge |
| `MySQL_Monitor_Workers_Started` | Number of monitor workers started | Counter |
| `MySQL_Monitor_connect_check_OK` | Successful monitor connect checks | Counter |
| `MySQL_Monitor_connect_check_ERR` | Failed monitor connect checks | Counter |
| `MySQL_Monitor_ping_check_OK` | Successful monitor ping checks | Counter |
| `MySQL_Monitor_ping_check_ERR` | Failed monitor ping checks | Counter |
| `MySQL_Monitor_read_only_check_OK` | Successful read-only checks | Counter |
| `MySQL_Monitor_read_only_check_ERR` | Failed read-only checks | Counter |
| `MySQL_Monitor_replication_lag_check_OK` | Successful replication lag checks | Counter |
| `MySQL_Monitor_replication_lag_check_ERR` | Failed replication lag checks | Counter |
| `MySQL_Monitor_dns_cache_queried` | DNS cache queries | Counter |
| `MySQL_Monitor_dns_cache_lookup_success` | Successful DNS cache lookups | Counter |
| `MySQL_Monitor_dns_cache_record_updated` | DNS cache records updated | Counter |

**Memory Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `SQLite3_memory_bytes` | SQLite3 internal memory usage | Gauge |
| `ConnPool_memory_bytes` | Connection pool memory usage | Gauge |

**Prepared Statement Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `Stmt_Client_Active_Total` | Total active client-side prepared statements | Gauge |
| `Stmt_Client_Active_Unique` | Unique active client-side prepared statements | Gauge |
| `Stmt_Server_Active_Total` | Total active server-side prepared statements | Gauge |
| `Stmt_Server_Active_Unique` | Unique active server-side prepared statements | Gauge |
| `Stmt_Max_Stmt_id` | Maximum prepared statement ID assigned | Gauge |
| `Stmt_Cached` | Cached prepared statements | Gauge |

**Query Cache Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `Query_Cache_Memory_bytes` | Memory used by query cache | Gauge |
| `Query_Cache_count_GET` | Query cache GET operations | Counter |
| `Query_Cache_count_GET_OK` | Successful query cache GETs | Counter |
| `Query_Cache_count_SET` | Query cache SET operations | Counter |
| `Query_Cache_bytes_IN` | Bytes written into query cache | Counter |
| `Query_Cache_bytes_OUT` | Bytes read from query cache | Counter |
| `Query_Cache_Purged` | Query cache entries purged | Counter |
| `Query_Cache_Entries` | Current query cache entries | Gauge |

**MySQL Logger Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `MySQL_Logger_memoryCopyCount` | Number of memory copy operations | Counter |
| `MySQL_Logger_diskCopyCount` | Number of disk copy operations | Counter |
| `MySQL_Logger_getAllEventsCallsCount` | Number of getAllEvents calls | Counter |
| `MySQL_Logger_getAllEventsEventsCount` | Total events from getAllEvents | Counter |
| `MySQL_Logger_totalMemoryCopyTimeMicros` | Total memory copy time (μs) | Counter |
| `MySQL_Logger_totalDiskCopyTimeMicros` | Total disk copy time (μs) | Counter |
| `MySQL_Logger_totalGetAllEventsTimeMicros` | Total getAllEvents time (μs) | Counter |
| `MySQL_Logger_totalEventsCopiedToMemory` | Events copied to memory | Counter |
| `MySQL_Logger_totalEventsCopiedToDisk` | Events copied to disk | Counter |
| `MySQL_Logger_circularBufferEventsAddedCount` | Events added to circular buffer | Counter |
| `MySQL_Logger_circularBufferEventsDroppedCount` | Events dropped from circular buffer | Counter |
| `MySQL_Logger_circularBufferEventsSize` | Current circular buffer size | Gauge |

#### Source References

Variables are aggregated from these code locations:
- `MySQL_Threads_Handler::SQL3_GlobalStatus()` in `lib/MySQL_Thread.cpp`
- `MySQL_HostGroups_Manager::SQL3_Get_ConnPool_Stats()` in `lib/MySQL_HostGroups_Manager.cpp`
- `ProxySQL_Admin::stats___mysql_global()` in `lib/ProxySQL_Admin_Stats.cpp`
- `Query_Cache::SQL3_getStats()` in `lib/Query_Cache.cpp`
- `MySQL_Logger::getAllMetrics()` in `lib/MySQL_Logger.cpp`

### 1.9 stats_memory_metrics

Memory usage statistics.

```sql
CREATE TABLE stats_memory_metrics (
    Variable_Name VARCHAR NOT NULL PRIMARY KEY,
    Variable_Value VARCHAR NOT NULL
)
```

**Complete Variable List:**

This table uses a key-value format. Variables are populated from `lib/ProxySQL_Admin_Stats.cpp`.

**Core Memory**

| Variable Name | Description | Conditional |
|---|---|---|
| `SQLite3_memory_bytes` | SQLite3 internal memory usage | Always |

**jemalloc Memory (requires jemalloc build)**

| Variable Name | Description | Conditional |
|---|---|---|
| `jemalloc_resident` | Resident memory reported by jemalloc | Build without `NOJEM` |
| `jemalloc_active` | Active memory reported by jemalloc | Build without `NOJEM` |
| `jemalloc_allocated` | Allocated memory reported by jemalloc | Build without `NOJEM` |
| `jemalloc_mapped` | Mapped memory reported by jemalloc | Build without `NOJEM` |
| `jemalloc_metadata` | Metadata memory reported by jemalloc | Build without `NOJEM` |
| `jemalloc_retained` | Retained memory reported by jemalloc | Build without `NOJEM` |

**Module Memory**

| Variable Name | Description | Conditional |
|---|---|---|
| `Auth_memory` | MySQL authentication module memory | `GloMyAuth` active |
| `mysql_query_digest_memory` | MySQL query digest memory | `GloMyQPro` active |
| `mysql_query_rules_memory` | MySQL query rules memory | `GloMyQPro` active |
| `pgsql_query_digest_memory` | PostgreSQL query digest memory | `GloPgQPro` active |
| `pgsql_query_rules_memory` | PostgreSQL query rules memory | `GloPgQPro` active |

**Prepared Statement Memory**

| Variable Name | Description | Conditional |
|---|---|---|
| `prepare_statement_metadata_memory` | Prepared statement metadata memory | `GloMyStmt` active |
| `prepare_statement_backend_memory` | Prepared statement backend memory | `GloMyStmt` active |

**Firewall Memory**

| Variable Name | Description | Conditional |
|---|---|---|
| `mysql_firewall_users_table` | Firewall users table memory | `GloMyQPro` active |
| `mysql_firewall_users_config` | Firewall users config memory | `GloMyQPro` active |
| `mysql_firewall_rules_table` | Firewall rules table memory | `GloMyQPro` active |
| `mysql_firewall_rules_config` | Firewall rules config memory | `GloMyQPro` active |

**Stack Memory**

| Variable Name | Description | Conditional |
|---|---|---|
| `stack_memory_mysql_threads` | Stack memory for MySQL threads | Always |
| `stack_memory_admin_threads` | Stack memory for admin threads | Always |
| `stack_memory_cluster_threads` | Stack memory for cluster threads | Always |

### 1.10 stats_mysql_gtid_executed

GTID (Global Transaction ID) information.

```sql
CREATE TABLE stats_mysql_gtid_executed (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 3306,
    gtid_executed VARCHAR,
    events INT NOT NULL
)
```

**Columns:**
- `hostname` - Backend server hostname
- `port` - Backend server port
- `gtid_executed` - GTID set string
- `events` - Number of GTID events

### 1.11 stats_mysql_errors

MySQL error tracking.

```sql
CREATE TABLE stats_mysql_errors (
    hostgroup INT NOT NULL,
    hostname VARCHAR NOT NULL,
    port INT NOT NULL,
    username VARCHAR NOT NULL,
    client_address VARCHAR NOT NULL,
    schemaname VARCHAR NOT NULL,
    errno INT NOT NULL,
    count_star INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    last_error VARCHAR NOT NULL DEFAULT '',
    PRIMARY KEY (hostgroup, hostname, port, username, schemaname, errno)
)
```

**Columns:**
- `hostgroup` - Hostgroup ID
- `hostname` - Backend server hostname
- `port` - Backend server port
- `username` - Username
- `client_address` - Client IP address
- `schemaname` - Database/schema name
- `errno` - MySQL error number
- `count_star` - Error count
- `first_seen` - Unix timestamp of first occurrence
- `last_seen` - Unix timestamp of last occurrence
- `last_error` - Error message

**stats_mysql_errors_reset** - Identical schema to `stats_mysql_errors` for resetting stats.

### 1.12 stats_mysql_client_host_cache

Client host error tracking for connection throttling.

```sql
CREATE TABLE stats_mysql_client_host_cache (
    client_address VARCHAR NOT NULL,
    error_count INT NOT NULL,
    last_updated BIGINT NOT NULL
)
```

**Columns:**
- `client_address` - Client IP address
- `error_count` - Number of recent errors from this host
- `last_updated` - Unix timestamp of last update

**stats_mysql_client_host_cache_reset** - Identical schema to `stats_mysql_client_host_cache` for resetting stats.

### 1.13 stats_mysql_prepared_statements_info

Prepared statement statistics.

```sql
CREATE TABLE stats_mysql_prepared_statements_info (
    global_stmt_id INT NOT NULL,
    schemaname VARCHAR NOT NULL,
    username VARCHAR NOT NULL,
    digest VARCHAR NOT NULL,
    ref_count_client INT NOT NULL,
    ref_count_server INT NOT NULL,
    num_columns INT NOT NULL,
    num_params INT NOT NULL,
    query VARCHAR NOT NULL
)
```

**Columns:**
- `global_stmt_id` - Global statement ID
- `schemaname` - Database schema
- `username` - Username
- `digest` - Query digest
- `ref_count_client` - Reference count from client
- `ref_count_server` - Reference count from server
- `num_columns` - Number of result columns
- `num_params` - Number of parameters
- `query` - Query text

### 1.14 stats_mysql_query_events

Query event log (when query logging is enabled).

```sql
CREATE TABLE stats_mysql_query_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER,
    username TEXT,
    schemaname TEXT,
    start_time INTEGER,
    end_time INTEGER,
    query_digest TEXT,
    query TEXT,
    server TEXT,
    client TEXT,
    event_type INTEGER,
    hid INTEGER,
    extra_info TEXT,
    affected_rows INTEGER,
    last_insert_id INTEGER,
    rows_sent INTEGER,
    client_stmt_id INTEGER,
    gtid TEXT,
    errno INT,
    error TEXT
)
```

**Columns:**
- `id` - Auto-increment ID
- `thread_id` - Thread ID
- `username` - Username
- `schemaname` - Database schema
- `start_time` - Start timestamp
- `end_time` - End timestamp
- `query_digest` - Query digest
- `query` - Full query text
- `server` - Server address
- `client` - Client address
- `event_type` - Event type
- `hid` - Hostgroup ID
- `extra_info` - Extra information
- `affected_rows` - Rows affected
- `last_insert_id` - Last insert ID
- `rows_sent` - Rows sent
- `client_stmt_id` - Client statement ID
- `gtid` - GTID information
- `errno` - Error number
- `error` - Error message

## 2. PostgreSQL Statistics Tables

All PostgreSQL stats tables mirror their MySQL counterparts with appropriate name changes (e.g., `schemaname` instead of `db`, `sqlstate` instead of `errno`).

### 2.1 stats_pgsql_query_rules

```sql
CREATE TABLE stats_pgsql_query_rules (
    rule_id INTEGER PRIMARY KEY,
    hits INT NOT NULL
)
```

### 2.2 stats_pgsql_users

```sql
CREATE TABLE stats_pgsql_users (
    username VARCHAR PRIMARY KEY,
    frontend_connections INT NOT NULL,
    frontend_max_connections INT NOT NULL
)
```

### 2.3 stats_pgsql_commands_counters

```sql
CREATE TABLE stats_pgsql_commands_counters (
    Command VARCHAR NOT NULL PRIMARY KEY,
    Total_Time_us INT NOT NULL,
    Total_cnt INT NOT NULL,
    cnt_100us INT NOT NULL,
    cnt_500us INT NOT NULL,
    cnt_1ms INT NOT NULL,
    cnt_5ms INT NOT NULL,
    cnt_10ms INT NOT NULL,
    cnt_50ms INT NOT NULL,
    cnt_100ms INT NOT NULL,
    cnt_500ms INT NOT NULL,
    cnt_1s INT NOT NULL,
    cnt_5s INT NOT NULL,
    cnt_10s INT NOT NULL,
    cnt_INFs INT NOT NULL
)
```

### 2.4 stats_pgsql_processlist

```sql
CREATE TABLE stats_pgsql_processlist (
    ThreadID INT NOT NULL,
    SessionID INTEGER PRIMARY KEY,
    user VARCHAR,
    database VARCHAR,
    cli_host VARCHAR,
    cli_port INT,
    hostgroup INT,
    l_srv_host VARCHAR,
    l_srv_port INT,
    srv_host VARCHAR,
    srv_port INT,
    backend_pid INT,
    backend_state VARCHAR,
    command VARCHAR,
    time_ms INT NOT NULL,
    info VARCHAR,
    status_flags INT,
    extended_info VARCHAR
)
```

**Note:** This table includes `database`, `backend_pid`, and `backend_state` columns specific to PostgreSQL.

### 2.5 stats_pgsql_stat_activity

A PostgreSQL-compatible **VIEW** (not a table) that mirrors `pg_stat_activity`.

```sql
CREATE VIEW stats_pgsql_stat_activity AS
SELECT
    ThreadID AS thread_id,
    database AS datname,
    SessionID AS pid,
    user AS usename,
    cli_host AS client_addr,
    cli_port AS client_port,
    hostgroup,
    l_srv_host,
    l_srv_port,
    srv_host,
    srv_port,
    backend_pid,
    backend_state AS state,
    command,
    time_ms AS duration_ms,
    info as query,
    status_flags,
    extended_info
FROM stats_pgsql_processlist
```

### 2.6 stats_pgsql_connection_pool

```sql
CREATE TABLE stats_pgsql_connection_pool (
    hostgroup INT,
    srv_host VARCHAR,
    srv_port INT,
    status VARCHAR,
    ConnUsed INT,
    ConnFree INT,
    ConnOK INT,
    ConnERR INT,
    MaxConnUsed INT,
    Queries INT,
    Bytes_data_sent INT,
    Bytes_data_recv INT,
    Latency_us INT
)
```

### 2.7 stats_pgsql_free_connections

```sql
CREATE TABLE stats_pgsql_free_connections (
    fd INT NOT NULL,
    hostgroup INT NOT NULL,
    srv_host VARCHAR NOT NULL,
    srv_port INT NOT NULL,
    user VARCHAR NOT NULL,
    database VARCHAR,
    init_connect VARCHAR,
    time_zone VARCHAR,
    sql_mode VARCHAR,
    idle_ms INT,
    statistics VARCHAR,
    pgsql_info VARCHAR
)
```

### 2.8 stats_pgsql_query_digest

```sql
CREATE TABLE stats_pgsql_query_digest (
    hostgroup INT,
    database VARCHAR NOT NULL,
    username VARCHAR NOT NULL,
    client_address VARCHAR NOT NULL,
    digest VARCHAR NOT NULL,
    digest_text VARCHAR NOT NULL,
    count_star INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    sum_time INTEGER NOT NULL,
    min_time INTEGER NOT NULL,
    max_time INTEGER NOT NULL,
    sum_rows_affected INTEGER NOT NULL,
    sum_rows_sent INTEGER NOT NULL,
    PRIMARY KEY(hostgroup, database, username, client_address, digest)
)
```

**Note:** This table uses `database` column, unlike MySQL which uses `schemaname`. However, the historical table `history_pgsql_query_digest` uses `schemaname` for consistency with MySQL history tables.

### 2.9 stats_pgsql_prepared_statements_info

```sql
CREATE TABLE stats_pgsql_prepared_statements_info (
    global_stmt_id INT NOT NULL,
    database VARCHAR NOT NULL,
    username VARCHAR NOT NULL,
    digest VARCHAR NOT NULL,
    ref_count_client INT NOT NULL,
    ref_count_server INT NOT NULL,
    num_param_types INT NOT NULL,
    query VARCHAR NOT NULL
)
```

### 2.10 stats_pgsql_global

```sql
CREATE TABLE stats_pgsql_global (
    Variable_Name VARCHAR NOT NULL PRIMARY KEY,
    Variable_Value VARCHAR NOT NULL
)
```

**Complete Variable List:**

This table uses a key-value format, similar to `stats_mysql_global`. Variables are populated from `PgSQL_Threads_Handler::SQL3_GlobalStatus()` in `lib/PgSQL_Thread.cpp` and other sources.

> **Note:** The PgSQL global stats are less mature than MySQL. Many counter/gauge arrays present in the MySQL path are commented out in the PgSQL code. The active variables are listed below.

**System / Uptime**

| Variable Name | Description | Type |
|---|---|---|
| `ProxySQL_Uptime` | Seconds since ProxySQL started | Gauge |

**Client Connection Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `Active_Transactions` | Currently active transactions | Gauge |
| `Client_Connections_aborted` | Total aborted client connections | Counter |
| `Client_Connections_connected` | Currently connected clients | Gauge |
| `Client_Connections_created` | Total client connections ever created | Counter |
| `Client_Connections_non_idle` | Non-idle client connections (requires `IDLE_THREADS`) | Gauge |

**Server Connection Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `Server_Connections_aborted` | Total aborted server connections | Counter |
| `Server_Connections_connected` | Currently connected backend servers | Gauge |
| `Server_Connections_created` | Total server connections ever created | Counter |
| `Server_Connections_delayed` | Connections delayed due to throttling | Counter |

**Memory Buffer Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `pgsql_backend_buffers_bytes` | Memory used by backend connection buffers | Gauge |
| `pgsql_frontend_buffers_bytes` | Memory used by frontend connection buffers | Gauge |
| `pgsql_session_internal_bytes` | Memory used by internal session structures | Gauge |

**Transaction Command Counters**

| Variable Name | Description | Type |
|---|---|---|
| `Commit` | COMMIT statements executed | Counter |
| `Commit_filtered` | COMMIT statements filtered | Counter |
| `Rollback` | ROLLBACK statements executed | Counter |
| `Rollback_filtered` | ROLLBACK statements filtered | Counter |

**Backend Command Counters**

| Variable Name | Description | Type |
|---|---|---|
| `Backend_reset_connection` | Backend connection resets | Counter |
| `Backend_set_client_encoding` | Backend SET client_encoding commands | Counter |
| `Frontend_set_client_encoding` | Frontend SET client_encoding commands | Counter |

**Mirror Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `Mirror_concurrency` | Current number of mirror sessions | Gauge |
| `Mirror_queue_length` | Current mirror queue length | Gauge |

**Miscellaneous Status**

| Variable Name | Description | Type |
|---|---|---|
| `Selects_for_update__autocommit0` | SELECT FOR UPDATE with autocommit=0 | Counter |
| `Servers_table_version` | Current version of the servers table | Gauge |
| `PgSQL_Thread_Workers` | Number of PgSQL thread workers | Gauge |
| `pgsql_listener_paused` | Whether the PgSQL listener is paused (0/1) | Gauge |

**Access Denied Counters**

| Variable Name | Description | Type |
|---|---|---|
| `Access_Denied_Wrong_Password` | Access denied due to wrong password | Counter |
| `Access_Denied_Max_Connections` | Access denied due to max connections | Counter |
| `Access_Denied_Max_User_Connections` | Access denied due to max user connections | Counter |

**PgSQL Monitor Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `PgSQL_Monitor_connect_check_OK` | Successful monitor connect checks | Counter |
| `PgSQL_Monitor_connect_check_ERR` | Failed monitor connect checks | Counter |
| `PgSQL_Monitor_ping_check_OK` | Successful monitor ping checks | Counter |
| `PgSQL_Monitor_ping_check_ERR` | Failed monitor ping checks | Counter |
| `PgSQL_Monitor_read_only_check_OK` | Successful read-only checks | Counter |
| `PgSQL_Monitor_read_only_check_ERR` | Failed read-only checks | Counter |
| `PgSQL_Monitor_ssl_connections_OK` | Successful SSL monitor connections | Counter |
| `PgSQL_Monitor_non_ssl_connections_OK` | Successful non-SSL monitor connections | Counter |

**Connection Pool Operation Counters**

| Variable Name | Description | Type |
|---|---|---|
| `PgHGM_pgconnpoll_get` | Total connection pool get operations | Counter |
| `PgHGM_pgconnpoll_get_ok` | Successful pool get operations | Counter |
| `PgHGM_pgconnpoll_push` | Connections returned to pool | Counter |
| `PgHGM_pgconnpoll_destroy` | Connections destroyed from pool | Counter |
| `PgHGM_pgconnpoll_reset` | Connection pool resets | Counter |

**Memory Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `SQLite3_memory_bytes` | SQLite3 internal memory usage | Gauge |
| `ConnPool_memory_bytes` | Connection pool memory usage | Gauge |

**Prepared Statement Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `Stmt_Client_Active_Total` | Total active client-side prepared statements | Gauge |
| `Stmt_Client_Active_Unique` | Unique active client-side prepared statements | Gauge |
| `Stmt_Server_Active_Total` | Total active server-side prepared statements | Gauge |
| `Stmt_Server_Active_Unique` | Unique active server-side prepared statements | Gauge |
| `Stmt_Max_Stmt_id` | Maximum prepared statement ID assigned | Gauge |
| `Stmt_Cached` | Cached prepared statements | Gauge |

**Query Cache Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `Query_Cache_Memory_bytes` | Memory used by query cache | Gauge |
| `Query_Cache_count_GET` | Query cache GET operations | Counter |
| `Query_Cache_count_GET_OK` | Successful query cache GETs | Counter |
| `Query_Cache_count_SET` | Query cache SET operations | Counter |
| `Query_Cache_bytes_IN` | Bytes written into query cache | Counter |
| `Query_Cache_bytes_OUT` | Bytes read from query cache | Counter |
| `Query_Cache_Purged` | Query cache entries purged | Counter |
| `Query_Cache_Entries` | Current query cache entries | Gauge |

**Query Processor Metrics**

| Variable Name | Description | Type |
|---|---|---|
| `new_req_conns_count` | New request connections count from query processor | Counter |

**Source References**

Variables are aggregated from these code locations:
- `PgSQL_Threads_Handler::SQL3_GlobalStatus()` in `lib/PgSQL_Thread.cpp`
- `PgSQL_HostGroups_Manager::SQL3_Get_ConnPool_Stats()` in `lib/PgSQL_HostGroups_Manager.cpp`
- `ProxySQL_Admin::stats___pgsql_global()` in `lib/ProxySQL_Admin_Stats.cpp`
- `Query_Cache::SQL3_getStats()` in `lib/Query_Cache.cpp`

### 2.11 stats_pgsql_errors

```sql
CREATE TABLE stats_pgsql_errors (
    hostgroup INT NOT NULL,
    hostname VARCHAR NOT NULL,
    port INT NOT NULL,
    username VARCHAR NOT NULL,
    client_address VARCHAR NOT NULL,
    database VARCHAR NOT NULL,
    sqlstate VARCHAR NOT NULL,
    count_star INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    last_error VARCHAR NOT NULL DEFAULT '',
    PRIMARY KEY (hostgroup, hostname, port, username, database, sqlstate)
)
```

### 2.12 stats_pgsql_client_host_cache

```sql
CREATE TABLE stats_pgsql_client_host_cache (
    client_address VARCHAR NOT NULL,
    error_count INT NOT NULL,
    last_updated BIGINT NOT NULL
)
```

### 2.13 MySQL vs PostgreSQL Column Naming

ProxySQL uses different column names for the same concept between MySQL and PostgreSQL tables:

| Concept | MySQL Column | PostgreSQL Column | Notes |
|---------|--------------|-------------------|-------|
| Database/Schema | `schemaname` | `database` | Different naming convention |
| Error Code | `errno` | `sqlstate` | MySQL uses numeric codes, PostgreSQL uses 5-char SQLSTATE |
| Backend Info | `mysql_info` | `pgsql_info` | In free_connections tables |
| Process DB | `db` | `database` | In processlist tables |

**Note on History Tables:** The `history_pgsql_query_digest` table uses `schemaname` (matching MySQL convention) rather than `database`, creating an inconsistency with the live `stats_pgsql_query_digest` table.

## 3. Cluster Statistics Tables

Tables for monitoring ProxySQL cluster nodes.

### 3.1 stats_proxysql_servers_clients_status

```sql
CREATE TABLE stats_proxysql_servers_clients_status (
    uuid VARCHAR NOT NULL,
    hostname VARCHAR NOT NULL,
    port INT NOT NULL,
    admin_mysql_ifaces VARCHAR NOT NULL,
    last_seen_at INT NOT NULL,
    PRIMARY KEY (uuid, hostname, port)
)
```

### 3.2 stats_proxysql_servers_status

```sql
CREATE TABLE stats_proxysql_servers_status (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 6032,
    weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0,
    master VARCHAR NOT NULL,
    global_version INT NOT NULL,
    check_age_us INT NOT NULL,
    ping_time_us INT NOT NULL,
    checks_OK INT NOT NULL,
    checks_ERR INT NOT NULL,
    PRIMARY KEY (hostname, port)
)
```

### 3.3 stats_proxysql_servers_metrics

```sql
CREATE TABLE stats_proxysql_servers_metrics (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 6032,
    weight INT CHECK (weight >= 0) NOT NULL DEFAULT 0,
    comment VARCHAR NOT NULL DEFAULT '',
    response_time_ms INT NOT NULL,
    Uptime_s INT NOT NULL,
    last_check_ms INT NOT NULL,
    Queries INT NOT NULL,
    Client_Connections_connected INT NOT NULL,
    Client_Connections_created INT NOT NULL,
    PRIMARY KEY (hostname, port)
)
```

### 3.4 stats_proxysql_servers_checksums

```sql
CREATE TABLE stats_proxysql_servers_checksums (
    hostname VARCHAR NOT NULL,
    port INT NOT NULL DEFAULT 6032,
    name VARCHAR NOT NULL,
    version INT NOT NULL,
    epoch INT NOT NULL,
    checksum VARCHAR NOT NULL,
    changed_at INT NOT NULL,
    updated_at INT NOT NULL,
    diff_check INT NOT NULL,
    PRIMARY KEY (hostname, port, name)
)
```

### 3.5 stats_proxysql_message_metrics

Message/metric tracking for ProxySQL internal use.

```sql
CREATE TABLE stats_proxysql_message_metrics (
    message_id VARCHAR NOT NULL,
    filename VARCHAR NOT NULL,
    line INT CHECK (line >= 0) NOT NULL DEFAULT 0,
    func VARCHAR NOT NULL,
    count_star INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (filename, line, func)
)
```

## 4. Historical Statistics Tables

Tables stored in the persistent statsdb_disk database with time-series data.

### 4.1 Connection Metrics

#### 4.1.1 mysql_connections

Connection statistics by timestamp.

```sql
CREATE TABLE mysql_connections (
    timestamp INT NOT NULL,
    Client_Connections_aborted INT NOT NULL,
    Client_Connections_connected INT NOT NULL,
    Client_Connections_created INT NOT NULL,
    Server_Connections_aborted INT NOT NULL,
    Server_Connections_connected INT NOT NULL,
    Server_Connections_created INT NOT NULL,
    ConnPool_get_conn_failure INT NOT NULL,
    ConnPool_get_conn_immediate INT NOT NULL,
    ConnPool_get_conn_success INT NOT NULL,
    Questions INT NOT NULL,
    Slow_queries INT NOT NULL,
    GTID_consistent_queries INT NOT NULL,
    PRIMARY KEY (timestamp)
)
```

#### 4.1.2 mysql_connections_hour

Hourly aggregated connection metrics.

#### 4.1.3 mysql_connections_day

Daily aggregated connection metrics.

### 4.2 Connection Pool History

#### 4.2.1 history_stats_mysql_connection_pool

Historical connection pool metrics by timestamp.

```sql
CREATE TABLE history_stats_mysql_connection_pool (
    timestamp INT NOT NULL,
    hostgroup INT,
    srv_host VARCHAR,
    srv_port INT,
    status VARCHAR,
    ConnUsed INT,
    ConnFree INT,
    ConnOK INT,
    ConnERR INT,
    MaxConnUsed INT,
    Queries INT,
    Queries_GTID_sync INT,
    Bytes_data_sent INT,
    Bytes_data_recv INT,
    Latency_us INT,
    PRIMARY KEY (timestamp, hostgroup, srv_host, srv_port)
)
```

### 4.3 MyHGM (MySQL Host Group Manager) Metrics

#### 4.3.1 myhgm_connections

MyHGM internal connection metrics.

```sql
CREATE TABLE myhgm_connections (
    timestamp INT NOT NULL,
    MyHGM_myconnpoll_destroy INT NOT NULL,
    MyHGM_myconnpoll_get INT NOT NULL,
    MyHGM_myconnpoll_get_ok INT NOT NULL,
    MyHGM_myconnpoll_push INT NOT NULL,
    MyHGM_myconnpoll_reset INT NOT NULL,
    PRIMARY KEY (timestamp)
)
```

### 4.4 MySQL Status Variables History

#### 4.4.1 history_mysql_status_variables

Time-series data for MySQL status variables.

```sql
CREATE TABLE history_mysql_status_variables (
    timestamp INT NOT NULL,
    variable_id INT NOT NULL,
    variable_value VARCHAR NOT NULL,
    PRIMARY KEY (timestamp, variable_id)
)
```

#### 4.4.2 history_mysql_status_variables_lookup

Mapping table for variable names to IDs.

```sql
CREATE TABLE history_mysql_status_variables_lookup (
    variable_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    variable_name VARCHAR NOT NULL,
    UNIQUE (variable_name)
)
```

#### 4.4.3 history_pgsql_status_variables

PostgreSQL status variables history.

#### 4.4.4 history_pgsql_status_variables_lookup

PostgreSQL variable name to ID mapping.

### 4.5 Query Digest History

#### 4.5.1 history_mysql_query_digest

Historical query digest snapshots.

```sql
CREATE TABLE history_mysql_query_digest (
    dump_time INT,
    hostgroup INT,
    schemaname VARCHAR NOT NULL,
    username VARCHAR NOT NULL,
    client_address VARCHAR NOT NULL,
    digest VARCHAR NOT NULL,
    digest_text VARCHAR NOT NULL,
    count_star INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    sum_time INTEGER NOT NULL,
    min_time INTEGER NOT NULL,
    max_time INTEGER NOT NULL,
    sum_rows_affected INTEGER NOT NULL,
    sum_rows_sent INTEGER NOT NULL
)
```

#### 4.5.2 history_pgsql_query_digest

PostgreSQL query digest history.

### 4.6 Query Events History

#### 4.6.1 history_mysql_query_events

Historical query event log.

```sql
CREATE TABLE history_mysql_query_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER,
    username TEXT,
    schemaname TEXT,
    start_time INTEGER,
    end_time INTEGER,
    query_digest TEXT,
    query TEXT,
    server TEXT,
    client TEXT,
    event_type INTEGER,
    hid INTEGER,
    extra_info TEXT,
    affected_rows INTEGER,
    last_insert_id INTEGER,
    rows_sent INTEGER,
    client_stmt_id INTEGER,
    gtid TEXT,
    errno INT,
    error TEXT
)
```

## 5. System Statistics Tables

### 5.1 CPU Metrics

#### 5.1.1 system_cpu

CPU usage statistics.

```sql
CREATE TABLE system_cpu (
    timestamp INT NOT NULL,
    tms_utime INT NOT NULL,
    tms_stime INT NOT NULL,
    PRIMARY KEY (timestamp)
)
```

#### 5.1.2 system_cpu_hour

Hourly aggregated CPU metrics.

#### 5.1.3 system_cpu_day

Daily aggregated CPU metrics.

### 5.2 Memory Metrics

#### 5.2.1 system_memory

Memory usage statistics (requires jemalloc, excluded with NOJEM).

```sql
CREATE TABLE system_memory (
    timestamp INT NOT NULL,
    allocated INT NOT NULL,
    resident INT NOT NULL,
    active INT NOT NULL,
    mapped INT NOT NULL,
    metadata INT NOT NULL,
    retained INT NOT NULL,
    PRIMARY KEY (timestamp)
)
```

#### 5.2.2 system_memory_hour

Hourly aggregated memory metrics.

#### 5.2.3 system_memory_day

Daily aggregated memory metrics.

### 5.3 Query Cache Metrics

#### 5.3.1 mysql_query_cache

Query cache statistics.

```sql
CREATE TABLE mysql_query_cache (
    timestamp INT NOT NULL,
    count_GET INT NOT NULL,
    count_GET_OK INT NOT NULL,
    count_SET INT NOT NULL,
    bytes_IN INT NOT NULL,
    bytes_OUT INT NOT NULL,
    Entries_Purged INT NOT NULL,
    Entries_In_Cache INT NOT NULL,
    Memory_Bytes INT NOT NULL,
    PRIMARY KEY (timestamp)
)
```

#### 5.3.2 mysql_query_cache_hour

Hourly aggregated query cache metrics.

#### 5.3.3 mysql_query_cache_day

Daily aggregated query cache metrics.

## 6. Table Reset Pattern

Many stats tables have a `*_reset` counterpart:

- `stats_mysql_connection_pool_reset`
- `stats_mysql_query_digest_reset`
- `stats_mysql_errors_reset`
- `stats_mysql_client_host_cache_reset`
- `stats_pgsql_connection_pool_reset`
- `stats_pgsql_query_digest_reset`
- `stats_pgsql_errors_reset`
- `stats_pgsql_client_host_cache_reset`
- `stats_proxysql_message_metrics_reset`

**Purpose:** Allow preserving current stats before resetting. Reset is typically done by:
1. Reading from the regular table
2. Inserting into the `_reset` table
3. Resetting the regular table counters

## 7. Database Architecture

### 7.1 stats (In-Memory Database)

Contains real-time statistics tables prefixed with `stats_*`. This database is attached to the main admin database as the `stats` schema.

### 7.2 statsdb_disk (Persistent Database)

Contains historical tables with time-series data. Attached as `stats_history` schema. Includes:
- Hourly aggregated tables (suffixed with `_hour`)
- Daily aggregated tables (suffixed with `_day`)
- Full-resolution history tables (prefixed with `history_`)

### 7.3 statsdb_mem (Internal In-Memory)

Internal statistics database used by ProxySQL for metrics collection and aggregation.

## 8. Data Characteristics and Example Queries

ProxySQL stats tables fall into a few distinct categories based on how they store data.

### 8.1 Key-Value Tables

These tables store metrics as `(Variable_Name, Variable_Value)` rows, where each row is a different metric.

| Table | Description |
|---|---|
| `stats_mysql_global` | ~129 variables covering connections, queries, monitors, caches, and more. Mix of counters (cumulative since startup) and gauges (current value). |
| `stats_pgsql_global` | ~59 variables, same structure as the MySQL counterpart. |
| `stats_memory_metrics` | ~21 variables tracking memory usage across modules. All values in bytes. |

**Example - Reading individual metrics:**
```sql
SELECT Variable_Value FROM stats_mysql_global
WHERE Variable_Name = 'Client_Connections_connected';
```

**Example - Pivoting multiple metrics into a single row:**
```sql
SELECT
  MAX(CASE WHEN Variable_Name = 'Client_Connections_connected' THEN Variable_Value END) AS connected,
  MAX(CASE WHEN Variable_Name = 'Client_Connections_created' THEN Variable_Value END) AS created,
  MAX(CASE WHEN Variable_Name = 'Questions' THEN Variable_Value END) AS questions
FROM stats_mysql_global;
```

### 8.2 Per-Entity Tables

Each row represents one instance of an entity (a backend server, a query pattern, a user, etc.), with numeric columns sharing the same meaning across rows.

| Table | Each Row Represents |
|---|---|
| `stats_mysql_connection_pool` | A backend server in a hostgroup |
| `stats_mysql_query_digest` | A unique query pattern (by digest) |
| `stats_mysql_commands_counters` | A MySQL command type |
| `stats_mysql_users` | A frontend user |
| `stats_mysql_errors` | An error type per server/user combination |
| `stats_mysql_query_rules` | A query rule |
| `stats_mysql_client_host_cache` | A client host |
| `stats_mysql_prepared_statements_info` | A prepared statement |

**Example - Connection pool summary by hostgroup:**
```sql
SELECT
  hostgroup,
  SUM(ConnUsed) AS total_used,
  SUM(ConnFree) AS total_free,
  SUM(Queries) AS total_queries,
  AVG(Latency_us) AS avg_latency_us
FROM stats_mysql_connection_pool
GROUP BY hostgroup;
```

**Example - Top 10 slowest query digests:**
```sql
SELECT digest_text, count_star,
  sum_time / count_star AS avg_time_us,
  max_time AS max_time_us
FROM stats_mysql_query_digest
ORDER BY sum_time DESC
LIMIT 10;
```

**Example - Error distribution by hostgroup:**
```sql
SELECT hostgroup, errno, SUM(count_star) AS total_errors
FROM stats_mysql_errors
GROUP BY hostgroup, errno
ORDER BY total_errors DESC;
```

### 8.3 Snapshot / Event Tables

These tables capture live state or individual events. Their contents change constantly and are primarily useful for real-time debugging.

| Table | Each Row Represents |
|---|---|
| `stats_mysql_processlist` | A currently active session |
| `stats_mysql_query_events` | An individual query event (log entry) |
| `stats_mysql_free_connections` | A currently idle connection in the pool |

### 8.4 Historical / Time-Series Tables

Stored in the persistent `statsdb_disk` database, these tables record timestamped snapshots at different granularities for trend analysis.

| Table | Granularity |
|---|---|
| `mysql_connections` | Per-minute |
| `mysql_connections_hour` | Hourly |
| `mysql_connections_day` | Daily |
| `history_stats_mysql_connection_pool` | Per-minute, per-server |
| `system_cpu` / `system_cpu_hour` / `system_cpu_day` | Per-minute / Hourly / Daily |
| `system_memory` / `system_memory_hour` / `system_memory_day` | Per-minute / Hourly / Daily |
| `mysql_query_cache` / `mysql_query_cache_hour` / `mysql_query_cache_day` | Per-minute / Hourly / Daily |

**Example - Connection trends over the last hour:**
```sql
SELECT timestamp, Questions, Client_Connections_connected
FROM mysql_connections
WHERE timestamp > strftime('%s','now','-1 hour');
```

### 8.5 Data Collection Triggers

Different tables are populated through different mechanisms:

#### Timer-Based Collection

Historical time-series tables are populated by periodic timers in the admin thread. Each metric type has its own configurable interval:

| Admin Variable | Controls | Default | Valid Range |
|---|---|---|---|
| `admin-stats_mysql_connections` | `mysql_connections`, `myhgm_connections` tables | 60s | 0-300s |
| `admin-stats_system_cpu` | `system_cpu` table | 60s | 0-600s |
| `admin-stats_system_memory` | `system_memory` table (requires jemalloc) | 60s | 0-600s |
| `admin-stats_mysql_query_cache` | `mysql_query_cache` table | 60s | 0-300s |
| `admin-stats_mysql_query_digest_to_disk` | `history_mysql_query_digest` table | 0 (disabled) | 0+ seconds |
| `admin-stats_mysql_connection_pool` | `history_stats_mysql_connection_pool` table | 60s | 0-300s |

Setting a variable to `0` disables collection for that metric type.

**Allowed Discrete Intervals:** Values are rounded to the nearest allowed interval: 0, 1, 5, 10, 30, 60, 120, 300, or 600 seconds.

#### Per-Query Updates

These tables are updated in real-time as queries execute:

| Table | Update Trigger |
|---|---|
| `stats_mysql_query_digest` | After each query completes, stats are aggregated into the in-memory digest map |
| `stats_mysql_commands_counters` | After each command completes |
| `stats_mysql_query_rules` | When a query rule is matched |
| `stats_mysql_errors` | When an error occurs |

#### On-Demand / Manual Collection

| Table | Trigger |
|---|---|
| `stats_mysql_query_events` | `DUMP EVENTSLOG FROM BUFFER TO MEMORY` command |
| `history_mysql_query_events` | `DUMP EVENTSLOG FROM BUFFER TO DISK` command |
| `history_mysql_query_digest` | `SAVE MYSQL DIGEST TO DISK` command or periodic timer |

### 8.6 Retention Policies

Historical tables in `statsdb_disk` have automatic retention management:

| Table Type | Retention Period | Cleanup Trigger |
|---|---|---|
| Raw tables (`mysql_connections`, `system_cpu`, etc.) | **7 days** | On each new data insertion |
| Hourly aggregated tables (`*_hour`) | **365 days** | On each new data insertion |
| Daily aggregated tables (`*_day`) | Not populated | N/A |

**Note:** The `*_day` tables are defined in the schema but are **never populated** by the current codebase. Only raw and hourly granularities contain data.

Retention cleanup happens automatically after each data insertion. For example, after inserting a new row into `system_cpu`, rows older than 7 days are deleted, and then the hourly aggregation is checked and performed if needed.

### 8.7 Aggregation Methods for Hourly Tables

When raw data is aggregated into `_hour` tables, different columns use different aggregation functions based on their metric type:

#### `system_cpu_hour`

| Column | Aggregation | Reasoning |
|---|---|---|
| `tms_utime` | **SUM** | CPU time is cumulative; sum gives total ticks in the hour |
| `tms_stime` | **SUM** | Same as above |

#### `system_memory_hour`

| Column | Aggregation | Reasoning |
|---|---|---|
| `allocated` | **AVG** | Memory is a point-in-time gauge; average gives representative value |
| `resident` | **AVG** | Same as above |
| `active` | **AVG** | Same as above |
| `mapped` | **AVG** | Same as above |
| `metadata` | **AVG** | Same as above |
| `retained` | **AVG** | Same as above |

#### `mysql_connections_hour`

| Column | Aggregation | Reasoning |
|---|---|---|
| `Client_Connections_aborted` | **MAX** | Counter - MAX captures end-of-hour cumulative value |
| `Client_Connections_connected` | **AVG** | Gauge - AVG gives average connections during the hour |
| `Client_Connections_created` | **MAX** | Counter |
| `Server_Connections_aborted` | **MAX** | Counter |
| `Server_Connections_connected` | **AVG** | Gauge |
| `Server_Connections_created` | **MAX** | Counter |
| `ConnPool_get_conn_failure` | **MAX** | Counter |
| `ConnPool_get_conn_immediate` | **MAX** | Counter |
| `ConnPool_get_conn_success` | **MAX** | Counter |
| `Questions` | **MAX** | Counter |
| `Slow_queries` | **MAX** | Counter |
| `GTID_consistent_queries` | **MAX** | Counter |

#### `mysql_query_cache_hour`

| Column | Aggregation | Reasoning |
|---|---|---|
| `count_GET` | **MAX** | Counter |
| `count_GET_OK` | **MAX** | Counter |
| `count_SET` | **MAX** | Counter |
| `bytes_IN` | **MAX** | Counter |
| `bytes_OUT` | **MAX** | Counter |
| `Entries_Purged` | **MAX** | Counter |
| `Entries_In_Cache` | **AVG** | Gauge |
| `Memory_Bytes` | **AVG** | Gauge |

#### `myhgm_connections_hour`

| Column | Aggregation | Reasoning |
|---|---|---|
| `MyHGM_myconnpoll_destroy` | **MAX** | Counter |
| `MyHGM_myconnpoll_get` | **MAX** | Counter |
| `MyHGM_myconnpoll_get_ok` | **MAX** | Counter |
| `MyHGM_myconnpoll_push` | **MAX** | Counter |
| `MyHGM_myconnpoll_reset` | **MAX** | Counter |

**Aggregation Timing:** Hourly aggregation is performed lazily. Each time a new raw row is inserted, the system checks if the current time is at least 3600 seconds past the last hourly entry. If so, it runs the aggregation INSERT for the completed hour(s).

### 8.8 Buffer and Flush Mechanics

Some tables require explicit flush operations to make data visible.

#### Query Events Buffer

Query events are first collected into a **circular buffer** in memory, not directly into SQLite tables.

**Data Flow:**
```text
Query executes
    ↓
MySQL_Logger::log_request() adds event to circular buffer (MyLogCB)
    ↓
Buffer accumulates events (size controlled by mysql_eventslog_table_memory_size)
    ↓
Manual DUMP command drains buffer to SQLite tables
```

**Flush Commands:**

| Command | Destination |
|---|---|
| `DUMP EVENTSLOG FROM BUFFER TO MEMORY` | `stats_mysql_query_events` (in-memory) |
| `DUMP EVENTSLOG FROM BUFFER TO DISK` | `history_mysql_query_events` (on-disk) |
| `DUMP EVENTSLOG FROM BUFFER TO BOTH` | Both tables |

**Important:** The `get_all_events()` operation **drains** the buffer. Once flushed, events are removed from the buffer. There is no way to peek at buffer contents without draining.

**Retention Differences:**
- `stats_mysql_query_events`: Capped to `eventslog_table_memory_size` entries; oldest rows evicted when full
- `history_mysql_query_events`: Append-only, no automatic eviction

#### Query Digest Snapshot

Query digest statistics are maintained in an in-memory hash map (`digest_umap`), not in SQLite. The map is updated in real-time as queries complete.

**Reading Live Data (Non-Destructive):**

When you `SELECT FROM stats_mysql_query_digest`, ProxySQL:
1. Briefly swaps the live map with an empty map
2. Serializes the swapped data to an in-memory SQLite table
3. Merges any new entries accumulated during serialization back into the map
4. Executes your query against the SQLite table

This is a **non-destructive** read — the data is preserved.

**Saving to History (Destructive):**

When you run `SAVE MYSQL DIGEST TO DISK` (or the periodic timer triggers):
1. The live map is atomically swapped with an empty map
2. The swapped data is written to `history_mysql_query_digest` with a `dump_time` column
3. The swapped data is deleted — **the live map is now empty**
4. New queries immediately start accumulating in the fresh empty map

**Snapshot Characteristics:**
- Each `SAVE` produces a batch of rows with the same `dump_time`
- Each snapshot represents stats accumulated **since the previous save**
- The same digest can appear in multiple snapshots with different counts
- `first_seen`/`last_seen` timestamps are converted from monotonic to wall-clock time

### 8.9 PostgreSQL Table Coverage

Not all tables have PostgreSQL equivalents. Here is the coverage matrix:

#### Live Statistics Tables

| MySQL Table | PostgreSQL Equivalent | Notes |
|---|---|---|
| `stats_mysql_global` | `stats_pgsql_global` | PostgreSQL has ~59 variables vs MySQL's ~129 |
| `stats_mysql_processlist` | `stats_pgsql_processlist` | Includes additional `backend_pid`, `backend_state` columns |
| `stats_mysql_query_digest` | `stats_pgsql_query_digest` | Uses `database` instead of `schemaname` |
| `stats_mysql_connection_pool` | `stats_pgsql_connection_pool` | No `Queries_GTID_sync` column |
| `stats_mysql_free_connections` | `stats_pgsql_free_connections` | Uses `database` and `pgsql_info` columns |
| `stats_mysql_commands_counters` | `stats_pgsql_commands_counters` | Full equivalent |
| `stats_mysql_users` | `stats_pgsql_users` | Full equivalent |
| `stats_mysql_errors` | `stats_pgsql_errors` | Uses `sqlstate` instead of `errno` |
| `stats_mysql_query_rules` | `stats_pgsql_query_rules` | Full equivalent |
| `stats_mysql_client_host_cache` | `stats_pgsql_client_host_cache` | Full equivalent |
| `stats_mysql_prepared_statements_info` | `stats_pgsql_prepared_statements_info` | Uses `database`, `num_param_types` columns |
| `stats_mysql_gtid_executed` | — | **MySQL only** (GTID is MySQL-specific) |
| `stats_mysql_query_events` | — | **MySQL only** |

#### Historical Tables

| MySQL Table | PostgreSQL Equivalent | Notes |
|---|---|---|
| `history_mysql_query_digest` | `history_pgsql_query_digest` | Full equivalent |
| `history_mysql_query_events` | — | **MySQL only** |
| `mysql_connections` | — | **MySQL only** |
| `mysql_connections_hour` | — | **MySQL only** |
| `myhgm_connections` | — | **MySQL only** |
| `myhgm_connections_hour` | — | **MySQL only** |
| `history_stats_mysql_connection_pool` | — | **MySQL only** |
| `mysql_query_cache` | — | **MySQL only** |
| `mysql_query_cache_hour` | — | **MySQL only** |
| `history_mysql_status_variables` | `history_pgsql_status_variables` | Full equivalent |

#### Shared Tables (Database-Agnostic)

These tables are shared between MySQL and PostgreSQL as they track ProxySQL itself:

- `stats_proxysql_servers_status`
- `stats_proxysql_servers_metrics`
- `stats_proxysql_servers_checksums`
- `stats_proxysql_servers_clients_status`
- `stats_memory_metrics`
- `system_cpu` / `system_cpu_hour`
- `system_memory` / `system_memory_hour`

## 9. Common Notes

1. **Schema Versioning:** Tables have version-specific definitions; current versions are aliased without version suffixes.

2. **Reset Capability:** Most counters support reset via `*_reset` tables.

3. **Time Units:**
   - `*_us` = microseconds
   - `*_ms` = milliseconds
   - `*_s` = seconds
   - Unqualified timestamps are Unix epoch (seconds)

4. **Primary Keys:** Most tables use composite keys for efficient data aggregation.

5. **Nullable Columns:** Some columns may be `NULL` depending on configuration (e.g., `status`, `port`, `hostgroup`).

6. **Views:** Some tables like `stats_pgsql_stat_activity` are actually views and cannot be dropped or modified directly.

7. **Performance Considerations:** Historical tables can grow large; ProxySQL manages retention through hourly/daily aggregation tables.

## 10. File References

Schema definitions are located in:
- `include/ProxySQL_Admin_Tables_Definitions.h` - Stats table definitions
- `include/ProxySQL_Statistics.hpp` - Historical/Time-series table definitions
- `lib/ProxySQL_Statistics.cpp` - Statistics initialization and management
- `lib/Admin_Bootstrap.cpp` - Stats table registration
- `lib/ProxySQL_Admin_Stats.cpp` - Stats table population logic
