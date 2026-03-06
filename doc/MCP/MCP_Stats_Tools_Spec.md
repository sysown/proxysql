# ProxySQL Stats MCP Tools - Specification

This document specifies the MCP tools available on the `/stats` endpoint for monitoring and analyzing ProxySQL statistics.

## Table of Contents

- [1. Overview](#1-overview)
- [2. Response Format Convention](#2-response-format-convention)
- [2.1 Time Field Conventions](#21-time-field-conventions)
- [3. Tool Categories](#3-tool-categories)
- [4. Live Data Tools](#4-live-data-tools)
  - [4.1 show_status](#41-show_status)
  - [4.2 show_processlist](#42-show_processlist)
  - [4.3 show_queries](#43-show_queries)
  - [4.4 show_commands](#44-show_commands)
  - [4.5 show_connections](#45-show_connections)
  - [4.6 show_errors](#46-show_errors)
  - [4.7 show_users](#47-show_users)
  - [4.8 show_client_cache](#48-show_client_cache)
  - [4.9 show_query_rules](#49-show_query_rules)
  - [4.10 show_prepared_statements](#410-show_prepared_statements)
  - [4.11 show_gtid](#411-show_gtid)
  - [4.12 show_cluster](#412-show_cluster)
- [5. Historical Data Tools](#5-historical-data-tools)
  - [5.1 show_system_history](#51-show_system_history)
  - [5.2 show_query_cache_history](#52-show_query_cache_history)
  - [5.3 show_connection_history](#53-show_connection_history)
  - [5.4 show_query_history](#54-show_query_history)
- [6. Utility Tools](#6-utility-tools)
  - [6.1 flush_query_log](#61-flush_query_log)
  - [6.2 show_query_log](#62-show_query_log)
  - [6.3 flush_queries](#63-flush_queries)

---

## 1. Overview

The `/stats` endpoint provides tools for monitoring ProxySQL performance, health, and operational metrics. Tools are organized into three categories:

- **Live Data Tools** - Real-time statistics and current state
- **Historical Data Tools** - Time-series data for trend analysis
- **Utility Tools** - Data management operations (flush, sync)

All tools support both MySQL and PostgreSQL where applicable, controlled by a `db_type` parameter.
`flush_query_log` and `flush_queries` are write-capable operations and should be protected via endpoint authentication.

---

## 2. Response Format Convention

All tools follow the MCP JSON-RPC response format with success/error wrappers.

**Success Response:**
```json
{
  "success": true,
  "result": {
    // Tool-specific result data
  }
}
```

**Error Response:**
```json
{
  "success": false,
  "error": "Error message describing what went wrong"
}
```

---

## 2.1 Time Field Conventions

All tools follow consistent naming conventions for time-related fields:

| Suffix | Unit | Example Fields |
|--------|------|----------------|
| `_us` | Microseconds | `sum_time_us`, `min_time_us`, `max_time_us`, `latency_us`, `ping_time_us` |
| `_ms` | Milliseconds | `time_ms`, `idle_ms` |
| (none) | Unix timestamp (seconds since epoch) | `first_seen`, `last_seen`, `timestamp`, `dump_time` |

**Notes:**
- Response field names may differ from database column names for clarity and consistency
- All duration/latency measurements use microseconds (`_us`) unless milliseconds provide more natural values (e.g., session duration)
- All timestamps are Unix epoch timestamps in seconds

---

## 3. Tool Categories

### Live Data Tools (12 tools)

| Tool | Description |
|---|---|
| `show_status` | Global status variables and metrics |
| `show_processlist` | Currently active sessions |
| `show_queries` | Query digest performance statistics |
| `show_commands` | Command execution counters with latency histograms |
| `show_connections` | Backend connection pool metrics |
| `show_errors` | Error tracking and frequency |
| `show_users` | User connection statistics |
| `show_client_cache` | Client host error cache |
| `show_query_rules` | Query rule hit counts |
| `show_prepared_statements` | Prepared statement information |
| `show_gtid` | GTID replication status (MySQL only) |
| `show_cluster` | ProxySQL cluster node health |

### Historical Data Tools (4 tools)

| Tool | Description |
|---|---|
| `show_system_history` | CPU and memory trends over time |
| `show_query_cache_history` | Query cache performance trends |
| `show_connection_history` | Connection metrics history |
| `show_query_history` | Query digest snapshots over time |

### Utility Tools (3 tools)

| Tool | Description |
|---|---|
| `flush_query_log` | Flush query events from buffer to tables |
| `show_query_log` | View query event audit log |
| `flush_queries` | Save query digest statistics to disk |

---

## 4. Live Data Tools

### 4.1 show_status

Returns global status variables and metrics from ProxySQL. Similar to MySQL's `SHOW STATUS` command.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `db_type` | `"mysql"` \| `"pgsql"` | No | `"mysql"` | Database type |
| `category` | string | No | (none) | Filter by category: `connections`, `queries`, `commands`, `pool_ops`, `monitor`, `query_cache`, `prepared_stmts`, `security`, `memory`, `errors`, `logger`, `system`, `mirror` |
| `variable_name` | string | No | (none) | Filter by variable name pattern (supports SQL LIKE with `%` wildcards) |

**Note:** If neither `category` nor `variable_name` is provided, returns all variables grouped by category.

**Response:**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "variables": [
      {
        "variable_name": "Client_Connections_connected",
        "value": "245"
      },
      {
        "variable_name": "Client_Connections_created",
        "value": "15432"
      },
      {
        "variable_name": "Questions",
        "value": "156789"
      }
    ]
  }
}
```

#### Variable Reference

For complete documentation of all available variables including descriptions and types, see:
- **MySQL:** [Stats_Tables.md - stats_mysql_global](../Stats_Tables.md#18-stats_mysql_global) (~102 variables)
- **PostgreSQL:** [Stats_Tables.md - stats_pgsql_global](../Stats_Tables.md#210-stats_pgsql_global) (~51 variables)

**PostgreSQL Notes:** Some variable names differ between MySQL and PostgreSQL (e.g., `pgsql_backend_buffers_bytes` instead of `mysql_backend_buffers_bytes`).

---

### 4.2 show_processlist

Shows all currently active sessions being processed by ProxySQL.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `db_type` | `"mysql"` \| `"pgsql"` | No | `"mysql"` | Database type |
| `username` | string | No | (none) | Filter by username |
| `hostgroup` | int | No | (none) | Filter by hostgroup ID |
| `min_time_ms` | int | No | (none) | Only show sessions running longer than N milliseconds |
| `limit` | int | No | `100` | Maximum number of sessions to return |
| `offset` | int | No | `0` | Skip first N results |

**Response:**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "total_sessions": 156,
    "sessions": [
      {
        "session_id": 12345,
        "thread_id": 67,
        "user": "app_user",
        "database": "production_db",
        "client_host": "10.0.1.50",
        "client_port": 54321,
        "hostgroup": 10,
        "backend_host": "db-server-01",
        "backend_port": 3306,
        "command": "Query",
        "time_ms": 234,
        "info": "SELECT * FROM orders WHERE status = 'pending' LIMIT 1000"
      }
    ],
    "summary": {
      "by_user": {
        "app_user": 120,
        "admin_user": 25,
        "report_user": 11
      },
      "by_hostgroup": {
        "10": 100,
        "20": 45,
        "30": 11
      },
      "by_command": {
        "Query": 145,
        "Sleep": 8,
        "Connect": 3
      }
    }
  }
}
```

**PostgreSQL Notes:** PostgreSQL processlist includes additional columns `backend_pid` and `backend_state`.

---

### 4.3 show_queries

Returns aggregated query performance statistics by digest pattern.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `db_type` | `"mysql"` \| `"pgsql"` | No | `"mysql"` | Database type |
| `sort_by` | `"count"` \| `"avg_time"` \| `"sum_time"` \| `"max_time"` \| `"rows_sent"` | No | `"count"` | Sort order |
| `limit` | int | No | `100` | Maximum number of results |
| `offset` | int | No | `0` | Skip first N results |
| `min_count` | int | No | (none) | Only show queries executed at least N times |
| `min_time_us` | int | No | (none) | Only show queries with avg time >= N microseconds |
| `database` | string | No | (none) | Filter by database name |
| `username` | string | No | (none) | Filter by username |
| `hostgroup` | int | No | (none) | Filter by hostgroup ID |
| `digest` | string | No | (none) | Filter by specific query digest |

**Response:**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "total_digests": 1234,
    "queries": [
      {
        "digest": "0x3A2B4C5D6E7F8A9B",
        "digest_text": "SELECT * FROM orders WHERE status = ?",
        "hostgroup": 10,
        "database": "production_db",
        "username": "app_user",
        "client_address": "10.0.1.50",
        "count_star": 15234,
        "first_seen": 1737440000,
        "last_seen": 1737446400,
        "sum_time_us": 45678900,
        "min_time_us": 1200,
        "max_time_us": 234500,
        "avg_time_us": 2998,
        "sum_rows_affected": 0,
        "sum_rows_sent": 15234000
      }
    ],
    "summary": {
      "total_queries": 156789,
      "total_time_us": 987654321
    }
  }
}
```

**PostgreSQL Notes:** MySQL uses the `schemaname` column while PostgreSQL uses the `database` column internally. The tool normalizes both to the `database` field in responses for consistency.

---

### 4.4 show_commands

Returns command execution statistics with latency distribution histograms.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `db_type` | `"mysql"` \| `"pgsql"` | No | `"mysql"` | Database type |
| `command` | string | No | (none) | Filter by specific command (SELECT, INSERT, etc.) |
| `limit` | int | No | `100` | Maximum number of commands to return |
| `offset` | int | No | `0` | Skip first N results |

**Response:**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "commands": [
      {
        "command": "SELECT",
        "total_count": 98765,
        "total_time_us": 234567890,
        "avg_time_us": 2375,
        "latency_histogram": {
          "cnt_100us": 1000,
          "cnt_500us": 5000,
          "cnt_1ms": 15000,
          "cnt_5ms": 40000,
          "cnt_10ms": 25000,
          "cnt_50ms": 10000,
          "cnt_100ms": 2500,
          "cnt_500ms": 200,
          "cnt_1s": 50,
          "cnt_5s": 10,
          "cnt_10s": 5,
          "cnt_INFs": 0
        },
        "percentiles": {
          "p50_us": 6500,
          "p90_us": 35000,
          "p95_us": 75000,
          "p99_us": 120000
        }
      },
      {
        "command": "INSERT",
        "total_count": 45678,
        "total_time_us": 123456789,
        "avg_time_us": 2702,
        "latency_histogram": {
          "cnt_100us": 500,
          "cnt_500us": 2000,
          "cnt_1ms": 8000,
          "cnt_5ms": 20000,
          "cnt_10ms": 10000,
          "cnt_50ms": 4000,
          "cnt_100ms": 1000,
          "cnt_500ms": 150,
          "cnt_1s": 25,
          "cnt_5s": 3,
          "cnt_10s": 0,
          "cnt_INFs": 0
        },
        "percentiles": {
          "p50_us": 5200,
          "p90_us": 28000,
          "p95_us": 55000,
          "p99_us": 95000
        }
      }
    ],
    "summary": {
      "total_commands": 245000,
      "total_time_us": 567890123
    }
  }
}
```

---

### 4.5 show_connections

Returns backend connection pool metrics per server.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `db_type` | `"mysql"` \| `"pgsql"` | No | `"mysql"` | Database type |
| `hostgroup` | int | No | (none) | Filter by hostgroup ID |
| `server` | string | No | (none) | Filter by server (format: `host:port`) |
| `status` | `"ONLINE"` \| `"SHUNNED"` \| `"OFFLINE_SOFT"` \| `"OFFLINE_HARD"` | No | (none) | Filter by server status |
| `detail` | bool | No | `false` | Include free connection details |

**Response:**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "servers": [
      {
        "hostgroup": 10,
        "srv_host": "db-server-01",
        "srv_port": 3306,
        "status": "ONLINE",
        "conn_used": 45,
        "conn_free": 55,
        "conn_ok": 123456,
        "conn_err": 23,
        "max_conn_used": 100,
        "queries": 456789,
        "queries_gtid_sync": 450000,
        "bytes_data_sent": 56789012,
        "bytes_data_recv": 1234567890,
        "latency_us": 1500,
        "utilization_pct": 45.0,
        "error_rate": 0.00019
      }
    ],
    "summary": {
      "total_servers": 5,
      "online_servers": 4,
      "total_conn_used": 180,
      "total_conn_free": 320,
      "total_queries": 2345678,
      "overall_utilization_pct": 36.0,
      "by_status": {
        "ONLINE": 4,
        "SHUNNED": 1,
        "OFFLINE_SOFT": 0,
        "OFFLINE_HARD": 0
      }
    }
  }
}
```

**Response with `detail=true`:**

When `detail=true`, includes an additional `free_connections` array showing individual idle connections:

```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "servers": [...],
    "free_connections": [
      {
        "fd": 123,
        "hostgroup": 10,
        "srv_host": "db-server-01",
        "srv_port": 3306,
        "user": "app_user",
        "schema": "production_db",
        "init_connect": "SET time_zone='UTC'",
        "time_zone": "UTC",
        "sql_mode": "STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION",
        "autocommit": "1",
        "idle_ms": 15000
      }
    ],
    "summary": {...}
  }
}
```

**PostgreSQL Notes:** PostgreSQL does not have the `queries_gtid_sync` column.

---

### 4.6 show_errors

Returns error tracking statistics with frequency analysis.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `db_type` | `"mysql"` \| `"pgsql"` | No | `"mysql"` | Database type |
| `errno` | int | No | (none) | Filter by error number (MySQL) |
| `sqlstate` | string | No | (none) | Filter by SQLSTATE (PostgreSQL) |
| `username` | string | No | (none) | Filter by username |
| `database` | string | No | (none) | Filter by database name |
| `hostgroup` | int | No | (none) | Filter by hostgroup ID |
| `min_count` | int | No | (none) | Only show errors with count >= N |
| `sort_by` | `"count"` \| `"first_seen"` \| `"last_seen"` | No | `"count"` | Sort order |
| `limit` | int | No | `100` | Maximum number of results |
| `offset` | int | No | `0` | Skip first N results |

**Response (MySQL):**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "total_error_types": 12,
    "total_error_count": 234,
    "errors": [
      {
        "hostgroup": 10,
        "hostname": "db-server-01",
        "port": 3306,
        "username": "app_user",
        "client_address": "10.0.1.50",
        "database": "production_db",
        "errno": 1062,
        "count_star": 45,
        "first_seen": 1737440000,
        "last_seen": 1737446400,
        "last_error": "Duplicate entry '123' for key 'PRIMARY'",
        "frequency_per_hour": 7.5
      }
    ],
    "summary": {
      "by_errno": {
        "1062": 45,
        "1045": 12,
        "2003": 5
      },
      "by_hostgroup": {
        "10": 42,
        "20": 20
      }
    }
  }
}
```

**Response (PostgreSQL):**

PostgreSQL uses `sqlstate` instead of `errno`:

```json
{
  "success": true,
  "result": {
    "db_type": "pgsql",
    "total_error_types": 8,
    "total_error_count": 156,
    "errors": [
      {
        "hostgroup": 10,
        "hostname": "pg-server-01",
        "port": 5432,
        "username": "app_user",
        "client_address": "10.0.1.50",
        "database": "production_db",
        "sqlstate": "23505",
        "count_star": 32,
        "first_seen": 1737440000,
        "last_seen": 1737446400,
        "last_error": "duplicate key value violates unique constraint",
        "frequency_per_hour": 5.3
      }
    ],
    "summary": {
      "by_sqlstate": {
        "23505": 32,
        "28P01": 8,
        "08006": 3
      },
      "by_hostgroup": {
        "10": 30,
        "20": 13
      }
    }
  }
}
```

---

### 4.7 show_users

Returns connection statistics per user.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `db_type` | `"mysql"` \| `"pgsql"` | No | `"mysql"` | Database type |
| `username` | string | No | (none) | Filter by specific username |
| `limit` | int | No | `100` | Maximum number of users to return |
| `offset` | int | No | `0` | Skip first N results |

**Response:**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "users": [
      {
        "username": "app_user",
        "frontend_connections": 120,
        "frontend_max_connections": 200,
        "utilization_pct": 60.0,
        "status": "normal"
      },
      {
        "username": "admin_user",
        "frontend_connections": 5,
        "frontend_max_connections": 10,
        "utilization_pct": 50.0,
        "status": "normal"
      },
      {
        "username": "batch_user",
        "frontend_connections": 48,
        "frontend_max_connections": 50,
        "utilization_pct": 96.0,
        "status": "near_limit"
      }
    ],
    "summary": {
      "total_users": 15,
      "total_connections": 245,
      "total_capacity": 500,
      "overall_utilization_pct": 49.0
    }
  }
}
```

**Status Values:**
- `normal` - Below 80% utilization
- `near_limit` - Between 80% and 100% utilization
- `at_limit` - At 100% utilization

---

### 4.8 show_client_cache

Returns client host error cache for connection throttling analysis.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `db_type` | `"mysql"` \| `"pgsql"` | No | `"mysql"` | Database type |
| `client_address` | string | No | (none) | Filter by specific client IP |
| `min_error_count` | int | No | (none) | Only show hosts with error count >= N |
| `limit` | int | No | `100` | Maximum number of hosts to return |
| `offset` | int | No | `0` | Skip first N results |

**Response:**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "hosts": [
      {
        "client_address": "10.0.1.50",
        "error_count": 15,
        "last_updated": 1737446400
      },
      {
        "client_address": "10.0.1.51",
        "error_count": 3,
        "last_updated": 1737445000
      }
    ],
    "summary": {
      "total_hosts": 12,
      "total_errors": 45
    }
  }
}
```

---

### 4.9 show_query_rules

Returns query rule hit statistics.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `db_type` | `"mysql"` \| `"pgsql"` | No | `"mysql"` | Database type |
| `rule_id` | int | No | (none) | Filter by specific rule ID |
| `min_hits` | int | No | (none) | Only show rules with hits >= N |
| `include_zero_hits` | bool | No | `false` | Include rules with zero hits |
| `limit` | int | No | `100` | Maximum number of rules to return |
| `offset` | int | No | `0` | Skip first N results |

**Response:**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "total_rules": 50,
    "rules": [
      {
        "rule_id": 1,
        "hits": 45678
      },
      {
        "rule_id": 2,
        "hits": 23456
      },
      {
        "rule_id": 5,
        "hits": 12345
      }
    ],
    "summary": {
      "total_hits": 234567,
      "rules_with_hits": 35,
      "rules_without_hits": 15
    }
  }
}
```

---

### 4.10 show_prepared_statements

Returns prepared statement information.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `db_type` | `"mysql"` \| `"pgsql"` | No | `"mysql"` | Database type |
| `username` | string | No | (none) | Filter by username |
| `database` | string | No | (none) | Filter by database name |

**Response (MySQL):**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "total_statements": 45,
    "statements": [
      {
        "global_stmt_id": 1,
        "database": "production_db",
        "username": "app_user",
        "digest": "0x3A2B4C5D6E7F8A9B",
        "ref_count_client": 10,
        "ref_count_server": 5,
        "num_columns": 8,
        "num_params": 2,
        "query": "SELECT * FROM orders WHERE id = ? AND status = ?"
      }
    ]
  }
}
```

**Response (PostgreSQL):**

PostgreSQL uses `num_param_types` instead of `num_columns`/`num_params`:

```json
{
  "success": true,
  "result": {
    "db_type": "pgsql",
    "total_statements": 32,
    "statements": [
      {
        "global_stmt_id": 1,
        "database": "production_db",
        "username": "app_user",
        "digest": "0x3A2B4C5D6E7F8A9B",
        "ref_count_client": 8,
        "ref_count_server": 4,
        "num_param_types": 2,
        "query": "SELECT * FROM orders WHERE id = $1 AND status = $2"
      }
    ]
  }
}
```

---

### 4.11 show_gtid

Returns GTID (Global Transaction ID) replication information.

**Note:** This tool is MySQL-only. GTID is a MySQL-specific replication feature. There is no `db_type` parameter.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `hostname` | string | No | (none) | Filter by backend server hostname |
| `port` | int | No | (none) | Filter by backend server port |

**Response:**
```json
{
  "success": true,
  "result": {
    "servers": [
      {
        "hostname": "db-server-01",
        "port": 3306,
        "gtid_executed": "3E11FA47-71CA-11E1-9E33-C80AA9429562:1-12345:23456-56789",
        "events": 678901
      },
      {
        "hostname": "db-server-02",
        "port": 3306,
        "gtid_executed": "3E11FA47-71CA-11E1-9E33-C80AA9429562:1-12340",
        "events": 678500
      }
    ],
    "summary": {
      "total_servers": 3,
      "total_events": 2036703
    }
  }
}
```

---

### 4.12 show_cluster

Returns ProxySQL cluster node health, synchronization status, and configuration checksums.

**Note:** This tool does not have a `db_type` parameter as cluster tables are shared.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `hostname` | string | No | (none) | Filter by specific node hostname |
| `include_checksums` | bool | No | `true` | Include configuration checksums |

**Response:**
```json
{
  "success": true,
  "result": {
    "cluster_health": "healthy",
    "total_nodes": 3,
    "online_nodes": 3,
    "master_node": "proxysql-01:6032",
    "nodes": [
      {
        "hostname": "proxysql-01",
        "port": 6032,
        "weight": 1000,
        "master": true,
        "global_version": 100,
        "check_age_us": 50000,
        "ping_time_us": 1234,
        "checks_ok": 9998,
        "checks_err": 2,
        "check_success_rate": 0.9998,
        "uptime_s": 8640000,
        "queries": 567890,
        "client_connections": 245
      },
      {
        "hostname": "proxysql-02",
        "port": 6032,
        "weight": 1000,
        "master": false,
        "global_version": 100,
        "check_age_us": 48000,
        "ping_time_us": 1456,
        "checks_ok": 9995,
        "checks_err": 5,
        "check_success_rate": 0.9995,
        "uptime_s": 8640000,
        "queries": 534567,
        "client_connections": 230
      }
    ],
    "checksums": [
      {
        "hostname": "proxysql-01",
        "port": 6032,
        "name": "mysql_servers",
        "version": 75,
        "epoch": 1737446400,
        "checksum": "0x1A2B3C4D5E6F",
        "changed_at": 1737440000,
        "updated_at": 1737446400,
        "diff_check": 0
      },
      {
        "hostname": "proxysql-02",
        "port": 6032,
        "name": "mysql_servers",
        "version": 75,
        "epoch": 1737446400,
        "checksum": "0x1A2B3C4D5E6F",
        "changed_at": 1737440000,
        "updated_at": 1737446400,
        "diff_check": 0
      }
    ],
    "summary": {
      "config_in_sync": true,
      "nodes_in_sync": 3,
      "nodes_out_of_sync": 0,
      "total_queries_all_nodes": 1703456,
      "total_client_connections": 735,
      "avg_ping_time_us": 1350
    }
  }
}
```

**Cluster Health Values:**
- `healthy` - All nodes online and in sync
- `degraded` - Some nodes offline or out of sync
- `unhealthy` - Majority of nodes have issues

---

## 5. Historical Data Tools

### 5.1 show_system_history

Returns historical CPU and memory usage trends.

**Note:** This tool does not have a `db_type` parameter as system metrics are shared.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `metric` | `"cpu"` \| `"memory"` \| `"all"` | No | `"all"` | Which metrics to return |
| `interval` | `"30m"` \| `"1h"` \| `"2h"` \| `"4h"` \| `"6h"` \| `"8h"` \| `"12h"` \| `"1d"` \| `"3d"` \| `"7d"` \| `"30d"` \| `"90d"` | No | `"1h"` | How far back to look |

**Table Selection:** Intervals ≤6h use raw tables; intervals ≥8h use hourly aggregated tables.

**Response:**
```json
{
  "success": true,
  "result": {
    "interval": "1h",
    "resolution": "raw",
    "cpu": [
      {
        "timestamp": 1737446400,
        "tms_utime": 12345,
        "tms_stime": 5678
      },
      {
        "timestamp": 1737446460,
        "tms_utime": 12400,
        "tms_stime": 5700
      }
    ],
    "memory": [
      {
        "timestamp": 1737446400,
        "allocated": 536870912,
        "resident": 398458880,
        "active": 304087040,
        "mapped": 524288000,
        "metadata": 10485760,
        "retained": 52428800
      },
      {
        "timestamp": 1737446460,
        "allocated": 540000000,
        "resident": 400000000,
        "active": 306000000,
        "mapped": 525000000,
        "metadata": 10500000,
        "retained": 52500000
      }
    ]
  }
}
```

**Note:** Memory metrics require jemalloc. If ProxySQL was built without jemalloc (`NOJEM`), the `memory` array will be empty.

---

### 5.2 show_query_cache_history

Returns historical query cache performance metrics.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `db_type` | `"mysql"` \| `"pgsql"` | No | `"mysql"` | Database type |
| `interval` | `"30m"` \| `"1h"` \| `"2h"` \| `"4h"` \| `"6h"` \| `"8h"` \| `"12h"` \| `"1d"` \| `"3d"` \| `"7d"` \| `"30d"` \| `"90d"` | No | `"1h"` | How far back to look |

**PostgreSQL Support:** Historical query cache data is only available for MySQL. When `db_type="pgsql"`, this tool returns an error.

**Response:**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "interval": "1h",
    "resolution": "raw",
    "data": [
      {
        "timestamp": 1737446400,
        "count_GET": 45678,
        "count_GET_OK": 38234,
        "count_SET": 12345,
        "bytes_IN": 45678901,
        "bytes_OUT": 234567890,
        "entries_purged": 123,
        "entries_in_cache": 4567,
        "memory_bytes": 52428800,
        "hit_rate": 0.837
      }
    ]
  }
}
```

---

### 5.3 show_connection_history

Returns historical connection metrics at global or per-server level.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `db_type` | `"mysql"` \| `"pgsql"` | No | `"mysql"` | Database type |
| `interval` | `"30m"` \| `"1h"` \| `"2h"` \| `"4h"` \| `"6h"` \| `"8h"` \| `"12h"` \| `"1d"` \| `"3d"` \| `"7d"` \| `"30d"` \| `"90d"` | No | `"1h"` | How far back to look |
| `scope` | `"global"` \| `"per_server"` \| `"all"` | No | `"global"` | Level of detail |
| `hostgroup` | int | No | (none) | Filter per_server by hostgroup |
| `server` | string | No | (none) | Filter per_server by server (format: `host:port`) |

**PostgreSQL Support:** Historical connection data is only available for MySQL. When `db_type="pgsql"`, this tool returns an error.

**Response with `scope="global"`:**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "interval": "1h",
    "resolution": "raw",
    "scope": "global",
    "global": {
      "connections": [
        {
          "timestamp": 1737446400,
          "Client_Connections_aborted": 5,
          "Client_Connections_connected": 245,
          "Client_Connections_created": 1500,
          "Server_Connections_aborted": 2,
          "Server_Connections_connected": 120,
          "Server_Connections_created": 800,
          "ConnPool_get_conn_failure": 3,
          "ConnPool_get_conn_immediate": 500,
          "ConnPool_get_conn_success": 1200,
          "Questions": 15678,
          "Slow_queries": 12,
          "GTID_consistent_queries": 100
        }
      ],
      "myhgm": [
        {
          "timestamp": 1737446400,
          "MyHGM_myconnpoll_destroy": 50,
          "MyHGM_myconnpoll_get": 1200,
          "MyHGM_myconnpoll_get_ok": 1197,
          "MyHGM_myconnpoll_push": 1150,
          "MyHGM_myconnpoll_reset": 10
        }
      ]
    }
  }
}
```

**Response with `scope="per_server"`:**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "interval": "1h",
    "resolution": "raw",
    "scope": "per_server",
    "per_server": [
      {
        "timestamp": 1737446400,
        "hostgroup": 10,
        "srv_host": "db-server-01",
        "srv_port": 3306,
        "status": "ONLINE",
        "conn_used": 45,
        "conn_free": 55,
        "conn_ok": 123456,
        "conn_err": 23,
        "max_conn_used": 100,
        "queries": 5678,
        "queries_gtid_sync": 5500,
        "bytes_data_sent": 1234567,
        "bytes_data_recv": 7654321,
        "latency_us": 1500
      }
    ]
  }
}
```

**Response with `scope="all"`:**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "interval": "1h",
    "resolution": "raw",
    "scope": "all",
    "global": {
      "connections": [...],
      "myhgm": [...]
    },
    "per_server": [...]
  }
}
```

---

### 5.4 show_query_history

Returns historical query digest snapshots for trend analysis.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `db_type` | `"mysql"` \| `"pgsql"` | No | `"mysql"` | Database type |
| `dump_time` | int | No | (none) | Filter by specific snapshot timestamp |
| `start_time` | int | No | (none) | Start of time range (Unix timestamp) |
| `end_time` | int | No | (none) | End of time range (Unix timestamp) |
| `digest` | string | No | (none) | Filter by specific query digest |
| `username` | string | No | (none) | Filter by username |
| `database` | string | No | (none) | Filter by database name |
| `limit` | int | No | `100` | Maximum results per snapshot |
| `offset` | int | No | `0` | Skip first N results |

**Note:** Query history is only populated when `SAVE MYSQL DIGEST TO DISK` (or the equivalent for PostgreSQL) has been executed, either manually or via the periodic timer.

**Response:**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "snapshots": [
      {
        "dump_time": 1737446400,
        "queries": [
          {
            "hostgroup": 10,
            "database": "production_db",
            "username": "app_user",
            "client_address": "10.0.1.50",
            "digest": "0x3A2B4C5D6E7F8A9B",
            "digest_text": "SELECT * FROM orders WHERE status = ?",
            "count_star": 5000,
            "first_seen": 1737442800,
            "last_seen": 1737446399,
            "sum_time_us": 15000000,
            "min_time_us": 1200,
            "max_time_us": 50000,
            "sum_rows_affected": 0,
            "sum_rows_sent": 5000000
          }
        ]
      },
      {
        "dump_time": 1737450000,
        "queries": [
          {
            "hostgroup": 10,
            "database": "production_db",
            "username": "app_user",
            "client_address": "10.0.1.50",
            "digest": "0x3A2B4C5D6E7F8A9B",
            "digest_text": "SELECT * FROM orders WHERE status = ?",
            "count_star": 6200,
            "first_seen": 1737446400,
            "last_seen": 1737449999,
            "sum_time_us": 18600000,
            "min_time_us": 1100,
            "max_time_us": 55000,
            "sum_rows_affected": 0,
            "sum_rows_sent": 6200000
          }
        ]
      }
    ],
    "summary": {
      "total_snapshots": 2,
      "earliest_snapshot": 1737446400,
      "latest_snapshot": 1737450000
    }
  }
}
```

---

## 6. Utility Tools

### 6.1 flush_query_log

Flushes query events from the circular buffer into queryable tables.

**Note:** This tool is MySQL-only. Query event logging is not available for PostgreSQL. There is no `db_type` parameter.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `destination` | `"memory"` \| `"disk"` \| `"both"` | No | `"memory"` | Where to flush events |

**Response:**
```json
{
  "success": true,
  "result": {
    "events_flushed": 1234,
    "destination": "memory"
  }
}
```

**Note:** This operation drains the circular buffer. Events are removed from the buffer after flushing.

---

### 6.2 show_query_log

Returns individual query execution events from the audit log.

**Note:** This tool is MySQL-only. Query event logging is not available for PostgreSQL. There is no `db_type` parameter. Query events must be flushed before they become visible. Use `flush_query_log` first.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `source` | `"memory"` \| `"disk"` | No | `"memory"` | Which table to read from |
| `username` | string | No | (none) | Filter by username |
| `database` | string | No | (none) | Filter by database name |
| `query_digest` | string | No | (none) | Filter by digest hash |
| `server` | string | No | (none) | Filter by backend server |
| `errno` | int | No | (none) | Filter by error number |
| `errors_only` | bool | No | `false` | Only show queries with errors |
| `start_time` | int | No | (none) | Start of time range (Unix timestamp) |
| `end_time` | int | No | (none) | End of time range (Unix timestamp) |
| `limit` | int | No | `100` | Maximum results |
| `offset` | int | No | `0` | Skip first N results |

**Response:**
```json
{
  "success": true,
  "result": {
    "source": "memory",
    "total_events": 1234,
    "events": [
      {
        "thread_id": 67,
        "username": "app_user",
        "database": "production_db",
        "start_time": 1737446400,
        "end_time": 1737446401,
        "query_digest": "0x3A2B4C5D6E7F8A9B",
        "query": "SELECT * FROM orders WHERE id = 12345",
        "server": "db-server-01:3306",
        "client": "10.0.1.50:54321",
        "event_type": 1,
        "hostgroup": 10,
        "affected_rows": 0,
        "rows_sent": 1,
        "errno": 0,
        "error": null
      }
    ],
    "summary": {
      "total_errors": 5,
      "time_range": {
        "earliest": 1737440000,
        "latest": 1737446400
      }
    }
  }
}
```

---

### 6.3 flush_queries

Saves current query digest statistics to disk and resets the in-memory counters.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `db_type` | `"mysql"` \| `"pgsql"` | No | `"mysql"` | Database type |

**Response:**
```json
{
  "success": true,
  "result": {
    "db_type": "mysql",
    "digests_saved": 1234,
    "dump_time": 1737446400
  }
}
```

**Important:** This operation resets the live query digest statistics. After flushing:
- `show_queries` will return empty results until new queries accumulate
- The saved data can be viewed with `show_query_history`

---

## Appendix: PostgreSQL Support Summary

| Tool | PostgreSQL Support |
|---|---|
| `show_status` | Full |
| `show_processlist` | Full |
| `show_queries` | Full |
| `show_commands` | Full |
| `show_connections` | Full |
| `show_errors` | Full |
| `show_users` | Full |
| `show_client_cache` | Full |
| `show_query_rules` | Full |
| `show_prepared_statements` | Full |
| `show_gtid` | Not applicable (MySQL only) |
| `show_cluster` | N/A (shared tables) |
| `show_system_history` | N/A (shared tables) |
| `show_query_cache_history` | Not supported (MySQL only data) |
| `show_connection_history` | Not supported (MySQL only data) |
| `show_query_history` | Full |
| `flush_query_log` | Not supported (MySQL only) |
| `show_query_log` | Not supported (MySQL only) |
| `flush_queries` | Full |
