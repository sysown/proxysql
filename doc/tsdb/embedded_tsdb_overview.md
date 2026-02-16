# Embedded TSDB Overview

## What is the TSDB?

The **ProxySQL TSDB** (Time Series Database) is an **embedded, lightweight time-series database** built directly into ProxySQL using SQLite. It provides:

- **Historical metric storage** - Persist query statistics, connection counts, backend health
- **Built-in monitoring** - Active health checks for all backend servers
- **SQL interface** - Query metrics using standard SQL
- **HTTP API** - RESTful endpoints for metric retrieval
- **Prometheus integration** - Sample Prometheus metrics into TSDB

### Key Benefits

| Benefit | Description |
|---------|-------------|
| **Zero external dependencies** | Uses existing SQLite infrastructure, no additional services required |
| **Always-on monitoring** | Built-in backend health checks |
| **Historical analysis** | Debug past performance issues |
| **Simple setup** | Enable with a single SQL command |
| **Production-ready** | Leverages battle-tested ProxySQL_Statistics system |
| **SQL queries** | Query metrics using familiar SQL syntax |

## Architecture Overview

The TSDB subsystem extends the existing `ProxySQL_Statistics` module with three SQLite tables:

```
┌─────────────────────────────────────────────────────────────┐
│                    ProxySQL_Statistics                       │
│                         (SQLite)                             │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐                │
│  │  tsdb_metrics    │  │ tsdb_metrics_hour│                │
│  │  (raw data)      │  │ (downsampled)    │                │
│  └──────────────────┘  └──────────────────┘                │
│  ┌──────────────────┐                                       │
│  │tsdb_backend_health│                                      │
│  │ (health probes)  │                                       │
│  └──────────────────┘                                       │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

```
┌──────────────────┐     ┌──────────────────┐
│  Prometheus      │     │  Backend Servers │
│  Registry        │     │                  │
└────────┬─────────┘     └────────┬─────────┘
         │                        │
         ▼                        ▼
┌──────────────────┐     ┌──────────────────┐
│  tsdb_sampler_   │     │  tsdb_monitor_   │
│  loop()          │     │  loop()          │
└────────┬─────────┘     └────────┬─────────┘
         │                        │
         └──────────┬─────────────┘
                    ▼
         ┌──────────────────┐
         │  SQLite Tables   │
         │  (tsdb_metrics)  │
         └────────┬─────────┘
                    │
         ┌──────────┼──────────┐
         ▼          ▼          ▼
   ┌──────────┐ ┌────────┐ ┌──────────┐
   │ HTTP API │ │ Admin  │ │ Automatic│
   │          │ │Commands│ │Compaction│
   └──────────┘ └────────┘ └──────────┘
```

### Storage Architecture

| Table | Purpose | Retention |
|-------|---------|-----------|
| `tsdb_metrics` | Raw metric samples | 7 days |
| `tsdb_metrics_hour` | Hourly aggregates (avg, max, min, count) | 1 year |
| `tsdb_backend_health` | Backend health probe results | 7 days |

### Automatic Downsampling

```
Raw Data (tsdb_metrics)         Hourly Aggregates (tsdb_metrics_hour)
┌─────────────────────┐        ┌──────────────────────────────────────┐
│ Time │ Metric │ Val│        │ Bucket │ Metric │ Avg │ Max │ Min │ N│
├─────────────────────┤        ├──────────────────────────────────────┤
│ 10:01│  cpu   │  50│   ──▶  │ 10:00  │  cpu   │ 52  │ 80  │ 20  │12│
│ 10:05│  cpu   │  55│   ──▶  │ 11:00  │  cpu   │ 48  │ 75  │ 25  │12│
│ 10:10│  cpu   │  60│   ──▶  │ ...    │        │     │     │     │  │
│ ...  │        │    │        └──────────────────────────────────────┘
└─────────────────────┘
   7 days                              1 year
```

## Quick Start

```sql
-- Enable TSDB
SET admin-stats_tsdb_enabled='true';
LOAD ADMIN VARIABLES TO RUNTIME;

-- Access metrics via SQL
SELECT * FROM statsdb_disk.tsdb_metrics
WHERE metric_name = 'mysql_connections'
AND timestamp > unixepoch() - 3600;

-- Query via HTTP API
-- curl "http://admin:admin@localhost:6032/api/tsdb/query?metric=mysql_connections&from=-1h"
```

## What Gets Monitored?

### 1. Traffic Metrics (from Prometheus Registry)
- Query counts and latency
- Frontend connections
- Backend connections
- Query cache stats

### 2. Backend Health (active probes)
- TCP connect success/failure
- Connection latency (milliseconds)
- Per-hostgroup, per-host, per-port tracking

### 3. System Health
- TSDB internal stats
- Storage usage

## Design Principles

### SQLite-Based Storage

- **ACID compliance** - Transactions ensure data integrity
- **Indexed queries** - Fast time-range lookups
- **JSON labels** - Flexible label storage with JSON extraction
- **SQL interface** - Query using standard SQL

### Bounded Resources

| Limit | Default | Purpose |
|-------|---------|---------|
| `stats_tsdb_retention_days` | 7 | Raw data retention |
| `stats_tsdb_sample_interval` | 5 sec | Metric sampling rate |
| `stats_tsdb_monitor_interval` | 10 sec | Health probe interval |

### Thread Safety

- Uses existing `ProxySQL_Statistics` locking
- SQLite prepared statements for concurrent access
- Atomic configuration updates

## Configuration at a Glance

| Variable | Default | Description |
|----------|---------|-------------|
| `stats_tsdb_enabled` | `0` | Master switch (0=off, 1=on) |
| `stats_tsdb_sample_interval` | `5` | How often to sample metrics (seconds) |
| `stats_tsdb_retention_days` | `7` | How long to keep raw data |
| `stats_tsdb_monitor_enabled` | `0` | Enable backend health monitoring |
| `stats_tsdb_monitor_interval` | `10` | How often to probe backends (seconds) |

See the [Reference Manual](./embedded_tsdb_reference.md) for complete configuration documentation.

## When to Use TSDB

| Use Case | Recommended |
|----------|-------------|
| **Quick troubleshooting** | Ideal - last 7 days of data |
| **Performance analysis** | Identify slow queries, bottlenecks |
| **Backend monitoring** | Track backend health over time |
| **Long-term analytics** | Use external system (Prometheus/Grafana) |

## When NOT to Use TSDB

- **Long-term retention** (> 1 week) - Use external TSDB
- **High-cardinality data** - Thousands of unique series may impact performance
- **Complex analytics** - Use external query/BI tools
- **Cross-server aggregation** - Use external monitoring

## Next Steps

1. **Read the Architecture** - [architecture.md](./embedded_tsdb_architecture.md)
2. **Explore the API** - [reference.md](./embedded_tsdb_reference.md)
3. **Check the Specs** - [specs.md](./embedded_tsdb_specs.md)
