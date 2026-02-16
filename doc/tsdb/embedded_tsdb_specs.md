# TSDB Technical Specifications

## Overview

The TSDB (Time Series Database) subsystem extends ProxySQL_Statistics with time-series metric storage using SQLite.

## Design Goals

1. **Zero External Dependencies** - Uses existing SQLite infrastructure
2. **Production Ready** - Leverages battle-tested ProxySQL_Statistics
3. **Automatic Maintenance** - Built-in downsampling and retention
4. **SQL Interface** - Query using standard SQL

## Storage Engine

### SQLite Configuration

- **Journal Mode**: WAL (Write-Ahead Logging)
- **Synchronous**: NORMAL
- **Page Size**: 4096 bytes
- **Cache Size**: -2000 (2MB)

### Table Schema

#### tsdb_metrics

```sql
CREATE TABLE tsdb_metrics (
    timestamp INT NOT NULL,
    metric_name TEXT NOT NULL,
    labels TEXT,           -- JSON object
    value REAL,
    PRIMARY KEY (timestamp, metric_name)
) WITHOUT ROWID;
```

**Rationale:**
- `WITHOUT ROWID` for efficient time-range scans
- Composite PK on (timestamp, metric_name) for fast lookups
- JSON labels for flexible metadata

#### tsdb_metrics_hour

```sql
CREATE TABLE tsdb_metrics_hour (
    bucket INT NOT NULL,
    metric_name TEXT NOT NULL,
    labels TEXT,
    avg_value REAL,
    max_value REAL,
    min_value REAL,
    count INT,
    PRIMARY KEY (bucket, metric_name)
) WITHOUT ROWID;
```

**Rationale:**
- Pre-aggregated data for fast historical queries
- Statistical summary (avg, max, min, count)

#### tsdb_backend_health

```sql
CREATE TABLE tsdb_backend_health (
    timestamp INT NOT NULL,
    hostgroup INT NOT NULL,
    hostname TEXT NOT NULL,
    port INT NOT NULL,
    probe_up INT NOT NULL,
    connect_ms INT,
    PRIMARY KEY (timestamp, hostgroup, hostname, port)
) WITHOUT ROWID;
```

**Rationale:**
- Tracks backend availability over time
- Composite PK for efficient per-backend queries

## Downsampling Algorithm

### Hourly Aggregation

```sql
INSERT OR REPLACE INTO tsdb_metrics_hour
SELECT
    (timestamp/3600)*3600 as bucket,
    metric_name,
    labels,
    AVG(value) as avg_value,
    MAX(value) as max_value,
    MIN(value) as min_value,
    COUNT(*) as count
FROM tsdb_metrics
WHERE timestamp >= :last_processed AND timestamp < :current_hour
GROUP BY bucket, metric_name, labels;
```

### Retention Enforcement

```sql
-- Raw data: 7 days
DELETE FROM tsdb_metrics WHERE timestamp < unixepoch() - 7*86400;

-- Hourly: 1 year
DELETE FROM tsdb_metrics_hour WHERE bucket < unixepoch() - 365*86400;

-- Health: 7 days
DELETE FROM tsdb_backend_health WHERE timestamp < unixepoch() - 7*86400;
```

## Performance Characteristics

### Insert Performance

- **Raw metrics**: ~10,000 inserts/second
- **Health probes**: ~5,000 inserts/second
- **Batched**: No (individual prepared statements)

### Query Performance

- **Time-range scan**: O(log n) with index
- **Label filter**: Full scan (JSON extraction)
- **Aggregated query**: O(log n) on tsdb_metrics_hour

### Storage Overhead

| Data Type | Per-Row Size |
|-----------|--------------|
| Raw metric | ~50 bytes + label JSON |
| Hourly aggregate | ~60 bytes + label JSON |
| Health probe | ~40 bytes |

## Memory Usage

- **Prepared statements**: 3 cached statements
- **JSON parsing**: Temporary during insert/query
- **Result sets**: Streamed to client

## Concurrency

### Thread Safety

- SQLite handles concurrency via WAL mode
- Multiple readers, single writer
- No additional application-level locks

### Connection Model

- Uses existing `statsdb_disk` connection
- Prepared statements cached per-thread

## API Specification

### C++ Interface

```cpp
class ProxySQL_Statistics {
public:
    // Metric insertion
    void insert_tsdb_metric(const std::string& metric_name,
                           const std::map<std::string, std::string>& labels,
                           double value, time_t timestamp);
    
    // Health insertion
    void insert_backend_health(int hostgroup, const std::string& hostname,
                              int port, bool probe_up, int connect_ms,
                              time_t timestamp);
    
    // Downsampling
    void tsdb_downsample_metrics();
    
    // Query
    SQLite3_result* query_tsdb_metrics(const std::string& metric_name,
                                      const std::map<std::string, std::string>& label_filters,
                                      time_t from, time_t to,
                                      const std::string& aggregation);
    
    // Status
    struct tsdb_status_t {
        size_t total_series;
        size_t total_datapoints;
        size_t disk_size_bytes;
        time_t oldest_datapoint;
        time_t newest_datapoint;
    };
    tsdb_status_t get_tsdb_status();
};
```

## Configuration

### Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| stats_tsdb_enabled | bool | false | Master switch |
| stats_tsdb_sample_interval | int | 5 | Sampling interval (seconds) |
| stats_tsdb_retention_days | int | 7 | Raw retention (days) |
| stats_tsdb_monitor_enabled | bool | false | Health monitoring |
| stats_tsdb_monitor_interval | int | 10 | Probe interval (seconds) |

## Testing

### Unit Tests

1. **Insert/Query roundtrip**
2. **Label filtering**
3. **Downsampling accuracy**
4. **Retention enforcement**

### Integration Tests

1. **Backend health monitoring**
2. **Prometheus metrics sampling**
3. **Concurrent access**
4. **Resource limits**

## Future Enhancements

1. **Label indexing** - Add GIN index on labels JSON
2. **Continuous queries** - User-defined aggregations
3. **Export formats** - CSV, JSON output
4. **Alerting** - Basic threshold alerts
