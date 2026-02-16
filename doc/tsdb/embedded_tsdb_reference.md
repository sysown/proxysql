# TSDB Reference Manual

## Configuration Variables

All TSDB configuration variables are managed through the standard ProxySQL admin variables system with prefix `admin-stats_tsdb_`.

### Complete Variable Reference

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `admin-stats_tsdb_enabled` | integer | `0` | Master switch (0=off, 1=on) |
| `admin-stats_tsdb_sample_interval` | integer | `5` | Metric sampling frequency (seconds) |
| `admin-stats_tsdb_retention_days` | integer | `7` | Raw data retention (days) |
| `admin-stats_tsdb_monitor_enabled` | integer | `0` | Enable backend health monitoring |
| `admin-stats_tsdb_monitor_interval` | integer | `10` | Health probe frequency (seconds) |

### Enabling TSDB

```sql
-- Enable TSDB
SET admin-stats_tsdb_enabled='1';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;

-- Check status
SELECT * FROM global_variables WHERE variable_name LIKE 'admin-stats_tsdb%';
```

## Admin Commands

### TSDB STATUS

Returns TSDB statistics including series count, datapoints, and time range.

```sql
-- Get TSDB status (when implemented in admin handler)
SELECT 
    (SELECT COUNT(DISTINCT metric_name || labels) FROM statsdb_disk.tsdb_metrics) as total_series,
    (SELECT COUNT(*) FROM statsdb_disk.tsdb_metrics) as total_datapoints,
    (SELECT MIN(timestamp) FROM statsdb_disk.tsdb_metrics) as oldest_datapoint,
    (SELECT MAX(timestamp) FROM statsdb_disk.tsdb_metrics) as newest_datapoint;
```

### Querying Metrics via SQL

```sql
-- Query recent metrics
SELECT * FROM statsdb_disk.tsdb_metrics 
WHERE metric_name = 'mysql_connections' 
AND timestamp > unixepoch() - 3600
ORDER BY timestamp DESC
LIMIT 100;

-- Query with label filter
SELECT * FROM statsdb_disk.tsdb_metrics 
WHERE metric_name = 'mysql_connections'
AND json_extract(labels, '$.hostgroup') = '1'
AND timestamp > unixepoch() - 3600;

-- Query hourly aggregates
SELECT 
    bucket,
    metric_name,
    avg_value,
    max_value,
    min_value,
    count
FROM statsdb_disk.tsdb_metrics_hour
WHERE metric_name = 'mysql_connections'
AND bucket > unixepoch() - 86400
ORDER BY bucket;

-- Query backend health
SELECT 
    datetime(timestamp, 'unixepoch') as time,
    hostgroup,
    hostname,
    port,
    probe_up,
    connect_ms
FROM statsdb_disk.tsdb_backend_health
WHERE timestamp > unixepoch() - 3600
ORDER BY timestamp DESC;
```

## C++ API

### Metric Insertion

```cpp
// Insert a metric sample
void ProxySQL_Statistics::insert_tsdb_metric(
    const std::string& metric_name,
    const std::map<std::string, std::string>& labels,
    double value,
    time_t timestamp = time(NULL)
);

// Example usage
std::map<std::string, std::string> labels;
labels["hostgroup"] = "1";
labels["backend"] = "192.168.1.1";
GloProxyStats->insert_tsdb_metric("connections", labels, 42.0, time(NULL));
```

### Backend Health Insertion

```cpp
// Insert backend health probe result
void ProxySQL_Statistics::insert_backend_health(
    int hostgroup,
    const std::string& hostname,
    int port,
    bool probe_up,
    int connect_ms,
    time_t timestamp = time(NULL)
);

// Example usage
GloProxyStats->insert_backend_health(
    1, "192.168.1.1", 3306, true, 5, time(NULL)
);
```

### Query Interface

```cpp
// Query metrics with label filters
SQLite3_result* ProxySQL_Statistics::query_tsdb_metrics(
    const std::string& metric_name,
    const std::map<std::string, std::string>& label_filters,
    time_t from,
    time_t to,
    const std::string& aggregation = ""
);

// Query backend health
SQLite3_result* ProxySQL_Statistics::get_backend_health_metrics(
    time_t from,
    time_t to,
    int hostgroup = -1
);

// Get TSDB status
struct tsdb_status_t {
    size_t total_series;
    size_t total_datapoints;
    size_t disk_size_bytes;
    time_t oldest_datapoint;
    time_t newest_datapoint;
};
tsdb_status_t ProxySQL_Statistics::get_tsdb_status();
```

## Database Schema

### tsdb_metrics

Stores raw metric samples.

```sql
CREATE TABLE tsdb_metrics (
    timestamp INT NOT NULL,
    metric_name TEXT NOT NULL,
    labels TEXT,
    value REAL,
    PRIMARY KEY (timestamp, metric_name)
) WITHOUT ROWID;
```

### tsdb_metrics_hour

Stores hourly aggregated metrics.

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

### tsdb_backend_health

Stores backend health probe results.

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

## Metrics Catalog

### System Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `mysql_connections` | gauge | hostgroup, backend | Active MySQL connections |
| `queries` | counter | hostgroup, backend | Total queries processed |
| `slow_queries` | counter | - | Slow query count |

### Backend Health Metrics

| Column | Description |
|--------|-------------|
| `probe_up` | 1 if TCP connect succeeded, 0 if failed |
| `connect_ms` | TCP connection time in milliseconds |

## Retention and Downsampling

### Automatic Downsampling

Raw data is automatically downsampled to hourly aggregates:

```
tsdb_metrics (raw) → tsdb_metrics_hour (aggregated)
     7 days                 1 year
```

### Retention Policy

- **Raw data** (`tsdb_metrics`): 7 days
- **Hourly aggregates** (`tsdb_metrics_hour`): 1 year
- **Backend health** (`tsdb_backend_health`): 7 days

## Troubleshooting

### Checking TSDB Status

```sql
-- Check if TSDB tables exist
SELECT name FROM statsdb_disk.sqlite_master WHERE type='table' AND name LIKE 'tsdb%';

-- Check recent metrics count
SELECT COUNT(*) FROM statsdb_disk.tsdb_metrics WHERE timestamp > unixepoch() - 3600;

-- Check table sizes
SELECT 
    name,
    (SELECT COUNT(*) FROM statsdb_disk.tsdb_metrics) as metrics_count,
    (SELECT COUNT(*) FROM statsdb_disk.tsdb_metrics_hour) as hourly_count,
    (SELECT COUNT(*) FROM statsdb_disk.tsdb_backend_health) as health_count;
```

### Common Issues

**Issue: No metrics being collected**
- Check `admin-stats_tsdb_enabled` is set to 1
- Verify `GloVars.prometheus_registry` is initialized

**Issue: Backend health not recorded**
- Check `admin-stats_tsdb_monitor_enabled` is set to 1
- Ensure `runtime_mysql_servers` has entries

**Issue: High disk usage**
- Reduce `admin-stats_tsdb_retention_days`
- Increase `admin-stats_tsdb_sample_interval`
