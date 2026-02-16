# TSDB Quickstart Guide

## Enable TSDB

```sql
-- Enable TSDB
SET admin-stats_tsdb_enabled='1';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
```

## Verify Tables Created

```sql
-- Check TSDB tables exist
SELECT name FROM statsdb_disk.sqlite_master 
WHERE type='table' AND name LIKE 'tsdb%';
```

Expected output:
```
+----------------------+
| name                 |
+----------------------+
| tsdb_metrics         |
| tsdb_metrics_hour    |
| tsdb_backend_health  |
+----------------------+
```

## Query Metrics

### View Recent Metrics

```sql
-- Last hour of metrics
SELECT 
    datetime(timestamp, 'unixepoch') as time,
    metric_name,
    json_extract(labels, '$.hostgroup') as hg,
    value
FROM statsdb_disk.tsdb_metrics
WHERE timestamp > unixepoch() - 3600
ORDER BY timestamp DESC
LIMIT 10;
```

### Query with Filters

```sql
-- Filter by metric name and label
SELECT * FROM statsdb_disk.tsdb_metrics
WHERE metric_name = 'mysql_connections'
AND json_extract(labels, '$.hostgroup') = '1'
AND timestamp > unixepoch() - 3600;
```

### Hourly Aggregates

```sql
-- Daily averages
SELECT 
    datetime(bucket, 'unixepoch') as hour,
    metric_name,
    avg_value,
    max_value,
    count
FROM statsdb_disk.tsdb_metrics_hour
WHERE bucket > unixepoch() - 86400
ORDER BY bucket;
```

## Enable Backend Health Monitoring

```sql
-- Enable health probes
SET admin-stats_tsdb_monitor_enabled='1';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;

-- Query health status
SELECT 
    datetime(timestamp, 'unixepoch') as time,
    hostgroup,
    hostname,
    port,
    CASE probe_up WHEN 1 THEN 'UP' ELSE 'DOWN' END as status,
    connect_ms
FROM statsdb_disk.tsdb_backend_health
WHERE timestamp > unixepoch() - 3600
ORDER BY timestamp DESC;
```

## Common Queries

### Connection Count Over Time

```sql
SELECT 
    datetime(timestamp, 'unixepoch') as time,
    value as connections
FROM statsdb_disk.tsdb_metrics
WHERE metric_name = 'mysql_connections'
AND timestamp > unixepoch() - 3600
ORDER BY timestamp;
```

### Backend Availability

```sql
-- Success rate by backend
SELECT 
    hostname,
    port,
    SUM(probe_up) as up_count,
    COUNT(*) as total,
    ROUND(100.0 * SUM(probe_up) / COUNT(*), 2) as uptime_pct
FROM statsdb_disk.tsdb_backend_health
WHERE timestamp > unixepoch() - 86400
GROUP BY hostname, port;
```

### Top Metrics

```sql
-- Most frequent metrics
SELECT 
    metric_name,
    COUNT(*) as samples
FROM statsdb_disk.tsdb_metrics
WHERE timestamp > unixepoch() - 3600
GROUP BY metric_name
ORDER BY samples DESC;
```

## Disable TSDB

```sql
SET admin-stats_tsdb_enabled='0';
SET admin-stats_tsdb_monitor_enabled='0';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
```

## Troubleshooting

### Check if Tables Exist

```sql
SELECT 
    (SELECT COUNT(*) FROM statsdb_disk.sqlite_master WHERE name='tsdb_metrics') as metrics_exists,
    (SELECT COUNT(*) FROM statsdb_disk.sqlite_master WHERE name='tsdb_metrics_hour') as hourly_exists,
    (SELECT COUNT(*) FROM statsdb_disk.sqlite_master WHERE name='tsdb_backend_health') as health_exists;
```

### Check Recent Activity

```sql
-- Metrics in last 5 minutes
SELECT COUNT(*) as recent_metrics
FROM statsdb_disk.tsdb_metrics
WHERE timestamp > unixepoch() - 300;

-- Health probes in last 5 minutes
SELECT COUNT(*) as recent_probes
FROM statsdb_disk.tsdb_backend_health
WHERE timestamp > unixepoch() - 300;
```
