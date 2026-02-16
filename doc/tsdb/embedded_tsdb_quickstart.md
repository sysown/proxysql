# TSDB Quickstart Guide

## 1. Enable TSDB

```sql
SET tsdb-enabled='1';
LOAD TSDB VARIABLES TO RUNTIME;
SAVE TSDB VARIABLES TO DISK;
```

Optional backend probe collection:

```sql
SET tsdb-monitor_enabled='1';
LOAD TSDB VARIABLES TO RUNTIME;
SAVE TSDB VARIABLES TO DISK;
```

## 2. Verify Tables

```sql
SELECT name
FROM statsdb_disk.sqlite_master
WHERE type='table' AND name LIKE 'tsdb_%';
```

## 3. Query Raw Samples

```sql
SELECT datetime(timestamp,'unixepoch') AS ts, metric_name, labels, value
FROM statsdb_disk.tsdb_metrics
WHERE timestamp > unixepoch() - 300
ORDER BY timestamp DESC
LIMIT 50;
```

## 4. Query Hourly Rollups

```sql
SELECT datetime(bucket,'unixepoch') AS hour, metric_name, avg_value, max_value, min_value, count
FROM statsdb_disk.tsdb_metrics_hour
WHERE bucket > unixepoch() - 86400
ORDER BY bucket;
```

## 5. Query Backend Probe Health

```sql
SELECT datetime(timestamp,'unixepoch') AS ts, hostgroup, hostname, port, probe_up, connect_ms
FROM statsdb_disk.tsdb_backend_health
WHERE timestamp > unixepoch() - 3600
ORDER BY timestamp DESC;
```

## Notes

- TSDB settings are TSDB variables (`tsdb-*`).
- There are no `LOAD/SAVE TSDB VARIABLES` commands.
