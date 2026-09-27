# TSDB Reference Manual

## Configuration Variables

The behavior of the TSDB subsystem is controlled by the following global variables:

| Variable | Type | Default | Range | Description |
|---|---|---:|---|---|
| `tsdb-enabled` | int | `0` | `0/1` | Master switch |
| `tsdb-sample_interval` | int | `5` | `1..3600` | Prometheus sampling interval (seconds) |
| `tsdb-retention_days` | int | `2` | `1..3650` | Raw/probe retention in days |
| `tsdb-monitor_enabled` | int | `0` | `0/1` | Backend probe switch |
| `tsdb-monitor_interval` | int | `10` | `1..3600` | Probe interval (seconds) |

### Apply Changes

```sql
SET tsdb-enabled=1;
LOAD TSDB VARIABLES TO RUNTIME;
SAVE TSDB VARIABLES TO DISK;
```

## Tables

### `stats_history.tsdb_metrics`

```sql
CREATE TABLE tsdb_metrics (
    timestamp INT NOT NULL,
    metric_name TEXT NOT NULL,
    labels TEXT NOT NULL DEFAULT '{}',
    value REAL,
    PRIMARY KEY (timestamp, metric_name, labels)
) WITHOUT ROWID;
```

### `stats_history.tsdb_metrics_hour`

```sql
CREATE TABLE tsdb_metrics_hour (
    bucket INT NOT NULL,
    metric_name TEXT NOT NULL,
    labels TEXT NOT NULL DEFAULT '{}',
    avg_value REAL,
    max_value REAL,
    min_value REAL,
    count INT,
    PRIMARY KEY (bucket, metric_name, labels)
) WITHOUT ROWID;
```

### `stats_history.tsdb_backend_health`

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

## Prometheus Ingestion Mapping

- `Counter` -> `<name>`
- `Gauge` -> `<name>`
- `Untyped` -> `<name>`
- `Info` -> `<name>`
- `Summary` -> `<name>{quantile=...}`, plus `<name>_sum`, `<name>_count`
- `Histogram` -> `<name>_bucket{le=...}`, plus `<name>_sum`, `<name>_count`

## SQL Examples

```sql
SELECT metric_name, labels, value
FROM stats_history.tsdb_metrics
WHERE timestamp > unixepoch() - 300
ORDER BY timestamp DESC
LIMIT 50;
```

```sql
SELECT datetime(bucket, 'unixepoch') AS hour, metric_name, avg_value, max_value, min_value, count
FROM stats_history.tsdb_metrics_hour
WHERE bucket > unixepoch() - 86400
ORDER BY bucket;
```

```sql
SELECT datetime(timestamp, 'unixepoch') AS ts, hostgroup, hostname, port, probe_up, connect_ms
FROM stats_history.tsdb_backend_health
WHERE timestamp > unixepoch() - 3600
ORDER BY timestamp DESC;
```
