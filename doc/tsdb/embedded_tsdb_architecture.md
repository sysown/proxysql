# TSDB Architecture

## Runtime Components

- `ProxySQL_Admin` main loop triggers three TSDB schedulers:
  - sampler (`tsdb_sampler_loop`)
  - downsampler (`tsdb_downsample_metrics`)
  - backend monitor (`tsdb_monitor_loop`)
- Data is stored in `statsdb_disk` SQLite tables.

## Data Path

1. Sampler collects all metric families from `GloVars.prometheus_registry->Collect()`.
2. Samples are normalized and inserted into `tsdb_metrics`.
3. Hourly job aggregates into `tsdb_metrics_hour`.
4. Backend monitor probes servers from `runtime_mysql_servers` and stores in `tsdb_backend_health`.
5. Retention cleanup removes old raw/probe data using configured days.

## Metric Family Handling

- Counter/Gauge/Untyped/Info: one sample per metric point.
- Summary: quantiles plus `_sum` and `_count` companion metrics.
- Histogram: `_bucket{le=...}` plus `_sum` and `_count` companion metrics.

## Storage Schema

- `tsdb_metrics`: PK `(timestamp, metric_name, labels)`
- `tsdb_metrics_hour`: PK `(bucket, metric_name, labels)`
- `tsdb_backend_health`: PK `(timestamp, hostgroup, hostname, port)`

## Configuration Lifecycle

TSDB configuration is handled via standard global variables with the `tsdb-` prefix. Changes are applied and persisted using the following dedicated administrative commands:

- `LOAD TSDB VARIABLES TO RUNTIME`
- `SAVE TSDB VARIABLES TO DISK`

These commands function similarly to their `MYSQL` and `PGSQL` counterparts, moving configuration between memory and disk storage.

