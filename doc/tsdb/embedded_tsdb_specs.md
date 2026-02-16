# TSDB Technical Specifications

## Scope

Embedded time-series storage in SQLite for ProxySQL runtime metrics and backend probe health.

## Table Definitions

### `tsdb_metrics`

- Columns: `timestamp`, `metric_name`, `labels`, `value`
- PK: `(timestamp, metric_name, labels)`
- `labels` is JSON text, default `'{}'`

### `tsdb_metrics_hour`

- Columns: `bucket`, `metric_name`, `labels`, `avg_value`, `max_value`, `min_value`, `count`
- PK: `(bucket, metric_name, labels)`

### `tsdb_backend_health`

- Columns: `timestamp`, `hostgroup`, `hostname`, `port`, `probe_up`, `connect_ms`
- PK: `(timestamp, hostgroup, hostname, port)`

## Sampling and Rollup

- Sampler interval: `tsdb-sample_interval`
- Rollup interval: hourly
- Rollup SQL: `INSERT OR REPLACE ... GROUP BY bucket, metric_name, labels`

## Retention

- Raw metrics retention: `tsdb-retention_days`
- Backend probe retention: `tsdb-retention_days`
- Hourly rollup retention: 365 days

## Variable Semantics

- All TSDB variables are TSDB variables (`tsdb-*`).
- Applied through standard ADMIN commands only.
- No dedicated `LOAD/SAVE TSDB VARIABLES` command set.

## Current API Surface

- C++ methods in `ProxySQL_Statistics` for insert, query, status, sampler/monitor loops.
- SQL querying through `statsdb_disk.tsdb_*` tables.
- No dedicated HTTP TSDB endpoint implementation at this time.
