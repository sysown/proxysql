# Embedded TSDB Overview

## What It Is

The ProxySQL TSDB is an embedded SQLite-based time-series store implemented in `ProxySQL_Statistics`.
It records Prometheus metrics and optional backend TCP probe health into `statsdb_disk`.

## What It Currently Implements

- Storage in SQLite tables:
  - `tsdb_metrics` (raw samples)
  - `tsdb_metrics_hour` (hourly rollups)
  - `tsdb_backend_health` (backend probes)
- Periodic sampling from the built-in Prometheus registry.
- Sampling of all Prometheus metric families:
  - Counter, Gauge, Summary, Histogram, Info, Untyped.
- Optional backend TCP probe loop for `runtime_mysql_servers`.
- Hourly downsampling and retention cleanup.
- Query access via SQL on `statsdb_disk.*` tables.

## Configuration Model

TSDB settings are standard global variables with the `tsdb-` prefix. They can be managed via standard `SET` commands or through the dedicated TSDB command set:

- `SET tsdb-...`
- `LOAD TSDB VARIABLES TO RUNTIME`
- `SAVE TSDB VARIABLES TO DISK`
- `SHOW TSDB VARIABLES`
- `SHOW TSDB STATUS`

## UI and REST API

A built-in dashboard is available at `/tsdb` on the ProxySQL HTTP Server (default port 6080).
It provides a simple visualization of collected metrics.

REST API endpoints are available under `/api/tsdb/` for external integrations.

## Variables

- `tsdb-enabled` (0/1)
- `tsdb-sample_interval` (1..3600 seconds)
- `tsdb-retention_days` (1..3650)
- `tsdb-monitor_enabled` (0/1)
- `tsdb-monitor_interval` (1..3600 seconds)

## Retention

- Raw metrics (`tsdb_metrics`): `tsdb-retention_days`
- Backend probes (`tsdb_backend_health`): `tsdb-retention_days`
- Hourly rollups (`tsdb_metrics_hour`): fixed 365 days
