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

TSDB settings are standard ADMIN variables and use the normal ADMIN load/save lifecycle:

- `SET admin-stats_tsdb_...`
- `LOAD ADMIN VARIABLES TO RUNTIME`
- `SAVE ADMIN VARIABLES TO DISK`

There is no separate `LOAD/SAVE TSDB VARIABLES ...` command set.

## Variables

- `admin-stats_tsdb_enabled` (0/1)
- `admin-stats_tsdb_sample_interval` (1..3600 seconds)
- `admin-stats_tsdb_retention_days` (1..3650)
- `admin-stats_tsdb_monitor_enabled` (0/1)
- `admin-stats_tsdb_monitor_interval` (1..3600 seconds)

## Retention

- Raw metrics (`tsdb_metrics`): `admin-stats_tsdb_retention_days`
- Backend probes (`tsdb_backend_health`): `admin-stats_tsdb_retention_days`
- Hourly rollups (`tsdb_metrics_hour`): fixed 365 days
