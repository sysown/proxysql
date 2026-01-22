# TSDB HTTP API Endpoints

The TSDB exposes a JSON API for the built-in UI and external queries. All endpoints require Admin authentication.

## `GET /api/tsdb/metrics`
Returns a list of all metrics currently stored in the TSDB.

## `GET /api/tsdb/query`
Retrieves time series data for a specific metric.
**Parameters:**
- `metric`: (Required) Name of the metric.
- `from`: (Required) Start timestamp (Unix ms).
- `to`: (Required) End timestamp (Unix ms).
- `step`: (Required) Resolution in seconds.
- `labels`: (Optional) Filter by labels (e.g., `hostgroup=10`).
- `agg`: (Optional) Aggregation function (`avg`, `max`, `rate`).

## `GET /api/tsdb/status`
Returns runtime statistics for the TSDB subsystem, including disk usage and series cardinality.
