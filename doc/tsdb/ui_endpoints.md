# TSDB UI and REST API

ProxySQL provides a built-in web dashboard and a set of REST API endpoints for the TSDB subsystem.

## Web Dashboard

The dashboard is accessible at: `http://<proxysql_host>:6080/tsdb`

It offers a simple interface to:
- Select available metrics.
- Choose a time range (Last Hour, Last Day, Last Week).
- Visualize metric data using interactive charts (Chart.js).

## REST API Endpoints

The following JSON endpoints are available for programmatic access.

### `GET /api/tsdb/metrics`

Returns a list of all available metric names.

**Response:**
```json
[
  "process_resident_memory_bytes",
  "process_cpu_seconds_total",
  "mysql_questions_total",
  ...
]
```

### `GET /api/tsdb/query`

Query time-series data for a specific metric.

**Parameters:**
- `metric` (required): The name of the metric to query.
- `from` (optional): Start timestamp (Unix epoch seconds). Defaults to 1 hour ago.
- `to` (optional): End timestamp (Unix epoch seconds). Defaults to now.
- `agg` (optional): Aggregation function (e.g., `avg`, `max`). *Note: Aggregation support depends on backend implementation.*
- Other parameters: Any other query parameters are treated as label filters (e.g., `cluster="cluster1"`).

**Response:**
```json
[
  {
    "ts": 1678886400,
    "metric": "process_resident_memory_bytes",
    "labels": {},
    "value": 104857600
  },
  ...
]
```

### `GET /api/tsdb/status`

Returns the current status of the TSDB subsystem.

**Response:**
```json
{
  "total_series": 50,
  "total_datapoints": 15000,
  "disk_size_bytes": 2048000,
  "oldest_datapoint": 1678800000,
  "newest_datapoint": 1678886400
}
```
