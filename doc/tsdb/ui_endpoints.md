# TSDB HTTP API Endpoints

The Embedded TSDB exposes a JSON API over the standard ProxySQL Admin HTTP interface. This API drives the built-in UI and can be used for custom integrations.

## Base URL
Default: `http://127.0.0.1:6080`

## Authentication
Basic Auth is required using the ProxySQL Admin credentials.
*   **User**: `admin` (default)
*   **Password**: `admin` (default)

---

## Endpoints

### 1. Query Range
**GET** `/api/tsdb/query`

Retrieves data points for a specific metric within a time range.

**Parameters:**
| Name | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `metric` | string | Yes | The exact name of the metric (e.g., `proxysql_questions_total`). |
| `from` | int64 | Yes | Start timestamp in milliseconds since epoch. |
| `to` | int64 | Yes | End timestamp in milliseconds since epoch. |
| `labels` | json | No | JSON object for filtering (e.g., `{"hostgroup":"10"}`). Exact match only. |

**Example Request:**
```http
GET /api/tsdb/query?metric=backend_probe_up&from=1678886400000&to=1678890000000&labels={"hostgroup":"10"}
```

**Example Response:**
```json
[
  {
    "labels": {
      "metric": "backend_probe_up",
      "hostgroup": "10",
      "endpoint": "192.168.1.50:3306"
    },
    "points": [
      { "t": 1678886400000, "v": 1.0 },
      { "t": 1678886405000, "v": 1.0 },
      { "t": 1678886410000, "v": 0.0 }
    ]
  },
  {
    "labels": {
      "metric": "backend_probe_up",
      "hostgroup": "10",
      "endpoint": "192.168.1.51:3306"
    },
    "points": [
      { "t": 1678886400000, "v": 1.0 },
      { "t": 1678886405000, "v": 1.0 }
    ]
  }
]
```

### 2. Status
**GET** `/api/tsdb/status`

Returns internal operational statistics of the TSDB subsystem.

**Example Response:**
```json
{
  "enabled": true,
  "series_count": 124,
  "disk_usage_bytes": 1048576,
  "last_compaction": 1678886400000,
  "uptime_seconds": 3600
}
```

### 3. List Metrics
**GET** `/api/tsdb/metrics`

Returns a list of all unique metric names currently indexed.

**Example Response:**
```json
[
  "proxysql_uptime_seconds",
  "backend_probe_up",
  "proxysql_queries_total"
]
```

---

## Error Handling

| Status Code | Description |
| :--- | :--- |
| `200 OK` | Success. Body contains JSON data. |
| `400 Bad Request` | Missing required parameters (e.g., missing `metric`). |
| `401 Unauthorized` | Invalid Admin credentials. |
| `404 Not Found` | Endpoint does not exist (check if TSDB is enabled). |
| `500 Internal Server Error` | Internal error (e.g., disk I/O failure). |