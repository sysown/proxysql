# TSDB Reference Manual

## Table of Contents
1. [Configuration Variables](#configuration-variables)
2. [Admin Commands](#admin-commands)
3. [HTTP API](#http-api)
4. [C++ API](#c-api)
5. [Metrics Catalog](#metrics-catalog)
6. [Troubleshooting](#troubleshooting)

---

## Configuration Variables

All TSDB configuration variables are prefixed with `tsdb-` and follow ProxySQL's standard variable naming conventions.

### Enabling TSDB

```sql
-- Enable TSDB subsystem
SET tsdb-enabled='true';
LOAD TSDB VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;

-- Check enabled status
SELECT @@tsdb-enabled;
```

### Complete Variable Reference

| Variable | Type | Default | Range | Description |
|----------|------|---------|-------|-------------|
| `tsdb-enabled` | boolean | `false` | - | Master switch for TSDB subsystem |
| `tsdb-data_dir` | string | `${datadir}/tsdb` | - | Directory for TSDB data files |
| `tsdb-retention_hours` | integer | `24` | 1-8760 | How long to keep data (hours) |
| `tsdb-sample_interval_seconds` | integer | `5` | 1-3600 | Metric sampling frequency (seconds) |
| `tsdb-raw_window_minutes` | integer | `120` | >0 | Raw data file rollup window (minutes) |
| `tsdb-rollup_interval_seconds` | integer | `60` | ≥1 | Rollup aggregation interval (seconds) |
| `tsdb-max_series` | integer | `10000` | ≥1 | Maximum active series limit |
| `tsdb-max_disk_mb` | integer | `2048` | ≥1 | Maximum disk usage (MB) |
| `tsdb-fsync_mode` | string | `periodic` | - | File sync strategy: `periodic` or `always` |
| `tsdb-digest_mode` | string | `off` | - | Query digest mode: `off`, `1` (enabled) |
| `tsdb-digest_topk` | integer | `20` | ≥1 | Number of top queries to track |
| **Monitor Variables** |||||
| `tsdb-monitor_enabled` | boolean | `true` | - | Enable backend monitoring |
| `tsdb-monitor_interval_seconds` | integer | `10` | ≥1 | Probe frequency (seconds) |
| `tsdb-monitor_connect_timeout_ms` | integer | `1000` | ≥1 | TCP connect timeout (ms) |
| `tsdb-monitor-ping_enabled` | boolean | `true` | - | Enable MySQL ping probes |
| `tsdb-monitor-max_concurrent_probes` | integer | `64` | ≥1 | Max concurrent probes |
| **UI Variables** |||||
| `tsdb-ui_enabled` | boolean | `true` | - | Enable HTTP endpoints and UI |
| `tsdb-ui_read_only` | boolean | `true` | - | Restrict UI to read-only mode |

### Variable Details

#### Core Variables

##### `tsdb-enabled`
Master switch for the TSDB subsystem. When disabled:
- No data is written
- Background threads are stopped
- HTTP endpoints return 404
- Admin commands return errors

```sql
SET tsdb-enabled='true';
LOAD TSDB VARIABLES TO RUNTIME;
```

##### `tsdb-data_dir`
Directory where TSDB stores data files. Default is `${datadir}/tsdb` where datadir is typically `/var/lib/proxysql`.

**Important:** Ensure ProxySQL has write permissions to this directory.

```sql
SET tsdb-data_dir='/mnt/ssd/proxysql_tsdb';
LOAD TSDB VARIABLES TO RUNTIME;
```

##### `tsdb-retention_hours`
How long to keep data before automatic deletion. Default is 24 hours.

- **Minimum:** 1 hour
- **Maximum:** 8760 hours (1 year)
- **Typical values:** 24 (daily), 168 (weekly), 720 (monthly)

```sql
-- Keep 7 days of data
SET tsdb-retention_hours='168';
LOAD TSDB VARIABLES TO RUNTIME;
```

##### `tsdb-sample_interval_seconds`
How often the sampler thread collects internal metrics. Default is 5 seconds.

- **Minimum:** 1 second
- **Maximum:** 3600 seconds (1 hour)
- **Trade-off:** Lower values = more granular data, but more disk/CPU usage

```sql
-- Sample every 10 seconds
SET tsdb-sample_interval_seconds='10';
LOAD TSDB VARIABLES TO RUNTIME;
```

##### `tsdb-raw_window_minutes`
Duration of each raw data file. Files are named `raw_<timestamp>.tsdb` and contain all data for that window.

- **Minimum:** >0 (must be positive)
- **Default:** 120 minutes (2 hours)
- **Effect:** Larger windows = fewer files, but slower queries

```sql
-- 1-hour windows
SET tsdb-raw_window_minutes='60';
LOAD TSDB VARIABLES TO RUNTIME;
```

##### `tsdb-max_series`
Maximum number of unique time series (metric + label combinations).

- **Minimum:** 1
- **Default:** 10000
- **When exceeded:** New writes are dropped with warning logged

```sql
-- Increase for high-cardinality environments
SET tsdb-max_series='50000';
LOAD TSDB VARIABLES TO RUNTIME;
```

##### `tsdb-max_disk_mb`
Maximum disk usage in megabytes. When exceeded, oldest data is deleted.

- **Minimum:** 1 MB
- **Default:** 2048 MB (2 GB)
- **Monitoring:** Check via `TSDB STATUS`

```sql
-- Allow up to 10GB
SET tsdb-max_disk_mb='10240';
LOAD TSDB VARIABLES TO RUNTIME;
```

#### Monitor Variables

##### `tsdb-monitor_enabled`
Enable active backend monitoring (TCP connect probes).

```sql
SET tsdb-monitor_enabled='true';
LOAD TSDB VARIABLES TO RUNTIME;
```

##### `tsdb-monitor_interval_seconds`
How often to probe backends. Default is 10 seconds.

```sql
SET tsdb-monitor_interval_seconds='5';
LOAD TSDB VARIABLES TO RUNTIME;
```

##### `tsdb-monitor_connect_timeout_ms`
TCP connect timeout for backend probes. Default is 1000ms.

```sql
SET tsdb-monitor_connect_timeout_ms='500';
LOAD TSDB VARIABLES TO RUNTIME;
```

#### Query Digest Variables

##### `tsdb-digest_mode`
Enable tracking of top queries from `stats_mysql_query_digest`.

- **`off`**: Disabled (default)
- **`1`**: Enabled

```sql
-- Track top 20 slowest queries
SET tsdb-digest_mode='1';
SET tsdb-digest_topk='20';
LOAD TSDB VARIABLES TO RUNTIME;
```

#### UI Variables

##### `tsdb-ui_enabled`
Control whether HTTP endpoints and UI are accessible.

```sql
-- Disable UI endpoints (internal API still works)
SET tsdb-ui_enabled='false';
LOAD TSDB VARIABLES TO RUNTIME;
```

When disabled:
- `/api/tsdb/status` → 404
- `/api/tsdb/query` → 404
- `/api/tsdb/metrics` → 404
- `/ui/` → 404

But `GloTSDB->write()` and `GloTSDB->query()` still work internally.

---

## Admin Commands

TSDB provides admin commands accessible via the MySQL admin interface.

### TSDB STATUS

Returns current TSDB subsystem statistics.

```sql
TSDB STATUS;
```

**Output:**
```
+--------------+------------------+----------------------+
| Series_count | Disk_usage_bytes | Last_compaction_ts   |
+--------------+------------------+----------------------+
| 1250         | 52428800        | 1735651200000        |
+--------------+------------------+----------------------+
```

**Columns:**
- `Series_count`: Number of active time series
- `Disk_usage_bytes`: Total disk used by TSDB files
- `Last_compaction_ts`: Unix timestamp (ms) of last compaction

### TSDB QUERY

Query time series data from TSDB.

```sql
TSDB QUERY <metric> [FROM <timestamp_ms>] [TO <timestamp_ms>]
```

**Parameters:**
- `metric`: (Required) Metric name to query
- `FROM`: (Optional) Start timestamp in milliseconds since epoch
- `TO`: (Optional) End timestamp in milliseconds since epoch

**Default Time Range:** If no FROM/TO specified, defaults to last 1 hour.

**Examples:**

```sql
-- Query last hour of backend probe metrics
TSDB QUERY backend_probe_up;

-- Query specific time range
TSDB QUERY proxysql_queries_total FROM 1735651200000 TO 1735737600000;

-- Query returns:
+---------------+---------+---------------------------------------+
| timestamp     | value   | labels                                |
+---------------+---------+---------------------------------------+
| 1735651200000 | 1234.5  | {"hostgroup":"10","endpoint":"..."}    |
| 1735651260000 | 1256.7  | {"hostgroup":"10","endpoint":"..."}    |
+---------------+---------+---------------------------------------+
```

**Return Columns:**
- `timestamp`: Unix timestamp in milliseconds
- `value`: Metric value (double)
- `labels`: JSON object with label key-value pairs

---

## HTTP API

TSDB exposes RESTful HTTP endpoints via ProxySQL's admin HTTP server.

### Authentication

All endpoints require **HTTP Digest Authentication** using ProxySQL admin credentials.

```bash
# Default credentials
username: admin
password: admin

# URL format
http://<host>:6080/api/tsdb/<endpoint>
```

### Endpoints

#### GET /api/tsdb/status

Get TSDB subsystem status.

**Request:**
```bash
curl -u admin:admin http://localhost:6080/api/tsdb/status
```

**Response:**
```json
{
  "series_count": 1250,
  "disk_usage_bytes": 52428800,
  "last_compaction_ts": 1735651200000
}
```

**When Disabled:** Returns 404 if `tsdb-ui_enabled='false'`

#### GET /api/tsdb/query

Query time series data.

**Request:**
```bash
curl -u admin:admin \
  "http://localhost:6080/api/tsdb/query?metric=backend_probe_up&from=1735651200000&to=1735737600000"
```

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `metric` | string | Yes | Metric name |
| `from` | integer | Yes | Start timestamp (ms) |
| `to` | integer | Yes | End timestamp (ms) |

**Response:**
```json
{
  "series": [
    {
      "labels": {
        "hostgroup": "10",
        "endpoint": "192.168.1.10:3306"
      },
      "points": [
        [1735651200000, 1.0],
        [1735651260000, 1.0],
        [1735651320000, 0.0]
      ]
    }
  ]
}
```

**When Disabled:** Returns 404 if `tsdb-ui_enabled='false'` or TSDB not enabled

#### GET /api/tsdb/metrics

Prometheus-compatible metrics export.

**Request:**
```bash
curl -u admin:admin \
  "http://localhost:6080/api/tsdb/metrics?metric=backend_probe_up&from=1735651200000&to=1735737600000"
```

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `metric` | string | No | Metric name (returns empty if not specified) |
| `from` | integer | No | Start timestamp (ms) |
| `to` | integer | No | End timestamp (ms) |

**Default Time Range:** If no FROM/TO specified, defaults to last 5 minutes.

**Response (Prometheus text format):**
```
backend_probe_up{endpoint="192.168.1.10:3306",hostgroup="10"} 1.0 1735651200000
backend_probe_up{endpoint="192.168.1.10:3306",hostgroup="10"} 1.0 1735651260000
backend_probe_up{endpoint="192.168.1.10:3306",hostgroup="10"} 0.0 1735651320000
```

**Integration with Prometheus:**

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'proxysql_tsdb'
    scrape_interval: 1m
    metrics_path: '/api/tsdb/metrics'
    static_configs:
      - targets: ['localhost:6080']
```

**When Disabled:** Returns 404 if `tsdb-ui_enabled='false'`

#### GET /ui/

Access the built-in TSDB dashboard UI.

**Request:**
```bash
curl -u admin:admin http://localhost:6080/ui/
```

**Response:** HTML dashboard page

**When Disabled:** Returns 404 if `tsdb-ui_enabled='false'`

---

## C++ API

The TSDB can be used programmatically from within ProxySQL code via the global `GloTSDB` pointer.

### Including the Header

```cpp
#include "ProxySQL_TSDB.h"

// Global instance
extern ProxySQL_TSDB *GloTSDB;
```

### Writing Metrics

```cpp
// Write a single metric
std::map<std::string, std::string> labels;
labels["hostgroup"] = "10";
labels["endpoint"] = "192.168.1.10:3306";

long long timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();

GloTSDB->write("my_metric", labels, timestamp, 42.0);
```

**Thread Safety:** `write()` is thread-safe and can be called from any ProxySQL thread.

### Querying Metrics

```cpp
// Query a metric
std::map<std::string, std::string> labels; // Empty = all series

long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
long long one_hour_ago = now - 3600000;

auto results = GloTSDB->query("backend_probe_up", labels, one_hour_ago, now, 0, "");

for (const auto& series : results) {
    for (const auto& point : series.points) {
        std::cout << "Timestamp: " << point.timestamp
                  << ", Value: " << point.value << std::endl;
    }
}
```

### Getting Status

```cpp
ProxySQL_TSDB::status_t status = GloTSDB->get_status();
std::cout << "Series: " << status.series_count << std::endl;
std::cout << "Disk: " << status.disk_usage_bytes << " bytes" << std::endl;
```

### Configuration

```cpp
// Check if TSDB is enabled
char* enabled = GloTSDB->get_variable("enabled");
if (enabled && strcmp(enabled, "true") == 0) {
    // TSDB is enabled
    free(enabled);
}

// Set a variable (use Admin interface instead for runtime changes)
// GloTSDB->set_variable("retention_hours", "48"); // Not recommended
```

**Important:** Use the Admin interface (`SET tsdb-xxx='...'`) for runtime configuration changes instead of calling `set_variable()` directly.

---

## Metrics Catalog

### Built-in Metrics

The TSDB sampler automatically collects the following metrics:

#### Traffic Metrics

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `proxysql_queries_total` | Counter | None | Total queries processed |
| `proxysql_query_latency_ms` | Gauge | None | Query latency (ms) |
| `proxysql_frontend_connections` | Gauge | None | Active client connections |

#### Backend Metrics (from Monitor)

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `backend_probe_up` | Gauge | `hostgroup`, `endpoint` | 1 if backend reachable, 0 otherwise |
| `backend_probe_connect_ms` | Gauge | `hostgroup`, `endpoint` | TCP connection time (ms) |

#### Query Digest Metrics

When `tsdb-digest_mode='1'`:

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `proxysql_query_digest_count` | Counter | `hostgroup`, `schema`, `user`, `digest` | Query execution count |
| `proxysql_query_digest_sum_time_us` | Counter | `hostgroup`, `schema`, `user`, `digest` | Total query time (microseconds) |
| `proxysql_query_digest_rows_affected` | Counter | `hostgroup`, `schema`, `user`, `digest` | Rows affected count |
| `proxysql_query_digest_rows_sent` | Counter | `hostgroup`, `schema`, `user`, `digest` | Rows sent count |

### Custom Metrics

You can write custom metrics from your code:

```cpp
// In your ProxySQL module
void track_custom_event(const std::string& event_name, double value) {
    if (!GloTSDB) return;

    std::map<std::string, std::string> labels;
    labels["event"] = event_name;

    long long ts = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    GloTSDB->write("custom_events", labels, ts, value);
}
```

---

## Troubleshooting

### TSDB Not Collecting Data

**Check TSDB is enabled:**
```sql
SELECT @@tsdb-enabled;
-- Should return "true"
```

**Check data directory is writable:**
```bash
ls -ld /var/lib/proxysql/tsdb
# Should show drwxr-xr-x and be owned by proxysql user
```

**Check for errors in ProxySQL log:**
```bash
grep "TSDB:" /var/lib/proxysql/proxysql.log | tail -50
```

### High Series Count

**Check current series count:**
```sql
TSDB STATUS;
```

**Find high-cardinality metrics:**
```bash
find /var/lib/proxysql/tsdb -name "*.data" | wc -l
```

**Solutions:**
- Increase `tsdb-max_series`
- Reduce label cardinality (fewer unique label values)
- Reduce `tsdb-retention_hours`

### Disk Space Issues

**Check disk usage:**
```sql
TSDB STATUS;
-- Check disk_usage_bytes column
```

**Check configured limit:**
```sql
SELECT @@tsdb-max_disk_mb;
```

**Solutions:**
- Increase `tsdb-max_disk_mb`
- Reduce `tsdb-retention_hours`
- Increase `tsdb-raw_window_minutes` (fewer files)

### HTTP Endpoints Return 404

**Check UI is enabled:**
```sql
SELECT @@tsdb-ui_enabled;
-- Should return "true"
```

**Check HTTP server is enabled:**
```sql
SELECT @@admin-web_enabled;
-- Should return "true"
```

**Check HTTP server port:**
```sql
SELECT @@admin-web_port;
-- Default is 6080
```

### Query Digest Not Appearing

**Check digest mode:**
```sql
SELECT @@tsdb-digest_mode;
-- Should be "1" to enable
```

**Check topk setting:**
```sql
SELECT @@tsdb-digest_topk;
-- Should be >= 1
```

**Verify query digest table has data:**
```sql
SELECT COUNT(*) FROM stats_mysql_query_digest;
```

---

## Examples and Use Cases

### Example 1: Enable TSDB for 7-Day Retention

```sql
-- Enable with 7-day retention
SET tsdb-enabled='true';
SET tsdb-retention_hours='168';  -- 7 days
SET tsdb-max_disk_mb='10240';    -- 10GB
SET tsdb-ui_enabled='true';
LOAD TSDB VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
```

### Example 2: Disable UI, Keep Internal Collection

```sql
-- Disable HTTP endpoints but keep metrics
SET tsdb-ui_enabled='false';
LOAD TSDB VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;

-- Internal API still works
-- GloTSDB->query() works from code
```

### Example 3: High-Frequency Sampling

```sql
-- Sample every second (for detailed analysis)
SET tsdb-sample_interval_seconds='1';
SET tsdb-raw_window_minutes='30';  -- Rollup every 30 min
SET tsdb-max_disk_mb='5120';       -- Need more disk
LOAD TSDB VARIABLES TO RUNTIME;
```

### Example 4: Query Last Hour of Backend Health

```sql
-- Via Admin command
TSDB QUERY backend_probe_up;

-- Via HTTP endpoint
# From shell:
curl -u admin:admin \
  "http://localhost:6080/api/tsdb/query?metric=backend_probe_up&from=$(($(date +%s%3N)-3600000))&to=$(date +%s%3N)"

-- Via Prometheus
# Configure prometheus to scrape:
# scrape_configs:
#   - job_name: 'proxysql_tsdb'
#     metrics_path: '/api/tsdb/metrics'
#     params:
#       metric: ['backend_probe_up']
```

### Example 5: Monitor Query Digest Performance

```sql
-- Enable query digest tracking
SET tsdb-digest_mode='1';
SET tsdb-digest_topk='50';  -- Top 50 queries
LOAD TSDB VARIABLES TO RUNTIME;

-- Query after some time has passed
TSDB QUERY proxysql_query_digest_sum_time_us;
```

---

## Best Practices

1. **Start with defaults** - The default settings work well for most deployments
2. **Monitor disk usage** - Set up alerts for `tsdb-max_disk_mb`
3. **Use retention wisely** - Longer retention = more disk usage
4. **Disable UI if not needed** - Saves HTTP server resources
5. **Adjust sampling based on needs** - Higher frequency = more data
6. **Query via UI or HTTP** - More flexible than admin command for complex queries
