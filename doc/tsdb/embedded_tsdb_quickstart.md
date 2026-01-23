# Embedded TSDB Quickstart Guide

This guide covers enabling, configuring, and troubleshooting the embedded Time Series Database in ProxySQL.

## 1. Enabling the TSDB
By default, the TSDB subsystem is disabled to save resources. To enable it:

```sql
-- Enable the master switch
SET admin-tsdb_enabled = 'true';

-- (Optional) Enable the active backend monitor
SET admin-tsdb_monitor_enabled = 'true';

-- Persist changes
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
```

*Note: A restart is **not** required. The subsystem will start background threads immediately upon loading to runtime.*

## 2. Configuration Reference
All TSDB variables are prefixed with `admin-tsdb_`.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `enabled` | `false` | Master switch. |
| `data_dir` | (datadir)/tsdb | Directory for storage. |
| `retention_hours` | `24` | Data older than this is deleted. |
| `sample_interval_seconds` | `5` | How often to poll internal metrics. |
| `max_disk_mb` | `2048` | Hard limit on disk usage. |
| `digest_mode` | `off` | Set to `'1'` to enable top-query tracking. |
| `digest_topk` | `20` | Number of top queries to record per sample. |
| `monitor_interval_seconds` | `10` | Frequency of backend active probes. |
| `ui_enabled` | `true` | Enable the embedded web dashboard. |

### Example: High-Resolution Troubleshooting
For a short-term debugging session (e.g., catching micro-bursts), you might increase resolution:

```sql
SET admin-tsdb_sample_interval_seconds = 1;
SET admin-tsdb_retention_hours = 4; -- Reduce retention to save disk
LOAD ADMIN VARIABLES TO RUNTIME;
```

## 3. Accessing the Dashboard
The built-in dashboard is served by the ProxySQL Admin HTTP server.

1.  Ensure the Admin HTTP server is running (check `admin-web_enabled` and `admin-web_port`, usually 6080).
2.  Navigate to: `http://<proxysql-host>:6080/ui/`
3.  Login with your Admin credentials (default: `admin` / `admin`).

The dashboard provides:
*   **Overview Tab**: CPU, Memory, Active Connections.
*   **Traffic Tab**: QPS, Latency, Errors.
*   **Backend Tab**: Health status of all backend servers.

## 4. Querying Data via SQL (Status)
You can inspect the operational status of the TSDB via the Admin interface:

```sql
-- Check if threads are running and general stats
TSDB STATUS;
```

*Example Output:*
```text
+------------------+-------+
| name             | value |
+------------------+-------+
| series_count     | 450   |
| disk_usage_bytes | 15MB  |
| queue_depth      | 0     |
| writer_uptime    | 3600  |
+------------------+-------+
```

## 5. Troubleshooting

### "UI shows no data"
1.  Check `TSDB STATUS` to see if `series_count` is increasing.
2.  Verify permissions: The user running ProxySQL must have write access to `data_dir`.
3.  Check `proxy.log` for errors related to `TSDB`.

### "High Disk Usage"
1.  Lower `admin-tsdb_retention_hours`.
2.  Check `admin-tsdb_max_disk_mb` setting.
3.  If `digest_mode` is enabled, try disabling it or reducing `digest_topk`. Query digests generate high-cardinality data.

### "Performance Impact"
If you suspect TSDB is affecting ProxySQL performance:
1.  Increase `sample_interval_seconds` (e.g., to 15 or 60).
2.  Disable `monitor_enabled` if you have many backends (> 100).
3.  As a last resort, `SET admin-tsdb_enabled='false'`.