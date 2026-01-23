# Embedded TSDB Overview

## Mission
The Embedded TSDB subsystem in ProxySQL provides a "batteries-included" observability solution for deployments where external monitoring infrastructure is either unavailable or overkill. It allows ProxySQL to persist runtime metrics, query digests, and backend monitoring results locally, enabling historical visualization through a built-in dashboard UI.

This system is **not** intended to replace Prometheus/Grafana for large-scale, multi-node aggregations. Instead, it serves as a high-resolution, local flight recorder for individual ProxySQL instances, perfect for deep-dive troubleshooting and standalone monitoring.

## Architecture
The TSDB is designed as a lightweight, bounded subsystem that minimizes impact on the ProxySQL dataplane (Core threads). It operates on dedicated background threads to ensure that metric collection and storage never block query processing.

### High-Level Components

```
+---------------------+       +-----------------------+
|  ProxySQL Core      |       |      TSDB Subsystem   |
|                     |       |                       |
|  [Prometheus Exp] --+-----> |  [Sampler Thread]     |
|                     |       |          |            |
|  [Admin Stats] -----+       |          v            |
|                     |       |    [Write Queue]      |
|                     |       |          |            |
+---------------------+       |          v            |
                              |   [Writer Thread]     |
                              |          |            |
                              |          v            |
                              |   [Disk Storage]      |
                              +----------+------------+
                                         ^
                                         |
+---------------------+       +----------+------------+
|  HTTP Server        | <---- |    [Query Engine]     |
|  (Admin Port)       |       +-----------------------+
+---------------------+
```

1.  **Sampler Thread**: Periodically (default: 5s) snapshots internal ProxySQL metrics. It sources data from:
    *   **Prometheus Registry**: Standard internal counters and gauges.
    *   **Query Digest**: Top-K queries by execution time (configurable).
    *   **Internal State**: Connection pool stats, memory usage, etc.

2.  **Monitor Thread**: An independent scheduler that performs active health checks against backend servers.
    *   **TCP Connect**: Measures network latency and availability.
    *   **Ping**: Measures application-level availability.
    *   These probes are stored as distinct metrics (`backend_probe_up`, `backend_probe_connect_ms`).

3.  **Storage Engine**: A custom, append-only storage system designed for:
    *   **High Write Throughput**: Metrics are batched and appended to series-specific files.
    *   **Isolation**: Each metric series (unique combination of name + labels) is stored independently to facilitate fast lookups.
    *   **Bounded Growth**: FIFO retention policies ensure disk usage remains within configured limits (`max_disk_mb`).

4.  **Query Engine**: Provides an interface for retrieving time-series data. It handles:
    *   **Time Range Filtering**: Efficiently scanning files for requested timestamps.
    *   **Aggregation**: (Future) Downsampling data for longer time ranges.
    *   **Label Filtering**: Selecting series based on dimensions (e.g., `hostgroup=10`).

### Storage Internals
The data is stored in the directory defined by `admin-tsdb_data_dir` (default: `<datadir>/tsdb`).

*   **Structure**:
    *   `raw_<timestamp>.tsdb`: Temporary raw write buffers (if enabled).
    *   `<metric>__<label>_<val>.data`: Per-series binary files.
*   **Format**:
    *   Each file is a sequence of binary records: `[Timestamp: 64-bit][Value: 64-bit double]`.
    *   This simple format avoids complex index management overhead, relying on the filesystem for series lookups.

## Performance & Trade-offs

### Design Decisions
*   **Bounded Cardinality**: To prevent resource exhaustion (inode usage, memory), the TSDB enforces strict limits on the number of active series (`max_series`). High-cardinality labels (like random query IDs) are aggregated or dropped.
*   **No Complex Index**: We do not maintain an inverted index (like Lucene). Searching for metrics by label involves scanning the series registry (filenames). This is acceptable because the number of series per ProxySQL instance is typically < 10,000.
*   **Fixed Retention**: Defaulted to 24 hours. The system is a "ring buffer" for metrics.

### Resource Impact
*   **CPU**: Minimal. Sampling and writing happen on low-priority threads.
*   **Memory**: The "Series Registry" keeps track of active series in memory. For 10k series, this overhead is < 50MB.
*   **Disk I/O**: Writes are buffered. Usage depends on `sample_interval`. At 5s intervals with 1000 active series, expect ~3MB/hour of writes.

## Thread Model
*   **Writer Thread**: Consumes the `write_queue` and persists data. It handles `fsync` logic to balance durability vs performance.
*   **Monitor Thread**: Runs autonomously to ensure probe intervals are consistent, regardless of system load.
*   **Compactor Thread**: (Planned) Runs periodically to delete old data files and potentially merge small files.