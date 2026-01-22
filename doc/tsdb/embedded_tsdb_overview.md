# Embedded TSDB Overview

## Mission
The Embedded TSDB subsystem in ProxySQL provides a "batteries-included" observability solution for small to medium deployments. It allows ProxySQL to persist runtime metrics and backend monitoring results locally, enabling historical visualization through a built-in dashboard UI without requiring external infrastructure like Prometheus and Grafana.

## Architecture
The TSDB is designed as a lightweight, bounded subsystem that minimizes impact on the ProxySQL dataplane.

### Components
1. **Sampler**: Periodically snapshots internal ProxySQL metrics (from the Prometheus registry) and enqueues them for storage.
2. **Backend Monitor Probes**: Independent scheduler that performs health checks (TCP, Ping) and stores results as time series.
3. **Storage Engine**: A custom, append-only segment-based storage system designed for high write throughput and fast range queries.
4. **Query Engine**: Provides an internal and HTTP JSON API for retrieving time series data.
5. **Built-in UI**: A minimal web interface served by ProxySQL's admin HTTP server that visualizes the stored metrics.

### Storage Design
- **Append-only Segments**: Data is written to immutable segment files.
- **In-memory Index**: A mapping of series keys to segment locations for fast lookups.
- **WAL (Write-Ahead Log)**: Ensures crash safety for recent writes.
- **Compactor**: Periodically rolls up raw data (L0) into minute-level buckets (L1) and enforces retention policies.

## Trade-offs
- **Bounded Cardinality**: To prevent resource exhaustion, the TSDB enforces strict limits on the number of active series.
- **Fixed Retention**: Defaulted to 24 hours, suitable for immediate troubleshooting and performance analysis.
- **Resolution**: Sampling interval is typically 5 seconds, providing enough granularity for most ProxySQL use cases while keeping disk I/O low.
