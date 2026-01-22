# Embedded TSDB Metrics Catalog

The following metrics are curated and stored by the TSDB sampler.

## Traffic / Latency
| Metric | Type | Description |
| --- | --- | --- |
| `proxysql_queries_total` | Counter | Total number of queries processed. |
| `proxysql_query_errors_total` | Counter | Total number of query errors. |
| `proxysql_query_latency_ms` | Gauge | p50, p95, and p99 query latency (derived). |

## Connections
| Metric | Type | Description |
| --- | --- | --- |
| `proxysql_frontend_connections` | Gauge | Number of active client connections. |
| `proxysql_backend_connections` | Gauge | Number of active backend connections (by hostgroup/backend). |
| `proxysql_connection_pool_saturation` | Gauge | Percentage of pool usage. |

## Backend Health (Probes)
| Metric | Type | Description |
| --- | --- | --- |
| `backend_probe_up` | Gauge | 1 if backend is reachable, 0 otherwise. |
| `backend_probe_connect_ms` | Gauge | TCP connection latency in ms. |
| `backend_state` | Gauge | Current state of the backend (Enum). |

## Proxy Health
| Metric | Type | Description |
| --- | --- | --- |
| `proxysql_uptime_seconds` | Gauge | Uptime of the ProxySQL process. |
| `proxysql_memory_bytes` | Gauge | Resident set size (RSS) memory usage. |
| `tsdb_series_count` | Gauge | Number of active series in the TSDB. |
