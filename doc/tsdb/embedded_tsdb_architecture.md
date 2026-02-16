# TSDB Architecture

## System Design

The TSDB subsystem is an extension of the existing `ProxySQL_Statistics` module, leveraging its proven SQLite-based storage infrastructure.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ProxySQL Core                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    ProxySQL_Statistics                                │  │
│  │                    (SQLite3DB *statsdb_disk)                          │  │
│  ├──────────────────────────────────────────────────────────────────────┤  │
│  │                                                                       │  │
│  │   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐      │  │
│  │   │  tsdb_metrics   │  │tsdb_metrics_hour│  │tsdb_backend_    │      │  │
│  │   │                 │  │                 │  │    health       │      │  │
│  │   │ • timestamp     │  │ • bucket        │  │ • timestamp     │      │  │
│  │   │ • metric_name   │  │ • metric_name   │  │ • hostgroup     │      │  │
│  │   │ • labels (JSON) │  │ • labels (JSON) │  │ • hostname      │      │  │
│  │   │ • value (REAL)  │  │ • avg_value     │  │ • port          │      │  │
│  │   │                 │  │ • max_value     │  │ • probe_up      │      │  │
│  │   │ PRIMARY KEY:    │  │ • min_value     │  │ • connect_ms    │      │  │
│  │   │ (timestamp,     │  │ • count         │  │                 │      │  │
│  │   │  metric_name)   │  │                 │  │ PRIMARY KEY:    │      │  │
│  │   │                 │  │ PRIMARY KEY:    │  │ (timestamp,     │      │  │
│  │   │ WITHOUT ROWID   │  │ (bucket,        │  │  hostgroup,     │      │  │
│  │   │                 │  │  metric_name)   │  │  hostname, port)│      │  │
│  │   │                 │  │                 │  │                 │      │  │
│  │   │ Retention: 7d   │  │ Retention: 1y   │  │ Retention: 7d   │      │  │
│  │   └─────────────────┘  └─────────────────┘  └─────────────────┘      │  │
│  │                                                                       │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Sampler Thread (`tsdb_sampler_loop()`)

**Purpose:** Collect metrics from Prometheus registry

**Frequency:** Every `stats_tsdb_sample_interval` seconds

**Process:**
1. Check if tsdb_sampler_timetoget() returns true
2. If GloVars.prometheus_registry exists:
   - Collect all metric families
   - For each metric, extract labels
   - Insert into tsdb_metrics table
3. Call tsdb_downsample_metrics()

### 2. Monitor Thread (`tsdb_monitor_loop()`)

**Purpose:** Active TCP probes to backend servers

**Frequency:** Every `stats_tsdb_monitor_interval` seconds

**Process:**
1. Check if tsdb_monitor_timetoget() returns true
2. Query runtime_mysql_servers for active backends
3. For each backend:
   - Create TCP socket
   - Measure connect time
   - Record success/failure
   - Insert into tsdb_backend_health

### 3. Compactor (`tsdb_downsample_metrics()`)

**Purpose:** Automatic downsampling and retention enforcement

**Frequency:** Every hour (triggered during sampler loop)

**Process:**
1. Get MAX(bucket) from tsdb_metrics_hour
2. For each hour bucket not yet processed:
   - Aggregate raw data (AVG, MAX, MIN, COUNT)
   - Insert into tsdb_metrics_hour
3. Delete raw data older than 7 days
4. Delete hourly data older than 1 year

**SQL Operations:**
```sql
-- Downsample raw data to hourly aggregates
INSERT OR REPLACE INTO tsdb_metrics_hour
SELECT
  (timestamp/3600)*3600 as bucket,
  metric_name,
  labels,
  AVG(value) as avg_value,
  MAX(value) as max_value,
  MIN(value) as min_value,
  COUNT(*) as count
FROM tsdb_metrics
WHERE timestamp >= ? AND timestamp < ?
GROUP BY bucket, metric_name, labels;

-- Enforce retention
DELETE FROM tsdb_metrics WHERE timestamp < unixepoch() - 7*86400;
DELETE FROM tsdb_metrics_hour WHERE bucket < unixepoch() - 365*86400;
```

### 4. Query Engine

**Purpose:** Serve metric queries via SQL and HTTP API

**Key Methods:**
- `query_tsdb_metrics()` - Query with label filters
- `get_backend_health_metrics()` - Query backend health
- `get_tsdb_status()` - Get TSDB statistics

**Label Filtering:**
```sql
-- Query with label filter using JSON_EXTRACT
SELECT * FROM tsdb_metrics
WHERE metric_name = 'mysql_connections'
AND json_extract(labels, '$.hostgroup') = '1'
AND timestamp BETWEEN 1704067200 AND 1704153600;
```

## Data Flow Diagrams

### Metric Ingestion Flow

```
┌──────────────────┐
│  Metric Source   │
│  (Prometheus)    │
└────────┬─────────┘
         │ Collect()
         ▼
┌──────────────────┐
│  tsdb_sampler_   │
│  loop()          │
│                  │
│  • Extract labels│
│  • Convert JSON  │
│  • Prepare stmt  │
└────────┬─────────┘
         │ INSERT
         ▼
┌──────────────────┐
│  SQLite3         │
│  (tsdb_metrics)  │
└──────────────────┘
```

### Health Probe Flow

```
┌──────────────────┐
│ runtime_mysql_   │
│ servers          │
└────────┬─────────┘
         │ SELECT
         ▼
┌──────────────────┐
│ tsdb_monitor_    │
│ loop()           │
│                  │
│  • TCP connect   │
│  • Measure time  │
│  • Record status │
└────────┬─────────┘
         │ INSERT
         ▼
┌──────────────────┐
│  SQLite3         │
│  (tsdb_backend_  │
│   health)        │
└──────────────────┘
```

## Thread Safety

The TSDB uses SQLite's built-in concurrency control:

1. **SQLite WAL Mode** - Write-Ahead Logging for concurrent reads/writes
2. **Prepared Statements** - Pre-compiled SQL for thread-safe execution
3. **No Additional Locks** - Relies on SQLite's internal locking

## Storage Schema

### tsdb_metrics Table

| Column | Type | Description |
|--------|------|-------------|
| timestamp | INT | Unix timestamp (seconds) |
| metric_name | TEXT | Metric identifier |
| labels | TEXT | JSON object with label key-value pairs |
| value | REAL | Metric value |

**Primary Key:** (timestamp, metric_name)
**Storage:** WITHOUT ROWID

### tsdb_metrics_hour Table

| Column | Type | Description |
|--------|------|-------------|
| bucket | INT | Hour bucket (unix timestamp rounded to hour) |
| metric_name | TEXT | Metric identifier |
| labels | TEXT | JSON labels |
| avg_value | REAL | Average value in bucket |
| max_value | REAL | Maximum value in bucket |
| min_value | REAL | Minimum value in bucket |
| count | INT | Number of samples in bucket |

**Primary Key:** (bucket, metric_name)
**Storage:** WITHOUT ROWID

### tsdb_backend_health Table

| Column | Type | Description |
|--------|------|-------------|
| timestamp | INT | Unix timestamp |
| hostgroup | INT | Backend hostgroup ID |
| hostname | TEXT | Backend hostname |
| port | INT | Backend port |
| probe_up | INT | 1=success, 0=failure |
| connect_ms | INT | Connection time in milliseconds |

**Primary Key:** (timestamp, hostgroup, hostname, port)
**Storage:** WITHOUT ROWID
