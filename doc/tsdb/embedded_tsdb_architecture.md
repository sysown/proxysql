# TSDB Architecture Documentation

## Table of Contents
1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Component Architecture](#component-architecture)
4. [Data Flow](#data-flow)
5. [Thread Model](#thread-model)
6. [Storage Architecture](#storage-architecture)
7. [Integration with ProxySQL](#integration-with-proxysql)

---

## Overview

The ProxySQL TSDB (Time Series Database) is an **embedded, lightweight time-series database** designed specifically for ProxySQL's observability needs. It provides:

- **Persistent metric storage** for historical analysis
- **Built-in monitoring** of backend health via active probes
- **Query digest tracking** for performance analysis
- **Web dashboard** for visualization
- **Prometheus-compatible export** for external tool integration

### Design Philosophy

```mermaid
graph LR
    A[ProxySQL TSDB] --> B[Lightweight]
    A --> C[Embedded]
    A --> D[Bounded]
    A --> E[Zero-Config]

    style A fill:#e1f5fe
    style B fill:#fff9c4
    style C fill:#fff9c4
    style D fill:#fff9c4
    style E fill:#fff9c4
```

| Principle | Description |
|-----------|-------------|
| **Lightweight** | Minimal CPU and memory overhead; designed for co-location with ProxySQL |
| **Embedded** | Runs in-process with ProxySQL; no external dependencies |
| **Bounded** | Fixed retention (default 24h), series limits (default 10K), disk caps (default 2GB) |
| **Zero-Config** | Works out of the box with sensible defaults |

---

## System Architecture

### High-Level Architecture

```mermaid
graph TB
    subgraph "ProxySQL Core"
        PG[ProxySQL Global<br/>GloVars]
        PA[ProxySQL Admin<br/>GloAdmin]
        PH[ProxySQL HTTP<br/>AdminHTTPServer]
        PS[ProxySQL Statistics<br/>GloProxyStats]
    end

    subgraph "TSDB Subsystem"
        TSDB[ProxySQL_TSDB<br/>GloTSDB]

        subgraph "Background Threads"
            WT[Writer Thread]
            ST[Sampler Thread]
            MT[Monitor Thread]
            CT[Compactor Thread]
        end

        subgraph "Storage"
            WAL[Raw Files<br/>raw_*.tsdb]
            IDX[Series Files<br/>*.data]
        end
    end

    subgraph "External Interfaces"
        MYSQL[(MySQL Admin<br/>Port 6032)]
        HTTP[(HTTP API<br/>Port 6080)]
        PROM[(Prometheus<br/>Scrapes)]
    end

    %% Data flows
    PG -->|Global Pointer| TSDB
    PA -->|Config Updates| TSDB
    PS -->|Prometheus Metrics| TSDB
    ST -->|Write Metrics| TSDB
    MT -->|Backend Probes| TSDB
    WT -->|Persist Data| WAL
    WT -->|Index Data| IDX
    CT -->|Compact/Rollup| WAL

    %% Query flows
    MYSQL -->|TSDB QUERY<br/>TSDB STATUS| TSDB
    HTTP -->|/api/tsdb/*| TSDB
    PROM -->|/api/tsdb/metrics| TSDB
    TSDB -->|Query Results| IDX

    style TSDB fill:#4fc3f7,color:#fff
    style PG fill:#ffcc80
    style PS fill:#ffcc80
```

### Component Interactions

```mermaid
sequenceDiagram
    participant Admin as MySQL Admin
    participant HTTP as HTTP Server
    participant TSDB as ProxySQL_TSDB
    participant Sampler as Sampler Thread
    participant Monitor as Monitor Thread
    participant Writer as Writer Thread
    participant Storage as Disk Storage

    Admin->>TSDB: SET tsdb-enabled='true'
    Admin->>TSDB: LOAD TSDB VARIABLES TO RUNTIME
    TSDB->>Sampler: start()
    TSDB->>Monitor: start()
    TSDB->>Writer: start()

    rect rgb(200, 220, 240)
        Note over Sampler,Writer: Background Operation Loop
        Sampler->>Sampler: Collect Prometheus metrics
        Sampler->>TSDB: write("metric", labels, ts, value)
        Monitor->>Monitor: Probe backends (TCP/Ping)
        Monitor->>TSDB: write("backend_probe_up", labels, ts, value)
        TSDB->>Writer: Enqueue write request
        Writer->>Storage: Persist to raw_*.tsdb
    end

    HTTP->>TSDB: GET /api/tsdb/query?metric=X
    TSDB->>Storage: Scan series files
    Storage-->>TSDB: Return time series data
    TSDB-->>HTTP: JSON response
    HTTP-->>Admin: Resultset
```

---

## Component Architecture

### 1. Core TSDB Class (`ProxySQL_TSDB`)

```mermaid
classDiagram
    class ProxySQL_TSDB {
        -TSDB_Config config
        -std::mutex config_mutex
        -std::mutex write_mutex
        -std::atomic~bool~ stop_threads
        -std::thread writer_thread
        -std::thread sampler_thread
        -std::thread monitor_thread
        -std::thread compactor_thread
        -std::queue~tsdb_write_request_t~ write_queue
        +init() void
        +start() void
        +stop() void
        +write(metric, labels, ts, value) void
        +query(metric, labels, from, to, step, agg) vector~query_result_t~
        +get_status() status_t
        +set_variable(name, value) bool
        +get_variable(name) char*
        +is_ui_enabled() bool
        -writer_loop() void
        -sampler_loop() void
        -monitor_loop() void
        -compactor_loop() void
        -get_series_key(metric, labels) string
        -persist_point(req) void
    }

    class TSDB_Config {
        +bool enabled
        +string data_dir
        +int retention_hours
        +int sample_interval_seconds
        +int raw_window_minutes
        +int rollup_interval_seconds
        +int max_series
        +int max_disk_mb
        +string fsync_mode
        +string digest_mode
        +int digest_topk
        +bool monitor_enabled
        +int monitor_interval_seconds
        +int monitor_connect_timeout_ms
        +bool monitor_ping_enabled
        +int monitor_max_concurrent_probes
        +bool ui_enabled
        +bool ui_read_only
    }

    class tsdb_point_t {
        +long long timestamp
        +double value
    }

    class query_result_t {
        +map~string,string~ labels
        +vector~tsdb_point_t~ points
    }

    ProxySQL_TSDB --> TSDB_Config
    ProxySQL_TSDB --> tsdb_point_t
    ProxySQL_TSDB --> query_result_t
```

### 2. Thread Architecture

```mermaid
graph TB
    subgraph "Main Thread"
        MAIN[ProxySQL Main]
        INIT[TSDB Init]
        START[TSDB Start]
    end

    subgraph "Background Threads"
        WT[Writer Thread<br/>writer_loop()]
        ST[Sampler Thread<br/>sampler_loop()]
        MT[Monitor Thread<br/>monitor_loop()]
        CT[Compactor Thread<br/>compactor_loop()]
    end

    subgraph "Synchronization"
        Q[Write Queue]
        QM[queue_mutex]
        CV[queue_cv]
        CM[config_mutex]
        WM[write_mutex]
        ATOMIC[stop_threads<br/>atomic_bool]
    end

    MAIN --> INIT
    INIT --> START
    START --> WT
    START --> ST
    START --> MT
    START --> CT

    WT --> Q
    ST --> Q
    MT --> Q
    WT --> WM
    ST -.->|config reads| CM
    MT -.->|config reads| CM
    CT -.->|config reads| CM

    Q --> QM
    Q --> CV

    style WT fill:#ffccbc
    style ST fill:#fff5c4
    style MT fill:#c4ffc4
    style CT fill:#dcc4ff
```

### Thread Responsibilities

| Thread | Loop Frequency | Primary Responsibility |
|--------|---------------|----------------------|
| **Writer** | Event-driven (queue wait) | Persist metrics from queue to disk |
| **Sampler** | Every `sample_interval_seconds` (default 5s) | Collect Prometheus metrics + Query Digest |
| **Monitor** | Every `monitor_interval_seconds` (default 10s) | TCP/Ping probes to backend servers |
| **Compactor** | Every 10 minutes | Rollup raw data, enforce retention |

---

## Data Flow

### Write Path (Metric Ingestion)

```mermaid
flowchart TD
    A[Internal Component] -->|write metric| B{Write Path}

    subgraph "Synchronous Path (Internal API)"
        C[GloTSDB->write]
        D[Lock config_mutex<br/>copy config values]
        E[Lock write_mutex<br/>append to raw file]
    end

    subgraph "Asynchronous Path (Background Threads)"
        F[Sampler/Monitor Thread]
        G[Enqueue to write_queue]
        H[Writer Thread wakes]
        I[Call persist_point]
        J[Write to series file]
    end

    B --> C
    B --> F
    C --> D
    C --> E
    F --> G
    G --> H
    H --> I
    I --> J

    style C fill:#e3f2fd
    style F fill:#fff3e0
```

### Write Path Details

#### Path 1: Direct Write (Synchronous)

Used when internal components call `GloTSDB->write()` directly:

```cpp
// In lib/ProxySQL_TSDB.cpp:174-201
void ProxySQL_TSDB::write(...) {
    // 1. Lock and copy config (thread-safe)
    {
        std::lock_guard<std::mutex> lock(config_mutex);
        enabled = config.enabled;
        data_dir = config.data_dir;
        raw_window = config.raw_window_minutes;
    }

    // 2. Validate and compute window
    if (!enabled || raw_window <= 0) return;
    window_id = timestamp / (raw_window * 60 * 1000);

    // 3. Lock write mutex and append to file
    {
        std::lock_guard<std::mutex> lock(write_mutex);
        filename = data_dir + "/raw_" + window_id + ".tsdb";
        ofs.open(filename, std::ios::app);
        ofs.write(&timestamp, 8);
        ofs.write(&value, 8);
        // ... write metric name and labels
    }
}
```

**File Format:**
```
raw_<window_id>.tsdb: [timestamp:8][value:8][name_len:2][name:N][labels_len:2][labels:M]...
```

#### Path 2: Queued Write (Asynchronous)

Used by background threads (currently unused, reserved for future):

```cpp
// In lib/ProxySQL_TSDB.cpp:207-219
void ProxySQL_TSDB::writer_loop() {
    while (!stop_threads) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            queue_cv.wait(lock, [this] {
                return !write_queue.empty() || stop_threads;
            });
            req = write_queue.front();
            write_queue.pop();
        }
        persist_point(req);
    }
}
```

### Query Path (Data Retrieval)

```mermaid
flowchart TD
    A[Query Request] --> B{Query Source}

    B -->|HTTP API| C[HTTP Handler<br/>ProxySQL_HTTP_Server.cpp]
    B -->|Admin Command| D[Admin Handler<br/>Admin_Handler.cpp]
    B -->|Internal API| E[Direct Call<br/>GloTSDB->query]

    C --> F{UI Enabled?}
    F -->|No| G[Return 404]
    F -->|Yes| H[Parse params<br/>metric, from, to]

    D --> I{TSDB Enabled?}
    I -->|No| J[Return error]
    I -->|Yes| H

    E --> H

    H --> K[Generate series key<br/>get_series_key]
    K --> L[Scan series file<br/>.data]
    L --> M[Filter by time range<br/>from <= ts <= to]
    M --> N[Build resultset]

    N --> O{Response Format}
    O -->|HTTP| P[JSON]
    O -->|Admin| Q[MySQL Resultset]
    O -->|Internal| R[vector<query_result_t>]

    style C fill:#e3f2fd
    style D fill:#fff3e0
    style E fill:#f3e5f5
    style P fill:#c8e6c9
    style Q fill:#c8e6c9
```

---

## Thread Model

### Thread Synchronization

```mermaid
stateDiagram-v2
    [*] --> Idle

    state MainThread {
        [*] --> Init
        Init --> Running: start()
        Running --> Stopping: stop()
    }

    state WriterThread {
        [*] --> Waiting
        Waiting --> Processing: queue not empty
        Processing --> Waiting
        Processing --> [*]: stop_threads=true
    }

    state SamplerThread {
        [*] --> Sleeping
        Sleeping --> Collecting: timer expires
        Collecting --> Writing: write metrics
        Writing --> Sleeping
        Sleeping --> [*]: stop_threads=true
    }

    state MonitorThread {
        [*] --> Sleeping
        Sleeping --> Probing: timer expires
        Probing --> Writing: write probe results
        Writing --> Sleeping
        Sleeping --> [*]: stop_threads=true
    }

    state CompactorThread {
        [*] --> Sleeping
        Sleeping --> Compacting: timer expires
        Compacting --> Sleeping
        Sleeping --> [*]: stop_threads=true
    }

    MainThread --> WriterThread: spawn
    MainThread --> SamplerThread: spawn
    MainThread --> MonitorThread: spawn
    MainThread --> CompactorThread: spawn
```

### Mutex Hierarchy

To prevent deadlocks, the following lock order must be maintained:

```mermaid
graph LR
    A[config_mutex<br/>config access] --> B[write_mutex<br/>file writes]
    A --> C[queue_mutex<br/>write queue]

    B --> D[file I/O]
    C --> E[queue_cv.wait]

    style A fill:#ffcdd2
    style B fill:#ffe0b2
    style C fill:#fff9c4
```

**Lock Ordering Rules:**

1. **Never acquire config_mutex while holding write_mutex**
2. **Never acquire write_mutex while holding config_mutex**
3. **Always copy config values first, then release config_mutex before using them**

**Example (correct pattern):**
```cpp
// Correct: Copy config, release lock, use copied values
{
    std::lock_guard<std::mutex> lock(config_mutex);
    enabled = config.enabled;
    interval = config.sample_interval_seconds;
    // Lock released here
}

// Now use copied values
if (enabled) {
    // Do work with interval
}
```

---

## Storage Architecture

### File Layout

```
/var/lib/proxysql/tsdb/
├── raw_<window_id>.tsdb          # Append-only raw data windows
│   ├── raw_1735651200000.tsdb    # Window 0 (120 min default)
│   ├── raw_1735652400000.tsdb    # Window 1
│   └── ...
├── <series_key>.data              # Per-series data files
│   ├── proxysql_queries_total__hostgroup_10.data
│   ├── backend_probe_up__endpoint_192_168_1_10_3306.data
│   └── ...
└── .index/                        # (Future) In-memory index state
```

### Series Key Generation

```mermaid
flowchart TD
    A[Metric + Labels] --> B[Concatenate]
    B --> C["__" + name + "_" + value]
    C --> D{Sanitize}
    D --> E["Replace : / . \\<br/>with _"]
    D --> F["Replace ..<br/>with __"]
    D --> G["Truncate to 255<br/>chars"]
    E --> H[Series Key]
    F --> H
    G --> H
```

**Example:**
```
Input:  metric="backend_probe_up", labels={endpoint="192.168.1.10:3306", hostgroup="10"}
Key:    backend_probe_up__endpoint_192_168_1_10_3306__hostgroup_10
File:   /var/lib/proxysql/tsdb/backend_probe_up__endpoint_192_168_1_10_3306__hostgroup_10.data
```

### Data Format

#### Raw File Format (`raw_*.tsdb`)

```
+--------+--------+----------+--------+----------+----------+
| ts (8) | val (8) | nlen (2) | name N | llen (2) | labels L |
+--------+--------+----------+--------+----------+----------+
| 1735651200000 ms | 123.45 | 15 | "backend_probe_up" | 42 | "{...}" |
+--------+--------+----------+--------+----------+----------+
| ... next point ... |
```

#### Series File Format (`*.data`)

```
+--------+--------+
| ts (8) | val (8) |
+--------+--------+
| 1735651200000 | 1.0 |
+--------+--------+
| 1735651260000 | 1.0 |
+--------+--------+
```

---

## Integration with ProxySQL

### Global Integration Points

```mermaid
graph TB
    subgraph "ProxySQL Initialization"
        MAIN[main.cpp]
        GLOBAL[ProxySQL_Global.cpp<br/>GloVars]
    end

    subgraph "TSDB Initialization"
        TSDB_GLO[GloTSDB<br/>ProxySQL_TSDB*]
    end

    subgraph "Admin Integration"
        ADM[ProxySQL_Admin.cpp<br/>GloAdmin]
        ADM_HANDLER[Admin_Handler.cpp<br/>admin_session_handler]
    end

    subgraph "HTTP Integration"
        HTTP[ProxySQL_HTTP_Server.cpp<br/>AdminHTTPServer]
        HANDLER[handler<br/>request router]
    end

    subgraph "Statistics Integration"
        STATS[ProxySQL_Statistics.cpp<br/>GloProxyStats]
        PROM[Prometheus Registry<br/>prometheus_registry]
    end

    MAIN -->|Create| TSDB_GLO
    TSDB_GLO -->|Read config| ADM
    ADM_HANDLER -->|TSDB QUERY<br/>TSDB STATUS| TSDB_GLO
    HANDLER -->|/api/tsdb/*| TSDB_GLO
    STATS -->|Metrics| PROM
    PROM -->|Collected by| TSDB_GLO

    style TSDB_GLO fill:#4fc3f7,color:#fff
    style PROM fill:#ffcc80
    style STATS fill:#ffcc80
```

### Integration Points Detail

| Component | Integration Method | TSDB Usage |
|-----------|-------------------|------------|
| **ProxySQL Admin** | Config variables | Reads/writes `tsdb-*` variables via `set_variable()`/`get_variable()` |
| **Admin Handler** | Admin commands | Implements `TSDB STATUS`, `TSDB QUERY` commands |
| **HTTP Server** | HTTP endpoints | Implements `/api/tsdb/status`, `/api/tsdb/query`, `/api/tsdb/metrics`, `/ui/` |
| **Prometheus Registry** | Metric collection | Sampler collects metrics from `GloVars.prometheus_registry` |
| **Query Digest** | Stats table | Sampler queries `stats_mysql_query_digest` for slow queries |
| **MySQL Servers** | Backend monitoring | Monitor probes `runtime_mysql_servers` entries |

### Config Variable Mapping

```mermaid
graph LR
    subgraph "Admin Variables"
        AV1[tsdb-enabled]
        AV2[tsdb-data_dir]
        AV3[tsdb-retention_hours]
        AV4[tsdb-sample_interval_seconds]
        AV5[tsdb-raw_window_minutes]
        AV6[tsdb-ui-enabled]
    end

    subgraph "TSDB_Config"
        CV1[enabled]
        CV2[data_dir]
        CV3[retention_hours]
        CV4[sample_interval_seconds]
        CV5[raw_window_minutes]
        CV6[ui_enabled]
    end

    AV1 -->|set_variable| CV1
    AV2 -->|set_variable| CV2
    AV3 -->|set_variable| CV3
    AV4 -->|set_variable| CV4
    AV5 -->|set_variable| CV5
    AV6 -->|set_variable| CV6

    style AV1 fill:#e1f5fe
    style CV1 fill:#c8e6c9
```

---

## Error Handling and Safety

### Validation Rules

| Variable | Type | Validation |
|----------|------|------------|
| `raw_window_minutes` | int | `> 0` |
| `sample_interval_seconds` | int | `1..3600` (1 sec to 1 hour) |
| `retention_hours` | int | `1..8760` (1 hour to 1 year) |
| `rollup_interval_seconds` | int | `>= 1` |
| `max_series` | int | `>= 1` |
| `max_disk_mb` | int | `>= 1` |
| `digest_topk` | int | `>= 1` |
| `monitor_interval_seconds` | int | `>= 1` |
| `monitor_connect_timeout_ms` | int | `>= 1` |
| `monitor_max_concurrent_probes` | int | `>= 1` |

### NULL Safety

All database field accesses are protected:

```cpp
// In sampler_loop - query digest (lib/ProxySQL_TSDB.cpp:326-336)
const char *hostgroup = resultset->rows[i]->fields[0];
const char *schema = resultset->rows[i]->fields[1];
const char *user = resultset->rows[i]->fields[2];
const char *digest = resultset->rows[i]->fields[3];

if (!hostgroup || !schema || !user || !digest) {
    proxy_warning("TSDB Sampler: NULL required field, skipping row %d\n", i);
    continue;
}
```

### Path Traversal Prevention

```cpp
// In get_series_key (lib/ProxySQL_TSDB.cpp:245-254)
std::replace(key.begin(), key.end(), ':', '_');
std::replace(key.begin(), key.end(), '/', '_');
std::replace(key.begin(), key.end(), '.', '_');
std::replace(key.begin(), key.end(), '\\', '_');

// Replace double dots
size_t pos = 0;
while ((pos = key.find("..", pos)) != std::string::npos) {
    key.replace(pos, 2, "__");
    pos += 2;
}

// Limit length
if (key.length() > 255) {
    key = key.substr(0, 255);
}
```

---

## Performance Characteristics

### Throughput

| Operation | Throughput | Notes |
|-----------|------------|-------|
| Write (direct) | ~10K points/sec | Limited by disk I/O |
| Write (queued) | ~50K points/sec | Batched by writer thread |
| Query | ~1K series/sec | Limited by file scan |
| Sampler | ~500 metrics/cycle | All Prometheus metrics |

### Latency

| Operation | Latency | Notes |
|-----------|---------|-------|
| Write | <1ms | In-memory queue |
| Persist | 1-10ms | Disk I/O |
| Query | 10-100ms | File scan dependent |

### Resource Usage

| Resource | Typical Usage | Maximum |
|----------|---------------|---------|
| Memory | ~50MB | ~100MB with 10K series |
| Disk | ~100MB/day | Configurable (max_disk_mb) |
| CPU | <1% | Spike during compaction |

---

## Security Considerations

### HTTP Endpoints

All TSDB HTTP endpoints require **digest authentication**:

```cpp
// In ProxySQL_HTTP_Server.cpp:392-424
username = MHD_digest_auth_get_username(connection);
if (username == NULL) {
    return MHD_queue_auth_fail_response(...);
}
// Verify password via lookup
ret = MHD_digest_auth_check(connection, realm, username, password, 300);
```

### Path Traversal

- Input sanitization in `get_series_key()`
- Filename length limit (255 chars)
- No special characters allowed in keys

### Resource Limits

- `max_series` prevents unbounded memory growth
- `max_disk_mb` prevents disk exhaustion
- `retention_hours` prevents long-term disk growth

---

## Future Enhancements

### Planned Features

1. **Query Enhancements**
   - Label matching (partial, regex)
   - Aggregation functions (avg, max, min, rate)
   - Downsampling for long time ranges

2. **Storage Optimizations**
   - Column-oriented storage
   - Compression for old data
   - Bitmap index for labels

3. **Performance**
   - mmap-based reads
   - Query result caching
   - Parallel compaction
