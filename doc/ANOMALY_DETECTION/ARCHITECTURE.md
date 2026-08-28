# Anomaly Detection Architecture

## System Architecture and Design Documentation

This document provides detailed architecture information for the Anomaly Detection feature in ProxySQL.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Component Architecture](#component-architecture)
3. [Detection Pipeline](#detection-pipeline)
4. [Data Structures](#data-structures)
5. [Algorithm Details](#algorithm-details)
6. [Integration Points](#integration-points)
7. [Performance Considerations](#performance-considerations)
8. [Security Architecture](#security-architecture)

---

## System Overview

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Client Application                       │
└─────────────────────────────────────┬───────────────────────────┘
                                      │
                                      │ MySQL Protocol
                                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                           ProxySQL                               │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    MySQL_Session                            │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │ │
│  │  │   Protocol   │  │   Query      │  │   Result     │     │ │
│  │  │   Handler    │  │   Parser     │  │   Handler    │     │ │
│  │  └──────────────┘  └──────┬───────┘  └──────────────┘     │ │
│  │                           │                                 │ │
│  │                    ┌──────▼───────┐                         │ │
│  │                    │   libinjection│                         │ │
│  │                    │   SQLi Check  │                         │ │
│  │                    └──────┬───────┘                         │ │
│  │                           │                                 │ │
│  │                    ┌──────▼───────┐                         │ │
│  │                    │    AI        │                         │ │
│  │                    │  Anomaly     │◄──────────┐            │ │
│  │                    │  Detection   │           │            │ │
│  │                    └──────┬───────┘           │            │ │
│  │                           │                   │            │ │
│  └───────────────────────────┼───────────────────┘            │ │
│                              │                                │
└──────────────────────────────┼────────────────────────────────┘
                               │
┌──────────────────────────────▼────────────────────────────────┐
│                     AI_Features_Manager                        │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │                   Anomaly_Detector                        │ │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐         │ │
│  │  │  Pattern   │  │    Rate    │  │ Statistical│         │ │
│  │  │  Matching  │  │  Limiting  │  │ Analysis   │         │ │
│  │  └────────────┘  └────────────┘  └────────────┘         │ │
│  │                                                          │ │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐         │ │
│  │  │ Normalize  │  │  Embedding │  │  User      │         │ │
│  │  │   Query    │  │ Similarity │  │ Statistics │         │ │
│  │  └────────────┘  └────────────┘  └────────────┘         │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │                  Configuration                            │ │
│  │  • risk_threshold                                        │ │
│  │  • rate_limit                                            │ │
│  │  • auto_block                                            │ │
│  │  • log_only                                              │ │
│  └──────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Defense in Depth**: Multiple detection layers for comprehensive coverage
2. **Performance First**: Minimal overhead on query processing
3. **Configurability**: All thresholds and behaviors configurable
4. **Observability**: Detailed metrics and logging
5. **Fail-Safe**: Legitimate queries not blocked unless clear threat

---

## Component Architecture

### Anomaly_Detector Class

**Location:** `include/Anomaly_Detector.h`, `lib/Anomaly_Detector.cpp`

**Responsibilities:**
- Coordinate all detection methods
- Aggregate results from multiple detectors
- Manage user statistics
- Provide configuration interface

**Key Members:**
```cpp
class Anomaly_Detector {
private:
    struct {
        bool enabled;
        int risk_threshold;
        int similarity_threshold;
        int rate_limit;
        bool auto_block;
        bool log_only;
    } config;

    SQLite3DB* vector_db;

    struct UserStats {
        uint64_t query_count;
        uint64_t last_query_time;
        std::vector<std::string> recent_queries;
    };
    std::unordered_map<std::string, UserStats> user_statistics;
};
```

### MySQL_Session Integration

**Location:** `lib/MySQL_Session.cpp:3626`

**Function:** `MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_detect_ai_anomaly()`

**Responsibilities:**
- Extract query context (user, host, schema)
- Call Anomaly_Detector::analyze()
- Handle blocking logic
- Generate error responses

### Status Variables

**Locations:**
- `include/MySQL_Thread.h:93-94` - Enum declarations
- `lib/MySQL_Thread.cpp:167-168` - Definitions
- `lib/MySQL_Thread.cpp:805-816` - Prometheus metrics

**Variables:**
- `ai_detected_anomalies` - Total anomalies detected
- `ai_blocked_queries` - Total queries blocked

---

## Detection Pipeline

### Pipeline Flow

```
Query Arrives
    │
    ├─► 1. Query Normalization
    │      ├─ Lowercase conversion
    │      ├─ Comment removal
    │      ├─ Literal replacement
    │      └─ Whitespace normalization
    │
    ├─► 2. SQL Injection Pattern Detection
    │      ├─ Regex pattern matching (11 patterns)
    │      ├─ Keyword matching (11 keywords)
    │      └─ Risk score calculation
    │
    ├─► 3. Rate Limiting Check
    │      ├─ Lookup user statistics
    │      ├─ Calculate queries/minute
    │      └─ Compare against threshold
    │
    ├─► 4. Statistical Anomaly Detection
    │      ├─ Calculate Z-scores
    │      ├─ Check execution time
    │      ├─ Check result set size
    │      └─ Check query frequency
    │
    ├─► 5. Embedding Similarity Check (Future)
    │      ├─ Generate query embedding
    │      ├─ Search threat database
    │      └─ Calculate similarity score
    │
    └─► 6. Result Aggregation
           ├─ Combine risk scores
           ├─ Determine blocking action
           └─ Update statistics
```

### Result Aggregation

```cpp
// Pseudo-code for result aggregation
AnomalyResult final;

for (auto& result : detection_results) {
    if (result.is_anomaly) {
        final.is_anomaly = true;
        final.risk_score = std::max(final.risk_score, result.risk_score);
        final.anomaly_type += result.anomaly_type + ",";
        final.matched_rules.insert(final.matched_rules.end(),
                                   result.matched_rules.begin(),
                                   result.matched_rules.end());
    }
}

final.should_block =
    final.is_anomaly &&
    final.risk_score > (config.risk_threshold / 100.0) &&
    config.auto_block &&
    !config.log_only;
```

---

## Data Structures

### AnomalyResult

```cpp
struct AnomalyResult {
    bool is_anomaly;                       // Anomaly detected flag
    float risk_score;                      // 0.0-1.0 risk score
    std::string anomaly_type;              // Type classification
    std::string explanation;               // Human explanation
    std::vector<std::string> matched_rules; // Matched rule IDs
    bool should_block;                     // Block decision
};
```

### QueryFingerprint

```cpp
struct QueryFingerprint {
    std::string query_pattern;    // Normalized query
    std::string user;             // Username
    std::string client_host;      // Client IP
    std::string schema;           // Database schema
    uint64_t timestamp;           // Query timestamp
    int affected_rows;            // Rows affected
    int execution_time_ms;        // Execution time
};
```

### UserStats

```cpp
struct UserStats {
    uint64_t query_count;                    // Total queries
    uint64_t last_query_time;                // Last query timestamp
    std::vector<std::string> recent_queries; // Recent query history
};
```

---

## Algorithm Details

### SQL Injection Pattern Detection

**Regex Patterns:**
```cpp
static const char* SQL_INJECTION_PATTERNS[] = {
    "('|\").*?('|\")",           // Quote sequences
    "\\bor\\b.*=.*\\bor\\b",      // OR 1=1
    "\\band\\b.*=.*\\band\\b",    // AND 1=1
    "union.*select",              // UNION SELECT
    "drop.*table",                // DROP TABLE
    "exec.*xp_",                  // SQL Server exec
    ";.*--",                      // Comment injection
    "/\\*.*\\*/",                 // Block comments
    "concat\\(",                  // CONCAT based attacks
    "char\\(",                    // CHAR based attacks
    "0x[0-9a-f]+",                // Hex encoded
    NULL
};
```

**Suspicious Keywords:**
```cpp
static const char* SUSPICIOUS_KEYWORDS[] = {
    "sleep(", "waitfor delay", "benchmark(", "pg_sleep",
    "load_file", "into outfile", "dumpfile",
    "script>", "javascript:", "onerror=", "onload=",
    NULL
};
```

**Risk Score Calculation:**
- Each pattern match: +20 points
- Each keyword match: +15 points
- Multiple matches: Cumulative up to 100

### Query Normalization

**Algorithm:**
```cpp
std::string normalize_query(const std::string& query) {
    std::string normalized = query;

    // 1. Convert to lowercase
    std::transform(normalized.begin(), normalized.end(),
                   normalized.begin(), ::tolower);

    // 2. Remove comments
    // Remove -- comments
    // Remove /* */ comments

    // 3. Replace string literals with ?
    // Replace '...' with ?

    // 4. Replace numeric literals with ?
    // Replace numbers with ?

    // 5. Normalize whitespace
    // Replace multiple spaces with single space

    return normalized;
}
```

### Rate Limiting

**Algorithm:**
```cpp
AnomalyResult check_rate_limiting(const std::string& user,
                                  const std::string& client_host) {
    std::string key = user + "@" + client_host;
    UserStats& stats = user_statistics[key];

    uint64_t current_time = time(NULL);
    uint64_t time_window = 60; // 1 minute

    // Calculate queries per minute
    uint64_t queries_per_minute =
        stats.query_count * time_window /
        (current_time - stats.last_query_time + 1);

    if (queries_per_minute > config.rate_limit) {
        AnomalyResult result;
        result.is_anomaly = true;
        result.risk_score = 0.8f;
        result.anomaly_type = "rate_limit";
        result.should_block = true;
        return result;
    }

    stats.query_count++;
    stats.last_query_time = current_time;

    return AnomalyResult(); // No anomaly
}
```

### Statistical Anomaly Detection

**Z-Score Calculation:**
```cpp
float calculate_z_score(float value, const std::vector<float>& samples) {
    float mean = calculate_mean(samples);
    float stddev = calculate_stddev(samples, mean);

    if (stddev == 0) return 0.0f;

    return (value - mean) / stddev;
}
```

**Thresholds:**
- Z-score > 3.0: High anomaly (risk score 0.9)
- Z-score > 2.5: Medium anomaly (risk score 0.7)
- Z-score > 2.0: Low anomaly (risk score 0.5)

---

## Integration Points

### Query Processing Flow

**File:** `lib/MySQL_Session.cpp`
**Function:** `MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY()`

**Integration Location:** Line ~5150

```cpp
// After libinjection SQLi detection
if (GloAI && GloAI->get_anomaly_detector()) {
    if (handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_detect_ai_anomaly()) {
        handler_ret = -1;
        return handler_ret;
    }
}
```

### Prometheus Metrics

**File:** `lib/MySQL_Thread.cpp`
**Location:** Lines ~805-816

```cpp
std::make_tuple (
    p_th_counter::ai_detected_anomalies,
    "proxysql_ai_detected_anomalies_total",
    "AI Anomaly Detection detected anomalous query behavior.",
    metric_tags {}
),
std::make_tuple (
    p_th_counter::ai_blocked_queries,
    "proxysql_ai_blocked_queries_total",
    "AI Anomaly Detection blocked queries due to anomalies.",
    metric_tags {}
)
```

---

## Performance Considerations

### Complexity Analysis

| Detection Method | Time Complexity | Space Complexity |
|-----------------|----------------|------------------|
| Query Normalization | O(n) | O(n) |
| Pattern Matching | O(n × p) | O(1) |
| Rate Limiting | O(1) | O(u) |
| Statistical Analysis | O(n) | O(h) |

Where:
- n = query length
- p = number of patterns
- u = number of active users
- h = history size

### Optimization Strategies

1. **Pattern Matching:**
   - Compiled regex objects (cached)
   - Early termination on match
   - Parallel pattern evaluation (future)

2. **Rate Limiting:**
   - Hash map for O(1) lookup
   - Automatic cleanup of stale entries

3. **Statistical Analysis:**
   - Fixed-size history buffers
   - Incremental mean/stddev calculation

### Memory Usage

- Per-user statistics: ~200 bytes per active user
- Pattern cache: ~10 KB
- Total: < 1 MB for 1000 active users

---

## Security Architecture

### Threat Model

**Protected Against:**
1. SQL Injection attacks
2. DoS via high query rates
3. Data exfiltration via large result sets
4. Reconnaissance via schema probing
5. Time-based blind SQLi

**Limitations:**
1. Second-order injection (not in query)
2. Stored procedure injection
3. No application-layer protection
4. Pattern evasion possible

### Defense in Depth

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
│  Input Validation, Parameterized Queries                │
└─────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────────────────────────────────────┐
│                    ProxySQL Layer                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ libinjection │  │   AI         │  │   Rate       │ │
│  │   SQLi       │  │  Anomaly     │  │  Limiting    │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────────────────────────────────────┐
│                   Database Layer                         │
│  Database permissions, row-level security               │
└─────────────────────────────────────────────────────────┘
```

### Access Control

**Bypass Rules:**
1. Admin interface queries bypass detection
2. Local connections bypass rate limiting (configurable)
3. System queries (SHOW, DESCRIBE) bypass detection

**Audit Trail:**
- All anomalies logged with timestamp
- Blocked queries logged with full context
- Statistics available via admin interface
