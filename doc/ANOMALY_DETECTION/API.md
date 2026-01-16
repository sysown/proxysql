# Anomaly Detection API Reference

## Complete API Documentation for Anomaly Detection Module

This document provides comprehensive API reference for the Anomaly Detection feature in ProxySQL.

---

## Table of Contents

1. [Configuration Variables](#configuration-variables)
2. [Status Variables](#status-variables)
3. [AnomalyResult Structure](#anomalyresult-structure)
4. [Anomaly_Detector Class](#anomaly_detector-class)
5. [MySQL_Session Integration](#mysql_session-integration)

---

## Configuration Variables

All configuration variables are prefixed with `ai_anomaly_` and can be set via the ProxySQL admin interface.

### ai_anomaly_enabled

**Type:** Boolean
**Default:** `true`
**Dynamic:** Yes

Enable or disable the anomaly detection module.

```sql
SET ai_anomaly_enabled='true';
SET ai_anomaly_enabled='false';
```

**Example:**
```sql
-- Disable anomaly detection temporarily
UPDATE mysql_servers SET ai_anomaly_enabled='false';
LOAD MYSQL VARIABLES TO RUNTIME;
```

---

### ai_anomaly_risk_threshold

**Type:** Integer (0-100)
**Default:** `70`
**Dynamic:** Yes

The risk score threshold for blocking queries. Queries with risk scores above this threshold will be blocked if auto-block is enabled.

- **0-49**: Low sensitivity, only severe threats blocked
- **50-69**: Medium sensitivity (default)
- **70-89**: High sensitivity
- **90-100**: Very high sensitivity, may block legitimate queries

```sql
SET ai_anomaly_risk_threshold='80';
```

**Risk Score Calculation:**
- Each detection method contributes 0-100 points
- Final score = maximum of all method scores
- Score > threshold = query blocked (if auto-block enabled)

---

### ai_anomaly_rate_limit

**Type:** Integer
**Default:** `100`
**Dynamic:** Yes

Maximum number of queries allowed per minute per user/host combination.

**Time Window:** 1 hour rolling window

```sql
-- Set rate limit to 200 queries per minute
SET ai_anomaly_rate_limit='200';

-- Set rate limit to 10 for testing
SET ai_anomaly_rate_limit='10';
```

**Rate Limiting Logic:**
1. Tracks query count per (user, host) pair
2. Calculates queries per minute
3. Blocks when rate > limit
4. Auto-resets after time window expires

---

### ai_anomaly_similarity_threshold

**Type:** Integer (0-100)
**Default:** `85`
**Dynamic:** Yes

Similarity threshold for embedding-based threat detection (future implementation).

Higher values = more exact matching required.

```sql
SET ai_anomaly_similarity_threshold='90';
```

---

### ai_anomaly_auto_block

**Type:** Boolean
**Default:** `true`
**Dynamic:** Yes

Automatically block queries that exceed the risk threshold.

```sql
-- Enable auto-blocking
SET ai_anomaly_auto_block='true';

-- Disable auto-blocking (log-only mode)
SET ai_anomaly_auto_block='false';
```

**When `true`:**
- Queries exceeding risk threshold are blocked
- Error 1313 returned to client
- Query not executed

**When `false`:**
- Queries are logged only
- Query executes normally
- Useful for testing/monitoring

---

### ai_anomaly_log_only

**Type:** Boolean
**Default:** `false`
**Dynamic:** Yes

Enable log-only mode (monitoring without blocking).

```sql
-- Enable log-only mode
SET ai_anomaly_log_only='true';
```

**Log-Only Mode:**
- Anomalies are detected and logged
- Queries are NOT blocked
- Statistics are incremented
- Useful for baselining

---

## Status Variables

Status variables provide runtime statistics about anomaly detection.

### ai_detected_anomalies

**Type:** Counter
**Read-Only:** Yes

Total number of anomalies detected since ProxySQL started.

```sql
SHOW STATUS LIKE 'ai_detected_anomalies';
```

**Example Output:**
```
+-----------------------+-------+
| Variable_name         | Value |
+-----------------------+-------+
| ai_detected_anomalies | 152   |
+-----------------------+-------+
```

**Prometheus Metric:** `proxysql_ai_detected_anomalies_total`

---

### ai_blocked_queries

**Type:** Counter
**Read-Only:** Yes

Total number of queries blocked by anomaly detection.

```sql
SHOW STATUS LIKE 'ai_blocked_queries';
```

**Example Output:**
```
+-------------------+-------+
| Variable_name     | Value |
+-------------------+-------+
| ai_blocked_queries | 89    |
+-------------------+-------+
```

**Prometheus Metric:** `proxysql_ai_blocked_queries_total`

---

## AnomalyResult Structure

The `AnomalyResult` structure contains the outcome of an anomaly check.

```cpp
struct AnomalyResult {
    bool is_anomaly;                       ///< True if anomaly detected
    float risk_score;                      ///< 0.0-1.0 risk score
    std::string anomaly_type;              ///< Type of anomaly
    std::string explanation;               ///< Human-readable explanation
    std::vector<std::string> matched_rules; ///< Rule names that matched
    bool should_block;                     ///< Whether to block query
};
```

### Fields

#### is_anomaly
**Type:** `bool`

Indicates whether an anomaly was detected.

**Values:**
- `true`: Anomaly detected
- `false`: No anomaly

---

#### risk_score
**Type:** `float`
**Range:** 0.0 - 1.0

The calculated risk score for the query.

**Interpretation:**
- `0.0 - 0.3`: Low risk
- `0.3 - 0.6`: Medium risk
- `0.6 - 1.0`: High risk

**Note:** Compare against `ai_anomaly_risk_threshold / 100.0`

---

#### anomaly_type
**Type:** `std::string`

Type of anomaly detected.

**Possible Values:**
- `"sql_injection"`: SQL injection pattern detected
- `"rate_limit"`: Rate limit exceeded
- `"statistical"`: Statistical anomaly
- `"embedding_similarity"`: Similar to known threat (future)
- `"multiple"`: Multiple detection methods triggered

---

#### explanation
**Type:** `std::string`

Human-readable explanation of why the query was flagged.

**Example:**
```
"SQL injection pattern detected: OR 1=1 tautology"
"Rate limit exceeded: 150 queries/min for user 'app'"
```

---

#### matched_rules
**Type:** `std::vector<std::string>`

List of rule names that matched.

**Example:**
```cpp
["pattern:or_tautology", "pattern:quote_sequence"]
```

---

#### should_block
**Type:** `bool`

Whether the query should be blocked based on configuration.

**Determined by:**
1. `is_anomaly == true`
2. `risk_score > ai_anomaly_risk_threshold / 100.0`
3. `ai_anomaly_auto_block == true`
4. `ai_anomaly_log_only == false`

---

## Anomaly_Detector Class

Main class for anomaly detection operations.

```cpp
class Anomaly_Detector {
public:
    Anomaly_Detector();
    ~Anomaly_Detector();

    int init();
    void close();

    AnomalyResult analyze(const std::string& query,
                         const std::string& user,
                         const std::string& client_host,
                         const std::string& schema);

    int add_threat_pattern(const std::string& pattern_name,
                          const std::string& query_example,
                          const std::string& pattern_type,
                          int severity);

    std::string list_threat_patterns();
    bool remove_threat_pattern(int pattern_id);

    std::string get_statistics();
    void clear_user_statistics();
};
```

---

### Constructor/Destructor

```cpp
Anomaly_Detector();
~Anomaly_Detector();
```

**Description:** Creates and destroys the anomaly detector instance.

**Default Configuration:**
- `enabled = true`
- `risk_threshold = 70`
- `similarity_threshold = 85`
- `rate_limit = 100`
- `auto_block = true`
- `log_only = false`

---

### init()

```cpp
int init();
```

**Description:** Initializes the anomaly detector.

**Return Value:**
- `0`: Success
- `non-zero`: Error

**Initialization Steps:**
1. Load configuration
2. Initialize user statistics tracking
3. Prepare detection patterns

**Example:**
```cpp
Anomaly_Detector* detector = new Anomaly_Detector();
if (detector->init() != 0) {
    // Handle error
}
```

---

### close()

```cpp
void close();
```

**Description:** Closes the anomaly detector and releases resources.

**Example:**
```cpp
detector->close();
delete detector;
```

---

### analyze()

```cpp
AnomalyResult analyze(const std::string& query,
                     const std::string& user,
                     const std::string& client_host,
                     const std::string& schema);
```

**Description:** Main entry point for anomaly detection.

**Parameters:**
- `query`: The SQL query to analyze
- `user`: Username executing the query
- `client_host`: Client IP address
- `schema`: Database schema name

**Return Value:** `AnomalyResult` structure

**Detection Pipeline:**
1. Query normalization
2. SQL injection pattern detection
3. Rate limiting check
4. Statistical anomaly detection
5. Embedding similarity check (future)
6. Result aggregation

**Example:**
```cpp
Anomaly_Detector* detector = GloAI->get_anomaly_detector();
AnomalyResult result = detector->analyze(
    "SELECT * FROM users WHERE username='admin' OR 1=1--'",
    "app_user",
    "192.168.1.100",
    "production"
);

if (result.should_block) {
    // Block the query
    std::cerr << "Blocked: " << result.explanation << std::endl;
}
```

---

### add_threat_pattern()

```cpp
int add_threat_pattern(const std::string& pattern_name,
                      const std::string& query_example,
                      const std::string& pattern_type,
                      int severity);
```

**Description:** Adds a custom threat pattern to the detection database.

**Parameters:**
- `pattern_name`: Name for the pattern
- `query_example`: Example query representing the threat
- `pattern_type`: Type of pattern (e.g., "sql_injection", "ddos")
- `severity`: Severity level (1-10)

**Return Value:**
- `> 0`: Pattern ID
- `-1`: Error

**Example:**
```cpp
int pattern_id = detector->add_threat_pattern(
    "custom_sqli",
    "SELECT * FROM users WHERE id='1' UNION SELECT 1,2,3--'",
    "sql_injection",
    8
);
```

---

### list_threat_patterns()

```cpp
std::string list_threat_patterns();
```

**Description:** Returns JSON-formatted list of all threat patterns.

**Return Value:** JSON string containing pattern list

**Example:**
```cpp
std::string patterns = detector->list_threat_patterns();
std::cout << patterns << std::endl;
// Output: {"patterns": [{"id": 1, "name": "sql_injection_or", ...}]}
```

---

### remove_threat_pattern()

```cpp
bool remove_threat_pattern(int pattern_id);
```

**Description:** Removes a threat pattern by ID.

**Parameters:**
- `pattern_id`: ID of pattern to remove

**Return Value:**
- `true`: Success
- `false`: Pattern not found

---

### get_statistics()

```cpp
std::string get_statistics();
```

**Description:** Returns JSON-formatted statistics.

**Return Value:** JSON string with statistics

**Example Output:**
```json
{
  "total_queries_analyzed": 15000,
  "anomalies_detected": 152,
  "queries_blocked": 89,
  "detection_methods": {
    "sql_injection": 120,
    "rate_limiting": 25,
    "statistical": 7
  },
  "user_statistics": {
    "app_user": {"query_count": 5000, "blocked": 5},
    "admin": {"query_count": 200, "blocked": 0}
  }
}
```

---

### clear_user_statistics()

```cpp
void clear_user_statistics();
```

**Description:** Clears all accumulated user statistics.

**Use Case:** Resetting statistics after configuration changes.

---

## MySQL_Session Integration

The anomaly detection is integrated into the MySQL query processing flow.

### Integration Point

**File:** `lib/MySQL_Session.cpp`
**Function:** `MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_detect_ai_anomaly()`
**Location:** Line ~3626

**Flow:**
```
Client Query
    ↓
Query Parsing
    ↓
libinjection SQLi Detection
    ↓
AI Anomaly Detection  ← Integration Point
    ↓
Query Execution
    ↓
Result Return
```

### Error Handling

When a query is blocked:
1. Error code 1317 (HY000) is returned
2. Custom error message includes explanation
3. Query is NOT executed
4. Event is logged

**Example Error:**
```
ERROR 1313 (HY000): Query blocked by anomaly detection: SQL injection pattern detected
```

### Access Control

Anomaly detection bypass for admin users:
- Queries from admin interface bypass detection
- Configurable via admin username whitelist
