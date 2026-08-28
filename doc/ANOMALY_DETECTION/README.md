# Anomaly Detection - Security Threat Detection for ProxySQL

## Overview

The Anomaly Detection module provides real-time security threat detection for ProxySQL using a multi-stage analysis pipeline. It identifies SQL injection attacks, unusual query patterns, rate limiting violations, and statistical anomalies.

## Features

- **Multi-Stage Detection Pipeline**: 5-layer analysis for comprehensive threat detection
- **SQL Injection Pattern Detection**: Regex-based and keyword-based detection
- **Query Normalization**: Advanced normalization for pattern matching
- **Rate Limiting**: Per-user and per-host query rate tracking
- **Statistical Anomaly Detection**: Z-score based outlier detection
- **Configurable Blocking**: Auto-block or log-only modes
- **Prometheus Metrics**: Native monitoring integration

## Quick Start

### 1. Enable Anomaly Detection

```sql
-- Via admin interface
SET genai-anomaly_enabled='true';
```

### 2. Configure Detection

```sql
-- Set risk threshold (0-100)
SET genai-anomaly_risk_threshold='70';

-- Set rate limit (queries per minute)
SET genai-anomaly_rate_limit='100';

-- Enable auto-blocking
SET genai-anomaly_auto_block='true';

-- Or enable log-only mode
SET genai-anomaly_log_only='false';
```

### 3. Monitor Detection Results

```sql
-- Check statistics
SHOW STATUS LIKE 'ai_detected_anomalies';
SHOW STATUS LIKE 'ai_blocked_queries';

-- View Prometheus metrics
curl http://localhost:4200/metrics | grep proxysql_ai
```

## Configuration

### Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `genai-anomaly_enabled` | true | Enable/disable anomaly detection |
| `genai-anomaly_risk_threshold` | 70 | Risk score threshold (0-100) for blocking |
| `genai-anomaly_rate_limit` | 100 | Max queries per minute per user/host |
| `genai-anomaly_similarity_threshold` | 85 | Similarity threshold for embedding matching (0-100) |
| `genai-anomaly_auto_block` | true | Automatically block suspicious queries |
| `genai-anomaly_log_only` | false | Log anomalies without blocking |

### Status Variables

| Variable | Description |
|----------|-------------|
| `ai_detected_anomalies` | Total number of anomalies detected |
| `ai_blocked_queries` | Total number of queries blocked |

## Detection Methods

### 1. SQL Injection Pattern Detection

Detects common SQL injection patterns using regex and keyword matching:

**Patterns Detected:**
- OR/AND tautologies: `OR 1=1`, `AND 1=1`
- Quote sequences: `'' OR ''=''`
- UNION SELECT: `UNION SELECT`
- DROP TABLE: `DROP TABLE`
- Comment injection: `--`, `/* */`
- Hex encoding: `0x414243`
- CONCAT attacks: `CONCAT(0x41, 0x42)`
- File operations: `INTO OUTFILE`, `LOAD_FILE`
- Timing attacks: `SLEEP()`, `BENCHMARK()`

**Example:**
```sql
-- This query will be blocked:
SELECT * FROM users WHERE username='admin' OR 1=1--' AND password='xxx'
```

### 2. Query Normalization

Normalizes queries for consistent pattern matching:
- Case normalization
- Comment removal
- Literal replacement
- Whitespace normalization

**Example:**
```sql
-- Input:
SELECT * FROM users WHERE name='John' -- comment

-- Normalized:
select * from users where name=?
```

### 3. Rate Limiting

Tracks query rates per user and host:
- Time window: 1 hour
- Tracks: Query count, last query time
- Action: Block when limit exceeded

**Configuration:**
```sql
SET ai_anomaly_rate_limit='100';
```

### 4. Statistical Anomaly Detection

Uses Z-score analysis to detect outliers:
- Query execution time
- Result set size
- Query frequency
- Schema access patterns

**Example:**
```sql
-- Unusually large result set:
SELECT * FROM huge_table -- May trigger statistical anomaly
```

### 5. Embedding-based Similarity

(Framework for future implementation)
Detects similarity to known threat patterns using vector embeddings.

## Examples

### SQL Injection Detection

```sql
-- Blocked: OR 1=1 tautology
mysql> SELECT * FROM users WHERE username='admin' OR 1=1--';
ERROR 1313 (HY000): Query blocked: SQL injection pattern detected

-- Blocked: UNION SELECT
mysql> SELECT name FROM products WHERE id=1 UNION SELECT password FROM users;
ERROR 1313 (HY000): Query blocked: SQL injection pattern detected

-- Blocked: Comment injection
mysql> SELECT * FROM users WHERE id=1-- AND password='xxx';
ERROR 1313 (HY000): Query blocked: SQL injection pattern detected
```

### Rate Limiting

```sql
-- Set low rate limit for testing
SET ai_anomaly_rate_limit='10';

-- After 10 queries in 1 minute:
mysql> SELECT 1;
ERROR 1313 (HY000): Query blocked: Rate limit exceeded for user 'app_user'
```

### Statistical Anomaly

```sql
-- Unusual query pattern detected
mysql> SELECT * FROM users CROSS JOIN orders CROSS JOIN products;
-- May trigger: Statistical anomaly detected (high result count)
```

## Log-Only Mode

For monitoring without blocking:

```sql
-- Enable log-only mode
SET ai_anomaly_log_only='true';
SET ai_anomaly_auto_block='false';

-- Queries will be logged but not blocked
-- Monitor via:
SHOW STATUS LIKE 'ai_detected_anomalies';
```

## Monitoring

### Prometheus Metrics

```bash
# View AI metrics
curl http://localhost:4200/metrics | grep proxysql_ai

# Output includes:
# proxysql_ai_detected_anomalies_total
# proxysql_ai_blocked_queries_total
```

### Admin Interface

```sql
-- Check detection statistics
SELECT * FROM stats_mysql_global WHERE variable_name LIKE 'ai_%';

-- View current configuration
SELECT * FROM runtime_mysql_servers WHERE variable_name LIKE 'ai_anomaly_%';
```

## Troubleshooting

### Queries Being Blocked Incorrectly

1. **Check if legitimate queries match patterns**:
   - Review the SQL injection patterns list
   - Consider log-only mode for testing

2. **Adjust risk threshold**:
   ```sql
   SET ai_anomaly_risk_threshold='80';  -- Higher threshold
   ```

3. **Adjust rate limit**:
   ```sql
   SET ai_anomaly_rate_limit='200';  -- Higher limit
   ```

### False Positives

If legitimate queries are being flagged:

1. Enable log-only mode to investigate:
   ```sql
   SET ai_anomaly_log_only='true';
   SET ai_anomaly_auto_block='false';
   ```

2. Check logs for specific patterns:
   ```bash
   tail -f proxysql.log | grep "Anomaly:"
   ```

3. Adjust configuration based on findings

### No Anomalies Detected

If detection seems inactive:

1. Verify anomaly detection is enabled:
   ```sql
   SELECT * FROM runtime_mysql_servers WHERE variable_name='ai_anomaly_enabled';
   ```

2. Check logs for errors:
   ```bash
   tail -f proxysql.log | grep "Anomaly:"
   ```

3. Verify AI features are initialized:
   ```bash
   grep "AI_Features" proxysql.log
   ```

## Security Considerations

1. **Anomaly Detection is a Defense in Depth**: It complements, not replaces, proper security practices
2. **Pattern Evasion Possible**: Attackers may evolve techniques; regular updates needed
3. **Performance Impact**: Detection adds minimal overhead (~1-2ms per query)
4. **Log Monitoring**: Regular review of anomaly logs recommended
5. **Tune for Your Workload**: Adjust thresholds based on your query patterns

## Performance

- **Detection Overhead**: ~1-2ms per query
- **Memory Usage**: ~100KB for user statistics
- **CPU Usage**: Minimal (regex-based detection)

## API Reference

See `API.md` for complete API documentation.

## Architecture

See `ARCHITECTURE.md` for detailed architecture information.

## Testing

See `TESTING.md` for testing guide and examples.
