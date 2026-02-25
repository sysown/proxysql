# Vector Features Testing Guide

## Overview

This document describes testing strategies and procedures for Vector Features in ProxySQL, including unit tests, integration tests, and manual testing procedures.

## Test Suite Overview

| Test Type | Location | Purpose | External Dependencies |
|-----------|----------|---------|----------------------|
| Unit Tests | `test/tap/tests/vector_features-t.cpp` | Test vector feature configuration and initialization | None |
| Integration Tests | `test/tap/tests/nl2sql_integration-t.cpp` | Test NL2SQL with real database | Test database |
| E2E Tests | `scripts/mcp/test_nl2sql_e2e.sh` | Complete workflow testing | Ollama/llama-server |
| Manual Tests | This document | Interactive testing | All components |

---

## Prerequisites

### 1. Enable AI Features

```sql
-- Connect to ProxySQL admin
mysql -h 127.0.0.1 -P 6032 -u admin -padmin

-- Enable AI features
SET ai_features_enabled='true';
SET ai_nl2sql_enabled='true';
SET ai_anomaly_detection_enabled='true';
LOAD MYSQL VARIABLES TO RUNTIME;
```

### 2. Start llama-server

```bash
# Start embedding service
ollama run nomic-embed-text-v1.5

# Or via llama-server directly
llama-server --model nomic-embed-text-v1.5 --port 8013 --embedding
```

### 3. Verify GenAI Connection

```bash
# Test embedding endpoint
curl -X POST http://127.0.0.1:8013/embedding \
  -H "Content-Type: application/json" \
  -d '{"content": "test embedding"}'

# Should return JSON with embedding array
```

---

## Unit Tests

### Running Unit Tests

```bash
cd /home/rene/proxysql-vec/test/tap

# Build vector features test
make vector_features

# Run the test
./vector_features
```

### Test Categories

#### 1. Virtual Table Creation Tests

**Purpose**: Verify sqlite-vec virtual tables are created correctly

```cpp
void test_virtual_tables_created() {
    // Checks:
    // - AI features initialized
    // - Vector DB path configured
    // - Vector dimension is 1536
}
```

**Expected Output**:
```
=== Virtual vec0 Table Creation Tests ===
ok 1 - AI features initialized
ok 2 - Vector DB path configured (or default used)
ok 3 - Vector dimension is 1536 or default
```

#### 2. NL2SQL Cache Configuration Tests

**Purpose**: Verify NL2SQL cache variables are accessible and configurable

```cpp
void test_nl2sql_cache_config() {
    // Checks:
    // - Cache enabled by default
    // - Similarity threshold is 85
    // - Threshold can be changed
}
```

**Expected Output**:
```
=== NL2SQL Vector Cache Configuration Tests ===
ok 4 - NL2SQL enabled by default
ok 5 - Cache similarity threshold is 85 or default
ok 6 - Cache threshold changed to 90
ok 7 - Cache threshold changed to 90
```

#### 3. Anomaly Embedding Configuration Tests

**Purpose**: Verify anomaly detection variables are accessible

```cpp
void test_anomaly_embedding_config() {
    // Checks:
    // - Anomaly detection enabled
    // - Similarity threshold is 85
    // - Risk threshold is 70
}
```

#### 4. Status Variables Tests

**Purpose**: Verify Prometheus-style status variables exist

```cpp
void test_status_variables() {
    // Checks:
    // - ai_detected_anomalies exists
    // - ai_blocked_queries exists
}
```

**Expected Output**:
```
=== Status Variables Tests ===
ok 12 - ai_detected_anomalies status variable exists
ok 13 - ai_blocked_queries status variable exists
```

---

## Integration Tests

### NL2SQL Semantic Cache Test

#### Test Case: Semantic Cache Hit

**Purpose**: Verify that semantically similar queries hit the cache

```sql
-- Step 1: Clear cache
DELETE FROM nl2sql_cache;

-- Step 2: First query (cache miss)
-- This will call LLM and cache the result
SELECT * FROM runtime_mysql_servers
WHERE variable_name = 'ai_nl2sql_enabled';

-- Via NL2SQL:
NL2SQL: Show all customers from USA;

-- Step 3: Similar query (should hit cache)
NL2SQL: Display USA customers;

-- Step 4: Another similar query
NL2SQL: List customers in United States;
```

**Expected Result**:
- First query: Calls LLM (takes 1-5 seconds)
- Subsequent queries: Return cached result (takes < 100ms)

#### Verify Cache Hit

```cpp
// Check cache statistics
std::string stats = converter->get_cache_stats();
// Should show increased hit count

// Or via SQL
SELECT COUNT(*) as cache_entries,
       SUM(hit_count) as total_hits
FROM nl2sql_cache;
```

### Anomaly Detection Tests

#### Test Case 1: Known Threat Pattern

**Purpose**: Verify detection of known SQL injection

```sql
-- Add threat pattern
-- (Via C++ API)
detector->add_threat_pattern(
    "OR 1=1 Tautology",
    "SELECT * FROM users WHERE id=1 OR 1=1--",
    "sql_injection",
    9
);

-- Test detection
SELECT * FROM users WHERE id=5 OR 2=2--';

-- Should be BLOCKED (high similarity to OR 1=1 pattern)
```

**Expected Result**:
- Query blocked
- Risk score > 0.7 (70%)
- Threat type: sql_injection

#### Test Case 2: Threat Variation

**Purpose**: Detect variations of attack patterns

```sql
-- Known pattern: "SELECT ... WHERE id=1 AND sleep(10)"
-- Test variation:
SELECT * FROM users WHERE id=5 AND SLEEP(5)--';

-- Should be FLAGGED (similar but lower severity)
```

**Expected Result**:
- Query flagged
- Risk score: 0.4-0.6 (medium)
- Action: Flagged but allowed

#### Test Case 3: Legitimate Query

**Purpose**: Ensure false positives are minimal

```sql
-- Normal query
SELECT * FROM users WHERE id=5;

-- Should be ALLOWED
```

**Expected Result**:
- No detection
- Query allowed through

---

## Manual Testing Procedures

### Test 1: NL2SQL Vector Cache

#### Setup

```sql
-- Enable NL2SQL
SET ai_nl2sql_enabled='true';
SET ai_nl2sql_cache_similarity_threshold='85';
LOAD MYSQL VARIABLES TO RUNTIME;

-- Clear cache
DELETE FROM nl2sql_cache;
DELETE FROM nl2sql_cache_vec;
```

#### Procedure

1. **First Query (Cold Cache)**
   ```sql
   NL2SQL: Show all customers from USA;
   ```
   - Record response time
   - Should take 1-5 seconds (LLM call)

2. **Check Cache Entry**
   ```sql
   SELECT id, natural_language, generated_sql, hit_count
   FROM nl2sql_cache;
   ```
   - Should have 1 entry
   - hit_count should be 0 or 1

3. **Similar Query (Warm Cache)**
   ```sql
   NL2SQL: Display USA customers;
   ```
   - Record response time
   - Should take < 100ms (cache hit)

4. **Verify Cache Hit**
   ```sql
   SELECT id, natural_language, hit_count
   FROM nl2sql_cache;
   ```
   - hit_count should be increased

5. **Different Query (Cache Miss)**
   ```sql
   NL2SQL: Show orders from last month;
   ```
   - Should take 1-5 seconds (new LLM call)

#### Expected Results

| Query | Expected Time | Source |
|-------|--------------|--------|
| First unique query | 1-5s | LLM |
| Similar query | < 100ms | Cache |
| Different query | 1-5s | LLM |

#### Troubleshooting

If cache doesn't work:
1. Check `ai_nl2sql_enabled='true'`
2. Check llama-server is running
3. Check vector DB exists: `ls -la /var/lib/proxysql/ai_features.db`
4. Check logs: `tail -f proxysql.log | grep NL2SQL`

---

### Test 2: Anomaly Detection Embedding Similarity

#### Setup

```sql
-- Enable anomaly detection
SET ai_anomaly_detection_enabled='true';
SET ai_anomaly_similarity_threshold='85';
SET ai_anomaly_risk_threshold='70';
SET ai_anomaly_auto_block='true';
LOAD MYSQL VARIABLES TO RUNTIME;

-- Add test threat patterns (via C++ API or script)
-- See scripts/add_threat_patterns.sh
```

#### Procedure

1. **Test SQL Injection Detection**
   ```sql
   -- Known threat: OR 1=1
   SELECT * FROM users WHERE id=1 OR 1=1--';
   ```
   - Expected: BLOCKED
   - Risk: > 70%
   - Type: sql_injection

2. **Test Injection Variation**
   ```sql
   -- Variation: OR 2=2
   SELECT * FROM users WHERE id=5 OR 2=2--';
   ```
   - Expected: BLOCKED or FLAGGED
   - Risk: 60-90%

3. **Test DoS Detection**
   ```sql
   -- Known threat: Sleep-based DoS
   SELECT * FROM users WHERE id=1 AND SLEEP(10);
   ```
   - Expected: BLOCKED or FLAGGED
   - Type: dos

4. **Test Legitimate Query**
   ```sql
   -- Normal query
   SELECT * FROM users WHERE id=5;
   ```
   - Expected: ALLOWED
   - No detection

5. **Check Statistics**
   ```sql
   SHOW STATUS LIKE 'ai_anomaly_%';
   -- ai_detected_anomalies
   -- ai_blocked_queries
   -- ai_flagged_queries
   ```

#### Expected Results

| Query | Expected Action | Risk Score |
|-------|----------------|------------|
| OR 1=1 injection | BLOCKED | > 70% |
| OR 2=2 variation | BLOCKED/FLAGGED | 60-90% |
| Sleep DoS | BLOCKED/FLAGGED | > 50% |
| Normal query | ALLOWED | < 30% |

#### Troubleshooting

If detection doesn't work:
1. Check threat patterns exist: `SELECT COUNT(*) FROM anomaly_patterns;`
2. Check similarity threshold: Lower to 80 for more sensitivity
3. Check embeddings are being generated: `tail -f proxysql.log | grep GenAI`
4. Verify query normalization: Check log for normalized query

---

### Test 3: Threat Pattern Management

#### Add Threat Pattern

```cpp
// Via C++ API
Anomaly_Detector* detector = GloAI->get_anomaly();

bool success = detector->add_threat_pattern(
    "Test Pattern",
    "SELECT * FROM test WHERE id=1",
    "test",
    5
);

if (success) {
    std::cout << "Pattern added successfully\n";
}
```

#### List Threat Patterns

```cpp
std::string patterns_json = detector->list_threat_patterns();
std::cout << "Patterns:\n" << patterns_json << "\n";
```

Or via SQL:
```sql
SELECT id, pattern_name, pattern_type, severity
FROM anomaly_patterns
ORDER BY severity DESC;
```

#### Remove Threat Pattern

```cpp
bool success = detector->remove_threat_pattern(1);
```

Or via SQL:
```sql
-- Note: This is for testing only, use C++ API in production
DELETE FROM anomaly_patterns WHERE id=1;
DELETE FROM anomaly_patterns_vec WHERE rowid=1;
```

---

## Performance Testing

### Baseline Metrics

Record baseline performance for your environment:

```bash
# Create test script
cat > test_performance.sh <<'EOF'
#!/bin/bash

echo "=== NL2SQL Performance Test ==="

# Test 1: Cold cache (no similar queries)
time mysql -h 127.0.0.1 -P 6033 -u test -ptest \
  -e "NL2SQL: Show all products from electronics category;"

sleep 1

# Test 2: Warm cache (similar query)
time mysql -h 127.0.0.1 -P 6033 -u test -ptest \
  -e "NL2SQL: Display electronics products;"

echo ""
echo "=== Anomaly Detection Performance Test ==="

# Test 3: Anomaly check
time mysql -h 127.0.0.1 -P 6033 -u test -ptest \
  -e "SELECT * FROM users WHERE id=1 OR 1=1--';"

EOF

chmod +x test_performance.sh
./test_performance.sh
```

### Expected Performance

| Operation | Target Time | Max Time |
|-----------|-------------|----------|
| Embedding generation | < 200ms | 500ms |
| Cache search | < 50ms | 100ms |
| Similarity check | < 50ms | 100ms |
| LLM call (Ollama) | 1-2s | 5s |
| Cached query | < 100ms | 200ms |

### Load Testing

```bash
# Test concurrent queries
for i in {1..100}; do
  mysql -h 127.0.0.1 -P 6033 -u test -ptest \
    -e "NL2SQL: Show customer $i;" &
done
wait

# Check statistics
SHOW STATUS LIKE 'ai_%';
```

---

## Debugging Tests

### Enable Debug Logging

```cpp
// In ProxySQL configuration
proxysql-debug-level 3
```

### Key Debug Commands

```bash
# NL2SQL logs
tail -f proxysql.log | grep NL2SQL

# Anomaly logs
tail -f proxysql.log | grep Anomaly

# GenAI/Embedding logs
tail -f proxysql.log | grep GenAI

# Vector DB logs
tail -f proxysql.log | grep "vec"

# All AI logs
tail -f proxysql.log | grep -E "(NL2SQL|Anomaly|GenAI|AI:)"
```

### Direct Database Inspection

```bash
# Open vector database
sqlite3 /var/lib/proxysql/ai_features.db

# Check schema
.schema

# View cache entries
SELECT id, natural_language, hit_count, created_at FROM nl2sql_cache;

# View threat patterns
SELECT id, pattern_name, pattern_type, severity FROM anomaly_patterns;

# Check virtual tables
SELECT rowid FROM nl2sql_cache_vec LIMIT 10;

# Count embeddings
SELECT COUNT(*) FROM nl2sql_cache WHERE embedding IS NOT NULL;
```

---

## Test Checklist

### Unit Tests
- [ ] Virtual tables created
- [ ] NL2SQL cache configuration
- [ ] Anomaly embedding configuration
- [ ] Vector DB file exists
- [ ] Status variables exist
- [ ] GenAI module accessible

### Integration Tests
- [ ] NL2SQL semantic cache hit
- [ ] NL2SQL cache miss
- [ ] Anomaly detection of known threats
- [ ] Anomaly detection of variations
- [ ] False positive check
- [ ] Threat pattern CRUD operations

### Manual Tests
- [ ] NL2SQL end-to-end flow
- [ ] Anomaly blocking
- [ ] Anomaly flagging
- [ ] Performance within targets
- [ ] Concurrent load handling
- [ ] Memory usage acceptable

---

## Continuous Testing

### Automated Test Script

```bash
#!/bin/bash
# run_vector_tests.sh

set -e

echo "=== Vector Features Test Suite ==="

# 1. Unit tests
echo "Running unit tests..."
cd test/tap
make vector_features
./vector_features

# 2. Integration tests
echo "Running integration tests..."
# Add integration test commands here

# 3. Performance tests
echo "Running performance tests..."
# Add performance test commands here

# 4. Cleanup
echo "Cleaning up..."
# Clear test data

echo "=== All tests passed ==="
```

### CI/CD Integration

```yaml
# Example GitHub Actions workflow
name: Vector Features Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Start llama-server
        run: ollama run nomic-embed-text-v1.5 &
      - name: Build ProxySQL
        run: make
      - name: Run unit tests
        run: cd test/tap && make vector_features && ./vector_features
      - name: Run integration tests
        run: ./scripts/mcp/test_nl2sql_e2e.sh --mock
```

---

## Common Issues and Solutions

### Issue: "No such table: nl2sql_cache_vec"

**Cause**: Virtual tables not created

**Solution**:
```sql
-- Recreate virtual tables
-- (Requires restarting ProxySQL)
```

### Issue: "Failed to generate embedding"

**Cause**: GenAI module not connected to llama-server

**Solution**:
```bash
# Check llama-server is running
curl http://127.0.0.1:8013/embedding

# Check ProxySQL logs
tail -f proxysql.log | grep GenAI
```

### Issue: "Poor similarity detection"

**Cause**: Threshold too high or embeddings not generated

**Solution**:
```sql
-- Lower threshold for testing
SET ai_anomaly_similarity_threshold='75';
```

### Issue: "Cache not hitting"

**Cause**: Similarity threshold too high

**Solution**:
```sql
-- Lower cache threshold
SET ai_nl2sql_cache_similarity_threshold='75';
```

---

## Test Data

### Sample NL2SQL Queries

```sql
-- Simple queries
NL2SQL: Show all customers;
NL2SQL: Display all users;
NL2SQL: List all customers;  -- Should hit cache

-- Conditional queries
NL2SQL: Find customers from USA;
NL2SQL: Display USA customers;  -- Should hit cache
NL2SQL: Show users in United States;  -- Should hit cache

-- Aggregation
NL2SQL: Count customers by country;
NL2SQL: How many customers per country?;  -- Should hit cache
```

### Sample Threat Patterns

See `scripts/add_threat_patterns.sh` for 10 example patterns covering:
- SQL Injection (OR 1=1, UNION, comments, etc.)
- DoS attacks (sleep, benchmark)
- Data exfiltration (INTO OUTFILE)
- Privilege escalation (DROP TABLE)
- Reconnaissance (schema probing)

---

## Reporting Test Results

### Test Result Template

```markdown
## Vector Features Test Results - [Date]

### Environment
- ProxySQL version: [version]
- Vector dimension: 1536
- Similarity threshold: 85
- llama-server status: [running/not running]

### Unit Tests
- Total: 20
- Passed: XX
- Failed: XX
- Skipped: XX

### Integration Tests
- NL2SQL cache: [PASS/FAIL]
- Anomaly detection: [PASS/FAIL]

### Performance
- Embedding generation: XXXms
- Cache search: XXms
- Similarity check: XXms
- Cold cache query: X.Xs
- Warm cache query: XXms

### Issues Found
1. [Description]
2. [Description]

### Notes
[Additional observations]
```
