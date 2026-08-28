# Vector Features - Embedding-Based Similarity for ProxySQL

## Overview

Vector Features provide **semantic similarity** capabilities for ProxySQL using **vector embeddings** and **sqlite-vec** for efficient similarity search. This enables:

- **NL2SQL Vector Cache**: Cache natural language queries by semantic meaning, not just exact text
- **Anomaly Detection**: Detect SQL threats using embedding similarity against known attack patterns

## Features

| Feature | Description | Benefit |
|---------|-------------|---------|
| **Semantic Caching** | Cache queries by meaning, not exact text | Higher cache hit rates for similar queries |
| **Threat Detection** | Detect attacks using embedding similarity | Catch variations of known attack patterns |
| **Vector Storage** | sqlite-vec for efficient KNN search | Fast similarity queries on embedded vectors |
| **GenAI Integration** | Uses existing GenAI module for embeddings | No external embedding service required |
| **Configurable Thresholds** | Adjust similarity sensitivity | Balance between false positives and negatives |

## Architecture

```
Query Input
    |
    v
+-----------------+
| GenAI Module    | -> Generate 1536-dim embedding
| (llama-server)  |
+-----------------+
    |
    v
+-----------------+
| Vector DB       | -> Store embedding in SQLite
| (sqlite-vec)    | -> Similarity search via KNN
+-----------------+
    |
    v
+-----------------+
| Result          | -> Similar items within threshold
+-----------------+
```

## Quick Start

### 1. Enable AI Features

```sql
-- Via admin interface
SET ai_features_enabled='true';
LOAD MYSQL VARIABLES TO RUNTIME;
```

### 2. Configure Vector Database

```sql
-- Set vector DB path (default: /var/lib/proxysql/ai_features.db)
SET ai_vector_db_path='/var/lib/proxysql/ai_features.db';

-- Set vector dimension (default: 1536 for text-embedding-3-small)
SET ai_vector_dimension='1536';
```

### 3. Configure NL2SQL Vector Cache

```sql
-- Enable NL2SQL
SET ai_nl2sql_enabled='true';

-- Set cache similarity threshold (0-100, default: 85)
SET ai_nl2sql_cache_similarity_threshold='85';
```

### 4. Configure Anomaly Detection

```sql
-- Enable anomaly detection
SET ai_anomaly_detection_enabled='true';

-- Set similarity threshold (0-100, default: 85)
SET ai_anomaly_similarity_threshold='85';

-- Set risk threshold (0-100, default: 70)
SET ai_anomaly_risk_threshold='70';
```

## NL2SQL Vector Cache

### How It Works

1. **User submits NL2SQL query**: `NL2SQL: Show all customers`
2. **Generate embedding**: Query text → 1536-dimensional vector
3. **Search cache**: Find semantically similar cached queries
4. **Return cached SQL** if similarity > threshold
5. **Otherwise call LLM** and store result in cache

### Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ai_nl2sql_enabled` | true | Enable/disable NL2SQL |
| `ai_nl2sql_cache_similarity_threshold` | 85 | Semantic similarity threshold (0-100) |
| `ai_nl2sql_timeout_ms` | 30000 | LLM request timeout |
| `ai_vector_db_path` | /var/lib/proxysql/ai_features.db | Vector database file path |
| `ai_vector_dimension` | 1536 | Embedding dimension |

### Example: Semantic Cache Hit

```sql
-- First query - calls LLM
NL2SQL: Show me all customers from USA;

-- Similar query - returns cached result (no LLM call!)
NL2SQL: Display customers in the United States;

-- Another similar query - cached
NL2SQL: List USA customers;
```

All three queries are **semantically similar** and will hit the cache after the first one.

### Cache Statistics

```sql
-- View cache statistics
SHOW STATUS LIKE 'ai_nl2sql_cache_%';
```

## Anomaly Detection

### How It Works

1. **Query intercepted** during session processing
2. **Generate embedding** of normalized query
3. **KNN search** against threat pattern embeddings
4. **Calculate risk score**: `(severity / 10) * (1 - distance / 2)`
5. **Block or flag** if risk > threshold

### Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ai_anomaly_detection_enabled` | true | Enable/disable anomaly detection |
| `ai_anomaly_similarity_threshold` | 85 | Similarity threshold for threat matching (0-100) |
| `ai_anomaly_risk_threshold` | 70 | Risk score threshold for blocking (0-100) |
| `ai_anomaly_rate_limit` | 100 | Max anomalies per minute before rate limiting |
| `ai_anomaly_auto_block` | true | Automatically block high-risk queries |
| `ai_anomaly_log_only` | false | If true, log but don't block |

### Threat Pattern Management

#### Add a Threat Pattern

Via C++ API:
```cpp
anomaly_detector->add_threat_pattern(
    "OR 1=1 Tautology",
    "SELECT * FROM users WHERE username='admin' OR 1=1--'",
    "sql_injection",
    9  // severity 1-10
);
```

Via MCP (future):
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "ai_add_threat_pattern",
    "arguments": {
      "pattern_name": "OR 1=1 Tautology",
      "query_example": "SELECT * FROM users WHERE username='admin' OR 1=1--'",
      "pattern_type": "sql_injection",
      "severity": 9
    }
  }
}
```

#### List Threat Patterns

```cpp
std::string patterns = anomaly_detector->list_threat_patterns();
// Returns JSON array of all patterns
```

#### Remove a Threat Pattern

```cpp
bool success = anomaly_detector->remove_threat_pattern(pattern_id);
```

### Built-in Threat Patterns

See `scripts/add_threat_patterns.sh` for 10 example threat patterns:

| Pattern | Type | Severity |
|---------|------|----------|
| OR 1=1 Tautology | sql_injection | 9 |
| UNION SELECT | sql_injection | 8 |
| Comment Injection | sql_injection | 7 |
| Sleep-based DoS | dos | 6 |
| Benchmark-based DoS | dos | 6 |
| INTO OUTFILE | data_exfiltration | 9 |
| DROP TABLE | privilege_escalation | 10 |
| Schema Probing | reconnaissance | 3 |
| CONCAT Injection | sql_injection | 8 |
| Hex Encoding | sql_injection | 7 |

### Detection Example

```sql
-- Known threat pattern in database:
-- "SELECT * FROM users WHERE id=1 OR 1=1--"

-- Attacker tries variation:
SELECT * FROM users WHERE id=5 OR 2=2--';

-- Embedding similarity detects this as similar to OR 1=1 pattern
-- Risk score: (9/10) * (1 - 0.15/2) = 0.86 (86% risk)
-- Since 86 > 70 (risk_threshold), query is BLOCKED
```

### Anomaly Statistics

```sql
-- View anomaly statistics
SHOW STATUS LIKE 'ai_anomaly_%';
-- ai_detected_anomalies
-- ai_blocked_queries
-- ai_flagged_queries
```

Via API:
```cpp
std::string stats = anomaly_detector->get_statistics();
// Returns JSON with detailed statistics
```

## Vector Database

### Schema

The vector database (`ai_features.db`) contains:

#### Main Tables

**nl2sql_cache**
```sql
CREATE TABLE nl2sql_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    natural_language TEXT NOT NULL,
    generated_sql TEXT NOT NULL,
    schema_context TEXT,
    embedding BLOB,
    hit_count INTEGER DEFAULT 0,
    last_hit INTEGER,
    created_at INTEGER
);
```

**anomaly_patterns**
```sql
CREATE TABLE anomaly_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_name TEXT,
    pattern_type TEXT,  -- 'sql_injection', 'dos', 'privilege_escalation'
    query_example TEXT,
    embedding BLOB,
    severity INTEGER,  -- 1-10
    created_at INTEGER
);
```

**query_history**
```sql
CREATE TABLE query_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query_text TEXT NOT NULL,
    generated_sql TEXT,
    embedding BLOB,
    execution_time_ms INTEGER,
    success BOOLEAN,
    timestamp INTEGER
);
```

#### Virtual Vector Tables (sqlite-vec)

```sql
CREATE VIRTUAL TABLE nl2sql_cache_vec USING vec0(
    embedding float(1536)
);

CREATE VIRTUAL TABLE anomaly_patterns_vec USING vec0(
    embedding float(1536)
);

CREATE VIRTUAL TABLE query_history_vec USING vec0(
    embedding float(1536)
);
```

### Similarity Search Algorithm

**Cosine Distance** is used for similarity measurement:

```
distance = 2 * (1 - cosine_similarity)

where:
cosine_similarity = (A . B) / (|A| * |B|)

Distance range: 0 (identical) to 2 (opposite)
Similarity = (2 - distance) / 2 * 100
```

**Threshold Conversion**:
```
similarity_threshold (0-100) → distance_threshold (0-2)
distance_threshold = 2.0 - (similarity_threshold / 50.0)

Example:
  similarity = 85 → distance = 2.0 - (85/50.0) = 0.3
```

### KNN Search Example

```sql
-- Find similar cached queries
SELECT c.natural_language, c.generated_sql,
       vec_distance_cosine(v.embedding, '[0.1, 0.2, ...]') as distance
FROM nl2sql_cache c
JOIN nl2sql_cache_vec v ON c.id = v.rowid
WHERE v.embedding MATCH '[0.1, 0.2, ...]'
AND distance < 0.3
ORDER BY distance
LIMIT 1;
```

## GenAI Integration

Vector Features use the existing **GenAI Module** for embedding generation.

### Embedding Endpoint

- **Module**: `lib/GenAI_Thread.cpp`
- **Global Handler**: `GenAI_Threads_Handler *GloGATH`
- **Method**: `embed_documents({text})`
- **Returns**: `GenAI_EmbeddingResult` with `float* data`, `embedding_size`, `count`

### Configuration

GenAI module connects to llama-server for embeddings:

```cpp
// Endpoint: http://127.0.0.1:8013/embedding
// Model: nomic-embed-text-v1.5 (or similar)
// Dimension: 1536
```

### Memory Management

```cpp
// GenAI returns malloc'd data - must free after copying
GenAI_EmbeddingResult result = GloGATH->embed_documents({text});

std::vector<float> embedding(result.data, result.data + result.embedding_size);
free(result.data);  // Important: free the original data
```

## Performance

### Embedding Generation

| Operation | Time | Notes |
|-----------|------|-------|
| Generate embedding | ~100-300ms | Via llama-server (local) |
| Vector cache search | ~10-50ms | KNN search with sqlite-vec |
| Pattern similarity check | ~10-50ms | KNN search with sqlite-vec |

### Cache Benefits

- **Cache hit**: ~10-50ms (vs 1-5s for LLM call)
- **Semantic matching**: Higher hit rate than exact text cache
- **Reduced LLM costs**: Fewer API calls to cloud providers

### Storage

- **Embedding size**: 1536 floats × 4 bytes = ~6 KB per query
- **1000 cached queries**: ~6 MB + overhead
- **100 threat patterns**: ~600 KB

## Troubleshooting

### Vector Features Not Working

1. **Check AI features enabled**:
   ```sql
   SELECT * FROM runtime_mysql_servers
   WHERE variable_name LIKE 'ai_%_enabled';
   ```

2. **Check vector DB exists**:
   ```bash
   ls -la /var/lib/proxysql/ai_features.db
   ```

3. **Check GenAI handler initialized**:
   ```bash
   tail -f proxysql.log | grep GenAI
   ```

4. **Check llama-server running**:
   ```bash
   curl http://127.0.0.1:8013/embedding
   ```

### Poor Similarity Detection

1. **Adjust thresholds**:
   ```sql
   -- Lower threshold = more sensitive (more false positives)
   SET ai_anomaly_similarity_threshold='80';
   ```

2. **Add more threat patterns**:
   ```cpp
   anomaly_detector->add_threat_pattern(...);
   ```

3. **Check embedding quality**:
   - Ensure llama-server is using a good embedding model
   - Verify query normalization is working

### Cache Issues

```sql
-- Clear cache (via API, not SQL yet)
anomaly_detector->clear_cache();

-- Check cache statistics
SHOW STATUS LIKE 'ai_nl2sql_cache_%';
```

## Security Considerations

- **Embeddings are stored locally** in SQLite database
- **No external API calls** for similarity search
- **Threat patterns are user-defined** - ensure proper access control
- **Risk scores are heuristic** - tune thresholds for your environment

## Future Enhancements

- [ ] Automatic threat pattern learning from flagged queries
- [ ] Embedding model fine-tuning for SQL domain
- [ ] Distributed vector storage for large-scale deployments
- [ ] Real-time embedding updates for adaptive learning
- [ ] Multi-lingual support for embeddings

## API Reference

See `API.md` for complete API documentation.

## Architecture Details

See `ARCHITECTURE.md` for detailed architecture documentation.

## Testing Guide

See `TESTING.md` for testing instructions.
