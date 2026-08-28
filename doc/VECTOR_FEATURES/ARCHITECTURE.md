# Vector Features Architecture

## System Overview

Vector Features provide semantic similarity capabilities for ProxySQL using vector embeddings and the **sqlite-vec** extension. The system integrates with the existing **GenAI module** for embedding generation and uses **SQLite** with virtual vector tables for efficient similarity search.

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Client Application                              │
│                    (SQL client with NL2SQL query)                        │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          MySQL_Session                                   │
│  ┌─────────────────┐         ┌──────────────────┐                        │
│  │ Query Parsing   │         │ NL2SQL Prefix    │                        │
│  │ "NL2SQL: ..."   │         │ Detection        │                        │
│  └────────┬────────┘         └────────┬─────────┘                        │
│           │                           │                                   │
│           ▼                           ▼                                   │
│  ┌─────────────────┐         ┌──────────────────┐                        │
│  │ Anomaly Check   │         │ NL2SQL Converter │                        │
│  │ (intercept all) │         │   (prefix only)  │                        │
│  └─────────────────┘         └────────┬─────────┘                        │
└────────────────┬────────────────────────────┼────────────────────────────┘
                 │                            │
                 ▼                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       AI_Features_Manager                                │
│  ┌──────────────────────┐      ┌──────────────────────┐                 │
│  │ Anomaly_Detector     │      │ NL2SQL_Converter     │                 │
│  │                      │      │                      │                 │
│  │ - get_query_embedding│      │ - get_query_embedding│                 │
│  │ - check_similarity   │      │ - check_vector_cache │                 │
│  │ - add_threat_pattern │      │ - store_in_cache     │                 │
│  └──────────┬───────────┘      └──────────┬───────────┘                 │
└─────────────┼──────────────────────────────┼────────────────────────────┘
              │                              │
              ▼                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          GenAI Module                                    │
│                    (lib/GenAI_Thread.cpp)                               │
│                                                                          │
│    GloGATH->embed_documents({text})                                     │
│           │                                                              │
│           ▼                                                              │
│  ┌──────────────────────────────────────────────────┐                   │
│  │     HTTP Request to llama-server                 │                   │
│  │     POST http://127.0.0.1:8013/embedding        │                   │
│  └──────────────────────────────────────────────────┘                   │
└────────────────────────┬───────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      llama-server                                       │
│                   (External Process)                                    │
│                                                                          │
│  Model: nomic-embed-text-v1.5 or similar                                │
│  Output: 1536-dimensional float vector                                  │
└────────────────────────┬───────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Vector Database (SQLite)                             │
│                 (/var/lib/proxysql/ai_features.db)                      │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────┐          │
│  │  Main Tables                        │          │
│  │  - nl2sql_cache                                              │          │
│  │  - anomaly_patterns                                         │          │
│  │  - query_history                                            │          │
│  └──────────────────────────────────────────────────────────┘          │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────┐          │
│  │  Virtual Vector Tables (sqlite-vec)       │          │
│  │  - nl2sql_cache_vec                                          │          │
│  │  - anomaly_patterns_vec                                     │          │
│  │  - query_history_vec                                        │          │
│  └──────────────────────────────────────────────────────────┘          │
│                                                                          │
│  KNN Search: vec_distance_cosine(embedding, '[...]')                   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Data Flow Diagrams

### NL2SQL Conversion Flow

```
Input: "NL2SQL: Show customers from USA"
    │
    ├─→ check_vector_cache()
    │       ├─→ Generate embedding via GenAI
    │       ├─→ KNN search in nl2sql_cache_vec
    │       └─→ Return if similarity > threshold
    │
    ├─→ (if cache miss) Build prompt
    │       ├─→ Get schema context
    │       └─→ Add system instructions
    │
    ├─→ Select model provider
    │       ├─→ Check latency requirements
    │       ├─→ Check API keys
    │       └─→ Choose Ollama/OpenAI/Anthropic
    │
    ├─→ Call LLM API
    │       └─→ HTTP request to model endpoint
    │
    ├─→ Validate SQL
    │       ├─→ Check SQL keywords
    │       └─→ Calculate confidence
    │
    └─→ store_in_vector_cache()
            ├─→ Generate embedding
            ├─→ Insert into nl2sql_cache
            └─→ Update nl2sql_cache_vec
```

### Anomaly Detection Flow

```
Input: "SELECT * FROM users WHERE id=5 OR 2=2--"
    │
    ├─→ normalize_query()
    │       ├─→ Lowercase
    │       ├─→ Remove extra whitespace
    │       └─→ Standardize SQL
    │
    ├─→ get_query_embedding()
    │       └─→ Call GenAI module
    │
    ├─→ check_embedding_similarity()
    │       ├─→ KNN search in anomaly_patterns_vec
    │       ├─→ For each match within threshold:
    │       │       ├─→ Calculate distance
    │       │       └─→ Calculate risk score
    │       └─→ Return highest risk match
    │
    └─→ Action decision
            ├─→ risk_score > threshold → BLOCK
            ├─→ risk_score > warning → FLAG
            └─→ Otherwise → ALLOW
```

## Database Schema

### Vector Database Structure

```
ai_features.db (SQLite)
│
├─ Main Tables (store data + embeddings as BLOB)
│  ├─ nl2sql_cache
│  │  ├─ id (INTEGER PRIMARY KEY)
│  │  ├─ natural_language (TEXT)
│  │  ├─ generated_sql (TEXT)
│  │  ├─ schema_context (TEXT)
│  │  ├─ embedding (BLOB)           ← 1536 floats as binary
│  │  ├─ hit_count (INTEGER)
│  │  ├─ last_hit (INTEGER)
│  │  └─ created_at (INTEGER)
│  │
│  ├─ anomaly_patterns
│  │  ├─ id (INTEGER PRIMARY KEY)
│  │  ├─ pattern_name (TEXT)
│  │  ├─ pattern_type (TEXT)
│  │  ├─ query_example (TEXT)
│  │  ├─ embedding (BLOB)           ← 1536 floats as binary
│  │  ├─ severity (INTEGER)
│  │  └─ created_at (INTEGER)
│  │
│  └─ query_history
│     ├─ id (INTEGER PRIMARY KEY)
│     ├─ query_text (TEXT)
│     ├─ generated_sql (TEXT)
│     ├─ embedding (BLOB)
│     ├─ execution_time_ms (INTEGER)
│     ├─ success (BOOLEAN)
│     └─ timestamp (INTEGER)
│
└─ Virtual Tables (sqlite-vec for KNN search)
   ├─ nl2sql_cache_vec
   │  └─ rowid (references nl2sql_cache.id)
   │     └─ embedding (float(1536))  ← Vector index
   │
   ├─ anomaly_patterns_vec
   │  └─ rowid (references anomaly_patterns.id)
   │     └─ embedding (float(1536))
   │
   └─ query_history_vec
      └─ rowid (references query_history.id)
         └─ embedding (float(1536))
```

## Similarity Metrics

### Cosine Distance

```
cosine_similarity = (A · B) / (|A| * |B|)
cosine_distance = 2 * (1 - cosine_similarity)

Range:
- cosine_similarity: -1 to 1
- cosine_distance: 0 to 2
  - 0 = identical vectors (similarity = 100%)
  - 1 = orthogonal vectors (similarity = 50%)
  - 2 = opposite vectors (similarity = 0%)
```

### Threshold Conversion

```
// User-configurable similarity (0-100)
int similarity_threshold = 85;  // 85% similar

// Convert to distance threshold for sqlite-vec
float distance_threshold = 2.0f - (similarity_threshold / 50.0f);
// = 2.0 - (85 / 50.0) = 2.0 - 1.7 = 0.3
```

### Risk Score Calculation

```
risk_score = (severity / 10.0f) * (1.0f - (distance / 2.0f));

// Example 1: High severity, very similar
// severity = 9, distance = 0.1 (99% similar)
// risk_score = 0.9 * (1 - 0.05) = 0.855 (85.5% risk)
```

## Thread Safety

```
AI_Features_Manager
│
├─ pthread_rwlock_t rwlock
│  ├─ wrlock() / wrunlock()  // For writes
│  └─ rdlock() / rdunlock()  // For reads
│
├─ NL2SQL_Converter (uses manager locks)
│  └─ Methods handle locking internally
│
└─ Anomaly_Detector (uses manager locks)
   └─ Methods handle locking internally
```
