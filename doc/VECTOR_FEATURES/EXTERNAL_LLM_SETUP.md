# External LLM Setup for Live Testing

## Overview

This guide shows how to configure ProxySQL Vector Features with:
- **Custom LLM endpoint** for NL2SQL (natural language to SQL)
- **llama-server (local)** for embeddings (semantic similarity/caching)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         ProxySQL                                 │
│                                                                   │
│  ┌──────────────────────┐      ┌──────────────────────┐       │
│  │   NL2SQL_Converter   │      │   Anomaly_Detector   │       │
│  │                      │      │                      │       │
│  │ - call_ollama()      │      │ - get_query_embedding()│     │
│  │   (or OpenAI compat) │      │   via GenAI module    │       │
│  └──────────┬───────────┘      └──────────┬───────────┘       │
│             │                              │                     │
│             ▼                              ▼                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    GenAI Module                          │  │
│  │            (lib/GenAI_Thread.cpp)                        │  │
│  │                                                          │  │
│  │  Variable: genai_embedding_uri                           │  │
│  │  Default: http://127.0.0.1:8013/embedding              │  │
│  └────────────────────────┬─────────────────────────────────┘  │
│                           │                                     │
└───────────────────────────┼─────────────────────────────────────┘
                            │
                            ▼
┌───────────────────────────────────────────────────────────────────┐
│                     External Services                             │
│                                                                   │
│  ┌─────────────────────┐          ┌──────────────────────┐      │
│  │  Custom LLM         │          │   llama-server       │      │
│  │  (Your endpoint)    │          │   (local, :8013)     │      │
│  │                     │          │                      │      │
│  │  For: NL2SQL        │          │  For: Embeddings     │      │
│  └─────────────────────┘          └──────────────────────┘      │
└───────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

### 1. llama-server for Embeddings

```bash
# Start llama-server with embedding model
ollama run nomic-embed-text-v1.5

# Or via llama-server directly
llama-server --model nomic-embed-text-v1.5 --port 8013 --embedding

# Verify it's running
curl http://127.0.0.1:8013/embedding
```

### 2. Custom LLM Endpoint

Your custom LLM endpoint should be **OpenAI-compatible** for easiest integration.

Example compatible endpoints:
- **vLLM**: `http://localhost:8000/v1/chat/completions`
- **LM Studio**: `http://localhost:1234/v1/chat/completions`
- **Ollama (via OpenAI compat)**: `http://localhost:11434/v1/chat/completions`
- **Custom API**: Must accept same format as OpenAI

---

## Configuration

### Step 1: Configure GenAI Embedding Endpoint

The embedding endpoint is configured via the `genai_embedding_uri` variable.

```sql
-- Connect to ProxySQL admin
mysql -h 127.0.0.1 -P 6032 -u admin -padmin

-- Set embedding endpoint (for llama-server)
UPDATE mysql_servers SET genai_embedding_uri='http://127.0.0.1:8013/embedding';

-- Or set a custom embedding endpoint
UPDATE mysql_servers SET genai_embedding_uri='http://your-embedding-server:port/embeddings';

LOAD MYSQL VARIABLES TO RUNTIME;
```

### Step 2: Configure NL2SQL LLM Provider

ProxySQL uses a **generic provider configuration** that supports any OpenAI-compatible or Anthropic-compatible endpoint.

**Option A: Use Ollama (Default)**

Ollama is used via its OpenAI-compatible endpoint:

```sql
SET ai_nl2sql_provider='openai';
SET ai_nl2sql_provider_url='http://localhost:11434/v1/chat/completions';
SET ai_nl2sql_provider_model='llama3.2';
SET ai_nl2sql_provider_key='';  -- Empty for local
```

**Option B: Use OpenAI**

```sql
SET ai_nl2sql_provider='openai';
SET ai_nl2sql_provider_url='https://api.openai.com/v1/chat/completions';
SET ai_nl2sql_provider_model='gpt-4o-mini';
SET ai_nl2sql_provider_key='sk-your-api-key';
```

**Option C: Use Any OpenAI-Compatible Endpoint**

This works with **any** OpenAI-compatible API:

```sql
-- For vLLM (local or remote)
SET ai_nl2sql_provider='openai';
SET ai_nl2sql_provider_url='http://localhost:8000/v1/chat/completions';
SET ai_nl2sql_provider_model='your-model-name';
SET ai_nl2sql_provider_key='';  -- Empty for local endpoints

-- For LM Studio
SET ai_nl2sql_provider='openai';
SET ai_nl2sql_provider_url='http://localhost:1234/v1/chat/completions';
SET ai_nl2sql_provider_model='your-model-name';
SET ai_nl2sql_provider_key='';

-- For Z.ai
SET ai_nl2sql_provider='openai';
SET ai_nl2sql_provider_url='https://api.z.ai/api/coding/paas/v4/chat/completions';
SET ai_nl2sql_provider_model='your-model-name';
SET ai_nl2sql_provider_key='your-zai-api-key';

-- For any other OpenAI-compatible endpoint
SET ai_nl2sql_provider='openai';
SET ai_nl2sql_provider_url='https://your-endpoint.com/v1/chat/completions';
SET ai_nl2sql_provider_model='your-model-name';
SET ai_nl2sql_provider_key='your-api-key';
```

**Option D: Use Anthropic**

```sql
SET ai_nl2sql_provider='anthropic';
SET ai_nl2sql_provider_url='https://api.anthropic.com/v1/messages';
SET ai_nl2sql_provider_model='claude-3-haiku';
SET ai_nl2sql_provider_key='sk-ant-your-api-key';
```

**Option E: Use Any Anthropic-Compatible Endpoint**

```sql
-- For any Anthropic-format endpoint
SET ai_nl2sql_provider='anthropic';
SET ai_nl2sql_provider_url='https://your-endpoint.com/v1/messages';
SET ai_nl2sql_provider_model='your-model-name';
SET ai_nl2sql_provider_key='your-api-key';
```

### Step 3: Enable Vector Features

```sql
SET ai_features_enabled='true';
SET ai_nl2sql_enabled='true';
SET ai_anomaly_detection_enabled='true';

-- Configure thresholds
SET ai_nl2sql_cache_similarity_threshold='85';
SET ai_anomaly_similarity_threshold='85';
SET ai_anomaly_risk_threshold='70';

LOAD MYSQL VARIABLES TO RUNTIME;
```

---

## Custom LLM Endpoints

With the generic provider configuration, **no code changes are needed** to support custom LLM endpoints. Simply:

1. Choose the appropriate provider format (`openai` or `anthropic`)
2. Set the `ai_nl2sql_provider_url` to your endpoint
3. Configure the model name and API key

This works with any OpenAI-compatible or Anthropic-compatible API without modifying the code.

---

## Testing

### Test 1: Embedding Generation

```bash
# Test llama-server is working
curl -X POST http://127.0.0.1:8013/embedding \
  -H "Content-Type: application/json" \
  -d '{
    "content": "test query",
    "model": "nomic-embed-text"
  }'
```

### Test 2: Add Threat Pattern

```cpp
// Via C++ API or MCP tool (when implemented)
Anomaly_Detector* detector = GloAI->get_anomaly();

int pattern_id = detector->add_threat_pattern(
    "OR 1=1 Tautology",
    "SELECT * FROM users WHERE id=1 OR 1=1--",
    "sql_injection",
    9
);

printf("Pattern added with ID: %d\n", pattern_id);
```

### Test 3: NL2SQL Conversion

```sql
-- Connect to ProxySQL data port
mysql -h 127.0.0.1 -P 6033 -u test -ptest

-- Try NL2SQL query
NL2SQL: Show all customers from USA;

-- Should return generated SQL
```

### Test 4: Vector Cache

```sql
-- First query (cache miss)
NL2SQL: Display customers from United States;

-- Similar query (should hit cache)
NL2SQL: List USA customers;

-- Check cache stats
SHOW STATUS LIKE 'ai_nl2sql_cache_%';
```

---

## Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `genai_embedding_uri` | `http://127.0.0.1:8013/embedding` | Embedding endpoint |
| **NL2SQL Provider** | | |
| `ai_nl2sql_provider` | `openai` | Provider format: `openai` or `anthropic` |
| `ai_nl2sql_provider_url` | `http://localhost:11434/v1/chat/completions` | Endpoint URL |
| `ai_nl2sql_provider_model` | `llama3.2` | Model name |
| `ai_nl2sql_provider_key` | (none) | API key (optional for local endpoints) |
| `ai_nl2sql_cache_similarity_threshold` | `85` | Semantic cache threshold (0-100) |
| `ai_nl2sql_timeout_ms` | `30000` | LLM request timeout (milliseconds) |
| **Anomaly Detection** | | |
| `ai_anomaly_similarity_threshold` | `85` | Anomaly similarity (0-100) |
| `ai_anomaly_risk_threshold` | `70` | Risk threshold (0-100) |

---

## Troubleshooting

### Embedding fails

```bash
# Check llama-server is running
curl http://127.0.0.1:8013/embedding

# Check ProxySQL logs
tail -f proxysql.log | grep GenAI

# Verify configuration
SELECT genai_embedding_uri FROM mysql_servers LIMIT 1;
```

### NL2SQL fails

```bash
# Check LLM endpoint is accessible
curl -X POST YOUR_ENDPOINT -H "Content-Type: application/json" -d '{...}'

# Check ProxySQL logs
tail -f proxysql.log | grep NL2SQL

# Verify configuration
SELECT ai_nl2sql_provider, ai_nl2sql_provider_url, ai_nl2sql_provider_model FROM mysql_servers;
```

### Vector cache not working

```sql
-- Check vector DB exists
-- (Use sqlite3 command line tool)
sqlite3 /var/lib/proxysql/ai_features.db

-- Check tables
.tables

-- Check entries
SELECT COUNT(*) FROM nl2sql_cache;
SELECT COUNT(*) FROM nl2sql_cache_vec;
```

---

## Quick Start Script

See `scripts/test_external_live.sh` for an automated testing script.

```bash
./scripts/test_external_live.sh
```
