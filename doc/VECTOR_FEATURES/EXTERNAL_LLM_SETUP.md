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

**Option A: Use OpenAI-Compatible Endpoint**

If your custom LLM is OpenAI-compatible, configure it as:

```sql
-- For OpenAI-compatible custom endpoints
-- You may need to modify lib/LLM_Clients.cpp to support custom URLs
-- Or use the Ollama provider with your endpoint

SET ai_nl2sql_model_provider='ollama';
SET ai_nl2sql_ollama_model='your-model-name';

-- If your endpoint is NOT localhost:11434, modify the code:
-- In lib/LLM_Clients.cpp, line 117:
--   snprintf(url, sizeof(url), "http://YOUR_ENDPOINT:PORT/api/generate");
```

**Option B: Use OpenAI Directly**

```sql
SET ai_nl2sql_model_provider='openai';
SET ai_nl2sql_openai_model='gpt-4o-mini';
SET ai_nl2sql_openai_key='sk-your-api-key';
```

**Option C: Use Anthropic**

```sql
SET ai_nl2sql_model_provider='anthropic';
SET ai_nl2sql_anthropic_model='claude-3-haiku';
SET ai_nl2sql_anthropic_key='sk-ant-your-api-key';
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

## Modifying Code for Custom LLM Endpoint

If you have a custom LLM endpoint that's not Ollama, OpenAI, or Anthropic, you need to modify the code:

### Option 1: Add Custom Provider to LLM_Clients.cpp

```cpp
// In lib/LLM_Clients.cpp, add:

// Near line 7, add:
// * - Custom LLM: POST http://your-endpoint/api/generate

// Add new provider in NL2SQL_Converter.h enum:
enum class ModelProvider {
    LOCAL_OLLAMA,
    CLOUD_OPENAI,
    CLOUD_ANTHROPIC,
    CUSTOM_LLM  // Add this
};

// In NL2SQL_Converter.cpp, add case for custom:
case ModelProvider::CUSTOM_LLM:
    raw_sql = call_custom_llm(prompt, model_name);
    result.explanation = "Generated by Custom LLM";
    break;

// Implement the custom function:
std::string NL2SQL_Converter::call_custom_llm(const std::string& prompt, 
                                                 const std::string& model) {
    // Use libcurl to call your endpoint
    // Format: OpenAI-compatible or your custom format
}
```

### Option 2: Quick Hack: Modify Ollama Endpoint

If your endpoint is OpenAI-compatible, just modify the URL in `lib/LLM_Clients.cpp`:

```cpp
// Line 117 in LLM_Clients.cpp
// Change from:
snprintf(url, sizeof(url), "http://localhost:11434/api/generate");

// To:
snprintf(url, sizeof(url), "http://YOUR_CUSTOM_ENDPOINT:PORT/v1/chat/completions");

// And modify the request format to be OpenAI-compatible
```

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
| `ai_nl2sql_model_provider` | `ollama` | LLM provider |
| `ai_nl2sql_ollama_model` | `llama3.2` | Model name |
| `ai_nl2sql_cache_similarity_threshold` | `85` | Cache threshold (0-100) |
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
SELECT ai_nl2sql_model_provider, ai_nl2sql_ollama_model FROM mysql_servers;
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
