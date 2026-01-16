# NL2SQL Architecture

## System Overview

```
Client Query (NL2SQL: ...)
    ↓
MySQL_Session (detects prefix)
    ↓
AI_Features_Manager::get_nl2sql()
    ↓
NL2SQL_Converter::convert()
    ├─ check_vector_cache()  ← sqlite-vec similarity search
    ├─ build_prompt()         ← Schema context via MySQL_Tool_Handler
    ├─ select_model()         ← Ollama/OpenAI/Anthropic selection
    ├─ call_llm_api()         ← libcurl HTTP request
    └─ validate_sql()         ← Keyword validation
    ↓
Return Resultset (sql_query, confidence, ...)
```

## Components

### 1. NL2SQL_Converter

**Location**: `include/NL2SQL_Converter.h`, `lib/NL2SQL_Converter.cpp`

Main class coordinating the NL2SQL conversion pipeline.

**Key Methods:**
- `convert()`: Main entry point for conversion
- `check_vector_cache()`: Semantic similarity search
- `build_prompt()`: Construct LLM prompt with schema context
- `select_model()`: Choose best LLM provider
- `call_ollama()`, `call_openai()`, `call_anthropic()`: LLM API calls

**Configuration:**
```cpp
struct {
    bool enabled;
    char* query_prefix;              // Default: "NL2SQL:"
    char* model_provider;            // Default: "ollama"
    char* ollama_model;              // Default: "llama3.2"
    char* openai_model;              // Default: "gpt-4o-mini"
    char* anthropic_model;           // Default: "claude-3-haiku"
    int cache_similarity_threshold;  // Default: 85
    int timeout_ms;                  // Default: 30000
    char* openai_key;
    char* anthropic_key;
    bool prefer_local;
} config;
```

### 2. LLM_Clients

**Location**: `lib/LLM_Clients.cpp`

HTTP clients for each LLM provider using libcurl.

#### Ollama (Local)

**Endpoint**: `POST http://localhost:11434/api/generate`

**Request Format:**
```json
{
  "model": "llama3.2",
  "prompt": "Convert to SQL: Show top customers",
  "stream": false,
  "options": {
    "temperature": 0.1,
    "num_predict": 500
  }
}
```

**Response Format:**
```json
{
  "response": "SELECT * FROM customers ORDER BY revenue DESC LIMIT 10",
  "model": "llama3.2",
  "total_duration": 123456789
}
```

#### OpenAI (Cloud)

**Endpoint**: `POST https://api.openai.com/v1/chat/completions`

**Headers:**
- `Content-Type: application/json`
- `Authorization: Bearer sk-...`

**Request Format:**
```json
{
  "model": "gpt-4o-mini",
  "messages": [
    {"role": "system", "content": "You are a SQL expert..."},
    {"role": "user", "content": "Convert to SQL: Show top customers"}
  ],
  "temperature": 0.1,
  "max_tokens": 500
}
```

**Response Format:**
```json
{
  "choices": [{
    "message": {
      "content": "SELECT * FROM customers ORDER BY revenue DESC LIMIT 10",
      "role": "assistant"
    },
    "finish_reason": "stop"
  }],
  "usage": {"total_tokens": 123}
}
```

#### Anthropic (Cloud)

**Endpoint**: `POST https://api.anthropic.com/v1/messages`

**Headers:**
- `Content-Type: application/json`
- `x-api-key: sk-ant-...`
- `anthropic-version: 2023-06-01`

**Request Format:**
```json
{
  "model": "claude-3-haiku-20240307",
  "max_tokens": 500,
  "messages": [
    {"role": "user", "content": "Convert to SQL: Show top customers"}
  ],
  "system": "You are a SQL expert...",
  "temperature": 0.1
}
```

**Response Format:**
```json
{
  "content": [{"type": "text", "text": "SELECT * FROM customers..."}],
  "model": "claude-3-haiku-20240307",
  "usage": {"input_tokens": 10, "output_tokens": 20}
}
```

### 3. Vector Cache

**Location**: Uses `SQLite3DB` with sqlite-vec extension

**Tables:**

```sql
-- Cache entries
CREATE TABLE nl2sql_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    natural_language TEXT NOT NULL,
    sql_query TEXT NOT NULL,
    model_provider TEXT,
    confidence REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Virtual table for similarity search
CREATE VIRTUAL TABLE nl2sql_cache_vec USING vec0(
    embedding FLOAT[1536],  -- Dimension depends on embedding model
    id INTEGER PRIMARY KEY
);
```

**Similarity Search:**
```sql
SELECT nc.sql_query, nc.confidence, distance
FROM nl2sql_cache_vec
JOIN nl2sql_cache nc ON nl2sql_cache_vec.id = nc.id
WHERE embedding MATCH ?
AND k = 10  -- Return top 10 matches
ORDER BY distance
LIMIT 1;
```

### 4. MySQL_Session Integration

**Location**: `lib/MySQL_Session.cpp` (around line ~6867)

Query interception flow:

1. Detect `NL2SQL:` prefix in query
2. Extract natural language text
3. Call `GloAI->get_nl2sql()->convert()`
4. Return generated SQL as resultset
5. User can review and execute

### 5. AI_Features_Manager

**Location**: `include/AI_Features_Manager.h`, `lib/AI_Features_Manager.cpp`

Coordinates all AI features including NL2SQL.

**Responsibilities:**
- Initialize vector database
- Create and manage NL2SQL_Converter instance
- Handle configuration variables with `ai_nl2sql_` prefix
- Provide thread-safe access to components

## Flow Diagrams

### Conversion Flow

```
┌─────────────────┐
│ NL2SQL Request  │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│ Check Vector Cache      │
│ - Generate embedding    │
│ - Similarity search     │
└────────┬────────────────┘
         │
    ┌────┴────┐
    │ Cache   │ No ───────────────┐
    │ Hit?    │                    │
    └────┬────┘                    │
         │ Yes                     │
         ▼                          │
    Return Cached                   ▼
┌──────────────────┐      ┌─────────────────┐
│   Build Prompt   │      │ Select Model    │
│ - System role    │      │ - Latency       │
│ - Schema context │      │ - Preference    │
│ - User query     │      │ - API keys      │
└────────┬─────────┘      └────────┬────────┘
         │                         │
         └─────────┬───────────────┘
                   ▼
         ┌──────────────────┐
         │   Call LLM API   │
         │ - libcurl HTTP   │
         │ - JSON parse     │
         └────────┬─────────┘
                  │
                  ▼
         ┌──────────────────┐
         │  Validate SQL    │
         │ - Keyword check  │
         │ - Clean output   │
         └────────┬─────────┘
                  │
                  ▼
         ┌──────────────────┐
         │ Store in Cache   │
         │ - Embed query    │
         │ - Save result    │
         └────────┬─────────┘
                  │
                  ▼
         ┌──────────────────┐
         │  Return Result   │
         │ - sql_query      │
         │ - confidence     │
         │ - explanation    │
         └──────────────────┘
```

### Model Selection Logic

```
┌─────────────────────────────────┐
│     Start: Select Model         │
└────────────┬────────────────────┘
             │
             ▼
    ┌─────────────────────┐
    │ max_latency_ms <    │──── Yes ────┐
    │ 500ms?              │              │
    └────────┬────────────┘              │
             │ No                        │
             ▼                           │
    ┌─────────────────────┐              │
    │ Check provider      │              │
    │ preference          │              │
    └────────┬────────────┘              │
             │                           │
      ┌──────┴──────┐                   │
      │             │                   │
      ▼             ▼                   │
   OpenAI      Anthropic             Ollama
      │             │                   │
      ▼             ▼                   │
 ┌─────────┐  ┌─────────┐         ┌─────────┐
 │ API key │  │ API key │         │ Return  │
 │ set?    │  │ set?    │         │ OLLAMA  │
 └────┬────┘  └────┬────┘         └─────────┘
      │            │
     Yes          Yes
      │            │
      └──────┬─────┘
             │
             ▼
     ┌──────────────┐
     │ Return cloud │
     │ provider     │
     └──────────────┘
```

## Data Structures

### NL2SQLRequest

```cpp
struct NL2SQLRequest {
    std::string natural_language;           // Input query
    std::string schema_name;                 // Current schema
    int max_latency_ms;                      // Latency requirement
    bool allow_cache;                        // Enable cache lookup
    std::vector<std::string> context_tables; // Optional table hints
};
```

### NL2SQLResult

```cpp
struct NL2SQLResult {
    std::string sql_query;                  // Generated SQL
    float confidence;                        // 0.0-1.0 score
    std::string explanation;                 // Model info
    std::vector<std::string> tables_used;    // Referenced tables
    bool cached;                             // From cache
    int64_t cache_id;                        // Cache entry ID
};
```

## Configuration Management

### Variable Namespacing

All NL2SQL variables use `ai_nl2sql_` prefix:

```
ai_nl2sql_enabled
ai_nl2sql_query_prefix
ai_nl2sql_model_provider
ai_nl2sql_ollama_model
ai_nl2sql_openai_model
ai_nl2sql_anthropic_model
ai_nl2sql_cache_similarity_threshold
ai_nl2sql_timeout_ms
ai_nl2sql_openai_key
ai_nl2sql_anthropic_key
ai_nl2sql_prefer_local
```

### Variable Persistence

```
Runtime (memory)
    ↑
    | LOAD MYSQL VARIABLES TO RUNTIME
    |
    | SET ai_nl2sql_... = 'value'
    |
    | SAVE MYSQL VARIABLES TO DISK
    ↓
Disk (config file)
```

## Thread Safety

- **NL2SQL_Converter**: NOT thread-safe by itself
- **AI_Features_Manager**: Provides thread-safe access via `wrlock()`/`wrunlock()`
- **Vector Cache**: Thread-safe via SQLite mutex

## Error Handling

### Error Categories

1. **LLM API Errors**: Timeout, connection failure, auth failure
   - Fallback: Try next available provider
   - Return: Empty SQL with error in explanation

2. **SQL Validation Failures**: Doesn't look like SQL
   - Return: SQL with warning comment
   - Confidence: Low (0.3)

3. **Cache Errors**: Database failures
   - Fallback: Continue without cache
   - Log: Warning in ProxySQL log

### Logging

All NL2SQL operations log to `proxysql.log`:

```
NL2SQL: Converting query: Show top customers
NL2SQL: Selecting local Ollama due to latency constraint
NL2SQL: Calling Ollama with model: llama3.2
NL2SQL: Conversion complete. Confidence: 0.85
```

## Performance Considerations

### Optimization Strategies

1. **Caching**: Enable for repeated queries
2. **Local First**: Prefer Ollama for lower latency
3. **Timeout**: Set appropriate `ai_nl2sql_timeout_ms`
4. **Batch Requests**: Not yet implemented (planned)

### Resource Usage

- **Memory**: Vector cache grows with usage
- **Network**: HTTP requests for each cache miss
- **CPU**: Embedding generation for cache entries

## Future Enhancements

- **Phase 3**: Full vector cache implementation
- **Phase 3**: Schema context retrieval via MySQL_Tool_Handler
- **Phase 4**: Async conversion API
- **Phase 5**: Batch query conversion
- **Phase 6**: Custom fine-tuned models

## See Also

- [README.md](README.md) - User documentation
- [API.md](API.md) - Complete API reference
- [TESTING.md](TESTING.md) - Testing guide
