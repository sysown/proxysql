# NL2SQL API Reference

## Complete API Documentation

This document provides a comprehensive reference for all NL2SQL APIs, including configuration variables, data structures, and methods.

## Table of Contents

- [Configuration Variables](#configuration-variables)
- [Data Structures](#data-structures)
- [NL2SQL_Converter Class](#nl2sql_converter-class)
- [AI_Features_Manager Class](#ai_features_manager-class)
- [MySQL Protocol Integration](#mysql-protocol-integration)

## Configuration Variables

All NL2SQL variables use the `ai_nl2sql_` prefix and are accessible via the ProxySQL admin interface.

### Master Switch

#### `ai_nl2sql_enabled`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable/disable NL2SQL feature
- **Runtime**: Yes
- **Example**:
  ```sql
  SET ai_nl2sql_enabled='true';
  LOAD MYSQL VARIABLES TO RUNTIME;
  ```

### Query Detection

#### `ai_nl2sql_query_prefix`

- **Type**: String
- **Default**: `NL2SQL:`
- **Description**: Prefix that identifies NL2SQL queries
- **Runtime**: Yes
- **Example**:
  ```sql
  SET ai_nl2sql_query_prefix='SQL:';
  -- Now use: SQL: Show customers
  ```

### Model Selection

#### `ai_nl2sql_model_provider`

- **Type**: Enum (`ollama`, `openai`, `anthropic`)
- **Default**: `ollama`
- **Description**: Preferred LLM provider
- **Runtime**: Yes
- **Example**:
  ```sql
  SET ai_nl2sql_model_provider='openai';
  LOAD MYSQL VARIABLES TO RUNTIME;
  ```

#### `ai_nl2sql_ollama_model`

- **Type**: String
- **Default**: `llama3.2`
- **Description**: Ollama model name
- **Runtime**: Yes
- **Example**:
  ```sql
  SET ai_nl2sql_ollama_model='llama3.3';
  ```

#### `ai_nl2sql_openai_model`

- **Type**: String
- **Default**: `gpt-4o-mini`
- **Description**: OpenAI model name
- **Runtime**: Yes
- **Example**:
  ```sql
  SET ai_nl2sql_openai_model='gpt-4o';
  ```

#### `ai_nl2sql_anthropic_model`

- **Type**: String
- **Default**: `claude-3-haiku`
- **Description**: Anthropic model name
- **Runtime**: Yes
- **Example**:
  ```sql
  SET ai_nl2sql_anthropic_model='claude-3-5-sonnet-20241022';
  ```

### API Keys

#### `ai_nl2sql_openai_key`

- **Type**: String (sensitive)
- **Default**: NULL
- **Description**: OpenAI API key
- **Runtime**: Yes
- **Example**:
  ```sql
  SET ai_nl2sql_openai_key='sk-proj-...';
  ```

#### `ai_nl2sql_anthropic_key`

- **Type**: String (sensitive)
- **Default**: NULL
- **Description**: Anthropic API key
- **Runtime**: Yes
- **Example**:
  ```sql
  SET ai_nl2sql_anthropic_key='sk-ant-...';
  ```

### Cache Configuration

#### `ai_nl2sql_cache_similarity_threshold`

- **Type**: Integer (0-100)
- **Default**: `85`
- **Description**: Minimum similarity score for cache hit
- **Runtime**: Yes
- **Example**:
  ```sql
  SET ai_nl2sql_cache_similarity_threshold='90';
  ```

### Performance

#### `ai_nl2sql_timeout_ms`

- **Type**: Integer
- **Default**: `30000` (30 seconds)
- **Description**: Maximum time to wait for LLM response
- **Runtime**: Yes
- **Example**:
  ```sql
  SET ai_nl2sql_timeout_ms='60000';
  ```

### Routing

#### `ai_nl2sql_prefer_local`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Prefer local Ollama over cloud APIs
- **Runtime**: Yes
- **Example**:
  ```sql
  SET ai_nl2sql_prefer_local='false';
  ```

## Data Structures

### NL2SQLRequest

```cpp
struct NL2SQLRequest {
    std::string natural_language;           // Natural language query text
    std::string schema_name;                 // Current database/schema name
    int max_latency_ms;                      // Max acceptable latency (ms)
    bool allow_cache;                        // Enable semantic cache lookup
    std::vector<std::string> context_tables; // Optional table hints for schema

    NL2SQLRequest() : max_latency_ms(0), allow_cache(true) {}
};
```

#### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `natural_language` | string | "" | The user's query in natural language |
| `schema_name` | string | "" | Current database/schema name |
| `max_latency_ms` | int | 0 | Max acceptable latency (0 = no constraint) |
| `allow_cache` | bool | true | Whether to check semantic cache |
| `context_tables` | vector<string> | {} | Optional table hints for schema context |

### NL2SQLResult

```cpp
struct NL2SQLResult {
    std::string sql_query;                  // Generated SQL query
    float confidence;                        // Confidence score 0.0-1.0
    std::string explanation;                 // Which model generated this
    std::vector<std::string> tables_used;    // Tables referenced in SQL
    bool cached;                             // True if from semantic cache
    int64_t cache_id;                        // Cache entry ID for tracking

    NL2SQLResult() : confidence(0.0f), cached(false), cache_id(0) {}
};
```

#### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `sql_query` | string | "" | Generated SQL query |
| `confidence` | float | 0.0 | Confidence score (0.0-1.0) |
| `explanation` | string | "" | Model/provider info |
| `tables_used` | vector<string> | {} | Tables referenced in SQL |
| `cached` | bool | false | Whether result came from cache |
| `cache_id` | int64 | 0 | Cache entry ID |

### ModelProvider Enum

```cpp
enum class ModelProvider {
    LOCAL_OLLAMA,      // Local models via Ollama
    CLOUD_OPENAI,      // OpenAI API
    CLOUD_ANTHROPIC,   // Anthropic API
    FALLBACK_ERROR     // No model available
};
```

## NL2SQL_Converter Class

### Constructor

```cpp
NL2SQL_Converter::NL2SQL_Converter();
```

Initializes with default configuration values.

### Destructor

```cpp
NL2SQL_Converter::~NL2SQL_Converter();
```

Frees allocated resources.

### Methods

#### `init()`

```cpp
int NL2SQL_Converter::init();
```

Initialize the NL2SQL converter.

**Returns**: `0` on success, non-zero on failure

#### `close()`

```cpp
void NL2SQL_Converter::close();
```

Shutdown and cleanup resources.

#### `convert()`

```cpp
NL2SQLResult NL2SQL_Converter::convert(const NL2SQLRequest& req);
```

Convert natural language to SQL.

**Parameters**:
- `req`: NL2SQL request with natural language query and context

**Returns**: NL2SQLResult with generated SQL and metadata

**Example**:
```cpp
NL2SQLRequest req;
req.natural_language = "Show top 10 customers";
req.allow_cache = true;
NL2SQLResult result = converter->convert(req);
if (result.confidence > 0.7f) {
    execute_sql(result.sql_query);
}
```

#### `clear_cache()`

```cpp
void NL2SQL_Converter::clear_cache();
```

Clear all cached NL2SQL conversions.

#### `get_cache_stats()`

```cpp
std::string NL2SQL_Converter::get_cache_stats();
```

Get cache statistics as JSON.

**Returns**: JSON string with cache metrics

**Example**:
```json
{
  "entries": 150,
  "hits": 1200,
  "misses": 300
}
```

## AI_Features_Manager Class

### Methods

#### `get_nl2sql()`

```cpp
NL2SQL_Converter* AI_Features_Manager::get_nl2sql();
```

Get the NL2SQL converter instance.

**Returns**: Pointer to NL2SQL_Converter or NULL

**Example**:
```cpp
NL2SQL_Converter* nl2sql = GloAI->get_nl2sql();
if (nl2sql) {
    NL2SQLResult result = nl2sql->convert(req);
}
```

#### `get_variable()`

```cpp
char* AI_Features_Manager::get_variable(const char* name);
```

Get configuration variable value.

**Parameters**:
- `name`: Variable name (without `ai_nl2sql_` prefix)

**Returns**: Variable value or NULL

**Example**:
```cpp
char* model = GloAI->get_variable("ollama_model");
```

#### `set_variable()`

```cpp
bool AI_Features_Manager::set_variable(const char* name, const char* value);
```

Set configuration variable value.

**Parameters**:
- `name`: Variable name (without `ai_nl2sql_` prefix)
- `value`: New value

**Returns**: true on success, false on failure

**Example**:
```cpp
GloAI->set_variable("ollama_model", "llama3.3");
```

## MySQL Protocol Integration

### Query Format

NL2SQL queries use a special prefix:

```sql
NL2SQL: <natural language query>
```

### Result Format

Results are returned as a standard MySQL resultset with columns:

| Column | Type | Description |
|--------|------|-------------|
| `sql_query` | TEXT | Generated SQL query |
| `confidence` | FLOAT | Confidence score |
| `explanation` | TEXT | Model info |
| `cached` | BOOLEAN | From cache |
| `cache_id` | BIGINT | Cache entry ID |

### Example Session

```sql
mysql> USE my_database;
mysql> NL2SQL: Show top 10 customers by revenue;
+---------------------------------------------+------------+-------------------------+--------+----------+
| sql_query                                    | confidence | explanation             | cached | cache_id |
+---------------------------------------------+------------+-------------------------+--------+----------+
| SELECT * FROM customers ORDER BY revenue    |      0.850 | Generated by Ollama    |      0 |        0 |
| DESC LIMIT 10                               |            | llama3.2                |        |          |
+---------------------------------------------+------------+-------------------------+--------+----------+
1 row in set (1.23 sec)
```

## Error Codes

| Code | Description | Action |
|------|-------------|--------|
| `ER_NL2SQL_DISABLED` | NL2SQL feature is disabled | Enable via `ai_nl2sql_enabled` |
| `ER_NL2SQL_TIMEOUT` | LLM request timed out | Increase `ai_nl2sql_timeout_ms` |
| `ER_NL2SQL_NO_MODEL` | No LLM model available | Configure API key or Ollama |
| `ER_NL2SQL_API_ERROR` | LLM API returned error | Check logs and API key |
| `ER_NL2SQL_INVALID_QUERY` | Query doesn't start with prefix | Use correct prefix format |

## Status Variables

Monitor NL2SQL performance via status variables:

```sql
-- View all AI status variables
SELECT * FROM runtime_mysql_servers
WHERE variable_name LIKE 'ai_nl2sql_%';

-- Key metrics
SELECT * FROM stats_ai_nl2sql;
```

| Variable | Description |
|----------|-------------|
| `nl2sql_total_requests` | Total NL2SQL conversions |
| `nl2sql_cache_hits` | Cache hit count |
| `nl2sql_local_model_calls` | Ollama API calls |
| `nl2sql_cloud_model_calls` | Cloud API calls |

## See Also

- [README.md](README.md) - User documentation
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [TESTING.md](TESTING.md) - Testing guide
