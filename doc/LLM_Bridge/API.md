# LLM Bridge API Reference

## Complete API Documentation

This document provides a comprehensive reference for all NL2SQL APIs, including configuration variables, data structures, and methods.

## Table of Contents

- [Configuration Variables](#configuration-variables)
- [Data Structures](#data-structures)
- [LLM_Bridge Class](#nl2sql_converter-class)
- [AI_Features_Manager Class](#ai_features_manager-class)
- [MySQL Protocol Integration](#mysql-protocol-integration)

## Configuration Variables

All LLM variables use the `genai_llm_` prefix and are accessible via the ProxySQL admin interface.

### Master Switch

#### `genai_llm_enabled`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Enable/disable NL2SQL feature
- **Runtime**: Yes
- **Example**:
  ```sql
  SET genai_llm_enabled='true';
  LOAD MYSQL VARIABLES TO RUNTIME;
  ```

### Query Detection

#### `genai_llm_query_prefix`

- **Type**: String
- **Default**: `NL2SQL:`
- **Description**: Prefix that identifies NL2SQL queries
- **Runtime**: Yes
- **Example**:
  ```sql
  SET genai_llm_query_prefix='SQL:';
  -- Now use: SQL: Show customers
  ```

### Model Selection

#### `genai_llm_provider`

- **Type**: Enum (`openai`, `anthropic`)
- **Default**: `openai`
- **Description**: Provider format to use
- **Runtime**: Yes
- **Example**:
  ```sql
  SET genai_llm_provider='openai';
  LOAD MYSQL VARIABLES TO RUNTIME;
  ```

#### `genai_llm_provider_url`

- **Type**: String
- **Default**: `http://localhost:11434/v1/chat/completions`
- **Description**: Endpoint URL
- **Runtime**: Yes
- **Example**:
  ```sql
  -- For OpenAI
  SET genai_llm_provider_url='https://api.openai.com/v1/chat/completions';

  -- For Ollama (via OpenAI-compatible endpoint)
  SET genai_llm_provider_url='http://localhost:11434/v1/chat/completions';

  -- For Anthropic
  SET genai_llm_provider_url='https://api.anthropic.com/v1/messages';
  ```

#### `genai_llm_provider_model`

- **Type**: String
- **Default**: `llama3.2`
- **Description**: Model name
- **Runtime**: Yes
- **Example**:
  ```sql
  SET genai_llm_provider_model='gpt-4o';
  ```

#### `genai_llm_provider_key`

- **Type**: String (sensitive)
- **Default**: NULL
- **Description**: API key (optional for local endpoints)
- **Runtime**: Yes
- **Example**:
  ```sql
  SET genai_llm_provider_key='sk-your-api-key';
  ```

### Cache Configuration

#### `genai_llm_cache_similarity_threshold`

- **Type**: Integer (0-100)
- **Default**: `85`
- **Description**: Minimum similarity score for cache hit
- **Runtime**: Yes
- **Example**:
  ```sql
  SET genai_llm_cache_similarity_threshold='90';
  ```

### Performance

#### `genai_llm_timeout_ms`

- **Type**: Integer
- **Default**: `30000` (30 seconds)
- **Description**: Maximum time to wait for LLM response
- **Runtime**: Yes
- **Example**:
  ```sql
  SET genai_llm_timeout_ms='60000';
  ```

### Routing

#### `genai_llm_prefer_local`

- **Type**: Boolean
- **Default**: `true`
- **Description**: Prefer local Ollama over cloud APIs
- **Runtime**: Yes
- **Example**:
  ```sql
  SET genai_llm_prefer_local='false';
  ```

## Data Structures

### LLM BridgeRequest

```cpp
struct NL2SQLRequest {
    std::string natural_language;           // Natural language query text
    std::string schema_name;                 // Current database/schema name
    int max_latency_ms;                      // Max acceptable latency (ms)
    bool allow_cache;                        // Enable semantic cache lookup
    std::vector<std::string> context_tables; // Optional table hints for schema

    // Request tracking for correlation and debugging
    std::string request_id;                  // Unique ID for this request (UUID-like)

    // Retry configuration for transient failures
    int max_retries;                         // Maximum retry attempts (default: 3)
    int retry_backoff_ms;                    // Initial backoff in ms (default: 1000)
    double retry_multiplier;                 // Backoff multiplier (default: 2.0)
    int retry_max_backoff_ms;                // Maximum backoff in ms (default: 30000)

    NL2SQLRequest() : max_latency_ms(0), allow_cache(true),
                      max_retries(3), retry_backoff_ms(1000),
                      retry_multiplier(2.0), retry_max_backoff_ms(30000) {
        // Generate UUID-like request ID
        char uuid[64];
        snprintf(uuid, sizeof(uuid), "%08lx-%04x-%04x-%04x-%012lx",
                 (unsigned long)rand(), (unsigned)rand() & 0xffff,
                 (unsigned)rand() & 0xffff, (unsigned)rand() & 0xffff,
                 (unsigned long)rand() & 0xffffffffffff);
        request_id = uuid;
    }
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
| `request_id` | string | auto-generated | UUID-like identifier for log correlation |
| `max_retries` | int | 3 | Maximum retry attempts for transient failures |
| `retry_backoff_ms` | int | 1000 | Initial backoff in milliseconds |
| `retry_multiplier` | double | 2.0 | Exponential backoff multiplier |
| `retry_max_backoff_ms` | int | 30000 | Maximum backoff in milliseconds |

### LLM BridgeResult

```cpp
struct NL2SQLResult {
    std::string text_response;                  // Generated SQL query
    float confidence;                        // Confidence score 0.0-1.0
    std::string explanation;                 // Which model generated this
    std::vector<std::string> tables_used;    // Tables referenced in SQL
    bool cached;                             // True if from semantic cache
    int64_t cache_id;                        // Cache entry ID for tracking

    // Error details - populated when conversion fails
    std::string error_code;                  // Structured error code (e.g., "ERR_API_KEY_MISSING")
    std::string error_details;               // Detailed error context with query, schema, provider, URL
    int http_status_code;                    // HTTP status code if applicable (0 if N/A)
    std::string provider_used;               // Which provider was attempted

    NL2SQLResult() : confidence(0.0f), cached(false), cache_id(0), http_status_code(0) {}
};
```

#### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `text_response` | string | "" | Generated SQL query |
| `confidence` | float | 0.0 | Confidence score (0.0-1.0) |
| `explanation` | string | "" | Model/provider info |
| `tables_used` | vector<string> | {} | Tables referenced in SQL |
| `cached` | bool | false | Whether result came from cache |
| `cache_id` | int64 | 0 | Cache entry ID |
| `error_code` | string | "" | Structured error code (if error occurred) |
| `error_details` | string | "" | Detailed error context with query, schema, provider, URL |
| `http_status_code` | int | 0 | HTTP status code if applicable |
| `provider_used` | string | "" | Which provider was attempted (if error occurred) |

### ModelProvider Enum

```cpp
enum class ModelProvider {
    GENERIC_OPENAI,    // Any OpenAI-compatible endpoint (configurable URL)
    GENERIC_ANTHROPIC, // Any Anthropic-compatible endpoint (configurable URL)
    FALLBACK_ERROR     // No model available (error state)
};
```

### LLM BridgeErrorCode Enum

```cpp
enum class NL2SQLErrorCode {
    SUCCESS = 0,                      // No error
    ERR_API_KEY_MISSING,              // API key not configured
    ERR_API_KEY_INVALID,              // API key format is invalid
    ERR_TIMEOUT,                      // Request timed out
    ERR_CONNECTION_FAILED,            // Network connection failed
    ERR_RATE_LIMITED,                 // Rate limited by provider (HTTP 429)
    ERR_SERVER_ERROR,                 // Server error (HTTP 5xx)
    ERR_EMPTY_RESPONSE,               // Empty response from LLM
    ERR_INVALID_RESPONSE,             // Malformed response from LLM
    ERR_SQL_INJECTION_DETECTED,       // SQL injection pattern detected
    ERR_VALIDATION_FAILED,            // Input validation failed
    ERR_UNKNOWN_PROVIDER,             // Invalid provider name
    ERR_REQUEST_TOO_LARGE             // Request exceeds size limit
};
```

**Function:**
```cpp
const char* nl2sql_error_code_to_string(NL2SQLErrorCode code);
```

Converts error code enum to string representation for logging and display purposes.

## LLM Bridge_Converter Class

### Constructor

```cpp
LLM_Bridge::LLM_Bridge();
```

Initializes with default configuration values.

### Destructor

```cpp
LLM_Bridge::~LLM_Bridge();
```

Frees allocated resources.

### Methods

#### `init()`

```cpp
int LLM_Bridge::init();
```

Initialize the NL2SQL converter.

**Returns**: `0` on success, non-zero on failure

#### `close()`

```cpp
void LLM_Bridge::close();
```

Shutdown and cleanup resources.

#### `convert()`

```cpp
NL2SQLResult LLM_Bridge::convert(const NL2SQLRequest& req);
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
    execute_sql(result.text_response);
}
```

#### `clear_cache()`

```cpp
void LLM_Bridge::clear_cache();
```

Clear all cached NL2SQL conversions.

#### `get_cache_stats()`

```cpp
std::string LLM_Bridge::get_cache_stats();
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
LLM_Bridge* AI_Features_Manager::get_nl2sql();
```

Get the NL2SQL converter instance.

**Returns**: Pointer to LLM_Bridge or NULL

**Example**:
```cpp
LLM_Bridge* nl2sql = GloAI->get_nl2sql();
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
- `name`: Variable name (without `genai_llm_` prefix)

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
- `name`: Variable name (without `genai_llm_` prefix)
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
| `text_response` | TEXT | Generated SQL query |
| `confidence` | FLOAT | Confidence score |
| `explanation` | TEXT | Model info |
| `cached` | BOOLEAN | From cache |
| `cache_id` | BIGINT | Cache entry ID |
| `error_code` | TEXT | Structured error code (if error) |
| `error_details` | TEXT | Detailed error context (if error) |
| `http_status_code` | INT | HTTP status code (if applicable) |
| `provider_used` | TEXT | Which provider was attempted (if error) |

### Example Session

```sql
mysql> USE my_database;
mysql> NL2SQL: Show top 10 customers by revenue;
+---------------------------------------------+------------+-------------------------+--------+----------+
| text_response                                    | confidence | explanation             | cached | cache_id |
+---------------------------------------------+------------+-------------------------+--------+----------+
| SELECT * FROM customers ORDER BY revenue    |      0.850 | Generated by Ollama    |      0 |        0 |
| DESC LIMIT 10                               |            | llama3.2                |        |          |
+---------------------------------------------+------------+-------------------------+--------+----------+
1 row in set (1.23 sec)
```

## Error Codes

### Structured Error Codes (NL2SQLErrorCode)

These error codes are returned in the `error_code` field of NL2SQLResult:

| Code | Description | HTTP Status | Action |
|------|-------------|-------------|--------|
| `ERR_API_KEY_MISSING` | API key not configured | N/A | Configure API key via `genai_llm_provider_key` |
| `ERR_API_KEY_INVALID` | API key format is invalid | N/A | Verify API key format |
| `ERR_TIMEOUT` | Request timed out | N/A | Increase `genai_llm_timeout_ms` |
| `ERR_CONNECTION_FAILED` | Network connection failed | 0 | Check network connectivity |
| `ERR_RATE_LIMITED` | Rate limited by provider | 429 | Wait and retry, or use different endpoint |
| `ERR_SERVER_ERROR` | Server error (5xx) | 500-599 | Retry or check provider status |
| `ERR_EMPTY_RESPONSE` | Empty response from LLM | N/A | Check model availability |
| `ERR_INVALID_RESPONSE` | Malformed response from LLM | N/A | Check model compatibility |
| `ERR_SQL_INJECTION_DETECTED` | SQL injection pattern detected | N/A | Review query for safety |
| `ERR_VALIDATION_FAILED` | Input validation failed | N/A | Check input parameters |
| `ERR_UNKNOWN_PROVIDER` | Invalid provider name | N/A | Use `openai` or `anthropic` |
| `ERR_REQUEST_TOO_LARGE` | Request exceeds size limit | 413 | Shorten query or context |

### MySQL Protocol Errors

| Code | Description | Action |
|------|-------------|--------|
| `ER_NL2SQL_DISABLED` | NL2SQL feature is disabled | Enable via `genai_llm_enabled` |
| `ER_NL2SQL_TIMEOUT` | LLM request timed out | Increase `genai_llm_timeout_ms` |
| `ER_NL2SQL_NO_MODEL` | No LLM model available | Configure API key or Ollama |
| `ER_NL2SQL_API_ERROR` | LLM API returned error | Check logs and API key |
| `ER_NL2SQL_INVALID_QUERY` | Query doesn't start with prefix | Use correct prefix format |

## Status Variables

Monitor NL2SQL performance via status variables:

```sql
-- View all AI status variables
SELECT * FROM runtime_mysql_servers
WHERE variable_name LIKE 'genai_llm_%';

-- Key metrics
SELECT * FROM stats_ai_nl2sql;
```

| Variable | Description |
|----------|-------------|
| `nl2sql_total_requests` | Total NL2SQL conversions |
| `llm_cache_hits` | Cache hit count |
| `nl2sql_local_model_calls` | Ollama API calls |
| `nl2sql_cloud_model_calls` | Cloud API calls |

## See Also

- [README.md](README.md) - User documentation
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [TESTING.md](TESTING.md) - Testing guide
