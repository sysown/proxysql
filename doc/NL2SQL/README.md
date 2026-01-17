# NL2SQL - Natural Language to SQL for ProxySQL

## Overview

NL2SQL (Natural Language to SQL) is a ProxySQL feature that converts natural language questions into SQL queries using Large Language Models (LLMs).

## Features

- **Generic Provider Support**: Works with any OpenAI-compatible or Anthropic-compatible endpoint
- **Semantic Caching**: Vector-based cache for similar queries using sqlite-vec
- **Schema Awareness**: Understands your database schema for better conversions
- **Multi-Provider**: Switch between LLM providers seamlessly
- **Security**: Generated SQL is returned for review before execution

**Supported Endpoints:**
- Ollama (via OpenAI-compatible `/v1/chat/completions` endpoint)
- OpenAI
- Anthropic
- vLLM
- LM Studio
- Z.ai
- Any other OpenAI-compatible or Anthropic-compatible endpoint

## Quick Start

### 1. Enable NL2SQL

```sql
-- Via admin interface
SET genai-nl2sql_enabled='true';
LOAD GENAI VARIABLES TO RUNTIME;
```

### 2. Configure LLM Provider

ProxySQL uses a **generic provider configuration** that supports any OpenAI-compatible or Anthropic-compatible endpoint.

**Using Ollama (default):**

Ollama is used via its OpenAI-compatible endpoint:

```sql
SET genai-nl2sql_provider='openai';
SET genai-nl2sql_provider_url='http://localhost:11434/v1/chat/completions';
SET genai-nl2sql_provider_model='llama3.2';
SET genai-nl2sql_provider_key='';  -- Empty for local Ollama
LOAD GENAI VARIABLES TO RUNTIME;
```

**Using OpenAI:**

```sql
SET genai-nl2sql_provider='openai';
SET genai-nl2sql_provider_url='https://api.openai.com/v1/chat/completions';
SET genai-nl2sql_provider_model='gpt-4o-mini';
SET genai-nl2sql_provider_key='sk-...';
LOAD GENAI VARIABLES TO RUNTIME;
```

**Using Anthropic:**

```sql
SET genai-nl2sql_provider='anthropic';
SET genai-nl2sql_provider_url='https://api.anthropic.com/v1/messages';
SET genai-nl2sql_provider_model='claude-3-haiku';
SET genai-nl2sql_provider_key='sk-ant-...';
LOAD GENAI VARIABLES TO RUNTIME;
```

**Using any OpenAI-compatible endpoint:**

This works with **any** OpenAI-compatible API (vLLM, LM Studio, Z.ai, etc.):

```sql
SET genai-nl2sql_provider='openai';
SET genai-nl2sql_provider_url='https://your-endpoint.com/v1/chat/completions';
SET genai-nl2sql_provider_model='your-model-name';
SET genai-nl2sql_provider_key='your-api-key';  -- Empty for local endpoints
LOAD GENAI VARIABLES TO RUNTIME;
```

### 3. Use NL2SQL

```sql
-- Verify NL2SQL is enabled (run this in the Admin interface)
SHOW VARIABLES LIKE 'genai-nl2sql%';

-- Use NL2SQL in your MySQL client (MySQL module, not Admin)
mysql> NL2SQL: Show top 10 customers by revenue;
```

**Important**: NL2SQL queries are executed in the **MySQL module** (your regular SQL client), not in the ProxySQL Admin interface. The Admin interface is only for configuration.

## Configuration

### Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `genai-nl2sql_enabled` | false | Enable/disable NL2SQL |
| `genai-nl2sql_query_prefix` | NL2SQL: | Prefix for NL2SQL queries |
| `genai-nl2sql_provider` | openai | Provider format: `openai` or `anthropic` |
| `genai-nl2sql_provider_url` | http://localhost:11434/v1/chat/completions | Endpoint URL |
| `genai-nl2sql_provider_model` | llama3.2 | Model name |
| `genai-nl2sql_provider_key` | (none) | API key (optional for local endpoints) |
| `genai-nl2sql_cache_similarity_threshold` | 85 | Semantic similarity threshold (0-100) |
| `genai-nl2sql_timeout_ms` | 30000 | LLM request timeout in milliseconds |

### Request Configuration (Advanced)

When using NL2SQL programmatically, you can configure retry behavior:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_retries` | 3 | Maximum retry attempts for transient failures |
| `retry_backoff_ms` | 1000 | Initial backoff in milliseconds |
| `retry_multiplier` | 2.0 | Backoff multiplier for exponential backoff |
| `retry_max_backoff_ms` | 30000 | Maximum backoff in milliseconds |
| `allow_cache` | true | Enable semantic cache lookup |

### Error Handling

NL2SQL provides structured error information to help diagnose issues:

| Error Code | Description | HTTP Status |
|-----------|-------------|-------------|
| `ERR_API_KEY_MISSING` | API key not configured | N/A |
| `ERR_API_KEY_INVALID` | API key format is invalid | N/A |
| `ERR_TIMEOUT` | Request timed out | N/A |
| `ERR_CONNECTION_FAILED` | Network connection failed | 0 |
| `ERR_RATE_LIMITED` | Rate limited by provider | 429 |
| `ERR_SERVER_ERROR` | Server error | 500-599 |
| `ERR_EMPTY_RESPONSE` | Empty response from LLM | N/A |
| `ERR_INVALID_RESPONSE` | Malformed response from LLM | N/A |
| `ERR_SQL_INJECTION_DETECTED` | SQL injection pattern detected | N/A |
| `ERR_VALIDATION_FAILED` | Input validation failed | N/A |
| `ERR_UNKNOWN_PROVIDER` | Invalid provider name | N/A |
| `ERR_REQUEST_TOO_LARGE` | Request exceeds size limit | 413 |

**Result Fields:**
- `error_code`: Structured error code (e.g., "ERR_API_KEY_MISSING")
- `error_details`: Detailed error context with query, schema, provider, URL
- `http_status_code`: HTTP status code if applicable
- `provider_used`: Which provider was attempted

### Request Correlation

Each NL2SQL request generates a unique request ID for log correlation:

```
NL2SQL [a1b2c3d4-e5f6-7890-abcd-ef1234567890]: REQUEST url=http://... model=llama3.2
NL2SQL [a1b2c3d4-e5f6-7890-abcd-ef1234567890]: RESPONSE status=200 duration_ms=1234
```

This allows tracing a single request through all log lines for debugging.

### Model Selection

The system automatically selects the best model based on:

1. **Provider format**: Uses `genai-nl2sql_provider` setting (openai or anthropic)
2. **API key availability**: For cloud endpoints, API key is required
3. **Local endpoints**: API key is optional for local endpoints (localhost, 127.0.0.1)

## Examples

### Basic Queries

```
NL2SQL: Show all users
NL2SQL: Find orders with amount > 100
NL2SQL: Count customers by country
```

### Complex Queries

```
NL2SQL: Show top 5 customers by total order amount
NL2SQL: Find customers who placed orders in the last 30 days
NL2SQL: What is the average order value per month?
```

### Schema-Aware Queries

```
-- Switch to your schema first
USE my_database;
NL2SQL: List all products in the Electronics category
NL2SQL: Find orders that contain specific products
```

### Results

NL2SQL returns a resultset with:

| Column | Type | Description |
|--------|------|-------------|
| `sql_query` | TEXT | Generated SQL query |
| `confidence` | FLOAT | Confidence score (0.0-1.0) |
| `explanation` | TEXT | Which model was used |
| `cached` | BOOLEAN | Whether from semantic cache |
| `cache_id` | BIGINT | Cache entry ID |
| `error_code` | TEXT | Structured error code (if error) |
| `error_details` | TEXT | Detailed error context (if error) |
| `http_status_code` | INT | HTTP status code (if applicable) |
| `provider_used` | TEXT | Which provider was attempted (if error) |

**Example successful response:**
```
+----------------------------------+------------+----------------------+------+----------+
| sql_query                         | confidence | explanation          | cached | cache_id |
+----------------------------------+------------+----------------------+------+----------+
| SELECT * FROM customers ORDER BY |      0.850 | Generated by llama3.2 |      0 |        0 |
| revenue DESC LIMIT 10             |            |                      |        |          |
+----------------------------------+------------+----------------------+------+----------+
```

**Example error response:**
```
+-----------------------------------------------------------------------+
| sql_query                                                             |
+-----------------------------------------------------------------------+
| -- NL2SQL conversion failed: API key not configured for provider      |
|                                                                       |
| error_code: ERR_API_KEY_MISSING                                       |
| error_details: NL2SQL conversion failed:                             |
|   Query: Show top 10 customers                                       |
|   Schema: (none)                                                     |
|   Provider: openai                                                   |
|   URL: https://api.openai.com/v1/chat/completions                    |
|   Error: API key not configured                                      |
|                                                                       |
| http_status_code: 0                                                  |
| provider_used: openai                                                |
+-----------------------------------------------------------------------+
```

## Troubleshooting

### NL2SQL returns empty result

1. Check AI module is initialized:
   ```sql
   SELECT * FROM runtime_mysql_servers WHERE variable_name LIKE 'ai_%';
   ```

2. Verify LLM is accessible:
   ```bash
   # For Ollama
   curl http://localhost:11434/api/tags

   # For cloud APIs, check your API keys
   ```

3. Check logs with request ID:
   ```bash
   # Find all log lines for a specific request
   tail -f proxysql.log | grep "NL2SQL \[a1b2c3d4"
   ```

4. Check error details:
   - Review `error_code` for structured error type
   - Review `error_details` for full context including query, schema, provider, URL
   - Review `http_status_code` for HTTP-level errors (429 = rate limit, 500+ = server error)

### Retry Behavior

NL2SQL automatically retries on transient failures:
- **Rate limiting (HTTP 429)**: Retries with exponential backoff
- **Server errors (500-504)**: Retries with exponential backoff
- **Network errors**: Retries with exponential backoff

**Default retry behavior:**
- Maximum retries: 3
- Initial backoff: 1000ms
- Multiplier: 2.0x
- Maximum backoff: 30000ms

**Log output during retry:**
```
NL2SQL [request-id]: ERROR phase=llm error=Empty response status=0
NL2SQL [request-id]: Retryable error (status=0), retrying in 1000ms (attempt 1/4)
NL2SQL [request-id]: Request succeeded after 1 retries
```

### Poor quality SQL

1. **Try a different model:**
   ```sql
   SET genai-nl2sql_provider_model='gpt-4o';
   LOAD GENAI VARIABLES TO RUNTIME;
   ```

2. **Increase timeout for complex queries:**
   ```sql
   SET genai-nl2sql_timeout_ms=60000;
   LOAD GENAI VARIABLES TO RUNTIME;
   ```

3. **Check confidence score:**
   - High confidence (> 0.7): Generally reliable
   - Medium confidence (0.4-0.7): Review before using
   - Low confidence (< 0.4): May need manual correction

### Cache Issues

```sql
-- Clear cache (Phase 3 feature)
-- TODO: Add cache clearing command

-- Check cache stats
SHOW STATUS LIKE 'genai-nl2sql%';
```

## Performance

| Operation | Typical Latency |
|-----------|-----------------|
| Local Ollama | ~1-2 seconds |
| Cloud API | ~2-5 seconds |
| Cache hit | < 50ms |

**Tips for better performance:**
- Use local Ollama for faster responses
- Enable caching for repeated queries
- Use `genai-nl2sql_timeout_ms` to limit wait time
- Consider pre-warming cache with common queries

## Security

### Important Notes

- NL2SQL queries are **NOT executed automatically**
- Generated SQL is returned for **review first**
- Always validate generated SQL before execution
- Keep API keys secure (use environment variables)

### Best Practices

1. **Review generated SQL**: Always check the output before running
2. **Use read-only accounts**: Test with limited permissions first
3. **Monitor confidence scores**: Low confidence may indicate errors
4. **Keep API keys secure**: Don't commit them to version control
5. **Use caching wisely**: Balance speed vs. data freshness

## API Reference

For complete API documentation, see [API.md](API.md).

## Architecture

For system architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Testing

For testing information, see [TESTING.md](TESTING.md).

## Version History

- **0.2.0** (2025-01-16):
  - Added structured error messages with error codes
  - Added request ID correlation for debugging
  - Added exponential backoff retry for transient failures
  - Added configurable retry parameters
  - Added unit tests for validation functions
- **0.1.0** (2025-01-16): Initial release with Ollama, OpenAI, Anthropic support

## License

This feature is part of ProxySQL and follows the same license.
