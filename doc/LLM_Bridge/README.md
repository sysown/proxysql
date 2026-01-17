# LLM Bridge - Generic LLM Access for ProxySQL

## Overview

LLM Bridge is a ProxySQL feature that provides generic access to Large Language Models (LLMs) through the MySQL protocol. It allows you to send any prompt to an LLM and receive the response as a MySQL resultset.

**Note:** This feature was previously called "NL2SQL" (Natural Language to SQL) but has been converted to a generic LLM bridge. Future NL2SQL functionality will be implemented as a Web UI using external agents (Claude Code + MCP server).

## Features

- **Generic Provider Support**: Works with any OpenAI-compatible or Anthropic-compatible endpoint
- **Semantic Caching**: Vector-based cache for similar prompts using sqlite-vec
- **Multi-Provider**: Switch between LLM providers seamlessly
- **Versatile**: Use LLMs for summarization, code generation, translation, analysis, etc.

**Supported Endpoints:**
- Ollama (via OpenAI-compatible `/v1/chat/completions` endpoint)
- OpenAI
- Anthropic
- vLLM
- LM Studio
- Z.ai
- Any other OpenAI-compatible or Anthropic-compatible endpoint

## Quick Start

### 1. Enable LLM Bridge

```sql
-- Via admin interface
SET genai-llm_enabled='true';
LOAD GENAI VARIABLES TO RUNTIME;
```

### 2. Configure LLM Provider

ProxySQL uses a **generic provider configuration** that supports any OpenAI-compatible or Anthropic-compatible endpoint.

**Using Ollama (default):**

Ollama is used via its OpenAI-compatible endpoint:

```sql
SET genai-llm_provider='openai';
SET genai-llm_provider_url='http://localhost:11434/v1/chat/completions';
SET genai-llm_provider_model='llama3.2';
SET genai-llm_provider_key='';  -- Empty for local Ollama
LOAD GENAI VARIABLES TO RUNTIME;
```

**Using OpenAI:**

```sql
SET genai-llm_provider='openai';
SET genai-llm_provider_url='https://api.openai.com/v1/chat/completions';
SET genai-llm_provider_model='gpt-4';
SET genai-llm_provider_key='sk-...';  -- Your OpenAI API key
LOAD GENAI VARIABLES TO RUNTIME;
```

**Using Anthropic:**

```sql
SET genai-llm_provider='anthropic';
SET genai-llm_provider_url='https://api.anthropic.com/v1/messages';
SET genai-llm_provider_model='claude-3-opus-20240229';
SET genai-llm_provider_key='sk-ant-...';  -- Your Anthropic API key
LOAD GENAI VARIABLES TO RUNTIME;
```

**Using any OpenAI-compatible endpoint:**

This works with **any** OpenAI-compatible API (vLLM, LM Studio, Z.ai, etc.):

```sql
SET genai-llm_provider='openai';
SET genai-llm_provider_url='https://your-endpoint.com/v1/chat/completions';
SET genai-llm_provider_model='your-model-name';
SET genai-llm_provider_key='your-api-key';  -- Empty for local endpoints
LOAD GENAI VARIABLES TO RUNTIME;
```

### 3. Use the LLM Bridge

Once configured, you can send prompts using the `/* LLM: */` prefix:

```sql
-- Summarize text
mysql> /* LLM: */ Summarize the customer feedback from last week

-- Explain SQL queries
mysql> /* LLM: */ Explain this query: SELECT COUNT(*) FROM users WHERE active = 1

-- Generate code
mysql> /* LLM: */ Generate a Python function to validate email addresses

-- Translate text
mysql> /* LLM: */ Translate "Hello world" to Spanish

-- Analyze data
mysql> /* LLM: */ Analyze the following sales data and provide insights
```

**Important**: LLM queries are executed in the **MySQL module** (your regular SQL client), not in the ProxySQL Admin interface. The Admin interface is only for configuration.

## Response Format

The LLM Bridge returns a resultset with the following columns:

| Column | Description |
|--------|-------------|
| `text_response` | The LLM's text response |
| `explanation` | Which model/provider generated the response |
| `cached` | Whether the response was from cache (true/false) |
| `provider` | The provider used (openai/anthropic) |

## Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `genai-llm_enabled` | false | Master enable for LLM bridge |
| `genai-llm_provider` | openai | Provider type (openai/anthropic) |
| `genai-llm_provider_url` | http://localhost:11434/v1/chat/completions | LLM endpoint URL |
| `genai-llm_provider_model` | llama3.2 | Model name |
| `genai-llm_provider_key` | (empty) | API key (optional for local) |
| `genai-llm_cache_enabled` | true | Enable semantic cache |
| `genai-llm_cache_similarity_threshold` | 85 | Cache similarity threshold (0-100) |
| `genai-llm_timeout_ms` | 30000 | Request timeout in milliseconds |

### Request Configuration (Advanced)

When using LLM bridge programmatically, you can configure retry behavior:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_retries` | 3 | Maximum retry attempts for transient failures |
| `retry_backoff_ms` | 1000 | Initial backoff in milliseconds |
| `retry_multiplier` | 2.0 | Backoff multiplier for exponential backoff |
| `retry_max_backoff_ms` | 30000 | Maximum backoff in milliseconds |
| `allow_cache` | true | Enable semantic cache lookup |

### Error Handling

LLM Bridge provides structured error information to help diagnose issues:

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
| `ERR_VALIDATION_FAILED` | Input validation failed | N/A |
| `ERR_UNKNOWN_PROVIDER` | Invalid provider name | N/A |
| `ERR_REQUEST_TOO_LARGE` | Request exceeds size limit | 413 |

**Result Fields:**
- `error_code`: Structured error code (e.g., "ERR_API_KEY_MISSING")
- `error_details`: Detailed error context with query, provider, URL
- `http_status_code`: HTTP status code if applicable
- `provider_used`: Which provider was attempted

### Request Correlation

Each LLM request generates a unique request ID for log correlation:

```
LLM [a1b2c3d4-e5f6-7890-abcd-ef1234567890]: REQUEST url=http://... model=llama3.2
LLM [a1b2c3d4-e5f6-7890-abcd-ef1234567890]: RESPONSE status=200 duration_ms=1234
```

This allows tracing a single request through all log lines for debugging.

## Use Cases

### 1. Text Summarization
```sql
/* LLM: */ Summarize this text: [long text...]
```

### 2. Code Generation
```sql
/* LLM: */ Write a Python function to check if a number is prime
/* LLM: */ Generate a SQL query to find duplicate users
```

### 3. Query Explanation
```sql
/* LLM: */ Explain what this query does: SELECT * FROM orders WHERE status = 'pending'
/* LLM: */ Why is this query slow: SELECT * FROM users JOIN orders ON...
```

### 4. Data Analysis
```sql
/* LLM: */ Analyze this CSV data and identify trends: [data...]
/* LLM: */ What insights can you derive from these sales figures?
```

### 5. Translation
```sql
/* LLM: */ Translate "Good morning" to French, German, and Spanish
/* LLM: */ Convert this SQL query to PostgreSQL dialect
```

### 6. Documentation
```sql
/* LLM: */ Write documentation for this function: [code...]
/* LLM: */ Generate API documentation for the users endpoint
```

### 7. Code Review
```sql
/* LLM: */ Review this code for security issues: [code...]
/* LLM: */ Suggest optimizations for this query
```

## Examples

### Basic Usage

```sql
-- Get a summary
mysql> /* LLM: */ What is machine learning?

-- Generate code
mysql> /* LLM: */ Write a function to calculate fibonacci numbers in JavaScript

-- Explain concepts
mysql> /* LLM: */ Explain the difference between INNER JOIN and LEFT JOIN
```

### Complex Prompts

```sql
-- Multi-step reasoning
mysql> /* LLM: */ Analyze the performance implications of using VARCHAR(255) vs TEXT in MySQL

-- Code with specific requirements
mysql> /* LLM: */ Write a Python script that reads a CSV file, filters rows where amount > 100, and outputs to JSON

-- Technical documentation
mysql> /* LLM: */ Create API documentation for a user registration endpoint with validation rules
```

### Results

LLM Bridge returns a resultset with:

| Column | Type | Description |
|--------|------|-------------|
| `text_response` | TEXT | LLM's text response |
| `explanation` | TEXT | Which model was used |
| `cached` | BOOLEAN | Whether from semantic cache |
| `error_code` | TEXT | Structured error code (if error) |
| `error_details` | TEXT | Detailed error context (if error) |
| `http_status_code` | INT | HTTP status code (if applicable) |
| `provider` | TEXT | Which provider was used |

**Example successful response:**
```
+-------------------------------------------------------------+----------------------+------+----------+
| text_response                                               | explanation          | cached | provider |
+-------------------------------------------------------------+----------------------+------+----------+
| Machine learning is a subset of artificial intelligence   | Generated by llama3.2 |      0 | openai   |
| that enables systems to learn from data...               |                      |        |          |
+-------------------------------------------------------------+----------------------+------+----------+
```

**Example error response:**
```
+-----------------------------------------------------------------------+
| text_response                                                         |
+-----------------------------------------------------------------------+
| -- LLM processing failed                                              |
|                                                                       |
| error_code: ERR_API_KEY_MISSING                                       |
| error_details: LLM processing failed:                                 |
|   Query: What is machine learning?                                     |
|   Provider: openai                                                    |
|   URL: https://api.openai.com/v1/chat/completions                    |
|   Error: API key not configured                                       |
|                                                                       |
| http_status_code: 0                                                  |
| provider_used: openai                                                 |
+-----------------------------------------------------------------------+
```

## Troubleshooting

### LLM Bridge returns empty result

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
   tail -f proxysql.log | grep "LLM \[a1b2c3d4"
   ```

4. Check error details:
   - Review `error_code` for structured error type
   - Review `error_details` for full context including query, provider, URL
   - Review `http_status_code` for HTTP-level errors (429 = rate limit, 500+ = server error)

### Retry Behavior

LLM Bridge automatically retries on transient failures:
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
LLM [request-id]: ERROR phase=llm error=Empty response status=0
LLM [request-id]: Retryable error (status=0), retrying in 1000ms (attempt 1/4)
LLM [request-id]: Request succeeded after 1 retries
```

### Slow Responses

1. **Try a different model:**
   ```sql
   SET genai-llm_provider_model='llama3.2';  -- Faster than GPT-4
   LOAD GENAI VARIABLES TO RUNTIME;
   ```

2. **Use local Ollama for faster responses:**
   ```sql
   SET genai-llm_provider_url='http://localhost:11434/v1/chat/completions';
   LOAD GENAI VARIABLES TO RUNTIME;
   ```

3. **Increase timeout for complex prompts:**
   ```sql
   SET genai-llm_timeout_ms=60000;
   LOAD GENAI VARIABLES TO RUNTIME;
   ```

### Cache Issues

```sql
-- Check cache stats
SHOW STATUS LIKE 'llm_%';

-- Cache is automatically managed based on semantic similarity
-- Adjust similarity threshold if needed
SET genai-llm_cache_similarity_threshold=80;  -- Lower = more matches
LOAD GENAI VARIABLES TO RUNTIME;
```

## Status Variables

Monitor LLM bridge usage:

```sql
SELECT * FROM stats_mysql_global WHERE variable_name LIKE 'llm_%';
```

Available status variables:
- `llm_total_requests` - Total number of LLM requests
- `llm_cache_hits` - Number of cache hits
- `llm_cache_misses` - Number of cache misses
- `llm_local_model_calls` - Calls to local models
- `llm_cloud_model_calls` - Calls to cloud APIs
- `llm_total_response_time_ms` - Total response time
- `llm_cache_total_lookup_time_ms` - Total cache lookup time
- `llm_cache_total_store_time_ms` - Total cache store time

## Performance

| Operation | Typical Latency |
|-----------|-----------------|
| Local Ollama | ~1-2 seconds |
| Cloud API | ~2-5 seconds |
| Cache hit | < 50ms |

**Tips for better performance:**
- Use local Ollama for faster responses
- Enable caching for repeated prompts
- Use `genai-llm_timeout_ms` to limit wait time
- Consider pre-warming cache with common prompts

## Migration from NL2SQL

If you were using the old `/* NL2SQL: */` prefix:

1. Update your queries from `/* NL2SQL: */` to `/* LLM: */`
2. Update configuration variables from `genai-nl2sql_*` to `genai-llm_*`
3. Note that the response format has changed:
   - Removed: `sql_query`, `confidence` columns
   - Added: `text_response`, `provider` columns
4. The `ai_nl2sql_convert` MCP tool is deprecated and will return an error

### Old NL2SQL Usage:
```sql
/* NL2SQL: */ Show top 10 customers by revenue
-- Returns: sql_query, confidence, explanation, cached
```

### New LLM Bridge Usage:
```sql
/* LLM: */ Show top 10 customers by revenue
-- Returns: text_response, explanation, cached, provider
```

For true NL2SQL functionality (schema-aware SQL generation with iteration), consider using external agents that can:
1. Analyze your database schema
2. Iterate on query refinement
3. Validate generated queries
4. Execute and review results

## Security

### Important Notes

- LLM responses are **NOT executed automatically**
- Text responses are returned for review
- Always validate generated code before execution
- Keep API keys secure (use environment variables)

### Best Practices

1. **Review generated code**: Always check output before running
2. **Use read-only accounts**: Test with limited permissions first
3. **Keep API keys secure**: Don't commit them to version control
4. **Use caching wisely**: Balance speed vs. data freshness
5. **Monitor usage**: Check status variables regularly

## API Reference

For complete API documentation, see [API.md](API.md).

## Architecture

For system architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Testing

For testing information, see [TESTING.md](TESTING.md).

## License

This feature is part of ProxySQL and follows the same license.
