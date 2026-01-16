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
SET ai_nl2sql_enabled='true';
LOAD MYSQL VARIABLES TO RUNTIME;
```

### 2. Configure LLM Provider

ProxySQL uses a **generic provider configuration** that supports any OpenAI-compatible or Anthropic-compatible endpoint.

**Using Ollama (default):**

Ollama is used via its OpenAI-compatible endpoint:

```sql
SET ai_nl2sql_provider='openai';
SET ai_nl2sql_provider_url='http://localhost:11434/v1/chat/completions';
SET ai_nl2sql_provider_model='llama3.2';
SET ai_nl2sql_provider_key='';  -- Empty for local Ollama
LOAD MYSQL VARIABLES TO RUNTIME;
```

**Using OpenAI:**

```sql
SET ai_nl2sql_provider='openai';
SET ai_nl2sql_provider_url='https://api.openai.com/v1/chat/completions';
SET ai_nl2sql_provider_model='gpt-4o-mini';
SET ai_nl2sql_provider_key='sk-...';
LOAD MYSQL VARIABLES TO RUNTIME;
```

**Using Anthropic:**

```sql
SET ai_nl2sql_provider='anthropic';
SET ai_nl2sql_provider_url='https://api.anthropic.com/v1/messages';
SET ai_nl2sql_provider_model='claude-3-haiku';
SET ai_nl2sql_provider_key='sk-ant-...';
LOAD MYSQL VARIABLES TO RUNTIME;
```

**Using any OpenAI-compatible endpoint:**

This works with **any** OpenAI-compatible API (vLLM, LM Studio, Z.ai, etc.):

```sql
SET ai_nl2sql_provider='openai';
SET ai_nl2sql_provider_url='https://your-endpoint.com/v1/chat/completions';
SET ai_nl2sql_provider_model='your-model-name';
SET ai_nl2sql_provider_key='your-api-key';  -- Empty for local endpoints
LOAD MYSQL VARIABLES TO RUNTIME;
```

### 3. Use NL2SQL

```sql
-- In your SQL client, prefix your query with "NL2SQL:"
mysql> SELECT * FROM runtime_mysql_servers WHERE variable_name='ai_nl2sql_enabled';

-- Query converted to SQL
mysql> NL2SQL: Show top 10 customers by revenue;
```

## Configuration

### Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ai_nl2sql_enabled` | true | Enable/disable NL2SQL |
| `ai_nl2sql_query_prefix` | NL2SQL: | Prefix for NL2SQL queries |
| `ai_nl2sql_provider` | openai | Provider format: `openai` or `anthropic` |
| `ai_nl2sql_provider_url` | http://localhost:11434/v1/chat/completions | Endpoint URL |
| `ai_nl2sql_provider_model` | llama3.2 | Model name |
| `ai_nl2sql_provider_key` | (none) | API key (optional for local endpoints) |
| `ai_nl2sql_cache_similarity_threshold` | 85 | Semantic similarity threshold (0-100) |
| `ai_nl2sql_timeout_ms` | 30000 | LLM request timeout in milliseconds |
| `ai_nl2sql_prefer_local` | true | Prefer local models when possible |

### Model Selection

The system automatically selects the best model based on:

1. **Provider format**: Uses `ai_nl2sql_provider` setting (openai or anthropic)
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
- `sql_query`: Generated SQL
- `confidence`: 0.0-1.0 score
- `explanation`: Which model was used
- `cached`: Whether from semantic cache

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

3. Check logs:
   ```bash
   tail -f proxysql.log | grep NL2SQL
   ```

### Poor quality SQL

1. **Try a different model:**
   ```sql
   SET ai_nl2sql_provider_model='gpt-4o';
   ```

2. **Increase timeout for complex queries:**
   ```sql
   SET ai_nl2sql_timeout_ms=60000;
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
SELECT * FROM stats_ai_nl2sql_cache;
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
- Use `ai_nl2sql_timeout_ms` to limit wait time
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

- **0.1.0** (2025-01-16): Initial release with Ollama, OpenAI, Anthropic support

## License

This feature is part of ProxySQL and follows the same license.
