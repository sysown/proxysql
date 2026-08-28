# GenAI Features Batch — Design Spec

**Date**: 2026-05-03
**Status**: Approved
**Branch**: `v3.0` (target)
**Scope**: 4 features in a single PR

## Overview

Four GenAI/MCP features that complement each other:
- **C**: GenAI status variables (observability)
- **A**: LLM Bridge semantic cache (cost reduction)
- **D**: RAG incremental sync (production-grade ingestion)
- **E**: Discovery batch persistence (restart resilience)

All work is contained within `plugins/genai/` and `RAG_POC/`. No core ABI changes needed.

---

## Feature C: GenAI Status Variables

### Goal

Expose internal genai/mcp/anomaly counters as SQL-queryable status, so operators can monitor plugin health from the admin interface.

### Current State

Three C++ structs maintain counters that are never exposed via SQL:
- `GenAI_Threads_Handler::status_variables` (4 counters)
- `MCP_Threads_Handler::status_variables` (3 counters)
- `AI_Features_Manager::status_variables` (12 counters)

### Design

#### New admin table: `stats_genai_global`

Registered via `register_runtime_view` with `db_kind=admin_db`. Schema:

```sql
CREATE TABLE stats_genai_global (
    Variable_name VARCHAR NOT NULL,
    Value VARCHAR NOT NULL,
    PRIMARY KEY (Variable_name)
);
```

Refresh callback (`refresh_stats_genai_global`) reads all three structs and produces rows:

| Variable_name | Source Struct |
|---|---|
| `genai_threads_initialized` | GenAI_Threads_Handler::status_variables |
| `genai_active_requests` | GenAI_Threads_Handler::status_variables |
| `genai_completed_requests` | GenAI_Threads_Handler::status_variables |
| `genai_failed_requests` | GenAI_Threads_Handler::status_variables |
| `mcp_total_requests` | MCP_Threads_Handler::status_variables |
| `mcp_failed_requests` | MCP_Threads_Handler::status_variables |
| `mcp_active_connections` | MCP_Threads_Handler::status_variables |
| `llm_total_requests` | AI_Features_Manager::status_variables |
| `llm_cache_hits` | AI_Features_Manager::status_variables |
| `llm_cache_misses` | AI_Features_Manager::status_variables |
| `llm_local_model_calls` | AI_Features_Manager::status_variables |
| `llm_cloud_model_calls` | AI_Features_Manager::status_variables |
| `llm_total_response_time_ms` | AI_Features_Manager::status_variables |
| `llm_cache_total_lookup_time_ms` | AI_Features_Manager::status_variables |
| `llm_cache_total_store_time_ms` | AI_Features_Manager::status_variables |
| `llm_cache_lookups` | AI_Features_Manager::status_variables |
| `llm_cache_stores` | AI_Features_Manager::status_variables |
| `anomaly_total_checks` | AI_Features_Manager::status_variables |
| `anomaly_blocked_queries` | AI_Features_Manager::status_variables |
| `anomaly_flagged_queries` | AI_Features_Manager::status_variables |
| `daily_cloud_spend_usd` | AI_Features_Manager::status_variables |

#### New admin commands

Registered via `register_command` in `plugin_commands.cpp`:

- `SHOW GENAI STATUS` → internally rewrites to `SELECT Variable_name, Value FROM stats_genai_global ORDER BY Variable_name`
- `SHOW MCP STATUS` → internally rewrites to `SELECT Variable_name, Value FROM stats_genai_global WHERE Variable_name LIKE 'mcp_%' ORDER BY Variable_name`

Both commands call the refresh callback before querying.

#### Files changed

- `plugins/genai/src/plugin_tables.cpp` — register `stats_genai_global` runtime view + refresh callback
- `plugins/genai/src/plugin_commands.cpp` — register `SHOW GENAI STATUS` and `SHOW MCP STATUS` commands
- `plugins/genai/include/AI_Features_Manager.h` — add `collect_status_variables()` method returning vector of (name, value) pairs
- `plugins/genai/include/GenAI_Thread.h` — add `collect_status_variables()` method
- `plugins/genai/include/MCP_Thread.h` — add `collect_status_variables()` method

---

## Feature A: LLM Bridge Semantic Cache

### Goal

Complete the 4 TODO stubs in `LLM_Bridge` to make semantic caching functional, reducing LLM API costs for repeated similar queries.

### Current State

- `LLM_Bridge::check_cache()` — returns cache-miss always (empty stub)
- `LLM_Bridge::store_in_cache()` — no-op (empty stub)
- `LLM_Bridge::clear_cache()` — logs "Cache cleared" but does nothing
- `LLM_Bridge::get_cache_stats()` — returns hardcoded zeros

Infrastructure already exists:
- `llm_cache` table with columns: id, prompt, response, system_message, embedding, hit_count, last_hit, created_at
- `llm_cache_vec` virtual table (sqlite-vec `vec0`) with embedding float[1536]
- `LLM_Bridge::get_text_embedding()` — generates embeddings via Ollama
- Config: `genai_llm_cache_similarity_threshold` (default 85) and `genai_llm_cache_enabled` (default true)
- Stats: atomic counters for cache hits/misses/lookups/stores/timing in `AI_Features_Manager`

### Design

#### `check_cache()`

```
1. If !config.cache_enabled or !req.allow_cache: return miss
2. embedding = get_text_embedding(req.prompt)
3. SELECT lc.id, lc.response, lc.hit_count
   FROM llm_cache_vec lcv
   JOIN llm_cache lc ON lc.rowid = lcv.rowid
   WHERE lcv.embedding MATCH ?1 AND k = 1
   ORDER BY distance
4. If distance <= (100 - threshold) / 100.0: hit
   - UPDATE llm_cache SET hit_count = hit_count + 1, last_hit = unixepoch() WHERE id = ?
   - Return cached response
5. Else: miss
```

Distance interpretation: sqlite-vec cosine distance is `1 - similarity`. So similarity ≥ 0.85 means distance ≤ 0.15.

#### `store_in_cache()`

```
1. If !config.cache_enabled: return
2. embedding = get_text_embedding(req.prompt)
3. INSERT INTO llm_cache (prompt, response, system_message, embedding, hit_count, created_at)
   VALUES (?, ?, ?, ?, 0, unixepoch())
4. INSERT INTO llm_cache_vec (rowid, embedding) VALUES (last_insert_rowid(), ?)
```

#### `clear_cache()`

```
1. DELETE FROM llm_cache_vec
2. DELETE FROM llm_cache
3. UPDATE atomic counters in AI_Features_Manager if needed
```

#### `get_cache_stats()`

```
1. SELECT COUNT(*) as entries, COALESCE(SUM(hit_count), 0) as total_hits FROM llm_cache
2. Read llm_cache_hits, llm_cache_misses, llm_cache_lookups, llm_cache_stores from AI_Features_Manager::status_variables
3. Return JSON: { entries, hits, misses, lookups, stores }
```

#### Wire `genai_llm_cache_enabled`

Add `bool cache_enabled` to the `LLM_Bridge::Config` struct. In `GenAI_Thread::update_config()`, read `genai_llm_cache_enabled` and pass it through to `LLM_Bridge::update_config()`.

#### Files changed

- `plugins/genai/src/LLM_Bridge.cpp` — implement 4 methods
- `plugins/genai/include/LLM_Bridge.h` — add `cache_enabled` to Config struct
- `plugins/genai/src/GenAI_Thread.cpp` — wire `genai_llm_cache_enabled` to LLM_Bridge config

---

## Feature D: RAG Incremental Sync

### Goal

Upgrade RAG ingestion from insert-only to full incremental: detect updated rows, re-chunk and re-embed changed documents, soft-delete removed documents.

### Current State

`RAG_POC/rag_ingest.cpp`:
- Watermark-based filtering (only fetch new rows from backend) — **implemented**
- Insert-only with skip-existing — **no updates**
- No hash-based change detection
- No delete detection
- Schema has `updated_at` and `deleted` columns in `rag_documents` but they're unused

### Design

#### Schema change

Add `content_hash VARCHAR(64)` column to `rag_documents`:

```sql
ALTER TABLE rag_documents ADD COLUMN content_hash VARCHAR(64);
```

This is done in `rag_ingest init` (the schema initialization step).

#### Hash computation

For each source row, compute:

```
sha256(concat_values_from_doc_map)
```

Where `concat_values_from_doc_map` is the concatenation of all mapped field values (title, body, metadata) in deterministic order. This produces a stable content fingerprint.

#### Updated ingestion logic

Replace the current `if doc_exists → skip` with:

```
for each source row:
    doc_id = format_doc_id(row)
    content_hash = sha256(concat_mapped_values(row))
    existing = SELECT content_hash FROM rag_documents WHERE doc_id = ?

    if no existing row:
        INSERT document + chunks + FTS index + optional embeddings
    else if existing.content_hash != content_hash:
        // Document changed — update
        UPDATE rag_documents SET deleted = 1, updated_at = unixepoch() WHERE doc_id = ?
        DELETE FROM rag_chunks WHERE doc_id = ?
        DELETE FROM rag_fts_chunks WHERE doc_id = ?  (if exists)
        DELETE FROM rag_vec_chunks WHERE doc_id = ?  (if exists)
        INSERT document with new content_hash + re-chunk + re-embed
    else:
        // Unchanged — skip
        continue
```

#### Delete detection

After processing all rows for a source:

```
// Find documents that exist in rag_documents but were NOT seen in this ingestion batch
seen_doc_ids = set of all doc_ids processed
existing_doc_ids = SELECT doc_id FROM rag_documents WHERE source_id = ? AND deleted = 0

for doc_id in existing_doc_ids - seen_doc_ids:
    UPDATE rag_documents SET deleted = 1, updated_at = unixepoch() WHERE doc_id = ?
    DELETE FROM rag_chunks WHERE doc_id = ?
    DELETE FROM rag_fts_chunks WHERE doc_id = ?
    DELETE FROM rag_vec_chunks WHERE doc_id = ?
```

#### MCP RAG tool compatibility

No changes needed. Existing MCP tools already filter `WHERE deleted = 0` in their queries.

#### Files changed

- `RAG_POC/rag_ingest.cpp` — rewrite ingestion loop, add hash computation, add delete detection
- `RAG_POC/Makefile` — add `-lcrypto` or use built-in sha256 (check availability)

---

## Feature E: Discovery Batch Persistence

### Goal

Persist MCP query digest statistics to SQLite so they survive restarts.

### Current State

`plugins/genai/src/Discovery_Schema.cpp`:
- `update_mcp_query_digest()` accumulates stats in an in-memory `unordered_map`
- TODO stub at line 2998 for batch persistence
- Stats lost on restart

### Design

#### New persistence table

Created during plugin init in the plugin's internal SQLite database:

```sql
CREATE TABLE IF NOT EXISTS mcp_query_digest_persist (
    tool_name VARCHAR NOT NULL,
    run_id INT,
    digest VARCHAR NOT NULL,
    digest_text VARCHAR NOT NULL,
    count_star INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    sum_time INTEGER NOT NULL,
    min_time INTEGER NOT NULL,
    max_time INTEGER NOT NULL,
    PRIMARY KEY(tool_name, run_id, digest)
);
```

#### Periodic flush

Replace the TODO stub (line 2998) with:

```
if (++update_count % 100 == 0):
    flush_digest_to_sqlite()
```

`flush_digest_to_sqlite()`:
```
BEGIN IMMEDIATE;
for each (key, stats) in mcp_digest_umap:
    INSERT OR REPLACE INTO mcp_query_digest_persist
    VALUES (tool_name, run_id, digest, digest_text,
            count_star, first_seen, last_seen, sum_time, min_time, max_time);
COMMIT;
```

#### Startup recovery

On plugin init, after `Discovery_Schema` is constructed:

```
SELECT * FROM mcp_query_digest_persist;
for each row:
    load into mcp_digest_umap in-memory map
```

#### Reset handling

`get_mcp_query_digest(reset=true)` already clears the in-memory map. Add:

```
DELETE FROM mcp_query_digest_persist;
```

#### Files changed

- `plugins/genai/src/Discovery_Schema.cpp` — implement `flush_digest_to_sqlite()`, `load_persisted_digests()`, replace TODO stub
- `plugins/genai/include/Discovery_Schema.h` — declare new methods + SQLite table creation in init

---

## Execution Order

1. **Feature E** (batch persistence) — smallest, isolated
2. **Feature C** (status variables) — independent, pure plugin code
3. **Feature A** (LLM cache) — uses status variables from C
4. **Feature D** (RAG sync) — largest, in RAG_POC

## Testing

- **E**: Unit test that verifies digest stats survive a simulated restart
- **C**: TAP test: `SHOW GENAI STATUS` returns expected rows after MCP traffic
- **A**: Unit test: cache miss → LLM call → cache hit on same query
- **D**: Integration test: ingest → modify source → re-ingest → verify updated + deleted docs

## Files Changed (Summary)

| File | Feature |
|---|---|
| `plugins/genai/src/plugin_tables.cpp` | C |
| `plugins/genai/src/plugin_commands.cpp` | C |
| `plugins/genai/include/AI_Features_Manager.h` | C |
| `plugins/genai/include/GenAI_Thread.h` | C |
| `plugins/genai/include/MCP_Thread.h` | C |
| `plugins/genai/src/LLM_Bridge.cpp` | A |
| `plugins/genai/include/LLM_Bridge.h` | A |
| `plugins/genai/src/GenAI_Thread.cpp` | A |
| `RAG_POC/rag_ingest.cpp` | D |
| `plugins/genai/src/Discovery_Schema.cpp` | E |
| `plugins/genai/include/Discovery_Schema.h` | E |
