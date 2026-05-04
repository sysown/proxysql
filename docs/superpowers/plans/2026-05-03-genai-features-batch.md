# GenAI Features Batch (C+A+D+E) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 4 GenAI features: status variables (C), LLM semantic cache (A), RAG incremental sync (D), discovery batch persistence (E).

**Architecture:** All work is in `plugins/genai/` and `RAG_POC/`. No core ABI changes. Uses existing `register_runtime_view`, `register_command`, and `register_table` plugin APIs.

**Tech Stack:** C++17, SQLite3, sqlite-vec, libcurl, sha256 (from OpenSSL or libc).

---

## File Map

| File | Feature | Change |
|---|---|---|
| `plugins/genai/include/Discovery_Schema.h` | E | Add `flush_digest_to_sqlite()`, `load_persisted_digests()`, `create_digest_persist_table()` |
| `plugins/genai/src/Discovery_Schema.cpp` | E | Implement flush, load, replace TODO stub at line 2998 |
| `plugins/genai/include/AI_Features_Manager.h` | C | Add `collect_status_variables()` returning `std::vector<std::pair<std::string,std::string>>` |
| `plugins/genai/include/GenAI_Thread.h` | C | Add `collect_status_variables()` |
| `plugins/genai/include/MCP_Thread.h` | C | Add `collect_status_variables()` |
| `plugins/genai/src/AI_Features_Manager.cpp` | C | Implement `collect_status_variables()` |
| `plugins/genai/src/GenAI_Thread.cpp` | C | Implement `collect_status_variables()` |
| `plugins/genai/src/MCP_Thread.cpp` | C | Implement `collect_status_variables()` |
| `plugins/genai/src/plugin_tables.cpp` | C | Register `stats_genai_global` runtime view + refresh callback |
| `plugins/genai/src/plugin_commands.cpp` | C | Register `SHOW GENAI STATUS` and `SHOW MCP STATUS` commands |
| `plugins/genai/include/LLM_Bridge.h` | A | Add `cache_enabled` to config struct, update `update_config()` signature |
| `plugins/genai/src/LLM_Bridge.cpp` | A | Implement `check_cache()`, `store_in_cache()`, `clear_cache()`, `get_cache_stats()` |
| `plugins/genai/src/GenAI_Thread.cpp` | A | Wire `genai_llm_cache_enabled` to `LLM_Bridge::update_config()` |
| `RAG_POC/rag_ingest.cpp` | D | Add content_hash column, hash computation, update detection, delete detection |

---

## Task 1: Discovery Batch Persistence (Feature E)

**Files:**
- Modify: `plugins/genai/include/Discovery_Schema.h`
- Modify: `plugins/genai/src/Discovery_Schema.cpp`

- [ ] **Step 1: Add method declarations to Discovery_Schema.h**

Add after the existing `get_mcp_query_digest()` declaration:

```cpp
void create_digest_persist_table();
void flush_digest_to_sqlite();
void load_persisted_digests();
```

Also add a member: `SQLite3DB* digest_persist_db;` to the class.

- [ ] **Step 2: Implement `create_digest_persist_table()` in Discovery_Schema.cpp**

This method creates the persistence table in the plugin's internal SQLite database. Use the same `vector_db` (or a dedicated DB) that `AI_Features_Manager` provides. For simplicity, store in the same SQLite database used by `llm_cache`:

```cpp
void Discovery_Schema::create_digest_persist_table() {
	if (!vector_db) return;
	const char* ddl =
		"CREATE TABLE IF NOT EXISTS mcp_query_digest_persist ("
		"tool_name VARCHAR NOT NULL,"
		"run_id INTEGER NOT NULL,"
		"digest VARCHAR NOT NULL,"
		"digest_text VARCHAR NOT NULL,"
		"count_star INTEGER NOT NULL,"
		"first_seen INTEGER NOT NULL,"
		"last_seen INTEGER NOT NULL,"
		"sum_time INTEGER NOT NULL,"
		"min_time INTEGER NOT NULL,"
		"max_time INTEGER NOT NULL,"
		"PRIMARY KEY(tool_name, run_id, digest))";
	vector_db->execute(ddl);
}
```

Note: The `vector_db` is the `SQLite3DB*` from `AI_Features_Manager`. If `Discovery_Schema` doesn't have access to it, add a `set_persist_db(SQLite3DB* db)` method and call it from `plugin_main.cpp` during init, passing `GloAI->get_vector_db()`.

- [ ] **Step 3: Implement `flush_digest_to_sqlite()` in Discovery_Schema.cpp**

```cpp
void Discovery_Schema::flush_digest_to_sqlite() {
	if (!digest_persist_db) return;

	pthread_rwlock_rdlock(&mcp_digest_rwlock);

	digest_persist_db->execute("BEGIN IMMEDIATE");
	for (auto const& [key1, inner_map] : mcp_digest_umap) {
		for (auto const& [digest, stats_ptr] : inner_map) {
			MCP_Query_Digest_Stats* stats = (MCP_Query_Digest_Stats*)stats_ptr;
			char* sql = sqlite3_mprintf(
				"INSERT OR REPLACE INTO mcp_query_digest_persist "
				"(tool_name, run_id, digest, digest_text, count_star, "
				"first_seen, last_seen, sum_time, min_time, max_time) "
				"VALUES (%Q, %d, '%llu', %Q, %llu, %ld, %ld, %llu, %llu, %llu)",
				stats->tool_name.c_str(), stats->run_id,
				(unsigned long long)stats->digest, stats->digest_text.c_str(),
				(unsigned long long)stats->count_star,
				(long)stats->first_seen, (long)stats->last_seen,
				(unsigned long long)stats->sum_time,
				(unsigned long long)stats->min_time,
				(unsigned long long)stats->max_time);
			if (sql) {
				digest_persist_db->execute(sql);
				sqlite3_free(sql);
			}
		}
	}
	digest_persist_db->execute("COMMIT");

	pthread_rwlock_unlock(&mcp_digest_rwlock);
}
```

- [ ] **Step 4: Implement `load_persisted_digests()` in Discovery_Schema.cpp**

```cpp
void Discovery_Schema::load_persisted_digests() {
	if (!digest_persist_db) return;

	char* errmsg = NULL;
	sqlite3_stmt* stmt = NULL;
	int rc = sqlite3_prepare_v2(digest_persist_db->get_db(),
		"SELECT tool_name, run_id, digest, digest_text, count_star, "
		"first_seen, last_seen, sum_time, min_time, max_time "
		"FROM mcp_query_digest_persist", -1, &stmt, NULL);
	if (rc != SQLITE_OK) return;

	pthread_rwlock_wrlock(&mcp_digest_rwlock);

	while (sqlite3_step(stmt) == SQLITE_ROW) {
		std::string tool_name = (const char*)sqlite3_column_text(stmt, 0);
		int run_id = sqlite3_column_int(stmt, 1);
		uint64_t digest = (uint64_t)sqlite3_column_int64(stmt, 2);
		std::string digest_text = (const char*)sqlite3_column_text(stmt, 3);

		std::string key = tool_name + "|" + std::to_string(run_id);
		auto& tool_map = mcp_digest_umap[key];

		MCP_Query_Digest_Stats* stats = new MCP_Query_Digest_Stats();
		stats->tool_name = tool_name;
		stats->run_id = run_id;
		stats->digest = digest;
		stats->digest_text = digest_text;
		stats->count_star = (unsigned long long)sqlite3_column_int64(stmt, 4);
		stats->first_seen = (time_t)sqlite3_column_int64(stmt, 5);
		stats->last_seen = (time_t)sqlite3_column_int64(stmt, 6);
		stats->sum_time = (unsigned long long)sqlite3_column_int64(stmt, 7);
		stats->min_time = (unsigned long long)sqlite3_column_int64(stmt, 8);
		stats->max_time = (unsigned long long)sqlite3_column_int64(stmt, 9);

		tool_map[digest] = stats;
	}

	pthread_rwlock_unlock(&mcp_digest_rwlock);
	sqlite3_finalize(stmt);
}
```

- [ ] **Step 5: Replace TODO stub and hook into init/reset**

In `update_mcp_query_digest()`, replace the TODO at line 2998:

```cpp
	if (++update_count % 100 == 0) {
		flush_digest_to_sqlite();
	}
```

In `get_mcp_query_digest(reset=true)`, after clearing the map, add:

```cpp
	if (digest_persist_db) {
		digest_persist_db->execute("DELETE FROM mcp_query_digest_persist");
	}
```

In the plugin init flow (wherever Discovery_Schema is constructed), call:
```cpp
	ds->create_digest_persist_table();
	ds->load_persisted_digests();
```

- [ ] **Step 6: Build and verify**

Run: `PROXYSQL40=1 make -j$(nproc)`
Expected: Clean build, no errors.

- [ ] **Step 7: Commit**

```bash
git add plugins/genai/include/Discovery_Schema.h plugins/genai/src/Discovery_Schema.cpp
git commit -m "feat(genai): persist MCP query digest stats to SQLite (Feature E)"
```

---

## Task 2: Status Variable Collection Methods (Feature C, Part 1)

**Files:**
- Modify: `plugins/genai/include/GenAI_Thread.h`
- Modify: `plugins/genai/src/GenAI_Thread.cpp`
- Modify: `plugins/genai/include/MCP_Thread.h`
- Modify: `plugins/genai/src/MCP_Thread.cpp`
- Modify: `plugins/genai/include/AI_Features_Manager.h`
- Modify: `plugins/genai/src/AI_Features_Manager.cpp`

- [ ] **Step 1: Add `collect_status_variables()` to GenAI_Threads_Handler**

In `plugins/genai/include/GenAI_Thread.h`, add public method:

```cpp
std::vector<std::pair<std::string, std::string>> collect_status_variables();
```

In `plugins/genai/src/GenAI_Thread.cpp`, implement:

```cpp
std::vector<std::pair<std::string, std::string>> GenAI_Threads_Handler::collect_status_variables() {
	std::vector<std::pair<std::string, std::string>> vars;
	vars.push_back({"genai_threads_initialized", std::to_string(status_variables.threads_initialized)});
	vars.push_back({"genai_active_requests", std::to_string(status_variables.active_requests)});
	vars.push_back({"genai_completed_requests", std::to_string(status_variables.completed_requests)});
	vars.push_back({"genai_failed_requests", std::to_string(status_variables.failed_requests)});
	return vars;
}
```

- [ ] **Step 2: Add `collect_status_variables()` to MCP_Threads_Handler**

In `plugins/genai/include/MCP_Thread.h`, add public method:

```cpp
std::vector<std::pair<std::string, std::string>> collect_status_variables();
```

In `plugins/genai/src/MCP_Thread.cpp`, implement:

```cpp
std::vector<std::pair<std::string, std::string>> MCP_Threads_Handler::collect_status_variables() {
	std::vector<std::pair<std::string, std::string>> vars;
	vars.push_back({"mcp_total_requests", std::to_string(status_variables.total_requests)});
	vars.push_back({"mcp_failed_requests", std::to_string(status_variables.failed_requests)});
	vars.push_back({"mcp_active_connections", std::to_string(status_variables.active_connections)});
	return vars;
}
```

- [ ] **Step 3: Add `collect_status_variables()` to AI_Features_Manager**

In `plugins/genai/include/AI_Features_Manager.h`, add public method:

```cpp
std::vector<std::pair<std::string, std::string>> collect_status_variables();
```

In `plugins/genai/src/AI_Features_Manager.cpp`, implement:

```cpp
std::vector<std::pair<std::string, std::string>> AI_Features_Manager::collect_status_variables() {
	std::vector<std::pair<std::string, std::string>> vars;
	vars.push_back({"llm_total_requests", std::to_string(status_variables.llm_total_requests)});
	vars.push_back({"llm_cache_hits", std::to_string(status_variables.llm_cache_hits)});
	vars.push_back({"llm_cache_misses", std::to_string(status_variables.llm_cache_misses)});
	vars.push_back({"llm_local_model_calls", std::to_string(status_variables.llm_local_model_calls)});
	vars.push_back({"llm_cloud_model_calls", std::to_string(status_variables.llm_cloud_model_calls)});
	vars.push_back({"llm_total_response_time_ms", std::to_string(status_variables.llm_total_response_time_ms)});
	vars.push_back({"llm_cache_total_lookup_time_ms", std::to_string(status_variables.llm_cache_total_lookup_time_ms)});
	vars.push_back({"llm_cache_total_store_time_ms", std::to_string(status_variables.llm_cache_total_store_time_ms)});
	vars.push_back({"llm_cache_lookups", std::to_string(status_variables.llm_cache_lookups)});
	vars.push_back({"llm_cache_stores", std::to_string(status_variables.llm_cache_stores)});
	vars.push_back({"anomaly_total_checks", std::to_string(status_variables.anomaly_total_checks)});
	vars.push_back({"anomaly_blocked_queries", std::to_string(status_variables.anomaly_blocked_queries)});
	vars.push_back({"anomaly_flagged_queries", std::to_string(status_variables.anomaly_flagged_queries)});
	vars.push_back({"daily_cloud_spend_usd", std::to_string(status_variables.daily_cloud_spend_usd)});
	return vars;
}
```

- [ ] **Step 4: Build**

Run: `PROXYSQL40=1 make -j$(nproc)`
Expected: Clean build.

- [ ] **Step 5: Commit**

```bash
git add plugins/genai/include/GenAI_Thread.h plugins/genai/src/GenAI_Thread.cpp \
        plugins/genai/include/MCP_Thread.h plugins/genai/src/MCP_Thread.cpp \
        plugins/genai/include/AI_Features_Manager.h plugins/genai/src/AI_Features_Manager.cpp
git commit -m "feat(genai): add collect_status_variables() to genai/mcp/ai handlers (Feature C)"
```

---

## Task 3: Status Variables Table + Commands (Feature C, Part 2)

**Files:**
- Modify: `plugins/genai/src/plugin_tables.cpp`
- Modify: `plugins/genai/src/plugin_commands.cpp`

- [ ] **Step 1: Add stats_genai_global DDL and refresh callback to plugin_tables.cpp**

Add a DDL constant (following the pattern of `kStatsMCPQueryDigest` at line 75):

```cpp
static constexpr const char* kStatsGenaiGlobal =
	"CREATE TABLE stats_genai_global ("
	"Variable_name VARCHAR NOT NULL, "
	"Value VARCHAR NOT NULL, "
	"PRIMARY KEY (Variable_name))";
```

Add a refresh callback that reads all three handler structs. This needs access to `GloGATH`, `GloMCPH`, and `GloAI` globals. Follow the same pattern as the existing `refresh_stats_mcp_query_digest` callback:

```cpp
static int refresh_stats_genai_global(ProxySQL_PluginServices* services,
                                       const char* table_name,
                                       SQLite3_result** result,
                                       void* context) {
	*result = new SQLite3_result(2);
	(*result)->add_column_definition(SQLITE_TEXT, "Variable_name");
	(*result)->add_column_definition(SQLITE_TEXT, "Value");

	// Collect from all three handlers
	std::vector<std::pair<std::string, std::string>> all_vars;

	if (GloGATH) {
		auto vars = GloGATH->collect_status_variables();
		all_vars.insert(all_vars.end(), vars.begin(), vars.end());
	}
	// GloMCPH: get from genai_context().mcp (see plugin_main.cpp)
	extern GenAIPluginContext& genai_context();
	if (genai_context().mcp) {
		auto vars = genai_context().mcp->collect_status_variables();
		all_vars.insert(all_vars.end(), vars.begin(), vars.end());
	}
	if (GloAI) {
		auto vars = GloAI->collect_status_variables();
		all_vars.insert(all_vars.end(), vars.begin(), vars.end());
	}

	for (auto& [name, value] : all_vars) {
		char** pta = (char**)malloc(sizeof(char*) * 2);
		pta[0] = strdup(name.c_str());
		pta[1] = strdup(value.c_str());
		(*result)->add_row(pta);
		for (int j = 0; j < 2; j++) free(pta[j]);
		free(pta);
	}

	return 0;
}
```

Register in `genai_register_stats_tables()`:

```cpp
register_stats(services, "stats_genai_global", kStatsGenaiGlobal);
services->register_runtime_view("stats_genai_global",
	refresh_stats_genai_global, nullptr, ProxySQL_PluginDBKind::admin_db);
```

- [ ] **Step 2: Add SHOW GENAI STATUS and SHOW MCP STATUS commands to plugin_commands.cpp**

Follow the existing pattern for `LOAD MCP VARIABLES TO RUNTIME` (line 454). Add after the existing command registrations:

```cpp
// SHOW GENAI STATUS
{
	const char* cmd = "SHOW GENAI STATUS";
	services->register_command(cmd, [](ProxySQL_PluginServices* srv, char** err,
	                                       const char* sql) -> int {
		// The admin handler will rewrite this query
		// For now, we use a simple approach: the command handler
		// triggers a refresh of stats_genai_global and the admin
		// rewriter in core handles the rest.
		//
		// Actually, we register this as a command so the admin
		// interface recognizes it. The actual rewrite happens via
		// the query hook or admin handler.
		//
		// Simplest approach: register the command, and in the
		// handler return 0 (success). The admin interface already
		// knows how to handle "SHOW" commands by looking at tables.
		return 0;
	});
}

// SHOW MCP STATUS
{
	const char* cmd = "SHOW MCP STATUS";
	services->register_command(cmd, [](ProxySQL_PluginServices* srv,
	                                       char** err, const char* sql) -> int {
		return 0;
	});
}
```

**Important**: The SHOW commands need admin-side rewriting (like `SHOW MYSQL STATUS` rewrites to `SELECT ... FROM stats_mysql_global`). This rewriting happens in `Admin_Handler.cpp` in core. Since we're not modifying core, we need to check if the admin handler already has a generic SHOW→SELECT rewriter for plugin tables, or if we need to add one.

**Alternative approach**: Instead of SHOW commands, just register the `stats_genai_global` table as an admin table. Users query it with `SELECT * FROM stats_genai_global`. This avoids needing core changes. We can add SHOW commands later as a convenience.

For this PR, use the table-only approach. Remove the SHOW command registration — just register the runtime view.

- [ ] **Step 3: Build and test**

Run: `PROXYSQL40=1 make -j$(nproc)`
Expected: Clean build.

Verify: Connect to admin (6032), run `SELECT * FROM stats_genai_global;`. Should return ~22 rows with counter names and values.

- [ ] **Step 4: Commit**

```bash
git add plugins/genai/src/plugin_tables.cpp
git commit -m "feat(genai): register stats_genai_global status table (Feature C)"
```

---

## Task 4: LLM Bridge — Wire cache_enabled (Feature A, Part 1)

**Files:**
- Modify: `plugins/genai/include/LLM_Bridge.h`
- Modify: `plugins/genai/src/LLM_Bridge.cpp`
- Modify: `plugins/genai/src/GenAI_Thread.cpp`

- [ ] **Step 1: Add `cache_enabled` to LLM_Bridge config struct**

In `plugins/genai/include/LLM_Bridge.h`, add to the config struct (line 196-204):

```cpp
struct {
	bool enabled;
	bool cache_enabled;             // NEW
	char* provider;
	char* provider_url;
	char* provider_model;
	char* provider_key;
	int cache_similarity_threshold;
	int timeout_ms;
} config;
```

Update `update_config()` signature (line 283):

```cpp
void update_config(const char* provider, const char* provider_url, const char* provider_model,
                   const char* provider_key, int cache_threshold, int timeout, bool cache_enabled);
```

Initialize `cache_enabled = true` in the constructor.

- [ ] **Step 2: Update GenAI_Thread to pass cache_enabled**

In `plugins/genai/src/GenAI_Thread.cpp`, find where `llm_bridge->update_config()` is called. Add `genai_llm_cache_enabled` as the last argument:

```cpp
llm_bridge->update_config(
	vars->llm_provider, vars->llm_provider_url, vars->llm_provider_model,
	vars->llm_provider_key, vars->llm_cache_similarity_threshold,
	vars->llm_timeout_ms, vars->llm_cache_enabled);
```

- [ ] **Step 3: Build**

Run: `PROXYSQL40=1 make -j$(nproc)`
Expected: Clean build.

- [ ] **Step 4: Commit**

```bash
git add plugins/genai/include/LLM_Bridge.h plugins/genai/src/LLM_Bridge.cpp plugins/genai/src/GenAI_Thread.cpp
git commit -m "feat(genai): wire genai_llm_cache_enabled to LLM_Bridge config (Feature A)"
```

---

## Task 5: LLM Bridge — Implement check_cache() (Feature A, Part 2)

**Files:**
- Modify: `plugins/genai/src/LLM_Bridge.cpp`

- [ ] **Step 1: Implement check_cache()**

Replace the TODO stub at line 164-185 with:

```cpp
LLMResult LLM_Bridge::check_cache(const LLMRequest& req) {
	LLMResult result;
	result.cached = false;
	result.cache_hit = false;

	if (!config.cache_enabled || !vector_db || !req.allow_cache) {
		return result;
	}

	auto start_time = std::chrono::high_resolution_clock::now();

	std::vector<float> embedding = get_text_embedding(req.prompt);
	if (embedding.empty()) {
		return result;
	}

	// Serialize embedding as blob for sqlite-vec KNN search
	size_t blob_size = embedding.size() * sizeof(float);
	std::string emb_blob(reinterpret_cast<const char*>(embedding.data()), blob_size);

	sqlite3* db = vector_db->get_db();
	sqlite3_stmt* stmt = nullptr;

	// KNN search: find the closest cached prompt
	int rc = sqlite3_prepare_v2(db,
		"SELECT lc.id, lc.response, lc.hit_count, lcv.distance "
		"FROM llm_cache_vec lcv "
		"JOIN llm_cache lc ON lc.rowid = lcv.rowid "
		"WHERE lcv.embedding MATCH ?1 AND k = 1 "
		"ORDER BY lcv.distance",
		-1, &stmt, nullptr);

	if (rc != SQLITE_OK) {
		auto end_time = std::chrono::high_resolution_clock::now();
		result.cache_lookup_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
		return result;
	}

	// Bind the embedding blob as parameter
	sqlite3_bind_blob(stmt, 1, emb_blob.data(), emb_blob.size(), SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		int64_t cache_id = sqlite3_column_int64(stmt, 0);
		const char* response_text = (const char*)sqlite3_column_text(stmt, 1);
		int hit_count = sqlite3_column_int(stmt, 2);
		double distance = sqlite3_column_double(stmt, 3);

		// cosine distance: 0 = identical, 2 = opposite
		// similarity = 1 - distance; threshold is 0-100 (e.g. 85 = 0.85 similarity)
		double similarity = 1.0 - distance;
		double threshold = config.cache_similarity_threshold / 100.0;

		if (similarity >= threshold) {
			result.cached = true;
			result.cache_hit = true;
			result.cache_id = cache_id;
			if (response_text) result.text_response = response_text;

			// Update hit stats
			char* update_sql = sqlite3_mprintf(
				"UPDATE llm_cache SET hit_count = hit_count + 1, last_hit = unixepoch() WHERE id = %lld",
				(long long)cache_id);
			if (update_sql) {
				sqlite3_exec(db, update_sql, nullptr, nullptr, nullptr);
				sqlite3_free(update_sql);
			}

			if (GloAI) {
				GloAI->increment_llm_cache_hits();
			}
		} else {
			if (GloAI) {
				GloAI->increment_llm_cache_misses();
			}
		}
	}

	sqlite3_finalize(stmt);

	auto end_time = std::chrono::high_resolution_clock::now();
	result.cache_lookup_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

	if (GloAI) {
		GloAI->increment_llm_cache_lookups();
		GloAI->add_llm_cache_lookup_time_ms(result.cache_lookup_time_ms);
	}

	return result;
}
```

- [ ] **Step 2: Build**

Run: `PROXYSQL40=1 make -j$(nproc)`

- [ ] **Step 3: Commit**

```bash
git add plugins/genai/src/LLM_Bridge.cpp
git commit -m "feat(genai): implement LLM Bridge check_cache with vector similarity (Feature A)"
```

---

## Task 6: LLM Bridge — Implement store_in_cache() (Feature A, Part 3)

**Files:**
- Modify: `plugins/genai/src/LLM_Bridge.cpp`

- [ ] **Step 1: Implement store_in_cache()**

Replace the TODO stub at line 190-204 with:

```cpp
void LLM_Bridge::store_in_cache(const LLMRequest& req, const LLMResult& result) {
	if (!config.cache_enabled || !vector_db || !req.allow_cache) {
		return;
	}
	if (result.text_response.empty()) {
		return;
	}

	auto start_time = std::chrono::high_resolution_clock::now();

	std::vector<float> embedding = get_text_embedding(req.prompt);
	if (embedding.empty()) {
		return;
	}

	sqlite3* db = vector_db->get_db();

	// Insert into llm_cache
	char* insert_sql = sqlite3_mprintf(
		"INSERT INTO llm_cache (prompt, response, system_message, embedding, hit_count, created_at) "
		"VALUES (%Q, %Q, %Q, ?, 0, unixepoch())",
		req.prompt.c_str(), result.text_response.c_str(),
		req.system_message.c_str());

	if (!insert_sql) return;

	sqlite3_stmt* stmt = nullptr;
	int rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
	sqlite3_free(insert_sql);

	if (rc != SQLITE_OK) return;

	// Bind embedding blob
	size_t blob_size = embedding.size() * sizeof(float);
	std::string emb_blob(reinterpret_cast<const char*>(embedding.data()), blob_size);
	sqlite3_bind_blob(stmt, sqlite3_bind_parameter_index(stmt, "?1"),
	                  emb_blob.data(), emb_blob.size(), SQLITE_STATIC);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		sqlite3_finalize(stmt);
		return;
	}
	sqlite3_finalize(stmt);

	sqlite3_int64 rowid = sqlite3_last_insert_rowid(db);

	// Insert into llm_cache_vec
	const char* vec_sql = "INSERT INTO llm_cache_vec (rowid, embedding) VALUES (?, ?)";
	rc = sqlite3_prepare_v2(db, vec_sql, -1, &stmt, nullptr);
	if (rc != SQLITE_OK) return;

	sqlite3_bind_int64(stmt, 1, rowid);
	sqlite3_bind_blob(stmt, 2, emb_blob.data(), emb_blob.size(), SQLITE_STATIC);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	auto end_time = std::chrono::high_resolution_clock::now();
	const_cast<LLMResult&>(result).cache_store_time_ms =
		std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

	if (GloAI) {
		GloAI->increment_llm_cache_stores();
		GloAI->add_llm_cache_store_time_ms(result.cache_store_time_ms);
	}
}
```

- [ ] **Step 2: Build**

Run: `PROXYSQL40=1 make -j$(nproc)`

- [ ] **Step 3: Commit**

```bash
git add plugins/genai/src/LLM_Bridge.cpp
git commit -m "feat(genai): implement LLM Bridge store_in_cache (Feature A)"
```

---

## Task 7: LLM Bridge — Implement clear_cache() + get_cache_stats() (Feature A, Part 4)

**Files:**
- Modify: `plugins/genai/src/LLM_Bridge.cpp`

- [ ] **Step 1: Implement clear_cache()**

Replace the TODO stub at line 355-364 with:

```cpp
void LLM_Bridge::clear_cache() {
	if (!vector_db) {
		return;
	}

	vector_db->execute("DELETE FROM llm_cache_vec");
	vector_db->execute("DELETE FROM llm_cache");

	proxy_info("LLM_Bridge: Cache cleared\n");
}
```

- [ ] **Step 2: Implement get_cache_stats()**

Replace the TODO stub at line 369-379 with:

```cpp
std::string LLM_Bridge::get_cache_stats() {
	json stats;
	stats["entries"] = 0;
	stats["hits"] = 0;
	stats["misses"] = 0;

	if (!vector_db) {
		return stats.dump();
	}

	sqlite3* db = vector_db->get_db();
	sqlite3_stmt* stmt = nullptr;

	int rc = sqlite3_prepare_v2(db,
		"SELECT COUNT(*), COALESCE(SUM(hit_count), 0) FROM llm_cache",
		-1, &stmt, nullptr);

	if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
		stats["entries"] = sqlite3_column_int(stmt, 0);
		stats["hits"] = sqlite3_column_int(stmt, 1);
	}

	sqlite3_finalize(stmt);

	if (GloAI) {
		stats["misses"] = GloAI->get_status_variable_llm_cache_misses();
		stats["lookups"] = GloAI->get_status_variable_llm_cache_lookups();
		stats["stores"] = GloAI->get_status_variable_llm_cache_stores();
	}

	return stats.dump();
}
```

Note: This requires adding getter methods to `AI_Features_Manager` for individual status variables, or making `status_variables` accessible. The simplest approach is to add `get_status_variable_llm_cache_misses()` etc. that return the atomic value. Alternatively, just read from the `collect_status_variables()` result added in Task 2.

- [ ] **Step 3: Build**

Run: `PROXYSQL40=1 make -j$(nproc)`

- [ ] **Step 4: Commit**

```bash
git add plugins/genai/src/LLM_Bridge.cpp
git commit -m "feat(genai): implement LLM Bridge clear_cache and get_cache_stats (Feature A)"
```

---

## Task 8: RAG — Add content_hash Column (Feature D, Part 1)

**Files:**
- Modify: `RAG_POC/rag_ingest.cpp`

- [ ] **Step 1: Add content_hash column to rag_documents schema**

In the `init_rag_schema()` function (around line 1841), add the `content_hash` column to the `rag_documents` CREATE TABLE:

```sql
CREATE TABLE IF NOT EXISTS rag_documents (
    doc_id VARCHAR NOT NULL PRIMARY KEY,
    source_id INTEGER NOT NULL,
    source_name VARCHAR,
    pk_json VARCHAR,
    title VARCHAR,
    body TEXT,
    metadata_json TEXT,
    content_hash VARCHAR(64),      -- NEW: SHA-256 of content for change detection
    updated_at INTEGER DEFAULT (unixepoch()),
    deleted INTEGER DEFAULT 0
)
```

Also add a migration for existing databases:

```cpp
// Add content_hash column if it doesn't exist (migration)
db.execute("ALTER TABLE rag_documents ADD COLUMN content_hash VARCHAR(64)");
// Ignore error if column already exists
```

- [ ] **Step 2: Implement SHA-256 hash computation**

Add a helper function near the top of `rag_ingest.cpp`:

```cpp
#include <openssl/sha.h>

static std::string compute_content_hash(const std::string& input) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

	char hex[SHA256_DIGEST_LENGTH * 2 + 1];
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		snprintf(hex + i * 2, 3, "%02x", hash[i]);
	}
	return std::string(hex);
}
```

If OpenSSL SHA256 is not available, use a simple fallback (but OpenSSL should be available since ProxySQL already links against it for SSL).

- [ ] **Step 3: Compute hash during document processing**

In the document processing loop, after building the doc fields (title, body, metadata), compute the hash:

```cpp
std::string content_input = doc.title + "|" + doc.body + "|" + doc.metadata_json;
std::string content_hash = compute_content_hash(content_input);
```

- [ ] **Step 4: Build rag_ingest**

Run: `cd RAG_POC && make`
Expected: Clean build.

- [ ] **Step 5: Commit**

```bash
git add RAG_POC/rag_ingest.cpp RAG_POC/Makefile
git commit -m "feat(rag): add content_hash column and SHA-256 computation (Feature D)"
```

---

## Task 9: RAG — Hash-Based Update Detection (Feature D, Part 2)

**Files:**
- Modify: `RAG_POC/rag_ingest.cpp`

- [ ] **Step 1: Replace doc_exists + skip with hash comparison**

Replace the current insert-only logic (around line 1673-1677):

```cpp
// OLD:
if (doc_exists(db, doc.doc_id)) {
    g_logger.trace("Document already exists: " + doc.doc_id + ", skipping");
    continue;
}
```

With:

```cpp
std::string existing_hash;
bool doc_changed = false;

MySQLDB::QueryResult hash_result = db.query(
    "SELECT content_hash FROM rag_documents WHERE doc_id = '" + escape_sql(doc.doc_id) + "'");
if (!hash_result.rows.empty()) {
    existing_hash = hash_result.rows[0][0] ? hash_result.rows[0][0] : "";
    if (existing_hash == content_hash) {
        g_logger.trace("Document unchanged: " + doc.doc_id);
        seen_doc_ids.insert(doc.doc_id);
        continue;
    }
    doc_changed = true;
    g_logger.debug("Document changed: " + doc.doc_id + " (hash mismatch)");
} else {
    g_logger.debug("New document: " + doc.doc_id);
}
```

- [ ] **Step 2: Handle document updates**

When `doc_changed == true`, soft-delete the old document and its chunks, then insert the new version:

```cpp
if (doc_changed) {
    // Soft-delete old document
    db.execute("UPDATE rag_documents SET deleted = 1, updated_at = unixepoch() WHERE doc_id = '"
               + escape_sql(doc.doc_id) + "'");
    // Delete old chunks
    db.execute("DELETE FROM rag_chunks WHERE doc_id = '" + escape_sql(doc.doc_id) + "'");
    // Delete old FTS chunks
    db.execute("DELETE FROM rag_fts_chunks WHERE doc_id = '" + escape_sql(doc.doc_id) + "'");
    // Delete old vector chunks (if embeddings exist)
    db.execute("DELETE FROM rag_vec_chunks WHERE doc_id = '" + escape_sql(doc.doc_id) + "'");
}
```

Then the existing INSERT logic for new documents runs (unchanged), but now also includes `content_hash`:

```cpp
// In the INSERT INTO rag_documents statement, add content_hash:
sql << "INSERT INTO rag_documents(doc_id, source_id, source_name, pk_json, title, body, metadata_json, content_hash) "
    << "VALUES ('";
// ... existing values ...
sql << "', '" << content_hash << "')";
```

- [ ] **Step 3: Track seen doc IDs**

Add a `std::set<std::string> seen_doc_ids` before the ingestion loop. Insert every `doc.doc_id` that gets processed (new or updated).

- [ ] **Step 4: Build and test**

Run: `cd RAG_POC && make`

- [ ] **Step 5: Commit**

```bash
git add RAG_POC/rag_ingest.cpp
git commit -m "feat(rag): hash-based update detection with re-chunk (Feature D)"
```

---

## Task 10: RAG — Delete Detection (Feature D, Part 3)

**Files:**
- Modify: `RAG_POC/rag_ingest.cpp`

- [ ] **Step 1: Add delete detection after ingestion loop**

After the row processing loop completes for a source, add:

```cpp
// Delete detection: find documents that exist but were NOT seen in this batch
MySQLDB::QueryResult existing_docs = db.query(
    "SELECT doc_id FROM rag_documents WHERE source_id = " + std::to_string(source.id) +
    " AND deleted = 0");

int soft_deleted = 0;
for (auto& row : existing_docs.rows) {
    std::string existing_doc_id = row[0] ? row[0] : "";
    if (seen_doc_ids.find(existing_doc_id) == seen_doc_ids.end()) {
        g_logger.debug("Document removed from source: " + existing_doc_id + " (soft deleting)");

        db.execute("UPDATE rag_documents SET deleted = 1, updated_at = unixepoch() "
                   "WHERE doc_id = '" + escape_sql(existing_doc_id) + "'");
        db.execute("DELETE FROM rag_chunks WHERE doc_id = '" + escape_sql(existing_doc_id) + "'");
        db.execute("DELETE FROM rag_fts_chunks WHERE doc_id = '" + escape_sql(existing_doc_id) + "'");
        db.execute("DELETE FROM rag_vec_chunks WHERE doc_id = '" + escape_sql(existing_doc_id) + "'");
        soft_deleted++;
    }
}

if (soft_deleted > 0) {
    g_logger.info("Soft-deleted " + std::to_string(soft_deleted) +
                  " documents no longer in source '" + source.name + "'");
}
```

- [ ] **Step 2: Build**

Run: `cd RAG_POC && make`

- [ ] **Step 3: Commit**

```bash
git add RAG_POC/rag_ingest.cpp
git commit -m "feat(rag): delete detection for removed source documents (Feature D)"
```

---

## Task 11: Final Build Verification

- [ ] **Step 1: Full build**

Run: `PROXYSQL40=1 make -j$(nproc) && cd RAG_POC && make`

- [ ] **Step 2: Run existing unit tests**

Run: `cd test/tap/tests/unit && PROXYSQL40=1 make plugin_runtime_views_unit-t && ./plugin_runtime_views_unit-t`

- [ ] **Step 3: Verify stats_genai_global**

Build proxysql, start it with `plugins = ( "genai" )`, connect to admin on port 6032:

```sql
SELECT * FROM stats_genai_global;
```

Expected: ~22 rows with counter names and values (many will be 0 initially).

- [ ] **Step 4: Commit any remaining fixes**

---

## Self-Review Checklist

- [ ] Spec coverage: All 4 features (C, A, D, E) have tasks
- [ ] No placeholders: Every step has complete code
- [ ] Type consistency: `collect_status_variables()` returns same type across all 3 handlers
- [ ] Thread safety: `flush_digest_to_sqlite()` uses rdlock; `load_persisted_digests()` uses wrlock
- [ ] Error handling: All sqlite3 operations checked for errors
- [ ] `cache_enabled` checked in both `check_cache()` and `store_in_cache()`
- [ ] RAG delete detection uses `seen_doc_ids` set populated in Task 9
