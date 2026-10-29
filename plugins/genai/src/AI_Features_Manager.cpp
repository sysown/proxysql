#ifdef PROXYSQL40

#include "AI_Features_Manager.h"
#include "GenAI_Thread.h"
#include "LLM_Bridge.h"
#include "sqlite3db.h"
#include "proxysql_utils.h"
#include <cstring>
#include <cstdlib>
#include <sys/stat.h>
#include <libgen.h>  // for dirname

// Global instance is defined in src/main.cpp
extern AI_Features_Manager *GloAI;

// GenAI module - configuration is now managed here
extern GenAI_Threads_Handler *GloGATH;

// Forward declaration to avoid header ordering issues
class ProxySQL_Admin;
extern ProxySQL_Admin *GloAdmin;

AI_Features_Manager::AI_Features_Manager()
	: shutdown_(0), llm_bridge(NULL), vector_db(NULL)
{
	pthread_rwlock_init(&rwlock, NULL);

	// Initialize status counters
	memset(&status_variables, 0, sizeof(status_variables));

	// Note: Configuration is now managed by GenAI module (GloGATH)
	// All genai-* variables are accessible via GloGATH->get_variable()
}

AI_Features_Manager::~AI_Features_Manager() {
	shutdown();

	// Note: Configuration strings are owned by GenAI module, not freed here
	pthread_rwlock_destroy(&rwlock);
}

int AI_Features_Manager::init_vector_db() {
	proxy_info("AI: Initializing vector storage at %s\n", GloGATH->variables.genai_vector_db_path);

	// Ensure directory exists
	std::string db_path(GloGATH->variables.genai_vector_db_path);
	std::string path_copy = db_path;
	char* dir = dirname(&path_copy[0]);
	struct stat st;
	if (stat(dir, &st) != 0) {
		std::string dir_path(dir);
		for (size_t i = 1; i < dir_path.size(); ++i) {
			if (dir_path[i] != '/') continue;
			dir_path[i] = '\0';
			if (mkdir(dir_path.c_str(), 0700) != 0 && errno != EEXIST) {
				proxy_error("AI: Failed to create directory %s: %s\n", dir_path.c_str(), strerror(errno));
				return -1;
			}
			dir_path[i] = '/';
		}
		if (mkdir(dir_path.c_str(), 0700) != 0 && errno != EEXIST) {
			proxy_error("AI: Failed to create directory %s: %s\n", dir_path.c_str(), strerror(errno));
			return -1;
		}
	}

	vector_db = new SQLite3DB();
	int rc = vector_db->open(&db_path[0], SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	if (rc != SQLITE_OK) {
		proxy_error("AI: Failed to open vector database: %s\n", GloGATH->variables.genai_vector_db_path);
		delete vector_db;
		vector_db = NULL;
		return -1;
	}

	// Enable SQLite extensions for vector_db
	// Once enabled, SQLite loads extensions such as vec0 automatically.
	// Refer - Admin_Bootstrap.cpp:590
	(*proxy_sqlite3_enable_load_extension)(vector_db->get_db(), 1);

	// Create tables for LLM cache
	const char* create_llm_cache =
		"CREATE TABLE IF NOT EXISTS llm_cache ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT , "
		"prompt TEXT NOT NULL , "
		"response TEXT NOT NULL , "
		"system_message TEXT , "
		"embedding BLOB , "
		"hit_count INTEGER DEFAULT 0 , "
		"last_hit INTEGER , "
		"created_at INTEGER DEFAULT (strftime('%s' ,  'now'))"
		");";

	if (!vector_db->execute(create_llm_cache)) {
		proxy_error("AI: Failed to create llm_cache table\n");
		return -1;
	}

	// Create table for anomaly patterns
	const char* create_anomaly_patterns =
		"CREATE TABLE IF NOT EXISTS anomaly_patterns ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT , "
		"pattern_name TEXT , "
		"pattern_type TEXT , "  // 'sql_injection', 'dos', 'privilege_escalation'
		"query_example TEXT , "
		"embedding BLOB , "
		"severity INTEGER , "  // 1-10
		"created_at INTEGER DEFAULT (strftime('%s' ,  'now'))"
		");";

	if (!vector_db->execute(create_anomaly_patterns)) {
		proxy_error("AI: Failed to create anomaly_patterns table\n");
		return -1;
	}

	// Create table for query history
	const char* create_query_history =
		"CREATE TABLE IF NOT EXISTS query_history ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT , "
		"prompt TEXT NOT NULL , "
		"response TEXT , "
		"embedding BLOB , "
		"execution_time_ms INTEGER , "
		"success BOOLEAN , "
		"timestamp INTEGER DEFAULT (strftime('%s' ,  'now'))"
		");";

	if (!vector_db->execute(create_query_history)) {
		proxy_error("AI: Failed to create query_history table\n");
		return -1;
	}

	// Create virtual vector tables for similarity search using sqlite-vec
	// Note: sqlite-vec extension is auto-loaded in Admin_Bootstrap.cpp:612

	// 1. LLM cache virtual table
	const char* create_llm_vec =
		"CREATE VIRTUAL TABLE IF NOT EXISTS llm_cache_vec USING vec0("
		"embedding float[1536]"
		");";

	if (!vector_db->execute(create_llm_vec)) {
		proxy_error("AI: Failed to create llm_cache_vec virtual table\n");
		// Virtual table creation failure is not critical - log and continue
		proxy_debug(PROXY_DEBUG_GENAI, 3, "Continuing without llm_cache_vec");
	}

	// 2. Anomaly patterns virtual table
	const char* create_anomaly_vec =
		"CREATE VIRTUAL TABLE IF NOT EXISTS anomaly_patterns_vec USING vec0("
		"embedding float[1536]"
		");";

	if (!vector_db->execute(create_anomaly_vec)) {
		proxy_error("AI: Failed to create anomaly_patterns_vec virtual table\n");
		proxy_debug(PROXY_DEBUG_GENAI, 3, "Continuing without anomaly_patterns_vec");
	}

	// 3. Query history virtual table
	const char* create_history_vec =
		"CREATE VIRTUAL TABLE IF NOT EXISTS query_history_vec USING vec0("
		"embedding float[1536]"
		");";

	if (!vector_db->execute(create_history_vec)) {
		proxy_error("AI: Failed to create query_history_vec virtual table\n");
		proxy_debug(PROXY_DEBUG_GENAI, 3, "Continuing without query_history_vec");
	}

	// 4. RAG tables for Retrieval-Augmented Generation
	// rag_sources: control plane for ingestion configuration
	const char* create_rag_sources =
		"CREATE TABLE IF NOT EXISTS rag_sources ("
		"source_id INTEGER PRIMARY KEY, "
		"name TEXT NOT NULL UNIQUE, "
		"enabled INTEGER NOT NULL DEFAULT 1, "
		"backend_type TEXT NOT NULL, "
		"backend_host TEXT NOT NULL, "
		"backend_port INTEGER NOT NULL, "
		"backend_user TEXT NOT NULL, "
		"backend_pass TEXT NOT NULL, "
		"backend_db TEXT NOT NULL, "
		"table_name TEXT NOT NULL, "
		"pk_column TEXT NOT NULL, "
		"where_sql TEXT, "
		"doc_map_json TEXT NOT NULL, "
		"chunking_json TEXT NOT NULL, "
		"embedding_json TEXT, "
		"created_at INTEGER NOT NULL DEFAULT (unixepoch()), "
		"updated_at INTEGER NOT NULL DEFAULT (unixepoch())"
		");";

	if (!vector_db->execute(create_rag_sources)) {
		proxy_error("AI: Failed to create rag_sources table\n");
		return -1;
	}

	// Indexes for rag_sources
	const char* create_rag_sources_enabled_idx =
		"CREATE INDEX IF NOT EXISTS idx_rag_sources_enabled ON rag_sources(enabled);";

	if (!vector_db->execute(create_rag_sources_enabled_idx)) {
		proxy_error("AI: Failed to create idx_rag_sources_enabled index\n");
		return -1;
	}

	const char* create_rag_sources_backend_idx =
		"CREATE INDEX IF NOT EXISTS idx_rag_sources_backend ON rag_sources(backend_type, backend_host, backend_port, backend_db, table_name);";

	if (!vector_db->execute(create_rag_sources_backend_idx)) {
		proxy_error("AI: Failed to create idx_rag_sources_backend index\n");
		return -1;
	}

	// rag_documents: canonical documents
	const char* create_rag_documents =
		"CREATE TABLE IF NOT EXISTS rag_documents ("
		"doc_id TEXT PRIMARY KEY, "
		"source_id INTEGER NOT NULL REFERENCES rag_sources(source_id), "
		"source_name TEXT NOT NULL, "
		"pk_json TEXT NOT NULL, "
		"title TEXT, "
		"body TEXT, "
		"metadata_json TEXT NOT NULL DEFAULT '{}', "
		"updated_at INTEGER NOT NULL DEFAULT (unixepoch()), "
		"deleted INTEGER NOT NULL DEFAULT 0"
		");";

	if (!vector_db->execute(create_rag_documents)) {
		proxy_error("AI: Failed to create rag_documents table\n");
		return -1;
	}

	// Indexes for rag_documents
	const char* create_rag_documents_source_updated_idx =
		"CREATE INDEX IF NOT EXISTS idx_rag_documents_source_updated ON rag_documents(source_id, updated_at);";

	if (!vector_db->execute(create_rag_documents_source_updated_idx)) {
		proxy_error("AI: Failed to create idx_rag_documents_source_updated index\n");
		return -1;
	}

	const char* create_rag_documents_source_deleted_idx =
		"CREATE INDEX IF NOT EXISTS idx_rag_documents_source_deleted ON rag_documents(source_id, deleted);";

	if (!vector_db->execute(create_rag_documents_source_deleted_idx)) {
		proxy_error("AI: Failed to create idx_rag_documents_source_deleted index\n");
		return -1;
	}

	// rag_chunks: chunked content
	const char* create_rag_chunks =
		"CREATE TABLE IF NOT EXISTS rag_chunks ("
		"chunk_id TEXT PRIMARY KEY, "
		"doc_id TEXT NOT NULL REFERENCES rag_documents(doc_id), "
		"source_id INTEGER NOT NULL REFERENCES rag_sources(source_id), "
		"chunk_index INTEGER NOT NULL, "
		"title TEXT, "
		"body TEXT NOT NULL, "
		"metadata_json TEXT NOT NULL DEFAULT '{}', "
		"updated_at INTEGER NOT NULL DEFAULT (unixepoch()), "
		"deleted INTEGER NOT NULL DEFAULT 0"
		");";

	if (!vector_db->execute(create_rag_chunks)) {
		proxy_error("AI: Failed to create rag_chunks table\n");
		return -1;
	}

	// Indexes for rag_chunks
	const char* create_rag_chunks_doc_idx =
		"CREATE UNIQUE INDEX IF NOT EXISTS uq_rag_chunks_doc_idx ON rag_chunks(doc_id, chunk_index);";

	if (!vector_db->execute(create_rag_chunks_doc_idx)) {
		proxy_error("AI: Failed to create uq_rag_chunks_doc_idx index\n");
		return -1;
	}

	const char* create_rag_chunks_source_doc_idx =
		"CREATE INDEX IF NOT EXISTS idx_rag_chunks_source_doc ON rag_chunks(source_id, doc_id);";

	if (!vector_db->execute(create_rag_chunks_source_doc_idx)) {
		proxy_error("AI: Failed to create idx_rag_chunks_source_doc index\n");
		return -1;
	}

	const char* create_rag_chunks_deleted_idx =
		"CREATE INDEX IF NOT EXISTS idx_rag_chunks_deleted ON rag_chunks(deleted);";

	if (!vector_db->execute(create_rag_chunks_deleted_idx)) {
		proxy_error("AI: Failed to create idx_rag_chunks_deleted index\n");
		return -1;
	}

	// rag_fts_chunks: FTS5 index (contentless)
	const char* create_rag_fts_chunks =
		"CREATE VIRTUAL TABLE IF NOT EXISTS rag_fts_chunks USING fts5("
		"chunk_id UNINDEXED, "
		"title, "
		"body, "
		"tokenize = 'unicode61'"
		");";

	if (!vector_db->execute(create_rag_fts_chunks)) {
		proxy_error("AI: Failed to create rag_fts_chunks virtual table\n");
		proxy_debug(PROXY_DEBUG_GENAI, 3, "Continuing without rag_fts_chunks");
	}

	// rag_vec_chunks: sqlite3-vec index
	// Use configurable vector dimension from GenAI module
	int vector_dimension = 1536; // Default value
	if (GloGATH) {
		vector_dimension = GloGATH->variables.genai_vector_dimension;
	}

	std::string create_rag_vec_chunks_sql =
		"CREATE VIRTUAL TABLE IF NOT EXISTS rag_vec_chunks USING vec0("
		"embedding float[" + std::to_string(vector_dimension) + "], "
		"chunk_id TEXT, "
		"doc_id TEXT, "
		"source_id INTEGER, "
		"updated_at INTEGER"
		");";

	const char* create_rag_vec_chunks = create_rag_vec_chunks_sql.c_str();

	if (!vector_db->execute(create_rag_vec_chunks)) {
		proxy_error("AI: Failed to create rag_vec_chunks virtual table\n");
		proxy_debug(PROXY_DEBUG_GENAI, 3, "Continuing without rag_vec_chunks");
	}

	// rag_chunk_view: convenience view for debugging
	const char* create_rag_chunk_view =
		"CREATE VIEW IF NOT EXISTS rag_chunk_view AS "
		"SELECT "
		"c.chunk_id, "
		"c.doc_id, "
		"c.source_id, "
		"d.source_name, "
		"d.pk_json, "
		"COALESCE(c.title, d.title) AS title, "
		"c.body, "
		"d.metadata_json AS doc_metadata_json, "
		"c.metadata_json AS chunk_metadata_json, "
		"c.updated_at "
		"FROM rag_chunks c "
		"JOIN rag_documents d ON d.doc_id = c.doc_id "
		"WHERE c.deleted = 0 AND d.deleted = 0;";

	if (!vector_db->execute(create_rag_chunk_view)) {
		proxy_error("AI: Failed to create rag_chunk_view view\n");
		proxy_debug(PROXY_DEBUG_GENAI, 3, "Continuing without rag_chunk_view");
	}

	// rag_sync_state: sync state placeholder for later incremental ingestion
	const char* create_rag_sync_state =
		"CREATE TABLE IF NOT EXISTS rag_sync_state ("
		"source_id INTEGER PRIMARY KEY REFERENCES rag_sources(source_id), "
		"mode TEXT NOT NULL DEFAULT 'poll', "
		"cursor_json TEXT NOT NULL DEFAULT '{}', "
		"last_ok_at INTEGER, "
		"last_error TEXT"
		");";

	if (!vector_db->execute(create_rag_sync_state)) {
		proxy_error("AI: Failed to create rag_sync_state table\n");
		return -1;
	}

	proxy_info("AI: Vector storage initialized successfully with virtual tables\n");
	return 0;
}

int AI_Features_Manager::init_llm_bridge() {
	if (!GloGATH->variables.genai_llm_enabled) {
		proxy_info("AI: LLM bridge disabled ,  skipping initialization\n");
		return 0;
	}

	proxy_info("AI: Initializing LLM Bridge\n");

	llm_bridge = new LLM_Bridge();

	// Set vector database
	llm_bridge->set_vector_db(vector_db);

	// Update config with current variables from GenAI module
	llm_bridge->update_config(
		GloGATH->variables.genai_llm_provider,
		GloGATH->variables.genai_llm_provider_url,
		GloGATH->variables.genai_llm_provider_model,
		GloGATH->variables.genai_llm_provider_key,
		GloGATH->variables.genai_llm_cache_similarity_threshold,
		GloGATH->variables.genai_llm_timeout_ms,
		GloGATH->variables.genai_llm_cache_enabled
	);

	if (llm_bridge->init() != 0) {
		proxy_error("AI: Failed to initialize LLM Bridge\n");
		delete llm_bridge;
		llm_bridge = NULL;
		return -1;
	}

	proxy_info("AI: LLM Bridge initialized\n");
	return 0;
}

// init_anomaly_detector / close_anomaly_detector were removed in
// Step 3 of the GenAI plugin carve-out: the Anomaly_Detector now lives
// inside plugins/genai/, owned by the plugin's own lifecycle.

void AI_Features_Manager::close_vector_db() {
	if (vector_db) {
		delete vector_db;
		vector_db = NULL;
	}
}

void AI_Features_Manager::close_llm_bridge() {
	if (llm_bridge) {
		llm_bridge->close();
		delete llm_bridge;
		llm_bridge = NULL;
	}
}

int AI_Features_Manager::init() {
	proxy_info("AI: Initializing AI Features Manager v%s\n", AI_FEATURES_MANAGER_VERSION);

	shutdown_ = 0;
	close_llm_bridge();
	close_vector_db();

	if (!GloGATH || !GloGATH->variables.genai_enabled) {
		proxy_info("AI: AI features disabled by configuration\n");
		return 0;
	}

	// Initialize vector storage first (needed by both LLM bridge and Anomaly Detector)
	if (init_vector_db() != 0) {
		proxy_error("AI: Failed to initialize vector storage\n");
		return -1;
	}

	// Initialize LLM bridge
	if (init_llm_bridge() != 0) {
		proxy_error("AI: Failed to initialize LLM bridge\n");
		return -1;
	}

	// Anomaly Detector init moved to the genai plugin in Step 3 of
	// the carve-out; AI_Features_Manager no longer owns it.

	proxy_info("AI: AI Features Manager initialized successfully\n");
	return 0;
}

void AI_Features_Manager::shutdown() {
	if (shutdown_) return;
	shutdown_ = 1;

	proxy_info("AI: Shutting down AI Features Manager\n");

	close_llm_bridge();
	// close_anomaly_detector() removed in Step 3 of the carve-out.
	close_vector_db();

	proxy_info("AI: AI Features Manager shutdown complete\n");
}

void AI_Features_Manager::wrlock() {
	pthread_rwlock_wrlock(&rwlock);
}

void AI_Features_Manager::wrunlock() {
	pthread_rwlock_unlock(&rwlock);
}

// Note: Configuration get/set methods have been removed - they are now
// handled by the GenAI module (GloGATH). Use GloGATH->get_variable()
// and GloGATH->set_variable() for configuration access.

std::string AI_Features_Manager::get_status_json() {
	char buf[2048];
	snprintf(buf, sizeof(buf),
		"{"
		"\"version\": \"%s\" , "
		"\"llm\": {"
		"\"total_requests\": %llu , "
		"\"cache_hits\": %llu , "
		"\"local_calls\": %llu , "
		"\"cloud_calls\": %llu , "
		"\"total_response_time_ms\": %llu , "
		"\"cache_total_lookup_time_ms\": %llu , "
		"\"cache_total_store_time_ms\": %llu , "
		"\"cache_lookups\": %llu , "
		"\"cache_stores\": %llu , "
		"\"cache_misses\": %llu"
		"} , "
		"\"anomaly\": {"
		"\"total_checks\": %llu , "
		"\"blocked\": %llu , "
		"\"flagged\": %llu"
		"} , "
		"\"spend\": {"
		"\"daily_usd\": %.2f"
		"}"
		"}",
		AI_FEATURES_MANAGER_VERSION,
		status_variables.llm_total_requests,
		status_variables.llm_cache_hits,
		status_variables.llm_local_model_calls,
		status_variables.llm_cloud_model_calls,
		status_variables.llm_total_response_time_ms,
		status_variables.llm_cache_total_lookup_time_ms,
		status_variables.llm_cache_total_store_time_ms,
		status_variables.llm_cache_lookups,
		status_variables.llm_cache_stores,
		status_variables.llm_cache_misses,
		status_variables.anomaly_total_checks,
		status_variables.anomaly_blocked_queries,
		status_variables.anomaly_flagged_queries,
		status_variables.daily_cloud_spend_usd
	);

	return std::string(buf);
}

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

#endif /* PROXYSQL40 */
