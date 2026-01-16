#include "AI_Features_Manager.h"
#include "NL2SQL_Converter.h"
#include "Anomaly_Detector.h"
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
	: shutdown_(0), nl2sql_converter(NULL), anomaly_detector(NULL), vector_db(NULL)
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
	char* path_copy = strdup(GloGATH->variables.genai_vector_db_path);
	if (!path_copy) {
		proxy_error("AI: Failed to allocate memory for path copy in init_vector_db\n");
		return -1;
	}
	char* dir = dirname(path_copy);
	struct stat st;
	if (stat(dir, &st) != 0) {
		// Create directory if it doesn't exist
		char cmd[512];
		snprintf(cmd, sizeof(cmd), "mkdir -p %s", dir);
		system(cmd);
	}
	free(path_copy);

	vector_db = new SQLite3DB();
	char path_buf[512];
	strncpy(path_buf, GloGATH->variables.genai_vector_db_path, sizeof(path_buf) - 1);
	path_buf[sizeof(path_buf) - 1] = '\0';
	int rc = vector_db->open(path_buf, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	if (rc != SQLITE_OK) {
		proxy_error("AI: Failed to open vector database: %s\n", GloGATH->variables.genai_vector_db_path);
		delete vector_db;
		vector_db = NULL;
		return -1;
	}

	// Create tables for NL2SQL cache
	const char* create_nl2sql_cache =
		"CREATE TABLE IF NOT EXISTS nl2sql_cache ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"natural_language TEXT NOT NULL,"
		"generated_sql TEXT NOT NULL,"
		"schema_context TEXT,"
		"embedding BLOB,"
		"hit_count INTEGER DEFAULT 0,"
		"last_hit INTEGER,"
		"created_at INTEGER DEFAULT (strftime('%s', 'now'))"
		");";

	if (vector_db->execute(create_nl2sql_cache) != 0) {
		proxy_error("AI: Failed to create nl2sql_cache table\n");
		return -1;
	}

	// Create table for anomaly patterns
	const char* create_anomaly_patterns =
		"CREATE TABLE IF NOT EXISTS anomaly_patterns ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"pattern_name TEXT,"
		"pattern_type TEXT,"  // 'sql_injection', 'dos', 'privilege_escalation'
		"query_example TEXT,"
		"embedding BLOB,"
		"severity INTEGER,"  // 1-10
		"created_at INTEGER DEFAULT (strftime('%s', 'now'))"
		");";

	if (vector_db->execute(create_anomaly_patterns) != 0) {
		proxy_error("AI: Failed to create anomaly_patterns table\n");
		return -1;
	}

	// Create table for query history
	const char* create_query_history =
		"CREATE TABLE IF NOT EXISTS query_history ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"query_text TEXT NOT NULL,"
		"generated_sql TEXT,"
		"embedding BLOB,"
		"execution_time_ms INTEGER,"
		"success BOOLEAN,"
		"timestamp INTEGER DEFAULT (strftime('%s', 'now'))"
		");";

	if (vector_db->execute(create_query_history) != 0) {
		proxy_error("AI: Failed to create query_history table\n");
		return -1;
	}

	// Create virtual vector tables for similarity search using sqlite-vec
	// Note: sqlite-vec extension is auto-loaded in Admin_Bootstrap.cpp:612

	// 1. NL2SQL cache virtual table
	const char* create_nl2sql_vec =
		"CREATE VIRTUAL TABLE IF NOT EXISTS nl2sql_cache_vec USING vec0("
		"embedding float(1536)"
		");";

	if (vector_db->execute(create_nl2sql_vec) != 0) {
		proxy_error("AI: Failed to create nl2sql_cache_vec virtual table\n");
		// Virtual table creation failure is not critical - log and continue
		proxy_debug(PROXY_DEBUG_GENAI, 3, "Continuing without nl2sql_cache_vec");
	}

	// 2. Anomaly patterns virtual table
	const char* create_anomaly_vec =
		"CREATE VIRTUAL TABLE IF NOT EXISTS anomaly_patterns_vec USING vec0("
		"embedding float(1536)"
		");";

	if (vector_db->execute(create_anomaly_vec) != 0) {
		proxy_error("AI: Failed to create anomaly_patterns_vec virtual table\n");
		proxy_debug(PROXY_DEBUG_GENAI, 3, "Continuing without anomaly_patterns_vec");
	}

	// 3. Query history virtual table
	const char* create_history_vec =
		"CREATE VIRTUAL TABLE IF NOT EXISTS query_history_vec USING vec0("
		"embedding float(1536)"
		");";

	if (vector_db->execute(create_history_vec) != 0) {
		proxy_error("AI: Failed to create query_history_vec virtual table\n");
		proxy_debug(PROXY_DEBUG_GENAI, 3, "Continuing without query_history_vec");
	}

	proxy_info("AI: Vector storage initialized successfully with virtual tables\n");
	return 0;
}

int AI_Features_Manager::init_nl2sql() {
	if (!GloGATH->variables.genai_nl2sql_enabled) {
		proxy_info("AI: NL2SQL disabled, skipping initialization\n");
		return 0;
	}

	proxy_info("AI: Initializing NL2SQL Converter\n");

	nl2sql_converter = new NL2SQL_Converter();

	// Set vector database
	nl2sql_converter->set_vector_db(vector_db);

	// Update config with current variables from GenAI module
	nl2sql_converter->update_config(
		GloGATH->variables.genai_nl2sql_provider,
		GloGATH->variables.genai_nl2sql_provider_url,
		GloGATH->variables.genai_nl2sql_provider_model,
		GloGATH->variables.genai_nl2sql_provider_key,
		GloGATH->variables.genai_nl2sql_cache_similarity_threshold,
		GloGATH->variables.genai_nl2sql_timeout_ms
	);

	if (nl2sql_converter->init() != 0) {
		proxy_error("AI: Failed to initialize NL2SQL Converter\n");
		delete nl2sql_converter;
		nl2sql_converter = NULL;
		return -1;
	}

	proxy_info("AI: NL2SQL Converter initialized\n");
	return 0;
}

int AI_Features_Manager::init_anomaly_detector() {
	if (!GloGATH->variables.genai_anomaly_enabled) {
		proxy_info("AI: Anomaly detection disabled, skipping initialization\n");
		return 0;
	}

	proxy_info("AI: Initializing Anomaly Detector\n");

	anomaly_detector = new Anomaly_Detector();
	if (anomaly_detector->init() != 0) {
		proxy_error("AI: Failed to initialize Anomaly Detector\n");
		delete anomaly_detector;
		anomaly_detector = NULL;
		return -1;
	}

	proxy_info("AI: Anomaly Detector initialized\n");
	return 0;
}

void AI_Features_Manager::close_vector_db() {
	if (vector_db) {
		delete vector_db;
		vector_db = NULL;
	}
}

void AI_Features_Manager::close_nl2sql() {
	if (nl2sql_converter) {
		nl2sql_converter->close();
		delete nl2sql_converter;
		nl2sql_converter = NULL;
	}
}

void AI_Features_Manager::close_anomaly_detector() {
	if (anomaly_detector) {
		anomaly_detector->close();
		delete anomaly_detector;
		anomaly_detector = NULL;
	}
}

int AI_Features_Manager::init() {
	proxy_info("AI: Initializing AI Features Manager v%s\n", AI_FEATURES_MANAGER_VERSION);

	if (!variables.ai_features_enabled) {
		proxy_info("AI: AI features disabled by configuration\n");
		return 0;
	}

	// Initialize vector storage first (needed by both NL2SQL and Anomaly Detector)
	if (init_vector_db() != 0) {
		proxy_error("AI: Failed to initialize vector storage\n");
		return -1;
	}

	// Initialize NL2SQL
	if (init_nl2sql() != 0) {
		proxy_error("AI: Failed to initialize NL2SQL\n");
		return -1;
	}

	// Initialize Anomaly Detector
	if (init_anomaly_detector() != 0) {
		proxy_error("AI: Failed to initialize Anomaly Detector\n");
		return -1;
	}

	proxy_info("AI: AI Features Manager initialized successfully\n");
	return 0;
}

void AI_Features_Manager::shutdown() {
	if (shutdown_) return;
	shutdown_ = 1;

	proxy_info("AI: Shutting down AI Features Manager\n");

	close_nl2sql();
	close_anomaly_detector();
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
		"\"version\": \"%s\","
		"\"nl2sql\": {"
		"\"total_requests\": %llu,"
		"\"cache_hits\": %llu,"
		"\"local_calls\": %llu,"
		"\"cloud_calls\": %llu,"
		"\"total_response_time_ms\": %llu,"
		"\"cache_total_lookup_time_ms\": %llu,"
		"\"cache_total_store_time_ms\": %llu,"
		"\"cache_lookups\": %llu,"
		"\"cache_stores\": %llu,"
		"\"cache_misses\": %llu"
		"},"
		"\"anomaly\": {"
		"\"total_checks\": %llu,"
		"\"blocked\": %llu,"
		"\"flagged\": %llu"
		"},"
		"\"spend\": {"
		"\"daily_usd\": %.2f"
		"}"
		"}",
		AI_FEATURES_MANAGER_VERSION,
		status_variables.nl2sql_total_requests,
		status_variables.nl2sql_cache_hits,
		status_variables.nl2sql_local_model_calls,
		status_variables.nl2sql_cloud_model_calls,
		status_variables.nl2sql_total_response_time_ms,
		status_variables.nl2sql_cache_total_lookup_time_ms,
		status_variables.nl2sql_cache_total_store_time_ms,
		status_variables.nl2sql_cache_lookups,
		status_variables.nl2sql_cache_stores,
		status_variables.nl2sql_cache_misses,
		status_variables.anomaly_total_checks,
		status_variables.anomaly_blocked_queries,
		status_variables.anomaly_flagged_queries,
		status_variables.daily_cloud_spend_usd
	);

	return std::string(buf);
}
