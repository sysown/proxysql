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

// Forward declaration to avoid header ordering issues
class ProxySQL_Admin;
extern ProxySQL_Admin *GloAdmin;

AI_Features_Manager::AI_Features_Manager()
	: shutdown_(0), nl2sql_converter(NULL), anomaly_detector(NULL), vector_db(NULL)
{
	pthread_rwlock_init(&rwlock, NULL);

	// Initialize configuration variables to defaults
	variables.ai_features_enabled = false;
	variables.ai_nl2sql_enabled = false;
	variables.ai_anomaly_detection_enabled = false;

	variables.ai_nl2sql_query_prefix = strdup("NL2SQL:");
	variables.ai_nl2sql_provider = strdup("openai");
	variables.ai_nl2sql_provider_url = strdup("http://localhost:11434/v1/chat/completions");
	variables.ai_nl2sql_provider_model = strdup("llama3.2");
	variables.ai_nl2sql_provider_key = NULL;
	variables.ai_nl2sql_cache_similarity_threshold = 85;
	variables.ai_nl2sql_timeout_ms = 30000;

	variables.ai_anomaly_risk_threshold = 70;
	variables.ai_anomaly_similarity_threshold = 80;
	variables.ai_anomaly_rate_limit = 100;
	variables.ai_anomaly_auto_block = true;
	variables.ai_anomaly_log_only = false;

	variables.ai_prefer_local_models = true;
	variables.ai_daily_budget_usd = 10.0;
	variables.ai_max_cloud_requests_per_hour = 100;

	variables.ai_vector_db_path = strdup("/var/lib/proxysql/ai_features.db");
	variables.ai_vector_dimension = 1536;  // OpenAI text-embedding-3-small

	// Initialize status counters
	memset(&status_variables, 0, sizeof(status_variables));
}

AI_Features_Manager::~AI_Features_Manager() {
	shutdown();

	// Free configuration strings
	free(variables.ai_nl2sql_query_prefix);
	free(variables.ai_nl2sql_provider);
	free(variables.ai_nl2sql_provider_url);
	free(variables.ai_nl2sql_provider_model);
	free(variables.ai_nl2sql_provider_key);
	free(variables.ai_vector_db_path);

	pthread_rwlock_destroy(&rwlock);
}

int AI_Features_Manager::init_vector_db() {
	proxy_info("AI: Initializing vector storage at %s\n", variables.ai_vector_db_path);

	// Ensure directory exists
	char* path_copy = strdup(variables.ai_vector_db_path);
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
	strncpy(path_buf, variables.ai_vector_db_path, sizeof(path_buf) - 1);
	path_buf[sizeof(path_buf) - 1] = '\0';
	int rc = vector_db->open(path_buf, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	if (rc != SQLITE_OK) {
		proxy_error("AI: Failed to open vector database: %s\n", variables.ai_vector_db_path);
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
	if (!variables.ai_nl2sql_enabled) {
		proxy_info("AI: NL2SQL disabled, skipping initialization\n");
		return 0;
	}

	proxy_info("AI: Initializing NL2SQL Converter\n");

	nl2sql_converter = new NL2SQL_Converter();

	// Set vector database
	nl2sql_converter->set_vector_db(vector_db);

	// Update config with current variables
	nl2sql_converter->update_config(
		variables.ai_nl2sql_provider,
		variables.ai_nl2sql_provider_url,
		variables.ai_nl2sql_provider_model,
		variables.ai_nl2sql_provider_key,
		variables.ai_nl2sql_cache_similarity_threshold,
		variables.ai_nl2sql_timeout_ms
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
	if (!variables.ai_anomaly_detection_enabled) {
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

char* AI_Features_Manager::get_variable(const char* name) {
	if (strcmp(name, "ai_features_enabled") == 0)
		return variables.ai_features_enabled ? strdup("true") : strdup("false");
	if (strcmp(name, "ai_nl2sql_enabled") == 0)
		return variables.ai_nl2sql_enabled ? strdup("true") : strdup("false");
	if (strcmp(name, "ai_anomaly_detection_enabled") == 0)
		return variables.ai_anomaly_detection_enabled ? strdup("true") : strdup("false");
	if (strcmp(name, "ai_nl2sql_query_prefix") == 0)
		return strdup(variables.ai_nl2sql_query_prefix);
	if (strcmp(name, "ai_nl2sql_provider") == 0)
		return strdup(variables.ai_nl2sql_provider);
	if (strcmp(name, "ai_nl2sql_provider_url") == 0)
		return strdup(variables.ai_nl2sql_provider_url);
	if (strcmp(name, "ai_nl2sql_provider_model") == 0)
		return strdup(variables.ai_nl2sql_provider_model);
	if (strcmp(name, "ai_nl2sql_provider_key") == 0)
		return variables.ai_nl2sql_provider_key ? strdup(variables.ai_nl2sql_provider_key) : strdup("");
	if (strcmp(name, "ai_anomaly_risk_threshold") == 0) {
		char buf[32];
		snprintf(buf, sizeof(buf), "%d", variables.ai_anomaly_risk_threshold);
		return strdup(buf);
	}
	if (strcmp(name, "ai_prefer_local_models") == 0)
		return variables.ai_prefer_local_models ? strdup("true") : strdup("false");
	if (strcmp(name, "ai_vector_db_path") == 0)
		return strdup(variables.ai_vector_db_path);

	return NULL;
}

bool AI_Features_Manager::set_variable(const char* name, const char* value) {
	wrlock();

	bool changed = false;

	if (strcmp(name, "ai_features_enabled") == 0) {
		bool new_val = (strcmp(value, "true") == 0);
		changed = (variables.ai_features_enabled != new_val);
		variables.ai_features_enabled = new_val;
	}
	else if (strcmp(name, "ai_nl2sql_enabled") == 0) {
		bool new_val = (strcmp(value, "true") == 0);
		changed = (variables.ai_nl2sql_enabled != new_val);
		variables.ai_nl2sql_enabled = new_val;
	}
	else if (strcmp(name, "ai_anomaly_detection_enabled") == 0) {
		bool new_val = (strcmp(value, "true") == 0);
		changed = (variables.ai_anomaly_detection_enabled != new_val);
		variables.ai_anomaly_detection_enabled = new_val;
	}
	else if (strcmp(name, "ai_nl2sql_query_prefix") == 0) {
		free(variables.ai_nl2sql_query_prefix);
		variables.ai_nl2sql_query_prefix = strdup(value);
		changed = true;
	}
	else if (strcmp(name, "ai_nl2sql_provider") == 0) {
		free(variables.ai_nl2sql_provider);
		variables.ai_nl2sql_provider = strdup(value);
		changed = true;
	}
	else if (strcmp(name, "ai_nl2sql_provider_url") == 0) {
		free(variables.ai_nl2sql_provider_url);
		variables.ai_nl2sql_provider_url = strdup(value);
		changed = true;
	}
	else if (strcmp(name, "ai_nl2sql_provider_model") == 0) {
		free(variables.ai_nl2sql_provider_model);
		variables.ai_nl2sql_provider_model = strdup(value);
		changed = true;
	}
	else if (strcmp(name, "ai_nl2sql_provider_key") == 0) {
		free(variables.ai_nl2sql_provider_key);
		variables.ai_nl2sql_provider_key = strdup(value);
		changed = true;
	}
	else if (strcmp(name, "ai_anomaly_risk_threshold") == 0) {
		variables.ai_anomaly_risk_threshold = atoi(value);
		changed = true;
	}
	else if (strcmp(name, "ai_prefer_local_models") == 0) {
		variables.ai_prefer_local_models = (strcmp(value, "true") == 0);
		changed = true;
	}
	else if (strcmp(name, "ai_vector_db_path") == 0) {
		free(variables.ai_vector_db_path);
		variables.ai_vector_db_path = strdup(value);
		changed = true;
	}

	wrunlock();
	return changed;
}

char** AI_Features_Manager::get_variables_list() {
	// Return NULL-terminated array of variable names
	static const char* vars[] = {
		"ai_features_enabled",
		"ai_nl2sql_enabled",
		"ai_anomaly_detection_enabled",
		"ai_nl2sql_query_prefix",
		"ai_nl2sql_provider",
		"ai_nl2sql_provider_url",
		"ai_nl2sql_provider_model",
		"ai_nl2sql_provider_key",
		"ai_nl2sql_cache_similarity_threshold",
		"ai_nl2sql_timeout_ms",
		"ai_anomaly_risk_threshold",
		"ai_anomaly_similarity_threshold",
		"ai_anomaly_rate_limit",
		"ai_anomaly_auto_block",
		"ai_anomaly_log_only",
		"ai_prefer_local_models",
		"ai_daily_budget_usd",
		"ai_max_cloud_requests_per_hour",
		"ai_vector_db_path",
		"ai_vector_dimension",
		NULL
	};

	// Clone the array
	char** result = (char**)malloc(sizeof(char*) * 20);
	for (int i = 0; vars[i]; i++) {
		result[i] = strdup(vars[i]);
	}
	result[19] = NULL;

	return result;
}

std::string AI_Features_Manager::get_status_json() {
	char buf[1024];
	snprintf(buf, sizeof(buf),
		"{"
		"\"version\": \"%s\","
		"\"nl2sql\": {"
		"\"total_requests\": %llu,"
		"\"cache_hits\": %llu,"
		"\"local_calls\": %llu,"
		"\"cloud_calls\": %llu"
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
		status_variables.anomaly_total_checks,
		status_variables.anomaly_blocked_queries,
		status_variables.anomaly_flagged_queries,
		status_variables.daily_cloud_spend_usd
	);

	return std::string(buf);
}
