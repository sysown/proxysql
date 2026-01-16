#ifndef __CLASS_NL2SQL_CONVERTER_H
#define __CLASS_NL2SQL_CONVERTER_H

#define NL2SQL_CONVERTER_VERSION "0.1.0"

#include "proxysql.h"
#include <string>
#include <vector>

// Forward declarations
class SQLite3DB;

/**
 * @brief Result structure for NL2SQL conversion
 */
struct NL2SQLResult {
	std::string sql_query;                  ///< Generated SQL
	float confidence;                        ///< 0.0-1.0
	std::string explanation;                 ///< LLM explanation
	std::vector<std::string> tables_used;    ///< Tables referenced
	bool cached;                             ///< From cache
	int64_t cache_id;                        ///< Cache entry ID

	NL2SQLResult() : confidence(0.0f), cached(false), cache_id(0) {}
};

/**
 * @brief Request structure for NL2SQL conversion
 */
struct NL2SQLRequest {
	std::string natural_language;           ///< Input query
	std::string schema_name;                 ///< Current schema
	int max_latency_ms;                      ///< Latency requirement
	bool allow_cache;                        ///< Check vector cache
	std::vector<std::string> context_tables; ///< Relevant tables

	NL2SQLRequest() : max_latency_ms(0), allow_cache(true) {}
};

/**
 * @brief Model provider options
 */
enum class ModelProvider {
	LOCAL_OLLAMA,      ///< Local models via Ollama
	CLOUD_OPENAI,      ///< OpenAI API
	CLOUD_ANTHROPIC,   ///< Anthropic API
	FALLBACK_ERROR     ///< No model available
};

/**
 * @brief NL2SQL Converter class
 *
 * Converts natural language queries to SQL using LLMs with hybrid
 * local/cloud model support and vector cache.
 */
class NL2SQL_Converter {
private:
	struct {
		bool enabled;
		char* query_prefix;
		char* model_provider;
		char* ollama_model;
		char* openai_model;
		char* anthropic_model;
		int cache_similarity_threshold;
		int timeout_ms;
		char* openai_key;
		char* anthropic_key;
		bool prefer_local;
	} config;

	SQLite3DB* vector_db;

	// Internal methods
	std::string build_prompt(const NL2SQLRequest& req, const std::string& schema_context);
	std::string call_ollama(const std::string& prompt, const std::string& model);
	std::string call_openai(const std::string& prompt, const std::string& model);
	std::string call_anthropic(const std::string& prompt, const std::string& model);
	NL2SQLResult check_vector_cache(const NL2SQLRequest& req);
	void store_in_vector_cache(const NL2SQLRequest& req, const NL2SQLResult& result);
	std::string get_schema_context(const std::vector<std::string>& tables);
	ModelProvider select_model(const NL2SQLRequest& req);

public:
	NL2SQL_Converter();
	~NL2SQL_Converter();

	// Initialization
	int init();
	void close();

	// Main conversion method
	NL2SQLResult convert(const NL2SQLRequest& req);

	// Cache management
	void clear_cache();
	std::string get_cache_stats();
};

// Global instance (defined by AI_Features_Manager)
// extern NL2SQL_Converter *GloNL2SQL;

#endif // __CLASS_NL2SQL_CONVERTER_H
