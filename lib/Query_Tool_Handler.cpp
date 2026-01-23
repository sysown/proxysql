#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "Query_Tool_Handler.h"
#include "proxysql_debug.h"

#include <vector>
#include <map>
#include <regex>
#include <cstring>

// MySQL client library
#include <mysql.h>

// ============================================================
// JSON Helper Functions
//
// These helper functions provide safe extraction of values from
// nlohmann::json objects with type coercion and default values.
// They handle edge cases like null values, type mismatches, and
// missing keys gracefully.
// ============================================================

// Safely extract a string value from JSON.
//
// Returns the value as a string if the key exists and is not null.
// For non-string types, returns the JSON dump representation.
// Returns the default value if the key is missing or null.
//
// Parameters:
//   j           - JSON object to extract from
//   key         - Key to look up
//   default_val - Default value if key is missing or null
//
// Returns:
//   String value, JSON dump, or default value
static std::string json_string(const json& j, const std::string& key, const std::string& default_val = "") {
	if (j.contains(key) && !j[key].is_null()) {
		if (j[key].is_string()) {
			return j[key].get<std::string>();
		}
		return j[key].dump();
	}
	return default_val;
}

// Safely extract an integer value from JSON with type coercion.
//
// Handles multiple input types:
// - Numbers: Returns directly as int
// - Booleans: Converts (true=1, false=0)
// - Strings: Attempts numeric parsing
// - Missing/null: Returns default value
//
// Parameters:
//   j           - JSON object to extract from
//   key         - Key to look up
//   default_val - Default value if key is missing, null, or unparseable
//
// Returns:
//   Integer value, or default value
static int json_int(const json& j, const std::string& key, int default_val = 0) {
	if (j.contains(key) && !j[key].is_null()) {
		const json& val = j[key];
		// If it's already a number, return it
		if (val.is_number()) {
			return val.get<int>();
		}
		// If it's a boolean, convert to int (true=1, false=0)
		if (val.is_boolean()) {
			return val.get<bool>() ? 1 : 0;
		}
		// If it's a string, try to parse it as an int
		if (val.is_string()) {
			std::string s = val.get<std::string>();
			try {
				return std::stoi(s);
			} catch (...) {
				// Parse failed, return default
				return default_val;
			}
		}
	}
	return default_val;
}

// Safely extract a double value from JSON with type coercion.
//
// Handles multiple input types:
// - Numbers: Returns directly as double
// - Strings: Attempts numeric parsing
// - Missing/null: Returns default value
//
// Parameters:
//   j           - JSON object to extract from
//   key         - Key to look up
//   default_val - Default value if key is missing, null, or unparseable
//
// Returns:
//   Double value, or default value
static double json_double(const json& j, const std::string& key, double default_val = 0.0) {
	if (j.contains(key) && !j[key].is_null()) {
		const json& val = j[key];
		// If it's already a number, return it
		if (val.is_number()) {
			return val.get<double>();
		}
		// If it's a string, try to parse it as a double
		if (val.is_string()) {
			std::string s = val.get<std::string>();
			try {
				return std::stod(s);
			} catch (...) {
				// Parse failed, return default
				return default_val;
			}
		}
	}
	return default_val;
}

// ============================================================
// SQL Escaping Helper Functions
//
// These functions provide safe SQL escaping to prevent
// SQL injection vulnerabilities when building queries.
// ============================================================

/**
 * @brief Validate and escape a SQL identifier (table name, column name, etc.)
 *
 * For SQLite, we validate that the identifier contains only safe characters.
 * This prevents SQL injection while allowing valid identifiers.
 *
 * @param identifier The identifier to validate/escape
 * @return Empty string if unsafe, otherwise the validated identifier
 */
static std::string validate_sql_identifier_sqlite(const std::string& identifier) {
	if (identifier.empty()) {
		return "";
	}

	// Check length (SQLite identifiers max 1000 characters, but we're more conservative)
	if (identifier.length() > 128) {
		return "";
	}

	// First character must be letter or underscore
	if (!isalpha(identifier[0]) && identifier[0] != '_') {
		return "";
	}

	// All characters must be alphanumeric, underscore, or dollar sign
	for (char c : identifier) {
		if (!isalnum(c) && c != '_' && c != '$') {
			return "";
		}
	}

	return identifier;
}

/**
 * @brief Escape a SQL string literal for use in queries
 *
 * Escapes single quotes by doubling them (standard SQL) and also escapes
 * backslashes for defense-in-depth (important for MySQL with certain modes).
 *
 * @param value The string value to escape
 * @return Escaped string safe for use in SQL queries
 */
static std::string escape_string_literal(const std::string& value) {
	std::string escaped;
	escaped.reserve(value.length() * 2 + 1);

	for (char c : value) {
		if (c == '\'') {
			escaped += "''";  // Double single quotes to escape (SQL standard)
		} else if (c == '\\') {
			escaped += "\\\\";  // Escape backslash (defense-in-depth)
		} else {
			escaped += c;
		}
	}

	return escaped;
}

Query_Tool_Handler::Query_Tool_Handler(
	const std::string& hosts,
	const std::string& ports,
	const std::string& user,
	const std::string& password,
	const std::string& schema,
	const std::string& catalog_path)
	: catalog(NULL),
	  harvester(NULL),
	  pool_size(0),
	  max_rows(200),
	  timeout_ms(2000),
	  allow_select_star(false)
{
	// Parse hosts
	std::istringstream h(hosts);
	std::string host;
	while (std::getline(h, host, ',')) {
		host.erase(0, host.find_first_not_of(" \t"));
		host.erase(host.find_last_not_of(" \t") + 1);
		if (!host.empty()) {
			// Store hosts for later
		}
	}

	// Parse ports
	std::istringstream p(ports);
	std::string port;
	while (std::getline(p, port, ',')) {
		port.erase(0, port.find_first_not_of(" \t"));
		port.erase(port.find_last_not_of(" \t") + 1);
	}

	mysql_hosts = hosts;
	mysql_ports = ports;
	mysql_user = user;
	mysql_password = password;
	mysql_schema = schema;

	// Initialize pool mutex
	pthread_mutex_init(&pool_lock, NULL);

	// Initialize counters mutex
	pthread_mutex_init(&counters_lock, NULL);

	// Create discovery schema and harvester
	catalog = new Discovery_Schema(catalog_path);
	harvester = new Static_Harvester(
		hosts.empty() ? "127.0.0.1" : hosts,
		ports.empty() ? 3306 : std::stoi(ports),
		user, password, schema, catalog_path
	);

	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Query_Tool_Handler created with Discovery_Schema\n");
}

Query_Tool_Handler::~Query_Tool_Handler() {
	close();

	if (catalog) {
		delete catalog;
		catalog = NULL;
	}

	if (harvester) {
		delete harvester;
		harvester = NULL;
	}

	pthread_mutex_destroy(&pool_lock);
	pthread_mutex_destroy(&counters_lock);
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Query_Tool_Handler destroyed\n");
}

int Query_Tool_Handler::init() {
	// Initialize discovery schema
	if (catalog->init()) {
		proxy_error("Query_Tool_Handler: Failed to initialize Discovery_Schema\n");
		return -1;
	}

	// Initialize harvester (but don't connect yet)
	if (harvester->init()) {
		proxy_error("Query_Tool_Handler: Failed to initialize Static_Harvester\n");
		return -1;
	}

	// Initialize connection pool
	if (init_connection_pool()) {
		proxy_error("Query_Tool_Handler: Failed to initialize connection pool\n");
		return -1;
	}

	proxy_info("Query_Tool_Handler initialized with Discovery_Schema and Static_Harvester\n");
	return 0;
}

void Query_Tool_Handler::close() {
	pthread_mutex_lock(&pool_lock);

	for (auto& conn : connection_pool) {
		if (conn.mysql) {
			mysql_close(static_cast<MYSQL*>(conn.mysql));
			conn.mysql = NULL;
		}
	}
	connection_pool.clear();
	pool_size = 0;

	pthread_mutex_unlock(&pool_lock);
}

int Query_Tool_Handler::init_connection_pool() {
	// Parse hosts
	std::vector<std::string> host_list;
	std::istringstream h(mysql_hosts);
	std::string host;
	while (std::getline(h, host, ',')) {
		host.erase(0, host.find_first_not_of(" \t"));
		host.erase(host.find_last_not_of(" \t") + 1);
		if (!host.empty()) {
			host_list.push_back(host);
		}
	}

	// Parse ports
	std::vector<int> port_list;
	std::istringstream p(mysql_ports);
	std::string port;
	while (std::getline(p, port, ',')) {
		port.erase(0, port.find_first_not_of(" \t"));
		port.erase(port.find_last_not_of(" \t") + 1);
		if (!port.empty()) {
			port_list.push_back(atoi(port.c_str()));
		}
	}

	// Ensure ports array matches hosts array size
	while (port_list.size() < host_list.size()) {
		port_list.push_back(3306);
	}

	if (host_list.empty()) {
		proxy_error("Query_Tool_Handler: No hosts configured\n");
		return -1;
	}

	pthread_mutex_lock(&pool_lock);

	for (size_t i = 0; i < host_list.size(); i++) {
		MySQLConnection conn;
		conn.host = host_list[i];
		conn.port = port_list[i];
		conn.in_use = false;

		MYSQL* mysql = mysql_init(NULL);
		if (!mysql) {
			proxy_error("Query_Tool_Handler: mysql_init failed for %s:%d\n",
				conn.host.c_str(), conn.port);
			pthread_mutex_unlock(&pool_lock);
			return -1;
		}

		unsigned int timeout = 5;
		mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
		mysql_options(mysql, MYSQL_OPT_READ_TIMEOUT, &timeout);
		mysql_options(mysql, MYSQL_OPT_WRITE_TIMEOUT, &timeout);

		if (!mysql_real_connect(
			mysql,
			conn.host.c_str(),
			mysql_user.c_str(),
			mysql_password.c_str(),
			mysql_schema.empty() ? NULL : mysql_schema.c_str(),
			conn.port,
			NULL,
			CLIENT_MULTI_STATEMENTS
		)) {
			proxy_error("Query_Tool_Handler: mysql_real_connect failed for %s:%d: %s\n",
				conn.host.c_str(), conn.port, mysql_error(mysql));
			mysql_close(mysql);
			pthread_mutex_unlock(&pool_lock);
			return -1;
		}

		conn.mysql = mysql;
		connection_pool.push_back(conn);
		pool_size++;

		proxy_info("Query_Tool_Handler: Connected to %s:%d\n",
			conn.host.c_str(), conn.port);
	}

	pthread_mutex_unlock(&pool_lock);
	proxy_info("Query_Tool_Handler: Connection pool initialized with %d connection(s)\n", pool_size);
	return 0;
}

void* Query_Tool_Handler::get_connection() {
	pthread_mutex_lock(&pool_lock);

	for (auto& conn : connection_pool) {
		if (!conn.in_use) {
			conn.in_use = true;
			pthread_mutex_unlock(&pool_lock);
			return conn.mysql;
		}
	}

	pthread_mutex_unlock(&pool_lock);
	proxy_error("Query_Tool_Handler: No available connection\n");
	return NULL;
}

void Query_Tool_Handler::return_connection(void* mysql_ptr) {
	if (!mysql_ptr) return;

	pthread_mutex_lock(&pool_lock);

	for (auto& conn : connection_pool) {
		if (conn.mysql == mysql_ptr) {
			conn.in_use = false;
			break;
		}
	}

	pthread_mutex_unlock(&pool_lock);
}

// Helper to find connection wrapper by mysql pointer (caller should NOT hold pool_lock)
Query_Tool_Handler::MySQLConnection* Query_Tool_Handler::find_connection(void* mysql_ptr) {
	for (auto& conn : connection_pool) {
		if (conn.mysql == mysql_ptr) {
			return &conn;
		}
	}
	return nullptr;
}

std::string Query_Tool_Handler::execute_query(const std::string& query) {
	void* mysql = get_connection();
	if (!mysql) {
		return "{\"error\": \"No available connection\"}";
	}

	MYSQL* mysql_ptr = static_cast<MYSQL*>(mysql);

	if (mysql_query(mysql_ptr, query.c_str())) {
		proxy_error("Query_Tool_Handler: Query failed: %s\n", mysql_error(mysql_ptr));
		return_connection(mysql);
		json j;
		j["success"] = false;
		j["error"] = std::string(mysql_error(mysql_ptr));
		return j.dump();
	}

	MYSQL_RES* res = mysql_store_result(mysql_ptr);

	// Capture affected_rows BEFORE return_connection to avoid race condition
	unsigned long affected_rows_val = mysql_affected_rows(mysql_ptr);
	return_connection(mysql);

	if (!res) {
		// No result set (e.g., INSERT/UPDATE)
		json j;
		j["success"] = true;
		j["affected_rows"] = static_cast<long>(affected_rows_val);
		return j.dump();
	}

	int num_fields = mysql_num_fields(res);
	MYSQL_ROW row;

	json results = json::array();
	while ((row = mysql_fetch_row(res))) {
		json row_data = json::array();
		for (int i = 0; i < num_fields; i++) {
			row_data.push_back(row[i] ? row[i] : "");
		}
		results.push_back(row_data);
	}

	mysql_free_result(res);

	json j;
	j["success"] = true;
	j["columns"] = num_fields;
	j["rows"] = results;
	return j.dump();
}

// Execute query with optional schema switching
std::string Query_Tool_Handler::execute_query_with_schema(
	const std::string& query,
	const std::string& schema
) {
	void* mysql = get_connection();
	if (!mysql) {
		return "{\"error\": \"No available connection\"}";
	}

	MYSQL* mysql_ptr = static_cast<MYSQL*>(mysql);
	MySQLConnection* conn_wrapper = find_connection(mysql);

	// If schema is provided and differs from current, switch to it
	if (!schema.empty() && conn_wrapper && conn_wrapper->current_schema != schema) {
		if (mysql_select_db(mysql_ptr, schema.c_str()) != 0) {
			proxy_error("Query_Tool_Handler: Failed to select database '%s': %s\n",
				schema.c_str(), mysql_error(mysql_ptr));
			return_connection(mysql);
			json j;
			j["success"] = false;
			j["error"] = std::string("Failed to select database: ") + schema;
			return j.dump();
		}
		// Update current schema tracking
		conn_wrapper->current_schema = schema;
		proxy_info("Query_Tool_Handler: Switched to schema '%s'\n", schema.c_str());
	}

	// Execute the actual query
	if (mysql_query(mysql_ptr, query.c_str())) {
		proxy_error("Query_Tool_Handler: Query failed: %s\n", mysql_error(mysql_ptr));
		return_connection(mysql);
		json j;
		j["success"] = false;
		j["error"] = std::string(mysql_error(mysql_ptr));
		return j.dump();
	}

	MYSQL_RES* res = mysql_store_result(mysql_ptr);

	// Capture affected_rows BEFORE return_connection to avoid race condition
	unsigned long affected_rows_val = mysql_affected_rows(mysql_ptr);
	return_connection(mysql);

	if (!res) {
		// No result set (e.g., INSERT/UPDATE)
		json j;
		j["success"] = true;
		j["affected_rows"] = static_cast<long>(affected_rows_val);
		return j.dump();
	}

	int num_fields = mysql_num_fields(res);
	MYSQL_ROW row;

	json results = json::array();
	while ((row = mysql_fetch_row(res))) {
		json row_data = json::array();
		for (int i = 0; i < num_fields; i++) {
			row_data.push_back(row[i] ? row[i] : "");
		}
		results.push_back(row_data);
	}

	mysql_free_result(res);

	json j;
	j["success"] = true;
	j["columns"] = num_fields;
	j["rows"] = results;
	return j.dump();
}

bool Query_Tool_Handler::validate_readonly_query(const std::string& query) {
	std::string upper = query;
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

	// Quick exit: blacklist check for dangerous keywords
	// This provides fast rejection of obviously dangerous queries
	std::vector<std::string> dangerous = {
		"INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
		"TRUNCATE", "REPLACE", "LOAD", "CALL", "EXECUTE"
	};

	for (const auto& word : dangerous) {
		if (upper.find(word) != std::string::npos) {
			return false;
		}
	}

	// Whitelist validation: query must start with an allowed read-only keyword
	// This ensures the query is of a known-safe type (SELECT, WITH, EXPLAIN, SHOW, DESCRIBE)
	// Only queries matching these specific patterns are allowed through
	if (upper.find("SELECT") == 0 && upper.find("FROM") != std::string::npos) {
		return true;
	}
	if (upper.find("WITH") == 0) {
		return true;
	}
	if (upper.find("EXPLAIN") == 0) {
		return true;
	}
	if (upper.find("SHOW") == 0) {
		return true;
	}
	if (upper.find("DESCRIBE") == 0 || upper.find("DESC") == 0) {
		return true;
	}

	return false;
}

bool Query_Tool_Handler::is_dangerous_query(const std::string& query) {
	std::string upper = query;
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

	// Extremely dangerous operations
	std::vector<std::string> critical = {
		"DROP DATABASE", "DROP TABLE", "TRUNCATE", "DELETE FROM", "DELETE FROM",
		"GRANT", "REVOKE", "CREATE USER", "ALTER USER", "SET PASSWORD"
	};

	for (const auto& phrase : critical) {
		if (upper.find(phrase) != std::string::npos) {
			return true;
		}
	}

	return false;
}

json Query_Tool_Handler::create_tool_schema(
	const std::string& tool_name,
	const std::string& description,
	const std::vector<std::string>& required_params,
	const std::map<std::string, std::string>& optional_params
) {
	json properties = json::object();

	for (const auto& param : required_params) {
		properties[param] = {
			{"type", "string"},
			{"description", param + " parameter"}
		};
	}

	for (const auto& param : optional_params) {
		properties[param.first] = {
			{"type", param.second},
			{"description", param.first + " parameter"}
		};
	}

	json schema;
	schema["type"] = "object";
	schema["properties"] = properties;
	if (!required_params.empty()) {
		schema["required"] = required_params;
	}

	return create_tool_description(tool_name, description, schema);
}

json Query_Tool_Handler::get_tool_list() {
	json tools = json::array();

	// ============================================================
	// INVENTORY TOOLS
	// ============================================================
	tools.push_back(create_tool_schema(
		"list_schemas",
		"List all available schemas/databases",
		{},
		{{"page_token", "string"}, {"page_size", "integer"}}
	));

	tools.push_back(create_tool_schema(
		"list_tables",
		"List tables in a schema",
		{"schema"},
		{{"page_token", "string"}, {"page_size", "integer"}, {"name_filter", "string"}}
	));

	// ============================================================
	// STRUCTURE TOOLS
	// ============================================================
	tools.push_back(create_tool_schema(
		"get_constraints",
		"[DEPRECATED] Use catalog.get_relationships with run_id=schema_name and object_key=schema.table instead. Get constraints (foreign keys, unique constraints, etc.) for a table",
		{"schema"},
		{{"table", "string"}}
	));

	// ============================================================
	// SAMPLING TOOLS
	// ============================================================
	tools.push_back(create_tool_schema(
		"sample_rows",
		"Get sample rows from a table (with hard cap on rows returned)",
		{"schema", "table"},
		{{"columns", "string"}, {"where", "string"}, {"order_by", "string"}, {"limit", "integer"}}
	));

	tools.push_back(create_tool_schema(
		"sample_distinct",
		"Sample distinct values from a column",
		{"schema", "table", "column"},
		{{"where", "string"}, {"limit", "integer"}}
	));

	// ============================================================
	// QUERY TOOLS
	// ============================================================
	tools.push_back(create_tool_schema(
		"run_sql_readonly",
		"Execute a read-only SQL query with safety guardrails enforced. Optional schema parameter switches database context before query execution.",
		{"sql"},
		{{"schema", "string"}, {"max_rows", "integer"}, {"timeout_sec", "integer"}}
	));

	tools.push_back(create_tool_schema(
		"explain_sql",
		"Explain a query execution plan using EXPLAIN or EXPLAIN ANALYZE",
		{"sql"},
		{}
	));

	// ============================================================
	// RELATIONSHIP INFERENCE TOOLS
	// ============================================================
	tools.push_back(create_tool_schema(
		"suggest_joins",
		"[DEPRECATED] Use catalog.get_relationships with run_id=schema_name instead. Suggest table joins based on heuristic analysis of column names and types",
		{"schema", "table_a"},
		{{"table_b", "string"}, {"max_candidates", "integer"}}
	));

	tools.push_back(create_tool_schema(
		"find_reference_candidates",
		"[DEPRECATED] Use catalog.get_relationships with run_id=schema_name instead. Find tables that might be referenced by a foreign key column",
		{"schema", "table", "column"},
		{{"max_tables", "integer"}}
	));

	// ============================================================
	// DISCOVERY TOOLS (Phase 1: Static Discovery)
	// ============================================================
	tools.push_back(create_tool_schema(
		"discovery.run_static",
		"Trigger ProxySQL to perform static metadata harvest from MySQL INFORMATION_SCHEMA for a single schema. Returns the new run_id for subsequent LLM analysis.",
		{"schema_filter"},
		{{"notes", "string"}}
	));

	// ============================================================
	// CATALOG TOOLS (using Discovery_Schema)
	// ============================================================
	tools.push_back(create_tool_schema(
		"catalog.init",
		"Initialize (or migrate) the SQLite catalog schema using the embedded Discovery_Schema.",
		{},
		{{"sqlite_path", "string"}}
	));

	tools.push_back(create_tool_schema(
		"catalog.search",
		"Full-text search over discovered objects (tables/views/routines) using FTS5. Returns ranked object_keys and basic metadata.",
		{"run_id", "query"},
		{{"limit", "integer"}, {"object_type", "string"}, {"schema_name", "string"}}
	));

	tools.push_back(create_tool_schema(
		"catalog.get_object",
		"Fetch a discovered object and its columns/indexes/foreign keys by object_key (schema.object) or by object_id.",
		{"run_id"},
		{{"object_id", "integer"}, {"object_key", "string"}, {"include_definition", "boolean"}, {"include_profiles", "boolean"}}
	));

	tools.push_back(create_tool_schema(
		"catalog.list_objects",
		"List objects (paged) for a run, optionally filtered by schema/type, ordered by name or size/rows estimate.",
		{"run_id"},
		{{"schema_name", "string"}, {"object_type", "string"}, {"order_by", "string"}, {"page_size", "integer"}, {"page_token", "string"}}
	));

	tools.push_back(create_tool_schema(
		"catalog.get_relationships",
		"Get relationships for a given object: foreign keys, view deps, inferred relationships (deterministic + LLM).",
		{"run_id"},
		{{"object_id", "integer"}, {"object_key", "string"}, {"include_inferred", "boolean"}, {"min_confidence", "number"}}
	));

	// ============================================================
	// AGENT TOOLS (Phase 2: LLM Agent Discovery)
	// ============================================================
	tools.push_back(create_tool_schema(
		"agent.run_start",
		"Create a new LLM agent run bound to a deterministic discovery run_id.",
		{"run_id", "model_name"},
		{{"prompt_hash", "string"}, {"budget", "object"}}
	));

	tools.push_back(create_tool_schema(
		"agent.run_finish",
		"Mark an agent run finished (success or failure).",
		{"agent_run_id", "status"},
		{{"error", "string"}}
	));

	tools.push_back(create_tool_schema(
		"agent.event_append",
		"Append an agent event for traceability (tool calls, results, notes, decisions).",
		{"agent_run_id", "event_type", "payload"},
		{}
	));

	// ============================================================
	// LLM MEMORY TOOLS (Phase 2: LLM Agent Discovery)
	// ============================================================
	tools.push_back(create_tool_schema(
		"llm.summary_upsert",
		"Upsert a structured semantic summary for an object (table/view/routine). This is the main LLM 'memory' per object.",
		{"agent_run_id", "run_id", "object_id", "summary"},
		{{"confidence", "number"}, {"status", "string"}, {"sources", "object"}}
	));

	tools.push_back(create_tool_schema(
		"llm.summary_get",
		"Get the LLM semantic summary for an object, optionally for a specific agent_run_id.",
		{"run_id", "object_id"},
		{{"agent_run_id", "integer"}, {"latest", "boolean"}}
	));

	tools.push_back(create_tool_schema(
		"llm.relationship_upsert",
		"Upsert an LLM-inferred relationship (join edge) between objects/columns with confidence and evidence.",
		{"agent_run_id", "run_id", "child_object_id", "child_column", "parent_object_id", "parent_column", "confidence"},
		{{"rel_type", "string"}, {"evidence", "object"}}
	));

	tools.push_back(create_tool_schema(
		"llm.domain_upsert",
		"Create or update a domain (cluster) like 'billing' and its description.",
		{"agent_run_id", "run_id", "domain_key"},
		{{"title", "string"}, {"description", "string"}, {"confidence", "number"}}
	));

	tools.push_back(create_tool_schema(
		"llm.domain_set_members",
		"Replace members of a domain with a provided list of object_ids and optional roles/confidences.",
		{"agent_run_id", "run_id", "domain_key", "members"},
		{}
	));

	tools.push_back(create_tool_schema(
		"llm.metric_upsert",
		"Upsert a metric/KPI definition with optional SQL template and dependencies.",
		{"agent_run_id", "run_id", "metric_key", "title"},
		{{"description", "string"}, {"domain_key", "string"}, {"grain", "string"}, {"unit", "string"}, {"sql_template", "string"}, {"depends", "object"}, {"confidence", "number"}}
	));

	tools.push_back(create_tool_schema(
		"llm.question_template_add",
		"Add a question template (NL) mapped to a structured query plan. Extract table/view names from example_sql and populate related_objects. agent_run_id is optional - if not provided, uses the last agent run for the schema.",
		{"run_id", "title", "question_nl", "template"},
		{{"agent_run_id", "integer"}, {"example_sql", "string"}, {"related_objects", "array"}, {"confidence", "number"}}
	));

	tools.push_back(create_tool_schema(
		"llm.note_add",
		"Add a durable free-form note (global/schema/object/domain scoped) for the agent memory.",
		{"agent_run_id", "run_id", "scope", "body"},
		{{"object_id", "integer"}, {"domain_key", "string"}, {"title", "string"}, {"tags", "array"}}
	));

	tools.push_back(create_tool_schema(
		"llm.search",
		"Full-text search across LLM artifacts. For question_templates, returns example_sql, related_objects, template_json, and confidence. Use include_objects=true with a non-empty query to get full object schema details (for search mode only). Empty query (list mode) returns only templates without objects to avoid huge responses.",
		{"run_id"},
		{{"query", "string"}, {"limit", "integer"}, {"include_objects", "boolean"}}
	));

	// ============================================================
	// STATISTICS TOOLS
	// ============================================================
	tools.push_back(create_tool_schema(
		"stats.get_tool_usage",
		"Get in-memory tool usage statistics grouped by tool name and schema.",
		{},
		{}
	));

	json result;
	result["tools"] = tools;
	return result;
}

json Query_Tool_Handler::get_tool_description(const std::string& tool_name) {
	json tools_list = get_tool_list();
	for (const auto& tool : tools_list["tools"]) {
		if (tool["name"] == tool_name) {
			return tool;
		}
	}
	return create_error_response("Tool not found: " + tool_name);
}

/**
 * @brief Extract schema name from tool arguments
 * Returns "(no schema)" for tools without schema context
 */
static std::string extract_schema_name(const std::string& tool_name, const json& arguments, Discovery_Schema* catalog) {
	// Tools that use run_id (can be resolved to schema)
	if (arguments.contains("run_id")) {
		std::string run_id_str = json_string(arguments, "run_id");
		int run_id = catalog->resolve_run_id(run_id_str);
		if (run_id > 0) {
			// Look up schema name from catalog
			char* error = NULL;
			int cols = 0, affected = 0;
			SQLite3_result* resultset = NULL;

			std::ostringstream sql;
			sql << "SELECT schema_name FROM schemas WHERE run_id = " << run_id << " LIMIT 1;";

			catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);
			if (resultset && resultset->rows_count > 0) {
				SQLite3_row* row = resultset->rows[0];
				std::string schema = std::string(row->fields[0] ? row->fields[0] : "");
				delete resultset;
				return schema;
			}
			if (resultset) delete resultset;
		}
		return std::to_string(run_id);
	}

	// Tools that use schema_name directly
	if (arguments.contains("schema_name")) {
		return json_string(arguments, "schema_name");
	}

	// Tools without schema context
	return "(no schema)";
}

/**
 * @brief Track tool invocation (thread-safe)
 */
void track_tool_invocation(
	Query_Tool_Handler* handler,
	const std::string& tool_name,
	const std::string& schema_name,
	unsigned long long duration_us
) {
	pthread_mutex_lock(&handler->counters_lock);
	handler->tool_usage_stats[tool_name][schema_name].add_timing(duration_us, monotonic_time());
	pthread_mutex_unlock(&handler->counters_lock);
}

json Query_Tool_Handler::execute_tool(const std::string& tool_name, const json& arguments) {
	// Start timing
	unsigned long long start_time = monotonic_time();

	std::string schema = extract_schema_name(tool_name, arguments, catalog);
	json result;

	// ============================================================
	// INVENTORY TOOLS
	// ============================================================
	if (tool_name == "list_schemas") {
		std::string page_token = json_string(arguments, "page_token");
		int page_size = json_int(arguments, "page_size", 50);

		// Query catalog's schemas table instead of live database
		char* error = NULL;
		int cols = 0, affected = 0;
		SQLite3_result* resultset = NULL;

		std::ostringstream sql;
		sql << "SELECT DISTINCT schema_name FROM schemas ORDER BY schema_name";
		if (page_size > 0) {
			sql << " LIMIT " << page_size;
			if (!page_token.empty()) {
				sql << " OFFSET " << page_token;
			}
		}
		sql << ";";

		catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);
		if (error) {
			std::string err_msg = std::string("Failed to query catalog: ") + error;
			free(error);
			return create_error_response(err_msg);
		}

		// Build results array (as array of arrays to match original format)
		json results = json::array();
		if (resultset && resultset->rows_count > 0) {
			for (const auto& row : resultset->rows) {
				if (row->cnt > 0 && row->fields[0]) {
					json schema_row = json::array();
					schema_row.push_back(std::string(row->fields[0]));
					results.push_back(schema_row);
				}
			}
		}
		delete resultset;

		// Return in format matching original: {columns: 1, rows: [[schema], ...]}
		json output;
		output["columns"] = 1;
		output["rows"] = results;
		output["success"] = true;

		result = create_success_response(output);
	}

	else if (tool_name == "list_tables") {
		std::string schema = json_string(arguments, "schema");
		std::string page_token = json_string(arguments, "page_token");
		int page_size = json_int(arguments, "page_size", 50);
		std::string name_filter = json_string(arguments, "name_filter");

		// Validate schema identifier if provided
		if (!schema.empty()) {
			std::string validated = validate_sql_identifier_sqlite(schema);
			if (validated.empty()) {
				result = create_error_response("Invalid schema name: contains unsafe characters");
				return result;  // Early return on validation failure
			} else {
				schema = validated;
			}
		}

		// TODO: Implement using MySQL connection
		std::ostringstream sql;
		sql << "SHOW TABLES";
		if (!schema.empty()) {
			sql << " FROM " << schema;
		}
		if (!name_filter.empty()) {
			// Escape the name_filter to prevent SQL injection
			sql << " LIKE '" << escape_string_literal(name_filter) << "'";
		}
		std::string query_result = execute_query(sql.str());
		result = create_success_response(json::parse(query_result));
	}

	// ============================================================
	// STRUCTURE TOOLS
	// ============================================================
	else if (tool_name == "get_constraints") {
		// Return deprecation warning with migration path
		result = create_error_response(
			"DEPRECATED: The 'get_constraints' tool is deprecated. "
			"Use 'catalog.get_relationships' with run_id='<schema_name>' (or numeric run_id) "
			"and object_key='schema.table' instead. "
			"Example: catalog.get_relationships(run_id='your_schema', object_key='schema.table')"
		);
	}

	// ============================================================
	// DISCOVERY TOOLS
	// ============================================================
	else if (tool_name == "discovery.run_static") {
		if (!harvester) {
			result = create_error_response("Static harvester not configured");
		} else {
			std::string schema_filter = json_string(arguments, "schema_filter");
			if (schema_filter.empty()) {
				result = create_error_response("schema_filter is required and must not be empty");
			} else {
				std::string notes = json_string(arguments, "notes", "Static discovery harvest");

				int run_id = harvester->run_full_harvest(schema_filter, notes);
				if (run_id < 0) {
					result = create_error_response("Static discovery failed");
				} else {
					// Get stats using the run_id (after finish_run() has reset current_run_id)
					std::string stats_str = harvester->get_harvest_stats(run_id);
					json stats;
					try {
						stats = json::parse(stats_str);
					} catch (...) {
						stats["run_id"] = run_id;
					}

					stats["started_at"] = "";
					stats["mysql_version"] = "";
					result = create_success_response(stats);
				}
			}
		}
	}

	// ============================================================
	// CATALOG TOOLS (Discovery_Schema)
	// ============================================================
	else if (tool_name == "catalog.init") {
		std::string sqlite_path = json_string(arguments, "sqlite_path");
		if (sqlite_path.empty()) {
			sqlite_path = catalog->get_db_path();
		}
		// Catalog already initialized, just return success
		json init_result;
		init_result["sqlite_path"] = sqlite_path;
		init_result["status"] = "initialized";
		result = create_success_response(init_result);
	}

	else if (tool_name == "catalog.search") {
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string query = json_string(arguments, "query");
		int limit = json_int(arguments, "limit", 25);
		std::string object_type = json_string(arguments, "object_type");
		std::string schema_name = json_string(arguments, "schema_name");

		if (run_id_or_schema.empty()) {
			result = create_error_response("run_id is required");
		} else if (query.empty()) {
			result = create_error_response("query is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found: " + run_id_or_schema);
			} else {
				std::string search_results = catalog->fts_search(run_id, query, limit, object_type, schema_name);
				try {
					result = create_success_response(json::parse(search_results));
				} catch (...) {
					result = create_error_response("Failed to parse search results");
				}
			}
		}
	}

	else if (tool_name == "catalog.get_object") {
		std::string run_id_or_schema = json_string(arguments, "run_id");
		int object_id = json_int(arguments, "object_id", -1);
		std::string object_key = json_string(arguments, "object_key");
		bool include_definition = json_int(arguments, "include_definition", 0) != 0;
		bool include_profiles = json_int(arguments, "include_profiles", 1) != 0;

		if (run_id_or_schema.empty()) {
			result = create_error_response("run_id is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found: " + run_id_or_schema);
			} else {
				std::string schema_name, object_name;
				if (!object_key.empty()) {
					size_t dot_pos = object_key.find('.');
					if (dot_pos != std::string::npos) {
						schema_name = object_key.substr(0, dot_pos);
						object_name = object_key.substr(dot_pos + 1);
					}
				}

				std::string obj_result = catalog->get_object(
					run_id, object_id, schema_name, object_name,
					include_definition, include_profiles
				);
				try {
					json parsed = json::parse(obj_result);
					if (parsed.is_null()) {
						result = create_error_response("Object not found");
					} else {
						result = create_success_response(parsed);
					}
				} catch (...) {
					result = create_error_response("Failed to parse object data");
				}
			}
		}
	}

	else if (tool_name == "catalog.list_objects") {
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string schema_name = json_string(arguments, "schema_name");
		std::string object_type = json_string(arguments, "object_type");
		std::string order_by = json_string(arguments, "order_by", "name");
		int page_size = json_int(arguments, "page_size", 50);
		std::string page_token = json_string(arguments, "page_token");

		if (run_id_or_schema.empty()) {
			result = create_error_response("run_id is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found: " + run_id_or_schema);
			} else {
				std::string list_result = catalog->list_objects(
					run_id, schema_name, object_type, order_by, page_size, page_token
				);
				try {
					result = create_success_response(json::parse(list_result));
				} catch (...) {
					result = create_error_response("Failed to parse objects list");
				}
			}
		}
	}

	else if (tool_name == "catalog.get_relationships") {
		std::string run_id_or_schema = json_string(arguments, "run_id");
		int object_id = json_int(arguments, "object_id", -1);
		std::string object_key = json_string(arguments, "object_key");
		bool include_inferred = json_int(arguments, "include_inferred", 1) != 0;
		double min_confidence = json_double(arguments, "min_confidence", 0.0);

		if (run_id_or_schema.empty()) {
			result = create_error_response("run_id is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found: " + run_id_or_schema);
			} else {
				// Resolve object_key to object_id if needed
				if (object_id < 0 && !object_key.empty()) {
					size_t dot_pos = object_key.find('.');
					if (dot_pos != std::string::npos) {
						std::string schema = object_key.substr(0, dot_pos);
						std::string table = object_key.substr(dot_pos + 1);

						// Validate identifiers to prevent SQL injection
						std::string validated_schema = validate_sql_identifier_sqlite(schema);
						std::string validated_table = validate_sql_identifier_sqlite(table);

						if (validated_schema.empty() || validated_table.empty()) {
							result = create_error_response("Invalid object_key: contains unsafe characters");
						} else {
							// Quick query to get object_id
							char* error = NULL;
							int cols = 0, affected = 0;
							SQLite3_result* resultset = NULL;
							std::ostringstream sql;
							sql << "SELECT object_id FROM objects WHERE run_id = " << run_id
							    << " AND schema_name = '" << validated_schema << "'"
							    << " AND object_name = '" << validated_table << "' LIMIT 1;";
							catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);
							if (resultset && !resultset->rows.empty()) {
								object_id = atoi(resultset->rows[0]->fields[0]);
							}
							delete resultset;
						}
					}
				}

				if (object_id < 0 && result.is_null()) {
					result = create_error_response("Valid object_id or object_key is required");
				} else if (!result.is_null()) {
					// Already have an error result from validation
				} else {
					std::string rel_result = catalog->get_relationships(run_id, object_id, include_inferred, min_confidence);
					try {
						result = create_success_response(json::parse(rel_result));
					} catch (...) {
						result = create_error_response("Failed to parse relationships");
					}
				}
			}
		}
	}

	// ============================================================
	// AGENT TOOLS
	// ============================================================
	else if (tool_name == "agent.run_start") {
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string model_name = json_string(arguments, "model_name");
		std::string prompt_hash = json_string(arguments, "prompt_hash");

		std::string budget_json;
		if (arguments.contains("budget") && !arguments["budget"].is_null()) {
			budget_json = arguments["budget"].dump();
		}

		if (run_id_or_schema.empty()) {
			result = create_error_response("run_id is required");
		} else if (model_name.empty()) {
			result = create_error_response("model_name is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found: " + run_id_or_schema);
			} else {
				int agent_run_id = catalog->create_agent_run(run_id, model_name, prompt_hash, budget_json);
				if (agent_run_id < 0) {
					result = create_error_response("Failed to create agent run");
				} else {
					json agent_result;
					agent_result["agent_run_id"] = agent_run_id;
					agent_result["run_id"] = run_id;
					agent_result["model_name"] = model_name;
					agent_result["status"] = "running";
					result = create_success_response(agent_result);
				}
			}
		}
	}

	else if (tool_name == "agent.run_finish") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string status = json_string(arguments, "status");
		std::string error = json_string(arguments, "error");

		if (agent_run_id <= 0) {
			result = create_error_response("agent_run_id is required");
		} else if (status != "success" && status != "failed") {
			result = create_error_response("status must be 'success' or 'failed'");
		} else {
			int rc = catalog->finish_agent_run(agent_run_id, status, error);
			if (rc) {
				result = create_error_response("Failed to finish agent run");
			} else {
				json finish_result;
				finish_result["agent_run_id"] = agent_run_id;
				finish_result["status"] = status;
				result = create_success_response(finish_result);
			}
		}
	}

	else if (tool_name == "agent.event_append") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string event_type = json_string(arguments, "event_type");

		std::string payload_json;
		if (arguments.contains("payload")) {
			payload_json = arguments["payload"].dump();
		}

		if (agent_run_id <= 0) {
			result = create_error_response("agent_run_id is required");
		} else if (event_type.empty()) {
			result = create_error_response("event_type is required");
		} else {
			int event_id = catalog->append_agent_event(agent_run_id, event_type, payload_json);
			if (event_id < 0) {
				result = create_error_response("Failed to append event");
			} else {
				json event_result;
				event_result["event_id"] = event_id;
				result = create_success_response(event_result);
			}
		}
	}

	// ============================================================
	// LLM MEMORY TOOLS
	// ============================================================
	else if (tool_name == "llm.summary_upsert") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		int object_id = json_int(arguments, "object_id");

		std::string summary_json;
		if (arguments.contains("summary")) {
			summary_json = arguments["summary"].dump();
		}

		double confidence = json_double(arguments, "confidence", 0.5);
		std::string status = json_string(arguments, "status", "draft");

		std::string sources_json;
		if (arguments.contains("sources") && !arguments["sources"].is_null()) {
			sources_json = arguments["sources"].dump();
		}

		if (agent_run_id <= 0 || run_id_or_schema.empty() || object_id <= 0) {
			result = create_error_response("agent_run_id, run_id, and object_id are required");
		} else if (summary_json.empty()) {
			result = create_error_response("summary is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found: " + run_id_or_schema);
			} else {
				int rc = catalog->upsert_llm_summary(
					agent_run_id, run_id, object_id, summary_json,
					confidence, status, sources_json
				);
				if (rc) {
					result = create_error_response("Failed to upsert summary");
				} else {
					json sum_result;
					sum_result["object_id"] = object_id;
					sum_result["status"] = "upserted";
					result = create_success_response(sum_result);
				}
			}
		}
	}

	else if (tool_name == "llm.summary_get") {
		std::string run_id_or_schema = json_string(arguments, "run_id");
		int object_id = json_int(arguments, "object_id");
		int agent_run_id = json_int(arguments, "agent_run_id", -1);
		bool latest = json_int(arguments, "latest", 1) != 0;

		if (run_id_or_schema.empty() || object_id <= 0) {
			result = create_error_response("run_id and object_id are required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found: " + run_id_or_schema);
			} else {
				std::string sum_result = catalog->get_llm_summary(run_id, object_id, agent_run_id, latest);
				try {
					json parsed = json::parse(sum_result);
					if (parsed.is_null()) {
						result = create_error_response("Summary not found");
					} else {
						result = create_success_response(parsed);
					}
				} catch (...) {
					result = create_error_response("Failed to parse summary");
				}
			}
		}
	}

	else if (tool_name == "llm.relationship_upsert") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		int child_object_id = json_int(arguments, "child_object_id");
		std::string child_column = json_string(arguments, "child_column");
		int parent_object_id = json_int(arguments, "parent_object_id");
		std::string parent_column = json_string(arguments, "parent_column");
		double confidence = json_double(arguments, "confidence");

		std::string rel_type = json_string(arguments, "rel_type", "fk_like");
		std::string evidence_json;
		if (arguments.contains("evidence")) {
			evidence_json = arguments["evidence"].dump();
		}

		if (agent_run_id <= 0 || run_id_or_schema.empty() || child_object_id <= 0 || parent_object_id <= 0) {
			result = create_error_response("agent_run_id, run_id, child_object_id, and parent_object_id are required");
		} else if (child_column.empty() || parent_column.empty()) {
			result = create_error_response("child_column and parent_column are required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found: " + run_id_or_schema);
			} else {
				int rc = catalog->upsert_llm_relationship(
					agent_run_id, run_id, child_object_id, child_column,
					parent_object_id, parent_column, rel_type, confidence, evidence_json
				);
				if (rc) {
					result = create_error_response("Failed to upsert relationship");
				} else {
					json rel_result;
					rel_result["status"] = "upserted";
					result = create_success_response(rel_result);
				}
			}
		}
	}

	else if (tool_name == "llm.domain_upsert") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string domain_key = json_string(arguments, "domain_key");
		std::string title = json_string(arguments, "title");
		std::string description = json_string(arguments, "description");
		double confidence = json_double(arguments, "confidence", 0.6);

		if (agent_run_id <= 0 || run_id_or_schema.empty() || domain_key.empty()) {
			result = create_error_response("agent_run_id, run_id, and domain_key are required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found: " + run_id_or_schema);
			} else {
				int domain_id = catalog->upsert_llm_domain(
					agent_run_id, run_id, domain_key, title, description, confidence
				);
				if (domain_id < 0) {
					result = create_error_response("Failed to upsert domain");
				} else {
					json domain_result;
					domain_result["domain_id"] = domain_id;
					domain_result["domain_key"] = domain_key;
					result = create_success_response(domain_result);
				}
			}
		}
	}

	else if (tool_name == "llm.domain_set_members") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string domain_key = json_string(arguments, "domain_key");

		std::string members_json;
		if (arguments.contains("members")) {
			const json& members = arguments["members"];
			if (members.is_array()) {
				// Array passed directly - serialize it
				members_json = members.dump();
			} else if (members.is_string()) {
				// JSON string passed - use it directly
				members_json = members.get<std::string>();
			}
		}

		if (agent_run_id <= 0 || run_id_or_schema.empty() || domain_key.empty()) {
			result = create_error_response("agent_run_id, run_id, and domain_key are required");
		} else if (members_json.empty()) {
			proxy_error("llm.domain_set_members: members not provided or invalid type (got: %s)\n",
				arguments.contains("members") ? arguments["members"].dump().c_str() : "missing");
			result = create_error_response("members array is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found: " + run_id_or_schema);
			} else {
				proxy_debug(PROXY_DEBUG_GENERIC, 3, "llm.domain_set_members: setting members='%s'\n", members_json.c_str());
				int rc = catalog->set_domain_members(agent_run_id, run_id, domain_key, members_json);
				if (rc) {
					proxy_error("llm.domain_set_members: failed to set members (rc=%d)\n", rc);
					result = create_error_response("Failed to set domain members");
				} else {
					json members_result;
					members_result["domain_key"] = domain_key;
					members_result["status"] = "members_set";
					result = create_success_response(members_result);
				}
			}
		}
	}

	else if (tool_name == "llm.metric_upsert") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string metric_key = json_string(arguments, "metric_key");
		std::string title = json_string(arguments, "title");
		std::string description = json_string(arguments, "description");
		std::string domain_key = json_string(arguments, "domain_key");
		std::string grain = json_string(arguments, "grain");
		std::string unit = json_string(arguments, "unit");
		std::string sql_template = json_string(arguments, "sql_template");

		std::string depends_json;
		if (arguments.contains("depends")) {
			depends_json = arguments["depends"].dump();
		}

		double confidence = json_double(arguments, "confidence", 0.6);

		if (agent_run_id <= 0 || run_id_or_schema.empty() || metric_key.empty() || title.empty()) {
			result = create_error_response("agent_run_id, run_id, metric_key, and title are required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found: " + run_id_or_schema);
			} else {
				int metric_id = catalog->upsert_llm_metric(
					agent_run_id, run_id, metric_key, title, description, domain_key,
					grain, unit, sql_template, depends_json, confidence
				);
				if (metric_id < 0) {
					result = create_error_response("Failed to upsert metric");
				} else {
					json metric_result;
					metric_result["metric_id"] = metric_id;
					metric_result["metric_key"] = metric_key;
					result = create_success_response(metric_result);
				}
			}
		}
	}

	else if (tool_name == "llm.question_template_add") {
		int agent_run_id = json_int(arguments, "agent_run_id", 0);  // Optional, default 0
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string title = json_string(arguments, "title");
		std::string question_nl = json_string(arguments, "question_nl");

		std::string template_json;
		if (arguments.contains("template")) {
			template_json = arguments["template"].dump();
		}

		std::string example_sql = json_string(arguments, "example_sql");
		double confidence = json_double(arguments, "confidence", 0.6);

		// Extract related_objects as JSON array string
		std::string related_objects = "";
		if (arguments.contains("related_objects") && arguments["related_objects"].is_array()) {
			related_objects = arguments["related_objects"].dump();
		}

		if (run_id_or_schema.empty() || title.empty() || question_nl.empty()) {
			result = create_error_response("run_id, title, and question_nl are required");
		} else if (template_json.empty()) {
			result = create_error_response("template is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found: " + run_id_or_schema);
			} else {
				// If agent_run_id not provided, get the last one for this run_id
				if (agent_run_id <= 0) {
					agent_run_id = catalog->get_last_agent_run_id(run_id);
					if (agent_run_id <= 0) {
						result = create_error_response(
							"No agent run found for schema. Please run discovery first, or provide agent_run_id."
						);
					}
				}

				if (agent_run_id > 0) {
					int template_id = catalog->add_question_template(
						agent_run_id, run_id, title, question_nl, template_json, example_sql, related_objects, confidence
					);
					if (template_id < 0) {
						result = create_error_response("Failed to add question template");
					} else {
						json tmpl_result;
						tmpl_result["template_id"] = template_id;
						tmpl_result["agent_run_id"] = agent_run_id;
						tmpl_result["title"] = title;
						result = create_success_response(tmpl_result);
					}
				}
			}
		}
	}

	else if (tool_name == "llm.note_add") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string scope = json_string(arguments, "scope");
		int object_id = json_int(arguments, "object_id", -1);
		std::string domain_key = json_string(arguments, "domain_key");
		std::string title = json_string(arguments, "title");
		std::string body = json_string(arguments, "body");

		std::string tags_json;
		if (arguments.contains("tags") && arguments["tags"].is_array()) {
			tags_json = arguments["tags"].dump();
		}

		if (agent_run_id <= 0 || run_id_or_schema.empty() || scope.empty() || body.empty()) {
			result = create_error_response("agent_run_id, run_id, scope, and body are required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found: " + run_id_or_schema);
			} else {
				int note_id = catalog->add_llm_note(
					agent_run_id, run_id, scope, object_id, domain_key, title, body, tags_json
				);
				if (note_id < 0) {
					result = create_error_response("Failed to add note");
				} else {
					json note_result;
					note_result["note_id"] = note_id;
					result = create_success_response(note_result);
				}
			}
		}
	}

	else if (tool_name == "llm.search") {
		std::string run_id_or_schema = json_string(arguments, "run_id");
		std::string query = json_string(arguments, "query");
		int limit = json_int(arguments, "limit", 25);
		bool include_objects = json_int(arguments, "include_objects", 0) != 0;

		if (run_id_or_schema.empty()) {
			result = create_error_response("run_id is required");
		} else {
			// Resolve schema name to run_id if needed
			int run_id = catalog->resolve_run_id(run_id_or_schema);
			if (run_id < 0) {
				result = create_error_response("Invalid run_id or schema not found: " + run_id_or_schema);
			} else {
				// Log the search query
				catalog->log_llm_search(run_id, query, limit);

				std::string search_results = catalog->fts_search_llm(run_id, query, limit, include_objects);
				try {
					result = create_success_response(json::parse(search_results));
				} catch (...) {
					result = create_error_response("Failed to parse LLM search results");
				}
			}
		}
	}

	// ============================================================
	// QUERY TOOLS
	// ============================================================
	else if (tool_name == "run_sql_readonly") {
		std::string sql = json_string(arguments, "sql");
		std::string schema = json_string(arguments, "schema");
		int max_rows = json_int(arguments, "max_rows", 200);
		int timeout_sec = json_int(arguments, "timeout_sec", 2);

		if (sql.empty()) {
			result = create_error_response("sql is required");
		} else {
			// ============================================================
			// MCP QUERY RULES EVALUATION
			// ============================================================
			MCP_Query_Processor_Output* qpo = catalog->evaluate_mcp_query_rules(
				tool_name,
				schema,
				arguments,
				sql
			);

			// Check for OK_msg (return success without executing)
			if (qpo->OK_msg) {
				unsigned long long duration = monotonic_time() - start_time;
				track_tool_invocation(this, tool_name, schema, duration);
				catalog->log_query_tool_call(tool_name, schema, 0, start_time, duration, "OK message from query rule");
				result = create_success_response(qpo->OK_msg);
				delete qpo;
				return result;
			}

			// Check for error_msg (block the query)
			if (qpo->error_msg) {
				unsigned long long duration = monotonic_time() - start_time;
				track_tool_invocation(this, tool_name, schema, duration);
				catalog->log_query_tool_call(tool_name, schema, 0, start_time, duration, "Blocked by query rule");
				result = create_error_response(qpo->error_msg);
				delete qpo;
				return result;
			}

			// Apply rewritten query if provided
			if (qpo->new_query) {
				sql = *qpo->new_query;
			}

			// Apply timeout if provided
			if (qpo->timeout_ms > 0) {
				// Use ceiling division to ensure sub-second timeouts are at least 1 second
				timeout_sec = (qpo->timeout_ms + 999) / 1000;
			}

			// Apply log flag if set
			if (qpo->log == 1) {
				// TODO: Implement query logging if needed
			}

			delete qpo;

			// Continue with validation and execution
			if (!validate_readonly_query(sql)) {
				result = create_error_response("SQL is not read-only");
			} else if (is_dangerous_query(sql)) {
				result = create_error_response("SQL contains dangerous operations");
			} else {
				std::string query_result = execute_query_with_schema(sql, schema);
				try {
					json result_json = json::parse(query_result);
					// Check if query actually failed
					if (result_json.contains("success") && !result_json["success"]) {
						result = create_error_response(result_json["error"]);
					} else {
						// ============================================================
						// MCP QUERY DIGEST TRACKING (on success)
						// ============================================================
						// Track successful MCP tool calls for statistics aggregation.
						// This computes a digest hash (similar to MySQL query digest) that
						// groups similar queries together by replacing literal values with
						// placeholders. Statistics are accumulated per digest and can be
						// queried via the stats_mcp_query_digest table.
						//
						// Process:
						//   1. Compute digest hash using fingerprinted arguments
						//   2. Store/aggregate statistics in the digest map (count, timing)
						//   3. Stats are available via stats_mcp_query_digest table
						//
						// Statistics tracked:
						//   - count_star: Number of times this digest was executed
						//   - sum_time, min_time, max_time: Execution timing metrics
						//   - first_seen, last_seen: Timestamps for occurrence tracking
						uint64_t digest = Discovery_Schema::compute_mcp_digest(tool_name, arguments);
						std::string digest_text = Discovery_Schema::fingerprint_mcp_args(arguments);
						unsigned long long duration = monotonic_time() - start_time;
						int digest_run_id = schema.empty() ? 0 : catalog->resolve_run_id(schema);
						catalog->update_mcp_query_digest(
							tool_name,
							digest_run_id,
							digest,
							digest_text,
							duration,
							time(NULL)
						);
						result = create_success_response(result_json);
					}
				} catch (...) {
					result = create_success_response(query_result);
				}
			}
		}
	}

	else if (tool_name == "explain_sql") {
		std::string sql = json_string(arguments, "sql");
		if (sql.empty()) {
			result = create_error_response("sql is required");
		} else {
			std::string query_result = execute_query("EXPLAIN " + sql);
			try {
				result = create_success_response(json::parse(query_result));
			} catch (...) {
				result = create_success_response(query_result);
			}
		}
	}

	// ============================================================
	// RELATIONSHIP INFERENCE TOOLS (DEPRECATED)
	// ============================================================
	else if (tool_name == "suggest_joins") {
		// Return deprecation warning with migration path
		result = create_error_response(
			"DEPRECATED: The 'suggest_joins' tool is deprecated. "
			"Use 'catalog.get_relationships' with run_id='<schema_name>' instead. "
			"This provides foreign keys, view dependencies, and LLM-inferred relationships."
		);
	}

	else if (tool_name == "find_reference_candidates") {
		// Return deprecation warning with migration path
		result = create_error_response(
			"DEPRECATED: The 'find_reference_candidates' tool is deprecated. "
			"Use 'catalog.get_relationships' with run_id='<schema_name>' instead. "
			"This provides foreign keys, view dependencies, and LLM-inferred relationships."
		);
	}

	// ============================================================
	// STATISTICS TOOLS
	// ============================================================
	else if (tool_name == "stats.get_tool_usage") {
		ToolUsageStatsMap stats = get_tool_usage_stats();
		json stats_result = json::object();
		for (ToolUsageStatsMap::const_iterator it = stats.begin(); it != stats.end(); ++it) {
			const std::string& tool_name = it->first;
			const SchemaStatsMap& schemas = it->second;
			json schema_stats = json::object();
			for (SchemaStatsMap::const_iterator sit = schemas.begin(); sit != schemas.end(); ++sit) {
				json stats_obj = json::object();
				stats_obj["count"] = sit->second.count;
				stats_obj["first_seen"] = sit->second.first_seen;
				stats_obj["last_seen"] = sit->second.last_seen;
				stats_obj["sum_time"] = sit->second.sum_time;
				stats_obj["min_time"] = sit->second.min_time;
				stats_obj["max_time"] = sit->second.max_time;
				schema_stats[sit->first] = stats_obj;
			}
			stats_result[tool_name] = schema_stats;
		}
		result = create_success_response(stats_result);
	}

	// ============================================================
	// FALLBACK - UNKNOWN TOOL
	// ============================================================
	else {
		result = create_error_response("Unknown tool: " + tool_name);
	}

	// Track invocation with timing
	unsigned long long duration = monotonic_time() - start_time;
	track_tool_invocation(this, tool_name, schema, duration);

	// Log tool invocation to catalog
	int run_id = 0;
	std::string run_id_str = json_string(arguments, "run_id");
	if (!run_id_str.empty()) {
		run_id = catalog->resolve_run_id(run_id_str);
	}

	// Extract error message if present
	std::string error_msg;
	if (result.contains("error")) {
		const json& err = result["error"];
		if (err.is_string()) {
			error_msg = err.get<std::string>();
		}
	}

	catalog->log_query_tool_call(tool_name, schema, run_id, start_time, duration, error_msg);

	return result;
}

Query_Tool_Handler::ToolUsageStatsMap Query_Tool_Handler::get_tool_usage_stats() {
	// Thread-safe copy of counters
	pthread_mutex_lock(&counters_lock);
	ToolUsageStatsMap copy = tool_usage_stats;
	pthread_mutex_unlock(&counters_lock);
	return copy;
}

SQLite3_result* Query_Tool_Handler::get_tool_usage_stats_resultset(bool reset) {
	SQLite3_result* result = new SQLite3_result(8);
	result->add_column_definition(SQLITE_TEXT, "tool");
	result->add_column_definition(SQLITE_TEXT, "schema");
	result->add_column_definition(SQLITE_TEXT, "count");
	result->add_column_definition(SQLITE_TEXT, "first_seen");
	result->add_column_definition(SQLITE_TEXT, "last_seen");
	result->add_column_definition(SQLITE_TEXT, "sum_time");
	result->add_column_definition(SQLITE_TEXT, "min_time");
	result->add_column_definition(SQLITE_TEXT, "max_time");

	pthread_mutex_lock(&counters_lock);

	for (ToolUsageStatsMap::const_iterator tool_it = tool_usage_stats.begin();
	     tool_it != tool_usage_stats.end(); ++tool_it) {
		const std::string& tool_name = tool_it->first;
		const SchemaStatsMap& schemas = tool_it->second;

		for (SchemaStatsMap::const_iterator schema_it = schemas.begin();
		     schema_it != schemas.end(); ++schema_it) {
			const std::string& schema_name = schema_it->first;
			const ToolUsageStats& stats = schema_it->second;

			char** row = new char*[8];
			row[0] = strdup(tool_name.c_str());
			row[1] = strdup(schema_name.c_str());

			char buf[32];
			snprintf(buf, sizeof(buf), "%llu", stats.count);
			row[2] = strdup(buf);
			snprintf(buf, sizeof(buf), "%llu", stats.first_seen);
			row[3] = strdup(buf);
			snprintf(buf, sizeof(buf), "%llu", stats.last_seen);
			row[4] = strdup(buf);
			snprintf(buf, sizeof(buf), "%llu", stats.sum_time);
			row[5] = strdup(buf);
			snprintf(buf, sizeof(buf), "%llu", stats.min_time);
			row[6] = strdup(buf);
			snprintf(buf, sizeof(buf), "%llu", stats.max_time);
			row[7] = strdup(buf);

			result->add_row(row);
		}
	}

	if (reset) {
		tool_usage_stats.clear();
	}

	pthread_mutex_unlock(&counters_lock);
	return result;
}
