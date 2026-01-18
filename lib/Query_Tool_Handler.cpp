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

// Helper to safely get string from JSON
static std::string json_string(const json& j, const std::string& key, const std::string& default_val = "") {
	if (j.contains(key) && !j[key].is_null()) {
		if (j[key].is_string()) {
			return j[key].get<std::string>();
		}
		return j[key].dump();
	}
	return default_val;
}

// Helper to safely get int from JSON
static int json_int(const json& j, const std::string& key, int default_val = 0) {
	if (j.contains(key) && !j[key].is_null()) {
		return j[key].get<int>();
	}
	return default_val;
}

static double json_double(const json& j, const std::string& key, double default_val = 0.0) {
	if (j.contains(key) && !j[key].is_null()) {
		return j[key].get<double>();
	}
	return default_val;
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

std::string Query_Tool_Handler::execute_query(const std::string& query) {
	void* mysql = get_connection();
	if (!mysql) {
		return "{\"error\": \"No available connection\"}";
	}

	std::string result = "{\"error\": \"Query execution failed\"}";

	if (mysql_query(static_cast<MYSQL*>(mysql), query.c_str())) {
		proxy_error("Query_Tool_Handler: Query failed: %s\n", mysql_error(static_cast<MYSQL*>(mysql)));
		return_connection(mysql);
	}

	MYSQL_RES* res = mysql_store_result(static_cast<MYSQL*>(mysql));
	return_connection(mysql);

	if (!res) {
		// No result set (e.g., INSERT/UPDATE)
		json j;
		j["success"] = true;
		j["affected_rows"] = static_cast<long>(mysql_affected_rows(static_cast<MYSQL*>(mysql)));
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

	// Check for dangerous keywords
	std::vector<std::string> dangerous = {
		"INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
		"TRUNCATE", "REPLACE", "LOAD", "CALL", "EXECUTE"
	};

	for (const auto& word : dangerous) {
		if (upper.find(word) != std::string::npos) {
			return false;
		}
	}

	// Must start with SELECT or WITH or EXPLAIN
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
		"describe_table",
		"Get detailed table schema including columns, types, keys, and indexes",
		{"schema", "table"},
		{}
	));

	tools.push_back(create_tool_schema(
		"get_constraints",
		"Get constraints (foreign keys, unique constraints, etc.) for a table",
		{"schema"},
		{{"table", "string"}}
	));

	// ============================================================
	// PROFILING TOOLS
	// ============================================================
	tools.push_back(create_tool_schema(
		"table_profile",
		"Get table statistics including row count, size estimates, and data distribution",
		{"schema", "table"},
		{{"mode", "string"}}
	));

	tools.push_back(create_tool_schema(
		"column_profile",
		"Get column statistics including distinct values, null count, and top values",
		{"schema", "table", "column"},
		{{"max_top_values", "integer"}}
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
		"Execute a read-only SQL query with safety guardrails enforced",
		{"sql"},
		{{"max_rows", "integer"}, {"timeout_sec", "integer"}}
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
		"Suggest table joins based on heuristic analysis of column names and types",
		{"schema", "table_a"},
		{{"table_b", "string"}, {"max_candidates", "integer"}}
	));

	tools.push_back(create_tool_schema(
		"find_reference_candidates",
		"Find tables that might be referenced by a foreign key column",
		{"schema", "table", "column"},
		{{"max_tables", "integer"}}
	));

	// ============================================================
	// DISCOVERY TOOLS (Phase 1: Static Discovery)
	// ============================================================
	tools.push_back(create_tool_schema(
		"discovery.run_static",
		"Trigger ProxySQL to perform static metadata harvest from MySQL INFORMATION_SCHEMA. Returns the new run_id for subsequent LLM analysis.",
		{},
		{{"schema_filter", "string"}, {"notes", "string"}}
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
		"Add a question template (NL) mapped to a structured query plan (and optional example SQL).",
		{"agent_run_id", "run_id", "title", "question_nl", "template"},
		{{"example_sql", "string"}, {"confidence", "number"}}
	));

	tools.push_back(create_tool_schema(
		"llm.note_add",
		"Add a durable free-form note (global/schema/object/domain scoped) for the agent memory.",
		{"agent_run_id", "run_id", "scope", "body"},
		{{"object_id", "integer"}, {"domain_key", "string"}, {"title", "string"}, {"tags", "array"}}
	));

	tools.push_back(create_tool_schema(
		"llm.search",
		"Full-text search across LLM artifacts (summaries/domains/metrics/templates/notes) using fts_llm.",
		{"run_id", "query"},
		{{"limit", "integer"}}
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

json Query_Tool_Handler::execute_tool(const std::string& tool_name, const json& arguments) {
	// ============================================================
	// INVENTORY TOOLS
	// ============================================================
	if (tool_name == "list_schemas") {
		std::string page_token = json_string(arguments, "page_token");
		int page_size = json_int(arguments, "page_size", 50);
		// TODO: Implement using MySQL connection
		std::string result = execute_query("SHOW DATABASES;");
		return create_success_response(json::parse(result));
	}

	if (tool_name == "list_tables") {
		std::string schema = json_string(arguments, "schema");
		std::string page_token = json_string(arguments, "page_token");
		int page_size = json_int(arguments, "page_size", 50);
		std::string name_filter = json_string(arguments, "name_filter");
		// TODO: Implement using MySQL connection
		std::ostringstream sql;
		sql << "SHOW TABLES";
		if (!schema.empty()) {
			sql << " FROM " << schema;
		}
		if (!name_filter.empty()) {
			sql << " LIKE '" << name_filter << "'";
		}
		std::string result = execute_query(sql.str());
		return create_success_response(json::parse(result));
	}

	// ============================================================
	// STRUCTURE TOOLS
	// ============================================================
	if (tool_name == "describe_table") {
		std::string schema = json_string(arguments, "schema");
		std::string table = json_string(arguments, "table");
		// TODO: Implement using catalog.get_object or MySQL query
		std::ostringstream sql;
		sql << "DESCRIBE " << schema << "." << table;
		std::string result = execute_query(sql.str());
		return create_success_response(json::parse(result));
	}

	if (tool_name == "get_constraints") {
		std::string schema = json_string(arguments, "schema");
		std::string table = json_string(arguments, "table", "");
		// TODO: Implement using catalog.get_relationships or MySQL query
		std::ostringstream sql;
		sql << "SELECT CONSTRAINT_NAME, CONSTRAINT_TYPE, TABLE_NAME, COLUMN_NAME, "
		       "REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME "
		       "FROM information_schema.KEY_COLUMN_USAGE "
		       "WHERE TABLE_SCHEMA = '" << schema << "' ";
		if (!table.empty()) {
			sql << "AND TABLE_NAME = '" << table << "' ";
		}
		sql << "ORDER BY CONSTRAINT_NAME, ORDINAL_POSITION;";
		std::string result = execute_query(sql.str());
		return create_success_response(json::parse(result));
	}

	// ============================================================
	// DISCOVERY TOOLS
	// ============================================================
	if (tool_name == "discovery.run_static") {
		if (!harvester) {
			return create_error_response("Static harvester not configured");
		}
		std::string schema_filter = json_string(arguments, "schema_filter");
		std::string notes = json_string(arguments, "notes", "Static discovery harvest");

		int run_id = harvester->run_full_harvest(schema_filter, notes);
		if (run_id < 0) {
			return create_error_response("Static discovery failed");
		}

		std::string stats_str = harvester->get_harvest_stats();
		json stats;
		try {
			stats = json::parse(stats_str);
		} catch (...) {
			stats["run_id"] = run_id;
		}

		stats["started_at"] = "";
		stats["mysql_version"] = "";
		return create_success_response(stats);
	}

	// ============================================================
	// CATALOG TOOLS (Discovery_Schema)
	// ============================================================
	if (tool_name == "catalog.init") {
		std::string sqlite_path = json_string(arguments, "sqlite_path");
		if (sqlite_path.empty()) {
			sqlite_path = catalog->get_db_path();
		}
		// Catalog already initialized, just return success
		json result;
		result["sqlite_path"] = sqlite_path;
		result["status"] = "initialized";
		return create_success_response(result);
	}

	if (tool_name == "catalog.search") {
		int run_id = json_int(arguments, "run_id");
		std::string query = json_string(arguments, "query");
		int limit = json_int(arguments, "limit", 25);
		std::string object_type = json_string(arguments, "object_type");
		std::string schema_name = json_string(arguments, "schema_name");

		if (run_id <= 0) {
			return create_error_response("run_id is required");
		}
		if (query.empty()) {
			return create_error_response("query is required");
		}

		std::string results = catalog->fts_search(run_id, query, limit, object_type, schema_name);
		try {
			return create_success_response(json::parse(results));
		} catch (...) {
			return create_error_response("Failed to parse search results");
		}
	}

	if (tool_name == "catalog.get_object") {
		int run_id = json_int(arguments, "run_id");
		int object_id = json_int(arguments, "object_id", -1);
		std::string object_key = json_string(arguments, "object_key");
		bool include_definition = json_int(arguments, "include_definition", 0) != 0;
		bool include_profiles = json_int(arguments, "include_profiles", 1) != 0;

		if (run_id <= 0) {
			return create_error_response("run_id is required");
		}

		std::string schema_name, object_name;
		if (!object_key.empty()) {
			size_t dot_pos = object_key.find('.');
			if (dot_pos != std::string::npos) {
				schema_name = object_key.substr(0, dot_pos);
				object_name = object_key.substr(dot_pos + 1);
			}
		}

		std::string result = catalog->get_object(
			run_id, object_id, schema_name, object_name,
			include_definition, include_profiles
		);
		try {
			json parsed = json::parse(result);
			if (parsed.is_null()) {
				return create_error_response("Object not found");
			}
			return create_success_response(parsed);
		} catch (...) {
			return create_error_response("Failed to parse object data");
		}
	}

	if (tool_name == "catalog.list_objects") {
		int run_id = json_int(arguments, "run_id");
		std::string schema_name = json_string(arguments, "schema_name");
		std::string object_type = json_string(arguments, "object_type");
		std::string order_by = json_string(arguments, "order_by", "name");
		int page_size = json_int(arguments, "page_size", 50);
		std::string page_token = json_string(arguments, "page_token");

		if (run_id <= 0) {
			return create_error_response("run_id is required");
		}

		std::string result = catalog->list_objects(
			run_id, schema_name, object_type, order_by, page_size, page_token
		);
		try {
			return create_success_response(json::parse(result));
		} catch (...) {
			return create_error_response("Failed to parse objects list");
		}
	}

	if (tool_name == "catalog.get_relationships") {
		int run_id = json_int(arguments, "run_id");
		int object_id = json_int(arguments, "object_id", -1);
		std::string object_key = json_string(arguments, "object_key");
		bool include_inferred = json_int(arguments, "include_inferred", 1) != 0;
		double min_confidence = json_double(arguments, "min_confidence", 0.0);

		if (run_id <= 0) {
			return create_error_response("run_id is required");
		}

		// Resolve object_key to object_id if needed
		if (object_id < 0 && !object_key.empty()) {
			size_t dot_pos = object_key.find('.');
			if (dot_pos != std::string::npos) {
				std::string schema = object_key.substr(0, dot_pos);
				std::string table = object_key.substr(dot_pos + 1);
				// Quick query to get object_id
				char* error = NULL;
				int cols = 0, affected = 0;
				SQLite3_result* resultset = NULL;
				std::ostringstream sql;
				sql << "SELECT object_id FROM objects WHERE run_id = " << run_id
				    << " AND schema_name = '" << schema << "'"
				    << " AND object_name = '" << table << "' LIMIT 1;";
				catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);
				if (resultset && !resultset->rows.empty()) {
					object_id = atoi(resultset->rows[0]->fields[0]);
				}
				delete resultset;
			}
		}

		if (object_id < 0) {
			return create_error_response("Valid object_id or object_key is required");
		}

		std::string result = catalog->get_relationships(run_id, object_id, include_inferred, min_confidence);
		try {
			return create_success_response(json::parse(result));
		} catch (...) {
			return create_error_response("Failed to parse relationships");
		}
	}

	// ============================================================
	// AGENT TOOLS
	// ============================================================
	if (tool_name == "agent.run_start") {
		int run_id = json_int(arguments, "run_id");
		std::string model_name = json_string(arguments, "model_name");
		std::string prompt_hash = json_string(arguments, "prompt_hash");

		std::string budget_json;
		if (arguments.contains("budget") && !arguments["budget"].is_null()) {
			budget_json = arguments["budget"].dump();
		}

		if (run_id <= 0) {
			return create_error_response("run_id is required and must be positive");
		}
		if (model_name.empty()) {
			return create_error_response("model_name is required");
		}

		int agent_run_id = catalog->create_agent_run(run_id, model_name, prompt_hash, budget_json);
		if (agent_run_id < 0) {
			return create_error_response("Failed to create agent run");
		}

		json result;
		result["agent_run_id"] = agent_run_id;
		result["run_id"] = run_id;
		result["model_name"] = model_name;
		result["status"] = "running";
		return create_success_response(result);
	}

	if (tool_name == "agent.run_finish") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string status = json_string(arguments, "status");
		std::string error = json_string(arguments, "error");

		if (agent_run_id <= 0) {
			return create_error_response("agent_run_id is required");
		}
		if (status != "success" && status != "failed") {
			return create_error_response("status must be 'success' or 'failed'");
		}

		int rc = catalog->finish_agent_run(agent_run_id, status, error);
		if (rc) {
			return create_error_response("Failed to finish agent run");
		}

		json result;
		result["agent_run_id"] = agent_run_id;
		result["status"] = status;
		return create_success_response(result);
	}

	if (tool_name == "agent.event_append") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		std::string event_type = json_string(arguments, "event_type");

		std::string payload_json;
		if (arguments.contains("payload")) {
			payload_json = arguments["payload"].dump();
		}

		if (agent_run_id <= 0) {
			return create_error_response("agent_run_id is required");
		}
		if (event_type.empty()) {
			return create_error_response("event_type is required");
		}

		int event_id = catalog->append_agent_event(agent_run_id, event_type, payload_json);
		if (event_id < 0) {
			return create_error_response("Failed to append event");
		}

		json result;
		result["event_id"] = event_id;
		return create_success_response(result);
	}

	// ============================================================
	// LLM MEMORY TOOLS
	// ============================================================
	if (tool_name == "llm.summary_upsert") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		int run_id = json_int(arguments, "run_id");
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

		if (agent_run_id <= 0 || run_id <= 0 || object_id <= 0) {
			return create_error_response("agent_run_id, run_id, and object_id are required");
		}
		if (summary_json.empty()) {
			return create_error_response("summary is required");
		}

		int rc = catalog->upsert_llm_summary(
			agent_run_id, run_id, object_id, summary_json,
			confidence, status, sources_json
		);

		if (rc) {
			return create_error_response("Failed to upsert summary");
		}

		json result;
		result["object_id"] = object_id;
		result["status"] = "upserted";
		return create_success_response(result);
	}

	if (tool_name == "llm.summary_get") {
		int run_id = json_int(arguments, "run_id");
		int object_id = json_int(arguments, "object_id");
		int agent_run_id = json_int(arguments, "agent_run_id", -1);
		bool latest = json_int(arguments, "latest", 1) != 0;

		if (run_id <= 0 || object_id <= 0) {
			return create_error_response("run_id and object_id are required");
		}

		std::string result = catalog->get_llm_summary(run_id, object_id, agent_run_id, latest);
		try {
			json parsed = json::parse(result);
			if (parsed.is_null()) {
				return create_error_response("Summary not found");
			}
			return create_success_response(parsed);
		} catch (...) {
			return create_error_response("Failed to parse summary");
		}
	}

	if (tool_name == "llm.relationship_upsert") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		int run_id = json_int(arguments, "run_id");
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

		if (agent_run_id <= 0 || run_id <= 0 || child_object_id <= 0 || parent_object_id <= 0) {
			return create_error_response("agent_run_id, run_id, child_object_id, and parent_object_id are required");
		}
		if (child_column.empty() || parent_column.empty()) {
			return create_error_response("child_column and parent_column are required");
		}

		int rc = catalog->upsert_llm_relationship(
			agent_run_id, run_id, child_object_id, child_column,
			parent_object_id, parent_column, rel_type, confidence, evidence_json
		);

		if (rc) {
			return create_error_response("Failed to upsert relationship");
		}

		json result;
		result["status"] = "upserted";
		return create_success_response(result);
	}

	if (tool_name == "llm.domain_upsert") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		int run_id = json_int(arguments, "run_id");
		std::string domain_key = json_string(arguments, "domain_key");
		std::string title = json_string(arguments, "title");
		std::string description = json_string(arguments, "description");
		double confidence = json_double(arguments, "confidence", 0.6);

		if (agent_run_id <= 0 || run_id <= 0 || domain_key.empty()) {
			return create_error_response("agent_run_id, run_id, and domain_key are required");
		}

		int domain_id = catalog->upsert_llm_domain(
			agent_run_id, run_id, domain_key, title, description, confidence
		);

		if (domain_id < 0) {
			return create_error_response("Failed to upsert domain");
		}

		json result;
		result["domain_id"] = domain_id;
		result["domain_key"] = domain_key;
		return create_success_response(result);
	}

	if (tool_name == "llm.domain_set_members") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		int run_id = json_int(arguments, "run_id");
		std::string domain_key = json_string(arguments, "domain_key");

		std::string members_json;
		if (arguments.contains("members") && arguments["members"].is_array()) {
			members_json = arguments["members"].dump();
		}

		if (agent_run_id <= 0 || run_id <= 0 || domain_key.empty()) {
			return create_error_response("agent_run_id, run_id, and domain_key are required");
		}
		if (members_json.empty()) {
			return create_error_response("members array is required");
		}

		int rc = catalog->set_domain_members(agent_run_id, run_id, domain_key, members_json);
		if (rc) {
			return create_error_response("Failed to set domain members");
		}

		json result;
		result["domain_key"] = domain_key;
		result["status"] = "members_set";
		return create_success_response(result);
	}

	if (tool_name == "llm.metric_upsert") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		int run_id = json_int(arguments, "run_id");
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

		if (agent_run_id <= 0 || run_id <= 0 || metric_key.empty() || title.empty()) {
			return create_error_response("agent_run_id, run_id, metric_key, and title are required");
		}

		int metric_id = catalog->upsert_llm_metric(
			agent_run_id, run_id, metric_key, title, description, domain_key,
			grain, unit, sql_template, depends_json, confidence
		);

		if (metric_id < 0) {
			return create_error_response("Failed to upsert metric");
		}

		json result;
		result["metric_id"] = metric_id;
		result["metric_key"] = metric_key;
		return create_success_response(result);
	}

	if (tool_name == "llm.question_template_add") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		int run_id = json_int(arguments, "run_id");
		std::string title = json_string(arguments, "title");
		std::string question_nl = json_string(arguments, "question_nl");

		std::string template_json;
		if (arguments.contains("template")) {
			template_json = arguments["template"].dump();
		}

		std::string example_sql = json_string(arguments, "example_sql");
		double confidence = json_double(arguments, "confidence", 0.6);

		if (agent_run_id <= 0 || run_id <= 0 || title.empty() || question_nl.empty()) {
			return create_error_response("agent_run_id, run_id, title, and question_nl are required");
		}
		if (template_json.empty()) {
			return create_error_response("template is required");
		}

		int template_id = catalog->add_question_template(
			agent_run_id, run_id, title, question_nl, template_json, example_sql, confidence
		);

		if (template_id < 0) {
			return create_error_response("Failed to add question template");
		}

		json result;
		result["template_id"] = template_id;
		result["title"] = title;
		return create_success_response(result);
	}

	if (tool_name == "llm.note_add") {
		int agent_run_id = json_int(arguments, "agent_run_id");
		int run_id = json_int(arguments, "run_id");
		std::string scope = json_string(arguments, "scope");
		int object_id = json_int(arguments, "object_id", -1);
		std::string domain_key = json_string(arguments, "domain_key");
		std::string title = json_string(arguments, "title");
		std::string body = json_string(arguments, "body");

		std::string tags_json;
		if (arguments.contains("tags") && arguments["tags"].is_array()) {
			tags_json = arguments["tags"].dump();
		}

		if (agent_run_id <= 0 || run_id <= 0 || scope.empty() || body.empty()) {
			return create_error_response("agent_run_id, run_id, scope, and body are required");
		}

		int note_id = catalog->add_llm_note(
			agent_run_id, run_id, scope, object_id, domain_key, title, body, tags_json
		);

		if (note_id < 0) {
			return create_error_response("Failed to add note");
		}

		json result;
		result["note_id"] = note_id;
		return create_success_response(result);
	}

	if (tool_name == "llm.search") {
		int run_id = json_int(arguments, "run_id");
		std::string query = json_string(arguments, "query");
		int limit = json_int(arguments, "limit", 25);

		if (run_id <= 0) {
			return create_error_response("run_id is required");
		}
		if (query.empty()) {
			return create_error_response("query is required");
		}

		std::string results = catalog->fts_search_llm(run_id, query, limit);
		try {
			return create_success_response(json::parse(results));
		} catch (...) {
			return create_error_response("Failed to parse LLM search results");
		}
	}

	// ============================================================
	// QUERY TOOLS
	// ============================================================
	if (tool_name == "run_sql_readonly") {
		std::string sql = json_string(arguments, "sql");
		int max_rows = json_int(arguments, "max_rows", 200);
		int timeout_sec = json_int(arguments, "timeout_sec", 2);

		if (sql.empty()) {
			return create_error_response("sql is required");
		}
		if (!validate_readonly_query(sql)) {
			return create_error_response("SQL is not read-only");
		}
		if (is_dangerous_query(sql)) {
			return create_error_response("SQL contains dangerous operations");
		}

		std::string result = execute_query(sql);
		try {
			json result_json = json::parse(result);
			return create_success_response(result_json);
		} catch (...) {
			return create_success_response(result);
		}
	}

	if (tool_name == "explain_sql") {
		std::string sql = json_string(arguments, "sql");
		if (sql.empty()) {
			return create_error_response("sql is required");
		}

		std::string result = execute_query("EXPLAIN " + sql);
		try {
			return create_success_response(json::parse(result));
		} catch (...) {
			return create_success_response(result);
		}
	}

	// ============================================================
	// RELATIONSHIP INFERENCE TOOLS
	// ============================================================
	if (tool_name == "suggest_joins") {
		std::string schema = json_string(arguments, "schema");
		std::string table_a = json_string(arguments, "table_a");
		std::string table_b = json_string(arguments, "table_b");
		int max_candidates = json_int(arguments, "max_candidates", 5);

		// TODO: Implement heuristic join suggestion using Discovery_Schema data
		json results = json::array();
		return create_success_response(results);
	}

	if (tool_name == "find_reference_candidates") {
		std::string schema = json_string(arguments, "schema");
		std::string table = json_string(arguments, "table");
		std::string column = json_string(arguments, "column");
		int max_tables = json_int(arguments, "max_tables", 50);

		// TODO: Implement reference candidate search using Discovery_Schema data
		json results = json::array();
		return create_success_response(results);
	}

	// ============================================================
	// FALLBACK - UNKNOWN TOOL
	// ============================================================
	return create_error_response("Unknown tool: " + tool_name);
}
