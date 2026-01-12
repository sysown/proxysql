#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "Query_Tool_Handler.h"
#include "proxysql_debug.h"

#include <vector>
#include <map>

Query_Tool_Handler::Query_Tool_Handler(MySQL_Tool_Handler* handler)
	: mysql_handler(handler), owns_handler(false)
{
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Query_Tool_Handler created (wrapping existing handler)\n");
}

Query_Tool_Handler::Query_Tool_Handler(
	const std::string& hosts,
	const std::string& ports,
	const std::string& user,
	const std::string& password,
	const std::string& schema,
	const std::string& catalog_path)
	: owns_handler(true)
{
	mysql_handler = new MySQL_Tool_Handler(hosts, ports, user, password, schema, catalog_path);
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Query_Tool_Handler created (with new handler)\n");
}

Query_Tool_Handler::~Query_Tool_Handler() {
	close();
	if (owns_handler && mysql_handler) {
		delete mysql_handler;
		mysql_handler = NULL;
	}
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Query_Tool_Handler destroyed\n");
}

int Query_Tool_Handler::init() {
	if (mysql_handler) {
		return mysql_handler->init();
	}
	return -1;
}

void Query_Tool_Handler::close() {
	if (owns_handler && mysql_handler) {
		mysql_handler->close();
	}
}

json Query_Tool_Handler::create_tool_schema(
	const std::string& tool_name,
	const std::string& description,
	const std::vector<std::string>& required_params,
	const std::map<std::string, std::string>& optional_params)
{
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

	// Inventory tools
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

	// Structure tools
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

	// Profiling tools
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

	// Sampling tools
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

	// Query tools
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

	// Relationship inference tools
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

	// Catalog tools (LLM memory)
	tools.push_back(create_tool_schema(
		"catalog_upsert",
		"Store or update an entry in the catalog (LLM external memory)",
		{"kind", "key", "document"},
		{{"tags", "string"}, {"links", "string"}}
	));

	tools.push_back(create_tool_schema(
		"catalog_get",
		"Retrieve an entry from the catalog",
		{"kind", "key"},
		{}
	));

	tools.push_back(create_tool_schema(
		"catalog_search",
		"Search the catalog for entries matching a query",
		{"query"},
		{{"kind", "string"}, {"tags", "string"}, {"limit", "integer"}, {"offset", "integer"}}
	));

	tools.push_back(create_tool_schema(
		"catalog_list",
		"List catalog entries by kind",
		{},
		{{"kind", "string"}, {"limit", "integer"}, {"offset", "integer"}}
	));

	tools.push_back(create_tool_schema(
		"catalog_merge",
		"Merge multiple catalog entries into a single consolidated entry",
		{"keys", "target_key"},
		{{"kind", "string"}, {"instructions", "string"}}
	));

	tools.push_back(create_tool_schema(
		"catalog_delete",
		"Delete an entry from the catalog",
		{"kind", "key"},
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

json Query_Tool_Handler::execute_tool(const std::string& tool_name, const json& arguments) {
	if (!mysql_handler) {
		return create_error_response("MySQL handler not initialized");
	}

	std::string result_str;

	try {
		// Inventory tools
		if (tool_name == "list_schemas") {
			std::string page_token = arguments.value("page_token", "");
			int page_size = arguments.value("page_size", 50);
			result_str = mysql_handler->list_schemas(page_token, page_size);
		}
		else if (tool_name == "list_tables") {
			std::string schema = arguments.value("schema", "");
			std::string page_token = arguments.value("page_token", "");
			int page_size = arguments.value("page_size", 50);
			std::string name_filter = arguments.value("name_filter", "");
			result_str = mysql_handler->list_tables(schema, page_token, page_size, name_filter);
		}
		// Structure tools
		else if (tool_name == "describe_table") {
			std::string schema = arguments.value("schema", "");
			std::string table = arguments.value("table", "");
			result_str = mysql_handler->describe_table(schema, table);
		}
		else if (tool_name == "get_constraints") {
			std::string schema = arguments.value("schema", "");
			std::string table = arguments.value("table", "");
			result_str = mysql_handler->get_constraints(schema, table);
		}
		// Profiling tools
		else if (tool_name == "table_profile") {
			std::string schema = arguments.value("schema", "");
			std::string table = arguments.value("table", "");
			std::string mode = arguments.value("mode", "quick");
			result_str = mysql_handler->table_profile(schema, table, mode);
		}
		else if (tool_name == "column_profile") {
			std::string schema = arguments.value("schema", "");
			std::string table = arguments.value("table", "");
			std::string column = arguments.value("column", "");
			int max_top_values = arguments.value("max_top_values", 20);
			result_str = mysql_handler->column_profile(schema, table, column, max_top_values);
		}
		// Sampling tools
		else if (tool_name == "sample_rows") {
			std::string schema = arguments.value("schema", "");
			std::string table = arguments.value("table", "");
			std::string columns = arguments.value("columns", "");
			std::string where = arguments.value("where", "");
			std::string order_by = arguments.value("order_by", "");
			int limit = arguments.value("limit", 20);
			result_str = mysql_handler->sample_rows(schema, table, columns, where, order_by, limit);
		}
		else if (tool_name == "sample_distinct") {
			std::string schema = arguments.value("schema", "");
			std::string table = arguments.value("table", "");
			std::string column = arguments.value("column", "");
			std::string where = arguments.value("where", "");
			int limit = arguments.value("limit", 50);
			result_str = mysql_handler->sample_distinct(schema, table, column, where, limit);
		}
		// Query tools
		else if (tool_name == "run_sql_readonly") {
			std::string sql = arguments.value("sql", "");
			int max_rows = arguments.value("max_rows", 200);
			int timeout_sec = arguments.value("timeout_sec", 2);
			result_str = mysql_handler->run_sql_readonly(sql, max_rows, timeout_sec);
		}
		else if (tool_name == "explain_sql") {
			std::string sql = arguments.value("sql", "");
			result_str = mysql_handler->explain_sql(sql);
		}
		// Relationship inference tools
		else if (tool_name == "suggest_joins") {
			std::string schema = arguments.value("schema", "");
			std::string table_a = arguments.value("table_a", "");
			std::string table_b = arguments.value("table_b", "");
			int max_candidates = arguments.value("max_candidates", 5);
			result_str = mysql_handler->suggest_joins(schema, table_a, table_b, max_candidates);
		}
		else if (tool_name == "find_reference_candidates") {
			std::string schema = arguments.value("schema", "");
			std::string table = arguments.value("table", "");
			std::string column = arguments.value("column", "");
			int max_tables = arguments.value("max_tables", 50);
			result_str = mysql_handler->find_reference_candidates(schema, table, column, max_tables);
		}
		// Catalog tools
		else if (tool_name == "catalog_upsert") {
			std::string kind = arguments.value("kind", "");
			std::string key = arguments.value("key", "");
			std::string document = arguments.value("document", "");
			std::string tags = arguments.value("tags", "");
			std::string links = arguments.value("links", "");
			result_str = mysql_handler->catalog_upsert(kind, key, document, tags, links);
		}
		else if (tool_name == "catalog_get") {
			std::string kind = arguments.value("kind", "");
			std::string key = arguments.value("key", "");
			result_str = mysql_handler->catalog_get(kind, key);
		}
		else if (tool_name == "catalog_search") {
			std::string query = arguments.value("query", "");
			std::string kind = arguments.value("kind", "");
			std::string tags = arguments.value("tags", "");
			int limit = arguments.value("limit", 20);
			int offset = arguments.value("offset", 0);
			result_str = mysql_handler->catalog_search(query, kind, tags, limit, offset);
		}
		else if (tool_name == "catalog_list") {
			std::string kind = arguments.value("kind", "");
			int limit = arguments.value("limit", 50);
			int offset = arguments.value("offset", 0);
			result_str = mysql_handler->catalog_list(kind, limit, offset);
		}
		else if (tool_name == "catalog_merge") {
			std::string keys = arguments.value("keys", "");
			std::string target_key = arguments.value("target_key", "");
			std::string kind = arguments.value("kind", "domain");
			std::string instructions = arguments.value("instructions", "");
			result_str = mysql_handler->catalog_merge(keys, target_key, kind, instructions);
		}
		else if (tool_name == "catalog_delete") {
			std::string kind = arguments.value("kind", "");
			std::string key = arguments.value("key", "");
			result_str = mysql_handler->catalog_delete(kind, key);
		}
		else {
			return create_error_response("Unknown tool: " + tool_name);
		}

		// Parse the result and return
		try {
			json result_json = json::parse(result_str);
			return create_success_response(result_json);
		} catch (const json::parse_error& e) {
			// If parsing fails, return as string
			json result;
			result["data"] = result_str;
			return create_success_response(result);
		}

	} catch (const std::exception& e) {
		return create_error_response(std::string("Exception: ") + e.what());
	}
}
