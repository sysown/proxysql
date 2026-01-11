#include "MySQL_Tool_Handler.h"
#include "proxysql_debug.h"
#include "cpp.h"
#include <sstream>
#include <algorithm>
#include <regex>
#include <cstring>

// JSON library
#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

MySQL_Tool_Handler::MySQL_Tool_Handler(
	const std::string& hosts,
	const std::string& ports,
	const std::string& user,
	const std::string& password,
	const std::string& schema,
	const std::string& catalog_path
)
	: catalog(NULL),
	  max_rows(200),
	  timeout_ms(2000),
	  allow_select_star(false)
{
	// Parse hosts
	std::istringstream h(hosts);
	std::string host;
	while (std::getline(h, host, ',')) {
		// Trim whitespace
		host.erase(0, host.find_first_not_of(" \t"));
		host.erase(host.find_last_not_of(" \t") + 1);
		if (!host.empty()) {
			mysql_hosts.push_back(host);
		}
	}

	// Parse ports
	std::istringstream p(ports);
	std::string port;
	while (std::getline(p, port, ',')) {
		port.erase(0, port.find_first_not_of(" \t"));
		port.erase(port.find_last_not_of(" \t") + 1);
		if (!port.empty()) {
			mysql_ports.push_back(atoi(port.c_str()));
		}
	}

	mysql_user = user;
	mysql_password = password;
	mysql_schema = schema;

	// Create catalog
	catalog = new MySQL_Catalog(catalog_path);
}

MySQL_Tool_Handler::~MySQL_Tool_Handler() {
	close();
	if (catalog) {
		delete catalog;
	}
}

int MySQL_Tool_Handler::init() {
	// Initialize catalog
	if (catalog->init()) {
		return -1;
	}

	// Initialize connection pool
	if (init_connection_pool()) {
		return -1;
	}

	proxy_info("MySQL Tool Handler initialized for schema '%s'\n", mysql_schema.c_str());
	return 0;
}

void MySQL_Tool_Handler::close() {
	// Connection pool cleanup would go here
}

int MySQL_Tool_Handler::init_connection_pool() {
	// For now, we'll use a simple direct connection approach
	// In production, this would create a pool of MySQL_Connection objects
	proxy_info("MySQL Tool Handler connection pool initialized\n");
	return 0;
}

std::string MySQL_Tool_Handler::sanitize_query(const std::string& query) {
	// Basic SQL injection prevention
	std::string sanitized = query;

	// Remove comments
	std::regex comment_regex("--[^\\n]*\\n|/\\*.*?\\*/");
	sanitized = std::regex_replace(sanitized, comment_regex, " ");

	// Trim
	sanitized.erase(0, sanitized.find_first_not_of(" \t\n\r"));
	sanitized.erase(sanitized.find_last_not_of(" \t\n\r") + 1);

	return sanitized;
}

bool MySQL_Tool_Handler::is_dangerous_query(const std::string& query) {
	std::string upper = query;
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

	// List of dangerous keywords
	static const char* dangerous[] = {
		"DROP", "DELETE", "INSERT", "UPDATE", "TRUNCATE",
		"ALTER", "CREATE", "GRANT", "REVOKE", "EXECUTE",
		"SCRIPT", "INTO OUTFILE", "LOAD_FILE", "LOAD DATA",
		"SLEEP", "BENCHMARK", "WAITFOR", "DELAY"
	};

	for (const char* word : dangerous) {
		if (upper.find(word) != std::string::npos) {
			proxy_debug(PROXY_DEBUG_GENERIC, 3, "Dangerous keyword found: %s\n", word);
			return true;
		}
	}

	return false;
}

bool MySQL_Tool_Handler::validate_readonly_query(const std::string& query) {
	std::string upper = query;
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

	// Must start with SELECT
	if (upper.substr(0, 6) != "SELECT ") {
		return false;
	}

	// Check for dangerous keywords
	if (is_dangerous_query(query)) {
		return false;
	}

	// Check for SELECT * without LIMIT
	if (!allow_select_star) {
		std::regex select_star_regex("\\bSELECT\\s+\\*\\s+FROM", std::regex_constants::icase);
		if (std::regex_search(upper, select_star_regex)) {
			// Allow if there's a LIMIT clause
			if (upper.find("LIMIT ") == std::string::npos) {
				proxy_debug(PROXY_DEBUG_GENERIC, 3, "SELECT * without LIMIT rejected\n");
				return false;
			}
		}
	}

	return true;
}

std::string MySQL_Tool_Handler::list_schemas(const std::string& page_token, int page_size) {
	// Build query to list schemas
	std::string query =
		"SELECT schema_name, "
		"  (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = s.schema_name) as table_count "
		"FROM information_schema.schemata s "
		"WHERE schema_name NOT IN ('information_schema', 'performance_schema', 'mysql', 'sys') "
		"ORDER BY schema_name "
		"LIMIT " + std::to_string(page_size);

	// For now, return a static result
	// In production, this would execute the query via execute_query()
	json result = json::array();
	result.push_back({
		{"name", "mysql"},
		{"table_count", 0}
	});

	return result.dump();
}

std::string MySQL_Tool_Handler::list_tables(
	const std::string& schema,
	const std::string& page_token,
	int page_size,
	const std::string& name_filter
) {
	// Build query to list tables with metadata
	std::string sql =
		"SELECT "
		"  t.table_name, "
		"  t.table_type, "
		"  COALESCE(t.table_rows, 0) as row_count, "
		"  COALESCE(t.data_length, 0) + COALESCE(t.index_length, 0) as total_size, "
		"  t.create_time, "
		"  t.update_time "
		"FROM information_schema.tables t "
		"WHERE t.table_schema = '" + (schema.empty() ? mysql_schema : schema) + "' ";

	if (!name_filter.empty()) {
		sql += " AND t.table_name LIKE '%" + name_filter + "%'";
	}

	sql += " ORDER BY t.table_name LIMIT " + std::to_string(page_size);

	proxy_debug(PROXY_DEBUG_GENERIC, 3, "list_tables query: %s\n", sql.c_str());

	// For now, return static result for testing
	// In production, execute the query
	json result = json::array();

	return result.dump();
}

std::string MySQL_Tool_Handler::describe_table(const std::string& schema, const std::string& table) {
	// This would execute queries to get:
	// - Columns (name, type, nullability, default, collation)
	// - Primary key
	// - Indexes
	// - Constraints

	json result;
	result["schema"] = schema;
	result["table"] = table;
	result["columns"] = json::array();
	result["primary_key"] = json::array();
	result["indexes"] = json::array();
	result["constraints"] = json::array();

	return result.dump();
}

std::string MySQL_Tool_Handler::get_constraints(const std::string& schema, const std::string& table) {
	// Get foreign keys, unique constraints, check constraints
	json result = json::array();
	return result.dump();
}

std::string MySQL_Tool_Handler::describe_view(const std::string& schema, const std::string& view) {
	// Get view definition and columns
	json result;
	result["schema"] = schema;
	result["view"] = view;
	result["definition"] = "";
	result["columns"] = json::array();
	return result.dump();
}

std::string MySQL_Tool_Handler::table_profile(
	const std::string& schema,
	const std::string& table,
	const std::string& mode
) {
	// Get table profile including:
	// - Estimated row count and size
	// - Time columns detected
	// - ID columns detected
	// - Column null percentages
	// - Top N distinct values for low-cardinality columns
	// - Min/max for numeric/date columns

	json result;
	result["schema"] = schema;
	result["table"] = table;
	result["row_estimate"] = 0;
	result["size_estimate"] = 0;
	result["time_columns"] = json::array();
	result["id_columns"] = json::array();
	result["column_stats"] = json::object();

	return result.dump();
}

std::string MySQL_Tool_Handler::column_profile(
	const std::string& schema,
	const std::string& table,
	const std::string& column,
	int max_top_values
) {
	// Get column profile:
	// - Null count and percentage
	// - Distinct count (approximate)
	// - Top N values (capped)
	// - Min/max for numeric/date types

	json result;
	result["schema"] = schema;
	result["table"] = table;
	result["column"] = column;
	result["null_count"] = 0;
	result["distinct_count"] = 0;
	result["top_values"] = json::array();
	result["min_value"] = nullptr;
	result["max_value"] = nullptr;

	return result.dump();
}

std::string MySQL_Tool_Handler::sample_rows(
	const std::string& schema,
	const std::string& table,
	const std::string& columns,
	const std::string& where,
	const std::string& order_by,
	int limit
) {
	// Build and execute sampling query with hard cap
	// Enforce limit parameter to prevent excessive data retrieval
	int actual_limit = std::min(limit, 20); // Hard cap at 20 rows

	std::string sql = "SELECT ";
	sql += columns.empty() ? "*" : columns;
	sql += " FROM " + (schema.empty() ? mysql_schema : schema) + "." + table;

	if (!where.empty()) {
		sql += " WHERE " + where;
	}

	if (!order_by.empty()) {
		sql += " ORDER BY " + order_by;
	}

	sql += " LIMIT " + std::to_string(actual_limit);

	proxy_debug(PROXY_DEBUG_GENERIC, 3, "sample_rows query: %s\n", sql.c_str());

	json result = json::array();
	return result.dump();
}

std::string MySQL_Tool_Handler::sample_distinct(
	const std::string& schema,
	const std::string& table,
	const std::string& column,
	const std::string& where,
	int limit
) {
	// Build query to sample distinct values
	int actual_limit = std::min(limit, 50);

	std::string sql = "SELECT DISTINCT " + column + " as value, COUNT(*) as count ";
	sql += " FROM " + (schema.empty() ? mysql_schema : schema) + "." + table;

	if (!where.empty()) {
		sql += " WHERE " + where;
	}

	sql += " GROUP BY " + column + " ORDER BY count DESC LIMIT " + std::to_string(actual_limit);

	proxy_debug(PROXY_DEBUG_GENERIC, 3, "sample_distinct query: %s\n", sql.c_str());

	json result = json::array();
	return result.dump();
}

std::string MySQL_Tool_Handler::run_sql_readonly(
	const std::string& sql,
	int max_rows,
	int timeout_sec
) {
	json result;
	result["success"] = false;

	// Validate query is read-only
	if (!validate_readonly_query(sql)) {
		result["error"] = "Query validation failed: not SELECT-only or contains dangerous keywords";
		return result.dump();
	}

	// Add LIMIT if not present and not an aggregate query
	std::string query = sql;
	std::string upper = sql;
	std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

	bool has_limit = upper.find("LIMIT ") != std::string::npos;
	bool is_aggregate = upper.find("GROUP BY") != std::string::npos ||
	                     upper.find("COUNT(") != std::string::npos ||
                     upper.find("SUM(") != std::string::npos ||
                     upper.find("AVG(") != std::string::npos;

	if (!has_limit && !is_aggregate && !allow_select_star) {
		query += " LIMIT " + std::to_string(std::min(max_rows, 200));
	}

	// In production, execute the query with timeout
	result["success"] = true;
	result["rows"] = json::array();
	result["row_count"] = 0;
	result["query"] = query;

	return result.dump();
}

std::string MySQL_Tool_Handler::explain_sql(const std::string& sql) {
	// Run EXPLAIN on the query
	std::string query = "EXPLAIN " + sql;

	json result = json::array();
	// In production, execute EXPLAIN and return results

	return result.dump();
}

std::string MySQL_Tool_Handler::suggest_joins(
	const std::string& schema,
	const std::string& table_a,
	const std::string& table_b,
	int max_candidates
) {
	// Heuristic-based join suggestion:
	// 1. Check for matching column names (id, user_id, etc.)
	// 2. Check for matching data types
	// 3. Check index presence on potential join columns

	json result = json::array();
	return result.dump();
}

std::string MySQL_Tool_Handler::find_reference_candidates(
	const std::string& schema,
	const std::string& table,
	const std::string& column,
	int max_tables
) {
	// Find tables that might be referenced by this column
	// Look for primary keys with matching names in other tables

	json result = json::array();
	return result.dump();
}

// Catalog tools (LLM memory)

std::string MySQL_Tool_Handler::catalog_upsert(
	const std::string& kind,
	const std::string& key,
	const std::string& document,
	const std::string& tags,
	const std::string& links
) {
	int rc = catalog->upsert(kind, key, document, tags, links);

	json result;
	result["success"] = (rc == 0);
	if (rc == 0) {
		result["kind"] = kind;
		result["key"] = key;
	} else {
		result["error"] = "Failed to upsert catalog entry";
	}

	return result.dump();
}

std::string MySQL_Tool_Handler::catalog_get(const std::string& kind, const std::string& key) {
	std::string document;
	int rc = catalog->get(kind, key, document);

	json result;
	result["success"] = (rc == 0);
	if (rc == 0) {
		result["kind"] = kind;
		result["key"] = key;
		result["document"] = json::parse(document);
	} else {
		result["error"] = "Entry not found";
	}

	return result.dump();
}

std::string MySQL_Tool_Handler::catalog_search(
	const std::string& query,
	const std::string& kind,
	const std::string& tags,
	int limit,
	int offset
) {
	std::string results = catalog->search(query, kind, tags, limit, offset);

	json result;
	result["query"] = query;
	result["results"] = json::parse(results);

	return result.dump();
}

std::string MySQL_Tool_Handler::catalog_list(
	const std::string& kind,
	int limit,
	int offset
) {
	std::string results = catalog->list(kind, limit, offset);

	json result;
	result["kind"] = kind.empty() ? "all" : kind;
	result["results"] = json::parse(results);

	return result.dump();
}

std::string MySQL_Tool_Handler::catalog_merge(
	const std::string& keys,
	const std::string& target_key,
	const std::string& kind,
	const std::string& instructions
) {
	// Parse keys JSON array
	json keys_json = json::parse(keys);
	std::vector<std::string> key_list;

	for (const auto& k : keys_json) {
		key_list.push_back(k.get<std::string>());
	}

	int rc = catalog->merge(key_list, target_key, kind, instructions);

	json result;
	result["success"] = (rc == 0);
	result["target_key"] = target_key;
	result["merged_keys"] = keys_json;

	return result.dump();
}

std::string MySQL_Tool_Handler::catalog_delete(const std::string& kind, const std::string& key) {
	int rc = catalog->remove(kind, key);

	json result;
	result["success"] = (rc == 0);
	result["kind"] = kind;
	result["key"] = key;

	return result.dump();
}
