#ifdef PROXYSQL40

#include "proxysql.h"
#include "cpp.h"

#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "MCP_Thread.h"
#include "MCP_Tool_Handler.h"
#include "Config_Tool_Handler.h"
#include "proxysql_debug.h"
#include "proxysql_admin.h"
#include "proxysql_utils.h"
#include "MySQL_HostGroups_Manager.h"
#include "PgSQL_HostGroups_Manager.h"
#include "sqlite3db.h"

#include <cctype>
#include <cstring>
#include <string>
#include <unordered_set>

extern ProxySQL_Admin *GloAdmin;

namespace {

const char* skip_sql_whitespace_and_comments(const char* p) {
	while (p && *p) {
		while (*p && std::isspace(static_cast<unsigned char>(*p))) {
			++p;
		}
		if (p[0] == '-' && p[1] == '-') {
			p += 2;
			while (*p && *p != '\n' && *p != '\r') {
				++p;
			}
			continue;
		}
		if (p[0] == '/' && p[1] == '*') {
			p += 2;
			while (*p && !(p[0] == '*' && p[1] == '/')) {
				++p;
			}
			if (*p) {
				p += 2;
			}
			continue;
		}
		break;
	}
	return p ? p : "";
}

std::string first_sql_keyword(const std::string& sql) {
	const char* p = skip_sql_whitespace_and_comments(sql.c_str());
	if (!p || !*p) {
		return "";
	}

	const char* start = p;
	while (*p && (std::isalpha(static_cast<unsigned char>(*p)) || *p == '_')) {
		++p;
	}

	std::string keyword(start, static_cast<size_t>(p - start));
	for (char& c : keyword) {
		c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
	}
	return keyword;
}

bool is_allowed_config_sql_keyword(const std::string& keyword) {
	static const std::unordered_set<std::string> allowed = {
		"SELECT",
		"WITH",
		"INSERT",
		"UPDATE",
		"DELETE",
		"REPLACE",
		"VALUES"
	};
	return allowed.find(keyword) != allowed.end();
}

bool contains_forbidden_sql_token(const std::string& sql) {
	static const std::unordered_set<std::string> forbidden = {
		"ATTACH",
		"ALTER",
		"BEGIN",
		"COMMIT",
		"CREATE",
		"DETACH",
		"DROP",
		"LOAD_EXTENSION",
		"PRAGMA",
		"REINDEX",
		"RELEASE",
		"ROLLBACK",
		"SAVEPOINT",
		"TRUNCATE",
		"VACUUM"
	};

	enum class State {
		Normal,
		SingleQuote,
		DoubleQuote,
		LineComment,
		BlockComment
	};

	State state = State::Normal;
	std::string token;

	auto flush_token = [&]() -> bool {
		if (token.empty()) {
			return false;
		}
		for (char& c : token) {
			c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
		}
		const bool blocked = forbidden.find(token) != forbidden.end();
		token.clear();
		return blocked;
	};

	for (size_t i = 0; i < sql.size(); ++i) {
		const char c = sql[i];
		const char next = (i + 1 < sql.size()) ? sql[i + 1] : '\0';

		switch (state) {
			case State::Normal:
				if (c == '\'') {
					if (flush_token()) {
						return true;
					}
					state = State::SingleQuote;
					continue;
				}
				if (c == '"') {
					if (flush_token()) {
						return true;
					}
					state = State::DoubleQuote;
					continue;
				}
				if (c == '-' && next == '-') {
					if (flush_token()) {
						return true;
					}
					state = State::LineComment;
					++i;
					continue;
				}
				if (c == '/' && next == '*') {
					if (flush_token()) {
						return true;
					}
					state = State::BlockComment;
					++i;
					continue;
				}
				if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
					token.push_back(c);
				} else if (flush_token()) {
					return true;
				}
				break;

			case State::SingleQuote:
				if (c == '\'' && next == '\'') {
					++i;
				} else if (c == '\'') {
					state = State::Normal;
				}
				break;

			case State::DoubleQuote:
				if (c == '"' && next == '"') {
					++i;
				} else if (c == '"') {
					state = State::Normal;
				}
				break;

			case State::LineComment:
				if (c == '\n' || c == '\r') {
					state = State::Normal;
				}
				break;

			case State::BlockComment:
				if (c == '*' && next == '/') {
					state = State::Normal;
					++i;
				}
				break;
		}
	}

	return flush_token();
}

std::string validate_config_sql(SQLite3DB* db, const std::string& sql) {
	if (!db || !db->get_db()) {
		return "Admin database not available";
	}

	const std::string keyword = first_sql_keyword(sql);
	if (keyword.empty()) {
		return "SQL statement is empty";
	}
	if (!is_allowed_config_sql_keyword(keyword)) {
		return "Statement type not allowed: " + keyword;
	}
	if (contains_forbidden_sql_token(sql)) {
		return "Statement contains a forbidden SQL token";
	}

	sqlite3_stmt* stmt = nullptr;
	const char* tail = nullptr;
	int rc = (*proxy_sqlite3_prepare_v2)(db->get_db(), sql.c_str(), -1, &stmt, &tail);
	if (stmt) {
		(*proxy_sqlite3_finalize)(stmt);
		stmt = nullptr;
	}
	if (rc != SQLITE_OK) {
		const char* err = (*proxy_sqlite3_errmsg)(db->get_db());
		return std::string("SQL error: ") + (err ? err : "unknown error");
	}

	const char* rest = skip_sql_whitespace_and_comments(tail ? tail : "");
	if (*rest == ';') {
		rest = skip_sql_whitespace_and_comments(rest + 1);
	}
	if (*rest != '\0') {
		return "Only a single SQL statement is allowed";
	}

	return "";
}

} // namespace

Config_Tool_Handler::Config_Tool_Handler(MCP_Threads_Handler* handler)
	: mcp_handler(handler)
{
	pthread_mutex_init(&handler_lock, NULL);
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Config_Tool_Handler created\n");
}

Config_Tool_Handler::~Config_Tool_Handler() {
	close();
	pthread_mutex_destroy(&handler_lock);
	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Config_Tool_Handler destroyed\n");
}

int Config_Tool_Handler::init() {
	proxy_info("Config_Tool_Handler initialized\n");
	return 0;
}

void Config_Tool_Handler::close() {
	proxy_debug(PROXY_DEBUG_GENERIC, 2, "Config_Tool_Handler closed\n");
}

json Config_Tool_Handler::get_tool_list() {
	json tools = json::array();

	// get_config
	tools.push_back(create_tool_description(
		"get_config",
		"Get the current value of a ProxySQL MCP configuration variable",
		{
			{"type", "object"},
			{"properties", {
				{"variable_name", {
					{"type", "string"},
					{"description", "Variable name (without 'mcp-' prefix)"}
				}}
			}},
			{"required", {"variable_name"}}
		}
	));

	// set_config
	tools.push_back(create_tool_description(
		"set_config",
		"Set the value of a ProxySQL MCP configuration variable",
		{
			{"type", "object"},
			{"properties", {
				{"variable_name", {
					{"type", "string"},
					{"description", "Variable name (without 'mcp-' prefix)"}
				}},
				{"value", {
					{"type", "string"},
					{"description", "New value for the variable"}
				}}
			}},
			{"required", {"variable_name", "value"}}
		}
	));

	// reload_config
	tools.push_back(create_tool_description(
		"reload_config",
		"Reload ProxySQL MCP configuration from disk/memory to runtime",
		{
			{"type", "object"},
			{"properties", {
				{"scope", {
					{"type", "string"},
					{"enum", {"disk", "memory", "runtime"}},
					{"description", "Reload scope: 'disk' (from disk to memory), 'memory' (not applicable), 'runtime' (from memory to runtime)"}
				}}
			}},
			{"required", {"scope"}}
		}
	));

	// list_variables
	tools.push_back(create_tool_description(
		"list_variables",
		"List all ProxySQL MCP configuration variables",
		{
			{"type", "object"},
			{"properties", {
				{"filter", {
					{"type", "string"},
					{"description", "Optional filter pattern (e.g., 'mysql_%' for MySQL-related variables)"}
				}}
			}}
		}
	));

	// get_status
	tools.push_back(create_tool_description(
		"get_status",
		"Get ProxySQL MCP server status information",
		{
			{"type", "object"},
			{"properties", {}}
		}
	));

	// query
	tools.push_back(create_tool_description(
		"query",
		"Execute constrained SQL against the ProxySQL admin/config database",
		{
			{"type", "object"},
			{"properties", {
				{"sql", {
					{"type", "string"},
					{"description", "Single SQL statement to execute"}
				}}
			}},
			{"required", {"sql"}}
		}
	));

	json result;
	result["tools"] = tools;
	return result;
}

json Config_Tool_Handler::get_tool_description(const std::string& tool_name) {
	// For now, just return the basic description from the list
	// In a full implementation, this would provide more detailed schema info
	json tools_list = get_tool_list();
	for (const auto& tool : tools_list["tools"]) {
		if (tool["name"] == tool_name) {
			return tool;
		}
	}
	return create_error_response("Tool not found: " + tool_name);
}

json Config_Tool_Handler::execute_tool(const std::string& tool_name, const json& arguments) {
	pthread_mutex_lock(&handler_lock);

	json result;

	try {
		if (tool_name == "get_config") {
			std::string var_name = arguments.value("variable_name", "");
			result = handle_get_config(var_name);
		} else if (tool_name == "set_config") {
			std::string var_name = arguments.value("variable_name", "");
			std::string var_value = arguments.value("value", "");
			result = handle_set_config(var_name, var_value);
		} else if (tool_name == "reload_config") {
			std::string scope = arguments.value("scope", "runtime");
			result = handle_reload_config(scope);
		} else if (tool_name == "list_variables") {
			std::string filter = arguments.value("filter", "");
			result = handle_list_variables(filter);
		} else if (tool_name == "get_status") {
			result = handle_get_status();
		} else if (tool_name == "query") {
			std::string sql = arguments.value("sql", "");
			result = handle_query(sql);
		} else {
			result = create_error_response("Unknown tool: " + tool_name);
		}
	} catch (const std::exception& e) {
		result = create_error_response(std::string("Exception: ") + e.what());
	}

	pthread_mutex_unlock(&handler_lock);
	return result;
}

json Config_Tool_Handler::handle_get_config(const std::string& var_name) {
	if (!mcp_handler) {
		return create_error_response("MCP handler not initialized");
	}

	char val[1024];
	if (mcp_handler->get_variable(var_name.c_str(), val, sizeof(val)) == 0) {
		json result;
		result["variable_name"] = var_name;
		result["value"] = val;
		return create_success_response(result);
	} else {
		return create_error_response("Variable not found: " + var_name);
	}
}

json Config_Tool_Handler::handle_set_config(const std::string& var_name, const std::string& var_value) {
	if (!mcp_handler) {
		return create_error_response("MCP handler not initialized");
	}

	if (mcp_handler->set_variable(var_name.c_str(), var_value.c_str()) == 0) {
		json result;
		result["variable_name"] = var_name;
		result["value"] = var_value;
		result["message"] = "Variable set successfully. Use 'reload_config' to load to runtime.";
		return create_success_response(result);
	} else {
		return create_error_response("Failed to set variable: " + var_name);
	}
}

json Config_Tool_Handler::handle_reload_config(const std::string& scope) {
	if (!mcp_handler) {
		return create_error_response("MCP handler not initialized");
	}

	// This is a stub - actual implementation would call Admin_FlushVariables
	// For now, return success with a message
	json result;
	result["scope"] = scope;
	result["message"] = "Configuration reload functionality to be implemented";
	return create_success_response(result);
}

json Config_Tool_Handler::handle_query(const std::string& sql) {
	if (!GloAdmin || !GloAdmin->admindb) {
		return create_error_response("ProxySQL Admin database not available");
	}

	const std::string validation_error = validate_config_sql(GloAdmin->admindb, sql);
	if (!validation_error.empty()) {
		return create_error_response(validation_error);
	}

	if (pthread_mutex_lock(&GloAdmin->sql_query_global_mutex) != 0) {
		return create_error_response("Failed to lock sql_query_global_mutex");
	}

	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* resultset = NULL;
	GloAdmin->admindb->execute_statement(sql.c_str(), &error, &cols, &affected_rows, &resultset);

	int unlock_rc = pthread_mutex_unlock(&GloAdmin->sql_query_global_mutex);
	if (unlock_rc != 0) {
		if (error) {
			std::string err_msg = error;
			free(error);
			if (resultset) {
				delete resultset;
			}
			return create_error_response(err_msg + "; also failed to unlock sql_query_global_mutex");
		}
		if (resultset) {
			delete resultset;
		}
		return create_error_response("Failed to unlock sql_query_global_mutex");
	}

	if (error) {
		std::string err_msg = error;
		free(error);
		if (resultset) {
			delete resultset;
		}
		return create_error_response(err_msg);
	}

	json payload;
	payload["sql"] = sql;
	payload["rows_affected"] = affected_rows;
	payload["row_count"] = resultset ? resultset->rows_count : 0;
	payload["columns"] = json::array();
	if (resultset) {
		for (const auto* column : resultset->column_definition) {
			payload["columns"].push_back(column ? column->name : "");
		}
		payload["rows"] = resultset_to_json(resultset, cols);
		delete resultset;
	} else {
		payload["rows"] = json::array();
	}

	return create_success_response(payload);
}

json Config_Tool_Handler::handle_list_variables(const std::string& filter) {
	if (!mcp_handler) {
		return create_error_response("MCP handler not initialized");
	}

	char** vars = mcp_handler->get_variables_list();
	if (!vars) {
		return create_error_response("Failed to get variables list");
	}

	json variables = json::array();

	// Filter and list variables
	for (int i = 0; vars[i] != NULL; i++) {
		std::string var_name = vars[i];

		// Apply filter if provided
		if (!filter.empty()) {
			// Simple pattern matching (expand to full SQL LIKE pattern later)
			if (var_name.find(filter) == std::string::npos) {
				continue;
			}
		}

		char val[1024];
		if (mcp_handler->get_variable(var_name.c_str(), val, sizeof(val)) == 0) {
			json var;
			var["name"] = var_name;
			var["value"] = val;
			variables.push_back(var);
		}

		free(vars[i]);
	}
	free(vars);

	json result;
	result["variables"] = variables;
	result["count"] = variables.size();
	return create_success_response(result);
}

json Config_Tool_Handler::handle_get_status() {
	if (!mcp_handler) {
		return create_error_response("MCP handler not initialized");
	}

	json status;
	status["enabled"] = mcp_handler->variables.mcp_enabled;
	status["port"] = mcp_handler->variables.mcp_port;
	status["total_requests"] = mcp_handler->status_variables.total_requests;
	status["failed_requests"] = mcp_handler->status_variables.failed_requests;
	status["active_connections"] = mcp_handler->status_variables.active_connections;

	return create_success_response(status);
}

#endif /* PROXYSQL40 */
