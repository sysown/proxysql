/*
 * Admin integration for the native TCP proxy plugin.
 *
 * Responsibilities:
 *   - declare the four persistent table pairs, runtime projections and stats
 *     tables in Phase B without touching any DB handle;
 *   - strictly parse editable rows into the frozen Engine Config value types;
 *   - implement the exact canonical LOAD/SAVE commands and their aliases;
 *   - perform the Admin-mutex handoff around activation with a dedicated
 *     non-blocking LOAD guard, and reacquire Admin through RAII on every exit;
 *   - publish runtime/stats projections from the actual Engine configuration
 *     and snapshot, never from unactivated Main-table edits.
 */

#include "tcp_proxy_plugin.h"

#include "sqlite3db.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <strings.h>
#include <initializer_list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tcp_proxy_plugin {
namespace {

constexpr const char* kOwner = "tcp_proxy";

struct TableDefinition {
	const char* name;
	const char* ddl;
};

const TableDefinition kPersistentTables[] {
	{
		"tcp_settings",
		"CREATE TABLE tcp_settings ("
		" id INTEGER PRIMARY KEY CHECK(id=1),"
		" worker_threads INTEGER NOT NULL DEFAULT 2 CHECK(worker_threads BETWEEN 1 AND 64),"
		" max_connections INTEGER NOT NULL DEFAULT 10000 CHECK(max_connections BETWEEN 1 AND 1000000),"
		" buffer_size INTEGER NOT NULL DEFAULT 16384 CHECK(buffer_size BETWEEN 1024 AND 1048576),"
		" shutdown_timeout_ms INTEGER NOT NULL DEFAULT 5000 CHECK(shutdown_timeout_ms BETWEEN 0 AND 60000),"
		" half_close_timeout_ms INTEGER NOT NULL DEFAULT 30000 CHECK(half_close_timeout_ms BETWEEN 1 AND 3600000)"
		")"
	},
	{
		"tcp_hostgroups",
		"CREATE TABLE tcp_hostgroups ( hostgroup_id INTEGER PRIMARY KEY CHECK(hostgroup_id >= 0), source_protocol TEXT NOT NULL CHECK(source_protocol IN ('MYSQL','PGSQL')), source_hostgroup INTEGER NOT NULL CHECK(source_hostgroup >= 0), comment TEXT NOT NULL DEFAULT '')"
	},
	{
		"tcp_listeners",
		"CREATE TABLE tcp_listeners ("
		" listener_id INTEGER PRIMARY KEY CHECK(listener_id >= 0),"
		" active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),"
		" bind_address TEXT NOT NULL DEFAULT '0.0.0.0' CHECK(length(bind_address) > 0),"
		" bind_port INTEGER NOT NULL CHECK(bind_port BETWEEN 1 AND 65535),"
		" default_hostgroup INTEGER NOT NULL CHECK(default_hostgroup >= 0),"
		" max_connections INTEGER NOT NULL DEFAULT 10000 CHECK(max_connections BETWEEN 1 AND 1000000),"
		" connect_timeout_ms INTEGER NOT NULL DEFAULT 2000 CHECK(connect_timeout_ms BETWEEN 1 AND 60000),"
		" idle_timeout_ms INTEGER NOT NULL DEFAULT 60000 CHECK(idle_timeout_ms=0 OR (idle_timeout_ms BETWEEN 1 AND 86400000)),"
		" max_connect_attempts INTEGER NOT NULL DEFAULT 3 CHECK(max_connect_attempts BETWEEN 1 AND 16),"
		" comment TEXT NOT NULL DEFAULT ''"
		")"
	},
	{
		"tcp_routing_rules",
		"CREATE TABLE tcp_routing_rules ("
		" rule_id INTEGER PRIMARY KEY CHECK(rule_id >= 0),"
		" active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),"
		" listener_id INTEGER NULL CHECK(listener_id IS NULL OR listener_id >= 0),"
		" source_cidr TEXT NULL,"
		" action TEXT NOT NULL DEFAULT 'ROUTE' CHECK(action IN ('ROUTE','REJECT')),"
		" destination_hostgroup INTEGER NULL CHECK(destination_hostgroup IS NULL OR destination_hostgroup >= 0),"
		" comment TEXT NOT NULL DEFAULT ''"
		")"
	},
};

const TableDefinition kRuntimeTables[] {
	{
		"runtime_tcp_settings",
		"CREATE TABLE runtime_tcp_settings ("
		" id INTEGER PRIMARY KEY CHECK(id=1),"
		" worker_threads INTEGER NOT NULL,"
		" max_connections INTEGER NOT NULL,"
		" buffer_size INTEGER NOT NULL,"
		" shutdown_timeout_ms INTEGER NOT NULL,"
		" half_close_timeout_ms INTEGER NOT NULL,"
		" generation INTEGER NOT NULL"
		")"
	},
	{
		"runtime_tcp_hostgroups",
		"CREATE TABLE runtime_tcp_hostgroups ("
		" hostgroup_id INTEGER PRIMARY KEY,"
		" source_protocol TEXT NOT NULL,"
		" source_hostgroup INTEGER NOT NULL,"
		" comment TEXT NOT NULL,"
		" generation INTEGER NOT NULL"
		")"
	},
	{
		"runtime_tcp_listeners",
		"CREATE TABLE runtime_tcp_listeners ("
		" listener_id INTEGER PRIMARY KEY,"
		" active INTEGER NOT NULL,"
		" bind_address TEXT NOT NULL,"
		" bind_port INTEGER NOT NULL,"
		" default_hostgroup INTEGER NOT NULL,"
		" max_connections INTEGER NOT NULL,"
		" connect_timeout_ms INTEGER NOT NULL,"
		" idle_timeout_ms INTEGER NOT NULL,"
		" max_connect_attempts INTEGER NOT NULL,"
		" comment TEXT NOT NULL,"
		" generation INTEGER NOT NULL"
		")"
	},
	{
		"runtime_tcp_routing_rules",
		"CREATE TABLE runtime_tcp_routing_rules ("
		" rule_id INTEGER PRIMARY KEY,"
		" active INTEGER NOT NULL,"
		" listener_id INTEGER NULL,"
		" source_cidr TEXT NULL,"
		" action TEXT NOT NULL,"
		" destination_hostgroup INTEGER NULL,"
		" comment TEXT NOT NULL,"
		" generation INTEGER NOT NULL"
		")"
	},
	{
		"runtime_tcp_status",
		"CREATE TABLE runtime_tcp_status ("
		" id INTEGER PRIMARY KEY CHECK(id=1),"
		" state TEXT NOT NULL,"
		" running INTEGER NOT NULL CHECK(running IN (0,1)),"
		" generation INTEGER NOT NULL,"
		" last_error TEXT NOT NULL DEFAULT '',"
		" active_connections INTEGER NOT NULL,"
		" retired_connections INTEGER NOT NULL,"
		" updated_at INTEGER NOT NULL"
		")"
	},
};

const TableDefinition kStatsTables[] {
	{
		"stats_tcp_listeners",
		"CREATE TABLE stats_tcp_listeners ("
		" listener_id INTEGER PRIMARY KEY,"
		" retired INTEGER NOT NULL CHECK(retired IN (0,1)),"
		" active_connections INTEGER NOT NULL,"
		" accepted_total INTEGER NOT NULL,"
		" rejected_total INTEGER NOT NULL,"
		" connect_errors INTEGER NOT NULL,"
		" bytes_client_to_server INTEGER NOT NULL,"
		" bytes_server_to_client INTEGER NOT NULL"
		")"
	},
	{
		"stats_tcp_rules",
		"CREATE TABLE stats_tcp_rules ("
		" rule_id INTEGER PRIMARY KEY,"
		" retired INTEGER NOT NULL CHECK(retired IN (0,1)),"
		" active_connections INTEGER NOT NULL,"
		" matched_total INTEGER NOT NULL,"
		" rejected_total INTEGER NOT NULL,"
		" bytes_client_to_server INTEGER NOT NULL,"
		" bytes_server_to_client INTEGER NOT NULL"
		")"
	},
};

const char* const kSettingsColumns[] {
	"id", "worker_threads", "max_connections", "buffer_size",
	"shutdown_timeout_ms", "half_close_timeout_ms",
};
const char* const kHostgroupColumns[] {
	"hostgroup_id", "source_protocol", "source_hostgroup", "comment",
};
const char* const kListenerColumns[] {
	"listener_id", "active", "bind_address", "bind_port", "default_hostgroup",
	"max_connections", "connect_timeout_ms", "idle_timeout_ms",
	"max_connect_attempts", "comment",
};
const char* const kRuleColumns[] {
	"rule_id", "active", "listener_id", "source_cidr", "action",
	"destination_hostgroup", "comment",
};

const char* const kRuntimeSettingsColumns[] {
	"id", "worker_threads", "max_connections", "buffer_size",
	"shutdown_timeout_ms", "half_close_timeout_ms", "generation",
};
const char* const kRuntimeHostgroupColumns[] {
	"hostgroup_id", "source_protocol", "source_hostgroup", "comment", "generation",
};
const char* const kRuntimeListenerColumns[] {
	"listener_id", "active", "bind_address", "bind_port", "default_hostgroup",
	"max_connections", "connect_timeout_ms", "idle_timeout_ms",
	"max_connect_attempts", "comment", "generation",
};
const char* const kRuntimeRuleColumns[] {
	"rule_id", "active", "listener_id", "source_cidr", "action",
	"destination_hostgroup", "comment", "generation",
};

std::string sqlite_quote(std::string_view value) {
	std::string result("'");
	for (char character : value) {
		if (character == '\'') result.push_back('\'');
		result.push_back(character);
	}
	result.push_back('\'');
	return result;
}

std::string identifier(std::string_view schema, std::string_view table) {
	std::string result;
	if (!schema.empty()) {
		result.push_back('"');
		result += schema;
		result += "\".";
	}
	result.push_back('"');
	result += table;
	result.push_back('"');
	return result;
}

std::string quote_identifier(std::string_view value) {
	std::string result("\"");
	for (char character : value) {
		if (character == '"') result.push_back('"');
		result.push_back(character);
	}
	result.push_back('"');
	return result;
}

std::string join_quoted(const char* const* columns, size_t count) {
	std::string result;
	for (size_t i = 0; i < count; ++i) {
		if (i != 0) result.push_back(',');
		result += quote_identifier(columns[i]);
	}
	return result;
}

std::string join_source_columns(const char* const* columns, size_t count,
		std::string_view) {
	/* A single named source table is used by the disk copy statements, so
	 * unqualified quoted column names are unambiguous and avoid SQLite's
	 * two-part name resolution ambiguity with schema-qualified tables. */
	return join_quoted(columns, count);
}

std::string select_sql(std::string_view schema, const char* table,
		const char* const* columns, size_t count, const char* order_by) {
	std::string sql = "SELECT ";
	for (size_t i = 0; i < count; ++i) {
		if (i != 0) sql.push_back(',');
		sql += quote_identifier(columns[i]);
	}
	for (size_t i = 0; i < count; ++i) {
		sql += ",typeof(";
		sql += quote_identifier(columns[i]);
		sql.push_back(')');
	}
	sql += " FROM ";
	sql += identifier(schema, table);
	sql += " ORDER BY ";
	sql += quote_identifier(order_by);
	return sql;
}

void log_message(const std::string& message, int level = 3) {
	Context& ctx = context();
	if (ctx.services != nullptr && ctx.services->log_message != nullptr) {
		ctx.services->log_message(level, message.c_str());
	}
}

bool query_rows(SQLite3DB& db, const std::string& sql,
		std::unique_ptr<SQLite3_result>& result, std::string& error) {
	char* raw_error = nullptr;
	result.reset(db.execute_statement(sql.c_str(), &raw_error));
	if (raw_error != nullptr) {
		error = raw_error;
		free(raw_error);
		return false;
	}
	if (!result) {
		error = "query returned no result: " + sql;
		return false;
	}
	return true;
}

bool table_exists(SQLite3DB& db, const char* schema, const char* table,
		bool& exists, std::string& error) {
	std::unique_ptr<SQLite3_result> result;
	const std::string sql = "SELECT COUNT(*) FROM " + identifier(schema, "sqlite_master") +
		" WHERE type='table' AND name=" + sqlite_quote(table);
	if (!query_rows(db, sql, result, error)) return false;
	exists = !result->rows.empty() && result->rows[0] != nullptr &&
		result->rows[0]->fields[0] != nullptr &&
		std::strcmp(result->rows[0]->fields[0], "0") != 0;
	return true;
}

bool fail(std::string& error, const std::string& message) {
	error = message;
	return false;
}

bool database_attached(SQLite3DB& db, const char* name, bool& attached,
		std::string& error) {
	std::unique_ptr<SQLite3_result> result;
	if (!query_rows(db, "PRAGMA database_list", result, error)) return false;
	attached = false;
	for (const SQLite3_row* raw_row : result->rows) {
		if (raw_row == nullptr || raw_row->fields[1] == nullptr) continue;
		if (::strcasecmp(raw_row->fields[1], name) == 0) {
			attached = true;
			break;
		}
	}
	return true;
}

/*
 * Legacy tcp_servers / tcp_hostgroup_mappings artifacts are never dropped or
 * migrated implicitly.  Inspect every sqlite_master object (any type and any
 * case) in the requested schema.  Metadata errors fail closed; only a genuinely
 * unattached disk schema is accepted as absent.
 */
bool reject_legacy_artifacts_checked(SQLite3DB& db, const char* schema,
		std::string& error) {
	if (std::strcmp(schema, "disk") == 0) {
		bool attached = false;
		if (!database_attached(db, "disk", attached, error)) return false;
		if (!attached) {
			error.clear();
			return true;
		}
	}
	std::unique_ptr<SQLite3_result> result;
	const std::string sql = "SELECT name FROM " + identifier(schema, "sqlite_master") +
		" WHERE lower(name) IN ('tcp_servers','tcp_hostgroup_mappings') LIMIT 1";
	if (!query_rows(db, sql, result, error)) {
		if (error.empty()) error = "cannot inspect legacy tcp_proxy artifacts";
		return false;
	}
	if (!result->rows.empty() && result->rows[0] != nullptr &&
		result->rows[0]->fields[0] != nullptr) {
		return fail(error, "legacy tcp_proxy object " + std::string(schema) + "." +
			result->rows[0]->fields[0] + " is present; run "
			"plugins/tcp_proxy/tools/migrate_tcp_config.py offline before "
			"starting tcp_proxy");
	}
	return true;
}

const char* type_of(const SQLite3_row& row, size_t base, size_t index) {
	return row.fields[base + index];
}

bool read_text(const SQLite3_row& row, size_t base, size_t index,
		const char* column, bool nullable, std::optional<std::string>& out,
		std::string& error) {
	const char* type = type_of(row, base, index);
	if (type == nullptr) return fail(error, std::string(column) + " has no SQLite type");
	if (std::strcmp(type, "null") == 0) {
		if (!nullable) return fail(error, std::string(column) + " must not be NULL");
		out.reset();
		return true;
	}
	if (std::strcmp(type, "text") != 0) {
		return fail(error, std::string(column) + " must be TEXT (stored type " +
			type + ")");
	}
	const char* value = row.fields[index];
	if (value == nullptr) return fail(error, std::string(column) + " has no value");
	const size_t size = static_cast<size_t>(row.sizes[index]);
	if (std::strlen(value) != size) {
		return fail(error, std::string(column) + " contains an embedded NUL byte");
	}
	out.emplace(value, size);
	return true;
}

bool read_required_text(const SQLite3_row& row, size_t base, size_t index,
		const char* column, std::string& out, std::string& error) {
	std::optional<std::string> value;
	if (!read_text(row, base, index, column, false, value, error)) return false;
	out = *value;
	return true;
}

bool read_int(const SQLite3_row& row, size_t base, size_t index,
		const char* column, long long minimum, long long maximum, int& out,
		std::string& error) {
	const char* type = type_of(row, base, index);
	if (type == nullptr) return fail(error, std::string(column) + " has no SQLite type");
	if (std::strcmp(type, "null") == 0) {
		return fail(error, std::string(column) + " must not be NULL");
	}
	if (std::strcmp(type, "integer") != 0) {
		return fail(error, std::string(column) + " must be an INTEGER (stored type " +
			type + ")");
	}
	const char* value = row.fields[index];
	if (value == nullptr) return fail(error, std::string(column) + " has no value");
	const size_t size = static_cast<size_t>(row.sizes[index]);
	if (std::strlen(value) != size) {
		return fail(error, std::string(column) + " contains an embedded NUL byte");
	}
	long long parsed = 0;
	const char* end = value + size;
	const auto conversion = std::from_chars(value, end, parsed);
	if (conversion.ec != std::errc() || conversion.ptr != end) {
		return fail(error, std::string(column) + " is not a valid signed integer");
	}
	if (parsed < minimum || parsed > maximum) {
		return fail(error, std::string(column) + " is outside the signed 32-bit "
			"accepted range " + std::to_string(minimum) + ".." +
			std::to_string(maximum));
	}
	out = static_cast<int>(parsed);
	return true;
}

bool read_optional_int(const SQLite3_row& row, size_t base, size_t index,
		const char* column, long long minimum, long long maximum,
		std::optional<int>& out, std::string& error) {
	const char* type = type_of(row, base, index);
	if (type == nullptr) return fail(error, std::string(column) + " has no SQLite type");
	if (std::strcmp(type, "null") == 0) {
		out.reset();
		return true;
	}
	int parsed = 0;
	if (!read_int(row, base, index, column, minimum, maximum, parsed, error)) return false;
	out = parsed;
	return true;
}

bool require_enum(const std::string& value, std::initializer_list<const char*> allowed,
		const char* column, std::string& error) {
	for (const char* candidate : allowed) {
		if (value == candidate) return true;
	}
	std::string message = std::string(column) + " must be one of ";
	bool first = true;
	for (const char* candidate : allowed) {
		if (!first) message += ", ";
		message += candidate;
		first = false;
	}
	return fail(error, message + " (got " + sqlite_quote(value) + ")");
}

bool require_range(int value, int minimum, int maximum, const char* column,
		std::string& error) {
	if (value < minimum || value > maximum) {
		return fail(error, std::string(column) + " must be between " +
			std::to_string(minimum) + " and " + std::to_string(maximum));
	}
	return true;
}

bool read_settings(SQLite3DB& db, tcp_proxy::Settings& settings, std::string& error) {
	std::unique_ptr<SQLite3_result> result;
	constexpr size_t count = sizeof(kSettingsColumns) / sizeof(kSettingsColumns[0]);
	if (!query_rows(db, select_sql("main", "tcp_settings", kSettingsColumns, count, "id"),
			result, error)) {
		return false;
	}
	if (result->rows.size() != 1) {
		return fail(error, "tcp_settings must contain exactly one row with id=1");
	}
	const SQLite3_row& row = *result->rows[0];
	if (!read_int(row, count, 0, "tcp_settings.id", 1, 1, settings.id, error) ||
		!read_int(row, count, 1, "tcp_settings.worker_threads", 1, 64,
			settings.worker_threads, error) ||
		!read_int(row, count, 2, "tcp_settings.max_connections", 1, 1000000,
			settings.max_connections, error) ||
		!read_int(row, count, 3, "tcp_settings.buffer_size", 1024, 1048576,
			settings.buffer_size, error) ||
		!read_int(row, count, 4, "tcp_settings.shutdown_timeout_ms", 0, 60000,
			settings.shutdown_timeout_ms, error) ||
		!read_int(row, count, 5, "tcp_settings.half_close_timeout_ms", 1, 3600000,
			settings.half_close_timeout_ms, error)) {
		return false;
	}
	return true;
}

bool read_hostgroups(SQLite3DB& db, std::vector<tcp_proxy::Hostgroup>& hostgroups,
		std::string& error) {
	std::unique_ptr<SQLite3_result> result;
	constexpr size_t count = sizeof(kHostgroupColumns) / sizeof(kHostgroupColumns[0]);
	if (!query_rows(db, select_sql("main", "tcp_hostgroups", kHostgroupColumns, count,
			"hostgroup_id"), result, error)) {
		return false;
	}
	for (const SQLite3_row* raw_row : result->rows) {
		if (raw_row == nullptr) continue;
		const SQLite3_row& row = *raw_row;
		tcp_proxy::Hostgroup hostgroup;
		if (!read_int(row, count, 0, "tcp_hostgroups.hostgroup_id", 0, INT_MAX,
				hostgroup.hostgroup_id, error) ||
			!read_required_text(row, count, 1, "tcp_hostgroups.source_protocol",
				hostgroup.source_protocol, error) ||
			!read_int(row, count, 2, "tcp_hostgroups.source_hostgroup", 0, INT_MAX,
				hostgroup.source_hostgroup, error) ||
			!read_required_text(row, count, 3, "tcp_hostgroups.comment",
				hostgroup.comment, error)) {
			return false;
		}
		if (!require_enum(hostgroup.source_protocol, {"MYSQL", "PGSQL"},
				"tcp_hostgroups.source_protocol", error)) {
			return false;
		}
		hostgroups.push_back(std::move(hostgroup));
	}
	return true;
}

bool read_listeners(SQLite3DB& db, std::vector<tcp_proxy::Listener>& listeners,
		std::string& error) {
	std::unique_ptr<SQLite3_result> result;
	constexpr size_t count = sizeof(kListenerColumns) / sizeof(kListenerColumns[0]);
	if (!query_rows(db, select_sql("main", "tcp_listeners", kListenerColumns, count,
			"listener_id"), result, error)) {
		return false;
	}
	for (const SQLite3_row* raw_row : result->rows) {
		if (raw_row == nullptr) continue;
		const SQLite3_row& row = *raw_row;
		tcp_proxy::Listener listener;
		if (!read_int(row, count, 0, "tcp_listeners.listener_id", 0, INT_MAX,
				listener.listener_id, error) ||
			!read_int(row, count, 1, "tcp_listeners.active", 0, 1, listener.active,
				error) ||
			!read_required_text(row, count, 2, "tcp_listeners.bind_address",
				listener.bind_address, error) ||
			!read_int(row, count, 3, "tcp_listeners.bind_port", 1, 65535,
				listener.bind_port, error) ||
			!read_int(row, count, 4, "tcp_listeners.default_hostgroup", 0, INT_MAX,
				listener.default_hostgroup, error) ||
			!read_int(row, count, 5, "tcp_listeners.max_connections", 1, 1000000,
				listener.max_connections, error) ||
			!read_int(row, count, 6, "tcp_listeners.connect_timeout_ms", 1, 60000,
				listener.connect_timeout_ms, error) ||
			!read_int(row, count, 7, "tcp_listeners.idle_timeout_ms", 0, 86400000,
				listener.idle_timeout_ms, error) ||
			!read_int(row, count, 8, "tcp_listeners.max_connect_attempts", 1, 16,
				listener.max_connect_attempts, error) ||
			!read_required_text(row, count, 9, "tcp_listeners.comment",
				listener.comment, error)) {
			return false;
		}
		if (listener.bind_address.empty()) {
			return fail(error, "tcp_listeners.bind_address must not be empty");
		}
		listeners.push_back(std::move(listener));
	}
	return true;
}

bool read_rules(SQLite3DB& db, std::vector<tcp_proxy::Rule>& rules,
		std::string& error) {
	std::unique_ptr<SQLite3_result> result;
	constexpr size_t count = sizeof(kRuleColumns) / sizeof(kRuleColumns[0]);
	if (!query_rows(db, select_sql("main", "tcp_routing_rules", kRuleColumns, count,
			"rule_id"), result, error)) {
		return false;
	}
	for (const SQLite3_row* raw_row : result->rows) {
		if (raw_row == nullptr) continue;
		const SQLite3_row& row = *raw_row;
		tcp_proxy::Rule rule;
		if (!read_int(row, count, 0, "tcp_routing_rules.rule_id", 0, INT_MAX,
				rule.rule_id, error) ||
			!read_int(row, count, 1, "tcp_routing_rules.active", 0, 1, rule.active,
				error) ||
			!read_optional_int(row, count, 2, "tcp_routing_rules.listener_id", 0,
				INT_MAX, rule.listener_id, error) ||
			!read_required_text(row, count, 4, "tcp_routing_rules.action", rule.action,
				error) ||
			!read_optional_int(row, count, 5,
				"tcp_routing_rules.destination_hostgroup", 0, INT_MAX,
				rule.destination_hostgroup, error) ||
			!read_required_text(row, count, 6, "tcp_routing_rules.comment",
				rule.comment, error)) {
			return false;
		}
		std::optional<std::string> source_cidr;
		if (!read_text(row, count, 3, "tcp_routing_rules.source_cidr", true,
				source_cidr, error)) {
			return false;
		}
		rule.source_cidr = std::move(source_cidr);
		if (!require_enum(rule.action, {"ROUTE", "REJECT"},
				"tcp_routing_rules.action", error)) {
			return false;
		}
		rules.push_back(std::move(rule));
	}
	return true;
}

class Transaction {
public:
	explicit Transaction(SQLite3DB& db) : db_(db) {}
	~Transaction() {
		if (active_) db_.execute("ROLLBACK");
	}

	bool begin(std::string& error) {
		if (!db_.execute("BEGIN")) return fail(error, "failed to begin admin transaction");
		active_ = true;
		return true;
	}

	bool commit(std::string& error) {
		if (!db_.execute("COMMIT")) {
			return fail(error, "failed to commit admin transaction");
		}
		active_ = false;
		return true;
	}

	void rollback() {
		if (active_) {
			db_.execute("ROLLBACK");
			active_ = false;
		}
	}

private:
	SQLite3DB& db_;
	bool active_ { false };
};

bool replace_table(SQLite3DB& db, const char* schema, const char* table,
		const char* const* columns, size_t count,
		const std::vector<std::string>& values, std::string& error) {
	const std::string deletion = "DELETE FROM " + identifier(schema, table);
	if (!db.execute(deletion.c_str())) {
		return fail(error, "failed clearing " + std::string(schema) + "." + table);
	}
	for (const std::string& row : values) {
		const std::string insertion = "INSERT INTO " + identifier(schema, table) +
			"(" + join_quoted(columns, count) + ") VALUES(" + row + ")";
		if (!db.execute(insertion.c_str())) {
			return fail(error, "failed inserting into " + std::string(schema) + "." +
				table);
		}
	}
	return true;
}

/* Insert the id=1 settings defaults only when no row exists.  A malformed
 * existing row is left untouched, so defaults never overwrite operator data. */
bool seed_main_settings_defaults(SQLite3DB& db, std::string& error) {
	const std::string main_insert =
		"INSERT INTO " + identifier("main", "tcp_settings") +
		"(" + join_quoted(kSettingsColumns,
			sizeof(kSettingsColumns) / sizeof(kSettingsColumns[0])) + ") "
		"SELECT 1,2,10000,16384,5000,30000 "
		"WHERE NOT EXISTS (SELECT 1 FROM " + identifier("main", "tcp_settings") + ")";
	if (!db.execute(main_insert.c_str())) {
		return fail(error, "failed seeding default tcp_settings row");
	}
	error.clear();
	return true;
}

std::string int_value(int value) { return std::to_string(value); }
std::string uint_value(uint64_t value) { return std::to_string(value); }
std::string optional_int_value(const std::optional<int>& value) {
	return value.has_value() ? std::to_string(*value) : "NULL";
}
std::string optional_text_value(const std::optional<std::string>& value) {
	return value.has_value() ? sqlite_quote(*value) : "NULL";
}

std::string settings_editable_row(const tcp_proxy::Settings& settings) {
	return int_value(settings.id) + "," + int_value(settings.worker_threads) + "," +
		int_value(settings.max_connections) + "," + int_value(settings.buffer_size) +
		"," + int_value(settings.shutdown_timeout_ms) + "," +
		int_value(settings.half_close_timeout_ms);
}

std::string hostgroup_editable_row(const tcp_proxy::Hostgroup& hostgroup) {
	return int_value(hostgroup.hostgroup_id) + "," +
		sqlite_quote(hostgroup.source_protocol) + "," +
		int_value(hostgroup.source_hostgroup) + "," +
		sqlite_quote(hostgroup.comment);
}

std::string listener_editable_row(const tcp_proxy::Listener& listener) {
	return int_value(listener.listener_id) + "," + int_value(listener.active) + "," +
		sqlite_quote(listener.bind_address) + "," + int_value(listener.bind_port) + "," +
		int_value(listener.default_hostgroup) + "," +
		int_value(listener.max_connections) + "," +
		int_value(listener.connect_timeout_ms) + "," +
		int_value(listener.idle_timeout_ms) + "," +
		int_value(listener.max_connect_attempts) + "," +
		sqlite_quote(listener.comment);
}

std::string rule_editable_row(const tcp_proxy::Rule& rule) {
	return int_value(rule.rule_id) + "," + int_value(rule.active) + "," +
		optional_int_value(rule.listener_id) + "," +
		optional_text_value(rule.source_cidr) + "," + sqlite_quote(rule.action) + "," +
		optional_int_value(rule.destination_hostgroup) + "," +
		sqlite_quote(rule.comment);
}

std::string settings_row(const tcp_proxy::Settings& settings, uint64_t generation) {
	return settings_editable_row(settings) + "," + uint_value(generation);
}

std::string hostgroup_row(const tcp_proxy::Hostgroup& hostgroup, uint64_t generation) {
	return hostgroup_editable_row(hostgroup) + "," + uint_value(generation);
}

std::string listener_row(const tcp_proxy::Listener& listener, uint64_t generation) {
	return listener_editable_row(listener) + "," + uint_value(generation);
}

std::string rule_row(const tcp_proxy::Rule& rule, uint64_t generation) {
	return rule_editable_row(rule) + "," + uint_value(generation);
}

bool coherent_runtime_view(Context& ctx, tcp_proxy::Config& config,
		tcp_proxy::Snapshot& snapshot, std::string& error) {
	std::shared_ptr<tcp_proxy::Engine> engine = copy_engine(ctx);
	if (!engine) {
		error = "TCP engine is not available";
		return false;
	}
	/*
	 * config() and snapshot() each take a short Engine lock and never wait for
	 * worker acknowledgements.  Take two snapshots around config() and retry a
	 * bounded number of times so the published generation belongs to the same
	 * contiguous interval as the configuration copy.
	 *
	 * Read APIs are allowed to propagate copy failures.  Contain them here so
	 * Admin command/view boundaries fail safely instead of terminating the
	 * daemon.  After exhausting the fence budget there is no coherent view:
	 * return an error rather than mixing the last snapshot with an unfenced
	 * configuration copy.
	 */
	try {
		for (int attempt = 0; attempt < 4; ++attempt) {
			tcp_proxy::Snapshot before = engine->snapshot();
			tcp_proxy::Config candidate = engine->config();
			tcp_proxy::Snapshot after = engine->snapshot();
			if (before.generation == after.generation) {
				if (!after.running) {
					error = "TCP engine is not running";
					return false;
				}
				config = std::move(candidate);
				snapshot = std::move(after);
				return true;
			}
		}
	} catch (const std::exception& exception) {
		error = std::string("cannot read TCP runtime configuration: ") +
			exception.what();
		return false;
	} catch (...) {
		error = "cannot read TCP runtime configuration";
		return false;
	}
	error = "TCP runtime configuration kept changing during the read; retry the command";
	return false;
}

void log_projection_error(const char* table, const std::string& error) {
	log_message(std::string("tcp_proxy: cannot refresh ") + table + ": " + error);
}

bool put_settings(SQLite3DB& db, const tcp_proxy::Config& config,
		uint64_t generation, std::string& error) {
	constexpr size_t count = sizeof(kRuntimeSettingsColumns) /
		sizeof(kRuntimeSettingsColumns[0]);
	const std::vector<std::string> rows { settings_row(config.settings, generation) };
	return replace_table(db, "main", "runtime_tcp_settings",
		kRuntimeSettingsColumns, count, rows, error);
}

bool put_hostgroups(SQLite3DB& db, const tcp_proxy::Config& config,
		uint64_t generation, std::string& error) {
	constexpr size_t count = sizeof(kRuntimeHostgroupColumns) /
		sizeof(kRuntimeHostgroupColumns[0]);
	std::vector<std::string> rows;
	rows.reserve(config.hostgroups.size());
	for (const auto& hostgroup : config.hostgroups) {
		rows.push_back(hostgroup_row(hostgroup, generation));
	}
	return replace_table(db, "main", "runtime_tcp_hostgroups",
		kRuntimeHostgroupColumns, count, rows, error);
}

bool put_listeners(SQLite3DB& db, const tcp_proxy::Config& config,
		uint64_t generation, std::string& error) {
	constexpr size_t count = sizeof(kRuntimeListenerColumns) /
		sizeof(kRuntimeListenerColumns[0]);
	std::vector<std::string> rows;
	rows.reserve(config.listeners.size());
	for (const auto& listener : config.listeners) {
		rows.push_back(listener_row(listener, generation));
	}
	return replace_table(db, "main", "runtime_tcp_listeners",
		kRuntimeListenerColumns, count, rows, error);
}

bool put_rules(SQLite3DB& db, const tcp_proxy::Config& config,
		uint64_t generation, std::string& error) {
	constexpr size_t count = sizeof(kRuntimeRuleColumns) /
		sizeof(kRuntimeRuleColumns[0]);
	std::vector<std::string> rows;
	rows.reserve(config.rules.size());
	for (const auto& rule : config.rules) {
		rows.push_back(rule_row(rule, generation));
	}
	return replace_table(db, "main", "runtime_tcp_routing_rules",
		kRuntimeRuleColumns, count, rows, error);
}

bool put_status(SQLite3DB& db, Context& ctx, const tcp_proxy::Snapshot* snapshot,
		std::string& error) {
	std::string state;
	std::string last_error;
	{
		std::lock_guard<std::mutex> guard(ctx.status_mutex);
		state = ctx.state;
		last_error = ctx.last_error;
	}
	tcp_proxy::Snapshot empty;
	const tcp_proxy::Snapshot& value = snapshot != nullptr ? *snapshot : empty;
	const bool running = snapshot != nullptr && value.running;
	const int64_t updated_at = static_cast<int64_t>(
		std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch()).count());
	const std::string row = std::string("1,") + sqlite_quote(state) + "," +
		(running ? "1" : "0") + "," + uint_value(value.generation) + "," +
		sqlite_quote(last_error) + "," + uint_value(value.active_connections) + "," +
		uint_value(value.retired_connections) + "," + std::to_string(updated_at);
	const std::vector<std::string> rows { row };
	const char* columns[] {
		"id", "state", "running", "generation", "last_error",
		"active_connections", "retired_connections", "updated_at",
	};
	constexpr size_t count = sizeof(columns) / sizeof(columns[0]);
	return replace_table(db, "main", "runtime_tcp_status", columns, count, rows,
		error);
}

void refresh_runtime_settings(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	Context& ctx = context();
	tcp_proxy::Config config;
	tcp_proxy::Snapshot snapshot;
	std::string error;
	if (!coherent_runtime_view(ctx, config, snapshot, error)) {
		Transaction transaction(*db);
		if (!transaction.begin(error) ||
			!replace_table(*db, "main", "runtime_tcp_settings",
				kRuntimeSettingsColumns,
				sizeof(kRuntimeSettingsColumns) / sizeof(kRuntimeSettingsColumns[0]),
				{}, error) ||
			!transaction.commit(error)) {
			transaction.rollback();
			log_projection_error("runtime_tcp_settings", error);
		}
		return;
	}
	Transaction transaction(*db);
	if (!transaction.begin(error) ||
		!put_settings(*db, config, snapshot.generation, error) ||
		!transaction.commit(error)) {
		transaction.rollback();
		log_projection_error("runtime_tcp_settings", error);
	}
}

void refresh_runtime_hostgroups(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	Context& ctx = context();
	tcp_proxy::Config config;
	tcp_proxy::Snapshot snapshot;
	std::string error;
	if (!coherent_runtime_view(ctx, config, snapshot, error)) {
		Transaction transaction(*db);
		if (!transaction.begin(error) ||
			!replace_table(*db, "main", "runtime_tcp_hostgroups",
				kRuntimeHostgroupColumns,
				sizeof(kRuntimeHostgroupColumns) / sizeof(kRuntimeHostgroupColumns[0]),
				{}, error) ||
			!transaction.commit(error)) {
			transaction.rollback();
			log_projection_error("runtime_tcp_hostgroups", error);
		}
		return;
	}
	Transaction transaction(*db);
	if (!transaction.begin(error) ||
		!put_hostgroups(*db, config, snapshot.generation, error) ||
		!transaction.commit(error)) {
		transaction.rollback();
		log_projection_error("runtime_tcp_hostgroups", error);
	}
}

void refresh_runtime_listeners(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	Context& ctx = context();
	tcp_proxy::Config config;
	tcp_proxy::Snapshot snapshot;
	std::string error;
	if (!coherent_runtime_view(ctx, config, snapshot, error)) {
		Transaction transaction(*db);
		if (!transaction.begin(error) ||
			!replace_table(*db, "main", "runtime_tcp_listeners",
				kRuntimeListenerColumns,
				sizeof(kRuntimeListenerColumns) / sizeof(kRuntimeListenerColumns[0]),
				{}, error) ||
			!transaction.commit(error)) {
			transaction.rollback();
			log_projection_error("runtime_tcp_listeners", error);
		}
		return;
	}
	Transaction transaction(*db);
	if (!transaction.begin(error) ||
		!put_listeners(*db, config, snapshot.generation, error) ||
		!transaction.commit(error)) {
		transaction.rollback();
		log_projection_error("runtime_tcp_listeners", error);
	}
}

void refresh_runtime_rules(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	Context& ctx = context();
	tcp_proxy::Config config;
	tcp_proxy::Snapshot snapshot;
	std::string error;
	if (!coherent_runtime_view(ctx, config, snapshot, error)) {
		Transaction transaction(*db);
		if (!transaction.begin(error) ||
			!replace_table(*db, "main", "runtime_tcp_routing_rules",
				kRuntimeRuleColumns,
				sizeof(kRuntimeRuleColumns) / sizeof(kRuntimeRuleColumns[0]),
				{}, error) ||
			!transaction.commit(error)) {
			transaction.rollback();
			log_projection_error("runtime_tcp_routing_rules", error);
		}
		return;
	}
	Transaction transaction(*db);
	if (!transaction.begin(error) ||
		!put_rules(*db, config, snapshot.generation, error) ||
		!transaction.commit(error)) {
		transaction.rollback();
		log_projection_error("runtime_tcp_routing_rules", error);
	}
}

void refresh_runtime_status(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	Context& ctx = context();
	tcp_proxy::Snapshot snapshot;
	bool have_snapshot = false;
	std::shared_ptr<tcp_proxy::Engine> engine = copy_engine(ctx);
	if (engine) {
		try {
			snapshot = engine->snapshot();
			have_snapshot = true;
		} catch (const std::exception& exception) {
			/* Status can still be published from the mode/error fields. */
			log_projection_error("runtime_tcp_status", exception.what());
		} catch (...) {
			log_projection_error("runtime_tcp_status",
				"unknown snapshot read failure");
		}
	}
	std::string error;
	Transaction transaction(*db);
	if (!transaction.begin(error) ||
		!put_status(*db, ctx, have_snapshot ? &snapshot : nullptr, error) ||
		!transaction.commit(error)) {
		transaction.rollback();
		log_projection_error("runtime_tcp_status", error);
	}
}

void refresh_stats_listeners(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	Context& ctx = context();
	std::shared_ptr<tcp_proxy::Engine> engine = copy_engine(ctx);
	const char* columns[] {
		"listener_id", "retired", "active_connections", "accepted_total",
		"rejected_total", "connect_errors", "bytes_client_to_server",
		"bytes_server_to_client",
	};
	std::vector<std::string> rows;
	if (engine) {
		try {
			const tcp_proxy::Snapshot snapshot = engine->snapshot();
			rows.reserve(snapshot.listeners.size());
			for (const auto& item : snapshot.listeners) {
				rows.push_back(int_value(item.listener_id) + "," +
					(item.retired ? "1" : "0") + "," +
					uint_value(item.active_connections) + "," +
					uint_value(item.accepted_total) + "," +
					uint_value(item.rejected_total) + "," +
					uint_value(item.connect_errors) + "," +
					uint_value(item.bytes_client_to_server) + "," +
					uint_value(item.bytes_server_to_client));
			}
		} catch (const std::exception& exception) {
			/* Leave the previous statistics rows intact on a failed read. */
			log_projection_error("stats_tcp_listeners", exception.what());
			return;
		} catch (...) {
			log_projection_error("stats_tcp_listeners",
				"unknown snapshot read failure");
			return;
		}
	}
	std::string error;
	Transaction transaction(*db);
	if (!transaction.begin(error) ||
		!replace_table(*db, "main", "stats_tcp_listeners", columns,
			sizeof(columns) / sizeof(columns[0]), rows, error) ||
		!transaction.commit(error)) {
		transaction.rollback();
		log_projection_error("stats_tcp_listeners", error);
	}
}

void refresh_stats_rules(SQLite3DB* db, void*) {
	if (db == nullptr) return;
	Context& ctx = context();
	std::shared_ptr<tcp_proxy::Engine> engine = copy_engine(ctx);
	const char* columns[] {
		"rule_id", "retired", "active_connections", "matched_total",
		"rejected_total", "bytes_client_to_server", "bytes_server_to_client",
	};
	constexpr size_t count = sizeof(columns) / sizeof(columns[0]);
	std::vector<std::string> rows;
	if (engine) {
		try {
			const tcp_proxy::Snapshot snapshot = engine->snapshot();
			rows.reserve(snapshot.rules.size());
			for (const auto& item : snapshot.rules) {
				rows.push_back(int_value(item.rule_id) + "," +
					(item.retired ? "1" : "0") + "," +
					uint_value(item.active_connections) + "," +
					uint_value(item.matched_total) + "," +
					uint_value(item.rejected_total) + "," +
					uint_value(item.bytes_client_to_server) + "," +
					uint_value(item.bytes_server_to_client));
			}
		} catch (const std::exception& exception) {
			log_projection_error("stats_tcp_rules", exception.what());
			return;
		} catch (...) {
			log_projection_error("stats_tcp_rules",
				"unknown snapshot read failure");
			return;
		}
	}
	std::string error;
	Transaction transaction(*db);
	if (!transaction.begin(error) ||
		!replace_table(*db, "main", "stats_tcp_rules", columns, count, rows,
			error) ||
		!transaction.commit(error)) {
		transaction.rollback();
		log_projection_error("stats_tcp_rules", error);
	}
}

class AdminHandoff {
public:
	explicit AdminHandoff(const ProxySQL_PluginCommandContext& command)
		: command_(command) {
		if (command_.release_admin_mutex != nullptr &&
			command_.acquire_admin_mutex != nullptr) {
			command_.release_admin_mutex(command_.admin_mutex_context);
			released_ = true;
		}
	}

	~AdminHandoff() {
		reacquire_noexcept();
	}

	void reacquire_noexcept() noexcept {
		if (!released_) return;
		try {
			command_.acquire_admin_mutex(command_.admin_mutex_context);
		} catch (...) {
			/* The callback is specified not to throw; a throwing callback cannot
			 * be recovered here and must not escape a destructor. */
		}
		released_ = false;
	}

private:
	const ProxySQL_PluginCommandContext& command_;
	bool released_ { false };
};

ProxySQL_PluginCommandResult command_failure(const std::string& message) {
	return { 1, 0, message.empty() ? "TCP proxy admin command failed" : message };
}

ProxySQL_PluginCommandResult load_to_runtime(
		const ProxySQL_PluginCommandContext& command, const char*) {
	Context& ctx = context();
	if (!ctx.initialized.load()) return command_failure("TCP proxy plugin is not initialized");
	if (command.admindb == nullptr) return command_failure("LOAD TCP CONFIG TO RUNTIME requires admin db");
	std::shared_ptr<tcp_proxy::Engine> engine = copy_engine(ctx);
	if (!engine || !engine->running()) {
		return command_failure("TCP proxy engine is not running");
	}

	/*
	 * Critical ordering: the dedicated LOAD guard is acquired with try_lock
	 * before copying any editable SQL row, while Admin still owns its global
	 * mutex.  A competing LOAD therefore observes busy immediately instead of
	 * waiting with Admin held.  The guard remains held until this function's
	 * return value is built and the Admin handoff below has reacquired Admin.
	 */
	std::unique_lock<std::mutex> load_guard(ctx.load_mutex, std::try_to_lock);
	if (!load_guard.owns_lock()) {
		return command_failure("another LOAD TCP CONFIG TO RUNTIME is already in progress");
	}

	tcp_proxy::Config candidate;
	std::string error;
	if (!read_config(*command.admindb, candidate, error)) {
		set_last_error(ctx, error);
		return command_failure(error);
	}

	/* No SQLite access is permitted while Admin is released. */
	AdminHandoff handoff(command);
	if (!tcp_proxy::validate_config(candidate, error)) {
		set_last_error(ctx, error);
		handoff.reacquire_noexcept();
		return command_failure(error);
	}
	if (!candidate.hostgroups.empty()) {
		std::shared_ptr<tcp_proxy::BackendProvider> provider;
		{
			std::lock_guard<std::mutex> guard(ctx.engine_mutex);
			provider = ctx.backend_provider;
		}
		if (!provider || !provider->available()) {
			error = "tcp_hostgroups require the core raw backend service "
				"(ABI 18), which is unavailable";
			set_last_error(ctx, error);
			handoff.reacquire_noexcept();
			return command_failure(error);
		}
	}

	const std::string interfaces = tcp_proxy::listener_interfaces(candidate);
	if (ctx.services != nullptr && ctx.services->validate_listener_interfaces != nullptr) {
		if (!ctx.services->validate_listener_interfaces(kOwner, interfaces.c_str(), error)) {
			set_last_error(ctx, error);
			handoff.reacquire_noexcept();
			return command_failure(error);
		}
	} else if (!interfaces.empty()) {
		error = "listener reservation validation service is unavailable";
		set_last_error(ctx, error);
		handoff.reacquire_noexcept();
		return command_failure(error);
	}

	if (!engine->apply(candidate, error)) {
		set_last_error(ctx, error);
		handoff.reacquire_noexcept();
		return command_failure(error);
	}

	clear_last_error(ctx);
	set_state(ctx, "running");
	handoff.reacquire_noexcept();
	return { 0, 0, "TCP configuration loaded to runtime" };
}

ProxySQL_PluginCommandResult save_from_runtime(
		const ProxySQL_PluginCommandContext& command, const char*) {
	Context& ctx = context();
	if (!ctx.initialized.load()) return command_failure("TCP proxy plugin is not initialized");
	if (command.admindb == nullptr) return command_failure("SAVE TCP CONFIG FROM RUNTIME requires admin db");
	std::shared_ptr<tcp_proxy::Engine> engine = copy_engine(ctx);
	if (!engine || !engine->running()) {
		return command_failure("TCP proxy engine is not running");
	}
	tcp_proxy::Config config;
	tcp_proxy::Snapshot snapshot;
	std::string error;
	if (!coherent_runtime_view(ctx, config, snapshot, error)) {
		return command_failure(error);
	}

	std::vector<std::string> hostgroup_rows;
	hostgroup_rows.reserve(config.hostgroups.size());
	for (const auto& hostgroup : config.hostgroups) {
		hostgroup_rows.push_back(hostgroup_editable_row(hostgroup));
	}
	std::vector<std::string> listener_rows;
	listener_rows.reserve(config.listeners.size());
	for (const auto& listener : config.listeners) {
		listener_rows.push_back(listener_editable_row(listener));
	}
	std::vector<std::string> rule_rows;
	rule_rows.reserve(config.rules.size());
	for (const auto& rule : config.rules) {
		rule_rows.push_back(rule_editable_row(rule));
	}
	Transaction transaction(*command.admindb);
	if (!transaction.begin(error) ||
		!replace_table(*command.admindb, "main", "tcp_settings", kSettingsColumns,
			sizeof(kSettingsColumns) / sizeof(kSettingsColumns[0]),
			{ settings_editable_row(config.settings) }, error) ||
		!replace_table(*command.admindb, "main", "tcp_hostgroups",
			kHostgroupColumns,
			sizeof(kHostgroupColumns) / sizeof(kHostgroupColumns[0]),
			hostgroup_rows, error) ||
		!replace_table(*command.admindb, "main", "tcp_listeners", kListenerColumns,
			sizeof(kListenerColumns) / sizeof(kListenerColumns[0]),
			listener_rows, error) ||
		!replace_table(*command.admindb, "main", "tcp_routing_rules", kRuleColumns,
			sizeof(kRuleColumns) / sizeof(kRuleColumns[0]), rule_rows, error) ||
		!transaction.commit(error)) {
		transaction.rollback();
		return command_failure(error);
	}
	return { 0, 0, "TCP configuration saved from runtime" };
}

ProxySQL_PluginCommandResult load_from_disk(
		const ProxySQL_PluginCommandContext& command, const char*) {
	if (command.admindb == nullptr) return command_failure("LOAD TCP CONFIG FROM DISK requires admin db");
	std::string error;
	if (!reject_legacy_artifacts_checked(*command.admindb, "disk", error)) {
		return command_failure(error);
	}
	Transaction transaction(*command.admindb);
	if (!transaction.begin(error)) return command_failure(error);
	const std::pair<const char*, const char* const*> tables[] {
		{ "tcp_settings", kSettingsColumns },
		{ "tcp_hostgroups", kHostgroupColumns },
		{ "tcp_listeners", kListenerColumns },
		{ "tcp_routing_rules", kRuleColumns },
	};
	const size_t counts[] {
		sizeof(kSettingsColumns) / sizeof(kSettingsColumns[0]),
		sizeof(kHostgroupColumns) / sizeof(kHostgroupColumns[0]),
		sizeof(kListenerColumns) / sizeof(kListenerColumns[0]),
		sizeof(kRuleColumns) / sizeof(kRuleColumns[0]),
	};
	for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); ++i) {
		const std::string deletion = "DELETE FROM " + identifier("main", tables[i].first);
		const std::string insertion = "INSERT INTO " + identifier("main", tables[i].first) +
			"(" + join_quoted(tables[i].second, counts[i]) + ") SELECT " +
			join_source_columns(tables[i].second, counts[i], "disk") + " FROM " +
			identifier("disk", tables[i].first);
		if (!command.admindb->execute(deletion.c_str()) ||
			!command.admindb->execute(insertion.c_str())) {
			transaction.rollback();
			return command_failure(std::string("failed loading ") + tables[i].first +
				" from disk");
		}
	}
	/* An explicitly empty disk tcp_settings table would otherwise leave Main
	 * without the exactly-one-row settings required by read_config(), making
	 * every later LOAD unusable.  Defaults are inserted only when the copied
	 * table is absent/empty; malformed existing rows are never replaced. */
	if (!seed_main_settings_defaults(*command.admindb, error)) {
		transaction.rollback();
		return command_failure(error);
	}
	if (!transaction.commit(error)) {
		transaction.rollback();
		return command_failure(error);
	}
	return { 0, 0, "TCP configuration loaded from disk to memory" };
}

ProxySQL_PluginCommandResult save_to_disk(
		const ProxySQL_PluginCommandContext& command, const char*) {
	if (command.admindb == nullptr) return command_failure("SAVE TCP CONFIG TO DISK requires admin db");
	std::string error;
	Transaction transaction(*command.admindb);
	if (!transaction.begin(error)) return command_failure(error);
	const std::pair<const char*, const char* const*> tables[] {
		{ "tcp_settings", kSettingsColumns },
		{ "tcp_hostgroups", kHostgroupColumns },
		{ "tcp_listeners", kListenerColumns },
		{ "tcp_routing_rules", kRuleColumns },
	};
	const size_t counts[] {
		sizeof(kSettingsColumns) / sizeof(kSettingsColumns[0]),
		sizeof(kHostgroupColumns) / sizeof(kHostgroupColumns[0]),
		sizeof(kListenerColumns) / sizeof(kListenerColumns[0]),
		sizeof(kRuleColumns) / sizeof(kRuleColumns[0]),
	};
	for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); ++i) {
		const std::string deletion = "DELETE FROM " + identifier("disk", tables[i].first);
		const std::string insertion = "INSERT INTO " + identifier("disk", tables[i].first) +
			"(" + join_quoted(tables[i].second, counts[i]) + ") SELECT " +
			join_source_columns(tables[i].second, counts[i], "main") + " FROM " +
			identifier("main", tables[i].first);
		if (!command.admindb->execute(deletion.c_str()) ||
			!command.admindb->execute(insertion.c_str())) {
			transaction.rollback();
			return command_failure(std::string("failed saving ") + tables[i].first +
				" to disk");
		}
	}
	if (!transaction.commit(error)) {
		transaction.rollback();
		return command_failure(error);
	}
	return { 0, 0, "TCP configuration saved to disk" };
}

bool register_table_pair(ProxySQL_PluginServices& services,
		const TableDefinition& table) {
	services.register_table({ ProxySQL_PluginDBKind::admin_db, table.name, table.ddl });
	services.register_table({ ProxySQL_PluginDBKind::config_db, table.name, table.ddl });
	return true;
}

} // namespace

bool reject_legacy_artifacts(SQLite3DB& db, const char* schema,
		std::string& error) {
	return reject_legacy_artifacts_checked(db, schema, error);
}

Context::~Context() {
	metrics_stop_sampler(*this);
}

/*
 * Explicit module-owned Context storage.
 *
 * A function-local static Context would register an atexit destructor when the
 * DSO is loaded.  Release SIGTERM calls std::exit(), whose atexit handlers run
 * before the earlier-created global ProxySQL_PluginManager destructor; that
 * destroyed the Context (and its Engine mutex) while stop_all() was still
 * calling plugin_stop().  A heap Context with no automatic destructor removes
 * that ordering hazard.
 *
 * context_finalize_if_idle() runs from the DSO finalizer: after an ordinary
 * STOP/dlclose it destroys the fully stopped Context, so repeated module
 * load/unload does not leak.  During process exit while the daemon is still
 * running it deliberately leaves the storage intact for the later chassis
 * stop callback; the process is terminating, so that remaining allocation is
 * not a per-reload leak.
 */
namespace {

std::atomic<Context*> context_storage { nullptr };

bool context_is_idle(Context& ctx) {
	if (ctx.initialized.load(std::memory_order_acquire)) return false;
	if (ctx.started.load(std::memory_order_acquire)) return false;
	if (ctx.metrics_thread.joinable()) return false;
	if (ctx.metrics) return false;
	std::lock_guard<std::mutex> guard(ctx.engine_mutex);
	return ctx.engine == nullptr;
}

} // namespace

Context& context() {
	Context* current = context_storage.load(std::memory_order_acquire);
	if (current != nullptr) return *current;
	Context* created = new Context();
	if (context_storage.compare_exchange_strong(current, created,
			std::memory_order_acq_rel, std::memory_order_acquire)) {
		return *created;
	}
	delete created;
	return *current;
}

void context_finalize_if_idle() {
	Context* current = context_storage.load(std::memory_order_acquire);
	if (current == nullptr || !context_is_idle(*current)) return;
	if (context_storage.compare_exchange_strong(current, nullptr,
			std::memory_order_acq_rel, std::memory_order_acquire)) {
		delete current;
	}
}

namespace {

__attribute__((destructor)) void tcp_proxy_context_finalizer() {
	context_finalize_if_idle();
}

} // namespace

std::shared_ptr<tcp_proxy::Engine> copy_engine(Context& ctx) {
	std::lock_guard<std::mutex> guard(ctx.engine_mutex);
	return ctx.engine;
}

bool engine_is_running(Context& ctx) {
	std::shared_ptr<tcp_proxy::Engine> engine = copy_engine(ctx);
	return engine != nullptr && engine->running();
}

void set_last_error(Context& ctx, const std::string& error) {
	std::lock_guard<std::mutex> guard(ctx.status_mutex);
	ctx.last_error = error;
}

void clear_last_error(Context& ctx) {
	std::lock_guard<std::mutex> guard(ctx.status_mutex);
	ctx.last_error.clear();
}

void set_state(Context& ctx, const std::string& state) {
	std::lock_guard<std::mutex> guard(ctx.status_mutex);
	ctx.state = state;
}

std::string state_snapshot(Context& ctx, std::string& last_error) {
	std::lock_guard<std::mutex> guard(ctx.status_mutex);
	last_error = ctx.last_error;
	return ctx.state;
}

bool seed_settings_defaults(SQLite3DB& db, std::string& error) {
	if (!seed_main_settings_defaults(db, error)) return false;
	bool has_disk = false;
	if (!table_exists(db, "disk", "tcp_settings", has_disk, error)) {
		/* No attached disk schema is valid for isolated tests and for a
		 * chassis path that only exposes memory tables.  A present disk table
		 * is seeded so an initial empty disk cannot erase the defaults when an
		 * operator later runs LOAD TCP CONFIG FROM DISK. */
		error.clear();
		return true;
	}
	if (!has_disk) return true;
	const std::string disk_insert =
		"INSERT INTO " + identifier("disk", "tcp_settings") +
		"(" + join_quoted(kSettingsColumns,
			sizeof(kSettingsColumns) / sizeof(kSettingsColumns[0])) + ") "
		"SELECT 1,2,10000,16384,5000,30000 "
		"WHERE NOT EXISTS (SELECT 1 FROM " + identifier("disk", "tcp_settings") + ")";
	if (!db.execute(disk_insert.c_str())) {
		return fail(error, "failed seeding default disk tcp_settings row");
	}
	error.clear();
	return true;
}

bool read_config(SQLite3DB& db, tcp_proxy::Config& config, std::string& error) {
	error.clear();
	config = tcp_proxy::Config {};
	if (!reject_legacy_artifacts_checked(db, "main", error)) return false;
	if (!reject_legacy_artifacts_checked(db, "disk", error)) return false;
	if (!read_settings(db, config.settings, error)) return false;
	if (!read_hostgroups(db, config.hostgroups, error)) return false;
	if (!read_listeners(db, config.listeners, error)) return false;
	if (!read_rules(db, config.rules, error)) return false;
	return true;
}

bool register_schemas(ProxySQL_PluginServices& services) {
	if (services.register_table == nullptr || services.register_command == nullptr ||
		services.register_runtime_view == nullptr ||
		services.register_command_alias == nullptr) {
		return false;
	}

	for (const auto& table : kPersistentTables) register_table_pair(services, table);
	for (const auto& table : kRuntimeTables) {
		services.register_table({ ProxySQL_PluginDBKind::admin_db, table.name, table.ddl });
	}
	for (const auto& table : kStatsTables) {
		services.register_table({ ProxySQL_PluginDBKind::stats_db, table.name, table.ddl });
	}

	struct ViewDefinition {
		const char* table;
		void (*refresh)(SQLite3DB *, void *);
		ProxySQL_PluginDBKind kind;
	};
	const ViewDefinition views[] {
		{ "runtime_tcp_settings", &refresh_runtime_settings, ProxySQL_PluginDBKind::admin_db },
		{ "runtime_tcp_hostgroups", &refresh_runtime_hostgroups, ProxySQL_PluginDBKind::admin_db },
		{ "runtime_tcp_listeners", &refresh_runtime_listeners, ProxySQL_PluginDBKind::admin_db },
		{ "runtime_tcp_routing_rules", &refresh_runtime_rules, ProxySQL_PluginDBKind::admin_db },
		{ "runtime_tcp_status", &refresh_runtime_status, ProxySQL_PluginDBKind::admin_db },
		{ "stats_tcp_listeners", &refresh_stats_listeners, ProxySQL_PluginDBKind::stats_db },
		{ "stats_tcp_rules", &refresh_stats_rules, ProxySQL_PluginDBKind::stats_db },
	};
	for (const auto& view : views) {
		ProxySQL_PluginRuntimeView registration {};
		registration.table_name = view.table;
		registration.refresh = view.refresh;
		registration.opaque = nullptr;
		registration.db_kind = view.kind;
		if (!services.register_runtime_view(registration)) return false;
	}

	const struct {
		const char* canonical;
		proxysql_plugin_admin_command_cb callback;
	} commands[] {
		{ "LOAD TCP CONFIG TO RUNTIME", &load_to_runtime },
		{ "SAVE TCP CONFIG FROM RUNTIME", &save_from_runtime },
		{ "LOAD TCP CONFIG FROM DISK", &load_from_disk },
		{ "SAVE TCP CONFIG TO DISK", &save_to_disk },
	};
	for (const auto& command : commands) {
		services.register_command(command.canonical, command.callback);
	}

	const struct {
		const char* canonical;
		const char* alias;
	} aliases[] {
		{ "LOAD TCP CONFIG TO RUNTIME", "LOAD TCP CONFIG FROM MEMORY" },
		{ "SAVE TCP CONFIG FROM RUNTIME", "SAVE TCP CONFIG TO MEMORY" },
		{ "LOAD TCP CONFIG FROM DISK", "LOAD TCP CONFIG TO MEMORY" },
		{ "SAVE TCP CONFIG TO DISK", "SAVE TCP CONFIG FROM MEMORY" },
	};
	for (const auto& alias : aliases) {
		services.register_command_alias(alias.canonical, alias.alias);
	}
	return true;
}

} // namespace tcp_proxy_plugin
