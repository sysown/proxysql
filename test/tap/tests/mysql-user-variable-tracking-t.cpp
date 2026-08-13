/**
 * @file mysql-user-variable-tracking-t.cpp
 * @brief End-to-end coverage for literal user-variable tracking across multiplexed backends.
 */

#include <array>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <unistd.h>

#include "mysql.h"

#include "command_line.h"
#include "json.hpp"
#include "tap.h"
#include "utils.h"

namespace {

using MysqlPtr = std::unique_ptr<MYSQL, decltype(&mysql_close)>;
using MysqlResultPtr = std::unique_ptr<MYSQL_RES, decltype(&mysql_free_result)>;
using nlohmann::json;

struct ResultCell {
	bool is_null { true };
	std::string bytes;
	enum enum_field_types type { MYSQL_TYPE_NULL };
};

struct QueryResult {
	std::vector<std::string> field_names;
	std::vector<std::vector<ResultCell>> rows;
};

MysqlPtr connect_mysql(
	const char* host, int port, const char* username, const char* password,
	const char* schema = nullptr, bool use_ssl = false) {
	MysqlPtr connection(mysql_init(nullptr), &mysql_close);
	if (connection && use_ssl) {
		mysql_ssl_set(connection.get(), nullptr, nullptr, nullptr, nullptr, nullptr);
	}
	if (connection && !mysql_real_connect(
			connection.get(), host, username, password, schema, port, nullptr,
			use_ssl ? CLIENT_SSL : 0)) {
		diag("Connection to %s:%d failed: errno=%u sqlstate=%s", host, port,
			mysql_errno(connection.get()), mysql_sqlstate(connection.get()));
		connection.reset();
	}
	return connection;
}

bool execute(MYSQL* connection, const std::string& query) {
	if (mysql_real_query(connection, query.data(), query.size()) != 0) {
		diag("Query failed: errno=%u sqlstate=%s (SQL text redacted)",
			mysql_errno(connection), mysql_sqlstate(connection));
		return false;
	}

	MysqlResultPtr result(mysql_store_result(connection), &mysql_free_result);
	return result != nullptr || mysql_field_count(connection) == 0;
}

bool execute_expect_error(MYSQL* connection, const std::string& query) {
	if (mysql_real_query(connection, query.data(), query.size()) == 0) {
		MysqlResultPtr result(mysql_store_result(connection), &mysql_free_result);
		diag("Query unexpectedly succeeded (SQL text redacted)");
		return false;
	}
	return mysql_errno(connection) != 0 && std::strlen(mysql_sqlstate(connection)) == 5;
}

bool execute_prepared(MYSQL* connection, const std::string& query) {
	MYSQL_STMT* statement = mysql_stmt_init(connection);
	if (!statement) {
		return false;
	}
	const bool success =
		mysql_stmt_prepare(statement, query.data(), query.size()) == 0 &&
		mysql_stmt_execute(statement) == 0 && mysql_stmt_store_result(statement) == 0;
	if (!success) {
		diag("Prepared query failed: errno=%u sqlstate=%s (SQL text redacted)",
			mysql_stmt_errno(statement), mysql_stmt_sqlstate(statement));
	}
	mysql_stmt_close(statement);
	return success;
}

std::optional<QueryResult> query_result(MYSQL* connection, const std::string& query) {
	if (mysql_real_query(connection, query.data(), query.size()) != 0) {
		diag("Query failed: errno=%u sqlstate=%s (SQL text redacted)",
			mysql_errno(connection), mysql_sqlstate(connection));
		return std::nullopt;
	}

	MysqlResultPtr result(mysql_store_result(connection), &mysql_free_result);
	if (!result) {
		diag("Query returned no result set (SQL text redacted)");
		return std::nullopt;
	}

	QueryResult output;
	const unsigned int field_count = mysql_num_fields(result.get());
	MYSQL_FIELD* fields = mysql_fetch_fields(result.get());
	for (unsigned int i = 0; i < field_count; ++i) {
		output.field_names.emplace_back(fields[i].name ? fields[i].name : "");
	}

	MYSQL_ROW row = nullptr;
	while ((row = mysql_fetch_row(result.get()))) {
		unsigned long* lengths = mysql_fetch_lengths(result.get());
		std::vector<ResultCell> cells;
		cells.reserve(field_count);
		for (unsigned int i = 0; i < field_count; ++i) {
			ResultCell cell;
			cell.is_null = row[i] == nullptr;
			cell.type = fields[i].type;
			if (row[i]) {
				cell.bytes.assign(row[i], lengths[i]);
			}
			cells.push_back(std::move(cell));
		}
		output.rows.push_back(std::move(cells));
	}
	return output;
}

std::optional<ResultCell> query_scalar(MYSQL* connection, const std::string& query) {
	auto result = query_result(connection, query);
	if (!result || result->rows.size() != 1 || result->rows.front().size() != 1) {
		diag("Expected exactly one row and one column (SQL text redacted)");
		return std::nullopt;
	}
	return result->rows.front().front();
}

bool result_cells_equal(const ResultCell& left, const ResultCell& right) {
	return left.is_null == right.is_null && left.type == right.type &&
		(left.is_null || left.bytes == right.bytes);
}

bool scalar_equals(MYSQL* connection, const std::string& query, const char* expected) {
	auto cell = query_scalar(connection, query);
	return cell && !cell->is_null && cell->bytes == expected;
}

bool query_rows_equal(MYSQL* proxy, MYSQL* direct, const std::string& query) {
	auto proxy_result = query_result(proxy, query);
	auto direct_result = query_result(direct, query);
	if (!proxy_result || !direct_result || proxy_result->rows.size() != direct_result->rows.size()) {
		return false;
	}
	for (size_t row = 0; row < proxy_result->rows.size(); ++row) {
		if (proxy_result->rows[row].size() != direct_result->rows[row].size()) {
			return false;
		}
		for (size_t column = 0; column < proxy_result->rows[row].size(); ++column) {
			if (!result_cells_equal(proxy_result->rows[row][column], direct_result->rows[row][column])) {
				return false;
			}
		}
	}
	return true;
}

std::optional<json> internal_session(MYSQL* connection) {
	auto cell = query_scalar(connection, "PROXYSQL INTERNAL SESSION");
	if (!cell || cell->is_null) {
		return std::nullopt;
	}
	try {
		return json::parse(cell->bytes);
	} catch (const std::exception& error) {
		diag("Unable to parse PROXYSQL INTERNAL SESSION: %s", error.what());
		return std::nullopt;
	}
}

struct UserVariableAggregate {
	size_t count { 0 };
	size_t stored_bytes { 0 };
	std::string fingerprint;
};

std::optional<UserVariableAggregate> user_variable_aggregate(MYSQL* connection) {
	auto session = internal_session(connection);
	if (!session || !session->contains("conn") ||
		!(*session)["conn"].contains("user_variables")) {
		return std::nullopt;
	}
	const auto& diagnostics = (*session)["conn"]["user_variables"];
	if (!diagnostics.contains("count") || !diagnostics["count"].is_number_unsigned() ||
		!diagnostics.contains("stored_bytes") ||
		!diagnostics["stored_bytes"].is_number_unsigned() ||
		!diagnostics.contains("fingerprint") || !diagnostics["fingerprint"].is_string()) {
		return std::nullopt;
	}
	return UserVariableAggregate {
		diagnostics["count"].get<size_t>(),
		diagnostics["stored_bytes"].get<size_t>(),
		diagnostics["fingerprint"].get<std::string>()
	};
}

bool aggregates_equal(
	const UserVariableAggregate& before, const UserVariableAggregate& after) {
	return before.count == after.count && before.stored_bytes == after.stored_bytes &&
		before.fingerprint == after.fingerprint;
}

std::optional<size_t> tracked_user_variable_count(MYSQL* connection) {
	auto session = internal_session(connection);
	if (!session || !session->contains("conn") ||
		!(*session)["conn"].contains("user_variables")) {
		return std::nullopt;
	}
	const auto& diagnostics = (*session)["conn"]["user_variables"];
	if (!diagnostics.contains("count") || !diagnostics["count"].is_number_unsigned()) {
		return std::nullopt;
	}
	return diagnostics["count"].get<size_t>();
}

std::optional<int> locked_hostgroup(MYSQL* connection) {
	auto session = internal_session(connection);
	if (!session || !session->contains("locked_on_hostgroup") ||
		!(*session)["locked_on_hostgroup"].is_number_integer()) {
		return std::nullopt;
	}
	return (*session)["locked_on_hostgroup"].get<int>();
}

struct UserVariableCounters {
	uint64_t assignments { 0 };
	uint64_t replay_commands { 0 };
	uint64_t replay_failures { 0 };
	uint64_t fallback_unsupported { 0 };
	uint64_t fallback_limits { 0 };
};

std::optional<uint64_t> parse_uint64(const std::string& text) {
	uint64_t value { 0 };
	const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
	return error == std::errc {} && end == text.data() + text.size()
		? std::optional<uint64_t> { value }
		: std::nullopt;
}

bool only_limit_fallback_incremented(
	const UserVariableCounters& before, const UserVariableCounters& after) {
	return after.assignments == before.assignments &&
		after.replay_commands == before.replay_commands &&
		after.replay_failures == before.replay_failures &&
		after.fallback_unsupported == before.fallback_unsupported &&
		after.fallback_limits == before.fallback_limits + 1;
}

std::optional<UserVariableCounters> user_variable_counters(MYSQL* admin) {
	auto result = query_result(admin,
		"SELECT Variable_Name,Variable_Value FROM stats_mysql_global WHERE Variable_Name IN ("
		"'User_variable_assignments_tracked','User_variable_replay_commands',"
		"'User_variable_replay_failures','User_variable_fallback_unsupported',"
		"'User_variable_fallback_limits')");
	if (!result || result->rows.size() != 5) {
		return std::nullopt;
	}
	std::map<std::string, uint64_t> values;
	for (const auto& row : result->rows) {
		if (row.size() != 2 || row[0].is_null || row[1].is_null) {
			return std::nullopt;
		}
		auto value = parse_uint64(row[1].bytes);
		if (!value.has_value()) {
			return std::nullopt;
		}
		values[row[0].bytes] = *value;
	}
	const std::array<const char*, 5> names {
		"User_variable_assignments_tracked", "User_variable_replay_commands",
		"User_variable_replay_failures", "User_variable_fallback_unsupported",
		"User_variable_fallback_limits"
	};
	for (const char* name : names) {
		if (!values.count(name)) {
			return std::nullopt;
		}
	}
	return UserVariableCounters {
		values[names[0]], values[names[1]], values[names[2]], values[names[3]], values[names[4]]
	};
}

struct BackendUdvInspection {
	size_t matching_hostgroups { 0 };
	size_t statuses_present { 0 };
	size_t inspected { 0 };
	bool all_clear { true };
};

struct AttachedBackendStatus {
	size_t matching_hostgroups { 0 };
	bool user_variable { false };
	bool no_multiplex { false };
	bool multiplex_disabled { false };
};

AttachedBackendStatus inspect_attached_backend_status(
	const json& session, int expected_hostgroup) {
	AttachedBackendStatus inspection;
	if (!session.contains("backends") || !session["backends"].is_array()) {
		return inspection;
	}
	for (const auto& backend : session["backends"]) {
		if (!backend.contains("hostgroup_id") ||
			backend.value("hostgroup_id", -1) != expected_hostgroup ||
			!backend.contains("conn")) {
			continue;
		}
		++inspection.matching_hostgroups;
		const auto& connection = backend["conn"];
		if (connection.contains("status") && connection["status"].is_object()) {
			const auto& status = connection["status"];
			if (status.contains("user_variable") && status["user_variable"].is_boolean()) {
				inspection.user_variable = status["user_variable"].get<bool>();
			}
			if (status.contains("no_multiplex") && status["no_multiplex"].is_boolean()) {
				inspection.no_multiplex = status["no_multiplex"].get<bool>();
			}
		}
		if (connection.contains("MultiplexDisabled") && connection["MultiplexDisabled"].is_boolean()) {
			inspection.multiplex_disabled = connection["MultiplexDisabled"].get<bool>();
		}
	}
	return inspection;
}

BackendUdvInspection inspect_backend_user_variable_status(
	const json& session, int expected_hostgroup) {
	BackendUdvInspection inspection;
	if (!session.contains("backends") || !session["backends"].is_array()) {
		return inspection;
	}
	for (const auto& backend : session["backends"]) {
		if (!backend.contains("hostgroup_id") ||
			backend.value("hostgroup_id", -1) != expected_hostgroup) {
			continue;
		}
		++inspection.matching_hostgroups;
		if (backend.contains("conn") && backend["conn"].contains("status")) {
			++inspection.statuses_present;
			const auto& status = backend["conn"]["status"];
			if (status.contains("user_variable") && status["user_variable"].is_boolean()) {
				++inspection.inspected;
				inspection.all_clear = inspection.all_clear &&
					!status["user_variable"].get<bool>();
			}
		}
	}
	return inspection;
}

std::string sql_quote(MYSQL* connection, const std::string& value) {
	std::string quoted(value.size() * 2 + 3, '\0');
	quoted[0] = '\'';
	const unsigned long escaped_length = mysql_real_escape_string(
		connection, quoted.data() + 1, value.data(), value.size());
	quoted.resize(escaped_length + 2);
	quoted[escaped_length + 1] = '\'';
	return quoted;
}

struct SavedConfig {
	std::string tracking;
	std::string set_parser;
	std::string query_parser;
	std::string set_lock;
	std::string multiplexing;
};

struct BackendEndpoint {
	std::string hostname;
	int port { 0 };
	int weight { 0 };
	int compression { 0 };
	int max_connections { 0 };
	int max_replication_lag { 0 };
	int max_latency_ms { 0 };
	int use_ssl { 0 };
	int gtid_port { 0 };
};

struct FixtureOwnership {
	bool hostgroups { false };
	bool rules { false };
	bool read_function { false };
	bool metadata_function { false };
	bool context_function { false };
};

std::optional<std::string> admin_variable(MYSQL* admin, const char* name) {
	auto cell = query_scalar(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name=" +
		sql_quote(admin, name));
	if (!cell || cell->is_null) {
		return std::nullopt;
	}
	return cell->bytes;
}

bool open_proxysql_log(const char* configured_datadir, std::fstream& log) {
	if (configured_datadir && open_file_and_seek_end(
			std::string(configured_datadir) + "/proxysql.log", log) == 0) {
		return true;
	}
	// Some registered groups use REGULAR_INFRA_DATADIR for test assets. The
	// isolated runner always mounts the daemon data directory here.
	log.close();
	log.clear();
	return (!configured_datadir || std::string(configured_datadir) != "/var/lib/proxysql") &&
		open_file_and_seek_end("/var/lib/proxysql/proxysql.log", log) == 0;
}

bool set_admin_variable(MYSQL* admin, const char* name, const std::string& value) {
	return execute(admin,
		"UPDATE global_variables SET variable_value=" + sql_quote(admin, value) +
		" WHERE variable_name=" + sql_quote(admin, name));
}

std::optional<SavedConfig> save_config(MYSQL* admin) {
	auto tracking = admin_variable(admin, "mysql-user_variable_tracking");
	auto set_parser = admin_variable(admin, "mysql-set_parser_algorithm");
	auto query_parser = admin_variable(admin, "mysql-query_processor_parser");
	auto set_lock = admin_variable(admin, "mysql-set_query_lock_on_hostgroup");
	auto multiplexing = admin_variable(admin, "mysql-multiplexing");
	if (!tracking || !set_parser || !query_parser || !set_lock || !multiplexing) {
		return std::nullopt;
	}
	return SavedConfig {
		*tracking, *set_parser, *query_parser, *set_lock, *multiplexing
	};
}

std::optional<BackendEndpoint> select_backend(MYSQL* admin) {
	auto result = query_result(admin,
		"SELECT hostname,port,weight,compression,max_connections,max_replication_lag,max_latency_ms,use_ssl,gtid_port "
		"FROM runtime_mysql_servers "
		"WHERE status='ONLINE' ORDER BY hostgroup_id,hostname,port LIMIT 1");
	if (!result || result->rows.size() != 1 || result->rows.front().size() != 9) {
		return std::nullopt;
	}
	const auto& row = result->rows.front();
	for (const auto& cell : row) {
		if (cell.is_null) {
			return std::nullopt;
		}
	}
	return BackendEndpoint {
		row[0].bytes, std::stoi(row[1].bytes), std::stoi(row[2].bytes), std::stoi(row[3].bytes),
		std::stoi(row[4].bytes), std::stoi(row[5].bytes), std::stoi(row[6].bytes),
		std::stoi(row[7].bytes), std::stoi(row[8].bytes)
	};
}

bool configure_fixture(
	MYSQL* admin, const CommandLine& cl, const BackendEndpoint& backend,
	const std::string& tag, FixtureOwnership& owned) {
	auto occupied = query_result(admin,
		"SELECT (SELECT COUNT(*) FROM mysql_servers WHERE hostgroup_id IN (18110,18111)),"
		"(SELECT COUNT(*) FROM runtime_mysql_servers WHERE hostgroup_id IN (18110,18111))");
	if (!occupied || occupied->rows.size() != 1 || occupied->rows.front().size() != 2 ||
		occupied->rows.front()[0].is_null || occupied->rows.front()[0].bytes != "0" ||
		occupied->rows.front()[1].is_null || occupied->rows.front()[1].bytes != "0") {
		diag("Temporary hostgroups 18110/18111 are already in use");
		return false;
	}

	const std::string server_values =
		"(18110," + sql_quote(admin, backend.hostname) + "," + std::to_string(backend.port) +
		"," + std::to_string(backend.weight) + "," + std::to_string(backend.compression) +
		"," + std::to_string(backend.max_connections) + "," + std::to_string(backend.max_replication_lag) +
		"," + std::to_string(backend.max_latency_ms) + "," + std::to_string(backend.use_ssl) +
		"," + std::to_string(backend.gtid_port) + "," + sql_quote(admin, tag) + ")," +
		"(18111," + sql_quote(admin, backend.hostname) + "," + std::to_string(backend.port) +
		"," + std::to_string(backend.weight) + "," + std::to_string(backend.compression) +
		"," + std::to_string(backend.max_connections) + "," + std::to_string(backend.max_replication_lag) +
		"," + std::to_string(backend.max_latency_ms) + "," + std::to_string(backend.use_ssl) +
		"," + std::to_string(backend.gtid_port) + "," + sql_quote(admin, tag) + ")";
	if (!execute(admin,
		"INSERT INTO mysql_servers(hostgroup_id,hostname,port,weight,compression,max_connections,"
		"max_replication_lag,max_latency_ms,use_ssl,gtid_port,comment) VALUES " +
		server_values)) {
		return false;
	}
	owned.hostgroups = true;

	const long rule_base = -181100000L - (static_cast<long>(getpid()) % 100000L) * 2L;
	auto rule_collision = query_result(admin,
		"SELECT (SELECT COUNT(*) FROM mysql_query_rules WHERE rule_id IN (" +
		std::to_string(rule_base) + "," + std::to_string(rule_base + 1) + "))," +
		"(SELECT COUNT(*) FROM runtime_mysql_query_rules WHERE rule_id IN (" +
		std::to_string(rule_base) + "," + std::to_string(rule_base + 1) + "))");
	if (!rule_collision || rule_collision->rows.size() != 1 ||
		rule_collision->rows.front().size() != 2 ||
		rule_collision->rows.front()[0].is_null ||
		rule_collision->rows.front()[0].bytes != "0" ||
		rule_collision->rows.front()[1].is_null ||
		rule_collision->rows.front()[1].bytes != "0") {
		diag("Reserved negative query-rule IDs are already in use");
		return false;
	}
	if (!execute(admin,
		"INSERT INTO mysql_query_rules(rule_id,active,username,match_pattern,destination_hostgroup,apply,comment) VALUES (" +
		std::to_string(rule_base) + ",1," + sql_quote(admin, cl.username) +
		"," + sql_quote(admin, "^/\\* uv_hg_a \\*/") + ",18110,1," + sql_quote(admin, tag) + "),(" +
		std::to_string(rule_base + 1) + ",1," + sql_quote(admin, cl.username) +
		"," + sql_quote(admin, "^/\\* uv_hg_b \\*/") + ",18111,1," + sql_quote(admin, tag) + ")")) {
		return false;
	}
	owned.rules = true;

	return set_admin_variable(admin, "mysql-user_variable_tracking", "1") &&
		set_admin_variable(admin, "mysql-set_parser_algorithm", "3") &&
		set_admin_variable(admin, "mysql-query_processor_parser", "0") &&
		set_admin_variable(admin, "mysql-set_query_lock_on_hostgroup", "1") &&
		execute(admin, "LOAD MYSQL SERVERS TO RUNTIME") &&
		execute(admin, "LOAD MYSQL QUERY RULES TO RUNTIME") &&
		execute(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
}

bool restore_config(
	MYSQL* admin, MYSQL* direct_backend, const SavedConfig& saved, const std::string& tag,
	const FixtureOwnership& owned) {
	bool success = true;
	if (owned.read_function && direct_backend) {
		success = execute(direct_backend, "DROP FUNCTION IF EXISTS test.proxysql_uv_read") && success;
	}
	if (owned.metadata_function && direct_backend) {
		success = execute(direct_backend, "DROP FUNCTION IF EXISTS test.proxysql_uv_metadata") && success;
	}
	if (owned.context_function && direct_backend) {
		success = execute(direct_backend, "DROP FUNCTION IF EXISTS test.proxysql_uv_context_metadata") && success;
	}
	if (owned.rules) {
		success = execute(admin, "DELETE FROM mysql_query_rules WHERE comment=" + sql_quote(admin, tag)) && success;
	}
	if (owned.hostgroups) {
		success = execute(admin,
			"DELETE FROM mysql_servers WHERE hostgroup_id IN (18110,18111) AND comment=" +
			sql_quote(admin, tag)) && success;
	}
	success = set_admin_variable(admin, "mysql-user_variable_tracking", saved.tracking) && success;
	success = set_admin_variable(admin, "mysql-set_parser_algorithm", saved.set_parser) && success;
	success = set_admin_variable(admin, "mysql-query_processor_parser", saved.query_parser) && success;
	success = set_admin_variable(admin, "mysql-set_query_lock_on_hostgroup", saved.set_lock) && success;
	success = execute(admin, "LOAD MYSQL VARIABLES TO RUNTIME") && success;
	success = execute(admin, "LOAD MYSQL QUERY RULES TO RUNTIME") && success;
	success = execute(admin, "LOAD MYSQL SERVERS TO RUNTIME") && success;
	return success;
}

} // namespace

int main() {
	plan(NO_PLAN);
	try {

	CommandLine cl;
	if (cl.getEnv()) {
		ok(false, "TAP environment is available");
		return exit_status();
	}

	MysqlPtr admin = connect_mysql(
		cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		ok(false, "ProxySQL admin connection is available");
		return exit_status();
	}

	auto saved = save_config(admin.get());
	if (!saved) {
		ok(false, "user-variable tracking configuration can be saved");
		return exit_status();
	}
	const bool multiplexing_enabled = saved->multiplexing == "true" ||
		saved->multiplexing == "1";
	const std::string tag = "mysql-user-variable-tracking-t-" + std::to_string(getpid());
	auto endpoint = select_backend(admin.get());
	if (!endpoint) {
		ok(false, "an ONLINE backend can be selected for the fixture");
		return exit_status();
	}
	MysqlPtr direct = connect_mysql(
		endpoint->hostname.c_str(), endpoint->port, cl.mysql_username, cl.mysql_password, "test",
		endpoint->use_ssl != 0);
	FixtureOwnership owned;
	struct Cleanup {
		MYSQL* admin;
		MYSQL* direct;
		const SavedConfig& saved;
		const std::string& tag;
		const FixtureOwnership& owned;
		bool active { true };
		Cleanup(const Cleanup&) = delete;
		Cleanup& operator=(const Cleanup&) = delete;
		bool run() {
			if (!active) {
				return true;
			}
			const bool success = restore_config(admin, direct, saved, tag, owned);
			active = !success;
			return success;
		}
		~Cleanup() {
			if (active) {
				restore_config(admin, direct, saved, tag, owned);
			}
		}
	} cleanup { admin.get(), direct.get(), *saved, tag, owned };

	ok(true, "user-variable tracking configuration is saved for unconditional cleanup");
	ok(direct != nullptr, "a direct connection to the selected backend is available");
	if (!direct) {
		return exit_status();
	}
	const bool fixture_configured = configure_fixture(admin.get(), cl, *endpoint, tag, owned);
	ok(fixture_configured,
		"temporary hostgroups, scoped rules, and tracking configuration are loaded");
	if (!fixture_configured) {
		return exit_status();
	}
	MysqlPtr proxy = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	if (!proxy) {
		ok(false, "frontend test connection is available");
		return exit_status();
	}
	std::fstream proxysql_log;
	const char* infra_datadir = std::getenv("REGULAR_INFRA_DATADIR");
	const bool log_ready = open_proxysql_log(infra_datadir, proxysql_log);
	ok(log_ready, "ProxySQL log is positioned before the reported SET");

	const std::string reported_set =
		"SET @browser_lang = 'en-US', @browser_time = '2026-08-11 18:11:12', "
		"@browser_timezone = 'GMT+2', @ip_address = '167.235.198.244'";
	ok(execute(proxy.get(), reported_set) && execute(direct.get(), reported_set),
		"the reported four-assignment literal SET succeeds through ProxySQL and directly");
	const std::string reported_select =
		"SELECT @browser_lang,@browser_time,@browser_timezone,@ip_address";
	ok(query_rows_equal(proxy.get(), direct.get(), reported_select),
		"the reported assignment preserves values and field types");

	const std::string literal_set =
		"SET @uv_string='line\\\\nquote\\\'slash\\\\\\\\',@uv_integer=-42,@uv_positive=+17,"
		"@uv_decimal=12.50,"
		"@uv_exponent=6.02e2,@uv_hex=0x4142,@uv_hex_quoted=X'4344',"
		"@uv_bit=0b101,@uv_bit_quoted=B'0110',@uv_null=NULL";
	ok(execute(proxy.get(), literal_set) && execute(direct.get(), literal_set),
		"every supported literal spelling succeeds through ProxySQL and directly");
	const std::string literal_select =
		"SELECT @uv_string,@uv_integer,@uv_positive,@uv_decimal,@uv_exponent,@uv_hex,@uv_hex_quoted,"
		"@uv_bit,@uv_bit_quoted,@uv_null";
	ok(query_rows_equal(proxy.get(), direct.get(), literal_select),
		"all supported literals preserve result bytes and MYSQL_FIELD types");
	const std::vector<std::string> tracked_variable_names {
		"browser_lang", "browser_time", "browser_timezone", "ip_address", "uv_string",
		"uv_integer", "uv_positive", "uv_decimal", "uv_exponent", "uv_hex",
		"uv_hex_quoted", "uv_bit", "uv_bit_quoted", "uv_null"
	};
	const std::array<std::string, 2> route_comments {
		"/* uv_hg_a */ ", "/* uv_hg_b */ "
	};
	const std::string all_variables_select =
		"SELECT @browser_lang,@browser_time,@browser_timezone,@ip_address,@uv_string,"
		"@uv_integer,@uv_positive,@uv_decimal,@uv_exponent,@uv_hex,@uv_hex_quoted,@uv_bit,"
		"@uv_bit_quoted,@uv_null";
	std::array<std::optional<std::string>, 2> route_connection_ids;
	std::array<bool, 2> route_ids_stable { true, true };
	bool switches_preserved_values = true;
	for (int round = 0; round < 4; ++round) {
		for (size_t route_index = 0; route_index < route_comments.size(); ++route_index) {
			const std::string& route = route_comments[route_index];
			const std::string routed_select = route + all_variables_select;
			auto routed = query_result(proxy.get(), routed_select);
			auto connection_id = query_scalar(proxy.get(), route + "SELECT CONNECTION_ID()");
			if (!routed || routed->rows.size() != 1 || routed->rows.front().size() != 14 ||
				!connection_id || connection_id->is_null) {
				switches_preserved_values = false;
				route_ids_stable[route_index] = false;
				continue;
			}
			if (route_connection_ids[route_index]) {
				route_ids_stable[route_index] = route_ids_stable[route_index] &&
					*route_connection_ids[route_index] == connection_id->bytes;
			} else {
				route_connection_ids[route_index] = connection_id->bytes;
			}
			auto direct_values = query_result(direct.get(),
				all_variables_select);
			if (!direct_values || direct_values->rows.size() != 1 ||
				direct_values->rows.front().size() != 14) {
				switches_preserved_values = false;
				continue;
			}
			for (size_t column = 0; column < 14; ++column) {
				switches_preserved_values = switches_preserved_values &&
					result_cells_equal(routed->rows.front()[column],
						direct_values->rows.front()[column]);
			}
		}
	}
	ok(switches_preserved_values,
		"all tracked values and types survive alternating hostgroup switches");
	ok(route_connection_ids[0] && route_ids_stable[0],
		"route A repeatedly returns one stable backend connection ID");
	ok(route_connection_ids[1] && route_ids_stable[1],
		"route B repeatedly returns one stable backend connection ID");
	ok(route_connection_ids[0] && route_connection_ids[1] &&
		*route_connection_ids[0] != *route_connection_ids[1],
		"routes A and B use distinct backend connection IDs");
	owned.read_function = execute(direct.get(),
		"CREATE FUNCTION test.proxysql_uv_read() RETURNS VARCHAR(64) DETERMINISTIC NO SQL "
		"RETURN @browser_lang");
	std::string metadata_expression = "CONCAT_WS('|',";
	for (const auto& name : tracked_variable_names) {
		metadata_expression +=
			"CONCAT_WS(':',IFNULL(HEX(@" + name + "),'<NULL>'),"
			"IFNULL(CHARSET(@" + name + "),'<NULL>'),"
			"IFNULL(COLLATION(@" + name + "),'<NULL>'),COERCIBILITY(@" + name + ")),";
	}
	metadata_expression.pop_back();
	metadata_expression += ")";
	owned.metadata_function = execute(direct.get(),
		"CREATE FUNCTION test.proxysql_uv_metadata() RETURNS TEXT DETERMINISTIC NO SQL RETURN " +
		metadata_expression);
	ok(owned.read_function && owned.metadata_function,
		"the read-only backend function fixtures are created after routing is proven");
	auto function_value = query_scalar(proxy.get(),
		"/* uv_hg_b */ SELECT test.proxysql_uv_read()");
	ok(function_value && !function_value->is_null && function_value->bytes == "en-US",
		"a routed backend-side reader with no at-sign sees synchronized tracked state");
	bool metadata_preserved = true;
	bool metadata_routes_match = true;
	auto direct_metadata = query_scalar(direct.get(), "SELECT test.proxysql_uv_metadata()");
	for (size_t route_index : { 0U, 1U, 0U, 1U }) {
		const std::string& route = route_comments[route_index];
		auto routed_id = query_scalar(proxy.get(), route + "SELECT CONNECTION_ID()");
		auto routed_metadata = query_scalar(proxy.get(),
			route + "SELECT test.proxysql_uv_metadata()");
		metadata_routes_match = metadata_routes_match && routed_id && !routed_id->is_null &&
			route_connection_ids[route_index] &&
			routed_id->bytes == *route_connection_ids[route_index];
		metadata_preserved = metadata_preserved && direct_metadata && routed_metadata &&
			result_cells_equal(*routed_metadata, *direct_metadata);
	}
	ok(metadata_routes_match,
		"metadata checks genuinely alternate across the proven A and B backend IDs");
	ok(metadata_preserved,
		"all 14 variables preserve HEX, charset, collation, and coercibility after every switch");

	bool warning_disclosed_reported_set = false;
	if (log_ready) {
		// Poll the already-open file for a bounded quiet period. If ProxySQL rotates
		// this descriptor during the interval, the test deliberately cannot follow
		// the replacement without a stable log marker from the daemon.
		for (int poll = 0; poll < 20 && !warning_disclosed_reported_set; ++poll) {
			proxysql_log.clear();
			std::string line;
			while (std::getline(proxysql_log, line)) {
				if (line.find("Unable to parse unknown SET query") != std::string::npos &&
					line.find("@browser_lang") != std::string::npos) {
					warning_disclosed_reported_set = true;
					break;
				}
			}
			if (!warning_disclosed_reported_set) {
				usleep(100000);
			}
		}
	}
	ok(log_ready && !warning_disclosed_reported_set,
		"the reported supported SET produces no unknown-SET warning or literal disclosure");

	auto aggregate_session = internal_session(proxy.get());
	const json diagnostics = aggregate_session && aggregate_session->contains("conn") &&
		(*aggregate_session)["conn"].is_object() &&
		(*aggregate_session)["conn"].contains("user_variables")
		? (*aggregate_session)["conn"]["user_variables"] : json {};
	const std::string serialized_session = aggregate_session
		? aggregate_session->dump() : std::string {};
	const bool fingerprint_valid = diagnostics.contains("fingerprint") &&
		diagnostics["fingerprint"].is_string() &&
		diagnostics["fingerprint"].get<std::string>().size() == 32;
	const bool aggregate_keys_only = diagnostics.is_object() && diagnostics.size() == 3 &&
		diagnostics.contains("count") && diagnostics.contains("stored_bytes") &&
		diagnostics.contains("fingerprint");
	ok(aggregate_session && aggregate_keys_only && diagnostics.value("count", 0) == 14 &&
		diagnostics.value("stored_bytes", 0) == 283 && fingerprint_valid,
		"internal session exposes only count 14, stored byte total 283, and an aggregate fingerprint");
	bool canonical_names_absent = true;
	for (const auto& name : tracked_variable_names) {
		canonical_names_absent = canonical_names_absent &&
			serialized_session.find(name) == std::string::npos;
	}
	const std::vector<std::string> distinctive_string_values {
		"en-US", "2026-08-11 18:11:12", "GMT+2", "167.235.198.244",
		R"(line\nquote'slash\\)"
	};
	bool distinctive_values_absent = true;
	for (const auto& value : distinctive_string_values) {
		distinctive_values_absent = distinctive_values_absent &&
			serialized_session.find(value) == std::string::npos;
	}
	ok(canonical_names_absent,
		"internal-session diagnostics contain none of the 14 canonical variable names");
	ok(distinctive_values_absent,
		"internal-session diagnostics contain none of the distinctive string values");
	bool transaction_status_clear = true;
	for (size_t route_index = 0; route_index < route_comments.size(); ++route_index) {
		const std::string& route = route_comments[route_index];
		const int expected_hostgroup = route_index == 0 ? 18110 : 18111;
		const bool transaction_started = execute(proxy.get(), route + "START TRANSACTION");
		auto transaction_id = query_scalar(proxy.get(), route + "SELECT CONNECTION_ID()");
		auto transaction_value = query_scalar(proxy.get(), route + "SELECT @browser_lang");
		auto transaction_session = internal_session(proxy.get());
		const BackendUdvInspection inspection = transaction_session
			? inspect_backend_user_variable_status(*transaction_session, expected_hostgroup)
			: BackendUdvInspection {};
		const bool rolled_back = execute(proxy.get(), "ROLLBACK");
		transaction_status_clear = transaction_status_clear && transaction_started &&
			transaction_id && !transaction_id->is_null && route_connection_ids[route_index] &&
			transaction_id->bytes == *route_connection_ids[route_index] &&
			transaction_value && !transaction_value->is_null &&
			transaction_value->bytes == "en-US" && transaction_session &&
			inspection.matching_hostgroups == 1 && inspection.statuses_present == 1 &&
			inspection.inspected == 1 && inspection.all_clear && rolled_back;
	}
	ok(transaction_status_clear,
		"each routed transaction exposes its attached hostgroup with user-variable status false");
	auto unlocked_session = internal_session(proxy.get());
	ok(unlocked_session && unlocked_session->value("locked_on_hostgroup", -2) == -1,
		"tracked traffic remains hostgroup-unlocked after both transaction rollbacks");

	// With multiplexing enabled, closing the original frontend returns both
	// connections to their pools and lets us prove exact-ID sanitization. With
	// multiplexing disabled, keep it open so each fresh frontend must receive a
	// distinct physical connection. Each route's ID and NULL checks deliberately
	// come from one result row.
	if (multiplexing_enabled) {
		proxy.reset();
	}
	std::array<bool, 2> isolated_id_condition { false, false };
	std::array<bool, 2> isolated_values_are_null { false, false };
	const std::string isolation_probe =
		"SELECT CONNECTION_ID(),@browser_lang IS NULL,@browser_time IS NULL,"
		"@browser_timezone IS NULL,"
		"@ip_address IS NULL,@uv_string IS NULL,@uv_integer IS NULL,@uv_positive IS NULL,"
		"@uv_decimal IS NULL,@uv_exponent IS NULL,@uv_hex IS NULL,@uv_hex_quoted IS NULL,"
		"@uv_bit IS NULL,@uv_bit_quoted IS NULL,@uv_null IS NULL";
	for (size_t route_index = 0; route_index < route_comments.size(); ++route_index) {
		MysqlPtr isolated = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
		auto result = isolated
			? query_result(isolated.get(), route_comments[route_index] + isolation_probe)
			: std::nullopt;
		if (!result || result->rows.size() != 1 || result->rows.front().size() != 15 ||
			result->rows.front()[0].is_null || !route_connection_ids[route_index]) {
			continue;
		}
		const auto& row = result->rows.front();
		isolated_id_condition[route_index] = multiplexing_enabled
			? row[0].bytes == *route_connection_ids[route_index]
			: row[0].bytes != *route_connection_ids[route_index];
		isolated_values_are_null[route_index] = true;
		for (size_t column = 1; column < row.size(); ++column) {
			isolated_values_are_null[route_index] =
				isolated_values_are_null[route_index] && !row[column].is_null &&
				row[column].bytes == "1";
		}
	}
	if (multiplexing_enabled) {
		ok(isolated_id_condition[0],
			"a fresh frontend reuses route A's exact pooled backend connection ID");
		ok(isolated_id_condition[1],
			"a fresh frontend reuses route B's exact pooled backend connection ID");
	} else {
		ok(isolated_id_condition[0],
			"a fresh frontend receives a distinct route A backend connection ID");
		ok(isolated_id_condition[1],
			"a fresh frontend receives a distinct route B backend connection ID");
	}
	ok(isolated_values_are_null[0] && isolated_values_are_null[1],
		"one response per route proves all variables are NULL on each fresh frontend");
	proxy.reset();

	MysqlPtr reset_session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const bool reset_staged = reset_session &&
		execute(reset_session.get(), "/* uv_hg_a */ SET @reset_lifecycle='reset-value'");
	const auto reset_id_before = reset_session
		? query_scalar(reset_session.get(), "/* uv_hg_a */ SELECT CONNECTION_ID()") : std::nullopt;
	const auto count_before_reset = reset_session
		? tracked_user_variable_count(reset_session.get()) : std::nullopt;
	ok(reset_staged && reset_id_before && !reset_id_before->is_null &&
		count_before_reset && *count_before_reset == 1,
		"reset lifecycle fixture begins with one tracked variable on a recorded backend ID");
	const int reset_rc = reset_session ? mysql_reset_connection(reset_session.get()) : -1;
	const auto count_after_reset = reset_session
		? tracked_user_variable_count(reset_session.get()) : std::nullopt;
	ok(reset_rc == 0 && count_after_reset && *count_after_reset == 0,
		"mysql_reset_connection clears frontend user-variable diagnostics");
	const auto reset_probe = reset_session
		? query_result(reset_session.get(),
			"/* uv_hg_a */ SELECT CONNECTION_ID(),@reset_lifecycle IS NULL")
		: std::nullopt;
	ok(reset_session && reset_id_before && !reset_id_before->is_null &&
		reset_probe && reset_probe->rows.size() == 1 && reset_probe->rows.front().size() == 2 &&
		!reset_probe->rows.front()[0].is_null &&
		(!multiplexing_enabled ||
			reset_probe->rows.front()[0].bytes == reset_id_before->bytes) &&
		!reset_probe->rows.front()[1].is_null && reset_probe->rows.front()[1].bytes == "1",
		multiplexing_enabled
			? "one response proves reset cleared the value on the exact recorded connection"
			: "one response proves reset cleared the value without assuming backend reuse");
	reset_session.reset();

	struct FallbackCase {
		const char* label;
		const char* query;
		bool server_accepts;
	};
	const std::array<FallbackCase, 12> fallback_cases {{
		{ "expression", "SET @fallback_value=1+1", true },
		{ "mixed system/user SET", "SET @fallback_value=1, sql_mode=''", true },
		{ "parenthesized value", "SET @fallback_value=(1)", true },
		{ "cast", "SET @fallback_value=CAST(1 AS SIGNED)", true },
		{ "character-set introducer", "SET @fallback_value=_utf8mb4'value'", true },
		{ "collation", "SET @fallback_value=_utf8mb4'value' COLLATE utf8mb4_bin", true },
		{ "malformed literal", "SET @fallback_value='unterminated", false },
		{ "partial statement", "SET @fallback_value=1 garbage", false },
		{ "trailing comma", "SET @fallback_value=1,", false },
		{ "second statement", "SET @fallback_value=1; SELECT 1", false },
		{ "SELECT assignment", "SELECT @fallback_value:=1", true },
		{ "SELECT INTO", "SELECT 1 INTO @fallback_value", true }
	}};
	bool fallback_cases_bound = true;
	for (const auto& test_case : fallback_cases) {
		MysqlPtr session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
		const auto aggregate_before = session
			? user_variable_aggregate(session.get()) : std::nullopt;
		const bool query_disposition = session && (test_case.server_accepts
			? execute(session.get(), test_case.query)
			: execute_expect_error(session.get(), test_case.query));
		const auto aggregate_after = session
			? user_variable_aggregate(session.get()) : std::nullopt;
		const auto locked = session ? locked_hostgroup(session.get()) : std::nullopt;
		const bool case_bound = query_disposition && aggregate_before && aggregate_after &&
			aggregates_equal(*aggregate_before, *aggregate_after) && locked && *locked >= 0;
		if (!case_bound) {
			diag("Fallback case did not preserve aggregate state and bind: %s", test_case.label);
		}
		fallback_cases_bound = fallback_cases_bound && case_bound;
	}
	ok(fallback_cases_bound,
		"unsupported, malformed, partial, and assignment queries preserve aggregate state and bind");

	MysqlPtr prepared_session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const auto prepared_aggregate_before = prepared_session
		? user_variable_aggregate(prepared_session.get()) : std::nullopt;
	const bool prepared_set_ok = prepared_session &&
		execute_prepared(prepared_session.get(), "SET @prepared_fallback=1");
	const auto prepared_aggregate_after = prepared_session
		? user_variable_aggregate(prepared_session.get()) : std::nullopt;
	const auto prepared_lock = prepared_session
		? locked_hostgroup(prepared_session.get()) : std::nullopt;
	ok(prepared_set_ok && prepared_aggregate_before && prepared_aggregate_after &&
		aggregates_equal(*prepared_aggregate_before, *prepared_aggregate_after) &&
		prepared_lock && *prepared_lock >= 0,
		"prepared SET preserves aggregate state and retains connection-bound fallback");

	const std::array<FallbackCase, 4> read_only_cases {{
		{ "plain read", "SELECT @read_only_value", true },
		{ "comparison", "SELECT @read_only_value = 1", true },
		{ "at-sign string", "SELECT '@read_only_value'", true },
		{ "at-sign comment", "SELECT 1 /* @read_only_value */", true }
	}};
	bool read_only_cases_unlocked = true;
	for (const auto& test_case : read_only_cases) {
		MysqlPtr session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
		const bool query_ok = session && execute(session.get(), test_case.query);
		const auto locked = session ? locked_hostgroup(session.get()) : std::nullopt;
		const bool case_unlocked = query_ok && locked && *locked == -1;
		if (!case_unlocked) {
			diag("Read-only case unexpectedly bound: %s", test_case.label);
		}
		read_only_cases_unlocked = read_only_cases_unlocked && case_unlocked;
	}
	ok(read_only_cases_unlocked,
		"plain reads, comparisons, strings, and comments containing at-signs remain unlocked");

	MysqlPtr rejected_session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const auto rejected_counter_before = user_variable_counters(admin.get());
	const auto rejected_count_before = rejected_session
		? tracked_user_variable_count(rejected_session.get()) : std::nullopt;
	const bool rejected_by_backend = rejected_session &&
		execute_expect_error(rejected_session.get(), "SET @backend_rejected=1e999999999");
	const auto rejected_count_after = rejected_session
		? tracked_user_variable_count(rejected_session.get()) : std::nullopt;
	const auto rejected_counter_after = user_variable_counters(admin.get());
	ok(rejected_by_backend && rejected_count_before && *rejected_count_before == 0 &&
		rejected_count_after && *rejected_count_after == 0 && rejected_counter_before &&
		rejected_counter_after &&
		rejected_counter_after->assignments == rejected_counter_before->assignments,
		"backend rejection commits no tracked state and increments no assignment counter");
	rejected_session.reset();

	MysqlPtr variable_limit_session = connect_mysql(
		cl.host, cl.port, cl.username, cl.password, "test");
	std::string first_128 = "/* uv_hg_a */ SET ";
	for (size_t i = 0; i < 128; ++i) {
		if (i != 0) {
			first_128 += ',';
		}
		first_128 += "@limit_" + std::to_string(i) + "=" + std::to_string(i);
	}
	const bool first_128_staged = variable_limit_session &&
		execute(variable_limit_session.get(), first_128);
	const auto variable_limit_aggregate_before = variable_limit_session
		? user_variable_aggregate(variable_limit_session.get()) : std::nullopt;
	const auto variable_limit_counter_before = user_variable_counters(admin.get());
	const bool variable_limit_fallback = variable_limit_session &&
		execute(variable_limit_session.get(), "/* uv_hg_a */ SET @limit_128=129");
	const auto variable_limit_aggregate_after = variable_limit_session
		? user_variable_aggregate(variable_limit_session.get()) : std::nullopt;
	const auto variable_limit_counter_after = user_variable_counters(admin.get());
	const auto variable_limit_lock = variable_limit_session
		? locked_hostgroup(variable_limit_session.get()) : std::nullopt;
	ok(first_128_staged && variable_limit_aggregate_before &&
		variable_limit_aggregate_before->count == 128 && variable_limit_fallback &&
		variable_limit_aggregate_after && aggregates_equal(
			*variable_limit_aggregate_before, *variable_limit_aggregate_after) &&
		variable_limit_counter_before && variable_limit_counter_after && only_limit_fallback_incremented(
			*variable_limit_counter_before, *variable_limit_counter_after) &&
		variable_limit_lock && *variable_limit_lock >= 0 &&
		scalar_equals(variable_limit_session.get(), "/* uv_hg_a */ SELECT @limit_0", "0") &&
		scalar_equals(variable_limit_session.get(), "/* uv_hg_a */ SELECT @limit_128", "129"),
		"the 129th variable preserves its aggregate fingerprint, increments only limit fallback, and binds");
	variable_limit_session.reset();

	MysqlPtr byte_limit_session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const std::string byte_target = "@byte_limit_base";
	const size_t payload_size = 64 * 1024 - byte_target.size() - 2;
	const std::string byte_limit_set =
		"/* uv_hg_b */ SET " + byte_target + "='" + std::string(payload_size, 'x') + "'";
	const bool byte_limit_staged = byte_limit_session &&
		execute(byte_limit_session.get(), byte_limit_set);
	const auto byte_limit_aggregate_before = byte_limit_session
		? user_variable_aggregate(byte_limit_session.get()) : std::nullopt;
	const auto byte_limit_counter_before = user_variable_counters(admin.get());
	const bool byte_limit_fallback = byte_limit_session &&
		execute(byte_limit_session.get(), "/* uv_hg_b */ SET @byte_limit_over=1");
	const auto byte_limit_aggregate_after = byte_limit_session
		? user_variable_aggregate(byte_limit_session.get()) : std::nullopt;
	const auto byte_limit_counter_after = user_variable_counters(admin.get());
	const auto byte_limit_lock = byte_limit_session
		? locked_hostgroup(byte_limit_session.get()) : std::nullopt;
	ok(byte_limit_staged && byte_limit_aggregate_before &&
		byte_limit_aggregate_before->stored_bytes == 64 * 1024 &&
		byte_limit_aggregate_before->count == 1 && byte_limit_fallback &&
		byte_limit_aggregate_after && aggregates_equal(
			*byte_limit_aggregate_before, *byte_limit_aggregate_after) &&
		byte_limit_counter_before && byte_limit_counter_after && only_limit_fallback_incremented(
			*byte_limit_counter_before, *byte_limit_counter_after) &&
		byte_limit_lock && *byte_limit_lock >= 0 &&
		scalar_equals(byte_limit_session.get(), "/* uv_hg_b */ SELECT @byte_limit_over", "1"),
		"state over 64 KiB preserves its aggregate fingerprint, increments only limit fallback, and binds");
	byte_limit_session.reset();

	owned.context_function = execute(direct.get(),
		"CREATE FUNCTION test.proxysql_uv_context_metadata() RETURNS VARCHAR(256) "
		"DETERMINISTIC NO SQL RETURN CONCAT_WS('|',HEX(@context_value),"
		"CHARSET(@context_value),COLLATION(@context_value))");
	ok(owned.context_function,
		"the interpretation-context metadata function is created with fixture ownership");

	MysqlPtr sql_mode_proxy = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	MysqlPtr sql_mode_direct = connect_mysql(
		endpoint->hostname.c_str(), endpoint->port, cl.mysql_username, cl.mysql_password, "test",
		endpoint->use_ssl != 0);
	const bool sql_mode_context_preserved = sql_mode_proxy && sql_mode_direct &&
		execute(sql_mode_proxy.get(), "/* uv_hg_a */ SET @context_value='A\\n'") &&
		execute(sql_mode_direct.get(), "SET @context_value='A\\n'") &&
		execute(sql_mode_proxy.get(), "/* uv_hg_a */ SET sql_mode='NO_BACKSLASH_ESCAPES'") &&
		execute(sql_mode_direct.get(), "SET sql_mode='NO_BACKSLASH_ESCAPES'") &&
		query_rows_equal(sql_mode_proxy.get(), sql_mode_direct.get(),
			"/* uv_hg_a */ SELECT test.proxysql_uv_context_metadata()");
	const auto sql_mode_lock = sql_mode_proxy
		? locked_hostgroup(sql_mode_proxy.get()) : std::nullopt;
	ok(sql_mode_context_preserved && sql_mode_lock && *sql_mode_lock >= 0,
		"sql_mode changes bind before execution and preserve prior HEX, charset, and collation");
	sql_mode_proxy.reset();
	sql_mode_direct.reset();

	MysqlPtr names_proxy = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	MysqlPtr names_direct = connect_mysql(
		endpoint->hostname.c_str(), endpoint->port, cl.mysql_username, cl.mysql_password, "test",
		endpoint->use_ssl != 0);
	const bool names_context_preserved = names_proxy && names_direct &&
		execute(names_proxy.get(), "/* uv_hg_b */ SET @context_value='context-value'") &&
		execute(names_direct.get(), "SET @context_value='context-value'") &&
		execute(names_proxy.get(), "/* uv_hg_b */ SET NAMES latin1") &&
		execute(names_direct.get(), "SET NAMES latin1") &&
		query_rows_equal(names_proxy.get(), names_direct.get(),
			"/* uv_hg_b */ SELECT test.proxysql_uv_context_metadata()");
	const auto names_lock = names_proxy ? locked_hostgroup(names_proxy.get()) : std::nullopt;
	ok(names_context_preserved && names_lock && *names_lock >= 0,
		"SET NAMES binds before execution and preserves prior HEX, charset, and collation");
	names_proxy.reset();
	names_direct.reset();

	std::fstream prerequisite_log;
	const bool prerequisite_log_ready = open_proxysql_log(infra_datadir, prerequisite_log);
	const bool misconfigured_loaded =
		set_admin_variable(admin.get(), "mysql-user_variable_tracking", "1") &&
		set_admin_variable(admin.get(), "mysql-set_parser_algorithm", "2") &&
		set_admin_variable(admin.get(), "mysql-query_processor_parser", "0") &&
		execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME");

	const std::string prerequisite_warning =
		"mysql-user_variable_tracking=1 remains inactive because "
		"mysql-set_parser_algorithm is not 3 and mysql-query_processor_parser is not 1. "
		"Enable either mysql-set_parser_algorithm=3 or mysql-query_processor_parser=1 "
		"to activate user-variable tracking.";
	size_t load_prerequisite_warning_count = 0;
	bool load_prerequisite_warning_fixed = true;
	bool load_prerequisite_warning_value_free = true;
	if (prerequisite_log_ready) {
		for (int poll = 0; poll < 20; ++poll) {
			prerequisite_log.clear();
			std::string line;
			while (std::getline(prerequisite_log, line)) {
				if (line.find("mysql-user_variable_tracking=1 remains inactive") ==
					std::string::npos) {
					continue;
				}
				++load_prerequisite_warning_count;
				load_prerequisite_warning_fixed = load_prerequisite_warning_fixed &&
					line.find(prerequisite_warning) != std::string::npos;
				load_prerequisite_warning_value_free =
					load_prerequisite_warning_value_free &&
					line.find("SET @") == std::string::npos;
			}
			usleep(100000);
		}
	}

	MysqlPtr misconfigured_session = connect_mysql(
		cl.host, cl.port, cl.username, cl.password, "test");
	const bool inactive_set_forwarded = misconfigured_session &&
		execute(misconfigured_session.get(), "SET @misconfigured_value='misconfigured-secret'");
	size_t post_load_prerequisite_warning_count = 0;
	bool post_load_prerequisite_warning_value_free = true;
	if (prerequisite_log_ready) {
		for (int poll = 0; poll < 20; ++poll) {
			prerequisite_log.clear();
			std::string line;
			while (std::getline(prerequisite_log, line)) {
				if (line.find("mysql-user_variable_tracking=1 remains inactive") !=
					std::string::npos) {
					++post_load_prerequisite_warning_count;
					post_load_prerequisite_warning_value_free =
						post_load_prerequisite_warning_value_free &&
						line.find("misconfigured-secret") == std::string::npos;
				}
			}
			usleep(100000);
		}
	}
	const auto inactive_count = misconfigured_session
		? tracked_user_variable_count(misconfigured_session.get()) : std::nullopt;
	const auto inactive_lock = misconfigured_session
		? locked_hostgroup(misconfigured_session.get()) : std::nullopt;
	const auto configured_tracking = admin_variable(admin.get(), "mysql-user_variable_tracking");
	const auto configured_set_parser = admin_variable(admin.get(), "mysql-set_parser_algorithm");
	const auto configured_query_parser = admin_variable(admin.get(), "mysql-query_processor_parser");
	ok(misconfigured_loaded && inactive_set_forwarded && inactive_count && *inactive_count == 0 &&
		inactive_lock && *inactive_lock >= 0 && configured_tracking && *configured_tracking == "1" &&
		configured_set_parser && *configured_set_parser == "2" && configured_query_parser &&
		*configured_query_parser == "0" && prerequisite_log_ready &&
		post_load_prerequisite_warning_count == 0 &&
		post_load_prerequisite_warning_value_free,
		"fallback emits no additional or literal-bearing prerequisite warning");
	ok(prerequisite_log_ready && load_prerequisite_warning_count == 1 &&
		load_prerequisite_warning_fixed && load_prerequisite_warning_value_free,
		"LOAD emits exactly one fixed value-free warning naming either parser prerequisite");
	misconfigured_session.reset();

	const bool full_query_parser_loaded =
		set_admin_variable(admin.get(), "mysql-set_parser_algorithm", "2") &&
		set_admin_variable(admin.get(), "mysql-query_processor_parser", "1") &&
		execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME");
	MysqlPtr full_query_session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const bool full_query_tracked = full_query_session &&
		execute(full_query_session.get(), "SET @full_query_parser='alternative'");
	const auto full_query_count = full_query_session
		? tracked_user_variable_count(full_query_session.get()) : std::nullopt;
	const auto full_query_lock = full_query_session
		? locked_hostgroup(full_query_session.get()) : std::nullopt;
	ok(full_query_parser_loaded && full_query_tracked && full_query_count &&
		*full_query_count == 1 && full_query_lock && *full_query_lock == -1,
		"full-query ParserSQL activates tracking while SET parser algorithm remains 2");
	full_query_session.reset();
	const bool primary_parser_restored =
		set_admin_variable(admin.get(), "mysql-set_parser_algorithm", "3") &&
		set_admin_variable(admin.get(), "mysql-query_processor_parser", "0") &&
		execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(primary_parser_restored,
		"ParserSQL SET mode is restored before remaining lifecycle phases");

	MysqlPtr mode_drain_session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const bool mode_drain_staged = mode_drain_session &&
		execute(mode_drain_session.get(), "SET @mode_drain='drain-value'");
	const bool mode_disabled = set_admin_variable(
		admin.get(), "mysql-user_variable_tracking", "0") &&
		execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME");
	const bool mode_drain_reads = mode_drain_session &&
		scalar_equals(mode_drain_session.get(), "/* uv_hg_a */ SELECT @mode_drain", "drain-value") &&
		scalar_equals(mode_drain_session.get(), "/* uv_hg_b */ SELECT @mode_drain", "drain-value");
	const auto mode_count_before_fallback = mode_drain_session
		? tracked_user_variable_count(mode_drain_session.get()) : std::nullopt;
	const bool mode_new_set_fallback = mode_drain_session &&
		execute(mode_drain_session.get(), "/* uv_hg_b */ SET @mode_disabled_new='fallback'");
	const auto mode_count_after_fallback = mode_drain_session
		? tracked_user_variable_count(mode_drain_session.get()) : std::nullopt;
	const auto mode_drain_lock = mode_drain_session
		? locked_hostgroup(mode_drain_session.get()) : std::nullopt;
	MysqlPtr mode_fresh_session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const bool mode_fresh_fallback = mode_fresh_session &&
		execute(mode_fresh_session.get(), "/* uv_hg_a */ SET @mode_fresh='fallback'");
	const auto mode_fresh_count = mode_fresh_session
		? tracked_user_variable_count(mode_fresh_session.get()) : std::nullopt;
	const auto mode_fresh_lock = mode_fresh_session
		? locked_hostgroup(mode_fresh_session.get()) : std::nullopt;
	ok(mode_drain_staged && mode_disabled && mode_drain_reads &&
		mode_count_before_fallback && *mode_count_before_fallback == 1 &&
		mode_new_set_fallback && mode_count_after_fallback && *mode_count_after_fallback == 1 &&
		mode_drain_lock && *mode_drain_lock >= 0 && mode_fresh_fallback &&
		mode_fresh_count && *mode_fresh_count == 0 && mode_fresh_lock && *mode_fresh_lock >= 0,
		"runtime mode disable drains tracked state across both hostgroups and makes new sessions fall back");
	mode_drain_session.reset();
	mode_fresh_session.reset();
	const bool mode_reenabled = set_admin_variable(
		admin.get(), "mysql-user_variable_tracking", "1") &&
		execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(mode_reenabled, "tracking mode is restored after mode-disable drain coverage");

	MysqlPtr parser_drain_session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const bool parser_drain_staged = parser_drain_session &&
		execute(parser_drain_session.get(), "SET @parser_drain='drain-value'");
	const bool parsers_disabled =
		set_admin_variable(admin.get(), "mysql-set_parser_algorithm", "2") &&
		set_admin_variable(admin.get(), "mysql-query_processor_parser", "0") &&
		execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME");
	const bool parser_drain_reads = parser_drain_session &&
		scalar_equals(parser_drain_session.get(), "/* uv_hg_a */ SELECT @parser_drain", "drain-value") &&
		scalar_equals(parser_drain_session.get(), "/* uv_hg_b */ SELECT @parser_drain", "drain-value");
	const auto parser_count_before_fallback = parser_drain_session
		? tracked_user_variable_count(parser_drain_session.get()) : std::nullopt;
	const bool parser_new_set_fallback = parser_drain_session &&
		execute(parser_drain_session.get(), "/* uv_hg_b */ SET @parser_disabled_new='fallback'");
	const auto parser_count_after_fallback = parser_drain_session
		? tracked_user_variable_count(parser_drain_session.get()) : std::nullopt;
	const auto parser_drain_lock = parser_drain_session
		? locked_hostgroup(parser_drain_session.get()) : std::nullopt;
	ok(parser_drain_staged && parsers_disabled && parser_drain_reads &&
		parser_count_before_fallback && *parser_count_before_fallback == 1 &&
		parser_new_set_fallback && parser_count_after_fallback && *parser_count_after_fallback == 1 &&
		parser_drain_lock && *parser_drain_lock >= 0,
		"runtime ParserSQL prerequisite disable drains prior state and makes new SET fall back");
	parser_drain_session.reset();
	const bool parsers_reenabled = set_admin_variable(
		admin.get(), "mysql-set_parser_algorithm", "3") &&
		execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(parsers_reenabled, "ParserSQL SET mode is restored after prerequisite-drain coverage");

	auto min_rule_id = query_scalar(admin.get(),
		"SELECT IFNULL(MIN(rule_id),0) FROM mysql_query_rules");
	const long policy_rule_base = min_rule_id && !min_rule_id->is_null
		? std::stol(min_rule_id->bytes) - 2 : -181300000L;
	auto policy_rule_collision = query_result(admin.get(),
		"SELECT (SELECT COUNT(*) FROM mysql_query_rules WHERE rule_id IN (" +
		std::to_string(policy_rule_base) + "," + std::to_string(policy_rule_base + 1) + "))," +
		"(SELECT COUNT(*) FROM runtime_mysql_query_rules WHERE rule_id IN (" +
		std::to_string(policy_rule_base) + "," + std::to_string(policy_rule_base + 1) + "))");
	const bool policy_rule_ids_free = policy_rule_collision &&
		policy_rule_collision->rows.size() == 1 && policy_rule_collision->rows.front().size() == 2 &&
		!policy_rule_collision->rows.front()[0].is_null &&
		policy_rule_collision->rows.front()[0].bytes == "0" &&
		!policy_rule_collision->rows.front()[1].is_null &&
		policy_rule_collision->rows.front()[1].bytes == "0";
	const bool policy_rules_loaded = policy_rule_ids_free && execute(admin.get(),
		"INSERT INTO mysql_query_rules(rule_id,active,username,match_pattern,destination_hostgroup,"
		"multiplex,apply,comment) VALUES (" + std::to_string(policy_rule_base) + ",1," +
		sql_quote(admin.get(), cl.username) + "," + sql_quote(admin.get(), "^/\\* uv_mux0 \\*/") +
		",18110,0,1," + sql_quote(admin.get(), tag) + "),(" +
		std::to_string(policy_rule_base + 1) + ",1," + sql_quote(admin.get(), cl.username) + "," +
		sql_quote(admin.get(), "^/\\* uv_mux1 \\*/") + ",18111,1,1," +
		sql_quote(admin.get(), tag) + ")") &&
		execute(admin.get(), "LOAD MYSQL QUERY RULES TO RUNTIME");
	ok(policy_rules_loaded,
		"collision-free tagged multiplex policy rules are loaded ahead of fixture routes");

	MysqlPtr mux0_session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const bool mux0_set = mux0_session &&
		execute(mux0_session.get(), "/* uv_mux0 */ SET @mux0_value='tracked'");
	const auto mux0_count = mux0_session
		? tracked_user_variable_count(mux0_session.get()) : std::nullopt;
	const bool mux0_transaction = mux0_session &&
		execute(mux0_session.get(), "/* uv_mux0 */ START TRANSACTION") &&
		scalar_equals(mux0_session.get(), "/* uv_mux0 */ SELECT @mux0_value", "tracked");
	auto mux0_internal = mux0_session ? internal_session(mux0_session.get()) : std::nullopt;
	const AttachedBackendStatus mux0_status = mux0_internal
		? inspect_attached_backend_status(*mux0_internal, 18110) : AttachedBackendStatus {};
	const bool mux0_rollback = mux0_session && execute(mux0_session.get(), "ROLLBACK");
	ok(mux0_set && mux0_count && *mux0_count == 1 && mux0_transaction &&
		mux0_status.matching_hostgroups == 1 && mux0_status.no_multiplex &&
		mux0_status.multiplex_disabled && mux0_rollback,
		"multiplex=0 is authoritative while supported SET remains tracked and readable");
	mux0_session.reset();

	MysqlPtr mux1_session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const bool mux1_unsafe = mux1_session &&
		execute(mux1_session.get(), "/* uv_mux1 */ SELECT @mux1_value:=1");
	const auto mux1_lock = mux1_session ? locked_hostgroup(mux1_session.get()) : std::nullopt;
	auto mux1_internal = mux1_session ? internal_session(mux1_session.get()) : std::nullopt;
	const AttachedBackendStatus mux1_status = mux1_internal
		? inspect_attached_backend_status(*mux1_internal, 18111) : AttachedBackendStatus {};
	ok(mux1_unsafe && mux1_lock && *mux1_lock == -1 &&
		mux1_status.matching_hostgroups == 1 && mux1_status.user_variable &&
		mux1_status.multiplex_disabled,
		"multiplex=1 unsafe use avoids hostgroup lock but remains protected from pool leakage");
	mux1_session.reset();

	const bool set_lock_disabled = set_admin_variable(
		admin.get(), "mysql-set_query_lock_on_hostgroup", "0") &&
		execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME");
	MysqlPtr status_fallback_session = connect_mysql(
		cl.host, cl.port, cl.username, cl.password, "test");
	const bool status_fallback_query = status_fallback_session &&
		execute(status_fallback_session.get(), "/* uv_hg_a */ SELECT @status_fallback:=1");
	const auto status_fallback_lock = status_fallback_session
		? locked_hostgroup(status_fallback_session.get()) : std::nullopt;
	auto status_fallback_internal = status_fallback_session
		? internal_session(status_fallback_session.get()) : std::nullopt;
	const AttachedBackendStatus status_fallback_status = status_fallback_internal
		? inspect_attached_backend_status(*status_fallback_internal, 18110)
		: AttachedBackendStatus {};
	ok(set_lock_disabled && status_fallback_query && status_fallback_lock &&
		*status_fallback_lock == -1 && status_fallback_status.matching_hostgroups == 1 &&
		status_fallback_status.user_variable && status_fallback_status.multiplex_disabled,
		"set-query-lock=0 protects the exact routed backend with user-variable status");
	status_fallback_session.reset();
	const bool set_lock_restored = set_admin_variable(
		admin.get(), "mysql-set_query_lock_on_hostgroup", "1") &&
		execute(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(set_lock_restored, "default SET lock policy is restored after status-fallback coverage");

	MysqlPtr change_user_session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const bool change_user_staged = change_user_session &&
		execute(change_user_session.get(), "/* uv_hg_b */ SET @change_user_lifecycle='change-user-value'");
	const auto change_user_id_before = change_user_session
		? query_scalar(change_user_session.get(), "/* uv_hg_b */ SELECT CONNECTION_ID()")
		: std::nullopt;
	const auto change_user_count_before = change_user_session
		? tracked_user_variable_count(change_user_session.get()) : std::nullopt;
	ok(change_user_staged && change_user_id_before && !change_user_id_before->is_null &&
		change_user_count_before && *change_user_count_before == 1,
		"change-user lifecycle fixture begins with one tracked variable on a recorded backend ID");
	const int change_user_rc = change_user_session
		? mysql_change_user(change_user_session.get(), cl.username, cl.password, "test") : -1;
	const auto change_user_count_after = change_user_session
		? tracked_user_variable_count(change_user_session.get()) : std::nullopt;
	const auto change_user_probe = change_user_session
		? query_result(change_user_session.get(),
			"/* uv_hg_b */ SELECT CONNECTION_ID(),@change_user_lifecycle IS NULL")
		: std::nullopt;
	ok(change_user_rc == 0 && change_user_count_after && *change_user_count_after == 0 &&
		change_user_session && change_user_id_before && !change_user_id_before->is_null &&
		change_user_probe && change_user_probe->rows.size() == 1 &&
		change_user_probe->rows.front().size() == 2 &&
		!change_user_probe->rows.front()[0].is_null &&
		change_user_probe->rows.front()[0].bytes == change_user_id_before->bytes &&
		!change_user_probe->rows.front()[1].is_null &&
		change_user_probe->rows.front()[1].bytes == "1",
		"one backend response proves change-user cleared the value on the exact recorded connection");
	change_user_session.reset();

	MysqlPtr disconnect_session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const bool disconnect_staged = disconnect_session &&
		execute(disconnect_session.get(), "/* uv_hg_a */ SET @disconnect_lifecycle='disconnect-value'");
	const auto disconnect_id = disconnect_session
		? query_scalar(disconnect_session.get(), "/* uv_hg_a */ SELECT CONNECTION_ID()") : std::nullopt;
	const bool disconnect_value_present = disconnect_session && scalar_equals(
		disconnect_session.get(), "/* uv_hg_a */ SELECT @disconnect_lifecycle", "disconnect-value");
	MysqlPtr after_disconnect = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const auto preattached_disconnect_id = !multiplexing_enabled && after_disconnect
		? query_scalar(after_disconnect.get(), "/* uv_hg_a */ SELECT CONNECTION_ID()")
		: std::nullopt;
	disconnect_session.reset();
	const auto disconnect_probe = after_disconnect
		? query_result(after_disconnect.get(),
			"/* uv_hg_a */ SELECT CONNECTION_ID(),@disconnect_lifecycle IS NULL")
		: std::nullopt;
	const bool disconnect_probe_valid = disconnect_probe &&
		disconnect_probe->rows.size() == 1 && disconnect_probe->rows.front().size() == 2 &&
		!disconnect_probe->rows.front()[0].is_null &&
		!disconnect_probe->rows.front()[1].is_null &&
		disconnect_probe->rows.front()[1].bytes == "1";
	const bool disconnect_id_condition = disconnect_probe_valid && disconnect_id &&
		!disconnect_id->is_null && (multiplexing_enabled
			? disconnect_probe->rows.front()[0].bytes == disconnect_id->bytes
			: preattached_disconnect_id && !preattached_disconnect_id->is_null &&
				disconnect_probe->rows.front()[0].bytes == preattached_disconnect_id->bytes &&
				disconnect_probe->rows.front()[0].bytes != disconnect_id->bytes);
	ok(disconnect_staged && disconnect_id && !disconnect_id->is_null &&
		disconnect_value_present && after_disconnect && disconnect_probe_valid &&
		disconnect_id_condition,
		multiplexing_enabled
			? "one response proves disconnect clears state on the exact reused pooled backend"
			: "one response proves a fresh backend ID and NULL state after disconnect without multiplexing");
	after_disconnect.reset();

	const auto counter_baseline = user_variable_counters(admin.get());
	MysqlPtr counter_replay_session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const bool counter_assignments_staged = counter_replay_session &&
		execute(counter_replay_session.get(), "SET @counter_alpha=1,@counter_bravo=2");
	std::array<std::optional<ResultCell>, 2> counter_route_ids;
	bool counter_replays_observed = counter_replay_session != nullptr;
	for (size_t route_index = 0; route_index < route_comments.size(); ++route_index) {
		const std::string& route = route_comments[route_index];
		counter_replays_observed = counter_replays_observed &&
			execute(counter_replay_session.get(), route + "START TRANSACTION");
		counter_route_ids[route_index] = query_scalar(
			counter_replay_session.get(), route + "SELECT CONNECTION_ID()");
		auto values = query_result(
			counter_replay_session.get(), route + "SELECT @counter_alpha,@counter_bravo");
		counter_replays_observed = counter_replays_observed && values &&
			values->rows.size() == 1 && values->rows.front().size() == 2 &&
			!values->rows.front()[0].is_null && values->rows.front()[0].bytes == "1" &&
			!values->rows.front()[1].is_null && values->rows.front()[1].bytes == "2" &&
			execute(counter_replay_session.get(), "ROLLBACK");
	}
	counter_replays_observed = counter_replays_observed && counter_route_ids[0] &&
		counter_route_ids[1] && !counter_route_ids[0]->is_null && !counter_route_ids[1]->is_null &&
		counter_route_ids[0]->bytes != counter_route_ids[1]->bytes;
	counter_replay_session.reset();

	MysqlPtr counter_unsupported_session = connect_mysql(
		cl.host, cl.port, cl.username, cl.password, "test");
	const bool counter_unsupported = counter_unsupported_session &&
		execute(counter_unsupported_session.get(), "SET @counter_unsupported=1+1");
	counter_unsupported_session.reset();

	MysqlPtr counter_limit_session = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	const std::string counter_limit_target = "@counter_limit_base";
	const size_t counter_limit_payload_size = 64 * 1024 - counter_limit_target.size() - 2;
	const bool counter_limit_base = counter_limit_session && execute(
		counter_limit_session.get(), "/* uv_hg_a */ SET " + counter_limit_target + "='" +
			std::string(counter_limit_payload_size, 'y') + "'");
	const bool counter_limit_overflow = counter_limit_session &&
		execute(counter_limit_session.get(), "/* uv_hg_a */ SET @counter_limit_over=1");
	counter_limit_session.reset();
	const auto counter_final = user_variable_counters(admin.get());
	ok(counter_baseline && counter_assignments_staged && counter_replays_observed &&
		counter_unsupported && counter_limit_base && counter_limit_overflow && counter_final &&
		counter_final->assignments == counter_baseline->assignments + 3 &&
		counter_final->replay_commands == counter_baseline->replay_commands + 2 &&
		counter_final->replay_failures == counter_baseline->replay_failures &&
		counter_final->fallback_unsupported == counter_baseline->fallback_unsupported + 1 &&
		counter_final->fallback_limits == counter_baseline->fallback_limits + 1,
		"controlled traffic produces exact deltas for all five user-variable counters");

	ok(cleanup.run(),
		"temporary functions, rules, hostgroups, and runtime variables are restored");
	} catch (const std::exception& error) {
		diag("Unexpected fixture exception: %s", error.what());
		ok(false, "fixture restores its owned state after an unexpected exception");
	}
	return exit_status();
}
