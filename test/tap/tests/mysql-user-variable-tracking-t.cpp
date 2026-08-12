/**
 * @file mysql-user-variable-tracking-t.cpp
 * @brief End-to-end coverage for literal user-variable tracking across multiplexed backends.
 */

#include <array>
#include <cstdlib>
#include <cstring>
#include <fstream>
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

struct BackendUdvInspection {
	size_t matching_hostgroups { 0 };
	size_t statuses_present { 0 };
	size_t inspected { 0 };
	bool all_clear { true };
};

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
	if (!tracking || !set_parser || !query_parser || !set_lock) {
		return std::nullopt;
	}
	return SavedConfig { *tracking, *set_parser, *query_parser, *set_lock };
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
	const bool log_ready = infra_datadir &&
		open_file_and_seek_end(std::string(infra_datadir) + "/proxysql.log", proxysql_log) == 0;
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
	const json diagnostics = aggregate_session
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

	proxy.reset();
	MysqlPtr isolated = connect_mysql(cl.host, cl.port, cl.username, cl.password, "test");
	std::array<bool, 2> isolated_ids_reused { false, false };
	if (isolated) {
		for (size_t route_index = 0; route_index < route_comments.size(); ++route_index) {
			auto connection_id = query_scalar(isolated.get(),
				route_comments[route_index] + "SELECT CONNECTION_ID()");
			isolated_ids_reused[route_index] = connection_id && !connection_id->is_null &&
				route_connection_ids[route_index] &&
				connection_id->bytes == *route_connection_ids[route_index];
		}
	}
	ok(isolated_ids_reused[0],
		"a fresh frontend reuses route A's exact pooled backend connection ID");
	ok(isolated_ids_reused[1],
		"a fresh frontend reuses route B's exact pooled backend connection ID");
	bool isolated_values_are_null = isolated != nullptr;
	const std::string null_checks =
		"SELECT @browser_lang IS NULL,@browser_time IS NULL,@browser_timezone IS NULL,"
		"@ip_address IS NULL,@uv_string IS NULL,@uv_integer IS NULL,@uv_positive IS NULL,"
		"@uv_decimal IS NULL,@uv_exponent IS NULL,@uv_hex IS NULL,@uv_hex_quoted IS NULL,"
		"@uv_bit IS NULL,@uv_bit_quoted IS NULL,@uv_null IS NULL";
	if (isolated) {
		for (const char* route : { "/* uv_hg_a */ ", "/* uv_hg_b */ " }) {
			auto result = query_result(isolated.get(), std::string(route) + null_checks);
			if (!result || result->rows.size() != 1 || result->rows.front().size() != 14) {
				isolated_values_are_null = false;
				continue;
			}
			for (const auto& cell : result->rows.front()) {
				isolated_values_are_null = isolated_values_are_null && !cell.is_null && cell.bytes == "1";
			}
		}
	}
	ok(isolated_values_are_null,
		"the fresh frontend sees NULL through both reused pooled backend connections");
	isolated.reset();
	ok(cleanup.run(),
		"temporary functions, rules, hostgroups, and runtime variables are restored");
	return exit_status();
}
