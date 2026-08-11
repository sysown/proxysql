/**
 * @file test_gtid_from_ok-t.cpp
 * @brief Verify that a GTID learned from an OK packet is shared across
 *        hostgroup copies of an endpoint, including an inactive GTID reader.
 */

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include <netdb.h>
#include <sys/socket.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "proxysql_utils.h"

namespace {

constexpr int RW_HG = 15983;
constexpr int RO_HG = 15984;
constexpr int RULE_FIRST = 159830;
constexpr int RULE_LAST = 159832;
constexpr const char* TEST_COMMENT = "test_gtid_from_ok-t";

static std::string sql_quote(MYSQL* mysql, const std::string& value) {
	std::vector<char> escaped(value.size() * 2 + 1);
	const unsigned long len = mysql_real_escape_string(
		mysql, escaped.data(), value.data(), value.size()
	);
	return "'" + std::string(escaped.data(), len) + "'";
}

static bool exec_query(MYSQL* mysql, const std::string& query, const char* context) {
	if (mysql_query(mysql, query.c_str()) == 0) {
		return true;
	}

	diag("%s failed: errno=%u error=%s query=%s", context, mysql_errno(mysql),
		mysql_error(mysql), query.c_str());
	return false;
}

static bool get_single_row(
	MYSQL* mysql,
	const std::string& query,
	std::vector<std::string>& row,
	const char* context
) {
	const auto result = mysql_query_ext_rows(mysql, query);
	if (result.first != 0 || result.second.size() != 1) {
		diag("%s failed: rc=%d rows=%zu query=%s", context, result.first,
			result.second.size(), query.c_str());
		return false;
	}

	row = result.second.front();
	return true;
}

static bool get_count(MYSQL* admin, const std::string& query, uint64_t& count) {
	const ext_val_t<uint64_t> result = mysql_query_ext_val(admin, query, uint64_t(0));
	if (result.err != 0) {
		diag("Count query failed: err=%d query=%s", result.err, query.c_str());
		return false;
	}
	count = result.val;
	return true;
}

static bool get_variable(MYSQL* admin, const std::string& name, std::string& value) {
	std::vector<std::string> row;
	const std::string query =
		"SELECT variable_value FROM global_variables WHERE variable_name=" + sql_quote(admin, name);
	if (!get_single_row(admin, query, row, ("save " + name).c_str()) || row.empty()) {
		return false;
	}
	value = row[0];
	return true;
}

static bool set_variable(MYSQL* admin, const std::string& name, const std::string& value) {
	return exec_query(admin, "SET " + name + "=" + sql_quote(admin, value), ("set " + name).c_str());
}

static std::string get_session_gtid(MYSQL* mysql) {
	if (!(mysql->server_status & SERVER_SESSION_STATE_CHANGED)) {
		return {};
	}
	const char* data = nullptr;
	size_t len = 0;
	if (mysql_session_track_get_first(mysql, SESSION_TRACK_GTIDS, &data, &len) != 0 || data == nullptr) {
		return {};
	}
	return std::string(data, len);
}

static bool resolve_ipv4(const std::string& hostname, std::string& numeric_address) {
	addrinfo hints {};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	addrinfo* addresses = nullptr;
	const int lookup_rc = getaddrinfo(hostname.c_str(), nullptr, &hints, &addresses);
	if (lookup_rc != 0 || addresses == nullptr) {
		diag("getaddrinfo(%s) failed: %s", hostname.c_str(), gai_strerror(lookup_rc));
		if (addresses != nullptr) {
			freeaddrinfo(addresses);
		}
		return false;
	}

	char host[NI_MAXHOST] = {};
	const int name_rc = getnameinfo(
		addresses->ai_addr, addresses->ai_addrlen, host, sizeof(host), nullptr, 0, NI_NUMERICHOST
	);
	freeaddrinfo(addresses);
	if (name_rc != 0) {
		diag("getnameinfo(%s) failed: %s", hostname.c_str(), gai_strerror(name_rc));
		return false;
	}

	numeric_address = host;
	return true;
}

static bool get_endpoint_gtid(
	MYSQL* admin,
	const std::string& address,
	int port,
	bool& found,
	std::string& gtid
) {
	const std::string query =
		"SELECT COALESCE(gtid_executed,'') FROM stats_mysql_gtid_executed WHERE hostname=" +
		sql_quote(admin, address) + " AND port=" + std::to_string(port);
	const auto result = mysql_query_ext_rows(admin, query);
	if (result.first != 0 || result.second.size() > 1) {
		diag("GTID stats query failed: rc=%d rows=%zu query=%s", result.first,
			result.second.size(), query.c_str());
		return false;
	}

	found = !result.second.empty();
	gtid = found && !result.second.front().empty() ? result.second.front()[0] : std::string {};
	return true;
}

template <typename Predicate>
static bool poll_endpoint_gtid(
	MYSQL* admin,
	const std::string& address,
	int port,
	Predicate predicate,
	std::string& observed
) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	do {
		bool found = false;
		if (!get_endpoint_gtid(admin, address, port, found, observed)) {
			return false;
		}
		if (found && predicate(observed)) {
			return true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	} while (std::chrono::steady_clock::now() < deadline);

	return false;
}

static MYSQL* connect_mysql(char* host, int port, char* username, char* password) {
	return init_mysql_conn(host, port, username, password);
}

static bool select_single_string(MYSQL* mysql, const std::string& query, std::string& value) {
	if (!exec_query(mysql, query, "select single value")) {
		return false;
	}

	MYSQL_RES* result = mysql_store_result(mysql);
	if (result == nullptr) {
		diag("mysql_store_result failed: errno=%u error=%s", mysql_errno(mysql), mysql_error(mysql));
		return false;
	}

	MYSQL_ROW row = mysql_fetch_row(result);
	const bool valid = row != nullptr && row[0] != nullptr && mysql_num_rows(result) == 1;
	if (valid) {
		value = row[0];
	} else {
		diag("Expected one non-NULL row for query: %s", query.c_str());
	}
	mysql_free_result(result);
	return valid;
}

struct TestConnections {
	MYSQL* direct = nullptr;
	MYSQL* first = nullptr;
	MYSQL* untracked = nullptr;
	MYSQL* tracked = nullptr;

	void close_all() {
		for (MYSQL** connection : { &direct, &first, &untracked, &tracked }) {
			if (*connection != nullptr) {
				mysql_close(*connection);
				*connection = nullptr;
			}
		}
	}
};

class CleanupGuard {
public:
	CleanupGuard(MYSQL* admin, const CommandLine& cl, TestConnections& connections)
		: admin_(admin), mysql_username_(cl.mysql_username), mysql_password_(cl.mysql_password),
		  connections_(connections) {}

	~CleanupGuard() {
		connections_.close_all();

		if (rules_installed_) {
			const std::string query =
				"DELETE FROM mysql_query_rules WHERE rule_id BETWEEN " + std::to_string(RULE_FIRST) +
				" AND " + std::to_string(RULE_LAST) + " AND comment=" + sql_quote(admin_, TEST_COMMENT);
			exec_query(admin_, query, "remove dedicated query rules");
			exec_query(admin_, "LOAD MYSQL QUERY RULES TO RUNTIME", "load query-rule cleanup");
		}

		if (servers_installed_) {
			const std::string query =
				"DELETE FROM mysql_servers WHERE hostgroup_id IN (" + std::to_string(RW_HG) + "," +
				std::to_string(RO_HG) + ") AND comment=" + sql_quote(admin_, TEST_COMMENT);
			exec_query(admin_, query, "remove dedicated servers");
			exec_query(admin_, "LOAD MYSQL SERVERS TO RUNTIME", "load server cleanup");
		}

		if (!saved_variables_.empty()) {
			for (const auto& variable : saved_variables_) {
				const std::string query =
					"UPDATE global_variables SET variable_value=" + sql_quote(admin_, variable.second) +
					" WHERE variable_name=" + sql_quote(admin_, variable.first);
				exec_query(admin_, query, ("restore " + variable.first).c_str());
			}
			exec_query(admin_, "LOAD MYSQL VARIABLES TO RUNTIME", "load variable cleanup");
		}

		if ((table_created_ || !backend_session_track_gtids_.empty()) && !address_.empty()) {
			MYSQL* direct = connect_mysql(
				const_cast<char*>(address_.c_str()), port_,
				const_cast<char*>(mysql_username_.c_str()), const_cast<char*>(mysql_password_.c_str())
			);
			if (direct == nullptr) {
				diag("Cleanup could not connect to %s:%d for backend cleanup",
					address_.c_str(), port_);
			} else {
				if (table_created_) {
					exec_query(direct, "DROP TABLE IF EXISTS test.gtid_from_ok", "drop test table");
				}
				if (!backend_session_track_gtids_.empty()) {
					exec_query(direct,
						"SET GLOBAL session_track_gtids=" +
							sql_quote(direct, backend_session_track_gtids_),
						"restore backend session_track_gtids");
				}
				mysql_close(direct);
			}
		}
	}

	void set_endpoint(const std::string& address, int port) {
		address_ = address;
		port_ = port;
	}

	void save_variable(const std::string& name, const std::string& value) {
		saved_variables_[name] = value;
	}
	void save_backend_session_track_gtids(const std::string& value) {
		backend_session_track_gtids_ = value;
	}

	void mark_servers_installed() { servers_installed_ = true; }
	void mark_rules_installed() { rules_installed_ = true; }
	void mark_table_created() { table_created_ = true; }

private:
	MYSQL* admin_;
	std::string mysql_username_;
	std::string mysql_password_;
	TestConnections& connections_;
	std::map<std::string, std::string> saved_variables_;
	std::string backend_session_track_gtids_;
	std::string address_;
	int port_ = 0;
	bool servers_installed_ = false;
	bool rules_installed_ = false;
	bool table_created_ = false;
};

static int run_test(
	CommandLine& cl,
	MYSQL* admin,
	TestConnections& connections,
	CleanupGuard& cleanup
) {
	std::string writer_query =
		"SELECT hostname,port FROM runtime_mysql_servers WHERE status='ONLINE'";
	const char* writer_hg = std::getenv("BINLOG_WHG");
	if (writer_hg != nullptr && *writer_hg != '\0') {
		char* end = nullptr;
		const long parsed_hg = std::strtol(writer_hg, &end, 10);
		if (end != writer_hg && *end == '\0' && parsed_hg >= 0) {
			writer_query += " ORDER BY CASE WHEN hostgroup_id=" + std::to_string(parsed_hg) +
				" THEN 0 ELSE 1 END,hostgroup_id,hostname,port LIMIT 1";
		} else {
			diag("Ignoring invalid BINLOG_WHG value: %s", writer_hg);
		}
	}
	if (writer_query.find(" ORDER BY ") == std::string::npos) {
		writer_query += " ORDER BY hostgroup_id,hostname,port LIMIT 1";
	}

	std::vector<std::string> writer;
	std::string address;
	int mysql_port = 0;
	bool writer_resolved = get_single_row(admin, writer_query, writer, "select configured writer") &&
		writer.size() >= 2;
	if (writer_resolved) {
		mysql_port = std::atoi(writer[1].c_str());
		writer_resolved = mysql_port > 0 && resolve_ipv4(writer[0], address);
	}
	ok(writer_resolved, "resolved configured writer to a numeric IPv4 endpoint");
	if (!writer_resolved) {
		return EXIT_FAILURE;
	}
	diag("Dedicated endpoint: configured=%s:%d numeric=%s:%d", writer[0].c_str(), mysql_port,
		address.c_str(), mysql_port);
	cleanup.set_endpoint(address, mysql_port);

	uint64_t count = 0;
	const std::string endpoint_filter =
		" hostname=" + sql_quote(admin, address) + " AND port=" + std::to_string(mysql_port);
	bool count_ok = get_count(admin, "SELECT COUNT(*) FROM runtime_mysql_servers WHERE" + endpoint_filter, count);
	ok(count_ok && count == 0, "numeric endpoint is absent from runtime_mysql_servers before setup");
	if (!count_ok || count != 0) {
		return EXIT_FAILURE;
	}

	count_ok = get_count(admin, "SELECT COUNT(*) FROM stats_mysql_gtid_executed WHERE" + endpoint_filter, count);
	ok(count_ok && count == 0, "numeric endpoint is absent from stats_mysql_gtid_executed before setup");
	if (!count_ok || count != 0) {
		return EXIT_FAILURE;
	}

	const std::string server_insert =
		"INSERT INTO mysql_servers (hostgroup_id,hostname,port,gtid_port,weight,comment) VALUES (" +
		std::to_string(RW_HG) + "," + sql_quote(admin, address) + "," + std::to_string(mysql_port) +
		",0,1," + sql_quote(admin, TEST_COMMENT) + "),(" + std::to_string(RO_HG) + "," +
		sql_quote(admin, address) + "," + std::to_string(mysql_port) + ",1,1," +
		sql_quote(admin, TEST_COMMENT) + ")";
	if (!exec_query(admin, server_insert, "insert dedicated servers")) {
		return EXIT_FAILURE;
	}
	cleanup.mark_servers_installed();

	const std::string username = sql_quote(admin, cl.username);
	const std::string comment = sql_quote(admin, TEST_COMMENT);
	const std::string rules_insert =
		"INSERT INTO mysql_query_rules "
		"(rule_id,active,username,match_digest,destination_hostgroup,apply,comment) VALUES "
		"(159830,1," + username + ",'^INSERT INTO test\\.gtid_from_ok',15983,1," + comment + "),"
		"(159831,1," + username + ",'^SELECT @@session\\.session_track_gtids',15983,1," + comment + "),"
		"(159832,1," + username + ",'^SELECT id FROM test\\.gtid_from_ok',15984,1," + comment + ")";
	if (!exec_query(admin, rules_insert, "insert dedicated query rules")) {
		return EXIT_FAILURE;
	}
	cleanup.mark_rules_installed();

	const std::vector<std::string> required_variables {
		"mysql-connect_timeout_server_max",
		"mysql-client_session_track_gtid",
		"mysql-default_session_track_gtids",
		"mysql-server_capabilities"
	};
	for (const std::string& name : required_variables) {
		std::string value;
		if (!get_variable(admin, name, value)) {
			diag("Required MySQL variable is unavailable: %s", name.c_str());
			return EXIT_FAILURE;
		}
		cleanup.save_variable(name, value);
	}

	std::string update_gtid_saved;
	if (get_variable(admin, "mysql-update_gtid_from_ok", update_gtid_saved)) {
		cleanup.save_variable("mysql-update_gtid_from_ok", update_gtid_saved);
	} else {
		diag("mysql-update_gtid_from_ok is not present yet; SET below establishes the expected red phase");
	}

	std::string capabilities;
	if (!get_variable(admin, "mysql-server_capabilities", capabilities)) {
		return EXIT_FAILURE;
	}
	char* end = nullptr;
	const uint64_t parsed_caps = std::strtoull(capabilities.c_str(), &end, 10);
	if (end == capabilities.c_str() || *end != '\0') {
		diag("Invalid mysql-server_capabilities value: %s", capabilities.c_str());
		return EXIT_FAILURE;
	}
	const uint64_t tracking_caps = parsed_caps | CLIENT_SESSION_TRACKING;

	if (!set_variable(admin, "mysql-connect_timeout_server_max", "1000") ||
		!set_variable(admin, "mysql-client_session_track_gtid", "true") ||
		!set_variable(admin, "mysql-default_session_track_gtids", "OFF") ||
		!set_variable(admin, "mysql-server_capabilities", std::to_string(tracking_caps)) ||
		!set_variable(admin, "mysql-update_gtid_from_ok", "false")) {
		return EXIT_FAILURE;
	}
	if (!exec_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME", "load test variables") ||
		!exec_query(admin, "LOAD MYSQL SERVERS TO RUNTIME", "load dedicated servers") ||
		!exec_query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME", "load dedicated query rules")) {
		return EXIT_FAILURE;
	}

	connections.direct = connect_mysql(
		const_cast<char*>(address.c_str()), mysql_port, cl.mysql_username, cl.mysql_password
	);
	std::string backend_session_track_gtids;
	const bool backend_tracking_ready = connections.direct != nullptr &&
		select_single_string(connections.direct, "SELECT @@GLOBAL.session_track_gtids",
			backend_session_track_gtids);
	if (backend_tracking_ready) {
		cleanup.save_backend_session_track_gtids(backend_session_track_gtids);
	}
	if (!backend_tracking_ready ||
		!exec_query(connections.direct, "SET GLOBAL session_track_gtids='OFF'",
			"set backend session_track_gtids default OFF")) {
		return EXIT_FAILURE;
	}

	bool table_ready =
		exec_query(connections.direct, "CREATE DATABASE IF NOT EXISTS test", "create test database") &&
		exec_query(connections.direct, "DROP TABLE IF EXISTS test.gtid_from_ok", "drop stale test table") &&
		exec_query(connections.direct, "CREATE TABLE test.gtid_from_ok (id INT PRIMARY KEY)", "create test table");
	if (table_ready) {
		cleanup.mark_table_created();
		mysql_close(connections.direct);
		connections.direct = nullptr;
	}
	ok(table_ready, "created test.gtid_from_ok through a direct backend connection");
	if (!table_ready) {
		return EXIT_FAILURE;
	}

	std::string endpoint_gtid;
	const bool initially_empty = poll_endpoint_gtid(
		admin, address, mysql_port, [](const std::string& value) { return value.empty(); }, endpoint_gtid
	);
	ok(initially_empty, "inactive reader exposes an initially empty endpoint GTID record");
	if (!initially_empty) {
		diag("Initial endpoint GTID value: %s", endpoint_gtid.c_str());
		return EXIT_FAILURE;
	}

	connections.first = connect_mysql(cl.host, cl.port, cl.username, cl.password);
	if (connections.first == nullptr ||
		!exec_query(connections.first, "SET SESSION session_track_gtids=OWN_GTID", "enable OWN_GTID for row 1")) {
		return EXIT_FAILURE;
	}
	const int insert1_rc = mysql_query(connections.first, "INSERT INTO test.gtid_from_ok VALUES (1)");
	if (insert1_rc != 0) {
		diag("Row 1 insert failed: errno=%u error=%s", mysql_errno(connections.first), mysql_error(connections.first));
	}
	const std::string gtid1 = insert1_rc == 0 ? get_session_gtid(connections.first) : std::string {};
	ok(insert1_rc == 0 && !gtid1.empty(), "row 1 INSERT returned a GTID in its OK packet");
	if (insert1_rc != 0 || gtid1.empty()) {
		return EXIT_FAILURE;
	}
	diag("Row 1 GTID: %s", gtid1.c_str());

	const std::string disabled_read =
		"/*+ ;min_gtid=" + gtid1 + " */ SELECT id FROM test.gtid_from_ok WHERE id=1";
	const int disabled_rc = mysql_query(connections.first, disabled_read.c_str());
	const unsigned int disabled_errno = mysql_errno(connections.first);
	const std::string disabled_error = mysql_error(connections.first);
	ok(disabled_rc != 0, "disabled OK-packet ingestion rejects min_gtid read (errno=%u, error=%s)",
		disabled_errno, disabled_error.c_str());
	if (disabled_rc == 0) {
		MYSQL_RES* unexpected = mysql_store_result(connections.first);
		if (unexpected != nullptr) {
			mysql_free_result(unexpected);
		}
		return EXIT_FAILURE;
	}
	if (!exec_query(connections.first, "/* hostgroup=15983 */ BEGIN", "pin tracked row 1 backend")) {
		return EXIT_FAILURE;
	}

	if (!set_variable(admin, "mysql-update_gtid_from_ok", "true") ||
		!exec_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME", "enable OK-packet ingestion")) {
		return EXIT_FAILURE;
	}

	connections.untracked = connect_mysql(cl.host, cl.port, cl.username, cl.password);
	if (connections.untracked == nullptr) {
		return EXIT_FAILURE;
	}
	std::string tracking_state;
	const bool tracking_query_ok = select_single_string(
		connections.untracked, "SELECT @@session.session_track_gtids", tracking_state
	);
	ok(tracking_query_ok && strcasecmp(tracking_state.c_str(), "OFF") == 0,
		"fresh backend session_track_gtids remains OFF (value=%s)", tracking_state.c_str());
	if (!tracking_query_ok) {
		return EXIT_FAILURE;
	}

	const int insert2_rc = mysql_query(connections.untracked, "INSERT INTO test.gtid_from_ok VALUES (2)");
	if (insert2_rc != 0) {
		diag("Row 2 insert failed: errno=%u error=%s", mysql_errno(connections.untracked),
			mysql_error(connections.untracked));
	}
	const std::string gtid2 = insert2_rc == 0 ? get_session_gtid(connections.untracked) : std::string {};
	ok(insert2_rc == 0 && gtid2.empty(), "row 2 INSERT returns no GTID when the client did not request one");
	if (insert2_rc != 0) {
		return EXIT_FAILURE;
	}

	bool found = false;
	endpoint_gtid.clear();
	const bool after_row2_ok = get_endpoint_gtid(admin, address, mysql_port, found, endpoint_gtid);
	ok(after_row2_ok && found && endpoint_gtid.empty(),
		"endpoint GTID set remains empty after untracked row 2 INSERT");
	if (!after_row2_ok || !found || !endpoint_gtid.empty()) {
		return EXIT_FAILURE;
	}
	mysql_close(connections.untracked);
	connections.untracked = nullptr;
	if (!exec_query(connections.first, "ROLLBACK", "release tracked row 1 backend")) {
		return EXIT_FAILURE;
	}
	mysql_close(connections.first);
	connections.first = nullptr;

	connections.tracked = connect_mysql(cl.host, cl.port, cl.username, cl.password);
	if (connections.tracked == nullptr ||
		!exec_query(connections.tracked, "SET SESSION session_track_gtids=OWN_GTID", "enable OWN_GTID for row 3")) {
		return EXIT_FAILURE;
	}
	const int insert3_rc = mysql_query(connections.tracked, "INSERT INTO test.gtid_from_ok VALUES (3)");
	if (insert3_rc != 0) {
		diag("Row 3 insert failed: errno=%u error=%s", mysql_errno(connections.tracked), mysql_error(connections.tracked));
	}
	const std::string gtid3 = insert3_rc == 0 ? get_session_gtid(connections.tracked) : std::string {};
	ok(insert3_rc == 0 && !gtid3.empty(), "row 3 INSERT returned a GTID in its OK packet");
	if (insert3_rc != 0 || gtid3.empty()) {
		return EXIT_FAILURE;
	}
	diag("Row 3 GTID: %s", gtid3.c_str());

	endpoint_gtid.clear();
	const bool learned = poll_endpoint_gtid(
		admin, address, mysql_port,
		[&gtid3](const std::string& value) { return value.find(gtid3) != std::string::npos; },
		endpoint_gtid
	);
	ok(learned, "endpoint GTID stats contains row 3 GTID (stats=%s)", endpoint_gtid.c_str());
	if (!learned) {
		return EXIT_FAILURE;
	}

	uint64_t queries_before = 0;
	const std::string query_counter =
		"SELECT COALESCE(SUM(Queries),0) FROM stats_mysql_connection_pool WHERE hostgroup=" +
		std::to_string(RO_HG);
	if (!get_count(admin, query_counter, queries_before)) {
		return EXIT_FAILURE;
	}

	const std::string causal_read =
		"/*+ ;min_gtid=" + gtid3 + " */ SELECT id FROM test.gtid_from_ok WHERE id=3";
	std::string selected_id;
	const bool read_ok = select_single_string(connections.tracked, causal_read, selected_id);
	ok(read_ok && selected_id == "3", "causal read through inactive-reader endpoint returns row 3");
	if (!read_ok || selected_id != "3") {
		return EXIT_FAILURE;
	}

	uint64_t queries_after = 0;
	const bool after_ok = get_count(admin, query_counter, queries_after);
	ok(after_ok && queries_after > queries_before,
		"HG %d query counter increments for causal read (%llu -> %llu)", RO_HG,
		static_cast<unsigned long long>(queries_before), static_cast<unsigned long long>(queries_after));
	return after_ok && queries_after > queries_before ? EXIT_SUCCESS : EXIT_FAILURE;
}

} // namespace

int main(int, char**) {
	plan(14);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables");
		return EXIT_FAILURE;
	}

	MYSQL* admin = connect_mysql(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (admin == nullptr) {
		diag("Failed to connect to ProxySQL Admin");
		return EXIT_FAILURE;
	}

	TestConnections connections;
	int run_rc = EXIT_FAILURE;
	{
		CleanupGuard cleanup(admin, cl, connections);
		run_rc = run_test(cl, admin, connections, cleanup);
	}

	mysql_close(admin);
	return run_rc == EXIT_SUCCESS ? exit_status() : EXIT_FAILURE;
}
