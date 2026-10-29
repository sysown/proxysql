/**
 * @file test_aurora_query_routing-t.cpp
 * @brief Exercise Aurora lag-aware server selection with a normal MySQL client query.
 *
 * The cluster simulator is deliberately limited to the monitor control plane: it
 * publishes a writer, a low-lag replica, and a high-lag replica.  The assertion
 * traffic itself is ordinary libmysql traffic through ProxySQL's frontend.
 */

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include "mysql.h"

#include "command_line.h"
#include "json.hpp"
#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

namespace {

constexpr const char* kSkippedReplicasStat = "get_aws_aurora_replicas_skipped_during_query";
constexpr const char* kAuroraReplicaVariable = "mysql-aurora_max_lag_ms_only_read_from_replicas";
constexpr const char* kRoutingQuery =
	"SELECT @@version_comment LIMIT 1 /* ;max_lag_ms=10;create_new_connection=1 */";
constexpr const char* kSelectedReader = "host.1.13.aws-test.com";
constexpr const char* kZeroLagReader = "host.1.12.aws-test.com";
constexpr const char* kWriter = "host.1.11.aws-test.com";

struct MySQLCloser {
	void operator()(MYSQL* mysql) const {
		if (mysql != nullptr) {
			mysql_close(mysql);
		}
	}
};

using mysql_ptr = std::unique_ptr<MYSQL, MySQLCloser>;

bool run_simulator_payload(const std::string& simulator, const std::string& payload) {
	std::string stdout_output;
	std::string stderr_output;
	const std::vector<const char*> args { "--mode", "verify", "-f", payload.c_str() };
	const int rc = wexecvp(simulator, args, {}, stdout_output, stderr_output);
	if (rc != EXIT_SUCCESS && (rc / 256) != EXIT_FAILURE) {
		diag("cluster_simulator failed: rc=%d stdout=%s stderr=%s", rc,
			stdout_output.c_str(), stderr_output.c_str());
		return false;
	}

	try {
		const auto result = nlohmann::ordered_json::parse(stdout_output);
		if (result.at("err_type") == "none") {
			return true;
		}
		diag("cluster_simulator verification failed: %s", stdout_output.c_str());
	} catch (const std::exception& error) {
		diag("cluster_simulator returned invalid JSON: %s; stdout=%s stderr=%s", error.what(),
			stdout_output.c_str(), stderr_output.c_str());
	}
	return false;
}

bool scalar_query(MYSQL* mysql, const std::string& query, std::string& value) {
	if (mysql_query(mysql, query.c_str()) != 0) {
		diag("Query failed: errno=%u error=%s query=%s", mysql_errno(mysql), mysql_error(mysql), query.c_str());
		return false;
	}
	MYSQL_RES* result = mysql_store_result(mysql);
	if (result == nullptr) {
		diag("Result retrieval failed: errno=%u error=%s query=%s", mysql_errno(mysql), mysql_error(mysql), query.c_str());
		return false;
	}
	MYSQL_ROW row = mysql_fetch_row(result);
	const bool valid = row != nullptr && row[0] != nullptr && mysql_num_rows(result) == 1;
	if (valid) {
		value = row[0];
	} else {
		diag("Expected exactly one non-NULL row for query=%s", query.c_str());
	}
	mysql_free_result(result);
	return valid;
}

bool get_stat(MYSQL* admin, uint64_t& value) {
	const auto result = mysql_query_ext_val(
		admin,
		"SELECT variable_value FROM stats_mysql_global WHERE variable_name='" +
			std::string(kSkippedReplicasStat) + "'",
		uint64_t { 0 }
	);
	if (result.err != 0) {
		diag("Could not read %s: err=%d", kSkippedReplicasStat, result.err);
		return false;
	}
	value = result.val;
	return true;
}

bool get_pool_connections(MYSQL* admin, const char* hostname, uint64_t& value) {
	const auto result = mysql_query_ext_val(
		admin,
		"SELECT COALESCE(SUM(ConnUsed + ConnFree), 0) FROM stats_mysql_connection_pool "
		"WHERE hostgroup=1272 AND srv_host='" + std::string(hostname) + "'",
		uint64_t { 0 }
	);
	if (result.err != 0) {
		diag("Could not read connection-pool state for %s: err=%d", hostname, result.err);
		return false;
	}
	value = result.val;
	return true;
}

class AuroraVariableRestore {
public:
	explicit AuroraVariableRestore(MYSQL* admin) : admin_(admin) {}

	bool set_one_replica_minimum() {
		std::string previous;
		if (!scalar_query(admin_,
			"SELECT variable_value FROM global_variables WHERE variable_name='" +
				std::string(kAuroraReplicaVariable) + "'", previous)) {
			return false;
		}
		previous_ = previous;
		// From this point on, a partially completed SET/LOAD must be restored
		// too.  Marking the guard active before the mutations covers the case
		// where SET succeeds but LOAD TO RUNTIME fails.
		active_ = true;
		if (mysql_query(admin_, "SET mysql-aurora_max_lag_ms_only_read_from_replicas=1") != 0 ||
			mysql_query(admin_, "LOAD MYSQL VARIABLES TO RUNTIME") != 0) {
			diag("Could not set %s: errno=%u error=%s", kAuroraReplicaVariable,
				mysql_errno(admin_), mysql_error(admin_));
			return false;
		}
		return true;
	}

	bool restore() {
		if (!active_) {
			return true;
		}
		const std::string query = "SET mysql-aurora_max_lag_ms_only_read_from_replicas=" + previous_;
		const bool restored = mysql_query(admin_, query.c_str()) == 0 &&
			mysql_query(admin_, "LOAD MYSQL VARIABLES TO RUNTIME") == 0;
		if (!restored) {
			diag("Could not restore %s: errno=%u error=%s", kAuroraReplicaVariable,
				mysql_errno(admin_), mysql_error(admin_));
		}
		active_ = false;
		return restored;
	}

	~AuroraVariableRestore() { (void)restore(); }

private:
	MYSQL* admin_;
	std::string previous_;
	bool active_ = false;
};

} // namespace

int main(int, char**) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to load TAP environment");
		return EXIT_FAILURE;
	}

	const char* simulator_env = std::getenv("CLUSTER_SIM_BINARY_PATH");
	const char* tests_root_env = std::getenv("CLUSTER_SIM_TESTS_ROOT");
	if (simulator_env == nullptr || *simulator_env == '\0' || tests_root_env == nullptr || *tests_root_env == '\0') {
		diag("CLUSTER_SIM_BINARY_PATH and CLUSTER_SIM_TESTS_ROOT are required");
		return EXIT_FAILURE;
	}

	plan(9);
	const std::string payload = std::string(tests_root_env) + "/aurora_traffic_payloads/query_routing.json";
	const bool simulator_ok = run_simulator_payload(simulator_env, payload);
	ok(simulator_ok, "Aurora monitor state is configured by cluster simulator");

	mysql_ptr admin { init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password) };
	if (!admin) {
		BAIL_OUT("Could not connect to ProxySQL Admin");
	}

	AuroraVariableRestore restore_variable { admin.get() };
	const bool variable_ok = simulator_ok && restore_variable.set_one_replica_minimum();
	ok(variable_ok, "Aurora selection requires one replica before retaining the writer");

	uint64_t skipped_before = 0;
	const bool before_ok = variable_ok && get_stat(admin.get(), skipped_before);
	ok(before_ok, "Read Aurora replica-skip counter before frontend traffic");

	uint64_t selected_reader_before = 0;
	const bool selected_reader_before_ok = before_ok &&
		get_pool_connections(admin.get(), kSelectedReader, selected_reader_before);
	ok(selected_reader_before_ok, "Read nonzero-lag reader pool before frontend traffic");

	uint64_t zero_lag_before = 0;
	const bool zero_lag_before_ok = selected_reader_before_ok &&
		get_pool_connections(admin.get(), kZeroLagReader, zero_lag_before);
	ok(zero_lag_before_ok, "Read zero-lag reader pool before frontend traffic");

	uint64_t writer_before = 0;
	const bool writer_before_ok = zero_lag_before_ok && get_pool_connections(admin.get(), kWriter, writer_before);
	ok(writer_before_ok, "Read writer pool before frontend traffic");

	char aurora_username[] = "aurora1";
	char aurora_password[] = "pass1";
	mysql_ptr proxy { init_mysql_conn(cl.host, cl.port, aurora_username, aurora_password) };
	std::string query_value;
	const bool query_ok = writer_before_ok && proxy && scalar_query(proxy.get(), kRoutingQuery, query_value);
	ok(query_ok, "Normal frontend query with max_lag_ms succeeds");

	uint64_t selected_reader_after = 0;
	uint64_t zero_lag_after = 0;
	uint64_t writer_after = 0;
	const bool selected_low_lag_replica = query_ok &&
		get_pool_connections(admin.get(), kSelectedReader, selected_reader_after) &&
		get_pool_connections(admin.get(), kZeroLagReader, zero_lag_after) &&
		get_pool_connections(admin.get(), kWriter, writer_after) &&
		selected_reader_after > selected_reader_before &&
		zero_lag_after == zero_lag_before && writer_after == writer_before;
	ok(selected_low_lag_replica,
		"Frontend traffic reaches nonzero-lag reader %s after excluding zero-lag %s and writer %s (%llu->%llu, %llu->%llu, %llu->%llu)",
		kSelectedReader, kZeroLagReader, kWriter,
		static_cast<unsigned long long>(selected_reader_before), static_cast<unsigned long long>(selected_reader_after),
		static_cast<unsigned long long>(zero_lag_before), static_cast<unsigned long long>(zero_lag_after),
		static_cast<unsigned long long>(writer_before), static_cast<unsigned long long>(writer_after));

	uint64_t skipped_after = 0;
	const bool counter_ok = selected_low_lag_replica && get_stat(admin.get(), skipped_after) &&
		skipped_after > skipped_before;
	ok(counter_ok, "High-lag reader was skipped during query (%llu -> %llu)",
		static_cast<unsigned long long>(skipped_before), static_cast<unsigned long long>(skipped_after));

	const bool restored = restore_variable.restore();
	if (!restored) {
		diag("Aurora variable restoration failed");
	}
	return exit_status() == EXIT_SUCCESS && restored ? EXIT_SUCCESS : EXIT_FAILURE;
}
