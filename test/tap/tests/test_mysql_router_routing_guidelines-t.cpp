/**
 * @file test_mysql_router_routing_guidelines-t.cpp
 * @brief Routing Guidelines E2E for proxysql_mysql_router.so (issue #6145).
 *
 * SKELETON: currently only verifies the mysql-router-ic-rg-g1 fixture that the
 * routing assertions will build on:
 *  - the InnoDB Cluster and the Routing Guidelines were created by an
 *    unmodified MySQL Shell 9.x (>= 9.2),
 *  - metadata schema_version >= 2.3,
 *  - Shell-created guidelines 'rg_default' and 'rg_custom' exist and none is
 *    active,
 *  - one instance carries the 'region'='eu' tag,
 *  - the MySQL Shell request queue executes AdminAPI scripts for the test.
 *
 * Running Shell commands from the test: the isolated test runner has no Docker
 * socket, so the backend container serves a file queue (mysqlsh-queue.sh) at
 * ${WORKSPACE}/ci_infra_logs/${INFRA_ID}/mysql-router/shell-queue. Scripts run
 * through rg-shell.sh with `session` and `cluster` pre-bound, e.g.
 *   run_mysqlsh(queue, "cluster.setRoutingOption('guideline', 'rg_custom')");
 */

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include <unistd.h>

#include "mysql.h"

#include "json.hpp"
#include "tap.h"

using MysqlPtr = std::unique_ptr<MYSQL, decltype(&mysql_close)>;
using nlohmann::json;

namespace {

MysqlPtr connect_mysql(const char* host, unsigned port, const char* user,
        const char* password) {
	MysqlPtr connection(mysql_init(nullptr), &mysql_close);
	unsigned timeout = 5;
	mysql_options(connection.get(), MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	if (!mysql_real_connect(connection.get(), host, user, password, nullptr,
			port, nullptr, 0)) {
		diag("connect %s:%u as %s failed: %s", host, port, user,
			mysql_error(connection.get()));
		return MysqlPtr(nullptr, &mysql_close);
	}
	return connection;
}

std::string scalar(MYSQL* connection, const std::string& sql) {
	if (!connection || mysql_query(connection, sql.c_str()) != 0) {
		diag("query failed: %s; SQL: %s",
			connection ? mysql_error(connection) : "no connection", sql.c_str());
		return {};
	}
	MYSQL_RES* result = mysql_store_result(connection);
	MYSQL_ROW row = result ? mysql_fetch_row(result) : nullptr;
	std::string value = row && row[0] ? row[0] : "";
	if (result) mysql_free_result(result);
	return value;
}

long long scalar_int(MYSQL* connection, const std::string& sql) {
	const std::string value = scalar(connection, sql);
	return value.empty() ? -1 : std::strtoll(value.c_str(), nullptr, 10);
}

json read_json(const std::string& path) {
	std::ifstream input(path);
	if (!input) return {};
	try { return json::parse(input); }
	catch (const std::exception& error) {
		diag("cannot parse %s: %s", path.c_str(), error.what());
		return {};
	}
}

std::string read_file(const std::string& path) {
	std::ifstream input(path);
	std::stringstream buffer;
	buffer << input.rdbuf();
	return buffer.str();
}

/** "9.7.0" -> 90700; 0 when unparsable. Accepts a "Ver 9.7.0" prefix too. */
long version_number(const std::string& text) {
	const size_t start = text.find_first_of("0123456789");
	if (start == std::string::npos) return 0;
	int major = 0, minor = 0, patch = 0;
	if (std::sscanf(text.c_str() + start, "%d.%d.%d", &major, &minor, &patch) < 2) return 0;
	return major * 10000L + minor * 100L + patch;
}

struct ShellResult {
	int rc {-1};
	std::string output;
};

/**
 * Execute a JavaScript snippet with the fixture's unmodified MySQL Shell via
 * the backend container's file queue. `session` and `cluster`
 * (dba.getCluster('proxysql_e2e')) are pre-bound. rc is mysqlsh's exit code
 * (-1 on timeout); output is combined stdout+stderr. Print structured results
 * with println('KEY=' + JSON.stringify(...)).
 */
ShellResult run_mysqlsh(const std::string& queue_dir, const std::string& js,
        unsigned timeout_seconds = 180) {
	static unsigned counter = 0;
	char id[96];
	std::snprintf(id, sizeof(id), "%020lld-%d-%u",
		static_cast<long long>(std::chrono::system_clock::now().time_since_epoch().count()),
		static_cast<int>(getpid()), ++counter);
	const std::string base = queue_dir + "/" + id;
	ShellResult result;
	{
		std::ofstream request(base + ".js.tmp");
		request << js << "\n";
		if (!request) {
			diag("cannot write MySQL Shell request %s.js.tmp", base.c_str());
			return result;
		}
	}
	if (std::rename((base + ".js.tmp").c_str(), (base + ".js").c_str()) != 0) {
		diag("cannot submit MySQL Shell request %s: errno %d", base.c_str(), errno);
		return result;
	}
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);
	while (std::chrono::steady_clock::now() < deadline) {
		std::ifstream rc_file(base + ".rc");
		if (rc_file && (rc_file >> result.rc)) {
			result.output = read_file(base + ".out");
			std::remove((base + ".rc").c_str());
			std::remove((base + ".out").c_str());
			std::remove((base + ".running").c_str());
			return result;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
	}
	diag("MySQL Shell request %s timed out after %us", id, timeout_seconds);
	return result;
}

/** Value printed by the Shell script as KEY=<json>, or null. */
json shell_value(const ShellResult& result, const std::string& key) {
	const std::string marker = key + "=";
	size_t pos = result.output.rfind(marker);
	if (pos == std::string::npos) return {};
	size_t end = result.output.find('\n', pos);
	try {
		return json::parse(result.output.substr(pos + marker.size(),
			end == std::string::npos ? std::string::npos : end - pos - marker.size()));
	} catch (const std::exception&) {
		return {};
	}
}

bool has_named(const json& list, const std::string& name) {
	if (!list.is_array()) return false;
	for (const auto& item : list) {
		if (item.is_object() && item.value("name", "") == name) return true;
	}
	return false;
}

} // namespace

int main() {
	plan(14);

	const char* workspace = std::getenv("WORKSPACE");
	const char* infra_id = std::getenv("INFRA_ID");
	const char* root_password = std::getenv("ROOT_PASSWORD");
	const char* backend_host = std::getenv("MYSQL_ROUTER_IC_HOST");
	if (!backend_host) backend_host = "dbdeployer1.infra-mysql-router-ic-rg";
	const std::string result_dir = std::string(workspace ? workspace : ".") +
		"/ci_infra_logs/" + (infra_id ? infra_id : "") + "/mysql-router";
	const std::string queue_dir = result_dir + "/shell-queue";

	const json fixture = read_json(result_dir + "/fixture.json");
	const json rg_fixture = read_json(result_dir + "/routing-guidelines.json");
	const json bootstrap = read_json(result_dir + "/bootstrap-status.json");
	diag("ProxySQL Router bootstrap status: %s", bootstrap.dump().c_str());

	ok(!fixture.empty() && fixture.value("cluster_name", "") == "proxysql_e2e" &&
	   fixture.contains("instances") && fixture["instances"].size() == 4 &&
	   fixture.value("read_replica_added", false),
		"unmodified MySQL Shell created the 3-member + read replica InnoDB Cluster");
	const std::string cluster_shell = fixture.value("mysqlsh_version", "");
	diag("cluster fixture MySQL Shell: %s", cluster_shell.c_str());
	ok(version_number(cluster_shell) >= 90200 && version_number(cluster_shell) < 100000,
		"the cluster fixture was created by MySQL Shell 9.x >= 9.2");
	const std::string rg_shell = rg_fixture.value("mysqlsh_version", "");
	ok(!rg_fixture.empty() && rg_shell == cluster_shell,
		"the Routing Guidelines were created by the same MySQL Shell (%s)", rg_shell.c_str());

	auto backend = connect_mysql(backend_host, 3306, "root", root_password);
	ok(backend != nullptr, "the InnoDB Cluster seed is reachable");
	if (!backend) BAIL_OUT("Routing Guidelines fixture requires the InnoDB Cluster");

	const std::string schema_version = scalar(backend.get(),
		"SELECT CONCAT(major,'.',minor,'.',patch) FROM mysql_innodb_cluster_metadata.schema_version");
	diag("metadata schema_version: %s", schema_version.c_str());
	ok(version_number(schema_version) >= 20300 &&
	   rg_fixture.value("metadata_schema_version", "") == schema_version,
		"metadata schema_version %s is >= 2.3", schema_version.c_str());

	ok(scalar_int(backend.get(), "SELECT COUNT(*) FROM mysql_innodb_cluster_metadata.routing_guidelines "
		"WHERE name IN ('rg_default','rg_custom')") == 2,
		"routing_guidelines contains the Shell-created rg_default and rg_custom");

	json custom;
	try {
		custom = json::parse(scalar(backend.get(), "SELECT CAST(guideline AS CHAR) FROM "
			"mysql_innodb_cluster_metadata.routing_guidelines WHERE name='rg_custom'"));
	} catch (const std::exception&) {}
	ok(custom.is_object() && has_named(custom["destinations"], "EUServers") &&
	   has_named(custom["routes"], "eu_reporting") &&
	   has_named(custom["routes"], "batch_program") &&
	   has_named(custom["routes"], "backend_network_readers") &&
	   custom["routes"].is_array() && !custom["routes"].empty() &&
	   custom["routes"][0].value("name", "") == "eu_reporting",
		"rg_custom stores the AdminAPI-added destination and ordered routes");
	ok(rg_fixture.contains("guidelines") &&
	   rg_fixture["guidelines"].value("rg_custom", json()) == custom,
		"Shell asJson() for rg_custom matches the metadata document");

	ok(scalar_int(backend.get(),
		"SELECT (SELECT COUNT(*) FROM mysql_innodb_cluster_metadata.clusters "
		"WHERE router_options->>'$.guideline' IS NOT NULL) + "
		"(SELECT COUNT(*) FROM mysql_innodb_cluster_metadata.routers "
		"WHERE options->>'$.guideline' IS NOT NULL)") == 0,
		"no Routing Guideline is active after fixture creation");

	ok(scalar_int(backend.get(), "SELECT COUNT(*) FROM mysql_innodb_cluster_metadata.v2_instances "
		"WHERE attributes->>'$.tags.region' = 'eu' AND address LIKE '%:3307'") == 1,
		"Shell setInstanceOption tagged exactly the 3307 instance with region=eu");

	const ShellResult probe = run_mysqlsh(queue_dir,
		"println('RG_PROBE=' + JSON.stringify({version: shell.version,"
		" custom: cluster.getRoutingGuideline('rg_custom').asJson()}));");
	const json probe_value = shell_value(probe, "RG_PROBE");
	ok(probe.rc == 0 && probe_value.is_object(),
		"the MySQL Shell request queue executes AdminAPI scripts (rc=%d)", probe.rc);
	if (probe.rc != 0) diag("queue output: %s", probe.output.c_str());
	ok(probe_value.is_object() && probe_value.value("version", "") == cluster_shell &&
	   probe_value["custom"] == custom,
		"the queued Shell is the fixture Shell and reads rg_custom from metadata");

	const ShellResult failing = run_mysqlsh(queue_dir,
		"cluster.getRoutingGuideline('rg_does_not_exist');");
	ok(failing.rc != 0 && failing.output.find("rg_does_not_exist") != std::string::npos,
		"a failing Shell command reports a non-zero exit code and its error text");
	if (failing.rc == 0) diag("unexpected output: %s", failing.output.c_str());

	ok(scalar_int(backend.get(),
		"SELECT COUNT(*) FROM mysql.user WHERE user IN ('rg_reporting','rg_batch')") == 2,
		"the guideline route accounts exist on the cluster");

	return exit_status();
}
