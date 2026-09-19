/**
 * @file test_mysql_router_routing_guidelines-t.cpp
 * @brief Routing Guidelines E2E for proxysql_mysql_router.so (issue #6145).
 *
 * Real InnoDB Cluster, Routing Guidelines created and managed by an unmodified
 * MySQL Shell 9.x (metadata >= 2.3), the production plugin, real client traffic:
 *  1. fixture provenance (Shell 9.x, metadata >= 2.3, Shell-created guidelines);
 *  2. the plugin advertises SupportedRoutingGuidelinesVersion so Shell activates
 *     a guideline for it;
 *  3. activation of rg_custom: explain views, CurrentRoutingGuideline, traffic
 *     matching routes by user, connect attribute and source network, the rw route,
 *     a session matching no route, operator rules unchanged and not remapped;
 *  4. modification through the AdminAPI (disable a route) converges;
 *  5. an invalid document keeps the last valid generation and is reported in
 *     stats_mysql_router_errors, then recovers;
 *  6. removal restores baseline routing and releases the route hostgroups.
 *
 * Shell commands run through the backend container's file queue
 * (${WORKSPACE}/ci_infra_logs/${INFRA_ID}/mysql-router/shell-queue), with
 * `session` and `cluster` pre-bound.
 */

#include <algorithm>
#include <cerrno>
#include <functional>
#include <map>
#include <set>
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

MysqlPtr connect_router(const char* host, unsigned port, const char* user,
        const std::map<std::string, std::string>& attrs = {}, const char* password = "router-app-password") {
	MysqlPtr connection(mysql_init(nullptr), &mysql_close);
	unsigned timeout = 5;
	mysql_options(connection.get(), MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	for (const auto& attr : attrs) {
		mysql_options4(connection.get(), MYSQL_OPT_CONNECT_ATTR_ADD, attr.first.c_str(), attr.second.c_str());
	}
	if (!mysql_real_connect(connection.get(), host, user, password, nullptr,
			port, nullptr, 0)) {
		diag("connect %s:%u as %s failed: %s", host, port, user, mysql_error(connection.get()));
		return MysqlPtr(nullptr, &mysql_close);
	}
	return connection;
}

/** Server UUID answering a fresh session, or "ERROR: <message>". */
std::string route_uuid(const char* host, unsigned port, const char* user,
        const std::map<std::string, std::string>& attrs = {}, const char* password = "router-app-password") {
	auto connection = connect_router(host, port, user, attrs, password);
	if (!connection) return "ERROR: connect";
	if (mysql_query(connection.get(), "SELECT @@server_uuid") != 0) {
		return std::string("ERROR: ") + mysql_error(connection.get());
	}
	MYSQL_RES* result = mysql_store_result(connection.get());
	MYSQL_ROW row = result ? mysql_fetch_row(result) : nullptr;
	std::string value = row && row[0] ? row[0] : "ERROR: empty";
	if (result) mysql_free_result(result);
	return value;
}

std::set<std::string> route_uuids(int sessions, const char* host, unsigned port, const char* user,
        const std::map<std::string, std::string>& attrs = {}) {
	std::set<std::string> result;
	for (int i = 0; i < sessions; ++i) result.insert(route_uuid(host, port, user, attrs));
	return result;
}

bool wait_until(const std::function<bool()>& condition, int seconds) {
	for (int i = 0; i < seconds * 2; ++i) {
		if (condition()) return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
	return condition();
}

bool subset(const std::set<std::string>& values, const std::set<std::string>& allowed) {
	return !values.empty() && std::all_of(values.begin(), values.end(),
		[&](const std::string& value) { return allowed.count(value) == 1; });
}

std::string join(const std::set<std::string>& values) {
	std::string result;
	for (const auto& value : values) result += (result.empty() ? "" : ",") + value;
	return result;
}

/** Forces a reconcile and waits for the runtime guideline state. */
bool wait_guideline_state(MYSQL* admin, const std::string& state, const std::string& name, int seconds = 40) {
	return wait_until([&] {
		(void)scalar(admin, "MYSQL ROUTER RECONCILE");
		const std::string current = scalar(admin,
			"SELECT state||'|'||name FROM runtime_mysql_router_guideline");
		return current == state + "|" + name;
	}, seconds);
}

std::string operator_rules(MYSQL* admin, const char* table) {
	return scalar(admin, std::string("SELECT group_concat(value,';') FROM (SELECT json_array(rule_id,active,") +
		"username,schemaname,flagIN,client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern," +
		"negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,cache_ttl,error_msg," +
		"OK_msg,multiplex,apply,attributes,comment) value FROM " + table +
		" WHERE comment NOT LIKE 'mysql_router:%' ORDER BY rule_id)");
}

} // namespace

int main() {
	plan(53);

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

	const char* proxy_host = std::getenv("TAP_ADMINHOST");
	if (!proxy_host) proxy_host = "proxysql";
	const char* admin_user = std::getenv("TAP_ADMINUSERNAME");
	if (!admin_user) admin_user = "radmin";
	const char* admin_password = std::getenv("TAP_ADMINPASSWORD");
	if (!admin_password) admin_password = "radmin"; // NOSONAR: public isolated-test default, not a secret.
	auto admin = connect_mysql(proxy_host, 6032, admin_user, admin_password);
	ok(admin != nullptr && bootstrap.value("bootstrap_rc", -1) == 0,
		"the production plugin bootstrapped against metadata %s", schema_version.c_str());
	if (!admin) BAIL_OUT("Routing Guidelines E2E requires ProxySQL Admin");

	// Topology from the plugin's own view: uuid -> endpoint, roles.
	const std::string primary_uuid = fixture.value("primary_uuid", "");
	std::string eu_uuid, replica_uuid;
	std::set<std::string> secondaries, readers;
	for (const auto& instance : fixture["instances"]) {
		const std::string uuid = instance.value("server_uuid", "");
		const std::string endpoint = scalar(admin.get(),
			"SELECT endpoint FROM runtime_mysql_router_topology WHERE instance_uuid='" + uuid + "'");
		if (instance.value("instance_type", "") == "read-replica") replica_uuid = uuid;
		else if (uuid != primary_uuid) secondaries.insert(uuid);
		if (uuid != primary_uuid) readers.insert(uuid);
		if (endpoint.size() > 5 && endpoint.compare(endpoint.size() - 5, 5, ":3307") == 0) eu_uuid = uuid;
	}
	ok(!primary_uuid.empty() && secondaries.size() == 2 && !replica_uuid.empty() && secondaries.count(eu_uuid),
		"the plugin topology maps the primary, two secondaries (3307 tagged eu) and the read replica");

	const std::string operator_main_before = operator_rules(admin.get(), "main.mysql_query_rules");
	const std::string operator_runtime_before = operator_rules(admin.get(), "runtime_mysql_query_rules");

	// 2. Router contract used by Shell.
	ok(wait_until([&] {
		(void)scalar(admin.get(), "MYSQL ROUTER RECONCILE");
		return scalar(backend.get(), "SELECT attributes->>'$.SupportedRoutingGuidelinesVersion' FROM "
			"mysql_innodb_cluster_metadata.v2_routers WHERE router_name='proxysql-e2e'") == "1.1";
	}, 30), "the plugin advertises SupportedRoutingGuidelinesVersion 1.1 in v2_routers");
	ok(scalar(admin.get(), "SELECT state FROM runtime_mysql_router_guideline") == "none",
		"no guideline is active in the plugin before activation");

	// 3. Activation with the unmodified Shell.
	const ShellResult activate = run_mysqlsh(queue_dir, "cluster.setRoutingOption('guideline', 'rg_custom');");
	ok(activate.rc == 0, "Shell setRoutingOption('guideline','rg_custom') accepts the ProxySQL Router (rc=%d)", activate.rc);
	if (activate.rc != 0) diag("Shell output: %s", activate.output.c_str());
	ok(wait_guideline_state(admin.get(), "active", "rg_custom"), "the plugin activates rg_custom (%s)",
		scalar(admin.get(), "SELECT state||'|'||name||'|'||last_error FROM runtime_mysql_router_guideline").c_str());
	ok(scalar(admin.get(), "SELECT version FROM runtime_mysql_router_guideline") == "1.1",
		"the explain view reports document version 1.1");
	ok(scalar_int(admin.get(), "SELECT COUNT(*) FROM runtime_mysql_router_guideline_routes") == 15 &&
	   scalar_int(admin.get(), "SELECT COUNT(DISTINCT route_name) FROM runtime_mysql_router_guideline_routes") == 5,
		"every enabled route is explained with its three pools");
	ok(scalar(admin.get(), "SELECT members FROM runtime_mysql_router_guideline_routes "
		"WHERE route_name='eu_reporting' AND pool='all'").find(":3307(weight=10000000)") != std::string::npos,
		"eu_reporting resolves to the eu-tagged member with first-available weights");
	ok(scalar(admin.get(), "SELECT classes FROM runtime_mysql_router_guideline_destinations WHERE server_uuid='" +
		eu_uuid + "'") == "Secondary,EUServers", "the destinations view classifies the tagged secondary");
	ok(scalar_int(admin.get(), "SELECT COUNT(*) FROM runtime_mysql_router_hostgroups WHERE role LIKE 'rg:%'") == 15 &&
	   scalar_int(admin.get(), "SELECT COUNT(*) FROM runtime_mysql_servers WHERE comment LIKE "
		"'%guideline=rg_custom;route=eu_reporting;pool=all;%'") == 1,
		"route hostgroups and servers are published to runtime");
	ok(wait_until([&] {
		(void)scalar(admin.get(), "MYSQL ROUTER RECONCILE");
		return scalar(backend.get(), "SELECT attributes->>'$.CurrentRoutingGuideline' FROM "
			"mysql_innodb_cluster_metadata.v2_routers WHERE router_name='proxysql-e2e'") == "rg_custom";
	}, 30), "v2_routers reports CurrentRoutingGuideline=rg_custom");
	const ShellResult routers = run_mysqlsh(queue_dir,
		"println('ROUTERS=' + JSON.stringify(cluster.listRouters()));");
	ok(routers.rc == 0 && shell_value(routers, "ROUTERS").dump().find("rg_custom") != std::string::npos,
		"Shell listRouters shows the ProxySQL Router using rg_custom");

	const auto reporting = route_uuids(5, proxy_host, 6447, "rg_reporting");
	ok(reporting == std::set<std::string>{eu_uuid},
		"route eu_reporting ($.session.user) sends rg_reporting to the eu member only [%s]", join(reporting).c_str());
	const auto batch = route_uuids(5, proxy_host, 6447, "rg_batch", {{"program_name", "rg_batch"}});
	ok(batch == std::set<std::string>{replica_uuid},
		"route batch_program ($.session.connectAttrs) sends rg_batch to the read replica [%s]", join(batch).c_str());
	const auto network_readers = route_uuids(12, proxy_host, 6447, "app_reader");
	ok(subset(network_readers, readers),
		"route backend_network_readers (NETWORK($.session.sourceIP)) uses secondaries/read replica [%s]",
		join(network_readers).c_str());
	const auto writers = route_uuids(5, proxy_host, 6446, "app_writer");
	ok(writers == std::set<std::string>{primary_uuid}, "route rw sends app_writer on 6446 to the primary [%s]",
		join(writers).c_str());
	const auto ro = route_uuids(12, proxy_host, 6447, "app_writer");
	ok(subset(ro, secondaries), "route ro sends app_writer on 6447 to the secondaries [%s]", join(ro).c_str());
	const std::string no_route = route_uuid(proxy_host, 6450, "app_writer");
	ok(no_route.find("no Routing Guideline route matches") != std::string::npos,
		"a session matching no route is rejected with an explicit error (%s)", no_route.c_str());
	// backend_network_readers lists Primary only in its priority 1 group: on the
	// rw_split port, statements that need the writer use that PRIMARY pool.
	const std::string split_write = [&] {
		auto connection = connect_router(proxy_host, 6450, "app_reader");
		if (!connection) return std::string("ERROR: connect");
		if (mysql_query(connection.get(), "SELECT @@server_uuid FOR UPDATE") != 0) {
			return std::string("ERROR: ") + mysql_error(connection.get());
		}
		MYSQL_RES* result = mysql_store_result(connection.get());
		MYSQL_ROW row = result ? mysql_fetch_row(result) : nullptr;
		std::string value = row && row[0] ? row[0] : "ERROR: empty";
		if (result) mysql_free_result(result);
		return value;
	}();
	ok(split_write == primary_uuid,
		"rw_split locking reads use the route's PRIMARY group (%s)", split_write.c_str());
	const auto split_reads = route_uuids(6, proxy_host, 6450, "app_reader");
	ok(subset(split_reads, readers), "rw_split reads on backend_network_readers use its read-only pool [%s]",
		join(split_reads).c_str());
	const std::string operator_route = route_uuid(proxy_host, 6446, "operator_user", {}, "operator-password");
	ok(operator_route.rfind("ERROR", 0) != 0,
		"an operator rule destination is not remapped by the guideline (%s)", operator_route.c_str());

	// 4. Modification through the AdminAPI.
	const ShellResult disable = run_mysqlsh(queue_dir,
		"cluster.getRoutingGuideline('rg_custom').setRouteOption('eu_reporting', 'enabled', false);");
	ok(disable.rc == 0, "Shell disables route eu_reporting (rc=%d)", disable.rc);
	ok(wait_until([&] {
		(void)scalar(admin.get(), "MYSQL ROUTER RECONCILE");
		return scalar_int(admin.get(), "SELECT COUNT(*) FROM runtime_mysql_router_guideline_routes "
			"WHERE route_name='eu_reporting'") == 0;
	}, 40), "the plugin converges on the modified guideline");
	const auto reporting_after = route_uuids(12, proxy_host, 6447, "rg_reporting");
	ok(subset(reporting_after, secondaries),
		"rg_reporting now follows route ro to the secondaries [%s]", join(reporting_after).c_str());
	ok(scalar_int(admin.get(), "SELECT COUNT(*) FROM runtime_mysql_router_hostgroups WHERE role LIKE 'rg:%'") == 12,
		"the hostgroups of the disabled route are released");

	// 5. Invalid document: last valid generation is kept.
	const std::string valid_document = scalar(backend.get(), "SELECT CAST(guideline AS CHAR) FROM "
		"mysql_innodb_cluster_metadata.routing_guidelines WHERE name='rg_custom'");
	ok(scalar(backend.get(), "UPDATE mysql_innodb_cluster_metadata.routing_guidelines SET guideline="
		"JSON_SET(guideline,'$.destinations[0].match','$.server.unknownVariable = 1') WHERE name='rg_custom'").empty() &&
	   mysql_affected_rows(backend.get()) == 1, "the guideline document is corrupted in the metadata");
	ok(wait_guideline_state(admin.get(), "stale", "rg_custom"), "an invalid document leaves the guideline stale");
	ok(scalar_int(admin.get(), "SELECT COUNT(*) FROM stats_mysql_router_errors WHERE kind='guideline_parse' "
		"AND message LIKE '%unknownVariable%'") >= 1, "the parse error is exposed in stats_mysql_router_errors");
	const auto stale_writers = route_uuids(3, proxy_host, 6446, "app_writer");
	ok(stale_writers == std::set<std::string>{primary_uuid} &&
	   route_uuid(proxy_host, 6450, "app_writer").find("no Routing Guideline route") != std::string::npos,
		"traffic keeps using the last valid generation [%s]", join(stale_writers).c_str());
	std::string restore = "UPDATE mysql_innodb_cluster_metadata.routing_guidelines SET guideline='";
	for (char c : valid_document) {
		if (c == '\'' || c == '\\') restore.push_back('\\');
		restore.push_back(c);
	}
	restore += "' WHERE name='rg_custom'";
	(void)scalar(backend.get(), restore);
	if (mysql_errno(backend.get()) != 0 || mysql_affected_rows(backend.get()) != 1) {
		diag("restoring rg_custom failed: errno=%u affected=%llu error=%s", mysql_errno(backend.get()),
			static_cast<unsigned long long>(mysql_affected_rows(backend.get())), mysql_error(backend.get()));
	}
	ok(wait_guideline_state(admin.get(), "active", "rg_custom"), "restoring the document reactivates the guideline");

	// 6. Removal.
	const ShellResult remove = run_mysqlsh(queue_dir, "cluster.setRoutingOption('guideline', null);");
	ok(remove.rc == 0, "Shell unsets the guideline option (rc=%d)", remove.rc);
	ok(wait_guideline_state(admin.get(), "none", ""), "the plugin deactivates the guideline");
	ok(wait_until([&] {
		return scalar_int(admin.get(), "SELECT COUNT(*) FROM runtime_mysql_router_hostgroups WHERE role LIKE 'rg:%'") == 0 &&
			scalar_int(admin.get(), "SELECT COUNT(*) FROM runtime_mysql_servers WHERE comment LIKE '%;guideline=%'") == 0;
	}, 20), "route hostgroups and servers are released");
	ok(wait_until([&] {
		(void)scalar(admin.get(), "MYSQL ROUTER RECONCILE");
		return scalar(backend.get(), "SELECT COALESCE(attributes->>'$.CurrentRoutingGuideline','null') FROM "
			"mysql_innodb_cluster_metadata.v2_routers WHERE router_name='proxysql-e2e'") == "null";
	}, 30), "v2_routers reports no current guideline");
	const std::string split_baseline = route_uuid(proxy_host, 6450, "app_writer");
	ok(split_baseline.rfind("ERROR", 0) != 0, "baseline rw_split routing is restored (%s)", split_baseline.c_str());
	const auto baseline_writers = route_uuids(3, proxy_host, 6446, "app_writer");
	ok(baseline_writers == std::set<std::string>{primary_uuid}, "baseline rw routing is restored");
	const ShellResult removed = run_mysqlsh(queue_dir,
		"println('ROUTERS=' + JSON.stringify(cluster.listRouters()));");
	ok(removed.rc == 0 && shell_value(removed, "ROUTERS").dump().find("rg_custom") == std::string::npos,
		"Shell no longer reports a current guideline for the ProxySQL Router");

	ok(operator_rules(admin.get(), "main.mysql_query_rules") == operator_main_before &&
	   operator_rules(admin.get(), "runtime_mysql_query_rules") == operator_runtime_before &&
	   !operator_main_before.empty(), "operator-owned query rules are unchanged by every reconciliation");

	return exit_status();
}
