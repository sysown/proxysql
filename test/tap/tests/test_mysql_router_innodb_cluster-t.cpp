#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <thread>

#include "mysql.h"

#include "json.hpp"
#include "tap.h"

using MysqlPtr = std::unique_ptr<MYSQL, decltype(&mysql_close)>;
using nlohmann::json;

namespace {

MysqlPtr connect_mysql(const char* host, unsigned port, const char* user,
        const char* password, const char* schema = nullptr) {
    MysqlPtr connection(mysql_init(nullptr), &mysql_close);
    unsigned timeout = 5;
    mysql_options(connection.get(), MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
    if (!mysql_real_connect(connection.get(), host, user, password, schema,
            port, nullptr, CLIENT_MULTI_STATEMENTS)) {
        diag("connect %s:%u as %s failed: %s", host, port, user,
            mysql_error(connection.get()));
        return MysqlPtr(nullptr, &mysql_close);
    }
    return connection;
}

bool execute(MYSQL* connection, const std::string& sql) {
    if (!connection || mysql_real_query(connection, sql.data(), sql.size()) != 0) {
        diag("query failed: %s; SQL: %s", connection ? mysql_error(connection) : "no connection",
            sql.c_str());
        return false;
    }
	for (;;) {
		MYSQL_RES* result = mysql_store_result(connection);
		if (result) mysql_free_result(result);
		else if (mysql_field_count(connection) != 0) {
			diag("cannot store query result: %s", mysql_error(connection));
			return false;
		}
		const int next = mysql_next_result(connection);
		if (next < 0) break;
		if (next > 0) {
			diag("later statement failed: %s; SQL: %s", mysql_error(connection), sql.c_str());
			return false;
		}
	}
	return true;
}

bool set_local_metadata_access(MYSQL* connection, const std::string& account,
        bool grant_access) {
    bool success = execute(connection, "SET SESSION sql_log_bin=0");
    success = execute(connection, "SET GLOBAL super_read_only=OFF") && success;
    success = execute(connection,
        std::string(grant_access ? "GRANT" : "REVOKE") +
        " SELECT, EXECUTE ON mysql_innodb_cluster_metadata.* " +
        (grant_access ? "TO " : "FROM ") + account) && success;
    success = execute(connection, "SET GLOBAL super_read_only=ON") && success;
    success = execute(connection, "SET SESSION sql_log_bin=1") && success;
    return success;
}

std::string scalar(MYSQL* connection, const std::string& sql) {
    if (!connection || mysql_query(connection, sql.c_str()) != 0) return {};
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

bool wait_until(const std::function<bool()>& predicate, unsigned seconds = 30) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    do {
        if (predicate()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    } while (std::chrono::steady_clock::now() < deadline);
    return false;
}

bool session_fast_forward(MYSQL* admin, unsigned long session_id, int expected) {
    const std::string row = scalar(admin,
        "SELECT extended_info FROM stats_mysql_processlist WHERE SessionID=" +
        std::to_string(session_id));
    if (row.empty()) return false;
    try {
        const json info = json::parse(row);
        if (!info.contains("fast_forward")) return false;
        if (info["fast_forward"].is_boolean()) {
            return static_cast<int>(info["fast_forward"].get<bool>()) == expected;
        }
        return info["fast_forward"].is_number_integer() &&
            info["fast_forward"].get<int>() == expected;
    } catch (...) {
        return false;
    }
}

bool wait_for_fast_forward(MYSQL* admin, unsigned long session_id, int expected) {
    return wait_until([&] { return session_fast_forward(admin, session_id, expected); }, 5);
}

class ProcesslistExtendedRestore {
public:
    explicit ProcesslistExtendedRestore(MYSQL* admin)
        : admin_(admin), original_(scalar(admin,
            "SELECT variable_value FROM global_variables "
            "WHERE variable_name='mysql-show_processlist_extended'")) {}
    ~ProcesslistExtendedRestore() {
        if (admin_ && !original_.empty()) {
            (void)execute(admin_, "SET mysql-show_processlist_extended=" + original_);
            (void)execute(admin_, "LOAD MYSQL VARIABLES TO RUNTIME");
        }
    }
    bool enable() {
        return !original_.empty() &&
            execute(admin_, "SET mysql-show_processlist_extended=2") &&
            execute(admin_, "LOAD MYSQL VARIABLES TO RUNTIME");
    }

private:
    MYSQL* admin_;
    std::string original_;
};

std::string endpoint_uuid(const char* host, unsigned port, const char* user,
        const char* password) {
    auto connection = connect_mysql(host, port, user, password, "router_e2e");
    return connection ? scalar(connection.get(), "SELECT @@server_uuid") : "";
}

std::string rule_row(MYSQL* admin, const char* table, int rule_id) {
    return scalar(admin, "SELECT json_array(rule_id,active,username,schemaname,flagIN,"
        "client_addr,proxy_addr,proxy_port,digest,match_digest,match_pattern,"
        "negate_match_pattern,re_modifiers,flagOUT,replace_pattern,destination_hostgroup,"
        "cache_ttl,cache_empty_result,cache_timeout,reconnect,timeout,retries,delay,"
        "next_query_flagIN,mirror_flagOUT,mirror_hostgroup,error_msg,OK_msg,sticky_conn,"
        "multiplex,gtid_from_hostgroup,log,apply,attributes,comment) FROM " +
        std::string(table) + " WHERE rule_id=" + std::to_string(rule_id));
}

} // namespace

int main() {
    plan(65);

    const char* workspace = std::getenv("WORKSPACE");
    const char* infra_id = std::getenv("INFRA_ID");
    const char* root_password = std::getenv("ROOT_PASSWORD");
    const char* admin_host = std::getenv("TAP_ADMINHOST");
    if (!admin_host) admin_host = "proxysql";
	const char* admin_user = std::getenv("TAP_ADMINUSERNAME");
	if (!admin_user) admin_user = "radmin";
	const char* admin_password = std::getenv("TAP_ADMINPASSWORD");
	if (!admin_password) admin_password = "radmin";
    const std::string result_dir = std::string(workspace ? workspace : ".") +
        "/ci_infra_logs/" + (infra_id ? infra_id : "") + "/mysql-router";

    const json fixture = read_json(result_dir + "/fixture.json");
    const json shell_contract = read_json(result_dir + "/shell-contract.json");
    ok(!fixture.empty(), "unmodified MySQL Shell produced the InnoDB Cluster fixture");
    ok(fixture.value("mysqlsh_version", "").find("8.4.8") != std::string::npos,
        "the fixture was created by the pinned MySQL Shell 8.4.8");
    ok(fixture.value("cluster_name", "") == "proxysql_e2e" &&
       fixture.value("topology_uuid", "").size() == 36,
        "Shell created the named Metadata 2.2 InnoDB Cluster");
    ok(fixture.contains("instances") && fixture["instances"].size() >= 3,
        "Shell registered three real Group Replication members");
    ok(fixture.value("read_replica_added", false) && fixture["instances"].size() == 4,
        "Shell added the supported asynchronous read replica");

    auto admin = connect_mysql(admin_host, 6032, admin_user, admin_password);
    ok(admin != nullptr, "ProxySQL Admin is reachable after public bootstrap");
    if (!admin) BAIL_OUT("Router E2E requires ProxySQL Admin");

    ProcesslistExtendedRestore processlist_restore(admin.get());
    ok(processlist_restore.enable(),
        "the E2E enables extended processlist state and will restore the prior value");

    ok(scalar_int(admin.get(), "SELECT COUNT(*) FROM disk.mysql_router_instance") == 1,
        "bootstrap persisted one Router identity");
    ok(scalar_int(admin.get(), "SELECT COUNT(*) FROM disk.mysql_router_hostgroups") == 8,
        "bootstrap persisted all eight managed hostgroups");
    ok(scalar(admin.get(), "SELECT topology_uuid FROM disk.mysql_router_instance") ==
       fixture.value("topology_uuid", ""), "the persisted identity owns the Shell topology UUID");
    ok(scalar(admin.get(), "SELECT advertised_version FROM disk.mysql_router_instance") == "8.4.0",
        "the persisted Router contract is 8.4.0");
    ok(scalar_int(admin.get(), "SELECT COUNT(*) FROM runtime_mysql_router_topology") == 4,
        "the real plugin projects all four topology instances");
    ok(scalar(admin.get(), "SELECT status_value FROM runtime_mysql_router_status "
        "WHERE status_key='gates_ready'") == "1", "the real plugin opened its listener gates");

    const std::string main_rules = scalar(admin.get(),
        "SELECT group_concat(value,';') FROM (SELECT rule_id||'|'||proxy_port||'|'||attributes||'|'||comment value "
        "FROM main.mysql_query_rules WHERE comment LIKE 'mysql_router:%' ORDER BY rule_id)");
    const std::string disk_rules = scalar(admin.get(),
        "SELECT group_concat(value,';') FROM (SELECT rule_id||'|'||proxy_port||'|'||attributes||'|'||comment value "
        "FROM disk.mysql_query_rules WHERE comment LIKE 'mysql_router:%' ORDER BY rule_id)");
    const std::string runtime_rules = scalar(admin.get(),
        "SELECT group_concat(value,';') FROM (SELECT rule_id||'|'||proxy_port||'|'||attributes||'|'||comment value "
        "FROM runtime_mysql_query_rules WHERE comment LIKE 'mysql_router:%' ORDER BY rule_id)");
    ok(!main_rules.empty() && main_rules == disk_rules && main_rules == runtime_rules &&
       scalar_int(admin.get(), "SELECT COUNT(*) FROM main.mysql_query_rules WHERE "
        "comment LIKE 'mysql_router:%'") == 5 &&
       scalar_int(admin.get(), "SELECT COUNT(*) FROM main.mysql_query_rules WHERE "
        "comment IN ('mysql_router:classic-rw','mysql_router:classic-ro') AND "
        "attributes='{\"switch_to_fast_forward\":true}'") == 2 &&
       scalar_int(admin.get(), "SELECT COUNT(*) FROM main.mysql_query_rules WHERE "
        "comment LIKE 'mysql_router:split-%' AND attributes=''") == 3,
        "main, disk, and runtime expose exact fast-forward defaults only on direct rules");

    const std::string shell_dump = shell_contract.dump();
    ok(!shell_contract.empty() && shell_dump.find("proxysql-e2e") != std::string::npos,
        "unmodified Shell listRouters sees the ProxySQL Router registration");
    ok(shell_dump.find("8.4.0") != std::string::npos,
        "Shell sees the advertised Router version");
    ok(shell_dump.find("6446") != std::string::npos &&
       shell_dump.find("6447") != std::string::npos &&
       shell_dump.find("6450") != std::string::npos,
        "Shell sees all three Classic endpoints");
    ok(shell_dump.find("routerX") == std::string::npos &&
       shell_dump.find("routingGuideline") == std::string::npos,
        "Shell sees no X endpoint or Routing Guideline capability");
    ok(shell_contract.contains("routing_options_after") &&
       shell_contract["routing_options_after"].dump().find("all") != std::string::npos,
        "Shell setRoutingOption persists read_only_targets=all for the real Router");
    ok(shell_contract.value("account_count", 0) == 1 &&
       shell_contract.contains("account_grants") &&
       shell_contract["account_grants"].dump().find("mysql_innodb_cluster_metadata") != std::string::npos,
        "Shell setupRouterAccount creates the requested account with Router metadata grants");

    const std::string original_primary = fixture.value("primary_uuid", "");
	std::set<std::string> eligible_readers;
	std::string read_replica_uuid;
	for (const auto& instance : fixture["instances"]) {
		const std::string uuid = instance.value("server_uuid", "");
		if (!uuid.empty() && uuid != original_primary) eligible_readers.insert(uuid);
		if (instance.value("instance_type", "") == "read-replica") read_replica_uuid = uuid;
	}
    std::set<std::string> writer_results;
	std::string first_writer;
	const bool writer_ready = wait_until([&] {
		first_writer = endpoint_uuid(admin_host, 6446, "app_writer", "router-app-password");
		return first_writer == original_primary;
	}, 20);
	if (writer_ready) writer_results.insert(first_writer);
	for (int i = 0; i < 4; ++i) {
        writer_results.insert(endpoint_uuid(admin_host, 6446, "app_writer", "router-app-password"));
    }
	ok(writer_ready && writer_results.size() == 1 && *writer_results.begin() == original_primary,
        "6446 routes repeatedly to the current primary only");

    std::set<std::string> reader_results;
	std::string first_reader;
	const bool reader_ready = wait_until([&] {
		first_reader = endpoint_uuid(admin_host, 6447, "app_reader", "router-app-password");
		return !first_reader.empty();
	}, 20);
	if (reader_ready) reader_results.insert(first_reader);
	for (int i = 0; i < 29; ++i) {
        reader_results.insert(endpoint_uuid(admin_host, 6447, "app_reader", "router-app-password"));
    }
    reader_results.erase("");
	ok(reader_ready && !reader_results.empty(), "6447 serves eligible reader traffic");
    ok(std::all_of(reader_results.begin(), reader_results.end(), [&](const std::string& uuid) {
		return eligible_readers.count(uuid) == 1;
	}), "6447 routes only to explicit Shell-discovered eligible reader members");
	ok(!read_replica_uuid.empty() && reader_results.count(read_replica_uuid) == 1,
		"6447 includes the Shell-managed asynchronous read replica");

    auto direct_rw = connect_mysql(admin_host, 6446, "app_writer",
        "router-app-password", "router_e2e");
    auto direct_ro = connect_mysql(admin_host, 6447, "app_reader",
        "router-app-password", "router_e2e");
    ok(direct_rw && direct_ro, "both direct Classic endpoints keep live test sessions");
    const std::string direct_rw_uuid = direct_rw
        ? scalar(direct_rw.get(), "SELECT @@server_uuid") : "";
    ok(!direct_rw_uuid.empty() && direct_rw && wait_for_fast_forward(
        admin.get(), mysql_thread_id(direct_rw.get()), 1),
        "the 6446 direct rule switches its COM_QUERY session to fast-forward");
    const std::string direct_ro_uuid = direct_ro
        ? scalar(direct_ro.get(), "SELECT @@server_uuid") : "";
    ok(!direct_ro_uuid.empty() && direct_ro && wait_for_fast_forward(
        admin.get(), mysql_thread_id(direct_ro.get()), 1),
        "the 6447 direct rule switches its COM_QUERY session to fast-forward");

	MysqlPtr split(nullptr, mysql_close);
	const bool split_ready = wait_until([&] {
		split = connect_mysql(admin_host, 6450, "app_writer", "router-app-password", "router_e2e");
		return split != nullptr;
	}, 20);
	ok(split_ready, "the read/write-split Classic endpoint accepts the synchronized user");
    const std::string split_reader = split ? scalar(split.get(), "SELECT @@server_uuid") : "";
    bool split_query_aware = split && wait_for_fast_forward(
        admin.get(), mysql_thread_id(split.get()), 0);
    ok(!split_reader.empty() && split_reader != original_primary,
        "6450 sends a safe read to an eligible reader");
    ok(split && execute(split.get(), "CREATE TABLE IF NOT EXISTS route_probe"
        "(id BIGINT PRIMARY KEY, note VARCHAR(32))"), "6450 routes DDL to the writer");
    split_query_aware = split_query_aware && split && wait_for_fast_forward(
        admin.get(), mysql_thread_id(split.get()), 0);
    ok(split && execute(split.get(), "BEGIN; INSERT INTO route_probe VALUES"
        "(9001,'transaction') ON DUPLICATE KEY UPDATE note=VALUES(note)"),
        "6450 starts a write transaction");
    const std::string transaction_uuid = split ? scalar(split.get(), "SELECT @@server_uuid") : "";
    ok(transaction_uuid == original_primary, "6450 pins the transaction to the writer");
    ok(split && execute(split.get(), "COMMIT"), "the split-endpoint transaction commits");
    split_query_aware = split_query_aware && split && wait_for_fast_forward(
        admin.get(), mysql_thread_id(split.get()), 0);
    ok(split && execute(split.get(), "BEGIN") &&
		scalar(split.get(), "SELECT @@server_uuid FROM route_probe WHERE id=9001 FOR UPDATE") ==
			original_primary && execute(split.get(), "ROLLBACK"),
        "6450 routes a locking read to the writer UUID");
    split_query_aware = split_query_aware && split && wait_for_fast_forward(
        admin.get(), mysql_thread_id(split.get()), 0);
    ok(split_query_aware,
        "the 6450 session remains query-aware through read, DDL, transaction, and locking read");

    auto operator_connection = connect_mysql(admin_host, 6033, "operator_user",
        "operator-password", "router_e2e");
    ok(operator_connection != nullptr &&
	   scalar(operator_connection.get(), "SELECT 1") == "1",
        "the existing operator route on 6033 survives bootstrap unchanged");
    auto operator_direct = connect_mysql(admin_host, 6446, "operator_user",
        "operator-password", "router_e2e");
    ok(operator_direct && !scalar(operator_direct.get(), "SELECT @@server_uuid").empty() &&
       wait_for_fast_forward(admin.get(), mysql_thread_id(operator_direct.get()), 0),
        "the lower-ID operator apply rule overrides the 6446 fast-forward default");
    const std::string operator_rule_before = rule_row(
        admin.get(), "main.mysql_query_rules", 777001);
    const std::string disk_operator_rule_before = rule_row(
        admin.get(), "disk.mysql_query_rules", 777001);
    const std::string runtime_operator_rule_before = rule_row(
        admin.get(), "runtime_mysql_query_rules", 777001);
    ok(scalar_int(admin.get(), "SELECT COUNT(*) FROM stats_mysql_connection_pool "
        "WHERE ConnUsed+ConnFree>0") > 0, "native ProxySQL pooling serves Router traffic");
    ok(scalar_int(admin.get(), "SELECT COUNT(*) FROM stats_mysql_query_digest "
        "WHERE digest_text LIKE '%route_probe%'") > 0,
        "native ProxySQL query processing records Router endpoint traffic");

    const int managed_hg = static_cast<int>(scalar_int(admin.get(),
        "SELECT hostgroup_id FROM disk.mysql_router_hostgroups WHERE role='route_reader'"));
    ok(managed_hg > 0, "the test resolved the plugin-owned reader hostgroup");
    ok(execute(admin.get(), "INSERT INTO mysql_servers(hostgroup_id,hostname,port,status,comment)"
        " VALUES(" + std::to_string(managed_hg) + ",'bogus.invalid',6553,'ONLINE','router-drift')") &&
       execute(admin.get(), "LOAD MYSQL SERVERS TO RUNTIME") &&
       execute(admin.get(), "SAVE MYSQL SERVERS TO DISK"),
        "the test injected drift inside a managed hostgroup");
    ok(execute(admin.get(), "MYSQL ROUTER RECONCILE"), "forced reconciliation completes");
    ok(scalar_int(admin.get(), "SELECT COUNT(*) FROM mysql_servers WHERE hostname='bogus.invalid'") == 0 &&
       scalar_int(admin.get(), "SELECT COUNT(*) FROM disk.mysql_servers WHERE hostname='bogus.invalid'") == 0,
        "reconciliation removes bogus managed-hostgroup drift from both tiers");
    ok(scalar_int(admin.get(), "SELECT COUNT(*) FROM mysql_servers WHERE hostgroup_id=77 "
        "AND comment='mysql-router-e2e-operator'") == 3 &&
       scalar_int(admin.get(), "SELECT COUNT(*) FROM disk.mysql_servers WHERE hostgroup_id=77 "
        "AND comment='mysql-router-e2e-operator'") == 3,
        "the operator server survives reconciliation unchanged");
    ok(scalar_int(admin.get(), "SELECT COUNT(*)=2 AND SUM(frontend)=1 AND SUM(backend)=1 "
        "FROM mysql_users WHERE username='operator_user' "
        "AND comment='mysql-router-e2e-operator'") == 1 &&
       !operator_rule_before.empty() &&
       rule_row(admin.get(), "main.mysql_query_rules", 777001) == operator_rule_before &&
       rule_row(admin.get(), "disk.mysql_query_rules", 777001) == disk_operator_rule_before &&
       rule_row(admin.get(), "runtime_mysql_query_rules", 777001) == runtime_operator_rule_before,
        "the operator user and exact query rule survive reconciliation unchanged");

    const char* backend_host = "dbdeployer1.infra-mysql-router-ic";
    unsigned primary_port = 0;
    for (unsigned port = 3306; port <= 3308; ++port) {
        auto backend = connect_mysql(backend_host, port, "root", root_password);
        if (backend && scalar(backend.get(), "SELECT @@server_uuid") == original_primary) {
            primary_port = port;
            break;
        }
    }
    ok(primary_port != 0, "the original primary was identified through real GR state");
    const std::string metadata_user = scalar(admin.get(),
        "SELECT metadata_user FROM disk.mysql_router_instance");
    const std::string account = "'" + metadata_user + "'@'%'";
    auto old_primary = connect_mysql(backend_host, primary_port, "root", root_password);
    ok(old_primary && execute(old_primary.get(), "STOP GROUP_REPLICATION"),
        "the test stops the real primary to trigger election");
    ok(old_primary && set_local_metadata_access(old_primary.get(), account, false),
        "the stopped seed locally loses metadata access without replicating the grant change");
    std::string elected_primary;
    const bool elected = wait_until([&] {
        elected_primary = endpoint_uuid(admin_host, 6446, "app_writer", "router-app-password");
        return !elected_primary.empty() && elected_primary != original_primary;
    }, 45);
    ok(elected, "6446 converges to the newly elected primary");
	auto split_after_failover = connect_mysql(
		admin_host, 6450, "app_writer", "router-app-password", "router_e2e");
	const bool split_write_converged = split_after_failover &&
		execute(split_after_failover.get(), "BEGIN") &&
		execute(split_after_failover.get(), "INSERT INTO route_probe VALUES"
			"(9002,'failover') ON DUPLICATE KEY UPDATE note=VALUES(note)") &&
		scalar(split_after_failover.get(), "SELECT @@server_uuid") == elected_primary &&
		execute(split_after_failover.get(), "COMMIT");
    ok(split_write_converged,
        "6450 writes converge without replacing operator query rules");
	ok(!operator_rule_before.empty() &&
		rule_row(admin.get(), "main.mysql_query_rules", 777001) == operator_rule_before &&
		rule_row(admin.get(), "disk.mysql_query_rules", 777001) == disk_operator_rule_before &&
		rule_row(admin.get(), "runtime_mysql_query_rules", 777001) == runtime_operator_rule_before,
		"failover preserves the exact operator query rule in main, disk, and runtime");
	const int writer_hg = static_cast<int>(scalar_int(admin.get(),
		"SELECT hostgroup_id FROM disk.mysql_router_hostgroups WHERE role='route_writer'"));
	ok(writer_hg > 0 && wait_until([&] {
		return scalar_int(admin.get(), "SELECT COUNT(*) FROM stats_mysql_connection_pool WHERE "
			"hostgroup=" + std::to_string(writer_hg) + " AND srv_port=" +
			std::to_string(primary_port) + " AND status='ONLINE'") == 0;
	}, 20), "the stopped former primary is unavailable in the active writer pool");

    unsigned elected_port = 0;
    for (unsigned port = 3306; port <= 3308; ++port) {
        auto backend = connect_mysql(backend_host, port, "root", root_password);
        if (backend && scalar(backend.get(), "SELECT @@server_uuid") == elected_primary) {
            elected_port = port;
            break;
        }
    }
    auto elected_backend = connect_mysql(backend_host, elected_port, "root", root_password);
    ok(elected_backend && execute(elected_backend.get(),
        "REVOKE SELECT, EXECUTE ON mysql_innodb_cluster_metadata.* FROM " + account),
        "metadata access is blocked while data access remains available");
    ok(wait_until([&] {
        return scalar(admin.get(), "SELECT status_value FROM runtime_mysql_router_status "
            "WHERE status_key='metadata_available'") == "0";
    }, 15), "the real plugin reports metadata unavailability");
    ok(scalar_int(admin.get(), "SELECT COUNT(*) FROM runtime_mysql_router_topology") == 4,
		"metadata outage retains the last complete four-instance topology");
    ok(writer_hg > 0 && scalar_int(admin.get(),
        "SELECT COUNT(*) FROM stats_mysql_connection_pool WHERE hostgroup=" +
        std::to_string(writer_hg) + " AND srv_port=" + std::to_string(primary_port) +
        " AND status='ONLINE'") == 0,
        "metadata outage keeps the unhealthy former primary non-routable");
    ok(endpoint_uuid(admin_host, 6446, "app_writer", "router-app-password") == elected_primary,
        "last metadata plus live GR health keep the healthy writer available");
    ok(scalar(admin.get(), "SELECT status_value FROM runtime_mysql_router_status "
        "WHERE status_key='runtime_state'") == "degraded",
        "metadata loss degrades Router status without stopping ProxySQL");
    ok(mysql_ping(admin.get()) == 0 && operator_connection && mysql_ping(operator_connection.get()) == 0,
        "Admin and the operator-owned 6033 route remain reachable");
    ok(elected_backend && execute(elected_backend.get(),
        "GRANT SELECT, EXECUTE ON mysql_innodb_cluster_metadata.* TO " + account) &&
       execute(admin.get(), "MYSQL ROUTER RECONCILE"),
        "metadata grants and normal reconciliation are restored");
    auto isolated_seed = connect_mysql(backend_host, primary_port, "root", root_password);
    ok(isolated_seed && scalar_int(isolated_seed.get(),
        "SELECT COUNT(*) FROM mysql.db WHERE User='" + metadata_user +
        "' AND Db='mysql_innodb_cluster_metadata' AND Select_priv='Y'") == 0,
        "the stopped seed still lacks metadata access, requiring alternate-endpoint recovery");
    ok(wait_until([&] {
		return scalar(admin.get(), "SELECT status_value FROM runtime_mysql_router_status "
			"WHERE status_key='metadata_available'") == "1";
	}, 20), "metadata availability recovers after grants are restored");

    auto stopped = connect_mysql(backend_host, primary_port, "root", root_password);
    ok(stopped && set_local_metadata_access(stopped.get(), account, true) &&
       execute(stopped.get(), "START GROUP_REPLICATION"),
        "the isolated metadata grant is restored before the stopped member rejoins");
	ok(execute(admin.get(), "MYSQL ROUTER RECONCILE") && wait_until([&] {
		return scalar_int(admin.get(), "SELECT COUNT(*) FROM runtime_mysql_router_topology WHERE "
			"instance_uuid='" + original_primary + "' AND upper(observed_state)='ONLINE'") == 1;
	}, 30), "the recovered member returns ONLINE in the live Router topology");
    ok(scalar_int(admin.get(), "SELECT COUNT(*) FROM mysql_router_users "
        "WHERE username IN ('app_writer','app_reader') AND state='active'") == 2,
        "managed application users remain active after failover and recovery");

    return exit_status();
}
