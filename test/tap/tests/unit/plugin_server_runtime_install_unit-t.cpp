#include "tap.h"
#include "ProxySQL_PluginManager.h"
#include "ProxySQL_Cluster.hpp"
#include "ProxySQL_ServerDiscovery.h"
#include "MySQL_Thread.h"
#include "ProxySQL_Statistics.hpp"
#include "MySQL_Monitor.hpp"
#include "proxysql_admin.h"
#include "test_globals.h"
#include "test_init.h"

#include <cstdlib>
#include <atomic>
#include <chrono>
#include <fstream>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_Statistics* GloProxyStats;
extern MySQL_Monitor* GloMyMon;

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif

namespace {

std::string g_log_path;

std::string read_log() {
	std::ifstream log(g_log_path);
	return std::string((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
}

std::unique_ptr<SQLite3_result> select_rows(SQLite3DB& db, const char* query) {
	char* sqlite_error = nullptr;
	int columns = 0, affected_rows = 0;
	SQLite3_result* rows = nullptr;
	db.execute_statement(query, &sqlite_error, &columns, &affected_rows, &rows);
	if (sqlite_error != nullptr) {
		free(sqlite_error);
		delete rows;
		return nullptr;
	}
	return std::unique_ptr<SQLite3_result>(rows);
}

void create_server_load_schema(SQLite3DB& db) {
	db.execute("CREATE TABLE mysql_servers (hostgroup_id INTEGER, hostname TEXT, port INTEGER, gtid_port INTEGER, status TEXT, weight INTEGER, compression INTEGER, max_connections INTEGER, max_replication_lag INTEGER, use_ssl INTEGER, max_latency_ms INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_fake_server_module_claims (writer INTEGER)");
	db.execute("CREATE TABLE pgsql_fake_server_module_claims (writer INTEGER)");
	db.execute("CREATE TABLE pgsql_servers (hostgroup_id INTEGER, hostname TEXT, port INTEGER, status TEXT, weight INTEGER, compression INTEGER, max_connections INTEGER, max_replication_lag INTEGER, use_ssl INTEGER, max_latency_ms INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INTEGER, reader_hostgroup INTEGER, check_type TEXT, comment TEXT)");
	db.execute("CREATE TABLE pgsql_replication_hostgroups (writer_hostgroup INTEGER, reader_hostgroup INTEGER, check_type TEXT, comment TEXT)");
	db.execute("CREATE TABLE mysql_group_replication_hostgroups (writer_hostgroup INTEGER, backup_writer_hostgroup INTEGER, reader_hostgroup INTEGER, offline_hostgroup INTEGER, active INTEGER, max_writers INTEGER, writer_is_also_reader INTEGER, max_transactions_behind INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_galera_hostgroups (writer_hostgroup INTEGER, backup_writer_hostgroup INTEGER, reader_hostgroup INTEGER, offline_hostgroup INTEGER, active INTEGER, max_writers INTEGER, writer_is_also_reader INTEGER, max_transactions_behind INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_aws_aurora_hostgroups (writer_hostgroup INTEGER, reader_hostgroup INTEGER, active INTEGER, aurora_port INTEGER, domain_name TEXT, max_lag_ms INTEGER, check_interval_ms INTEGER, check_timeout_ms INTEGER, writer_is_also_reader INTEGER, new_reader_weight INTEGER, add_lag_ms INTEGER, min_lag_ms INTEGER, lag_num_checks INTEGER, autopurge_missing_checks INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_aws_rds_bgd_hostgroups (writer_hostgroup INTEGER, reader_hostgroup INTEGER, green_writer_hostgroup INTEGER, green_reader_hostgroup INTEGER, active INTEGER, writer_is_also_reader INTEGER, check_interval_ms INTEGER, check_timeout_ms INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_hostgroup_attributes (hostgroup_id INTEGER, max_num_online_servers INTEGER, autocommit INTEGER, free_connections_pct INTEGER, init_connect TEXT, multiplex INTEGER, connection_warming INTEGER, throttle_connections_per_sec INTEGER, ignore_session_variables TEXT, hostgroup_settings TEXT, comment TEXT)");
	db.execute("CREATE TABLE pgsql_hostgroup_attributes (hostgroup_id INTEGER, max_num_online_servers INTEGER, free_connections_pct INTEGER, init_connect TEXT, multiplex INTEGER, connection_warming INTEGER, throttle_connections_per_sec INTEGER, ignore_session_variables TEXT, hostgroup_settings TEXT, comment TEXT)");
	db.execute("CREATE TABLE mysql_servers_ssl_params (hostgroup_id INTEGER, hostname TEXT, port INTEGER, username TEXT)");
	db.execute("CREATE TABLE pgsql_servers_ssl_params (hostgroup_id INTEGER, hostname TEXT, port INTEGER, username TEXT)");
}

size_t occurrences(const std::string& value, const std::string& needle) {
	size_t count = 0;
	for (size_t offset = 0; (offset = value.find(needle, offset)) != std::string::npos; offset += needle.size()) ++count;
	return count;
}

} // namespace

int main() {
	plan(32);
	test_init_minimal();
	char path[] = "/tmp/proxysql_server_runtime_install.XXXXXX";
	const int fd = mkstemp(path);
	if (fd < 0) BAIL_OUT("cannot create private server runtime install log");
	close(fd);
	g_log_path = path;
	setenv("PROXYSQL_FAKE_PLUGIN_LOG", g_log_path.c_str(), 1);
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_SERVER_DISCOVERY", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_AFFILIATED", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_BOTH_PROTOCOLS", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_INSTALL_SERVER_DISCOVERY_CONTROLLER", "1", 1);

	std::unique_ptr<ProxySQL_PluginManager> manager;
	std::string error;
	ok(proxysql_load_configured_plugins(manager, {PROXYSQL_FAKE_PLUGIN_PATH}, error) &&
		proxysql_init_configured_plugins(manager.get(), error),
		"loads an active server module and controller through the public lifecycle");

	auto module_snapshot = [](ProxySQL_ServerProtocol protocol) {
		ProxySQL_ServerModuleSnapshot snapshot {};
		snapshot.runtime.protocol = protocol;
		return snapshot;
	};
	auto claims_are = [](ProxySQL_ServerProtocol protocol,
		const std::vector<ProxySQL_ServerHostgroupClaim>& expected) {
		const auto claims = proxysql_active_server_hostgroup_claims(protocol);
		if (claims.size() != expected.size()) return false;
		for (size_t i = 0; i < claims.size(); ++i) {
			if (claims[i].writer_hostgroup != expected[i].writer_hostgroup ||
				claims[i].reader_hostgroup != expected[i].reader_hostgroup) return false;
		}
		return true;
	};

	ProxySQL_ServerModuleSnapshot snapshot = module_snapshot(ProxySQL_ServerProtocol::mysql);
	snapshot.runtime.servers.push_back({17, "runtime.example", 3306, 0, "ONLINE", 5, 0, 100, 0, 1, 0, "complete"});
	const uint64_t candidate = proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql);
	ok(proxysql_publish_server_runtime(std::move(snapshot), true) == candidate,
		"a publication carries the protocol's next runtime generation");
	ok(proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql) == candidate + 1,
		"a MySQL publication advances exactly one protocol generation");
	const std::string after_first = read_log();
	ok(occurrences(after_first, "server_module_runtime_installed") == 1 &&
		occurrences(after_first, "server_controller_runtime") == 1 &&
		after_first.find("server_module_runtime_installed") < after_first.find("server_controller_runtime"),
		"a publication notifies the module, then the controller, exactly once");
	const std::string generation_text = std::to_string(candidate);
	ok(after_first.find("runtime_installed_generation=" + generation_text) != std::string::npos &&
		after_first.find("runtime_controller_generation=" + generation_text) != std::string::npos,
		"the module and the controller receive the publication's generation");

	proxysql_publish_server_runtime(module_snapshot(ProxySQL_ServerProtocol::mysql), true);
	ok(occurrences(read_log(), "server_controller_runtime") == 2,
		"zero-server publication restarts the controller without seeds");

	const uint64_t pgsql_candidate = proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::pgsql);
	proxysql_publish_server_runtime(module_snapshot(ProxySQL_ServerProtocol::pgsql), true);
	ok(proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::pgsql) == pgsql_candidate + 1 &&
		proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql) == candidate + 2,
		"MySQL and PostgreSQL generations are independent and monotonic");

	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_ZERO_CLAIM", "1", 1);
	proxysql_publish_server_runtime(module_snapshot(ProxySQL_ServerProtocol::mysql), true);
	ok(claims_are(ProxySQL_ServerProtocol::mysql, {{0, 1}}),
		"the MySQL module reports and owns the claim pair (0,1)");
	proxysql_publish_server_runtime(module_snapshot(ProxySQL_ServerProtocol::pgsql), true);
	ok(claims_are(ProxySQL_ServerProtocol::pgsql, {{1, 0}}),
		"the PostgreSQL module reports and owns the claim pair (1,0)");
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_ZERO_CLAIM");

	// Publications of one protocol are serialized by the install lock: one
	// arriving while another installation holds it waits, and never fails.
	std::atomic<bool> second_published {false};
	std::atomic<bool> second_started {false};
	std::thread second;
	{
		ProxySQL_ServerRuntimeInstallLock held(ProxySQL_ServerProtocol::mysql);
		second = std::thread([&] {
			second_started.store(true, std::memory_order_release);
			proxysql_publish_server_runtime(module_snapshot(ProxySQL_ServerProtocol::mysql), true);
			second_published.store(true, std::memory_order_release);
		});
		while (!second_started.load(std::memory_order_acquire)) std::this_thread::yield();
		std::this_thread::sleep_for(std::chrono::milliseconds(30));
		ok(!second_published.load(std::memory_order_acquire),
			"a concurrent MySQL publication waits for the held install lock");
	}
	second.join();
	ok(second_published.load(std::memory_order_acquire),
		"the waiting publication completes once the install lock is released");

	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_CLAIM", "1", 1);
	ProxySQL_ServerModuleSnapshot delegated_seed = module_snapshot(ProxySQL_ServerProtocol::mysql);
	delegated_seed.runtime.servers.push_back({17, "delegated-seed.example", 3306});
	proxysql_publish_server_runtime(std::move(delegated_seed), true);
	ok(claims_are(ProxySQL_ServerProtocol::mysql, {{17, 18}}),
		"a delegated plugin hostgroup may also appear as an ordinary core server seed");
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_CLAIM");

	const uint64_t before_throw = proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql);
	const size_t before_throw_controller = occurrences(read_log(), "server_controller_runtime");
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_RUNTIME_THROW", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_SECOND_CLAIM", "1", 1);
	proxysql_publish_server_runtime(module_snapshot(ProxySQL_ServerProtocol::mysql), true);
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_RUNTIME_THROW");
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_SECOND_CLAIM");
	ok(proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql) == before_throw + 1 &&
		occurrences(read_log(), "server_controller_runtime") == before_throw_controller + 1,
		"a throwing module cannot block the publication or the controller notification");
	ok(claims_are(ProxySQL_ServerProtocol::mysql, {}),
		"a throwing module owns no hostgroup claims");

	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_INVALID_CLAIM", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_SECOND_CLAIM", "1", 1);
	proxysql_publish_server_runtime(module_snapshot(ProxySQL_ServerProtocol::mysql), true);
	ok(claims_are(ProxySQL_ServerProtocol::mysql, {{27, 28}}),
		"an invalid writer==reader claim is dropped, the valid claim is kept");
	const size_t before_core_only = occurrences(read_log(), "server_module_runtime_installed");
	proxysql_publish_server_runtime(module_snapshot(ProxySQL_ServerProtocol::mysql), false);
	ok(occurrences(read_log(), "server_module_runtime_installed") == before_core_only &&
		claims_are(ProxySQL_ServerProtocol::mysql, {{27, 28}}),
		"a core-only publication does not call the module, which keeps its claims");
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_INVALID_CLAIM");
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_SECOND_CLAIM");

	// This enters the public Admin LOAD implementation, rather than the
	// dispatcher: its HGM staging must occur between prepare and commit.
	char stats_memory_db[] = ":memory:";
	GloVars.statsdb_disk = stats_memory_db;
	ProxySQL_Statistics* stats = new ProxySQL_Statistics(); // process-scoped fixture
	GloProxyStats = stats;
	test_init_query_processor();
	test_init_hostgroups();
	MySQL_Monitor* monitor = new MySQL_Monitor(); // process-scoped fixture
	GloMyMon = monitor; // production HGM owns this public monitor dependency
	// test_init_hostgroups intentionally does not start the background GTID
	// synchronizer.  A real Admin LOAD still emits its async notification, so
	// provide the corresponding event-loop state without starting a thread.
	MyHGM->gtid_ev_loop = ev_loop_new(0);
	ev_async_init(MyHGM->gtid_ev_async, [](EV_P_ ev_async*, int) {});
	SQLite3DB admin_db;
	char memory_db[] = ":memory:";
	admin_db.open(memory_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	create_server_load_schema(admin_db);
	admin_db.execute("INSERT INTO mysql_servers VALUES (31,'admin-load.example',3306,0,'ONLINE',1,0,100,0,1,0,'admin')");
	admin_db.execute("INSERT INTO mysql_replication_hostgroups VALUES (31,32,'read_only','monitor fixture')");
	admin_db.execute("INSERT INTO mysql_group_replication_hostgroups VALUES (51,52,53,54,1,1,0,0,'group replication')");
	admin_db.execute("INSERT INTO mysql_group_replication_hostgroups VALUES (151,152,153,154,0,1,0,0,'inactive group replication')");
	admin_db.execute("INSERT INTO mysql_galera_hostgroups VALUES (61,62,63,64,1,1,0,0,'galera')");
	admin_db.execute("INSERT INTO mysql_galera_hostgroups VALUES (161,162,163,164,0,1,0,0,'inactive galera')");
	admin_db.execute("INSERT INTO mysql_aws_aurora_hostgroups VALUES (71,72,1,3306,'example',100,1000,100,0,1,0,0,1,1,'aurora')");
	admin_db.execute("INSERT INTO mysql_aws_aurora_hostgroups VALUES (171,172,0,3306,'inactive',100,1000,100,0,1,0,0,1,1,'inactive aurora')");
	admin_db.execute("INSERT INTO mysql_aws_rds_bgd_hostgroups VALUES (81,82,NULL,0,1,0,1000,100,'rds blue green')");
	admin_db.execute("INSERT INTO mysql_aws_rds_bgd_hostgroups VALUES (181,182,183,184,0,0,1000,100,'inactive rds blue green')");
	admin_db.execute("INSERT INTO pgsql_servers VALUES (41,'pgsql-load.example',5432,'ONLINE',1,0,100,0,1,0,'admin')");
	admin_db.execute("INSERT INTO pgsql_replication_hostgroups VALUES (31,32,'read_only','runtime fixture')");
	std::vector<uint32_t> mysql_topology;
	std::vector<uint32_t> pgsql_topology;
	ProxySQL_ServerBuiltinTopologyInputs topology_inputs {};
	ok(proxysql_collect_active_builtin_server_topology(admin_db, ProxySQL_ServerProtocol::mysql,
		topology_inputs, mysql_topology, error) &&
		std::set<uint32_t>(mysql_topology.begin(), mysql_topology.end()) ==
			std::set<uint32_t>({0,31,32,51,52,53,54,61,62,63,64,71,72,81,82}),
		"the common collector ignores inactive mappings, skips nullable optional RDS claims, and accepts schema-valid zero hostgroups");
	ok(proxysql_collect_active_builtin_server_topology(admin_db, ProxySQL_ServerProtocol::pgsql,
		topology_inputs, pgsql_topology, error) &&
		std::set<uint32_t>(pgsql_topology.begin(), pgsql_topology.end()) == std::set<uint32_t>({31,32}),
		"the common collector includes active PostgreSQL replication topology owners");
	admin_db.execute("INSERT INTO mysql_replication_hostgroups VALUES (NULL,193,'read_only','malformed required hostgroup')");
	ok(!proxysql_collect_active_builtin_server_topology(admin_db, ProxySQL_ServerProtocol::mysql,
		topology_inputs, mysql_topology, error),
		"the common collector rejects a missing required topology hostgroup");
	admin_db.execute("DELETE FROM mysql_replication_hostgroups WHERE writer_hostgroup IS NULL");
	std::unique_ptr<SQLite3_result> supplied_group = select_rows(admin_db,
		"SELECT * FROM mysql_group_replication_hostgroups ORDER BY writer_hostgroup");
	ProxySQL_ServerBuiltinTopologyInputs supplied_inputs {};
	supplied_inputs.mysql_group_replication = supplied_group.get();
	admin_db.execute("DELETE FROM mysql_group_replication_hostgroups");
	ok(proxysql_collect_active_builtin_server_topology(admin_db, ProxySQL_ServerProtocol::mysql,
		supplied_inputs, mysql_topology, error) &&
		std::set<uint32_t>(mysql_topology.begin(), mysql_topology.end()) ==
			std::set<uint32_t>({0,31,32,51,52,53,54,61,62,63,64,71,72,81,82}),
		"supplied Cluster-v2 topology projections apply the same active-row semantics as queried Admin tables");
	admin_db.execute("DELETE FROM mysql_galera_hostgroups");
	admin_db.execute("DELETE FROM mysql_aws_aurora_hostgroups");
	admin_db.execute("DELETE FROM mysql_aws_rds_bgd_hostgroups");
	ProxySQL_Admin* admin = new ProxySQL_Admin(); // process-scoped fixture
	admin->admindb = &admin_db;
	GloAdmin = admin;
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_ZERO_CLAIM", "1", 1);
	const size_t before_admin_load = occurrences(read_log(), "server_controller_runtime");
	const size_t before_admin_module = occurrences(read_log(), "server_module_runtime_installed");
	admin->mysql_servers_wrlock();
	admin->load_mysql_servers_to_runtime();
	admin->mysql_servers_wrunlock();
	const std::string after_admin_mysql_load = read_log();
	const auto mysql_admin_zero_claims = proxysql_active_server_hostgroup_claims(
		ProxySQL_ServerProtocol::mysql);
	ok(occurrences(after_admin_mysql_load, "server_module_runtime_installed") == before_admin_module + 1 &&
		occurrences(after_admin_mysql_load, "server_controller_runtime") == before_admin_load + 1 &&
		mysql_admin_zero_claims.size() == 1 &&
		mysql_admin_zero_claims[0].writer_hostgroup == 0 &&
		mysql_admin_zero_claims[0].reader_hostgroup == 1 &&
		after_admin_mysql_load.rfind("server_module_runtime_installed") < after_admin_mysql_load.rfind("server_controller_runtime"),
		"public MySQL Admin LOAD notifies the module, then restarts the controller");
	admin->pgsql_servers_wrlock();
	const uint64_t pgsql_before_admin_load = proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::pgsql);
	const size_t before_pgsql_module = occurrences(read_log(), "server_module_runtime_installed");
	const size_t before_pgsql_controller = occurrences(read_log(), "server_controller_runtime");
	admin->load_pgsql_servers_to_runtime();
	admin->pgsql_servers_wrunlock();
	const std::string after_admin_pgsql_load = read_log();
	const auto pgsql_admin_zero_claims = proxysql_active_server_hostgroup_claims(
		ProxySQL_ServerProtocol::pgsql);
	ok(proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::pgsql) == pgsql_before_admin_load + 1 &&
		occurrences(after_admin_pgsql_load, "server_module_runtime_installed") == before_pgsql_module + 1 &&
		occurrences(after_admin_pgsql_load, "server_controller_runtime") == before_pgsql_controller + 1 &&
		pgsql_admin_zero_claims.size() == 1 &&
		pgsql_admin_zero_claims[0].writer_hostgroup == 1 &&
		pgsql_admin_zero_claims[0].reader_hostgroup == 0,
		"public PostgreSQL Admin LOAD reaches the same post-HGM module installation path");
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_ZERO_CLAIM");

	const size_t before_monitor_reload = occurrences(read_log(), "server_controller_runtime");
	const size_t before_monitor_module = occurrences(read_log(), "server_module_runtime_installed");
	const uint64_t mysql_before_monitor_reload = proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql);
	MyHGM->read_only_action_v2({{"admin-load.example", 3306, 1}});
	const std::string after_monitor_reload = read_log();
	ok(occurrences(after_monitor_reload, "server_controller_runtime") == before_monitor_reload &&
		occurrences(after_monitor_reload, "server_module_runtime_installed") == before_monitor_module &&
		proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql) == mysql_before_monitor_reload,
		"active HGM monitor reconciliation mutates runtime without notifying the module or restarting discovery");

	// The shared post-fetch branch is the exact endpoint used by both v1
	// Cluster pull functions.  An old peer has no module metadata, so it must
	// install only its core snapshot and leave local affiliated policy untouched.
	auto select_rows = [&](const char* query) {
		char* sqlite_error = nullptr;
		int columns = 0, affected_rows = 0;
		SQLite3_result* rows = nullptr;
		admin_db.execute_statement(query, &sqlite_error, &columns, &affected_rows, &rows);
		if (sqlite_error != nullptr) {
			free(sqlite_error);
			delete rows;
			return static_cast<SQLite3_result*>(nullptr);
		}
		return rows;
	};
	auto module_tables = [&](ProxySQL_ServerProtocol protocol) {
		std::vector<ProxySQL_ServerModuleClusterTable> tables;
		const bool mysql = protocol == ProxySQL_ServerProtocol::mysql;
		tables.push_back({mysql ? "mysql_fake_server_module_claims" : "pgsql_fake_server_module_claims",
			mysql ? "runtime_mysql_fake_server_module_claims" : "runtime_pgsql_fake_server_module_claims",
			"writer", std::unique_ptr<SQLite3_result>(select_rows(mysql
				? "SELECT * FROM mysql_fake_server_module_claims ORDER BY writer"
				: "SELECT * FROM pgsql_fake_server_module_claims ORDER BY writer"))});
		return tables;
	};
	auto mysql_core_rows = [&]() {
		return select_rows("SELECT hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers");
	};
	auto pgsql_core_rows = [&]() {
		return select_rows("SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM pgsql_servers");
	};
	auto mysql_stage = [](SQLite3_result* rows) { MyHGM->servers_add(rows); };
	auto mysql_commit = [](SQLite3_result* rows) { MyHGM->commit({rows, {}}, {nullptr, {}}, true, true); };
	auto pgsql_stage = [](SQLite3_result* rows) { PgHGM->servers_add(rows); };
	auto pgsql_commit = [](SQLite3_result* rows) { PgHGM->commit({rows, {}}, {nullptr, {}}, true, true); };
	const size_t before_topology_snapshot = occurrences(
		read_log(), "runtime_controller_topology_count=2");
	proxysql_cluster_install_v1_runtime_post_fetch(ProxySQL_ServerProtocol::mysql, mysql_core_rows(),
		true, module_tables(ProxySQL_ServerProtocol::mysql), mysql_stage, mysql_commit);
	ok(occurrences(read_log(), "runtime_controller_topology_count=2") == before_topology_snapshot + 1,
		"MySQL Cluster v1 publishes the installed built-in topology with its runtime snapshot");
	// The module claims (31,32), still owned by the installed runtime topology
	// although MEMORY has removed it: the claim is dropped, the pull installs.
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_BUILTIN_CLAIM", "1", 1);
	admin_db.execute("DELETE FROM mysql_replication_hostgroups");
	const uint64_t before_mysql_conflict = proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql);
	proxysql_cluster_install_v1_runtime_post_fetch(ProxySQL_ServerProtocol::mysql, mysql_core_rows(),
		true, module_tables(ProxySQL_ServerProtocol::mysql), mysql_stage, mysql_commit);
	ok(proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql) == before_mysql_conflict + 1 &&
		claims_are(ProxySQL_ServerProtocol::mysql, {}),
		"MySQL Cluster v1 installs and drops a module claim owned by installed runtime topology");
	admin_db.execute("DELETE FROM pgsql_replication_hostgroups");
	const uint64_t before_pgsql_conflict = proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::pgsql);
	proxysql_cluster_install_v1_runtime_post_fetch(ProxySQL_ServerProtocol::pgsql, pgsql_core_rows(),
		true, module_tables(ProxySQL_ServerProtocol::pgsql), pgsql_stage, pgsql_commit);
	ok(proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::pgsql) == before_pgsql_conflict + 1 &&
		claims_are(ProxySQL_ServerProtocol::pgsql, {}),
		"PostgreSQL Cluster v1 installs and drops a module claim owned by installed runtime topology");
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_BUILTIN_CLAIM");

	incoming_servers_t clear_mysql_topology {};
	clear_mysql_topology.incoming_replication_hostgroups =
		select_rows("SELECT * FROM mysql_replication_hostgroups WHERE 0");
	admin->mysql_servers_wrlock();
	admin->load_mysql_servers_to_runtime(clear_mysql_topology, {}, {}, true, false);
	admin->mysql_servers_wrunlock();
	incoming_pgsql_servers_t clear_pgsql_topology {};
	clear_pgsql_topology.incoming_replication_hostgroups =
		select_rows("SELECT * FROM pgsql_replication_hostgroups WHERE 0");
	admin->pgsql_servers_wrlock();
	admin->load_pgsql_servers_to_runtime(clear_pgsql_topology, {}, {}, false);
	admin->pgsql_servers_wrunlock();
	admin_db.execute("INSERT INTO mysql_replication_hostgroups VALUES (31,32,'read_only','MEMORY only')");
	admin_db.execute("INSERT INTO pgsql_replication_hostgroups VALUES (31,32,'read_only','MEMORY only')");
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_BUILTIN_CLAIM", "1", 1);
	proxysql_cluster_install_v1_runtime_post_fetch(ProxySQL_ServerProtocol::mysql, mysql_core_rows(),
		true, module_tables(ProxySQL_ServerProtocol::mysql), mysql_stage, mysql_commit);
	ok(claims_are(ProxySQL_ServerProtocol::mysql, {{31, 32}}),
		"MySQL Cluster v1 keeps a module claim absent from installed runtime topology even when stale MEMORY still contains it");
	proxysql_cluster_install_v1_runtime_post_fetch(ProxySQL_ServerProtocol::pgsql, pgsql_core_rows(),
		true, module_tables(ProxySQL_ServerProtocol::pgsql), pgsql_stage, pgsql_commit);
	ok(claims_are(ProxySQL_ServerProtocol::pgsql, {{31, 32}}),
		"PostgreSQL Cluster v1 keeps a module claim absent from installed runtime topology even when stale MEMORY still contains it");
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_BUILTIN_CLAIM");
	const size_t before_mysql_fallback_module = occurrences(read_log(), "server_module_runtime_installed");
	const size_t before_mysql_fallback_controller = occurrences(read_log(), "server_controller_runtime");
	const uint64_t before_mysql_fallback_generation = proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql);
	proxysql_cluster_install_v1_runtime_post_fetch(ProxySQL_ServerProtocol::mysql, mysql_core_rows(),
		false, {}, mysql_stage, mysql_commit);
	ok(occurrences(read_log(), "server_module_runtime_installed") == before_mysql_fallback_module &&
		occurrences(read_log(), "server_controller_runtime") == before_mysql_fallback_controller + 1 &&
		proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql) == before_mysql_fallback_generation + 1 &&
		claims_are(ProxySQL_ServerProtocol::mysql, {{31, 32}}),
		"real MySQL v1 old-peer fallback advances one generation without touching affiliated policy");
	const size_t before_pgsql_fallback_module = occurrences(read_log(), "server_module_runtime_installed");
	const size_t before_pgsql_fallback_controller = occurrences(read_log(), "server_controller_runtime");
	const uint64_t before_pgsql_fallback_generation = proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::pgsql);
	proxysql_cluster_install_v1_runtime_post_fetch(ProxySQL_ServerProtocol::pgsql, pgsql_core_rows(),
		false, {}, pgsql_stage, pgsql_commit);
	ok(occurrences(read_log(), "server_module_runtime_installed") == before_pgsql_fallback_module &&
		occurrences(read_log(), "server_controller_runtime") == before_pgsql_fallback_controller + 1 &&
		proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::pgsql) == before_pgsql_fallback_generation + 1 &&
		claims_are(ProxySQL_ServerProtocol::pgsql, {{31, 32}}),
		"real PostgreSQL v1 old-peer fallback advances one generation without touching affiliated policy");

	// A module can never reject an operator LOAD (#6448): a claim overlapping
	// the built-in topology is dropped, and the core and module are installed.
	admin_db.execute("INSERT INTO mysql_servers VALUES (17,'claim-conflict.example',3306,0,'ONLINE',1,0,100,0,1,0,'claim')");
	const uint64_t before_conflict_load = proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql);
	const size_t before_conflict_module = occurrences(read_log(), "server_module_runtime_installed");
	const size_t before_conflict_controller = occurrences(read_log(), "server_controller_runtime");
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_BUILTIN_CLAIM", "1", 1);
	admin->mysql_servers_wrlock();
	admin->load_mysql_servers_to_runtime();
	admin->mysql_servers_wrunlock();
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_BUILTIN_CLAIM");
	std::unique_ptr<SQLite3_result> conflict_runtime(MyHGM->dump_table_mysql("mysql_servers"));
	ok(conflict_runtime != nullptr && conflict_runtime->rows_count == 2 &&
		proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql) == before_conflict_load + 1 &&
		occurrences(read_log(), "server_module_runtime_installed") == before_conflict_module + 1 &&
		occurrences(read_log(), "server_controller_runtime") == before_conflict_controller + 1,
		"a conflicting module claim cannot block the Admin LOAD of core and module tables");
	ok(claims_are(ProxySQL_ServerProtocol::mysql, {}),
		"the Admin LOAD drops the module claim that overlaps the built-in topology");
	GloAdmin = nullptr;

	(void)proxysql_stop_configured_plugins(manager, error);
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
	unsetenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_SERVER_DISCOVERY");
	unsetenv("PROXYSQL_FAKE_PLUGIN_INSTALL_SERVER_DISCOVERY_CONTROLLER");
	unsetenv("PROXYSQL_FAKE_PLUGIN_AFFILIATED");
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_BOTH_PROTOCOLS");
	unsetenv("PROXYSQL_FAKE_PLUGIN_LOG");
	unlink(g_log_path.c_str());
	return exit_status();
}
