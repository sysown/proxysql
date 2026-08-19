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

void create_server_load_schema(SQLite3DB& db) {
	db.execute("CREATE TABLE mysql_servers (hostgroup_id INTEGER, hostname TEXT, port INTEGER, gtid_port INTEGER, status TEXT, weight INTEGER, compression INTEGER, max_connections INTEGER, max_replication_lag INTEGER, use_ssl INTEGER, max_latency_ms INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_fake_server_module_claims (writer INTEGER)");
	db.execute("CREATE TABLE pgsql_fake_server_module_claims (writer INTEGER)");
	db.execute("CREATE TABLE pgsql_servers (hostgroup_id INTEGER, hostname TEXT, port INTEGER, status TEXT, weight INTEGER, compression INTEGER, max_connections INTEGER, max_replication_lag INTEGER, use_ssl INTEGER, max_latency_ms INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INTEGER, reader_hostgroup INTEGER, check_type TEXT, comment TEXT)");
	db.execute("CREATE TABLE pgsql_replication_hostgroups (writer_hostgroup INTEGER, reader_hostgroup INTEGER)");
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
	plan(20);
	test_init_minimal();
	char path[] = "/tmp/proxysql_server_runtime_install.XXXXXX";
	const int fd = mkstemp(path);
	if (fd >= 0) close(fd);
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

	ProxySQL_ServerRuntimeSnapshot snapshot {};
	snapshot.protocol = ProxySQL_ServerProtocol::mysql;
	snapshot.generation = proxysql_pending_server_runtime_generation(snapshot.protocol);
	snapshot.servers.push_back({17, "runtime.example", 3306, 0, "ONLINE", 5, 0, 100, 0, 1, 0, "complete"});
	const uint64_t candidate = snapshot.generation;
	ok(proxysql_prepare_server_runtime_install(snapshot),
		"the source-agnostic prepare dispatcher accepts the complete operator/Cluster snapshot");
	ok(proxysql_pending_server_runtime_generation(snapshot.protocol) == candidate,
		"preparation never consumes an installed generation before the HGM commit point");
	ok(read_log().find("server_controller_runtime") == std::string::npos,
		"prepare alone does not restart the controller");

	proxysql_commit_server_runtime_install(snapshot);
	const std::string after_first = read_log();
	ok(occurrences(after_first, "server_controller_runtime") == 1,
		"post-HGM commit publishes exactly one runtime installation event");
	ok(proxysql_pending_server_runtime_generation(snapshot.protocol) == candidate + 1,
		"a successful MySQL installation advances exactly one protocol generation");

	ProxySQL_ServerRuntimeSnapshot zero_servers {};
	zero_servers.protocol = ProxySQL_ServerProtocol::mysql;
	zero_servers.generation = proxysql_pending_server_runtime_generation(zero_servers.protocol);
	ok(proxysql_prepare_server_runtime_install(zero_servers),
		"zero-server runtime installations remain valid");
	proxysql_commit_server_runtime_install(std::move(zero_servers));
	ok(occurrences(read_log(), "server_controller_runtime") == 2,
		"zero-server post-commit installation restarts the controller without seeds");

	ProxySQL_ServerRuntimeSnapshot pgsql_snapshot {};
	pgsql_snapshot.protocol = ProxySQL_ServerProtocol::pgsql;
	pgsql_snapshot.generation = proxysql_pending_server_runtime_generation(pgsql_snapshot.protocol);
	const uint64_t pgsql_candidate = pgsql_snapshot.generation;
	ok(proxysql_prepare_server_runtime_install(pgsql_snapshot),
		"the identical dispatcher accepts a PostgreSQL runtime installation");
	proxysql_commit_server_runtime_install(std::move(pgsql_snapshot));
	ok(proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::pgsql) == pgsql_candidate + 1 &&
		proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql) == candidate + 2,
		"MySQL and PostgreSQL installed generations are independent and monotonic");

	// Keep the first preparation open while another MySQL installation arrives.
	// The second must not run module prepare against the same candidate then be
	// retagged at commit; the per-protocol reservation serializes the full pair.
	ProxySQL_ServerRuntimeSnapshot first_concurrent {};
	first_concurrent.protocol = ProxySQL_ServerProtocol::mysql;
	ok(proxysql_prepare_server_runtime_install(first_concurrent),
		"first concurrent preparation reserves the MySQL install generation");
	std::atomic<bool> second_prepared {false};
	std::thread second([&] {
		ProxySQL_ServerRuntimeSnapshot second_concurrent {};
		second_concurrent.protocol = ProxySQL_ServerProtocol::mysql;
		if (proxysql_prepare_server_runtime_install(second_concurrent)) {
			second_prepared.store(true, std::memory_order_release);
			proxysql_commit_server_runtime_install(std::move(second_concurrent));
		}
	});
	std::this_thread::sleep_for(std::chrono::milliseconds(30));
	ok(!second_prepared.load(std::memory_order_acquire),
		"second MySQL preparation cannot pass the prepare-to-commit reservation");
	proxysql_commit_server_runtime_install(std::move(first_concurrent));
	second.join();
	ok(second_prepared.load(std::memory_order_acquire),
		"second preparation runs only after the first installation commits");

	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_CLAIM", "1", 1);
	ProxySQL_ServerRuntimeSnapshot conflicting_claim {};
	conflicting_claim.protocol = ProxySQL_ServerProtocol::mysql;
	conflicting_claim.generation = proxysql_pending_server_runtime_generation(conflicting_claim.protocol);
	conflicting_claim.servers.push_back({17, "topology-owner.example", 3306});
	ok(!proxysql_prepare_server_runtime_install(conflicting_claim),
		"a plugin claim overlapping the core topology is rejected before HGM staging");
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_CLAIM");

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
	admin_db.execute("INSERT INTO pgsql_servers VALUES (41,'pgsql-load.example',5432,'ONLINE',1,0,100,0,1,0,'admin')");
	ProxySQL_Admin* admin = new ProxySQL_Admin(); // process-scoped fixture
	admin->admindb = &admin_db;
	GloAdmin = admin;
	const size_t before_admin_load = occurrences(read_log(), "server_controller_runtime");
	const size_t before_admin_prepare = occurrences(read_log(), "server_module_prepare");
	const size_t before_admin_commit = occurrences(read_log(), "server_module_commit");
	admin->mysql_servers_wrlock();
	admin->load_mysql_servers_to_runtime();
	admin->mysql_servers_wrunlock();
	const std::string after_admin_mysql_load = read_log();
	ok(occurrences(after_admin_mysql_load, "server_module_prepare") == before_admin_prepare + 1 &&
		occurrences(after_admin_mysql_load, "server_module_commit") == before_admin_commit + 1 &&
		occurrences(after_admin_mysql_load, "server_controller_runtime") == before_admin_load + 1 &&
		after_admin_mysql_load.rfind("server_module_prepare") < after_admin_mysql_load.rfind("server_module_commit") &&
		after_admin_mysql_load.rfind("server_module_commit") < after_admin_mysql_load.rfind("server_controller_runtime"),
		"public MySQL Admin LOAD prepares before HGM staging and commits before controller restart");
	admin->pgsql_servers_wrlock();
	const uint64_t pgsql_before_admin_load = proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::pgsql);
	const size_t before_pgsql_prepare = occurrences(read_log(), "server_module_prepare");
	const size_t before_pgsql_commit = occurrences(read_log(), "server_module_commit");
	const size_t before_pgsql_controller = occurrences(read_log(), "server_controller_runtime");
	admin->load_pgsql_servers_to_runtime();
	admin->pgsql_servers_wrunlock();
	const std::string after_admin_pgsql_load = read_log();
	ok(proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::pgsql) == pgsql_before_admin_load + 1 &&
		occurrences(after_admin_pgsql_load, "server_module_prepare") == before_pgsql_prepare + 1 &&
		occurrences(after_admin_pgsql_load, "server_module_commit") == before_pgsql_commit + 1 &&
		occurrences(after_admin_pgsql_load, "server_controller_runtime") == before_pgsql_controller + 1,
		"public PostgreSQL Admin LOAD reaches the same post-HGM module installation path");

	const size_t before_monitor_reload = occurrences(read_log(), "server_controller_runtime");
	const size_t before_monitor_prepare = occurrences(read_log(), "server_module_prepare");
	const size_t before_monitor_commit = occurrences(read_log(), "server_module_commit");
	const uint64_t mysql_before_monitor_reload = proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql);
	MyHGM->read_only_action_v2({{"admin-load.example", 3306, 1}});
	const std::string after_monitor_reload = read_log();
	ok(occurrences(after_monitor_reload, "server_controller_runtime") == before_monitor_reload &&
		occurrences(after_monitor_reload, "server_module_prepare") == before_monitor_prepare &&
		occurrences(after_monitor_reload, "server_module_commit") == before_monitor_commit &&
		proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql) == mysql_before_monitor_reload,
		"active HGM monitor reconciliation mutates runtime without preparing, committing, or restarting discovery");

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
	const size_t before_mysql_fallback_prepare = occurrences(read_log(), "server_module_prepare");
	const size_t before_mysql_fallback_commit = occurrences(read_log(), "server_module_commit");
	const size_t before_mysql_fallback_controller = occurrences(read_log(), "server_controller_runtime");
	ok(proxysql_cluster_install_v1_runtime_post_fetch(ProxySQL_ServerProtocol::mysql,
		select_rows("SELECT hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers"),
		false, 0,
		[](SQLite3_result* rows) { MyHGM->servers_add(rows); },
		[](SQLite3_result* rows) { return MyHGM->commit({rows, {}}, {nullptr, {}}, true, true); }) &&
		occurrences(read_log(), "server_module_prepare") == before_mysql_fallback_prepare &&
		occurrences(read_log(), "server_module_commit") == before_mysql_fallback_commit &&
		occurrences(read_log(), "server_controller_runtime") == before_mysql_fallback_controller + 1,
		"real MySQL v1 old-peer fallback installs core runtime without touching affiliated policy");
	const size_t before_pgsql_fallback_prepare = occurrences(read_log(), "server_module_prepare");
	const size_t before_pgsql_fallback_commit = occurrences(read_log(), "server_module_commit");
	const size_t before_pgsql_fallback_controller = occurrences(read_log(), "server_controller_runtime");
	ok(proxysql_cluster_install_v1_runtime_post_fetch(ProxySQL_ServerProtocol::pgsql,
		select_rows("SELECT hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM pgsql_servers"),
		false, 0,
		[](SQLite3_result* rows) { PgHGM->servers_add(rows); },
		[](SQLite3_result* rows) { return PgHGM->commit({rows, {}}, {nullptr, {}}, true, true); }) &&
		occurrences(read_log(), "server_module_prepare") == before_pgsql_fallback_prepare &&
		occurrences(read_log(), "server_module_commit") == before_pgsql_fallback_commit &&
		occurrences(read_log(), "server_controller_runtime") == before_pgsql_fallback_controller + 1,
		"real PostgreSQL v1 old-peer fallback installs core runtime without touching affiliated policy");

	// A rejected operator LOAD must unwind the Admin-selected core resultset
	// and the install reservation, so the next ordinary LOAD can proceed.
	admin_db.execute("INSERT INTO mysql_servers VALUES (17,'claim-conflict.example',3306,0,'ONLINE',1,0,100,0,1,0,'claim')");
	const uint64_t before_rejected_load = proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql);
	const size_t before_rejected_commit = occurrences(read_log(), "server_module_commit");
	const size_t before_rejected_controller = occurrences(read_log(), "server_controller_runtime");
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_CLAIM", "1", 1);
	admin->mysql_servers_wrlock();
	admin->load_mysql_servers_to_runtime();
	admin->mysql_servers_wrunlock();
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_CLAIM");
	admin->mysql_servers_wrlock();
	admin->load_mysql_servers_to_runtime();
	admin->mysql_servers_wrunlock();
	ok(proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql) == before_rejected_load + 1 &&
		occurrences(read_log(), "server_module_commit") == before_rejected_commit + 1 &&
		occurrences(read_log(), "server_controller_runtime") == before_rejected_controller + 1,
		"prepare-rejected Admin LOAD cleans its selected rows and leaves the next operator LOAD installable");
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
