#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "ProxySQL_ServerDiscovery.h"
#include "MySQL_Thread.h"
#include "ProxySQL_Statistics.hpp"
#include "MySQL_Monitor.hpp"
#include "proxysql_admin.h"
#ifdef PROXYSQL40
#include "ProxySQL_PluginManager.h"
#endif

#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>

extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_Statistics* GloProxyStats;
extern MySQL_Monitor* GloMyMon;

#ifdef __linux__
// Corrupt the candidate generation at the installation boundary so the real
// transaction rejects it. The loaders must report that failure even though
// the preceding HGM commit has already succeeded.
static bool reject_next_install = false;
extern "C" bool __real__ZN40ProxySQL_ServerRuntimeInstallTransaction6commitE30ProxySQL_ServerRuntimeSnapshotb(
	ProxySQL_ServerRuntimeInstallTransaction*, ProxySQL_ServerRuntimeSnapshot, bool);
/** @brief Reject one real installation without replacing transaction validation. */
extern "C" bool __wrap__ZN40ProxySQL_ServerRuntimeInstallTransaction6commitE30ProxySQL_ServerRuntimeSnapshotb(
	ProxySQL_ServerRuntimeInstallTransaction* transaction, ProxySQL_ServerRuntimeSnapshot snapshot,
	bool commit_module) {
	if (reject_next_install) {
		reject_next_install = false;
		snapshot.generation = 0;
	}
	return __real__ZN40ProxySQL_ServerRuntimeInstallTransaction6commitE30ProxySQL_ServerRuntimeSnapshotb(
		transaction, std::move(snapshot), commit_module);
}
#endif

namespace {

/** @brief Own the resources whose constructors support this thread-free fixture. */
class RuntimeLoadFixture {
	char memory_db[9] = ":memory:";
	char* saved_statsdb_path;
	std::unique_ptr<ProxySQL_Statistics> statistics;
	std::unique_ptr<MySQL_Monitor> monitor;
	std::unique_ptr<SQLite3DB> admin_db;
public:
	/** @brief Initialize real loader dependencies without starting daemon threads. */
	RuntimeLoadFixture() : saved_statsdb_path(GloVars.statsdb_disk) {
		GloVars.statsdb_disk = memory_db;
		statistics = std::make_unique<ProxySQL_Statistics>();
		statistics->init();
		GloProxyStats = statistics.get();
		test_init_query_processor();
		test_init_hostgroups();
		monitor = std::make_unique<MySQL_Monitor>();
		GloMyMon = monitor.get();
		MyHGM->gtid_ev_loop = ev_loop_new(0);
		ev_async_init(MyHGM->gtid_ev_async, [](EV_P_ ev_async*, int) {
			// No GTID worker runs in this fixture; HGM commits may send a wake-up.
		});
		// Admin cannot be destroyed without its private daemon initialization
		// and shutdown lifecycle. Keep it process-scoped, as in existing Admin
		// publisher fixtures; its separately owned database is detached below.
		GloAdmin = new ProxySQL_Admin();
		admin_db = std::make_unique<SQLite3DB>();
		admin_db->open(memory_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		GloAdmin->admindb = admin_db.get();
	}

	/** @brief Detach borrowed globals before destroying fixture-owned resources. */
	~RuntimeLoadFixture() {
		GloAdmin->admindb = nullptr;
		admin_db.reset();
		GloMyMon = nullptr;
		monitor.reset();
		GloProxyStats = nullptr;
		statistics.reset();
		GloVars.statsdb_disk = saved_statsdb_path;
	}
};

/** @brief Create the server projections consumed by the real checked Admin loaders. */
void create_schema(SQLite3DB& db) {
	db.execute("CREATE TABLE mysql_servers (hostgroup_id INTEGER, hostname TEXT, port INTEGER, gtid_port INTEGER, status TEXT, weight INTEGER, compression INTEGER, max_connections INTEGER, max_replication_lag INTEGER, use_ssl INTEGER, max_latency_ms INTEGER, comment TEXT)");
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

/** @brief Invoke the public checked loader under its required protocol lock. */
bool load(ProxySQL_ServerProtocol protocol, bool emit = true) {
	if (protocol == ProxySQL_ServerProtocol::mysql) {
		GloAdmin->mysql_servers_wrlock();
		const bool loaded = GloAdmin->load_mysql_servers_to_runtime({}, {}, {}, true, emit);
		GloAdmin->mysql_servers_wrunlock();
		return loaded;
	}
	GloAdmin->pgsql_servers_wrlock();
	const bool loaded = GloAdmin->load_pgsql_servers_to_runtime_checked({}, {}, {}, emit);
	GloAdmin->pgsql_servers_wrunlock();
	return loaded;
}

/** @brief Take ownership of the HGM runtime projection returned to the caller. */
std::unique_ptr<SQLite3_result> runtime_rows(ProxySQL_ServerProtocol protocol) {
	return std::unique_ptr<SQLite3_result>(protocol == ProxySQL_ServerProtocol::mysql
		? MyHGM->dump_table_mysql("mysql_servers") : PgHGM->dump_table_pgsql("pgsql_servers"));
}

/** @brief Check the installed hostname and weight through the HGM public dump API. */
bool runtime_matches(ProxySQL_ServerProtocol protocol, const char* hostname, const char* weight) {
	const auto rows = runtime_rows(protocol);
	const int weight_column = protocol == ProxySQL_ServerProtocol::mysql ? 5 : 4;
	return rows != nullptr && rows->rows_count == 1 &&
		strcmp(rows->rows[0]->fields[1], hostname) == 0 &&
		strcmp(rows->rows[0]->fields[weight_column], weight) == 0;
}

/** @brief Exercise runtime changes, rejected installs, and recovery for one protocol. */
void test_protocol_loads(SQLite3DB& db, ProxySQL_ServerProtocol protocol) {
	const bool mysql = protocol == ProxySQL_ServerProtocol::mysql;
	const char* name = mysql ? "MySQL" : "PostgreSQL";
	const int index = mysql ? 0 : 1;
	uint64_t generation = proxysql_pending_server_runtime_generation(protocol);
	ok(load(protocol), "%s ordinary checked Admin LOAD succeeds", name);
	ok(GloAdmin->servers_load_veto[index].empty(), "%s successful LOAD has no module veto", name);
	ok(proxysql_pending_server_runtime_generation(protocol) == generation + 1,
		"%s LOAD commits exactly one runtime installation generation", name);
	ok(runtime_matches(protocol, mysql ? "mysql-load.example" : "pgsql-load.example", "1"),
		"%s LOAD installs the configured server in HGM", name);

	db.execute(mysql ? "UPDATE mysql_servers SET weight=7" : "UPDATE pgsql_servers SET weight=7");
	generation = proxysql_pending_server_runtime_generation(protocol);
	ok(load(protocol) && proxysql_pending_server_runtime_generation(protocol) == generation + 1,
		"%s repeated LOAD releases its reservation and advances the generation", name);
	ok(runtime_matches(protocol, mysql ? "mysql-load.example" : "pgsql-load.example", "7"),
		"%s repeated LOAD installs the updated server weight", name);

	db.execute(mysql ? "UPDATE mysql_servers SET weight=8" : "UPDATE pgsql_servers SET weight=8");
	generation = proxysql_pending_server_runtime_generation(protocol);
	ok(load(protocol, false) && GloAdmin->servers_load_veto[index].empty() &&
		runtime_matches(protocol, mysql ? "mysql-load.example" : "pgsql-load.example", "8"),
		"%s LOAD without installation notification applies the updated configuration", name);
	ok(proxysql_pending_server_runtime_generation(protocol) == generation,
		"%s non-emitting LOAD does not consume a runtime generation", name);

#ifdef __linux__
	db.execute(mysql ? "UPDATE mysql_servers SET weight=9" : "UPDATE pgsql_servers SET weight=9");
	reject_next_install = true;
	ok(!load(protocol), "%s checked LOAD reports a failed runtime installation commit", name);
	ok(!GloAdmin->servers_load_veto[index].empty(), "%s failed installation has an error reason", name);
	ok(proxysql_pending_server_runtime_generation(protocol) == generation,
		"%s failed installation does not advance the generation", name);
	ok(runtime_matches(protocol, mysql ? "mysql-load.example" : "pgsql-load.example", "9"),
		"%s installation failure follows an already committed HGM configuration", name);
	ok(load(protocol) && GloAdmin->servers_load_veto[index].empty() &&
		proxysql_pending_server_runtime_generation(protocol) == generation + 1,
		"%s checked LOAD recovers after an installation commit failure", name);
	generation = proxysql_pending_server_runtime_generation(protocol);
#else
	skip(5, "runtime commit fault injection requires GNU ld --wrap");
#endif

	std::string error;
	{
		ProxySQL_ServerRuntimeInstallTransaction reserved(protocol, error);
		ok(reserved && !load(protocol), "%s checked LOAD reports an unavailable installation transaction", name);
		ok(proxysql_pending_server_runtime_generation(protocol) == generation,
			"%s failed preparation does not consume a runtime generation", name);
	}

	db.execute(mysql ? "DELETE FROM mysql_servers" : "DELETE FROM pgsql_servers");
	ok(load(protocol) && GloAdmin->servers_load_veto[index].empty() &&
		proxysql_pending_server_runtime_generation(protocol) == generation + 1,
		"%s empty LOAD succeeds after an aborted reservation", name);
	const auto rows = runtime_rows(protocol);
	ok(rows != nullptr && rows->rows_count == 0, "%s empty LOAD removes the runtime server", name);
}

#if defined(PROXYSQL40) && defined(__linux__)
/**
 * @brief Verify that an advisory module veto cannot hide a later commit failure.
 * Successful core-only installations still preserve the module rejection.
 */
void test_vetoed_install(SQLite3DB& db) {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_SERVER_DISCOVERY", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_AFFILIATED", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> manager;
	std::string error;
	if (!proxysql_load_configured_plugins(manager, {PROXYSQL_FAKE_PLUGIN_PATH}, error) ||
		!proxysql_init_configured_plugins(manager.get(), error))
		BAIL_OUT("cannot activate the server module fixture: %s", error.c_str());
	db.execute("CREATE TABLE mysql_fake_server_module_claims (writer INTEGER)");
	db.execute("INSERT INTO mysql_servers VALUES (31,'mysql-load.example',3306,0,'ONLINE',10,0,100,0,0,0,'mysql')");
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_PREPARE_THROW", "1", 1);
	const auto protocol = ProxySQL_ServerProtocol::mysql;
	const uint64_t generation = proxysql_pending_server_runtime_generation(protocol);
	ok(load(protocol), "MySQL core-only LOAD succeeds despite a module veto");
	ok(!GloAdmin->servers_load_veto[0].empty(), "MySQL successful core-only LOAD preserves the module veto");
	ok(proxysql_pending_server_runtime_generation(protocol) == generation + 1,
		"MySQL successful core-only LOAD advances the generation");
	ok(runtime_matches(protocol, "mysql-load.example", "10"), "MySQL vetoed module does not block core server changes");

	db.execute("UPDATE mysql_servers SET weight=11");
	reject_next_install = true;
	ok(!load(protocol), "MySQL checked LOAD reports a failed core-only commit after a module veto");
	ok(GloAdmin->servers_load_veto[0].find("commit MySQL server runtime installation") != std::string::npos,
		"MySQL core-only commit failure replaces the earlier module veto for the caller");
	ok(proxysql_pending_server_runtime_generation(protocol) == generation + 1,
		"MySQL failed core-only commit does not advance the generation");
	ok(runtime_matches(protocol, "mysql-load.example", "11"), "MySQL failed core-only commit follows the HGM update");
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_PREPARE_THROW");
	db.execute("UPDATE mysql_servers SET weight=12");
	ok(load(protocol) && GloAdmin->servers_load_veto[0].empty() &&
		proxysql_pending_server_runtime_generation(protocol) == generation + 2,
		"MySQL checked LOAD recovers after a veto and failed core-only commit");
	ok(runtime_matches(protocol, "mysql-load.example", "12"), "MySQL recovered LOAD installs the next server configuration");
	(void)proxysql_stop_configured_plugins(manager, error);
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
	unsetenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_SERVER_DISCOVERY");
	unsetenv("PROXYSQL_FAKE_PLUGIN_AFFILIATED");
}
#endif

} // namespace

/** @brief Run checked LOAD regressions on every supported product tier. */
int main() {
#if defined(PROXYSQL40) && defined(__linux__)
	plan(44);
#else
	plan(34);
#endif
	test_init_minimal();
	{
		RuntimeLoadFixture fixture;
		SQLite3DB& db = *GloAdmin->admindb;
		create_schema(db);
		db.execute("INSERT INTO mysql_servers VALUES (31,'mysql-load.example',3306,0,'ONLINE',1,0,100,0,0,0,'mysql')");
		db.execute("INSERT INTO pgsql_servers VALUES (41,'pgsql-load.example',5432,'ONLINE',1,0,100,0,0,0,'pgsql')");

		test_protocol_loads(db, ProxySQL_ServerProtocol::mysql);
		test_protocol_loads(db, ProxySQL_ServerProtocol::pgsql);

#if defined(PROXYSQL40) && defined(__linux__)
		test_vetoed_install(db);
#endif
	}
	test_cleanup_minimal();
	return exit_status();
}
