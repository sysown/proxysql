#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "ProxySQL_ServerDiscovery.h"
#include "MySQL_Thread.h"
#include "ProxySQL_Statistics.hpp"
#include "MySQL_Monitor.hpp"
#include "proxysql_admin.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>

extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_Statistics* GloProxyStats;
extern MySQL_Monitor* GloMyMon;


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

/** @brief Create the server projections consumed by the real Admin loaders. */
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

/** @brief Invoke the public loader under its required protocol lock. */
void load(ProxySQL_ServerProtocol protocol, bool emit = true) {
	if (protocol == ProxySQL_ServerProtocol::mysql) {
		GloAdmin->mysql_servers_wrlock();
		GloAdmin->load_mysql_servers_to_runtime({}, {}, {}, true, emit);
		GloAdmin->mysql_servers_wrunlock();
		return;
	}
	GloAdmin->pgsql_servers_wrlock();
	GloAdmin->load_pgsql_servers_to_runtime({}, {}, {}, emit);
	GloAdmin->pgsql_servers_wrunlock();
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

/** @brief Recreate the hostgroup attributes table dropped to inject an SQLite error. */
void create_hostgroup_attributes(SQLite3DB& db, bool mysql) {
	db.execute(mysql
		? "CREATE TABLE mysql_hostgroup_attributes (hostgroup_id INTEGER, max_num_online_servers INTEGER, autocommit INTEGER, free_connections_pct INTEGER, init_connect TEXT, multiplex INTEGER, connection_warming INTEGER, throttle_connections_per_sec INTEGER, ignore_session_variables TEXT, hostgroup_settings TEXT, comment TEXT)"
		: "CREATE TABLE pgsql_hostgroup_attributes (hostgroup_id INTEGER, max_num_online_servers INTEGER, free_connections_pct INTEGER, init_connect TEXT, multiplex INTEGER, connection_warming INTEGER, throttle_connections_per_sec INTEGER, ignore_session_variables TEXT, hostgroup_settings TEXT, comment TEXT)");
}

/**
 * @brief LOAD ... SERVERS TO RUNTIME always installs the admin tables (#6448).
 * @details As in v3.0.11, an SQLite error on a table is only logged. On
 *   PROXYSQL40 every emitting LOAD publishes exactly one runtime generation.
 */
void test_protocol_loads(SQLite3DB& db, ProxySQL_ServerProtocol protocol) {
	const bool mysql = protocol == ProxySQL_ServerProtocol::mysql;
	const char* name = mysql ? "MySQL" : "PostgreSQL";
	const char* host = mysql ? "mysql-load.example" : "pgsql-load.example";
#ifdef PROXYSQL40
	uint64_t generation = proxysql_pending_server_runtime_generation(protocol);
#endif
	load(protocol);
	ok(runtime_matches(protocol, host, "1"), "%s LOAD installs the configured server in HGM", name);
#ifdef PROXYSQL40
	ok(proxysql_pending_server_runtime_generation(protocol) == generation + 1,
		"%s LOAD publishes exactly one runtime generation", name);
#endif

	db.execute(mysql ? "UPDATE mysql_servers SET weight=7" : "UPDATE pgsql_servers SET weight=7");
	load(protocol);
	ok(runtime_matches(protocol, host, "7"), "%s repeated LOAD installs the updated server weight", name);

	db.execute(mysql ? "DROP TABLE mysql_hostgroup_attributes" : "DROP TABLE pgsql_hostgroup_attributes");
	db.execute(mysql ? "UPDATE mysql_servers SET weight=8" : "UPDATE pgsql_servers SET weight=8");
#ifdef PROXYSQL40
	generation = proxysql_pending_server_runtime_generation(protocol);
#endif
	load(protocol);
	ok(runtime_matches(protocol, host, "8"),
		"%s LOAD with an SQLite error on another admin table still installs the servers", name);
#ifdef PROXYSQL40
	ok(proxysql_pending_server_runtime_generation(protocol) == generation + 1,
		"%s LOAD with an SQLite error is still published", name);
#endif
	create_hostgroup_attributes(db, mysql);

	db.execute(mysql ? "UPDATE mysql_servers SET weight=9" : "UPDATE pgsql_servers SET weight=9");
#ifdef PROXYSQL40
	generation = proxysql_pending_server_runtime_generation(protocol);
#endif
	load(protocol, false);
	ok(runtime_matches(protocol, host, "9"),
		"%s LOAD without installation notification applies the updated configuration", name);
#ifdef PROXYSQL40
	ok(proxysql_pending_server_runtime_generation(protocol) == generation,
		"%s non-emitting LOAD does not publish a runtime generation", name);

	// A LOAD on a thread that already holds the install lock (plugin MySQL
	// configuration publication) used to fail as a nested installation.
	db.execute(mysql ? "UPDATE mysql_servers SET weight=10" : "UPDATE pgsql_servers SET weight=10");
	{
		// Hold Admin before install, matching the loader's Admin -> install -> HGM order.
		ScopedServerDiscoveryProtocolLock admin_lock(protocol);
		ProxySQL_ServerRuntimeInstallLock held(protocol);
		if (mysql) GloAdmin->load_mysql_servers_to_runtime({}, {}, {}, true, true);
		else GloAdmin->load_pgsql_servers_to_runtime({}, {}, {}, true);
	}
	ok(runtime_matches(protocol, host, "10") &&
		proxysql_pending_server_runtime_generation(protocol) == generation + 1,
		"%s LOAD under a held install lock installs and publishes", name);
#endif

	db.execute(mysql ? "DELETE FROM mysql_servers" : "DELETE FROM pgsql_servers");
	load(protocol);
	const auto rows = runtime_rows(protocol);
	ok(rows != nullptr && rows->rows_count == 0, "%s empty LOAD removes the runtime server", name);
}

} // namespace

/** @brief Run LOAD ... SERVERS TO RUNTIME regressions on every supported product tier. */
int main() {
#if defined(PROXYSQL40)
	plan(2 * 9);
#else
	plan(2 * 5);
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
	}
	test_cleanup_minimal();
	return exit_status();
}
