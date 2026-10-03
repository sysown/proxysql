#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "ProxySQL_ServerDiscovery.h"
#include "MySQL_Thread.h"
#include "ProxySQL_Statistics.hpp"
#include "MySQL_Monitor.hpp"
#include "proxysql_admin.h"

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

std::unique_ptr<SQLite3_result> runtime_rows(ProxySQL_ServerProtocol protocol) {
	return std::unique_ptr<SQLite3_result>(protocol == ProxySQL_ServerProtocol::mysql
		? MyHGM->dump_table_mysql("mysql_servers") : PgHGM->dump_table_pgsql("pgsql_servers"));
}

bool runtime_matches(ProxySQL_ServerProtocol protocol, const char* hostname, const char* weight) {
	const auto rows = runtime_rows(protocol);
	const int weight_column = protocol == ProxySQL_ServerProtocol::mysql ? 5 : 4;
	return rows != nullptr && rows->rows_count == 1 &&
		strcmp(rows->rows[0]->fields[1], hostname) == 0 &&
		strcmp(rows->rows[0]->fields[weight_column], weight) == 0;
}

} // namespace

int main() {
	plan(34);
	test_init_minimal();
	// Match the existing Admin publisher fixtures: these components stay
	// reachable through their process globals. Admin teardown requires daemon
	// threads and table definitions that this focused fixture never starts.
	GloVars.statsdb_disk = const_cast<char*>(":memory:");
	GloProxyStats = new ProxySQL_Statistics();
	test_init_query_processor();
	test_init_hostgroups();
	GloMyMon = new MySQL_Monitor();
	MyHGM->gtid_ev_loop = ev_loop_new(0);
	ev_async_init(MyHGM->gtid_ev_async, [](EV_P_ ev_async*, int) {});
	GloAdmin = new ProxySQL_Admin();
	GloAdmin->admindb = new SQLite3DB();
	GloAdmin->admindb->open(const_cast<char*>(":memory:"),
		SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	SQLite3DB& db = *GloAdmin->admindb;
	create_schema(db);
	db.execute("INSERT INTO mysql_servers VALUES (31,'mysql-load.example',3306,0,'ONLINE',1,0,100,0,0,0,'mysql')");
	db.execute("INSERT INTO pgsql_servers VALUES (41,'pgsql-load.example',5432,'ONLINE',1,0,100,0,0,0,'pgsql')");

	for (const auto protocol : {ProxySQL_ServerProtocol::mysql, ProxySQL_ServerProtocol::pgsql}) {
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

	test_cleanup_minimal();
	return exit_status();
}
