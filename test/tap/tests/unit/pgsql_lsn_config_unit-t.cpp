#include "cpp.h"
#include "proxysql.h"
#include "proxysql_admin.h"
#include "proxysql_config.h"
#include "configfile.hpp"
#include "ProxySQL_Admin_Tables_Definitions.h"
#include "ProxySQL_Statistics.hpp"
#include "sqlite3db.h"
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include <algorithm>
#include <memory>

extern PgSQL_Threads_Handler* GloPTH;
extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_Statistics* GloProxyStats;
static SQLite3DB* memory_db() {
	auto* db = new SQLite3DB();
	db->open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	return db;
}
static std::string scalar(SQLite3DB& db, const char* sql) {
	sqlite3_stmt* statement = nullptr;
	if ((*proxy_sqlite3_prepare_v2)(db.get_db(), sql, -1, &statement, nullptr) != SQLITE_OK) return "<error>";
	std::string value = "<null>";
	if ((*proxy_sqlite3_step)(statement) == SQLITE_ROW) {
		const auto* text = (*proxy_sqlite3_column_text)(statement, 0);
		if (text) value = reinterpret_cast<const char*>(text);
	}
	(*proxy_sqlite3_finalize)(statement);
	return value;
}
static std::string variable(const char* name) {
	char* value = GloPTH->get_variable(const_cast<char*>(name));
	std::string result = value ? value : "<missing>";
	free(value);
	return result;
}
static bool set_setting(const char* name, const char* value) {
	return GloPTH->set_variable(const_cast<char*>(name), value);
}
static bool load_servers() {
	GloAdmin->pgsql_servers_wrlock();
	bool loaded = GloAdmin->load_pgsql_servers_to_runtime_checked({}, {}, {}, false);
	GloAdmin->pgsql_servers_wrunlock();
	return loaded;
}
#ifdef PROXYSQL31
static void test_retention(SQLite3DB& db) {
	using namespace pgsql_lsn;
	const Endpoint source{"source",5432}, peer{"source-peer",5432}, b{"destination-b",5432}, c{"destination-c",5432};
	db.execute("INSERT INTO pgsql_servers(hostgroup_id,hostname) VALUES(10,'source'),(10,'source-peer'),(40,'source'),(20,'destination-b'),(30,'destination-c')");
	db.execute("UPDATE pgsql_servers SET status='OFFLINE_SOFT' WHERE hostname='source-peer'");
	ok(load_servers(), "server memberships load without replication activation");
	PgHGM->replace_lsn_interests({{10,{20},false},{40,{30},false}});
	ok(PgHGM->lsn_endpoints().size() == 4, "shared source membership deduplicates endpoints and includes offline-soft members");
	auto& manager = PgHGM->lsn_manager();
	auto publish = [&](const Endpoint& endpoint, Micros time, Lsn lsn, History identity = History{123,1}) {
		manager.publish({endpoint,identity,1000,{time,lsn},true});
	};
	auto target = [&](Micros completion) {
		const auto result = manager.lookup_after(source, completion);
		return result.required ? result.required->lsn : UINT64_MAX;
	};
	for (unsigned i=1; i<=4; ++i) publish(source,i*100,i*100);
	publish(peer,400,250);
	publish(b,400,400);
	publish(c,400,150);
	PgHGM->prune_lsn_history(0);
	ok(target(50) == 100, "shared source considers destinations from both source hostgroups");
	publish(c,500,400);
	PgHGM->prune_lsn_history(0);
	ok(target(50) == 200, "source peers also constrain the minimum progress floor");
	publish(peer,500,400);
	PgHGM->prune_lsn_history(0);
	ok(target(50) == 300 && target(300) == 400, "progress pruning retains the real strict predecessor and its timestamp");
	publish(source,500,500);
	publish(source,600,600);
	manager.withdraw(c);
	PgHGM->prune_lsn_history(550);
	ok(target(50) == 500 && target(500) == 600, "down destination blocks only progress pruning while age pruning keeps one boundary sample");
	PgHGM->replace_lsn_interests({{10,{20,99},false},{40,{30},false}});
	publish(source,700,700);
	publish(source,800,800);
	PgHGM->prune_lsn_history(0);
	ok(target(50) == 500, "unknown destination hostgroup cannot fabricate a progress floor");
	PgHGM->prune_lsn_history(750);
	ok(target(50) == 700, "unknown relationships cannot block age cleanup");
	publish(c,900,1000,{999,1});
	publish(source,900,900);
	PgHGM->replace_lsn_interests({{10,{20},false},{40,{30},false}});
	PgHGM->prune_lsn_history(950);
	ok(target(50) == 900, "incompatible WAL history and expired unchanged progress permit age cleanup");
	ok(manager.lookup_after(source,900).state == LookupState::Pending, "expired samples never invent a later timestamp");
	db.execute("DELETE FROM pgsql_servers WHERE hostname='destination-c'");
	db.execute("INSERT INTO pgsql_servers(hostgroup_id,hostname) VALUES(30,'replacement')");
	ok(load_servers(), "server reload recomputes rule memberships");
	const auto endpoints = PgHGM->lsn_endpoints();
	ok(endpoints.size() == 4 && std::find(endpoints.begin(),endpoints.end(),Endpoint{"replacement",5432}) != endpoints.end()
		&& std::find(endpoints.begin(),endpoints.end(),c) == endpoints.end(), "membership reload replaces physical destination endpoint");
	PgHGM->replace_lsn_interests({{10,{},true}});
	ok(PgHGM->lsn_endpoints().size() == 4, "unspecified destinations conservatively include configured hostgroups");
	PgHGM->replace_lsn_interests({});
	ok(PgHGM->lsn_endpoints().empty() && manager.latest_all().empty(), "removed rule interests retire monitor membership");
}
#endif
int main() {
	plan(NO_PLAN);
	test_init_minimal();
	test_init_query_processor();
	test_init_hostgroups();
	auto* previous_statsdb_path = GloVars.statsdb_disk;
	GloVars.statsdb_disk = const_cast<char*>(":memory:");
	auto statistics = std::make_unique<ProxySQL_Statistics>();
	GloProxyStats = statistics.get();
	GloProxyStats->init();
	// The partial admin fixture cannot run the production thread-shutdown destructor.
	GloAdmin = new ProxySQL_Admin();
	GloAdmin->admindb = memory_db();
	GloAdmin->configdb = memory_db();
	auto& db = *GloAdmin->admindb;
	for (const auto* schema : {ADMIN_SQLITE_TABLE_PGSQL_SERVERS, ADMIN_SQLITE_TABLE_PGSQL_REPLICATION_HOSTGROUPS,
		ADMIN_SQLITE_TABLE_PGSQL_HOSTGROUP_ATTRIBUTES, ADMIN_SQLITE_TABLE_PGSQL_SERVERS_SSL_PARAMS,
		ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_SERVERS, ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_REPLICATION_HOSTGROUPS,
		ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_HOSTGROUP_ATTRIBUTES, ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_SERVERS_SSL_PARAMS,
		ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES, ADMIN_SQLITE_RUNTIME_GLOBAL_VARIABLES}) db.execute(schema);
	ok(scalar(db,"SELECT COUNT(*) FROM pragma_table_info('pgsql_replication_hostgroups')") == "4", "replication hostgroups retain four columns");
	ok(scalar(db,"SELECT COUNT(*) FROM pragma_table_info('pgsql_replication_hostgroups') WHERE name='lsn_causal_reads'") == "0", "rejected replication activation is absent");
	for (const auto* name : {"lsn_poll_interval","lsn_wait_timeout"})
		ok(variable(name) == "<missing>" && !set_setting(name,"10"), "old %s variable has no alias",name);
#ifdef PROXYSQL31
	struct Setting {const char* name;const char* initial;const char* low;const char* high;const char* below;const char* above;};
	const Setting settings[] = {
		{"monitor_lsn_poll_interval","10","1","60000","0","60001"},
		{"monitor_lsn_poll_timeout","100","1","600000","0","600001"},
		{"monitor_lsn_history","60000","1000","604800000","999","604800001"}
	};
	for (const auto& setting : settings) {
		ok(variable(setting.name) == setting.initial,"%s default is %s ms",setting.name,setting.initial);
		for (const auto* value : {"","word","10garbage","99999999999999999999","-1",setting.below,setting.above})
			ok(!set_setting(setting.name,value),"reject %s=%s",setting.name,value);
		ok(set_setting(setting.name,setting.low),"accept %s lower boundary",setting.name);
		ok(set_setting(setting.name,setting.high),"accept %s upper boundary",setting.name);
		ok(!set_setting(setting.name,setting.above) && variable(setting.name) == setting.high,"rejection preserves %s",setting.name);
	}
	db.execute("INSERT INTO global_variables VALUES('pgsql-monitor_lsn_poll_interval','17'),('pgsql-monitor_lsn_poll_timeout','19'),('pgsql-monitor_lsn_history','2000')");
	auto flushed = GloAdmin->load_pgsql_variables_to_runtime();
	ok(flushed.rejected == 0 && variable("monitor_lsn_poll_interval") == "17" && variable("monitor_lsn_poll_timeout") == "19"
		&& variable("monitor_lsn_history") == "2000", "runtime variable reload installs all three monitor settings");
	GloAdmin->save_pgsql_variables_from_runtime();
	ok(scalar(db,"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-monitor_lsn_history'") == "2000", "runtime export retains history retention setting");
	test_retention(db);
#else
	for (const auto* name : {"monitor_lsn_poll_interval","monitor_lsn_poll_timeout","monitor_lsn_history"})
		ok(variable(name) == "<missing>" && !set_setting(name,"1000"),"v3.0 omits %s",name);
#endif
	delete GloAdmin->admindb;
	delete GloAdmin->configdb;
	GloAdmin->admindb = nullptr;
	GloAdmin->configdb = nullptr;
	GloAdmin = nullptr;
	GloProxyStats = nullptr;
	statistics.reset();
	GloVars.statsdb_disk = previous_statsdb_path;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}
