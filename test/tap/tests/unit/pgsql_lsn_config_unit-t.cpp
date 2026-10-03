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
#include <memory>

extern PgSQL_Threads_Handler* GloPTH;
extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_Statistics* GloProxyStats;
class TestDiskUpgrade {
public:
	static void pgsql(ProxySQL_Admin& admin) { admin.disk_upgrade_pgsql_replication_hostgroups(); }
};
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
int main() {
	plan(NO_PLAN);
	test_init_minimal();
	test_init_query_processor();
	test_init_hostgroups();
	GloVars.statsdb_disk = const_cast<char*>(":memory:");
	GloProxyStats = new ProxySQL_Statistics();
	GloProxyStats->init();
	GloAdmin = new ProxySQL_Admin();
	GloAdmin->admindb = memory_db();
	GloAdmin->configdb = memory_db();
	auto& db = *GloAdmin->admindb;
	for (const auto* schema : {ADMIN_SQLITE_TABLE_PGSQL_SERVERS, ADMIN_SQLITE_TABLE_PGSQL_REPLICATION_HOSTGROUPS,
		ADMIN_SQLITE_TABLE_PGSQL_HOSTGROUP_ATTRIBUTES, ADMIN_SQLITE_TABLE_PGSQL_SERVERS_SSL_PARAMS,
		ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_SERVERS, ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_REPLICATION_HOSTGROUPS,
		ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_HOSTGROUP_ATTRIBUTES, ADMIN_SQLITE_TABLE_RUNTIME_PGSQL_SERVERS_SSL_PARAMS,
		ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES, ADMIN_SQLITE_RUNTIME_GLOBAL_VARIABLES}) db.execute(schema);
	const bool has_flag = db.execute("INSERT INTO pgsql_replication_hostgroups(writer_hostgroup,reader_hostgroup,lsn_causal_reads) VALUES(10,20,1)");
	ok(has_flag, "activation column accepts enabled pair");
	db.execute("INSERT INTO pgsql_replication_hostgroups(writer_hostgroup,reader_hostgroup) VALUES(30,40)");
	ok(scalar(db, "SELECT lsn_causal_reads FROM pgsql_replication_hostgroups WHERE writer_hostgroup=30") == "0", "protection defaults off");
	ok(!db.execute("UPDATE pgsql_replication_hostgroups SET lsn_causal_reads=2"), "activation rejects value two");
	ok(!db.execute("UPDATE pgsql_replication_hostgroups SET lsn_causal_reads=NULL"), "activation rejects NULL");
	ok(variable("lsn_poll_interval") == "10", "polling defaults to ten milliseconds");
	ok(variable("lsn_wait_timeout") == "100", "waiting defaults to one hundred milliseconds");
	for (const auto* name : {"lsn_poll_interval", "lsn_wait_timeout"}) {
		for (const auto* value : {"", "word", "10garbage", "99999999999999999999", "-1"})
			ok(!GloPTH->set_variable(const_cast<char*>(name), value), "reject %s=%s", name, value);
	}
	ok(!GloPTH->set_variable(const_cast<char*>("lsn_poll_interval"), "0"), "zero cannot disable polling");
	ok(!GloPTH->set_variable(const_cast<char*>("lsn_poll_interval"), "60001"), "poll limit enforced");
	ok(GloPTH->set_variable(const_cast<char*>("lsn_poll_interval"), "60000"), "poll upper boundary accepted");
	ok(GloPTH->set_variable(const_cast<char*>("lsn_poll_interval"), "1"), "poll lower boundary accepted");
	ok(GloPTH->set_variable(const_cast<char*>("lsn_wait_timeout"), "0"), "zero selects immediate writer fallback");
	ok(GloPTH->set_variable(const_cast<char*>("lsn_wait_timeout"), "600000"), "wait upper boundary accepted");
	ok(!GloPTH->set_variable(const_cast<char*>("lsn_wait_timeout"), "600001"), "wait limit enforced");
	ok(variable("lsn_wait_timeout") == "600000", "rejected setting preserves prior value");
	db.execute("INSERT INTO global_variables VALUES('pgsql-lsn_poll_interval','17'),('pgsql-lsn_wait_timeout','0')");
	auto flushed = GloAdmin->load_pgsql_variables_to_runtime();
	ok(flushed.rejected == 0 && variable("lsn_poll_interval") == "17" && variable("lsn_wait_timeout") == "0", "LOAD PGSQL VARIABLES installs LSN settings");
	GloAdmin->save_pgsql_variables_from_runtime();
	ok(scalar(db, "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-lsn_poll_interval'") == "17", "SAVE FROM RUNTIME preserves LSN setting");
	for (const auto* schema : {ADMIN_SQLITE_TABLE_PGSQL_REPLICATION_HOSTGROUPS_V3_0_1,
		ADMIN_SQLITE_TABLE_PGSQL_REPLICATION_HOSTGROUPS_V3_0_2}) {
		delete GloAdmin->configdb;
		GloAdmin->configdb = memory_db();
		auto& disk = *GloAdmin->configdb;
		disk.execute(schema);
		disk.execute("INSERT INTO pgsql_replication_hostgroups(writer_hostgroup,reader_hostgroup,comment) VALUES(10,20,'old ''comment'),(30,40,'second')");
		TestDiskUpgrade::pgsql(*GloAdmin);
		ok(scalar(disk, "SELECT SUM(lsn_causal_reads) FROM pgsql_replication_hostgroups") == "0", "legacy migration disables LSN protection");
		ok(scalar(disk, "SELECT COUNT(*) FROM pgsql_replication_hostgroups") == "2", "migration preserves both rows");
		ok(scalar(disk, "SELECT comment FROM pgsql_replication_hostgroups WHERE writer_hostgroup=10") == "old 'comment", "migration preserves quoted comment");
		ok(scalar(disk, "SELECT check_type FROM pgsql_replication_hostgroups WHERE writer_hostgroup=10") == "read_only", "migration preserves or supplies check_type");
		if (scalar(disk, "SELECT lsn_causal_reads FROM pgsql_replication_hostgroups LIMIT 1") != "<error>") {
			disk.execute("UPDATE pgsql_replication_hostgroups SET lsn_causal_reads=1 WHERE writer_hostgroup=10");
			TestDiskUpgrade::pgsql(*GloAdmin);
			ok(scalar(disk, "SELECT lsn_causal_reads FROM pgsql_replication_hostgroups WHERE writer_hostgroup=10") == "1", "repeated upgrade preserves explicit opt-in");
		}
	}
	if (has_flag) {
		ProxySQL_Config exporter(&db);
		std::string serialized;
		exporter.Write_PgSQL_Servers_to_configfile(serialized);
		ProxySQL_ConfigFile parsed;
		parsed.cfg.readString(serialized.c_str());
		auto* saved_config = GloVars.confFile;
		GloVars.confFile = &parsed;
		std::unique_ptr<SQLite3DB> imported(memory_db());
		for (const auto* schema : {ADMIN_SQLITE_TABLE_PGSQL_SERVERS, ADMIN_SQLITE_TABLE_PGSQL_REPLICATION_HOSTGROUPS,
			ADMIN_SQLITE_TABLE_PGSQL_HOSTGROUP_ATTRIBUTES, ADMIN_SQLITE_TABLE_PGSQL_SERVERS_SSL_PARAMS}) imported->execute(schema);
		ProxySQL_Config importer(imported.get());
		std::string error;
		ok(importer.Read_PgSQL_Servers_from_configfile(error) >= 0, "configuration roundtrip parses");
		ok(scalar(*imported, "SELECT lsn_causal_reads FROM pgsql_replication_hostgroups WHERE writer_hostgroup=10") == "1", "configuration roundtrip preserves opt-in");
		GloVars.confFile = saved_config;
		for (const auto* bad : {"2", "\"yes\""}) {
			ProxySQL_ConfigFile invalid;
			invalid.cfg.readString((std::string("pgsql_replication_hostgroups=({writer_hostgroup=60;reader_hostgroup=70;lsn_causal_reads=") + bad + ";});").c_str());
			GloVars.confFile = &invalid;
			error.clear();
			ok(importer.Read_PgSQL_Servers_from_configfile(error) < 0 && !error.empty(), "invalid config activation %s is rejected explicitly", bad);
			GloVars.confFile = saved_config;
		}
		std::unique_ptr<SQLite3_result> legacy(db.execute_statement("SELECT writer_hostgroup,reader_hostgroup,check_type,comment FROM pgsql_replication_hostgroups", nullptr));
		ok(!PgSQL_HostGroups_Manager::validate_lsn_replication_rows(legacy.get(), error), "legacy cluster projection cannot silently lose activation");
		db.execute("INSERT INTO pgsql_servers(hostgroup_id,hostname) VALUES(10,'writer'),(20,'reader')");
		GloAdmin->pgsql_servers_wrlock();
		bool loaded = GloAdmin->load_pgsql_servers_to_runtime_checked({}, {}, {}, false);
		GloAdmin->pgsql_servers_wrunlock();
		ok(loaded, "valid enabled mapping loads to runtime");
		ok(PgHGM->lsn_manager().group_for_hostgroup(20) == 10, "reader hostgroup maps to protected writer");
		ok(PgHGM->lsn_manager().snapshot(10).config.writers.size() == 1, "runtime topology supplies exact writer endpoint");
		std::unique_ptr<SQLite3_result> runtime(PgHGM->dump_table_pgsql("pgsql_replication_hostgroups"));
		ok(runtime && runtime->columns == 5 && runtime->rows_count == 2 && !strcmp(runtime->rows[0]->fields[4], "1"), "internal runtime retains opt-in column");
		GloAdmin->save_pgsql_servers_runtime_to_database(true);
		ok(scalar(db, "SELECT lsn_causal_reads FROM runtime_pgsql_replication_hostgroups WHERE writer_hostgroup=10") == "1", "runtime admin export retains opt-in");
		db.execute("INSERT INTO pgsql_replication_hostgroups(writer_hostgroup,reader_hostgroup,lsn_causal_reads) VALUES(20,50,1)");
		GloAdmin->pgsql_servers_wrlock();
		loaded = GloAdmin->load_pgsql_servers_to_runtime_checked({}, {}, {}, false);
		GloAdmin->pgsql_servers_wrunlock();
		ok(!loaded, "ambiguous protected mapping rejects LOAD atomically");
		runtime.reset(PgHGM->dump_table_pgsql("pgsql_replication_hostgroups"));
		ok(runtime && runtime->rows_count == 2, "rejected LOAD preserves prior runtime mappings");
	}
	return exit_status();
}
