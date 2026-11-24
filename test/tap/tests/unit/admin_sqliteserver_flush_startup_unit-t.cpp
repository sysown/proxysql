/**
 * @file admin_sqliteserver_flush_startup_unit-t.cpp
 * @brief Regression test for #6720: Admin must not touch the SQLite3 server before it exists.
 *
 * @details Admin accepts queries before main.cpp phase 3 creates 'GloSQLite3Server'. A query on
 *   'global_variables' refreshes the runtime variables of every module, and
 *   'flush_sqliteserver_variables___runtime_to_database()' called 'GloSQLite3Server->wrlock()'
 *   without checking for NULL, so ProxySQL started with '--sqlite3-server' crashed when an Admin
 *   client was fast enough. The flush is private; 'save_sqliteserver_variables_from_runtime()'
 *   ('SAVE SQLITESERVER VARIABLES FROM RUNTIME') reaches it the same way.
 *
 *   With '--sqlite3-server' enabled and no SQLite3 server created yet, the save must return
 *   without crashing and leave 'global_variables' unchanged. The SQLite3 server itself lives in
 *   src/, outside libproxysql.a, so the case with the server running is covered by the TAP suite.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_admin.h"
#include "ProxySQL_Statistics.hpp"
#include "ProxySQL_Admin_Tables_Definitions.h"
#include "sqlite3db.h"
#include "SQLite3_Server.h"

extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_Statistics* GloProxyStats;
extern SQLite3_Server* GloSQLite3Server;

static int count_rows(SQLite3DB& db, const char* sql) {
	sqlite3_stmt* statement = nullptr;
	if (sqlite3_prepare_v2(db.get_db(), sql, -1, &statement, nullptr) != SQLITE_OK) return -1;
	const int result = sqlite3_step(statement) == SQLITE_ROW ? sqlite3_column_int(statement, 0) : -1;
	sqlite3_finalize(statement);
	return result;
}

int main() {
	plan(3);
	test_init_minimal();
	GloVars.statsdb_disk = const_cast<char*>(":memory:");
	// Real, process-scoped Admin as in the other Admin unit fixtures. Its destructor requires
	// the full daemon lifecycle, so it is not deleted.
	GloProxyStats = new ProxySQL_Statistics();
	GloAdmin = new ProxySQL_Admin();
	GloAdmin->admindb = new SQLite3DB();
	GloAdmin->admindb->open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	GloAdmin->admindb->execute(ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
	GloAdmin->admindb->execute(ADMIN_SQLITE_RUNTIME_GLOBAL_VARIABLES);
	GloAdmin->admindb->execute("INSERT INTO global_variables VALUES ('sqliteserver-mysql_ifaces', '127.0.0.1:6030')");

	// Started with '--sqlite3-server', still before ProxySQL_Main_init_SQLite3Server().
	GloVars.global.sqlite3_server = true;
	GloSQLite3Server = nullptr;
	ok(GloSQLite3Server == nullptr, "the SQLite3 server is enabled but not created yet");

	GloAdmin->save_sqliteserver_variables_from_runtime();
	ok(true, "saving the SQLite3 server variables before the server exists does not crash");
	ok(count_rows(*GloAdmin->admindb, "SELECT COUNT(*) FROM global_variables WHERE variable_name='sqliteserver-mysql_ifaces' AND variable_value='127.0.0.1:6030'") == 1,
		"the save leaves global_variables unchanged until the server exists");

	return exit_status();
}
