/**
 * @file managed_engine_projection_txn_unit-t.cpp
 * @brief Regression test for #6464: the managed engine-variables projection
 *        must run as ONE SQLite transaction on admindb.
 *
 * ProxySQL_Admin::commit_managed_engine_variables_projection(pgsql=true) used
 * to wrap flush_pgsql_variables___runtime_to_database(..., use_lock=true) in
 * its own BEGIN/COMMIT, while the flusher opens and commits a transaction of
 * its own. The inner BEGIN failed ("cannot start a transaction within a
 * transaction"), the inner COMMIT ended the outer transaction early and the
 * outer COMMIT failed ("cannot commit - no transaction is active").
 *
 * The test traces every statement run on admindb and records any BEGIN that
 * starts while a transaction is already open and any COMMIT that runs with no
 * transaction open. Both engines must produce neither, leave the connection in
 * autocommit mode, and refresh the runtime projection + checksum.
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

#include <cstring>
#include <string>

extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_Statistics* GloProxyStats;
extern PgSQL_Threads_Handler* GloPTH;

namespace {

struct TxnTrace {
	sqlite3* db { nullptr };
	int begins { 0 };
	int nested_begins { 0 };
	int commits { 0 };
	int orphan_commits { 0 };
};

bool starts_with_ci(const char* sql, const char* word) {
	while (*sql == ' ' || *sql == '\t' || *sql == '\n') ++sql;
	return strncasecmp(sql, word, strlen(word)) == 0;
}

int trace_cb(unsigned type, void* ctx, void* p, void* x) {
	if (type != SQLITE_TRACE_STMT) return 0;
	auto* trace = static_cast<TxnTrace*>(ctx);
	const char* sql = static_cast<const char*>(x);
	(void)p;
	if (sql == nullptr) return 0;
	// SQLITE_TRACE_STMT fires before the statement runs, so autocommit still
	// reflects the transaction state the statement starts in.
	const bool in_txn = sqlite3_get_autocommit(trace->db) == 0;
	if (starts_with_ci(sql, "BEGIN")) {
		++trace->begins;
		if (in_txn) ++trace->nested_begins;
	} else if (starts_with_ci(sql, "COMMIT") || starts_with_ci(sql, "END")) {
		++trace->commits;
		if (!in_txn) ++trace->orphan_commits;
	}
	return 0;
}

int scalar_int(SQLite3DB& db, const char* sql) {
	sqlite3_stmt* stmt = nullptr;
	if (sqlite3_prepare_v2(db.get_db(), sql, -1, &stmt, nullptr) != SQLITE_OK) return -1;
	const int value = sqlite3_step(stmt) == SQLITE_ROW ? sqlite3_column_int(stmt, 0) : -1;
	sqlite3_finalize(stmt);
	return value;
}

void check_engine(bool pgsql) {
	const char* engine = pgsql ? "pgsql" : "mysql";
	SQLite3DB& db = *GloAdmin->admindb;
	TxnTrace trace;
	trace.db = db.get_db();
	sqlite3_trace_v2(trace.db, SQLITE_TRACE_STMT, &trace_cb, &trace);
	ProxySQL_Checksum_Value& checksum = pgsql ? GloVars.checksums_values.pgsql_variables
	                                          : GloVars.checksums_values.mysql_variables;
	const unsigned long long version_before = checksum.version;

	GloAdmin->commit_managed_engine_variables_projection(pgsql);

	sqlite3_trace_v2(trace.db, 0, nullptr, nullptr);

	ok(trace.nested_begins == 0,
	   "%s projection never starts a transaction inside another one (nested BEGIN=%d)",
	   engine, trace.nested_begins);
	ok(trace.orphan_commits == 0,
	   "%s projection never commits outside a transaction (orphan COMMIT=%d)",
	   engine, trace.orphan_commits);
	ok(trace.begins == 1 && trace.commits == 1,
	   "%s projection runs exactly one transaction (BEGIN=%d COMMIT=%d)",
	   engine, trace.begins, trace.commits);
	ok(sqlite3_get_autocommit(trace.db) != 0,
	   "%s projection leaves admindb in autocommit mode", engine);
	const std::string count_sql = std::string(
		"SELECT COUNT(*) FROM runtime_global_variables WHERE variable_name LIKE '") + engine + "-%'";
	ok(scalar_int(db, count_sql.c_str()) > 0,
	   "%s runtime_global_variables projection is populated", engine);
	ok(checksum.version > version_before && checksum.checksum[0] != '\0',
	   "%s variables checksum was recomputed", engine);
}

} // namespace

int main() {
	plan(12);
	test_init_minimal();
	// Creates GloMTH/GloPTH with their default variables.
	test_init_query_processor();

	GloVars.statsdb_disk = const_cast<char*>(":memory:");
	GloProxyStats = new ProxySQL_Statistics();
	GloAdmin = new ProxySQL_Admin();
	GloAdmin->admindb = new SQLite3DB();
	GloAdmin->admindb->open(const_cast<char*>(":memory:"),
		SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	GloAdmin->admindb->execute(ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES);
	GloAdmin->admindb->execute(ADMIN_SQLITE_RUNTIME_GLOBAL_VARIABLES);

	check_engine(true);
	check_engine(false);

	return exit_status();
}
