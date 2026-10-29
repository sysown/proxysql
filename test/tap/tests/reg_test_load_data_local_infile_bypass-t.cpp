/**
 * @file reg_test_load_data_local_infile_bypass-t.cpp
 * @brief Regression test for GHSA-crwq-rcqp-v8jr.
 *
 * @details With 'mysql-enable_load_data_local_infile=false' ProxySQL must never read a
 *   file from its own host on behalf of a client, whatever the statement spelling or the
 *   command used to send it:
 *   - Non-canonical spellings (extra whitespace, LOW_PRIORITY) must get the descriptive 1047 error.
 *   - COM_STMT_PREPARE of 'LOAD DATA LOCAL INFILE' must get the descriptive 1047 error.
 *   - Spellings that bypass the textual check (an empty executable comment) must be refused by the
 *     connector: no rows may be loaded.
 *   - A pooled backend connection that served an allowed LOAD DATA must refuse it once the
 *     variable is switched back to 'false'.
 */

#include <cstdlib>
#include <cstring>
#include <string>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

namespace {

const char* TABLE = "test.reg_ldli_bypass";

bool run(MYSQL* mysql, const std::string& q) {
	if (mysql_query(mysql, q.c_str())) {
		diag("Query '%s' failed: (%d) %s", q.c_str(), mysql_errno(mysql), mysql_error(mysql));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(mysql);
	if (res) mysql_free_result(res);
	return true;
}

bool set_local_infile(MYSQL* admin, bool enabled) {
	std::string q = std::string("SET mysql-enable_load_data_local_infile='") + (enabled ? "true" : "false") + "'";
	return run(admin, q) && run(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
}

long row_count(MYSQL* mysql) {
	std::string q = std::string("SELECT COUNT(*) /* ;hostgroup=0 */ FROM ") + TABLE;
	if (mysql_query(mysql, q.c_str())) {
		diag("Count failed: %s", mysql_error(mysql));
		return -1;
	}
	MYSQL_RES* res = mysql_store_result(mysql);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
	long n = (row && row[0]) ? atol(row[0]) : -1;
	if (res) mysql_free_result(res);
	return n;
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(9);

	// Data file on the shared volume: '/var/lib/proxysql' here, REGULAR_INFRA_DATADIR inside ProxySQL.
	const std::string dir = "/var/lib/proxysql/reg_ldli_bypass";
	const std::string cmd = "mkdir -p " + dir + " && printf '1,a\\n2,b\\n3,c\\n' > " + dir + "/data.txt && chmod -R 777 " + dir;
	if (system(cmd.c_str()) != 0) {
		diag("Failed to provision data file with '%s'", cmd.c_str());
	}
	const char* d_env = getenv("REGULAR_INFRA_DATADIR");
	const std::string datafile = (d_env ? std::string(d_env) : std::string(cl.workdir)) + "/reg_ldli_bypass/data.txt";
	diag("Data file path (ProxySQL side): %s", datafile.c_str());

	MYSQL* admin = mysql_init(nullptr);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
		diag("Admin connection failed: %s", mysql_error(admin));
		return exit_status();
	}
	MYSQL* proxy = mysql_init(nullptr);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
		diag("Frontend connection failed: %s", mysql_error(proxy));
		return exit_status();
	}

	const std::string load_tail = " '" + datafile + "' INTO TABLE " + TABLE +
		" FIELDS TERMINATED BY ',' LINES TERMINATED BY '\\n' (id, s)";
	const std::string canonical = "LOAD DATA LOCAL INFILE" + load_tail;
	// Executed by the backend and armed by the connector (starts with 'load'), but invisible
	// to ProxySQL's textual check: only the connector-level policy can refuse it.
	const std::string bypass = "LOAD DATA /*!*/ LOCAL INFILE" + load_tail;

	bool prep = run(proxy, "CREATE DATABASE IF NOT EXISTS test")
		&& run(proxy, std::string("DROP TABLE IF EXISTS ") + TABLE)
		&& run(proxy, std::string("CREATE TABLE ") + TABLE + " (id INT, s VARCHAR(16))");

	// 1. Baseline: when enabled, the feature works, proving the backend accepts LOCAL INFILE
	//    (otherwise the negative checks below would pass vacuously).
	set_local_infile(admin, true);
	int rc = mysql_query(proxy, canonical.c_str());
	ok(prep && rc == 0 && row_count(proxy) == 3,
		"Enabled: canonical LOAD DATA LOCAL INFILE loads the file. rc=%d err='%s'", rc, mysql_error(proxy));

	// 2. Disabled: every variant must be refused and no rows loaded.
	set_local_infile(admin, false);
	run(proxy, std::string("TRUNCATE TABLE ") + TABLE);

	rc = mysql_query(proxy, ("LOAD  DATA\tLOCAL\n INFILE" + load_tail).c_str());
	ok(rc != 0 && mysql_errno(proxy) == 1047,
		"Disabled: extra-whitespace spelling gets 1047. errno=%d err='%s'", mysql_errno(proxy), mysql_error(proxy));

	rc = mysql_query(proxy, ("load data low_priority local infile" + load_tail).c_str());
	ok(rc != 0 && mysql_errno(proxy) == 1047,
		"Disabled: LOW_PRIORITY spelling gets 1047. errno=%d err='%s'", mysql_errno(proxy), mysql_error(proxy));

	MYSQL_STMT* stmt = mysql_stmt_init(proxy);
	rc = mysql_stmt_prepare(stmt, canonical.c_str(), canonical.size());
	ok(rc != 0 && mysql_stmt_errno(stmt) == 1047,
		"Disabled: COM_STMT_PREPARE gets 1047. errno=%d err='%s'", mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
	mysql_stmt_close(stmt);

	rc = mysql_query(proxy, bypass.c_str());
	ok(rc != 0, "Disabled: text-check bypass spelling fails. errno=%d err='%s'", mysql_errno(proxy), mysql_error(proxy));

	ok(row_count(proxy) == 0, "Disabled: no rows were loaded from the ProxySQL host");

	ok(run(proxy, "SELECT 1"), "Frontend connection is still usable after the refused requests");

	// 3. Toggle back on and off: pooled backend connections must follow the runtime value.
	set_local_infile(admin, true);
	rc = mysql_query(proxy, bypass.c_str());
	ok(rc == 0 && row_count(proxy) == 3,
		"Re-enabled: text-check bypass spelling loads the file. rc=%d err='%s'", rc, mysql_error(proxy));

	set_local_infile(admin, false);
	run(proxy, std::string("TRUNCATE TABLE ") + TABLE);
	mysql_query(proxy, bypass.c_str());
	ok(row_count(proxy) == 0, "Disabled again: pooled connection refuses the file request");

	run(proxy, std::string("DROP TABLE IF EXISTS ") + TABLE);
	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
