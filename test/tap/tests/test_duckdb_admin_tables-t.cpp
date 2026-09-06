// Full ProxySQL integration coverage for DuckDB's standard scalar-variable
// path. This talks to the real Admin and DuckDB MySQL listeners.

#include <cstdlib>
#include <string>

#include "mysql.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

namespace {

MYSQL* admin = nullptr;

bool execute(MYSQL* connection, const std::string& sql) {
	if (mysql_query(connection, sql.c_str()) != 0) return false;
	if (MYSQL_RES* result = mysql_store_result(connection)) mysql_free_result(result);
	return true;
}

std::string cell(MYSQL* connection, const std::string& sql) {
	if (mysql_query(connection, sql.c_str()) != 0) return {};
	MYSQL_RES* result = mysql_store_result(connection);
	if (result == nullptr) return {};
	MYSQL_ROW row = mysql_fetch_row(result);
	const std::string value = row != nullptr && row[0] != nullptr ? row[0] : "";
	mysql_free_result(result);
	return value;
}

MYSQL* connect_duckdb(const CommandLine& cl) {
	MYSQL* connection = mysql_init(nullptr);
	if (connection == nullptr) return nullptr;
	if (!mysql_real_connect(connection, cl.host, cl.username, cl.password,
	                        nullptr, 6031, nullptr, 0)) {
		mysql_close(connection);
		return nullptr;
	}
	return connection;
}

} // namespace

int main() {
	CommandLine cl;
	if (cl.getEnv()) return -1;
	plan(21);

	admin = init_mysql_conn(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	ok(admin != nullptr, "Admin connection established");
	if (admin == nullptr) BAIL_OUT("cannot continue without Admin");

	ok(cell(admin,
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN "
		"('duckdb_variables','runtime_duckdb_variables')") == "0",
	   "dedicated DuckDB scalar-variable tables do not exist");
	ok(cell(admin,
		"SELECT COUNT(*) FROM global_variables WHERE variable_name LIKE 'duckdb-%'") == "8",
	   "Main exposes eight duckdb-prefixed variables");
	ok(cell(admin,
		"SELECT COUNT(*) FROM runtime_global_variables WHERE variable_name LIKE 'duckdb-%'") == "8",
	   "Runtime exposes eight effective duckdb-prefixed variables");

	MYSQL* first = connect_duckdb(cl);
	MYSQL* second = connect_duckdb(cl);
	ok(first != nullptr && second != nullptr, "two DuckDB plugin connections remain open");
	if (first == nullptr || second == nullptr) BAIL_OUT("DuckDB connections required");

	const std::string before = cell(second, "SELECT current_setting('threads')");
	const std::string desired = before == "6" ? "5" : "6";
	ok(execute(admin, "UPDATE global_variables SET variable_value='" + desired +
	                  "' WHERE variable_name='duckdb-threads'") &&
	   cell(admin, "SELECT variable_value FROM runtime_global_variables "
	               "WHERE variable_name='duckdb-threads'") == before,
	   "an edit in Main does not alter effective Runtime before LOAD");

	ok(execute(admin,
		"UPDATE global_variables SET variable_value='512MB' "
		"WHERE variable_name='duckdb-memory_limit'") &&
	   execute(admin, "LOAD DUCKDB VARIABLES TO RUNTIME"),
	   "LOAD accepts valid live thread and memory changes");
	ok(cell(first, "SELECT current_setting('threads')") == desired &&
	   cell(second, "SELECT current_setting('threads')") == desired,
	   "thread change is visible through both existing plugin connections");
	ok(cell(first, "SELECT current_setting('memory_limit')") == "488.2 MiB" &&
	   cell(admin, "SELECT variable_value FROM runtime_global_variables "
	               "WHERE variable_name='duckdb-memory_limit'") == "488.2 MiB",
	   "Runtime agrees with canonical engine memory readback");

	ok(execute(admin, "UPDATE global_variables SET variable_value='2' "
	                  "WHERE variable_name='duckdb-max_connections'") &&
	   execute(admin, "LOAD DUCKDB VARIABLES TO RUNTIME") &&
	   cell(first, "SELECT 42") == "42" && cell(second, "SELECT 43") == "43",
	   "lowering the live connection limit preserves existing sessions");
	MYSQL* rejected = connect_duckdb(cl);
	ok(rejected == nullptr, "the lowered connection limit rejects a new session");
	if (rejected != nullptr) mysql_close(rejected);
	ok(execute(admin, "UPDATE global_variables SET variable_value='3' "
	                  "WHERE variable_name='duckdb-max_connections'") &&
	   execute(admin, "LOAD DUCKDB VARIABLES TO RUNTIME") &&
	   (rejected = connect_duckdb(cl)) != nullptr,
	   "raising the live connection limit admits a new session");
	if (rejected != nullptr) mysql_close(rejected);

	ok(execute(admin, "UPDATE global_variables SET variable_value='7' "
	                  "WHERE variable_name='duckdb-threads'") &&
	   execute(admin, "UPDATE global_variables SET variable_value='bad-limit' "
	                  "WHERE variable_name='duckdb-memory_limit'") &&
	   !execute(admin, "LOAD DUCKDB VARIABLES TO RUNTIME"),
	   "a mixed invalid LOAD returns an Admin error");
	ok(cell(second, "SELECT current_setting('threads')") == desired &&
	   cell(admin, "SELECT variable_value FROM runtime_global_variables "
	               "WHERE variable_name='duckdb-threads'") == desired,
	   "mixed invalid LOAD applies nothing and Runtime remains truthful");

	execute(admin, "UPDATE global_variables SET variable_value='512MB' "
	               "WHERE variable_name='duckdb-memory_limit'");
	execute(admin, "UPDATE global_variables SET variable_value='" + desired +
	               "' WHERE variable_name='duckdb-threads'");
	ok(execute(first, "SET threads=3") &&
	   cell(second, "SELECT current_setting('threads')") == "3",
	   "direct managed SET uses global engine control and reaches an existing connection");
	ok(cell(admin, "SELECT variable_value FROM runtime_global_variables "
	               "WHERE variable_name='duckdb-threads'") == "3",
	   "Runtime refresh observes a permitted direct client SET");

	ok(execute(admin, "UPDATE global_variables SET variable_value='/tmp/not-opened.db' "
	                  "WHERE variable_name='duckdb-database_path'") &&
	   !execute(admin, "LOAD DUCKDB VARIABLES TO RUNTIME"),
	   "changed database path is rejected while the database is open");
	ok(cell(admin, "SELECT variable_value FROM global_variables "
	               "WHERE variable_name='duckdb-database_path'") == "/tmp/not-opened.db" &&
	   cell(admin, "SELECT variable_value FROM runtime_global_variables "
	               "WHERE variable_name='duckdb-database_path'") == ":memory:",
	   "rejected path remains pending in Main without falsifying Runtime");

	ok(execute(admin, "SAVE DUCKDB VARIABLES TO MEMORY") &&
	   cell(admin, "SELECT variable_value FROM global_variables "
	               "WHERE variable_name='duckdb-database_path'") == ":memory:" &&
	   cell(admin, "SELECT variable_value FROM global_variables "
	               "WHERE variable_name='duckdb-threads'") == "3",
	   "SAVE FROM RUNTIME replaces pending Main with effective values");
	ok(execute(admin, "SAVE DUCKDB VARIABLES FROM MEMORY TO DISK") &&
	   cell(admin, "SELECT COUNT(*) FROM disk.global_variables "
	               "WHERE variable_name LIKE 'duckdb-%'") == "8",
	   "Disk alias persists only the complete duckdb-prefixed slice");
	ok(execute(admin, "UPDATE disk.global_variables SET variable_value='5' "
	                  "WHERE variable_name='duckdb-threads'") &&
	   execute(admin, "LOAD DUCKDB VARIABLES FROM DISK") &&
	   cell(admin, "SELECT variable_value FROM global_variables "
	               "WHERE variable_name='duckdb-threads'") == "5" &&
	   cell(admin, "SELECT variable_value FROM runtime_global_variables "
	               "WHERE variable_name='duckdb-threads'") == "3",
	   "LOAD FROM DISK follows standard Disk-to-Main separation without applying Runtime");

	mysql_close(second);
	mysql_close(first);
	mysql_close(admin);
	return exit_status();
}
