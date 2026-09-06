#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

const int DUCKDB_MYSQL_PORT = 6031;

MYSQL* connect_duckdb(CommandLine& cl, const char* user, const char* pass) {
	MYSQL* c = mysql_init(NULL);
	if (c == NULL) return NULL;
	if (!mysql_real_connect(c, cl.host, user, pass, NULL, DUCKDB_MYSQL_PORT, NULL, 0)) {
		mysql_close(c);
		return NULL;
	}
	return c;
}

// Runs `q` and returns the single cell of the single row, or "" on failure.
std::string one_cell(MYSQL* c, const char* q) {
	if (mysql_query(c, q) != 0) return "";
	MYSQL_RES* r = mysql_store_result(c);
	if (r == NULL) return "";
	std::string out;
	if (MYSQL_ROW row = mysql_fetch_row(r)) if (row[0]) out = row[0];
	mysql_free_result(r);
	return out;
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) { diag("Failed to get the required environment variables"); return -1; }

	plan(17);

	MYSQL* c = connect_duckdb(cl, cl.username, cl.password);
	ok(c != NULL, "connect to the DuckDB MySQL port with mysql_users credentials");
	if (c == NULL) BAIL_OUT("cannot continue without a connection");

	ok(one_cell(c, "SELECT 42 AS answer") == "42", "integer literal round-trips");
	ok(one_cell(c, "SELECT 'hello' AS s") == "hello", "string literal round-trips");
	ok(one_cell(c, "SELECT CAST(1.5 AS DOUBLE) AS d") == "1.5", "double round-trips");

	// NULL must arrive as a real NULL, not the string "NULL".
	{
		ok(mysql_query(c, "SELECT NULL AS n") == 0, "NULL select executes");
		MYSQL_RES* r = mysql_store_result(c);
		MYSQL_ROW row = r ? mysql_fetch_row(r) : NULL;
		ok(r != NULL && row != NULL && row[0] == NULL, "NULL arrives as a null field");
		if (r) mysql_free_result(r);
	}

	// DDL + DML must report affected rows.
	//
	// CREATE OR REPLACE TABLE, not a bare CREATE TABLE: the plugin's
	// default database_path is ":memory:" (duckdb_config.cpp), so this
	// database lives for the whole ProxySQL process, shared across every
	// test invocation against the same container -- a bare CREATE TABLE
	// would fail with "table already exists" on any run after the first
	// against a warm container. OR REPLACE makes this test runnable
	// twice in a row without recreating the container, and since it
	// fully replaces (empties) the table, the INSERT below always sees
	// an empty table and its affected-rows count stays correct
	// regardless of how many times this test has already run.
	ok(mysql_query(c, "CREATE OR REPLACE TABLE t_e2e(a INTEGER)") == 0, "CREATE TABLE succeeds");
	ok(mysql_query(c, "INSERT INTO t_e2e VALUES (1),(2),(3)") == 0 &&
	   mysql_affected_rows(c) == 3, "INSERT reports three affected rows");

	// A syntax error must come back as an error, not a silent empty set.
	ok(mysql_query(c, "SELECT FROM WHERE") != 0 && mysql_errno(c) != 0,
	   "a malformed query returns a protocol error");

	ok(one_cell(c, "SELECT DATABASE()") == "memory",
	   "SELECT DATABASE() reports memory for the default in-memory engine");

	ok(mysql_query(c, "SELECT gen_random_uuid()") == 0, "UUID rewrap succeeds on the wire");
	{
		MYSQL_RES* r = mysql_store_result(c);
		MYSQL_ROW row = r ? mysql_fetch_row(r) : NULL;
		ok(r != NULL && row != NULL && row[0] != NULL && std::strlen(row[0]) == 36,
		   "UUID arrives as text, not NULL");
		if (r) mysql_free_result(r);
	}

	ok(mysql_query(c, "SELECT 1; SELECT 2") != 0, "multi-statement is rejected");

	bool errors_ok = true;
	for (int i = 0; i < 20; i++) {
		if (mysql_query(c, "SELECT FROM WHERE") == 0) errors_ok = false;
	}
	ok(errors_ok, "repeated syntax errors do not abort the connection");
	ok(mysql_query(c, "SELECT 1") == 0, "connection still works after repeated errors");

	mysql_close(c);

	// Oracle MySQL 8 negotiates CLIENT_DEPRECATE_EOF, unlike the bundled
	// MariaDB Connector/C used above. Exercise the real client so result-set
	// terminator framing is covered, not merely query success.
	const std::string port = std::to_string(DUCKDB_MYSQL_PORT);
	const std::string user = std::string("-u") + cl.username;
	const std::string password = std::string("-p") + cl.password;
	const std::vector<const char*> mysql8_args = {
		"mysql", "--protocol=TCP", "-h", cl.host, "-P", port.c_str(),
		user.c_str(), password.c_str(), "--batch", "--skip-column-names",
		"--execute=SELECT 42 AS answer"
	};
	std::string mysql8_output;
	const int mysql8_rc = execvp("mysql", mysql8_args, mysql8_output);
	ok(mysql8_rc == 0 && mysql8_output == "42\n",
	   "MySQL 8 CLIENT_DEPRECATE_EOF client receives result rows");

	// Authentication must actually be enforced.
	MYSQL* bad = connect_duckdb(cl, cl.username, "definitely-not-the-password");
	ok(bad == NULL, "a wrong password is rejected");
	if (bad) mysql_close(bad);

	return exit_status();
}
