/**
 * @file pgsql-reg_test_6564_quoted_client_encoding-t.cpp
 * @brief Regression #6564: a quoted client_encoding value broke the SET sent to a pooled
 *        backend connection.
 *
 * asyncpg sends client_encoding='utf-8' at login, quotes included. PostgreSQL accepts it,
 * because its encoding-name lookup skips everything that is not a letter or a digit, and
 * stores UTF8. ProxySQL stored the client's text, 'UTF-8' with the quotes, so the
 * SET client_encoding it sent to bring a pooled backend connection in line failed with
 * 42601, and the client's statement failed with it. ProxySQL now stores the standard name,
 * as PostgreSQL does, and keeps exactly "UNICODE" as written, as PostgreSQL also does.
 *
 * Each case first leaves a backend connection with another encoding in the pool, so the
 * connection the client gets usually needs its client_encoding changed. The values use single
 * quotes, which are what broke that SET; double quotes still made a valid one. Each case also
 * spells the encoding its own way: before the fix, a connection left by an earlier case could
 * already carry the same text, need no SET, and hide the bug.
 */

#include <cstdlib>
#include <memory>
#include <sstream>
#include <string>
#include <unistd.h>

#include "libpq-fe.h"
#include "mysql.h"
#include "command_line.h"
#include "tap.h"

CommandLine cl;

using PGConn = std::unique_ptr<PGconn, decltype(&PQfinish)>;
using PGResult = std::unique_ptr<PGresult, decltype(&PQclear)>;

static PGConn connect_proxy(const std::string& extra) {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port << " user=" << cl.pgsql_username
	   << " password=" << cl.pgsql_password << " sslmode=disable connect_timeout=10 " << extra;
	PGConn conn(PQconnectdb(ss.str().c_str()), &PQfinish);
	if (PQstatus(conn.get()) != CONNECTION_OK) {
		diag("Connection with '%s' failed: %s", extra.c_str(), PQerrorMessage(conn.get()));
		conn.reset();
	}
	return conn;
}

static bool exec_ok(PGconn* conn, const char* sql) {
	if (!conn) return false;
	PGResult res(PQexec(conn, sql), &PQclear);
	const ExecStatusType st = PQresultStatus(res.get());
	if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
		diag("'%s' failed: %s", sql, PQerrorMessage(conn));
		return false;
	}
	return true;
}

// Parse/Bind/Execute/Sync instead of a simple Query.
static bool exec_params_ok(PGconn* conn) {
	if (!conn) return false;
	const char* values[1] = { "x" };
	PGResult res(PQexecParams(conn, "SELECT $1::text", 1, nullptr, values, nullptr, nullptr, 0), &PQclear);
	if (PQresultStatus(res.get()) != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
		diag("Extended query failed: %s", PQerrorMessage(conn));
		return false;
	}
	return std::string(PQgetvalue(res.get(), 0, 0)) == "x";
}

// Answered by the backend, after ProxySQL brought the connection in line.
static std::string shown_encoding(PGconn* conn) {
	if (!conn) return "";
	PGResult res(PQexec(conn, "SHOW client_encoding"), &PQclear);
	if (PQresultStatus(res.get()) != PGRES_TUPLES_OK || PQntuples(res.get()) != 1) {
		diag("SHOW client_encoding failed: %s", PQerrorMessage(conn));
		return "";
	}
	return PQgetvalue(res.get(), 0, 0);
}

// The value of the last ParameterStatus for client_encoding the client received.
static std::string reported_encoding(PGconn* conn) {
	const char* v = conn ? PQparameterStatus(conn, "client_encoding") : nullptr;
	return v ? v : "";
}

static void leave_pooled_connection(const char* encoding) {
	PGConn conn = connect_proxy(std::string("client_encoding=") + encoding);
	exec_ok(conn.get(), "SELECT 1");
}

static bool admin_exec(MYSQL* admin, const std::string& sql) {
	if (mysql_query(admin, sql.c_str())) {
		diag("Admin query failed: %s; SQL: %s", mysql_error(admin), sql.c_str());
		return false;
	}
	return true;
}

static std::string admin_value(MYSQL* admin, const std::string& sql) {
	std::string ret;
	if (!admin_exec(admin, sql)) return ret;
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
	if (row && row[0]) ret = row[0];
	mysql_free_result(res);
	return ret;
}

static void check_login_quoted() {
	leave_pooled_connection("LATIN1");
	PGConn conn = connect_proxy("client_encoding='\\'utf-8\\''");
	ok(exec_ok(conn.get(), "SELECT 1"),
		"Login with client_encoding='utf-8': a query on a pooled connection succeeds");
	const std::string shown = shown_encoding(conn.get());
	ok(shown == "UTF8", "Login with client_encoding='utf-8': SHOW client_encoding is UTF8 (got '%s')",
		shown.c_str());
	const std::string reported = reported_encoding(conn.get());
	ok(reported == "UTF8", "Login with client_encoding='utf-8': reported to the client as UTF8 (got '%s')",
		reported.c_str());
}

static void check_login_quoted_extended() {
	leave_pooled_connection("LATIN1");
	PGConn conn = connect_proxy("client_encoding='\\'utf8\\''");
	ok(exec_params_ok(conn.get()),
		"Login with client_encoding='utf8': an extended query on a pooled connection succeeds");
}

// Only exactly "UNICODE" is kept as written; a quoted 'unicode' is stored as UTF8.
static void check_options_quoted() {
	leave_pooled_connection("LATIN1");
	PGConn conn = connect_proxy("options='-c client_encoding=\\'unicode\\''");
	ok(exec_ok(conn.get(), "SELECT 1"),
		"options -c client_encoding='unicode': a query on a pooled connection succeeds");
	const std::string reported = reported_encoding(conn.get());
	ok(reported == "UTF8", "options -c client_encoding='unicode': reported to the client as UTF8 (got '%s')",
		reported.c_str());
}

static void check_set_alias() {
	PGConn conn = connect_proxy("client_encoding=LATIN1");
	const bool set_ok = exec_ok(conn.get(), "SET client_encoding = 'utf-8'");
	const std::string reported = reported_encoding(conn.get());
	ok(set_ok && reported == "UTF8", "SET client_encoding = 'utf-8': reported to the client as UTF8 (got '%s')",
		reported.c_str());
	ok(exec_ok(conn.get(), "SELECT 1"), "SET client_encoding = 'utf-8': the next query succeeds");
}

// DEFAULT goes back to the login value, so it must be stored in a form that can be sent.
static void check_default_after_quoted_login() {
	leave_pooled_connection("LATIN1");
	PGConn conn = connect_proxy("client_encoding='\\'utf_8\\''");
	const bool moved = exec_ok(conn.get(), "SET client_encoding = 'LATIN1'") && exec_ok(conn.get(), "SELECT 1")
		&& exec_ok(conn.get(), "SET client_encoding TO DEFAULT");
	ok(moved && exec_ok(conn.get(), "SELECT 1"),
		"Login with client_encoding='utf_8', SET LATIN1, SET TO DEFAULT: the next query succeeds");
	const std::string shown = shown_encoding(conn.get());
	ok(shown == "UTF8", "Login with client_encoding='utf_8', SET TO DEFAULT: SHOW client_encoding is UTF8 (got '%s')",
		shown.c_str());
}

static void check_unicode_kept() {
	PGConn conn = connect_proxy("client_encoding=LATIN1");
	const bool set_ok = exec_ok(conn.get(), "SET client_encoding = 'UNICODE'");
	const std::string reported = reported_encoding(conn.get());
	ok(set_ok && reported == "UNICODE", "SET client_encoding = 'UNICODE': reported as UNICODE (got '%s')",
		reported.c_str());
	const std::string shown = shown_encoding(conn.get());
	ok(shown == "UNICODE", "SET client_encoding = 'UNICODE': SHOW client_encoding is UNICODE (got '%s')",
		shown.c_str());
}

// A client that sends no client_encoding gets pgsql-default_client_encoding.
static void check_quoted_default_variable(MYSQL* admin) {
	const std::string original = admin_value(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-default_client_encoding'");
	if (original.empty()) {
		BAIL_OUT("Could not read pgsql-default_client_encoding");
	}

	admin_exec(admin, "UPDATE global_variables SET variable_value='''latin1''' "
		"WHERE variable_name='pgsql-default_client_encoding'");
	admin_exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	const std::string runtime = admin_value(admin,
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-default_client_encoding'");
	ok(runtime == "LATIN1", "pgsql-default_client_encoding='latin1': runtime value is LATIN1 (got '%s')",
		runtime.c_str());

	leave_pooled_connection("UTF8");
	{
		PGConn conn = connect_proxy("");
		ok(exec_ok(conn.get(), "SELECT 1"),
			"pgsql-default_client_encoding='latin1': a query from a client that sends no encoding succeeds");
		const std::string reported = reported_encoding(conn.get());
		ok(reported == "LATIN1",
			"pgsql-default_client_encoding='latin1': reported to the client as LATIN1 (got '%s')", reported.c_str());
	}

	admin_exec(admin, "UPDATE global_variables SET variable_value='" + original +
		"' WHERE variable_name='pgsql-default_client_encoding'");
	admin_exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

int main() {
	if (cl.getEnv()) return exit_status();

	plan(15);
	alarm(120);

	// libpq would send this as client_encoding; every case chooses its own value.
	unsetenv("PGCLIENTENCODING");

	MYSQL* admin = mysql_init(nullptr);
	if (!admin || !mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password,
		nullptr, cl.admin_port, nullptr, 0)) {
		BAIL_OUT("Admin connection failed: %s", admin ? mysql_error(admin) : "mysql_init failed");
	}

	check_login_quoted();
	check_login_quoted_extended();
	check_options_quoted();
	check_set_alias();
	check_default_after_quoted_login();
	check_unicode_kept();
	check_quoted_default_variable(admin);

	mysql_close(admin);
	return exit_status();
}
