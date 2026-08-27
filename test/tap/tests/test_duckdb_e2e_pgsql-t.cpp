#include "libpq-fe.h"
#include "tap.h"
#include "command_line.h"

#include <cstring>
#include <string>

namespace {

// The plugin's default pgsql_ifaces (plugins/duckdb/src/duckdb_config.cpp,
// kDefaultPgsqlIfaces) is 6034, deliberately off of ProxySQL's own Admin
// port (6032, see etc/proxysql.cnf and this group's proxysql-ci.cnf) --
// the listener binds with SO_REUSEPORT (duckdb_listener.cpp), so a wrong
// port here would silently split connections between Admin and the plugin
// instead of failing outright.
const char* DUCKDB_PGSQL_PORT = "6034";

PGconn* connect_duckdb(CommandLine& cl, const char* user, const char* pass) {
	std::string conninfo = "host=" + std::string(cl.host) +
		" port=" + DUCKDB_PGSQL_PORT +
		" user=" + user + " password=" + pass +
		" dbname=main connect_timeout=10";
	PGconn* c = PQconnectdb(conninfo.c_str());
	if (PQstatus(c) != CONNECTION_OK) { PQfinish(c); return NULL; }
	return c;
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) { diag("Failed to get the required environment variables"); return -1; }

	plan(8);

	PGconn* c = connect_duckdb(cl, cl.pgsql_username, cl.pgsql_password);
	ok(c != NULL, "connect to the DuckDB PgSQL port with pgsql_users credentials");
	if (c == NULL) BAIL_OUT("cannot continue without a connection");

	{
		PGresult* r = PQexec(c, "SELECT 42 AS answer");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
		   std::strcmp(PQgetvalue(r, 0, 0), "42") == 0, "integer literal round-trips");
		ok(PQnfields(r) == 1 && std::strcmp(PQfname(r, 0), "answer") == 0,
		   "the column name is preserved");
		PQclear(r);
	}

	{
		PGresult* r = PQexec(c, "SELECT NULL AS n");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQgetisnull(r, 0, 0) == 1,
		   "NULL arrives as a real SQL NULL");
		PQclear(r);
	}

	{
		// CommandComplete tag: SQLite3_to_Postgres derives it from the
		// first whitespace-delimited word of whatever string it is
		// handed. "SHOW TABLES" is the discriminator that actually
		// proves which string that is: duckdb_classify_query() (in
		// duckdb_session.cpp) intercepts it and *rewrites* `effective`
		// to "SELECT table_name FROM information_schema.tables ...",
		// while the ORIGINAL `sql` -- "SHOW TABLES" -- is what
		// duckdb_send_result() must pass to SQLite3_to_Postgres(). A
		// plain "SELECT ..." query can't distinguish the two, because
		// for such a query `effective == sql` byte-for-byte and the
		// tag would read "SELECT" regardless of which one was passed.
		// If the rewritten form ever leaked through instead, this tag
		// would read "SELECT", not "SHOW".
		PGresult* r = PQexec(c, "SHOW TABLES");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK &&
		   std::strncmp(PQcmdStatus(r), "SHOW", 4) == 0,
		   "the CommandComplete tag says SHOW (the original sql, not the rewritten effective query)");
		PQclear(r);
	}

	{
		// CREATE OR REPLACE TABLE, not a bare CREATE TABLE: the plugin's
		// default database_path is ":memory:" (duckdb_config.cpp), so
		// this database lives for the whole ProxySQL process, shared
		// across every test invocation against the same container -- a
		// bare CREATE TABLE would fail with "table already exists" on
		// any run after the first against a warm container. OR REPLACE
		// makes this test runnable twice in a row without recreating
		// the container.
		PGresult* r = PQexec(c, "CREATE OR REPLACE TABLE t_pg_e2e(a INTEGER)");
		ok(PQresultStatus(r) == PGRES_COMMAND_OK, "CREATE TABLE succeeds");
		PQclear(r);
	}

	{
		// The error must carry a syntax-error SQLSTATE, not core's
		// hardcoded 28000 (invalid authorization).
		PGresult* r = PQexec(c, "SELECT FROM WHERE");
		const char* state = PQresultErrorField(r, PG_DIAG_SQLSTATE);
		ok(PQresultStatus(r) == PGRES_FATAL_ERROR, "a malformed query returns an error");
		ok(state != NULL && std::strcmp(state, "42601") == 0,
		   "the error SQLSTATE is the plugin's syntax_error 42601, not core's misleading 28000");
		PQclear(r);
	}

	PQfinish(c);
	return exit_status();
}
