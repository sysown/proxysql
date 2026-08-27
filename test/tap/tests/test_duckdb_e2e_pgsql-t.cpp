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
		// first word of the query, so "SELECT n" must come back.
		PGresult* r = PQexec(c, "SELECT 1 UNION ALL SELECT 2");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK &&
		   std::strncmp(PQcmdStatus(r), "SELECT", 6) == 0,
		   "the CommandComplete tag says SELECT");
		PQclear(r);
	}

	{
		PGresult* r = PQexec(c, "CREATE TABLE t_pg_e2e(a INTEGER)");
		ok(PQresultStatus(r) == PGRES_COMMAND_OK, "CREATE TABLE succeeds");
		PQclear(r);
	}

	{
		// The error must carry a syntax-error SQLSTATE, not core's
		// hardcoded 28000 (invalid authorization).
		PGresult* r = PQexec(c, "SELECT FROM WHERE");
		const char* state = PQresultErrorField(r, PG_DIAG_SQLSTATE);
		ok(PQresultStatus(r) == PGRES_FATAL_ERROR, "a malformed query returns an error");
		ok(state != NULL && std::strcmp(state, "28000") != 0,
		   "the error SQLSTATE is not the misleading 28000");
		PQclear(r);
	}

	PQfinish(c);
	return exit_status();
}
