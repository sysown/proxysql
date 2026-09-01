#include "libpq-fe.h"
#include "tap.h"
#include "command_line.h"

#include <cstring>
#include <cstdint>
#include <string>

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>

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
	if (c == nullptr) return nullptr;
	if (PQstatus(c) != CONNECTION_OK) { PQfinish(c); return NULL; }
	return c;
}

PGresult* exec_or_bail(PGconn* c, const char* sql) {
	PGresult* result = PQexec(c, sql);
	if (result == nullptr) {
		BAIL_OUT("DuckDB PostgreSQL connection lost while executing: %s", sql);
		return nullptr;
	}
	return result;
}

bool unsupported_message_gets_error(PGconn* c, char type) {
	unsigned char packet[5] = { static_cast<unsigned char>(type), 0, 0, 0, 0 };
	const uint32_t length = htonl(4);
	std::memcpy(packet + 1, &length, sizeof(length));
	if (send(PQsocket(c), packet, sizeof(packet), 0) != sizeof(packet)) return false;

	pollfd pfd { PQsocket(c), POLLIN, 0 };
	if (poll(&pfd, 1, 1000) != 1 || (pfd.revents & POLLIN) == 0) return false;
	unsigned char response_type = 0;
	return recv(PQsocket(c), &response_type, 1, MSG_PEEK) == 1 && response_type == 'E';
}

bool send_empty_message(PGconn* c, char type) {
	unsigned char packet[5] = { static_cast<unsigned char>(type), 0, 0, 0, 0 };
	const uint32_t length = htonl(4);
	std::memcpy(packet + 1, &length, sizeof(length));
	return send(PQsocket(c), packet, sizeof(packet), 0) == sizeof(packet);
}

bool receive_message_type(PGconn* c, char& type, int timeout_ms) {
	pollfd pfd { PQsocket(c), POLLIN, 0 };
	if (poll(&pfd, 1, timeout_ms) != 1 || (pfd.revents & POLLIN) == 0) return false;

	unsigned char header[5];
	if (recv(PQsocket(c), header, sizeof(header), MSG_WAITALL) != sizeof(header)) return false;
	type = static_cast<char>(header[0]);
	uint32_t network_length = 0;
	std::memcpy(&network_length, header + 1, sizeof(network_length));
	const uint32_t length = ntohl(network_length);
	if (length < 4) return false;

	uint32_t remaining = length - 4;
	unsigned char discard[256];
	while (remaining > 0) {
		const size_t chunk = remaining < sizeof(discard) ? remaining : sizeof(discard);
		const ssize_t received = recv(PQsocket(c), discard, chunk, MSG_WAITALL);
		if (received <= 0) return false;
		remaining -= static_cast<uint32_t>(received);
	}
	return true;
}

bool extended_error_resynchronizes_on_sync(PGconn* c) {
	if (!send_empty_message(c, 'P') || !send_empty_message(c, 'B')) return false;

	char type = 0;
	if (!receive_message_type(c, type, 1000) || type != 'E') return false;

	pollfd pfd { PQsocket(c), POLLIN, 0 };
	if (poll(&pfd, 1, 100) != 0) return false;

	if (!send_empty_message(c, 'S')) return false;
	return receive_message_type(c, type, 1000) && type == 'Z';
}

bool result_has_value(PGresult* r, const char* value) {
	if (r == nullptr || PQnfields(r) < 1) return false;
	for (int row = 0; row < PQntuples(r); row++) {
		if (!PQgetisnull(r, row, 0) && std::strcmp(PQgetvalue(r, row, 0), value) == 0)
			return true;
	}
	return false;
}

} // namespace

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) { diag("Failed to get the required environment variables"); return -1; }

	plan(21);

	PGconn* c = connect_duckdb(cl, cl.pgsql_username, cl.pgsql_password);
	ok(c != NULL, "connect to the DuckDB PgSQL port with pgsql_users credentials");
	if (c == NULL) BAIL_OUT("cannot continue without a connection");

	{
		PGresult* r = exec_or_bail(c, "SELECT 42 AS answer");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
		   std::strcmp(PQgetvalue(r, 0, 0), "42") == 0, "integer literal round-trips");
		ok(PQnfields(r) == 1 && std::strcmp(PQfname(r, 0), "answer") == 0,
		   "the column name is preserved");
		PQclear(r);
	}

	{
		PGresult* setup = exec_or_bail(c, "CREATE SCHEMA IF NOT EXISTS duckdb_e2e_schema");
		if (PQresultStatus(setup) != PGRES_COMMAND_OK) BAIL_OUT("could not create test schema");
		PQclear(setup);
		setup = exec_or_bail(c, "ATTACH ':memory:' AS duckdb_e2e_catalog");
		if (PQresultStatus(setup) != PGRES_COMMAND_OK) BAIL_OUT("could not attach test catalog");
		PQclear(setup);

		PGresult* databases = exec_or_bail(c, "SHOW DATABASES");
		ok(PQresultStatus(databases) == PGRES_TUPLES_OK &&
		   result_has_value(databases, "duckdb_e2e_catalog") &&
		   !result_has_value(databases, "duckdb_e2e_schema"),
		   "SHOW DATABASES enumerates catalogs, not schemas");
		PQclear(databases);

		PGresult* schemas = exec_or_bail(c, "SHOW SCHEMAS");
		ok(PQresultStatus(schemas) == PGRES_TUPLES_OK &&
		   result_has_value(schemas, "duckdb_e2e_schema") &&
		   !result_has_value(schemas, "duckdb_e2e_catalog"),
		   "SHOW SCHEMAS enumerates schema metadata separately");
		PQclear(schemas);
	}

	{
		PGresult* r = exec_or_bail(c, "SELECT NULL AS n");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQgetisnull(r, 0, 0) == 1,
		   "NULL arrives as a real SQL NULL");
		PQclear(r);
	}

	{
		PGresult* set = exec_or_bail(c, "SET threads=2");
		const bool set_ok = PQresultStatus(set) == PGRES_COMMAND_OK;
		PQclear(set);
		PGresult* current = exec_or_bail(c, "SELECT current_setting('threads')");
		ok(set_ok && PQresultStatus(current) == PGRES_TUPLES_OK &&
		   PQntuples(current) == 1 && std::strcmp(PQgetvalue(current, 0, 0), "2") == 0,
		   "DuckDB-native SET reaches the engine and changes the setting");
		PQclear(current);
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
		PGresult* r = exec_or_bail(c, "SHOW TABLES");
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
		PGresult* r = exec_or_bail(c, "CREATE OR REPLACE TABLE t_pg_e2e(a INTEGER)");
		ok(PQresultStatus(r) == PGRES_COMMAND_OK, "CREATE TABLE succeeds");
		PQclear(r);
	}

	{
		// The error must carry a syntax-error SQLSTATE, not core's
		// hardcoded 28000 (invalid authorization).
		PGresult* r = exec_or_bail(c, "SELECT FROM WHERE");
		const char* state = PQresultErrorField(r, PG_DIAG_SQLSTATE);
		ok(PQresultStatus(r) == PGRES_FATAL_ERROR, "a malformed query returns an error");
		ok(state != NULL && std::strcmp(state, "42601") == 0,
		   "the error SQLSTATE is the plugin's syntax_error 42601, not core's misleading 28000");
		PQclear(r);
	}

	{
		PGresult* setup = exec_or_bail(c, "CREATE OR REPLACE TABLE tx_error(v VARCHAR)");
		if (PQresultStatus(setup) != PGRES_COMMAND_OK) BAIL_OUT("could not create transaction-error table");
		PQclear(setup);
		setup = exec_or_bail(c, "INSERT INTO tx_error VALUES ('not-an-integer')");
		if (PQresultStatus(setup) != PGRES_COMMAND_OK) BAIL_OUT("could not populate transaction-error table");
		PQclear(setup);

		PGresult* r = exec_or_bail(c, "BEGIN");
		ok(PQresultStatus(r) == PGRES_COMMAND_OK &&
		   PQtransactionStatus(c) == PQTRANS_INTRANS,
		   "ReadyForQuery reports an active DuckDB transaction after BEGIN");
		PQclear(r);

		r = exec_or_bail(c, "SELECT CAST(v AS INTEGER) FROM tx_error");
		const char* state = PQresultErrorField(r, PG_DIAG_SQLSTATE);
		ok(PQresultStatus(r) == PGRES_FATAL_ERROR && state != NULL &&
		   std::strcmp(state, "22018") == 0,
		   "a DuckDB conversion error uses SQLSTATE 22018 instead of syntax_error");
		ok(PQtransactionStatus(c) == PQTRANS_INERROR,
		   "ReadyForQuery reports DuckDB's invalidated transaction state");
		PQclear(r);

		r = exec_or_bail(c, "ROLLBACK");
		ok(PQresultStatus(r) == PGRES_COMMAND_OK &&
		   PQtransactionStatus(c) == PQTRANS_IDLE,
		   "ReadyForQuery returns to idle after ROLLBACK");
		PQclear(r);
	}

	for (char type : { 'P', 'B', 'C', 'D', 'E' }) {
		PGconn* extended = connect_duckdb(cl, cl.pgsql_username, cl.pgsql_password);
		ok(extended != NULL && unsupported_message_gets_error(extended, type),
		   "unsupported extended-query message %c gets an immediate ErrorResponse", type);
		if (extended != NULL) PQfinish(extended);
	}

	{
		PGconn* extended = connect_duckdb(cl, cl.pgsql_username, cl.pgsql_password);
		ok(extended != NULL && extended_error_resynchronizes_on_sync(extended),
		   "extended-query rejection emits one error, discards until Sync, then sends ReadyForQuery");
		if (extended != NULL) PQfinish(extended);
	}

	PQfinish(c);
	return exit_status();
}
