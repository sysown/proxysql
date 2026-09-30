#include "libpq-fe.h"
#include "tap.h"
#include "command_line.h"

#include <cstring>
#include <cstdlib>
#include <limits>
#include <cstdint>
#include <string>
#include <utility>

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

PGconn* connect_duckdb(CommandLine& cl, const char* user, const char* pass,
                       bool raw_protocol = false) {
	std::string conninfo = "host=" + std::string(cl.host) +
		" port=" + DUCKDB_PGSQL_PORT +
		" user=" + user + " password=" + pass +
		" dbname=main connect_timeout=10";
	// Direct send/recv tests need plaintext frames; libpq normally negotiates TLS.
	if (raw_protocol) conninfo += " sslmode=disable";
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
	if (!send_empty_message(c, 'P') || !send_empty_message(c, 'H')) return false;

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

	plan(72);

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

	for (const auto& value : {
		std::make_pair("SELECT '1.0000000000000002'::DOUBLE", 0x1.0000000000001p0),
		std::make_pair("SELECT '1.7976931348623157e308'::DOUBLE", std::numeric_limits<double>::max())
	}) {
		PGresult* r = exec_or_bail(c, value.first);
		bool exact = false;
		if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 && !PQgetisnull(r, 0, 0)) {
			const char* text = PQgetvalue(r, 0, 0);
			char* end = nullptr;
			const double received = std::strtod(text, &end);
			exact = end != text && *end == '\0' && received == value.second;
		}
		ok(exact, "DOUBLE survives PostgreSQL text transfer exactly: %s", value.first);
		PQclear(r);
	}

	const struct {
		const char* expression;
		Oid oid;
		int size;
		int modifier;
	} metadata_cases[] = {
		{ "'-128'::TINYINT", 21, 2, -1 },
		{ "'-32768'::SMALLINT", 21, 2, -1 },
		{ "42::INTEGER", 23, 4, -1 },
		{ "9223372036854775807::BIGINT", 20, 8, -1 },
		{ "255::UTINYINT", 21, 2, -1 },
		{ "65535::USMALLINT", 23, 4, -1 },
		{ "4294967295::UINTEGER", 20, 8, -1 },
		{ "18446744073709551615::UBIGINT", 1700, -1, (20 << 16) + 4 },
		{ "1.5::FLOAT", 700, 4, -1 },
		{ "1.5::DOUBLE", 701, 8, -1 },
		{ "1.25::DECIMAL(10,2)", 1700, -1, (10 << 16) + 2 + 4 },
		{ "'-170141183460469231731687303715884105728'::HUGEINT", 1700, -1, (39 << 16) + 4 },
		{ "'340282366920938463463374607431768211455'::UHUGEINT", 1700, -1, (39 << 16) + 4 },
		{ "NULL::INTEGER", 23, 4, -1 }
	};
	for (const auto& value : metadata_cases) {
		const std::string sql = std::string("SELECT ") + value.expression + " AS typed_value";
		PGresult* r = exec_or_bail(c, sql.c_str());
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQnfields(r) == 1 &&
		   PQftype(r, 0) == value.oid && PQfsize(r, 0) == value.size &&
		   PQfmod(r, 0) == value.modifier && PQfformat(r, 0) == 0 &&
		   std::strcmp(PQfname(r, 0), "typed_value") == 0,
		   "PostgreSQL numeric metadata preserves type and precision: %s", value.expression);
		PQclear(r);
	}
	{
		PGresult* r = exec_or_bail(c, "SELECT 1.25::DECIMAL(10,2) AS amount WHERE false");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 0 &&
		   PQftype(r, 0) == 1700 && PQfmod(r, 0) == (10 << 16) + 2 + 4,
		   "empty PostgreSQL results retain decimal metadata");
		PQclear(r);
	}
	for (const char* sql : {
		"SELECT INTERVAL 1 DAY AS fallback",
		"SELECT DATE '2024-01-01' AS fallback",
		"SELECT 42 AS numeric_value, [1, 2] AS wrapped_value"
	}) {
		PGresult* r = exec_or_bail(c, sql);
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQftype(r, 0) == 25,
		   "PostgreSQL text fallback matches the executed result: %s", sql);
		PQclear(r);
	}

	{
		PGresult* r = exec_or_bail(c, "SELECT 42::INTEGER, 'text', 1.25::DECIMAL(4,2), NULL::BIGINT");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQnfields(r) == 4 && PQntuples(r) == 1 &&
		   PQftype(r, 0) == 23 && PQftype(r, 1) == 25 && PQftype(r, 2) == 1700 && PQftype(r, 3) == 20 &&
		   std::strcmp(PQgetvalue(r, 0, 0), "42") == 0 && std::strcmp(PQgetvalue(r, 0, 1), "text") == 0 &&
		   std::strcmp(PQgetvalue(r, 0, 2), "1.25") == 0 && PQgetisnull(r, 0, 3),
		   "mixed PostgreSQL column types retain their values and SQL NULL");
		PQclear(r);
	}

	{
		PGresult* r = exec_or_bail(c, "SELECT from_hex('00015CFF'), ''::BLOB, NULL::BLOB");
		const bool shape = PQresultStatus(r) == PGRES_TUPLES_OK && PQnfields(r) == 3 && PQntuples(r) == 1;
		ok(shape && PQftype(r, 0) == 17 && PQftype(r, 1) == 17 && PQftype(r, 2) == 17 && PQfformat(r, 0) == 0,
		   "PostgreSQL BLOB columns advertise BYTEA text format, including typed NULL");
		size_t size = 0;
		unsigned char* decoded = shape ? PQunescapeBytea(
			reinterpret_cast<const unsigned char*>(PQgetvalue(r, 0, 0)), &size) : nullptr;
		const unsigned char expected[] = { 0, 1, 0x5c, 0xff };
		ok(decoded && size == sizeof(expected) && std::memcmp(decoded, expected, sizeof(expected)) == 0 &&
		   !PQgetisnull(r, 0, 1) && std::strcmp(PQgetvalue(r, 0, 1), "\\x") == 0 && PQgetisnull(r, 0, 2),
		   "libpq decodes arbitrary bytes while distinguishing empty BYTEA from SQL NULL");
		PQfreemem(decoded);
		PQclear(r);
	}
	{
		PGresult* r = exec_or_bail(c, "SELECT repeat('a', 70000)::BLOB");
		size_t size = 0;
		unsigned char* decoded = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1
			? PQunescapeBytea(reinterpret_cast<const unsigned char*>(PQgetvalue(r, 0, 0)), &size) : nullptr;
		ok(decoded && std::string(reinterpret_cast<char*>(decoded), size) == std::string(70000, 'a'),
		   "libpq decodes BYTEA values larger than 64 KiB without truncation");
		PQfreemem(decoded);
		PQclear(r);
	}

	{
		PGresult* r = exec_or_bail(c, "SELECT true, false, NULL::BOOLEAN");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQnfields(r) == 3 && PQntuples(r) == 1 &&
		   PQftype(r, 0) == 16 && PQftype(r, 1) == 16 && PQftype(r, 2) == 16 && PQfsize(r, 0) == 1 &&
		   std::strcmp(PQgetvalue(r, 0, 0), "t") == 0 && std::strcmp(PQgetvalue(r, 0, 1), "f") == 0 &&
		   PQgetisnull(r, 0, 2), "PostgreSQL booleans carry native metadata and values while preserving NULL");
		PQclear(r);
	}

	{
		PGresult* r = exec_or_bail(c, "SELECT 42::INTEGER, '2024-01-02 03:04:05'::TIMESTAMP_S, "
			"'2024-01-02 03:04:05.123'::TIMESTAMP_MS, '1969-12-31 23:59:59.999999999'::TIMESTAMP_NS");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQnfields(r) == 4 && PQntuples(r) == 1 &&
		   PQftype(r, 0) == 23 && PQftype(r, 3) == 25 &&
		   std::strcmp(PQgetvalue(r, 0, 1), "2024-01-02 03:04:05") == 0 &&
		   std::strcmp(PQgetvalue(r, 0, 2), "2024-01-02 03:04:05.123") == 0 &&
		   std::strcmp(PQgetvalue(r, 0, 3), "1969-12-31 23:59:59.999999999") == 0,
		   "timestamp resolutions retain precision without changing adjacent PostgreSQL numeric metadata");
		PQclear(r);
		r = exec_or_bail(c, "CREATE OR REPLACE TABLE t_pg_timestamp(i INTEGER, ts TIMESTAMP_NS)");
		ok(PQresultStatus(r) == PGRES_COMMAND_OK, "create timestamp RETURNING fixture");
		PQclear(r);
		r = exec_or_bail(c, "INSERT INTO t_pg_timestamp VALUES "
			"(1, '2024-01-02 03:04:05.123456789'), (2, NULL) RETURNING i, ts");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 2 &&
		   std::strcmp(PQgetvalue(r, 0, 0), "1") == 0 &&
		   std::strcmp(PQgetvalue(r, 0, 1), "2024-01-02 03:04:05.123456789") == 0 &&
		   std::strcmp(PQgetvalue(r, 1, 0), "2") == 0 && PQgetisnull(r, 1, 1),
		   "PostgreSQL RETURNING delivers nanosecond timestamps and NULL directly");
		PQclear(r);
		r = exec_or_bail(c, "SELECT COUNT(*) FROM t_pg_timestamp");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
		   std::strcmp(PQgetvalue(r, 0, 0), "2") == 0, "timestamp RETURNING inserts exactly once");
		PQclear(r);
	}

	{
		PGresult* r = exec_or_bail(c, "CREATE OR REPLACE TABLE t_pg_timetz(i INTEGER, t TIMETZ)");
		ok(PQresultStatus(r) == PGRES_COMMAND_OK, "create TIMETZ RETURNING fixture");
		PQclear(r);
		r = exec_or_bail(c, "INSERT INTO t_pg_timetz VALUES "
			"(1, '12:34:56.123456+05:30'), (2, '00:00:00-03:30:45'), (3, NULL) RETURNING i, t");
		const bool shape_ok = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 3 && PQnfields(r) == 2;
		ok(shape_ok && PQftype(r, 0) == 23 && PQftype(r, 1) == 25,
		   "TIMETZ RETURNING retains neighboring PostgreSQL numeric metadata");
		const char* expected[] = { "12:34:56.123456+05:30", "00:00:00-03:30:45", nullptr };
		bool values_ok = shape_ok;
		for (int i = 0; values_ok && i < 3; ++i) {
			values_ok = std::string(PQgetvalue(r, i, 0)) == std::to_string(i + 1) &&
				(expected[i] ? !PQgetisnull(r, i, 1) && std::strcmp(PQgetvalue(r, i, 1), expected[i]) == 0
				             : PQgetisnull(r, i, 1));
		}
		ok(values_ok, "PostgreSQL TIMETZ preserves fractional seconds, signed offsets and NULL");
		PQclear(r);
		r = exec_or_bail(c, "SELECT COUNT(*) FROM t_pg_timetz");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
		   std::strcmp(PQgetvalue(r, 0, 0), "3") == 0, "TIMETZ RETURNING inserts exactly once");
		PQclear(r);
		r = exec_or_bail(c, "SELECT i, t FROM t_pg_timetz WHERE false");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 0 && PQnfields(r) == 2 &&
		   PQftype(r, 0) == 23 && PQftype(r, 1) == 25, "empty TIMETZ results preserve PostgreSQL column metadata");
		PQclear(r);
	}

	{
		PGresult* r = exec_or_bail(c, "CREATE OR REPLACE TABLE t_pg_scalar(i INTEGER, t TIME_NS, b BIT, e ENUM('', 'ready', 'café'))");
		ok(PQresultStatus(r) == PGRES_COMMAND_OK, "create TIME_NS/BIT/ENUM RETURNING fixture");
		PQclear(r);
		r = exec_or_bail(c, "INSERT INTO t_pg_scalar VALUES "
			"(1, '12:34:56.123456789', '000101001', 'café'), (2, '24:00:00', '0', ''), (3, NULL, NULL, NULL) RETURNING *");
		const bool shape_ok = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 3 && PQnfields(r) == 4;
		ok(shape_ok && PQftype(r, 0) == 23 && PQftype(r, 1) == 25 && PQftype(r, 2) == 25 && PQftype(r, 3) == 25,
		   "TIME_NS/BIT/ENUM RETURNING retains neighboring PostgreSQL numeric metadata");
		const char* expected[3][3] = {{ "12:34:56.123456789", "000101001", "café" },
		                             { "24:00:00", "0", "" }, { nullptr, nullptr, nullptr }};
		bool values_ok = shape_ok;
		for (int i = 0; values_ok && i < 3; ++i) {
			values_ok = std::string(PQgetvalue(r, i, 0)) == std::to_string(i + 1);
			for (int j = 0; values_ok && j < 3; ++j)
				values_ok = expected[i][j] ? !PQgetisnull(r, i, j + 1) && std::strcmp(PQgetvalue(r, i, j + 1), expected[i][j]) == 0
				                           : PQgetisnull(r, i, j + 1);
		}
		ok(values_ok, "PostgreSQL preserves nanosecond time, BIT leading zeroes, ENUM labels, empty strings and NULL");
		PQclear(r);
		r = exec_or_bail(c, "SELECT COUNT(*) FROM t_pg_scalar");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
		   std::strcmp(PQgetvalue(r, 0, 0), "3") == 0, "scalar RETURNING inserts exactly once");
		PQclear(r);
		r = exec_or_bail(c, "SELECT * FROM t_pg_scalar WHERE false");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 0 && PQnfields(r) == 4 &&
		   PQftype(r, 0) == 23 && PQftype(r, 1) == 25 && PQftype(r, 2) == 25 && PQftype(r, 3) == 25,
		   "empty scalar results preserve PostgreSQL metadata");
		PQclear(r);
		r = exec_or_bail(c, "UPDATE t_pg_scalar SET b='000000001' WHERE i=1 RETURNING b");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
		   std::strcmp(PQgetvalue(r, 0, 0), "000000001") == 0, "BIT UPDATE RETURNING preserves leading zeroes");
		PQclear(r);
		r = exec_or_bail(c, "DELETE FROM t_pg_scalar WHERE i=1 RETURNING e");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
		   std::strcmp(PQgetvalue(r, 0, 0), "café") == 0, "ENUM DELETE RETURNING preserves the label");
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
		PGresult* r = exec_or_bail(c, "CREATE OR REPLACE TABLE t_pg_uuid(n INTEGER, id UUID)");
		ok(PQresultStatus(r) == PGRES_COMMAND_OK, "create UUID RETURNING fixture");
		PQclear(r);
		r = exec_or_bail(c, "INSERT INTO t_pg_uuid VALUES "
		                   "(1, '00112233-4455-6677-8899-aabbccddeeff'), (2, NULL) RETURNING n, id");
		const bool shape_ok = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 2 && PQnfields(r) == 2;
		ok(shape_ok, "UUID RETURNING executes");
		ok(shape_ok && PQftype(r, 0) == 23 && PQftype(r, 1) == 25,
		   "UUID text metadata preserves adjacent INTEGER metadata");
		ok(shape_ok && !PQgetisnull(r, 0, 1) &&
		   std::strcmp(PQgetvalue(r, 0, 0), "1") == 0 &&
		   std::strcmp(PQgetvalue(r, 0, 1), "00112233-4455-6677-8899-aabbccddeeff") == 0 &&
		   std::strcmp(PQgetvalue(r, 1, 0), "2") == 0 && PQgetisnull(r, 1, 1),
		   "UUID RETURNING preserves canonical values and NULL");
		PQclear(r);
		r = exec_or_bail(c, "SELECT COUNT(*) FROM t_pg_uuid");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
		   std::strcmp(PQgetvalue(r, 0, 0), "2") == 0, "UUID RETURNING inserts exactly once");
		PQclear(r);
	}

	{
		PGresult* r = exec_or_bail(c,
			"CREATE OR REPLACE TABLE t_pg_returning(id INTEGER[] DEFAULT [1, 2])");
		ok(PQresultStatus(r) == PGRES_COMMAND_OK, "create unsupported RETURNING fixture");
		PQclear(r);

		r = exec_or_bail(c, "INSERT INTO t_pg_returning DEFAULT VALUES RETURNING id");
		const char* state = PQresultErrorField(r, PG_DIAG_SQLSTATE);
		ok(PQresultStatus(r) == PGRES_FATAL_ERROR && state &&
		   std::strcmp(state, "0A000") == 0 &&
		   std::strstr(PQresultErrorMessage(r), "VARCHAR") != nullptr,
		   "unsupported RETURNING reports an actionable feature-not-supported error");
		PQclear(r);

		r = exec_or_bail(c, "SELECT COUNT(*) FROM t_pg_returning");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
		   std::strcmp(PQgetvalue(r, 0, 0), "0") == 0,
		   "rejected RETURNING leaves no committed row");
		PQclear(r);

		r = exec_or_bail(c, "INSERT INTO t_pg_returning DEFAULT VALUES RETURNING id::VARCHAR");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
		   !PQgetisnull(r, 0, 0) && std::strcmp(PQgetvalue(r, 0, 0), "[1, 2]") == 0,
		   "an explicit VARCHAR cast returns the LIST value");
		PQclear(r);

		r = exec_or_bail(c, "SELECT COUNT(*) FROM t_pg_returning");
		ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
		   std::strcmp(PQgetvalue(r, 0, 0), "1") == 0,
		   "the supported RETURNING insert executes exactly once");
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
		PGconn* extended = connect_duckdb(cl, cl.pgsql_username, cl.pgsql_password, true);
		ok(extended != NULL && unsupported_message_gets_error(extended, type),
		   "unsupported extended-query message %c gets an immediate ErrorResponse", type);
		if (extended != NULL) PQfinish(extended);
	}

	{
		PGconn* extended = connect_duckdb(cl, cl.pgsql_username, cl.pgsql_password, true);
		ok(extended != NULL && extended_error_resynchronizes_on_sync(extended),
		   "extended-query rejection emits one error, discards Flush until Sync, then sends ReadyForQuery");
		if (extended != NULL) PQfinish(extended);
	}

	PQfinish(c);
	return exit_status();
}
