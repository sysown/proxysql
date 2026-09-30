#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include <cstring>
#include <cstdlib>
#include <limits>
#include <string>
#include <utility>
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

	plan(62);

	MYSQL* c = connect_duckdb(cl, cl.username, cl.password);
	ok(c != NULL, "connect to the DuckDB MySQL port with mysql_users credentials");
	if (c == NULL) BAIL_OUT("cannot continue without a connection");

	ok(one_cell(c, "SELECT 42 AS answer") == "42", "integer literal round-trips");
	ok(one_cell(c, "SELECT 'hello' AS s") == "hello", "string literal round-trips");
	ok(one_cell(c, "SELECT CAST(1.5 AS DOUBLE) AS d") == "1.5", "double round-trips");

	for (const auto& value : {
		std::make_pair("SELECT '1.0000000000000002'::DOUBLE", 0x1.0000000000001p0),
		std::make_pair("SELECT '1.7976931348623157e308'::DOUBLE", std::numeric_limits<double>::max())
	}) {
		const std::string text = one_cell(c, value.first);
		char* end = nullptr;
		const double received = std::strtod(text.c_str(), &end);
		ok(!text.empty() && *end == '\0' && received == value.second,
		   "DOUBLE survives MySQL text transfer exactly: %s", value.first);
	}

	// Metadata must describe the actual result schema, including empty results.
	const struct {
		const char* expression;
		enum_field_types type;
		bool is_unsigned;
		unsigned int scale;
		unsigned long width;
	} metadata_cases[] = {
		{ "'-128'::TINYINT", MYSQL_TYPE_TINY, false, 0, 4 },
		{ "'-32768'::SMALLINT", MYSQL_TYPE_SHORT, false, 0, 6 },
		{ "42::INTEGER", MYSQL_TYPE_LONG, false, 0, 11 },
		{ "9223372036854775807::BIGINT", MYSQL_TYPE_LONGLONG, false, 0, 20 },
		{ "255::UTINYINT", MYSQL_TYPE_TINY, true, 0, 3 },
		{ "65535::USMALLINT", MYSQL_TYPE_SHORT, true, 0, 5 },
		{ "4294967295::UINTEGER", MYSQL_TYPE_LONG, true, 0, 10 },
		{ "18446744073709551615::UBIGINT", MYSQL_TYPE_LONGLONG, true, 0, 20 },
		{ "1.5::FLOAT", MYSQL_TYPE_FLOAT, false, 31, 12 },
		{ "1.5::DOUBLE", MYSQL_TYPE_DOUBLE, false, 31, 22 },
		{ "1.25::DECIMAL(10,2)", MYSQL_TYPE_NEWDECIMAL, false, 2, 12 },
		{ "'-170141183460469231731687303715884105728'::HUGEINT", MYSQL_TYPE_NEWDECIMAL, false, 0, 40 },
		{ "'340282366920938463463374607431768211455'::UHUGEINT", MYSQL_TYPE_NEWDECIMAL, true, 0, 39 },
		{ "NULL::INTEGER", MYSQL_TYPE_LONG, false, 0, 11 }
	};
	for (const auto& value : metadata_cases) {
		const std::string sql = std::string("SELECT ") + value.expression + " AS typed_value";
		const int rc = mysql_query(c, sql.c_str());
		MYSQL_RES* r = rc == 0 ? mysql_store_result(c) : nullptr;
		MYSQL_FIELD* f = r ? mysql_fetch_field(r) : nullptr;
		ok(f && f->type == value.type && bool(f->flags & UNSIGNED_FLAG) == value.is_unsigned &&
		   !(f->flags & NOT_NULL_FLAG) && f->decimals == value.scale && f->length == value.width &&
		   std::strcmp(f->name, "typed_value") == 0,
		   "MySQL numeric metadata preserves type, signedness and scale: %s", value.expression);
		if (r) mysql_free_result(r);
	}
	{
		const int rc = mysql_query(c, "SELECT 1.25::DECIMAL(10,2) AS amount WHERE false");
		MYSQL_RES* r = rc == 0 ? mysql_store_result(c) : nullptr;
		MYSQL_FIELD* f = r ? mysql_fetch_field(r) : nullptr;
		ok(f && mysql_num_rows(r) == 0 && f->type == MYSQL_TYPE_NEWDECIMAL && f->decimals == 2,
		   "empty MySQL results retain decimal metadata");
		if (r) mysql_free_result(r);
	}
	for (const char* sql : {
		"SELECT INTERVAL 1 DAY AS fallback",
		"SELECT DATE '2024-01-01' AS fallback",
		"SELECT 42 AS numeric_value, [1, 2] AS wrapped_value"
	}) {
		const int rc = mysql_query(c, sql);
		MYSQL_RES* r = rc == 0 ? mysql_store_result(c) : nullptr;
		MYSQL_FIELD* f = r ? mysql_fetch_field(r) : nullptr;
		ok(f && f->type == MYSQL_TYPE_VAR_STRING,
		   "MySQL text fallback matches the executed result: %s", sql);
		if (r) mysql_free_result(r);
	}

	{
		const int rc = mysql_query(c, "SELECT 42::INTEGER, 'text', 1.25::DECIMAL(4,2), NULL::BIGINT");
		MYSQL_RES* r = rc == 0 ? mysql_store_result(c) : nullptr;
		MYSQL_FIELD* fields = r ? mysql_fetch_fields(r) : nullptr;
		MYSQL_ROW row = r ? mysql_fetch_row(r) : nullptr;
		ok(r && mysql_num_fields(r) == 4 && fields[0].type == MYSQL_TYPE_LONG &&
		   fields[1].type == MYSQL_TYPE_VAR_STRING && fields[2].type == MYSQL_TYPE_NEWDECIMAL &&
		   fields[3].type == MYSQL_TYPE_LONGLONG && row && row[0] && row[1] && row[2] &&
		   std::strcmp(row[0], "42") == 0 && std::strcmp(row[1], "text") == 0 &&
		   std::strcmp(row[2], "1.25") == 0 && row[3] == nullptr,
		   "mixed MySQL column types retain their values and SQL NULL");
		if (r) mysql_free_result(r);
	}
	{
		std::string sql = "SELECT 1::INTEGER";
		for (int i = 1; i < 300; ++i) sql += ", 1::INTEGER";
		const int rc = mysql_query(c, sql.c_str());
		MYSQL_RES* r = rc == 0 ? mysql_store_result(c) : nullptr;
		bool valid = r && mysql_num_fields(r) == 300;
		if (valid) {
			MYSQL_FIELD* fields = mysql_fetch_fields(r);
			MYSQL_ROW row = mysql_fetch_row(r);
			for (int i = 0; i < 300; ++i)
				valid = valid && fields[i].type == MYSQL_TYPE_LONG && row && row[i] &&
				        std::strcmp(row[i], "1") == 0;
		}
		ok(valid, "typed MySQL column packets preserve sequence IDs across wraparound");
		if (r) mysql_free_result(r);
	}

	{
		const int rc = mysql_query(c, "SELECT from_hex('00015CFF'), ''::BLOB, NULL::BLOB");
		MYSQL_RES* r = rc == 0 ? mysql_store_result(c) : nullptr;
		MYSQL_FIELD* fields = r ? mysql_fetch_fields(r) : nullptr;
		bool binary_types = r && mysql_num_fields(r) == 3;
		if (binary_types) {
			for (int i = 0; i < 3; ++i)
				binary_types = binary_types && fields[i].type == MYSQL_TYPE_LONG_BLOB &&
				               fields[i].charsetnr == 63 && (fields[i].flags & BINARY_FLAG);
		}
		ok(binary_types, "MySQL BLOB columns advertise binary metadata, including typed NULL");
		MYSQL_ROW row = r ? mysql_fetch_row(r) : nullptr;
		const unsigned long* lengths = row ? mysql_fetch_lengths(r) : nullptr;
		const unsigned char expected[] = { 0, 1, 0x5c, 0xff };
		ok(row && row[0] && lengths[0] == sizeof(expected) &&
		   std::memcmp(row[0], expected, sizeof(expected)) == 0 && row[1] && lengths[1] == 0 && !row[2],
		   "MySQL BLOB preserves arbitrary bytes, empty data and SQL NULL");
		if (r) mysql_free_result(r);
	}
	{
		const std::string value = one_cell(c, "SELECT repeat('a', 70000)::BLOB");
		ok(value == std::string(70000, 'a'), "MySQL BLOB values larger than 64 KiB remain intact");
	}

	{
		const int rc = mysql_query(c, "SELECT true, false, NULL::BOOLEAN");
		MYSQL_RES* r = rc == 0 ? mysql_store_result(c) : nullptr;
		MYSQL_FIELD* fields = r ? mysql_fetch_fields(r) : nullptr;
		MYSQL_ROW row = r ? mysql_fetch_row(r) : nullptr;
		ok(r && mysql_num_fields(r) == 3 && row && fields[0].type == MYSQL_TYPE_TINY &&
		   fields[1].type == MYSQL_TYPE_TINY && fields[2].type == MYSQL_TYPE_TINY &&
		   fields[0].length == 1 && fields[1].length == 1 && fields[2].length == 1 &&
		   row[0] && std::strcmp(row[0], "1") == 0 && row[1] && std::strcmp(row[1], "0") == 0 && !row[2],
		   "MySQL booleans carry TINYINT metadata and numeric values while preserving NULL");
		if (r) mysql_free_result(r);
	}

	{
		const int rc = mysql_query(c, "SELECT 42::INTEGER, '2024-01-02 03:04:05'::TIMESTAMP_S, "
			"'2024-01-02 03:04:05.123'::TIMESTAMP_MS, '1969-12-31 23:59:59.999999999'::TIMESTAMP_NS");
		MYSQL_RES* r = rc == 0 ? mysql_store_result(c) : nullptr;
		MYSQL_FIELD* fields = r ? mysql_fetch_fields(r) : nullptr;
		MYSQL_ROW row = r ? mysql_fetch_row(r) : nullptr;
		ok(r && mysql_num_fields(r) == 4 && fields[0].type == MYSQL_TYPE_LONG &&
		   fields[3].type == MYSQL_TYPE_VAR_STRING && row && row[1] && row[2] && row[3] &&
		   std::strcmp(row[1], "2024-01-02 03:04:05") == 0 &&
		   std::strcmp(row[2], "2024-01-02 03:04:05.123") == 0 &&
		   std::strcmp(row[3], "1969-12-31 23:59:59.999999999") == 0,
		   "timestamp resolutions retain precision without changing adjacent MySQL numeric metadata");
		if (r) mysql_free_result(r);
	}
	ok(mysql_query(c, "CREATE OR REPLACE TABLE t_mysql_timestamp(i INTEGER, ts TIMESTAMP_NS)") == 0,
	   "create timestamp RETURNING fixture");
	{
		const int rc = mysql_query(c, "INSERT INTO t_mysql_timestamp VALUES "
			"(1, '2024-01-02 03:04:05.123456789'), (2, NULL) RETURNING i, ts");
		MYSQL_RES* r = rc == 0 ? mysql_store_result(c) : nullptr;
		MYSQL_ROW first = r ? mysql_fetch_row(r) : nullptr;
		const bool first_ok = first && first[0] && first[1] && std::strcmp(first[0], "1") == 0 &&
			std::strcmp(first[1], "2024-01-02 03:04:05.123456789") == 0;
		MYSQL_ROW second = r ? mysql_fetch_row(r) : nullptr;
		ok(r && mysql_num_rows(r) == 2 && first_ok && second && second[0] &&
		   std::strcmp(second[0], "2") == 0 && !second[1],
		   "MySQL RETURNING delivers nanosecond timestamps and NULL directly");
		if (r) mysql_free_result(r);
	}
	ok(one_cell(c, "SELECT COUNT(*) FROM t_mysql_timestamp") == "2",
	   "timestamp RETURNING inserts exactly once");

	{
		ok(mysql_query(c, "CREATE OR REPLACE TABLE t_mysql_timetz(i INTEGER, t TIMETZ)") == 0,
		   "create TIMETZ RETURNING fixture");
		const int rc = mysql_query(c, "INSERT INTO t_mysql_timetz VALUES "
			"(1, '12:34:56.123456+05:30'), (2, '00:00:00-03:30:45'), (3, NULL) RETURNING i, t");
		MYSQL_RES* r = rc == 0 ? mysql_store_result(c) : nullptr;
		MYSQL_FIELD* fields = r && mysql_num_fields(r) == 2 ? mysql_fetch_fields(r) : nullptr;
		ok(fields && fields[0].type == MYSQL_TYPE_LONG && fields[1].type == MYSQL_TYPE_VAR_STRING,
		   "TIMETZ RETURNING retains neighboring MySQL numeric metadata");
		const char* expected[] = { "12:34:56.123456+05:30", "00:00:00-03:30:45", nullptr };
		bool values_ok = fields && mysql_num_rows(r) == 3;
		for (int i = 0; values_ok && i < 3; ++i) {
			MYSQL_ROW row = mysql_fetch_row(r);
			values_ok = row && row[0] && std::string(row[0]) == std::to_string(i + 1) &&
				(expected[i] ? row[1] && std::strcmp(row[1], expected[i]) == 0 : row[1] == nullptr);
		}
		ok(values_ok, "MySQL TIMETZ preserves fractional seconds, signed offsets and NULL");
		if (r) mysql_free_result(r);
		ok(one_cell(c, "SELECT COUNT(*) FROM t_mysql_timetz") == "3", "TIMETZ RETURNING inserts exactly once");
		const int empty_rc = mysql_query(c, "SELECT i, t FROM t_mysql_timetz WHERE false");
		r = empty_rc == 0 ? mysql_store_result(c) : nullptr;
		fields = r && mysql_num_fields(r) == 2 ? mysql_fetch_fields(r) : nullptr;
		ok(fields && mysql_num_rows(r) == 0 && fields[0].type == MYSQL_TYPE_LONG &&
		   fields[1].type == MYSQL_TYPE_VAR_STRING, "empty TIMETZ results preserve MySQL column metadata");
		if (r) mysql_free_result(r);
	}

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

	ok(mysql_query(c, "SELECT gen_random_uuid()") == 0, "UUID query succeeds on the wire");
	{
		MYSQL_RES* r = mysql_store_result(c);
		MYSQL_ROW row = r ? mysql_fetch_row(r) : NULL;
		ok(r != NULL && row != NULL && row[0] != NULL && std::strlen(row[0]) == 36,
		   "UUID arrives as text, not NULL");
		if (r) mysql_free_result(r);
	}

	// UUID RETURNING must use direct conversion and preserve adjacent numeric metadata.
	ok(mysql_query(c, "CREATE OR REPLACE TABLE t_mysql_uuid(n INTEGER, id UUID)") == 0,
	   "create UUID RETURNING fixture");
	ok(mysql_query(c, "INSERT INTO t_mysql_uuid VALUES "
	                 "(1, '00112233-4455-6677-8899-aabbccddeeff'), (2, NULL) RETURNING n, id") == 0,
	   "UUID RETURNING executes");
	{
		MYSQL_RES* r = mysql_store_result(c);
		MYSQL_FIELD* fields = r && mysql_num_fields(r) == 2 ? mysql_fetch_fields(r) : nullptr;
		ok(fields && fields[0].type == MYSQL_TYPE_LONG && fields[1].type == MYSQL_TYPE_VAR_STRING,
		   "UUID text metadata preserves adjacent INTEGER metadata");
		MYSQL_ROW row = fields ? mysql_fetch_row(r) : nullptr;
		const bool first_ok = row && row[0] && row[1] && std::strcmp(row[0], "1") == 0 &&
			std::strcmp(row[1], "00112233-4455-6677-8899-aabbccddeeff") == 0;
		row = fields ? mysql_fetch_row(r) : nullptr;
		ok(r && mysql_num_rows(r) == 2 && first_ok && row && row[0] &&
		   std::strcmp(row[0], "2") == 0 && !row[1], "UUID RETURNING preserves canonical values and NULL");
		if (r) mysql_free_result(r);
	}
	ok(one_cell(c, "SELECT COUNT(*) FROM t_mysql_uuid") == "2", "UUID RETURNING inserts exactly once");

	// A failed conversion must not commit a write or fabricate a SQL NULL.
	ok(mysql_query(c, "CREATE OR REPLACE TABLE t_mysql_returning(id INTEGER[] DEFAULT [1, 2])") == 0,
	   "create unsupported RETURNING fixture");
	const int returning_rc = mysql_query(c, "INSERT INTO t_mysql_returning DEFAULT VALUES RETURNING id");
	ok(returning_rc != 0 && mysql_errno(c) == 1235 &&
	   std::strcmp(mysql_sqlstate(c), "0A000") == 0 &&
	   std::strstr(mysql_error(c), "VARCHAR") != NULL,
	   "unsupported RETURNING reports an actionable feature-not-supported error");
	{
		MYSQL_RES* r = mysql_store_result(c);
		if (r) mysql_free_result(r);
	}
	ok(one_cell(c, "SELECT COUNT(*) FROM t_mysql_returning") == "0",
	   "rejected RETURNING leaves no committed row");
	ok(one_cell(c, "INSERT INTO t_mysql_returning DEFAULT VALUES RETURNING id::VARCHAR") == "[1, 2]",
	   "an explicit VARCHAR cast returns the LIST value");
	ok(one_cell(c, "SELECT COUNT(*) FROM t_mysql_returning") == "1",
	   "the supported RETURNING insert executes exactly once");

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
