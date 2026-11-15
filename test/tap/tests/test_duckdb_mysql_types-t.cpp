#include "duckdb_replica_test_utils.h"
#include <memory>
#include <cstring>
using namespace duckdb_replica_test;
namespace {
struct Column {
	enum_field_types type;
	unsigned flags;
	unsigned charset;
	int decimals;
	const char* value;
};
bool verify(MYSQL* c, const std::string& sql, const std::vector<Column>& expected,
			bool empty = false, const std::vector<std::string>& names = {}) {
	if (mysql_query(c, sql.c_str())) {
		diag("typed query error: %s", mysql_error(c));
		return false;
	}
	std::unique_ptr<MYSQL_RES, decltype(&mysql_free_result)> r(mysql_store_result(c),
															   mysql_free_result);
	if (!r || mysql_num_fields(r.get()) != expected.size() ||
		mysql_num_rows(r.get()) != (empty ? 0 : 1))
		return false;
	MYSQL_FIELD* fields = mysql_fetch_fields(r.get());
	MYSQL_ROW row = empty ? nullptr : mysql_fetch_row(r.get());
	unsigned long* lengths = empty ? nullptr : mysql_fetch_lengths(r.get());
	for (size_t i = 0; i < expected.size(); ++i) {
		const auto& e = expected[i];
		if (!names.empty() && names[i] != fields[i].name)
			return false;
		if (fields[i].flags & NOT_NULL_FLAG)
			return false;
		if (fields[i].type != e.type || (fields[i].flags & UNSIGNED_FLAG) != e.flags ||
			fields[i].charsetnr != e.charset ||
			(e.decimals >= 0 && fields[i].decimals != static_cast<unsigned>(e.decimals))) {
			diag("column %zu: type=%d unsigned=%u charset=%u decimals=%u", i, int(fields[i].type),
				 fields[i].flags & UNSIGNED_FLAG, fields[i].charsetnr, fields[i].decimals);
			return false;
		}
		if (!empty && row[i] && (e.type == MYSQL_TYPE_VAR_STRING || e.type == MYSQL_TYPE_LONG_BLOB) &&
			fields[i].length < lengths[i])
			return false;
		if (!empty &&
			(e.value ? !row[i] || std::string(row[i], lengths[i]) != e.value : row[i] != nullptr))
			return false;
	}
	return true;
}
bool cases(MYSQL* c) {
	const std::string scalar =
		"SELECT (-128)::TINYINT AS t,(-32768)::SMALLINT AS s,(-2147483648)::INTEGER AS i,"
		"'-9223372036854775808'::BIGINT AS b,255::UTINYINT AS ut,65535::USMALLINT AS us,"
		"4294967295::UINTEGER AS ui,'18446744073709551615'::UBIGINT AS ub,TRUE AS flag,"
		"NULL::INTEGER AS missing,'1.2300'::DECIMAL(20,4) AS d";
	const std::vector<Column> ints = {
		{MYSQL_TYPE_TINY, 0, 63, 0, "-128"},
		{MYSQL_TYPE_SHORT, 0, 63, 0, "-32768"},
		{MYSQL_TYPE_LONG, 0, 63, 0, "-2147483648"},
		{MYSQL_TYPE_LONGLONG, 0, 63, 0, "-9223372036854775808"},
		{MYSQL_TYPE_TINY, UNSIGNED_FLAG, 63, 0, "255"},
		{MYSQL_TYPE_SHORT, UNSIGNED_FLAG, 63, 0, "65535"},
		{MYSQL_TYPE_LONG, UNSIGNED_FLAG, 63, 0, "4294967295"},
		{MYSQL_TYPE_LONGLONG, UNSIGNED_FLAG, 63, 0, "18446744073709551615"},
		{MYSQL_TYPE_TINY, 0, 63, 0, "1"},
		{MYSQL_TYPE_LONG, 0, 63, 0, nullptr},
		{MYSQL_TYPE_NEWDECIMAL, 0, 63, 4, "1.2300"}};
	if (!check(
			verify(c, scalar, ints),
			"integer widths, signedness, boolean, typed NULL and decimal scale reach the driver"))
		return false;
	if (!check(verify(c, scalar + " WHERE FALSE", ints, true),
			   "empty results retain logical column types and scale"))
		return false;
	if (!check(
			verify(c,
				   "SELECT '123456789012345678901234567890123456.78'::DECIMAL(38,2),"
				   "'-170141183460469231731687303715884105728'::HUGEINT,'"
				   "340282366920938463463374607431768211455'::UHUGEINT",
				   {{MYSQL_TYPE_NEWDECIMAL, 0, 63, 2, "123456789012345678901234567890123456.78"},
					{MYSQL_TYPE_NEWDECIMAL, 0, 63, 0, "-170141183460469231731687303715884105728"},
					{MYSQL_TYPE_NEWDECIMAL, UNSIGNED_FLAG, 63, 0,
					 "340282366920938463463374607431768211455"}}),
			"128-bit integers and wide decimals preserve exact digits"))
		return false;
	if (!check(verify(c,
					  "SELECT 1.5::FLOAT,'1.2345678901234567'::DOUBLE,DATE '2026-11-05',TIME "
					  "'12:34:56.123456',TIMESTAMP '2026-11-05 12:34:56.654321'",
					  {{MYSQL_TYPE_FLOAT, 0, 63, -1, "1.5"},
					   {MYSQL_TYPE_DOUBLE, 0, 63, -1, "1.2345678901234567"},
					   {MYSQL_TYPE_DATE, 0, 63, 0, "2026-11-05"},
					   {MYSQL_TYPE_TIME, 0, 63, 6, "12:34:56.123456"},
					   {MYSQL_TYPE_DATETIME, 0, 63, 6, "2026-11-05 12:34:56.654321"}}),
			   "floating-point precision and temporal types reach the driver"))
		return false;
	if (!check(
			verify(c,
				   "SELECT 'NaN'::DOUBLE,DATE 'infinity',TIMESTAMP '-infinity',DATE '10000-01-01'",
				   {{MYSQL_TYPE_VAR_STRING, 0, 45, 0, "nan"},
					{MYSQL_TYPE_VAR_STRING, 0, 45, 0, "infinity"},
					{MYSQL_TYPE_VAR_STRING, 0, 45, 0, "-infinity"},
					{MYSQL_TYPE_VAR_STRING, 0, 45, 0, "10000-01-01"}}),
			"unrepresentable numeric and temporal values use honest text metadata"))
		return false;
	if (!check(verify(c, "SELECT 1 AS dup,[2] AS nested,'text' AS dup,TRUE AS flag",
					  {{MYSQL_TYPE_LONG, 0, 63, 0, "1"},
					   {MYSQL_TYPE_VAR_STRING, 0, 45, 0, "[2]"},
					   {MYSQL_TYPE_VAR_STRING, 0, 45, 0, "text"},
					   {MYSQL_TYPE_TINY, 0, 63, 0, "1"}},
					  false, {"dup", "nested", "dup", "flag"}),
			   "a nested projection preserves neighboring scalar types and duplicate labels"))
		return false;
	if (!check(verify(c, "SELECT ''::VARCHAR,''::BLOB,NULL::BLOB",
					  {{MYSQL_TYPE_VAR_STRING, 0, 45, 0, ""},
					   {MYSQL_TYPE_LONG_BLOB, 0, 63, 0, ""},
					   {MYSQL_TYPE_LONG_BLOB, 0, 63, 0, nullptr}}),
			   "empty text, empty blob and SQL NULL remain distinct"))
		return false;
	{
		if (mysql_query(c, "SELECT from_hex('410042') AS b,'Grüße' AS v"))
			return false;
		std::unique_ptr<MYSQL_RES, decltype(&mysql_free_result)> r(mysql_store_result(c),
																   mysql_free_result);
		if (!r)
			return false;
		auto* fields = mysql_fetch_fields(r.get());
		auto row = mysql_fetch_row(r.get());
		auto* lengths = mysql_fetch_lengths(r.get());
		if (!check(
				row && fields[0].type == MYSQL_TYPE_LONG_BLOB && fields[0].charsetnr == 63 &&
					(fields[0].flags & BINARY_FLAG) && fields[0].length == 3 && lengths[0] == 3 &&
					std::memcmp(row[0], "A\0B", 3) == 0 && fields[1].charsetnr == 45 &&
					std::string(row[1], lengths[1]) == "Grüße",
				"binary embedded NUL and utf8mb4 text preserve bytes, character sets and lengths"))
			return false;
	}
	{
		const std::string huge(16777220, 'x');
		if (!check(verify(c, "SELECT repeat('x',16777220) AS large_value",
						  {{MYSQL_TYPE_VAR_STRING, 0, 45, 0, huge.c_str()}}),
				   "typed text rows remain correct across the 16 MiB packet boundary"))
			return false;
		std::string sql = "SELECT ";
		std::vector<Column> columns;
		for (int i = 0; i < 300; ++i) {
			if (i)
				sql += ",";
			sql += "1 AS c" + std::to_string(i);
			columns.push_back({MYSQL_TYPE_LONG, 0, 63, 0, "1"});
		}
		if (!check(verify(c, sql, columns),
				   "typed field packet sequence numbers wrap across more than 255 columns"))
			return false;
	}
	if (!check(query(c, "BEGIN") && verify(c, "SELECT 42", {{MYSQL_TYPE_LONG, 0, 63, 0, "42"}}) &&
				   (c->server_status & SERVER_STATUS_IN_TRANS) && query(c, "ROLLBACK") &&
				   !(c->server_status & SERVER_STATUS_IN_TRANS),
			   "typed results preserve transaction status through BEGIN and ROLLBACK"))
		return false;
	if (!check(
			query(c,
				  "CREATE OR REPLACE TABLE mysql_typed_returning(id INTEGER,nested INTEGER[])") &&
				verify(c, "INSERT INTO mysql_typed_returning VALUES(7,[2]) RETURNING id",
					   {{MYSQL_TYPE_LONG, 0, 63, 0, "7"}}),
			"scalar DML RETURNING exposes native metadata"))
		return false;
	const bool rejected =
		mysql_query(c, "INSERT INTO mysql_typed_returning VALUES(8,[3]) RETURNING nested") != 0 &&
		mysql_errno(c) == 1235;
	if (!check(rejected && cell(c, "SELECT COUNT(*) FROM mysql_typed_returning") == "1" &&
				   query(c, "DROP TABLE mysql_typed_returning"),
			   "unsupported DML RETURNING reports an error before changing data"))
		return false;
	return true;
}
bool run(Fixture& f) {
	if (!check(f.bootstrap(), "open private DuckDB listener for typed MySQL driver checks"))
		return false;
	if (!cases(f.duck))
		return false;
	if (!check(
			query(
				f.admin,
				"INSERT INTO mysql_servers(hostgroup_id,hostname,port) VALUES(19401,'127.0.0.1'," +
					std::to_string(f.duck_port) + ")") &&
				query(f.admin, "UPDATE mysql_users SET default_hostgroup=19401 WHERE "
							   "username='recovery_client'") &&
				query(f.admin, "LOAD MYSQL SERVERS TO RUNTIME") &&
				query(f.admin, "LOAD MYSQL USERS TO RUNTIME"),
			"route ordinary ProxySQL connections to the same instance's DuckDB backend"))
		return false;
	std::unique_ptr<MYSQL, decltype(&mysql_close)> front(
		connect("127.0.0.1", f.mysql_port, "recovery_client", "recovery_client"), mysql_close);
	if (!front || !cases(front.get()))
		return false;
	return true;
}
} // namespace
int main() {
	CommandLine cl;
	if (cl.getEnv())
		return EXIT_FAILURE;
	plan(NO_PLAN);
	{
		Fixture f(cl);
		f.complete = run(f);
		ok(f.complete, "typed MySQL direct and routed scenario completed");
	}
	return exit_status();
}
