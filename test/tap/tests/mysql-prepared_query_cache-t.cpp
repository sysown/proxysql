/**
 * MySQL binary result-cache prototype regression tests.
 * Exercises real COM_STMT_EXECUTE requests, including omitted type blocks.
 * Requires an isolated ProxySQL: flushes the shared cache and installs a test
 * query rule. No backend tables are needed.
 */
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <vector>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"

namespace {
MYSQL* rules_admin = nullptr;

// Restore runtime first, then any pending in-memory configuration separately.
// BAIL_OUT calls exit(), so use atexit rather than relying on stack unwinding.
void restore_query_rules() {
	if (!rules_admin) return;
	for (const char* sql : {
		"DELETE FROM mysql_query_rules",
		"INSERT INTO mysql_query_rules SELECT * FROM ps_cache_proto_runtime_rules",
		"DELETE FROM mysql_query_rules_fast_routing",
		"INSERT INTO mysql_query_rules_fast_routing SELECT * FROM ps_cache_proto_runtime_fast_rules",
		"LOAD MYSQL QUERY RULES TO RUNTIME",
		"DELETE FROM mysql_query_rules",
		"INSERT INTO mysql_query_rules SELECT * FROM ps_cache_proto_memory_rules",
		"DELETE FROM mysql_query_rules_fast_routing",
		"INSERT INTO mysql_query_rules_fast_routing SELECT * FROM ps_cache_proto_memory_fast_rules",
		"DROP TABLE ps_cache_proto_runtime_rules",
		"DROP TABLE ps_cache_proto_memory_rules",
		"DROP TABLE ps_cache_proto_runtime_fast_rules",
		"DROP TABLE ps_cache_proto_memory_fast_rules"}) {
		if (mysql_query(rules_admin, sql)) {
			fprintf(stderr, "Cannot restore query rules: %s: %s\n", sql, mysql_error(rules_admin));
			// Do not report a successful test or recursively invoke atexit.
			std::_Exit(EXIT_FAILURE);
		}
	}
	rules_admin = nullptr;
}

void query(MYSQL* mysql, const std::string& sql) {
	if (mysql_query(mysql, sql.c_str())) {
		BAIL_OUT("Query failed: %s: %s", sql.c_str(), mysql_error(mysql));
	}
}

long long scalar(MYSQL* mysql, const std::string& sql) {
	query(mysql, sql);
	MYSQL_RES* res = mysql_store_result(mysql);
	if (!res) BAIL_OUT("Missing scalar result: %s", mysql_error(mysql));
	MYSQL_ROW row = mysql_fetch_row(res);
	long long value = row && row[0] ? strtoll(row[0], nullptr, 10) : -1;
	mysql_free_result(res);
	return value;
}

long long hits(MYSQL* admin) {
	return scalar(admin, "SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='Query_Cache_count_GET_OK'");
}

long long inserts(MYSQL* admin) {
	return scalar(admin, "SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='Query_Cache_count_SET'");
}

bool prepared_cache_enabled(MYSQL* admin) {
	query(admin, "SELECT variable_value FROM global_variables WHERE variable_name='admin-version'");
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
	int major = 0, minor = 0;
	if (!row || !row[0] || sscanf(row[0], "%d.%d", &major, &minor) != 2)
		BAIL_OUT("Cannot determine ProxySQL build tier from admin-version");
	diag("Testing prepared-cache build gate on ProxySQL %s", row[0]);
	mysql_free_result(res);
	return major > 3 || (major == 3 && minor >= 1);
}

MYSQL* connect(const CommandLine& cl, bool admin = false, bool deprecate_eof = true) {
	MYSQL* mysql = mysql_init(nullptr);
	mysql->options.client_flag &= ~CLIENT_DEPRECATE_EOF;
	if (!mysql_real_connect(mysql, admin ? cl.admin_host : cl.host,
		admin ? cl.admin_username : cl.username, admin ? cl.admin_password : cl.password,
		nullptr, admin ? cl.admin_port : cl.port, nullptr, deprecate_eof ? CLIENT_DEPRECATE_EOF : 0)) {
		BAIL_OUT("Connect failed: %s", mysql_error(mysql));
	}
	return mysql;
}

MYSQL_STMT* prepare(MYSQL* mysql, const char* sql) {
	MYSQL_STMT* stmt = mysql_stmt_init(mysql);
	if (mysql_stmt_prepare(stmt, sql, strlen(sql))) BAIL_OUT("Prepare failed: %s", mysql_stmt_error(stmt));
	return stmt;
}

void bind(MYSQL_STMT* stmt, enum_field_types type, void* value, unsigned long* length = nullptr,
	my_bool* is_null = nullptr, bool is_unsigned = false) {
	MYSQL_BIND b {};
	b.buffer_type = type;
	b.buffer = value;
	b.length = length;
	b.buffer_length = length ? *length : 0;
	b.is_null = is_null;
	b.is_unsigned = is_unsigned;
	if (mysql_stmt_bind_param(stmt, &b)) BAIL_OUT("Bind failed: %s", mysql_stmt_error(stmt));
}

void execute(MYSQL_STMT* stmt, const std::string& expected, const char* label,
	bool expected_null = false, bool empty = false) {
	if (mysql_stmt_execute(stmt) || mysql_stmt_store_result(stmt)) {
		BAIL_OUT("%s: execute failed: %s", label, mysql_stmt_error(stmt));
	}
	char value[256] {};
	unsigned long length = 0;
	my_bool is_null = false;
	MYSQL_BIND result {};
	result.buffer_type = MYSQL_TYPE_STRING;
	result.buffer = value;
	result.buffer_length = sizeof(value);
	result.length = &length;
	result.is_null = &is_null;
	if (mysql_stmt_bind_result(stmt, &result)) BAIL_OUT("Result bind failed: %s", mysql_stmt_error(stmt));
	int rc = mysql_stmt_fetch(stmt);
	ok(empty ? rc == MYSQL_NO_DATA :
		(rc == 0 && bool(is_null) == expected_null && (expected_null || std::string(value, length) == expected)),
		"%s: expected value/NULL/row count", label);
	if (!empty && rc == 0) {
		if (mysql_stmt_fetch(stmt) != MYSQL_NO_DATA) BAIL_OUT("Unexpected extra row");
	}
	mysql_stmt_free_result(stmt);
}

void cached_repeat(MYSQL* admin, MYSQL_STMT* stmt, const std::string& expected, const char* label,
	bool expected_null = false, bool empty = false) {
	// First execute sends types, subsequent executes normally omit them. Warm both forms.
	execute(stmt, expected, label, expected_null, empty);
	execute(stmt, expected, label, expected_null, empty);
	long long before = hits(admin);
	long long backend_before = scalar(admin, "SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='Com_backend_stmt_execute'");
	execute(stmt, expected, label, expected_null, empty);
	ok(hits(admin) == before + 1, "%s: repeated binary execution hits cache", label);
	ok(scalar(admin, "SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='Com_backend_stmt_execute'") == backend_before,
		"%s: hit does not execute on backend", label);
}

void malformed_execute(MYSQL* mysql, MYSQL_STMT* stmt, std::vector<unsigned char> packet, const char* label) {
	// Dedicated plaintext test connection. The client library is deliberately
	// bypassed so it cannot repair missing type blocks before transmission.
	packet[0] = packet.size() - 4;
	packet[4] = 0x17;
	uint32_t id = stmt->stmt_id;
	memcpy(packet.data() + 5, &id, sizeof(id));
	packet[10] = 1;
	if (write(mysql->net.fd, packet.data(), packet.size()) != ssize_t(packet.size())) BAIL_OUT("Raw execute write failed");
	unsigned char header[4];
	if (recv(mysql->net.fd, header, 4, MSG_WAITALL) != 4) BAIL_OUT("Raw execute header read failed");
	size_t size = header[0] | (size_t(header[1]) << 8) | (size_t(header[2]) << 16);
	if (size < 3 || size > 1024) BAIL_OUT("Unexpected raw execute response length");
	std::vector<unsigned char> response(size);
	if (recv(mysql->net.fd, response.data(), size, MSG_WAITALL) != ssize_t(size)) BAIL_OUT("Raw execute response read failed");
	ok(response[0] == 0xff && (response[1] | (unsigned(response[2]) << 8)) == 1210, "%s: malformed execute rejected", label);
}

// These are protocol correctness fixes, not PROXYSQL31 cache features.
void check_execute_protocol(const CommandLine& cl, MYSQL* admin, MYSQL* mysql) {
	int integer = 1065353216; // Same wire bytes as float 1.0.
	float floating = 1.0f;
	// No cache rule matches this SQL: retained types must work on the backend.
	const char* sql = "SELECT /* ps_type_proto */ CAST(? AS CHAR)";
	MYSQL_STMT* first = prepare(mysql, sql);
	MYSQL_STMT* second = prepare(mysql, sql);
	bind(first, MYSQL_TYPE_FLOAT, &floating);
	execute(first, "1", "FLOAT parameter on every tier");
	bind(second, MYSQL_TYPE_LONG, &integer);
	execute(second, "1065353216", "Second handle has independent LONG type");
	execute(first, "1", "First handle retains FLOAT with omitted types");
	unsigned int unsigned_value = 0xffffffffU;
	bind(first, MYSQL_TYPE_LONG, &unsigned_value, nullptr, nullptr, true);
	execute(first, "4294967295", "Unsigned parameter on every tier");
	execute(second, "1065353216", "Other handle retains signed LONG");
	execute(first, "4294967295", "First handle retains unsigned LONG with omitted types");
	mysql_stmt_close(first);
	mysql_stmt_close(second);

	MYSQL* raw = connect(cl);
	timeval read_timeout {5, 0};
	setsockopt(raw->net.fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));
	MYSQL_STMT* raw_stmt = prepare(raw, "SELECT /* ps_cache_proto */ CAST(? AS CHAR)");
	const long long before_hits = hits(admin), before_inserts = inserts(admin);
	malformed_execute(raw, raw_stmt, std::vector<unsigned char>(20, 0), "missing retained types");
	std::vector<unsigned char> truncated(17, 0);
	truncated[15] = 1; truncated[16] = MYSQL_TYPE_LONG;
	malformed_execute(raw, raw_stmt, truncated, "truncated explicit types");
	std::vector<unsigned char> bad_value(19, 0);
	bad_value[15] = 1; bad_value[16] = MYSQL_TYPE_STRING; bad_value[18] = 100;
	malformed_execute(raw, raw_stmt, bad_value, "invalid value length on backend miss");
	ok(hits(admin) == before_hits && inserts(admin) == before_inserts, "malformed requests do not hit or populate cache");
	bind(raw_stmt, MYSQL_TYPE_LONG, &integer);
	execute(raw_stmt, "1065353216", "valid execute after malformed packets");
	mysql_stmt_close(raw_stmt);
	mysql_close(raw);
}
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	plan(NO_PLAN);
	MYSQL* admin = connect(cl, true);
	// Materialize the current runtime snapshot before copying its SQLite table.
	scalar(admin, "SELECT count(*) FROM runtime_mysql_query_rules");
	scalar(admin, "SELECT count(*) FROM runtime_mysql_query_rules_fast_routing");
	query(admin, "CREATE TEMPORARY TABLE ps_cache_proto_memory_rules AS SELECT * FROM mysql_query_rules");
	query(admin, "CREATE TEMPORARY TABLE ps_cache_proto_runtime_rules AS SELECT * FROM runtime_mysql_query_rules");
	query(admin, "CREATE TEMPORARY TABLE ps_cache_proto_memory_fast_rules AS SELECT * FROM mysql_query_rules_fast_routing");
	query(admin, "CREATE TEMPORARY TABLE ps_cache_proto_runtime_fast_rules AS SELECT * FROM runtime_mysql_query_rules_fast_routing");
	if (std::atexit(restore_query_rules) != 0) BAIL_OUT("Cannot register query-rule cleanup");
	rules_admin = admin;
	// CI installs lower-numbered SELECT routing rules with apply=1. Remove
	// them while testing so our cache/error rule is actually evaluated.
	// Only memory/runtime are modified; never persist this fixture to disk.
	query(admin, "DELETE FROM mysql_query_rules");
	query(admin, "DELETE FROM mysql_query_rules_fast_routing");
	query(admin, "INSERT INTO mysql_query_rules(rule_id,active,match_pattern,cache_ttl,cache_empty_result,apply) "
		"VALUES(971003,1,'^SELECT /[*] ps_cache_proto [*]/',60000,1,1)");
	query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	MYSQL* mysql = connect(cl);
	const bool cache_enabled = prepared_cache_enabled(admin);
	query(admin, "PROXYSQL FLUSH QUERY CACHE");
	const char* text_sql = "SELECT /* ps_cache_proto */ 7319";
	ok(scalar(mysql, text_sql) == 7319, "Text query returns its value on every tier");
	const long long text_hits = hits(admin);
	ok(scalar(mysql, text_sql) == 7319, "Repeated text query returns its value");
	ok(hits(admin) == text_hits + 1, "Text-protocol caching remains enabled on every tier");
	check_execute_protocol(cl, admin, mysql);
	query(admin, "PROXYSQL FLUSH QUERY CACHE");
	if (!cache_enabled) {
		MYSQL_STMT* uncached = prepare(mysql, "SELECT /* ps_cache_proto */ ?");
		int value = 7319;
		bind(uncached, MYSQL_TYPE_LONG, &value);
		const long long h = hits(admin), s = inserts(admin);
		const long long gets = scalar(admin, "SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='Query_Cache_count_GET'");
		const long long b = scalar(admin, "SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='Com_backend_stmt_execute'");
		for (int i = 0; i < 3; ++i) execute(uncached, "7319", "Stable-tier prepared execution");
		ok(scalar(admin, "SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='Query_Cache_count_GET'") == gets,
			"Without PROXYSQL31, prepared executions do not look up the cache");
		ok(hits(admin) == h, "Without PROXYSQL31, prepared executions do not hit the cache");
		ok(inserts(admin) == s, "Without PROXYSQL31, prepared executions do not populate the cache");
		ok(scalar(admin, "SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='Com_backend_stmt_execute'") == b + 3,
			"Without PROXYSQL31, all prepared executions reach the backend");
		mysql_stmt_close(uncached);
		mysql_close(mysql);
		restore_query_rules();
		mysql_close(admin);
		return exit_status();
	}
	// These locking clauses evade the legacy end-of-string heuristic. Neither
	// the first execution nor a repeat may be admitted to the prepared cache.
	for (const std::string& suffix : {
		std::string(" FOR UPDATE;"),
		std::string(" FOR UPDATE /*") + std::string(160, 'x') + "*/",
		std::string(" FOR\nUPDATE;"),
		std::string(" FOR/**/UPDATE;"),
		std::string(" LOCK IN SHARE MODE;"),
		std::string(" /*!50000 FOR UPDATE */")}) {
		const std::string sql = "SELECT /* ps_cache_proto */ 23" + suffix;
		MYSQL_STMT* locking = prepare(mysql, sql.c_str());
		const long long h = hits(admin), s = inserts(admin);
		const long long b = scalar(admin, "SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='Com_backend_stmt_execute'");
		execute(locking, "23", "locking SELECT first execution");
		execute(locking, "23", "locking SELECT repeat");
		ok(hits(admin) == h && inserts(admin) == s, "Locking clause bypasses cache: %s", suffix.c_str());
		ok(scalar(admin, "SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='Com_backend_stmt_execute'") == b + 2,
			"Both locking SELECT executions reach the backend");
		mysql_stmt_close(locking);
	}
	// A normal parameterized read can depend on tracked state without naming
	// a session variable. FROM_UNIXTIME must not reuse another time zone's row.
	MYSQL* tz1 = connect(cl);
	MYSQL* tz2 = connect(cl);
	query(tz1, "SET time_zone='+00:00'");
	query(tz2, "SET time_zone='+01:00'");
	// MySQL and MariaDB expose different fractional-second metadata for a
	// parameterized FROM_UNIXTIME; use a fixed format to test time zones only.
	const char* timezone_sql = "SELECT /* ps_cache_proto */ DATE_FORMAT(FROM_UNIXTIME(?), '%Y-%m-%d %H:%i:%s')";
	MYSQL_STMT* utc = prepare(tz1, timezone_sql);
	MYSQL_STMT* east = prepare(tz2, timezone_sql);
	int epoch = 0;
	bind(utc, MYSQL_TYPE_LONG, &epoch);
	bind(east, MYSQL_TYPE_LONG, &epoch);
	cached_repeat(admin, utc, "1970-01-01 00:00:00", "UTC partition");
	cached_repeat(admin, east, "1970-01-01 01:00:00", "Different-session time zone partition");
	query(tz1, "SET time_zone='+02:00'");
	cached_repeat(admin, utc, "1970-01-01 02:00:00", "Changed time zone on existing statement");
	query(tz2, "SET time_zone='+02:00'");
	long long shared_hits = hits(admin);
	execute(east, "1970-01-01 02:00:00", "Equivalent tracked state shares entries");
	ok(hits(admin) == shared_hits + 1, "Equivalent tracked state shares the warmed entry");
	// SQL modes also change ordinary expression semantics at execution time.
	query(tz1, "SET sql_mode=''");
	MYSQL_STMT* mode = prepare(tz1, "SELECT /* ps_cache_proto */ CAST(? AS UNSIGNED)-1");
	int one = 1; bind(mode, MYSQL_TYPE_LONG, &one);
	cached_repeat(admin, mode, "0", "Default subtraction mode");
	query(tz1, "SET sql_mode='NO_UNSIGNED_SUBTRACTION'");
	long long mode_hits = hits(admin);
	execute(mode, "0", "Changed sql_mode must miss even when row bytes coincide");
	ok(hits(admin) == mode_hits, "sql_mode partitions prepared cache identity");
	// Result encoding must not leak across sessions either.
	query(tz1, "SET character_set_results=utf8mb4");
	MYSQL_STMT* encoding = prepare(tz1, "SELECT /* ps_cache_proto */ CONVERT(0xC3A9 USING utf8mb4)");
	cached_repeat(admin, encoding, std::string("\xC3\xA9", 2), "UTF-8 result encoding");
	query(tz1, "SET character_set_results=latin1");
	cached_repeat(admin, encoding, std::string("\xE9", 1), "Changed result encoding");
	for (MYSQL_STMT* s : {utc, east, mode, encoding}) mysql_stmt_close(s);
	mysql_close(tz1); mysql_close(tz2);
	MYSQL_STMT* stmt = prepare(mysql, "SELECT /* ps_cache_proto */ CAST(? AS CHAR)");
	int integer = 1065353216; // Same wire bytes as float 1.0.
	bind(stmt, MYSQL_TYPE_LONG, &integer);
	cached_repeat(admin, stmt, "1065353216", "integer parameter");

	float floating = 1.0f;
	bind(stmt, MYSQL_TYPE_FLOAT, &floating);
	cached_repeat(admin, stmt, "1", "type change with identical value bytes");

	// Two client handles share a global statement, but have independent retained types.
	MYSQL_STMT* other = prepare(mysql, "SELECT /* ps_cache_proto */ CAST(? AS CHAR)");
	bind(other, MYSQL_TYPE_LONG, &integer);
	cached_repeat(admin, other, "1065353216", "second client statement");
	execute(stmt, "1", "first statement retains FLOAT after second statement");
	query(admin, "PROXYSQL FLUSH QUERY CACHE");
	execute(stmt, "1", "retained FLOAT also works on backend miss");

	unsigned int unsigned_value = 0xffffffffU;
	bind(stmt, MYSQL_TYPE_LONG, &unsigned_value, nullptr, nullptr, true);
	cached_repeat(admin, stmt, "4294967295", "retained unsigned type");
	query(admin, "PROXYSQL FLUSH QUERY CACHE");
	execute(stmt, "4294967295", "unsigned type also survives backend miss");

	std::string text("a\0b", 3);
	unsigned long length = text.size();
	my_bool null_value = false;
	bind(stmt, MYSQL_TYPE_STRING, &text[0], &length, &null_value);
	cached_repeat(admin, stmt, text, "embedded NUL parameter");
	length = 0;
	cached_repeat(admin, stmt, "", "empty string parameter");
	null_value = true;
	cached_repeat(admin, stmt, "", "NULL parameter", true);
	null_value = false;

	bind(stmt, MYSQL_TYPE_STRING, &text[0], &length);
	long long before_hits = hits(admin), before_inserts = inserts(admin);
	if (mysql_stmt_send_long_data(stmt, 0, "long-A", 6)) BAIL_OUT("Send long data failed");
	execute(stmt, "long-A", "LongData A");
	if (mysql_stmt_send_long_data(stmt, 0, "long-B", 6)) BAIL_OUT("Send long data failed");
	execute(stmt, "long-B", "LongData B with identical execute payload");
	ok(hits(admin) == before_hits && inserts(admin) == before_inserts, "LongData bypasses lookup and insertion");
	cached_repeat(admin, stmt, "", "normal execution after LongData");
	before_hits = hits(admin);
	before_inserts = inserts(admin);
	if (mysql_stmt_send_long_data(stmt, 0, "", 0)) BAIL_OUT("Empty LongData failed");
	execute(stmt, "", "zero-length LongData");
	ok(hits(admin) == before_hits && inserts(admin) == before_inserts, "even empty LongData bypasses cache");
	if (mysql_stmt_send_long_data(stmt, 0, "discard", 7) || mysql_stmt_reset(stmt)) BAIL_OUT("Reset failed");
	cached_repeat(admin, stmt, "", "reset clears LongData");
	if (mysql_stmt_send_long_data(stmt, 0, "discard", 7)) BAIL_OUT("LongData before rejection failed");
	query(admin, "UPDATE mysql_query_rules SET error_msg='prototype rejection' WHERE rule_id=971003");
	query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	ok(mysql_stmt_execute(stmt) != 0 && mysql_stmt_errno(stmt) == 1148, "rule rejects execute with pending LongData");
	query(admin, "UPDATE mysql_query_rules SET error_msg=NULL WHERE rule_id=971003");
	query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	query(admin, "PROXYSQL FLUSH QUERY CACHE");
	execute(stmt, "", "rejected execution consumes LongData");

	MYSQL_TIME timestamp {};
	timestamp.year = 2026; timestamp.month = 9; timestamp.day = 13;
	timestamp.hour = 12; timestamp.minute = 34; timestamp.second = 56;
	timestamp.time_type = MYSQL_TIMESTAMP_DATETIME;
	bind(stmt, MYSQL_TYPE_DATETIME, &timestamp);
	cached_repeat(admin, stmt, "2026-09-13 12:34:56", "temporal parameter");

	MYSQL_STMT* many = prepare(mysql, "SELECT /* ps_cache_proto */ CONCAT(?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, 'null'))");
	MYSQL_BIND parameters[9] {};
	int values[9] {1,2,3,4,5,6,7,8,9};
	my_bool last_null = true;
	for (int i = 0; i < 9; ++i) {
		parameters[i].buffer_type = MYSQL_TYPE_LONG;
		parameters[i].buffer = &values[i];
	}
	parameters[8].is_null = &last_null;
	if (mysql_stmt_bind_param(many, parameters)) BAIL_OUT("Multi-parameter bind failed");
	cached_repeat(admin, many, "12345678null", "two-byte NULL bitmap");
	last_null = false;
	cached_repeat(admin, many, "123456789", "last NULL bit changes");

	MYSQL_STMT* zero = prepare(mysql, "SELECT /* ps_cache_proto */ 17");
	query(mysql, "SELECT /* ps_cache_proto */ 17");
	mysql_free_result(mysql_store_result(mysql));
	before_hits = hits(admin);
	execute(zero, "17", "binary result does not replay text entry");
	ok(hits(admin) == before_hits, "text and binary entries are separate");
	cached_repeat(admin, zero, "17", "zero parameters");
	query(admin, "UPDATE mysql_query_rules SET gtid_from_hostgroup=0 WHERE rule_id=971003");
	query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	before_hits = hits(admin); before_inserts = inserts(admin);
	execute(zero, "17", "GTID constrained read");
	ok(hits(admin) == before_hits && inserts(admin) == before_inserts, "gtid_from_hostgroup bypasses binary cache");
	query(admin, "UPDATE mysql_query_rules SET gtid_from_hostgroup=NULL WHERE rule_id=971003");
	query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	MYSQL* cursor_conn = connect(cl);
	MYSQL_STMT* cursor = prepare(cursor_conn, "SELECT /* ps_cache_proto */ 17");
	unsigned long cursor_type = CURSOR_TYPE_READ_ONLY;
	if (mysql_stmt_attr_set(cursor, STMT_ATTR_CURSOR_TYPE, &cursor_type)) BAIL_OUT("Cursor attribute failed");
	before_hits = hits(admin); before_inserts = inserts(admin);
	// Existing ProxySQL cursor handling is not part of this prototype. Some
	// connectors reject its noncursor response; only assert cache bypass.
	if (mysql_stmt_execute(cursor) == 0) mysql_stmt_store_result(cursor);
	ok(hits(admin) == before_hits && inserts(admin) == before_inserts, "cursor execution bypasses cache");
	mysql_stmt_close(cursor);
	mysql_close(cursor_conn);

	// Different client statement IDs and both binary EOF encodings share entries.
	MYSQL* classic = connect(cl, false, false);
	MYSQL_STMT* dummy = prepare(classic, "SELECT 0");
	MYSQL_STMT* classic_zero = prepare(classic, "SELECT /* ps_cache_proto */ 17");
	before_hits = hits(admin);
	execute(classic_zero, "17", "cross-connection classic EOF hit");
	ok(hits(admin) == before_hits + 1, "different client handle hits existing binary entry");
	query(admin, "PROXYSQL FLUSH QUERY CACHE");
	execute(classic_zero, "17", "populate classic EOF entry");
	before_hits = hits(admin);
	execute(zero, "17", "classic EOF entry replayed to modern client");
	ok(hits(admin) == before_hits + 1, "binary entry supports reverse EOF conversion");
	for (MYSQL_STMT* s : {dummy, classic_zero}) mysql_stmt_close(s);
	mysql_close(classic);
	MYSQL_STMT* literal = prepare(mysql, "SELECT /* ps_cache_proto */ 18");
	cached_repeat(admin, literal, "18", "embedded SQL literal preserved");

	// MySQL 5.7 requires FROM DUAL for a tableless SELECT with WHERE.
	MYSQL_STMT* empty = prepare(mysql, "SELECT /* ps_cache_proto */ 19 FROM DUAL WHERE 0");
	cached_repeat(admin, empty, "", "empty result", false, true);
	query(admin, "UPDATE mysql_query_rules SET cache_empty_result=0 WHERE rule_id=971003");
	query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	query(admin, "PROXYSQL FLUSH QUERY CACHE");
	before_inserts = inserts(admin);
	execute(empty, "", "empty admission disabled", false, true);
	execute(empty, "", "empty admission still disabled", false, true);
	ok(inserts(admin) == before_inserts, "cache_empty_result=0 prevents empty insertion");
	cached_repeat(admin, zero, "17", "nonempty admission still works");

	query(admin, "UPDATE mysql_query_rules SET active=0 WHERE rule_id=971003");
	query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	before_hits = hits(admin); before_inserts = inserts(admin);
	execute(zero, "17", "cache rule disabled");
	ok(hits(admin) == before_hits && inserts(admin) == before_inserts, "disabled cache rule bypasses warmed binary entry");
	query(admin, "UPDATE mysql_query_rules SET active=1,cache_empty_result=1 WHERE rule_id=971003");
	query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	long long warning_policy = scalar(admin, "SELECT variable_value FROM global_variables WHERE variable_name='mysql-query_cache_handle_warnings'");
	query(admin, "SET mysql-query_cache_handle_warnings=0");
	query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	MYSQL_STMT* warning = prepare(mysql, "SELECT /* ps_cache_proto */ CAST('not-a-number' AS UNSIGNED)");
	before_hits = hits(admin); before_inserts = inserts(admin);
	execute(warning, "0", "warning result");
	execute(warning, "0", "warning result repeated");
	ok(hits(admin) == before_hits && inserts(admin) == before_inserts, "warning policy prevents caching");
	query(admin, "SET mysql-query_cache_handle_warnings=1");
	query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	cached_repeat(admin, warning, "0", "warning admission enabled");
	query(admin, "SET mysql-query_cache_handle_warnings=" + std::to_string(warning_policy));
	query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL_STMT* error = prepare(mysql, "SELECT /* ps_cache_proto */ (SELECT 1 UNION ALL SELECT 2)");
	before_hits = hits(admin); before_inserts = inserts(admin);
	for (int i = 0; i < 2; ++i) {
		int rc = mysql_stmt_execute(error);
		if (rc == 0) rc = mysql_stmt_store_result(error); // ERR can follow column definitions.
		ok(rc != 0 && mysql_stmt_errno(error) == 1242, "execution error is returned normally");
		mysql_stmt_free_result(error);
	}
	ok(hits(admin) == before_hits && inserts(admin) == before_inserts, "errors are not cached");

	query(admin, "UPDATE mysql_query_rules SET cache_ttl=100 WHERE rule_id=971003");
	query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	MYSQL_STMT* expiry = prepare(mysql, "SELECT /* ps_cache_proto */ 971003");
	execute(expiry, "971003", "Warm fresh entry for TTL expiration");
	before_hits = hits(admin);
	usleep(300000);
	execute(expiry, "971003", "TTL expiration");
	ok(hits(admin) == before_hits, "expired binary result is a miss");
	mysql_stmt_close(expiry);
	query(admin, "UPDATE mysql_query_rules SET cache_ttl=60000 WHERE rule_id=971003");
	query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	query(mysql, "BEGIN");
	before_hits = hits(admin);
	execute(zero, "17", "transaction execution");
	ok(hits(admin) == before_hits, "active transactions bypass prototype cache");
	query(mysql, "ROLLBACK");
	query(mysql, "SET autocommit=0");
	before_hits = hits(admin);
	execute(zero, "17", "autocommit disabled");
	ok(hits(admin) == before_hits, "autocommit disabled bypasses prototype cache");
	query(mysql, "SET autocommit=1");

	// Closing another handle also drops shared decoded metadata. The remaining
	// handle must still know its effective types on a miss.
	mysql_stmt_close(other);
	query(admin, "PROXYSQL FLUSH QUERY CACHE");
	execute(stmt, "2026-09-13 12:34:56", "types survive closing another client handle");
	for (MYSQL_STMT* s : {stmt, many, zero, literal, empty, warning, error}) mysql_stmt_close(s);
	mysql_close(mysql);
	restore_query_rules();
	mysql_close(admin);
	return exit_status();
}
