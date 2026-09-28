/**
 * Extended-protocol result cache regression tests. Requires an isolated
 * ProxySQL instance: installs a test rule and flushes its PostgreSQL cache.
 * libpq performs authentication; raw protocol messages exercise response
 * framing, parameter encodings and exchanges libpq does not expose directly.
 */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include "libpq-fe.h"
#include "tap.h"
#include "command_line.h"

namespace {
CommandLine cl;
using Bytes = std::string;
void u16(Bytes& b, uint16_t n) { n = htons(n); b.append(reinterpret_cast<char*>(&n), 2); }
void u32(Bytes& b, uint32_t n) { n = htonl(n); b.append(reinterpret_cast<char*>(&n), 4); }
uint32_t read32(const char* p) { uint32_t n; memcpy(&n, p, 4); return ntohl(n); }
Bytes str(const std::string& s) { return s + '\0'; }
Bytes msg(char type, const Bytes& body = {}) {
	Bytes b(1, type); u32(b, body.size() + 4); return b + body;
}
PGconn* connect(bool admin = false, const char* database = nullptr) {
	std::string port = std::to_string(admin ? cl.pgsql_admin_port : cl.pgsql_port);
	const char* keys[] = {"host", "port", "user", "password", "dbname", "sslmode", "connect_timeout", nullptr};
	const char* vals[] = {admin ? cl.pgsql_admin_host : cl.pgsql_host, port.c_str(),
		admin ? cl.admin_username : cl.pgsql_username, admin ? cl.admin_password : cl.pgsql_password,
		admin ? "postgres" : (database ? database : (getenv("PGDATABASE") ? getenv("PGDATABASE") : "postgres")), "disable", "5", nullptr};
	PGconn* c = PQconnectdbParams(keys, vals, 0);
	if (PQstatus(c) != CONNECTION_OK) BAIL_OUT("Connect: %s", PQerrorMessage(c));
	if (!admin) fcntl(PQsocket(c), F_SETFL, fcntl(PQsocket(c), F_GETFL) & ~O_NONBLOCK);
	timeval tv {5, 0}; setsockopt(PQsocket(c), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return c;
}
PGresult* query(PGconn* c, const std::string& sql) {
	PGresult* r = PQexec(c, sql.c_str());
	if (PQresultStatus(r) != PGRES_COMMAND_OK && PQresultStatus(r) != PGRES_TUPLES_OK)
		BAIL_OUT("Query %s: %s", sql.c_str(), PQerrorMessage(c));
	return r;
}
void command(PGconn* c, const std::string& sql) { PQclear(query(c, sql)); }
long long metric(PGconn* admin, const char* name) {
	PGresult* r = query(admin, std::string("SELECT Variable_Value FROM stats_pgsql_global WHERE Variable_Name='") + name + "'");
	if (PQntuples(r) != 1) BAIL_OUT("Missing metric %s", name);
	long long v = strtoll(PQgetvalue(r, 0, 0), nullptr, 10); PQclear(r); return v;
}
long long hits(PGconn* a) { return metric(a, "Query_Cache_count_GET_OK"); }
bool prepared_cache_enabled(PGconn* admin) {
	PGresult* r = query(admin, "SELECT variable_value FROM global_variables WHERE variable_name='admin-version'");
	int major = 0, minor = 0;
	if (PQntuples(r) != 1 || sscanf(PQgetvalue(r, 0, 0), "%d.%d", &major, &minor) != 2)
		BAIL_OUT("Cannot determine ProxySQL build tier from admin-version");
	diag("Testing prepared-cache build gate on ProxySQL %s", PQgetvalue(r, 0, 0));
	PQclear(r);
	return major > 3 || (major == 3 && minor >= 1);
}
long long backend_queries(PGconn* a) {
	PGresult* r = query(a, "SELECT COALESCE(SUM(Queries),0) FROM stats_pgsql_connection_pool");
	long long v = strtoll(PQgetvalue(r, 0, 0), nullptr, 10); PQclear(r); return v;
}
Bytes recv_bytes(int fd, size_t n) {
	Bytes b(n, '\0'); size_t off = 0;
	while (off < n) { ssize_t r = recv(fd, &b[off], n-off, 0); if (r <= 0) BAIL_OUT("Socket read failed"); off += r; }
	return b;
}
struct Reply {
	Bytes types;
	std::vector<Bytes> rows;
	std::vector<bool> nulls;
	std::vector<uint16_t> formats;
	char state = 0;
};
Reply send_extended_messages_and_read_reply(PGconn* c, const Bytes& bytes) {
	size_t off = 0;
	while (off < bytes.size()) { ssize_t n = send(PQsocket(c), bytes.data()+off, bytes.size()-off, MSG_NOSIGNAL);
		if (n <= 0) BAIL_OUT("Socket write failed"); off += n; }
	Reply r;
	for (;;) {
		Bytes h = recv_bytes(PQsocket(c), 5);
		uint32_t len = read32(h.data()+1);
		if (len < 4 || len > 32*1024*1024) BAIL_OUT("Bad response length");
		Bytes body = recv_bytes(PQsocket(c), len-4);
		r.types += h[0];
		if (h[0] == 'T') {
			if (body.size() < 2 || body[0] != 0 || body[1] != 1) BAIL_OUT("Expected one described column");
			size_t end = body.find('\0', 2);
			if (end == Bytes::npos || end + 19 != body.size()) BAIL_OUT("Bad RowDescription");
			uint16_t format; memcpy(&format, body.data() + end + 17, 2); r.formats.push_back(ntohs(format));
		}
		if (h[0] == 'D') {
			if (body.size() < 6 || body[0] != 0 || body[1] != 1) BAIL_OUT("Expected one column");
			uint32_t size = read32(body.data()+2);
			r.nulls.push_back(size == UINT32_MAX);
			r.rows.push_back(size == UINT32_MAX ? Bytes() : body.substr(6, size));
		}
		if (h[0] == 'Z') { r.state = body.at(0); return r; }
	}
}
Bytes parse(const std::string& name, const std::string& sql, uint32_t oid = 25) {
	Bytes b = str(name) + str(sql); u16(b, 1); u32(b, oid); return msg('P', b);
}
void prepare(PGconn* c, const std::string& name, const std::string& sql, uint32_t oid = 25) {
	Reply r = send_extended_messages_and_read_reply(c, parse(name, sql, oid) + msg('S'));
	if (r.types != "1Z") BAIL_OUT("Prepare response: %s", r.types.c_str());
}
Bytes execution(const std::string& name, const Bytes& value, bool describe = true,
	int param_format = 0, int result_format = 0, bool is_null = false, uint32_t max_rows = 0) {
	Bytes b = str("") + str(name);
	u16(b, 1); u16(b, param_format); u16(b, 1);
	u32(b, is_null ? UINT32_MAX : value.size()); if (!is_null) b += value;
	u16(b, 1); u16(b, result_format);
	Bytes e = str(""); u32(e, max_rows);
	return msg('B', b) + (describe ? msg('D', "P" + str("")) : Bytes()) + msg('E', e);
}
void row(const Reply& r, const Bytes& value, bool describe = true, bool is_null = false, int format = 0) {
	ok(r.types == (describe ? "2TDCZ" : "2DCZ") && r.state == 'I',
		"Execution response has exactly one BindComplete, expected metadata, row, command and idle ReadyForQuery (%s)", r.types.c_str());
	ok(r.rows.size() == 1 && r.nulls[0] == is_null && (is_null || r.rows[0] == value), "Returned value and NULL marker match");
	ok(describe ? (r.formats == std::vector<uint16_t>{uint16_t(format)}) : r.formats.empty(), "RowDescription has requested format or is absent");
}
void cached(PGconn* a, PGconn* c, const Bytes& request, const Bytes& value,
	bool describe = true, bool is_null = false, int format = 0) {
	row(send_extended_messages_and_read_reply(c, request + msg('S')), value, describe, is_null, format);
	long long h = hits(a), b = backend_queries(a);
	row(send_extended_messages_and_read_reply(c, request + msg('S')), value, describe, is_null, format);
	ok(hits(a) == h + 1, "Repeated execution hits cache");
	ok(backend_queries(a) == b, "Hit executes no backend query");
}
}
int main() {
	if (cl.getEnv()) return exit_status();
	plan(NO_PLAN);
	PGconn* admin = connect(true);
	command(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=971004");
	command(admin, "INSERT INTO pgsql_query_rules(rule_id,active,match_pattern,cache_ttl,apply) VALUES(971004,1,'^SELECT /[*]ext_cache[*]/',60000,1)");
	command(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	command(admin, "PROXYSQL FLUSH PGSQL QUERY CACHE");
	PGconn* c = connect();
	const bool cache_enabled = prepared_cache_enabled(admin);
	const Bytes simple = msg('Q', str("SELECT /*ext_cache*/ 7319"));
	auto check_simple = [&]() {
		const Reply r = send_extended_messages_and_read_reply(c, simple);
		ok(r.types == "TDCZ" && r.state == 'I' && r.rows == std::vector<Bytes>{"7319"},
			"Simple query returns its value and correct framing on every tier");
	};
	check_simple();
	const long long simple_hits = hits(admin);
	check_simple();
	ok(hits(admin) == simple_hits + 1, "Simple-query caching remains enabled on every tier");
	const char* sql = "SELECT /*ext_cache*/ $1::text";
	prepare(c, "first", sql);
	if (!cache_enabled) {
		const long long h = hits(admin), s = metric(admin, "Query_Cache_count_SET"), b = backend_queries(admin);
		const long long gets = metric(admin, "Query_Cache_count_GET");
		for (int i = 0; i < 3; ++i)
			row(send_extended_messages_and_read_reply(c, execution("first", "hello") + msg('S')), "hello");
		ok(metric(admin, "Query_Cache_count_GET") == gets, "Without PROXYSQL31, extended executions do not look up the cache");
		ok(hits(admin) == h, "Without PROXYSQL31, extended executions do not hit the cache");
		ok(metric(admin, "Query_Cache_count_SET") == s, "Without PROXYSQL31, extended executions do not populate the cache");
		ok(backend_queries(admin) == b + 3, "Without PROXYSQL31, all extended executions reach the backend");
		PQfinish(c);
		command(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=971004");
		command(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
		PQfinish(admin);
		return exit_status();
	}
	row(send_extended_messages_and_read_reply(c, execution("first", "hello") + msg('S')), "hello");
	long long before = hits(admin);
	row(send_extended_messages_and_read_reply(c, execution("first", "hello") + msg('S')), "hello");
	ok(hits(admin) == before + 1, "Repeated extended execution hits the cache");
	PGconn* other = connect(); prepare(other, "different_name", sql);
	before = hits(admin);
	row(send_extended_messages_and_read_reply(other, execution("different_name", "hello") + msg('S')), "hello");
	ok(hits(admin) == before + 1, "Cache entry shared across connections and statement names");
	ok(metric(admin, "Query_Cache_count_SET") > 0, "Extended execution populated the cache");
	// Removing response-shape discrimination would replay an unsolicited T.
	cached(admin, c, execution("first", "hello", false), "hello", false);
	// Omitting parameter bytes, NULL lengths or formats from the key would
	// conflate these distinct executions or return the wrong wire encoding.
	cached(admin, c, execution("first", "different"), "different");
	cached(admin, c, execution("first", ""), "");
	cached(admin, c, execution("first", "", true, 0, 0, true), "", true, true);
	prepare(c, "integer", "SELECT /*ext_cache*/ $1::int4", 23);
	Bytes integer; u32(integer, 42);
	cached(admin, c, execution("integer", "42"), "42");
	cached(admin, c, execution("integer", "42", true, 0, 1), integer, true, false, 1);
	cached(admin, c, execution("integer", integer, true, 1, 0), "42");
	cached(admin, c, execution("integer", integer, true, 1, 1), integer, true, false, 1);
	// Identical SQL and Bind bytes, different Parse type OIDs.
	prepare(c, "inttype", "SELECT /*ext_cache*/ pg_typeof($1)::text", 23);
	prepare(c, "bigtype", "SELECT /*ext_cache*/ pg_typeof($1)::text", 20);
	cached(admin, c, execution("inttype", "42"), "integer");
	cached(admin, c, execution("bigtype", "42"), "bigint");
	// Explicitly set session values must partition cached output.
	prepare(c, "date", "SELECT /*ext_cache*/ $1::date", 1082);
	Reply r = send_extended_messages_and_read_reply(c, msg('Q', str("SET DateStyle='ISO, MDY'")));
	ok(r.types == "SCZ" || r.types == "CZ", "Set DateStyle");
	cached(admin, c, execution("date", "2024-03-04"), "2024-03-04");
	send_extended_messages_and_read_reply(c, msg('Q', str("SET DateStyle='SQL, DMY'")));
	cached(admin, c, execution("date", "2024-03-04"), "04/03/2024");
	prepare(c, "schema", "SELECT /*ext_cache*/ current_schema()::text || $1");
	send_extended_messages_and_read_reply(c, msg('Q', str("SET search_path=public")));
	cached(admin, c, execution("schema", "!"), "public!");
	send_extended_messages_and_read_reply(c, msg('Q', str("SET search_path=pg_catalog")));
	cached(admin, c, execution("schema", "!"), "pg_catalog!");
	// Fresh connection shares already-warmed original entries.
	before = hits(admin);
	row(send_extended_messages_and_read_reply(other, execution("different_name", "hello") + msg('S')), "hello");
	ok(hits(admin) == before + 1, "Other session retains its original cache partition");
	// Database identity must also partition identical SQL/Bind bytes.
	PGconn* another_db = connect(false, "template1"); prepare(another_db, "first", sql);
	before = hits(admin);
	row(send_extended_messages_and_read_reply(another_db, execution("first", "hello") + msg('S')), "hello");
	ok(hits(admin) == before, "A different database cannot consume the warmed entry");
	cached(admin, another_db, execution("first", "hello"), "hello");
	PQfinish(another_db);
	// Actual libpq prepared execution (default/text parameter formats and
	// binary results), in addition to the independently constructed wire tests.
	PGconn* pq = connect(); Oid oid = 23;
	PGresult* pq_result = PQprepare(pq, "libpq", "SELECT /*ext_cache*/ $1::int4", 1, &oid);
	if (PQresultStatus(pq_result) != PGRES_COMMAND_OK) BAIL_OUT("libpq prepare: %s", PQerrorMessage(pq));
	PQclear(pq_result);
	const char* values[] = {"42"};
	for (int i = 0; i < 2; ++i) {
		before = hits(admin); long long b = backend_queries(admin);
		pq_result = PQexecPrepared(pq, "libpq", 1, values, nullptr, nullptr, 1);
		ok(PQresultStatus(pq_result) == PGRES_TUPLES_OK && PQntuples(pq_result) == 1 &&
			PQfformat(pq_result, 0) == 1 && PQgetlength(pq_result, 0, 0) == 4 &&
			memcmp(PQgetvalue(pq_result, 0, 0), integer.data(), 4) == 0, "libpq decodes prepared binary result and metadata");
		PQclear(pq_result);
		if (i) ok(hits(admin) == before + 1 && backend_queries(admin) == b, "libpq repeat hits with no backend work");
	}
	PQfinish(pq);
	before = hits(admin);
	// Cursor-limited and multi-execute frames must not consume warmed entries.
	before = hits(admin);
	r = send_extended_messages_and_read_reply(other, execution("different_name", "hello", true, 0, 0, false, 1) + msg('S'));
	ok(hits(admin) == before, "Nonzero Execute row limit bypasses cache");
	r = send_extended_messages_and_read_reply(other, execution("different_name", "hello") + execution("different_name", "hello") + msg('S'));
	ok(r.types == "2TDC2TDCZ" && r.rows.size() == 2, "Multi-execute cycle preserves complete response sequence");
	ok(hits(admin) == before, "All executions in multi-execute cycle bypass cache");
	r = send_extended_messages_and_read_reply(other, parse("bundled", sql) + execution("bundled", "hello") + msg('S'));
	ok(r.types == "12TDCZ", "Bundled Parse/Bind/Execute remains valid");
	ok(hits(admin) == before, "Bundled Parse bypasses cache");
	// An explicit transaction must neither use nor populate cache entries.
	send_extended_messages_and_read_reply(other, msg('Q', str("BEGIN")));
	r = send_extended_messages_and_read_reply(other, execution("different_name", "hello") + msg('S'));
	ok(r.types == "2TDCZ" && r.state == 'T', "Transactional execution returns transaction state");
	ok(hits(admin) == before, "Transaction bypasses warmed entry");
	send_extended_messages_and_read_reply(other, msg('Q', str("ROLLBACK")));
	// A backend error cannot become a cached result; Sync must recover.
	long long sets = metric(admin, "Query_Cache_count_SET");
	r = send_extended_messages_and_read_reply(c, execution("integer", "not-an-integer") + msg('S'));
	ok(r.types.find('E') != Bytes::npos && r.state == 'I', "Invalid parameter reports error and recovers at Sync");
	ok(metric(admin, "Query_Cache_count_SET") == sets, "Error does not populate cache");
	cached(admin, c, execution("integer", "42"), "42");
	// Closing/replacing names must not make old cached SQL visible.
	r = send_extended_messages_and_read_reply(other, msg('C', "S" + str("different_name")) + msg('S'));
	ok(r.types == "3Z", "Close statement has exactly one CloseComplete");
	prepare(other, "different_name", "SELECT /*ext_cache*/ upper($1::text)");
	cached(admin, other, execution("different_name", "hello"), "HELLO");
	prepare(other, "", sql);
	cached(admin, other, execution("", "hello"), "hello");
	prepare(other, "", "SELECT /*ext_cache*/ upper($1::text)");
	cached(admin, other, execution("", "hello"), "HELLO");
	// Respect the existing empty-result admission setting, including executions
	// without Describe where no RowDescription is emitted at all.
	prepare(c, "empty", "SELECT /*ext_cache*/ $1::text WHERE false");
	command(admin, "UPDATE pgsql_query_rules SET cache_empty_result=0 WHERE rule_id=971004");
	command(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	sets = metric(admin, "Query_Cache_count_SET");
	r = send_extended_messages_and_read_reply(c, execution("empty", "empty") + msg('S'));
	ok(r.types == "2TCZ" && r.rows.empty(), "Empty result has metadata but no rows");
	ok(metric(admin, "Query_Cache_count_SET") == sets, "cache_empty_result=0 prevents insertion");
	command(admin, "UPDATE pgsql_query_rules SET cache_empty_result=1 WHERE rule_id=971004");
	command(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	for (bool describe : {true, false}) {
		send_extended_messages_and_read_reply(c, execution("empty", "empty", describe) + msg('S'));
		before = hits(admin);
		r = send_extended_messages_and_read_reply(c, execution("empty", "empty", describe) + msg('S'));
		ok(r.types == (describe ? "2TCZ" : "2CZ") && r.rows.empty(), "Cached empty result preserves response shape");
		ok(hits(admin) == before + 1, "cache_empty_result=1 caches empty execution with/without Describe");
	}
	// Simple and extended entries for identical zero-parameter SQL cannot mix.
	const std::string zero_sql = "SELECT /*ext_cache*/ 'zero'::text";
	Bytes zero_parse = str("zero") + str(zero_sql); u16(zero_parse, 0);
	r = send_extended_messages_and_read_reply(c, msg('P', zero_parse) + msg('S'));
	ok(r.types == "1Z", "Prepare zero-parameter statement");
	Bytes zero_bind = str("") + str("zero"); u16(zero_bind, 0); u16(zero_bind, 0); u16(zero_bind, 0);
	Bytes zero_execute = str(""); u32(zero_execute, 0);
	Bytes zero_request = msg('B', zero_bind) + msg('D', "P" + str("")) + msg('E', zero_execute);
	cached(admin, c, zero_request, "zero");
	before = hits(admin);
	r = send_extended_messages_and_read_reply(c, msg('Q', str(zero_sql)));
	ok(r.types == "TDCZ" && r.rows == std::vector<Bytes>{"zero"}, "Simple query gets its own response shape");
	ok(hits(admin) == before, "Simple query does not consume extended entry");
	r = send_extended_messages_and_read_reply(c, msg('Q', str(zero_sql)));
	ok(r.types == "TDCZ" && hits(admin) == before + 1, "Existing simple query cache still hits");
	// Pinned state must bypass entries warmed by an ordinary session.
	PGconn* pinned = connect(); prepare(pinned, "pinned", sql);
	send_extended_messages_and_read_reply(pinned, msg('Q', str("SET ext_cache.flag='private'")));
	before = hits(admin); sets = metric(admin, "Query_Cache_count_SET");
	row(send_extended_messages_and_read_reply(pinned, execution("pinned", "hello") + msg('S')), "hello");
	ok(hits(admin) == before && metric(admin, "Query_Cache_count_SET") == sets, "Untracked SET bypasses lookup and insertion");
	PQfinish(pinned);
	pinned = connect(); prepare(pinned, "pinned", sql);
	send_extended_messages_and_read_reply(pinned, msg('Q', str("CREATE TEMP TABLE ext_cache_temp(v text)")));
	before = hits(admin); sets = metric(admin, "Query_Cache_count_SET");
	row(send_extended_messages_and_read_reply(pinned, execution("pinned", "hello") + msg('S')), "hello");
	ok(hits(admin) == before && metric(admin, "Query_Cache_count_SET") == sets, "Temporary-table session bypasses lookup and insertion");
	PQfinish(pinned);
	// A SELECT may introduce session state on its first execution. It must
	// be classified before admitting the result, not only at RequestEnd.
	pinned = connect();
	prepare(pinned, "into", "SELECT /*ext_cache*/ $1::text AS v INTO TEMP TABLE ext_cache_select_into");
	sets = metric(admin, "Query_Cache_count_SET");
	r = send_extended_messages_and_read_reply(pinned, execution("into", "value", false) + msg('S'));
	ok(r.types == "2CZ", "SELECT INTO returns command completion, not a rowset");
	ok(metric(admin, "Query_Cache_count_SET") == sets, "Command-only SELECT INTO is not admitted without Describe");
	send_extended_messages_and_read_reply(pinned, msg('Q', str("DROP TABLE IF EXISTS pg_temp.ext_cache_select_into")));
	PQfinish(pinned);
	pinned = connect();
	prepare(pinned, "lock", "SELECT /*ext_cache*/ pg_advisory_lock($1)", 20);
	sets = metric(admin, "Query_Cache_count_SET");
	r = send_extended_messages_and_read_reply(pinned, execution("lock", "9710041667") + msg('S'));
	ok(r.types == "2TDCZ", "Advisory-lock SELECT executes normally");
	ok(metric(admin, "Query_Cache_count_SET") == sets, "SELECT introducing session state is not admitted");
	send_extended_messages_and_read_reply(pinned, msg('Q', str("SELECT pg_advisory_unlock_all()")));
	PQfinish(pinned);
	// Rule disable and expiration retain their existing meaning.
	command(admin, "UPDATE pgsql_query_rules SET active=0 WHERE rule_id=971004");
	command(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	before = hits(admin); long long b = backend_queries(admin);
	send_extended_messages_and_read_reply(c, execution("integer", "42") + msg('S'));
	diag("Disabled rule: hit delta=%lld, backend query delta=%lld", hits(admin)-before, backend_queries(admin)-b);
	// A miss can additionally prepare the statement on a different pooled
	// backend, so require backend work, not exactly one pool query.
	ok(hits(admin) == before && backend_queries(admin) > b, "Disabled cache rule bypasses warmed entry");
	command(admin, "UPDATE pgsql_query_rules SET active=1,cache_ttl=50 WHERE rule_id=971004");
	command(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	send_extended_messages_and_read_reply(c, execution("integer", "43") + msg('S'));
	before = hits(admin); b = backend_queries(admin);
	usleep(150000);
	row(send_extended_messages_and_read_reply(c, execution("integer", "43") + msg('S')), "43");
	ok(hits(admin) == before && backend_queries(admin) > b, "Expired extended entry executes on backend");
	// Force an extended result to be transferred in pieces. A cached suffix
	// would silently lose rows on the next execution.
	PGresult* saved = query(admin, "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-query_cache_size_MB'");
	std::string saved_size = PQgetvalue(saved, 0, 0); PQclear(saved);
	saved = query(admin, "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-threshold_resultset_size'");
	std::string saved_threshold = PQgetvalue(saved, 0, 0); PQclear(saved);
	command(admin, "UPDATE pgsql_query_rules SET cache_ttl=60000 WHERE rule_id=971004");
	command(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	command(admin, "UPDATE global_variables SET variable_value=1 WHERE variable_name='pgsql-query_cache_size_MB'");
	command(admin, "UPDATE global_variables SET variable_value=4096 WHERE variable_name='pgsql-threshold_resultset_size'");
	command(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	prepare(c, "stream", "SELECT /*ext_cache*/ repeat($1::text,64) FROM generate_series(1,40000)");
	before = hits(admin); sets = metric(admin, "Query_Cache_count_SET");
	for (int i = 0; i < 2; ++i) {
		r = send_extended_messages_and_read_reply(c, execution("stream", "x") + msg('S'));
		ok(r.types == "2T" + Bytes(40000, 'D') + "CZ" && r.rows.size() == 40000 &&
			std::all_of(r.rows.begin(), r.rows.end(), [](const Bytes& v) { return v == Bytes(64, 'x'); }),
			"Streamed execution delivers all 40000 rows");
		ok(hits(admin) == before && metric(admin, "Query_Cache_count_SET") == sets, "Partially transferred execution is neither cached nor replayed");
	}
	command(admin, "UPDATE global_variables SET variable_value=" + saved_size + " WHERE variable_name='pgsql-query_cache_size_MB'");
	command(admin, "UPDATE global_variables SET variable_value=" + saved_threshold + " WHERE variable_name='pgsql-threshold_resultset_size'");
	command(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	PQfinish(other); PQfinish(c);
	command(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=971004");
	command(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	PQfinish(admin);
	return exit_status();
}
