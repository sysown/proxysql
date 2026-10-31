/**
 * @file pgsql-stmt_result_change-t.cpp
 * @brief A query whose result columns differ from what ProxySQL's kept statement was prepared with
 * must keep working through ProxySQL, in libpq and in native backend mode.
 *
 * ProxySQL keeps one prepared statement per query text on each backend connection, also for a client
 * that sends the unnamed statement, which PostgreSQL would parse again every time. PostgreSQL refuses
 * a kept statement whose result columns changed ("cached plan must not change result type", 0A000).
 * Two ways in, both checked on one backend connection, so every query runs where the old one is kept:
 *  - search_path: clients whose search_path finds tables of different shapes under the same name
 *    must each get their own table's columns, with no error.
 *  - ALTER TABLE ADD COLUMN: an unnamed query gets the error at most once, then the new column; inside
 *    a transaction it gets the error and works after ROLLBACK; a named statement gets the error, as
 *    from PostgreSQL, and works once the client prepares it again.
 * Edge cases try to break both: search_path set in other ways (pipeline, SET LOCAL, a rolled back SET,
 * a startup option, other spellings), tables of the same shape (rows must come from the
 * client's own schema), a named statement run after its client changed search_path, DROP and CREATE,
 * a column type change, Describe, a 0A000 that is not about a kept statement (must not be forgotten),
 * a stale statement in the middle of a pipeline, more statements than max_stmts_per_connection,
 * clients of both search_paths interleaved on the one backend connection, and a refused statement
 * that stays on the backend counting toward max_stmts_per_connection.
 */

#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int HG = 0;
static const std::string TBL = "stmt_result_change_t";
static const std::string Q = "SELECT * FROM " + TBL;
static int stray_replies = 0;

static void count_stray(void*, const char* message) {
	stray_replies++;
	diag("libpq notice: %s", message);
}

static PGConnPtr openConn(const char* host, int port, const char* user, const char* pass, const char* db) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass;
	if (db && *db) ss << " dbname=" << db;
	ss << " sslmode=disable";
	PGconn* c = PQconnectdb(ss.str().c_str());
	if (PQstatus(c) != CONNECTION_OK) {
		diag("connection to %s:%d failed: %s", host, port, PQerrorMessage(c));
	} else {
		PQsetNoticeProcessor(c, count_stray, nullptr);
	}
	return PGConnPtr(c, &PQfinish);
}
static PGConnPtr proxyConn() {
	return openConn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, nullptr);
}
static bool exec(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	const bool good = (PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK);
	if (!good) diag("query failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(r);
	return good;
}
static std::string execScalar(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	std::string v = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
		? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return v;
}

// "cols=<n>" for rows, or "ERROR <sqlstate>".
static std::string shape(PGresult* r) {
	std::string out;
	if (PQresultStatus(r) == PGRES_TUPLES_OK) {
		out = "cols=" + std::to_string(PQnfields(r));
	} else {
		const char* st = PQresultErrorField(r, PG_DIAG_SQLSTATE);
		out = std::string("ERROR ") + (st ? st : "?");
		diag("error: %s", PQresultErrorMessage(r));
	}
	PQclear(r);
	return out;
}
// The query with the unnamed statement.
static std::string unnamed(PGconn* c, const std::string& q = Q) {
	return shape(PQexecParams(c, q.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0));
}
static std::string named(PGconn* c, const char* name) {
	return shape(PQexecPrepared(c, name, 0, nullptr, nullptr, nullptr, 0));
}
static std::string cols(int n) {
	return "cols=" + std::to_string(n);
}
// "v=<first cell>" for rows, or "ERROR <sqlstate>".
static std::string first_value(PGresult* r) {
	std::string out;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
		out = std::string("v=") + PQgetvalue(r, 0, 0);
	} else {
		const char* st = PQresultErrorField(r, PG_DIAG_SQLSTATE);
		out = std::string("ERROR ") + (st ? st : "?");
		diag("error: %s", PQresultErrorMessage(r));
	}
	PQclear(r);
	return out;
}
static std::string unnamed_value(PGconn* c, const std::string& q, const char* param = nullptr) {
	const char* params[1] = { param };
	return first_value(PQexecParams(c, q.c_str(), param ? 1 : 0, nullptr, param ? params : nullptr, nullptr, nullptr, 0));
}
// Sends the queries as one pipeline (unnamed statements, one Sync) and returns each one's shape:
// "ok", "cols=<n>", "ERROR <sqlstate>" or "aborted".
static std::vector<std::string> pipeline(PGconn* c, const std::vector<std::string>& qs) {
	std::vector<std::string> out;
	if (PQenterPipelineMode(c) != 1) {
		diag("could not enter pipeline mode: %s", PQerrorMessage(c));
		return out;
	}
	for (const std::string& q : qs) {
		PQsendQueryParams(c, q.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0);
	}
	PQpipelineSync(c);
	for (size_t i = 0; i < qs.size(); i++) {
		PGresult* r = PQgetResult(c);
		if (r == nullptr) { out.push_back("none"); continue; }
		if (PQresultStatus(r) == PGRES_COMMAND_OK) { out.push_back("ok"); PQclear(r); }
		else if (PQresultStatus(r) == PGRES_PIPELINE_ABORTED) { out.push_back("aborted"); PQclear(r); }
		else out.push_back(shape(r));
		while ((r = PQgetResult(c)) != nullptr) PQclear(r);   // the NULL that ends each query
	}
	PGresult* r = PQgetResult(c);   // the Sync
	if (r) PQclear(r);
	PQexitPipelineMode(c);
	return out;
}
static std::string join(const std::vector<std::string>& v) {
	std::string s;
	for (const std::string& x : v) s += (s.empty() ? "" : ", ") + x;
	return s;
}
// Statements the one backend connection holds, ProxySQL's included.
static int backend_stmts(PGconn* c) {
	const std::string v = execScalar(c, "SELECT count(*) FROM pg_prepared_statements");
	return v.empty() ? -1 : std::stoi(v);
}
static PGConnPtr proxyConnWithPath(const char* path) {
	PGConnPtr c = proxyConn();
	exec(c.get(), std::string("SET search_path = ") + path);
	return c;
}

// One backend connection, in the given mode. Taking the servers down first closes every pooled
// connection, which keeps the protocol it was opened with.
static bool one_backend(PGconn* admin, const std::string& native, const std::string& max_conn) {
	const std::string hg = std::to_string(HG);
	if (!exec(admin, "SET pgsql-use_native_backend_protocol='" + native + "'") ||
		!exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME") ||
		!exec(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" + hg) ||
		!exec(admin, "LOAD PGSQL SERVERS TO RUNTIME")) {
		return false;
	}
	for (int i = 0; i < 100; i++) {
		if (execScalar(admin, "SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_pgsql_connection_pool "
			"WHERE hostgroup=" + hg) == "0") break;
		usleep(100000);
	}
	const bool loaded = exec(admin, "UPDATE pgsql_servers SET status='ONLINE', max_connections=" + max_conn +
		" WHERE hostgroup_id=" + hg) && exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	usleep(200000);
	return loaded;
}

// Schemas sr_a and sr_b each hold a table t, of 1 and 2 columns. The same text finds a different
// table for each, which ProxySQL must not answer with one statement.
static void search_path_cases(const char* mode) {
	const std::string q = "SELECT * FROM t";
	const char* paths[] = { "sr_a", "sr_b", "sr_b", "sr_a", "sr_b" };
	for (const char* p : paths) {
		PGConnPtr c = proxyConn();
		exec(c.get(), std::string("SET search_path = ") + p);
		const std::string r = unnamed(c.get(), q);
		const int want = (p[3] == 'a') ? 1 : 2;
		ok(r == cols(want), "%s: new client with search_path %s gets its own table: '%s', expected '%s'",
			mode, p, r.c_str(), cols(want).c_str());
	}
	PGConnPtr c = proxyConn();
	const char* same[] = { "sr_a", "sr_b", "sr_a" };
	for (const char* p : same) {
		exec(c.get(), std::string("SET search_path = ") + p);
		const std::string r = unnamed(c.get(), q);
		const int want = (p[3] == 'a') ? 1 : 2;
		ok(r == cols(want), "%s: one client switching to search_path %s gets its own table: '%s', expected '%s'",
			mode, p, r.c_str(), cols(want).c_str());
	}
}

// The table is made over the direct connection, as its owner: only the owner may ALTER it, and the
// schema changes come from there, as a migration would.
static void schema_change_cases(const char* mode, PGconn* be) {
	int n = 1;
	if (!exec(be, "DROP TABLE IF EXISTS " + TBL) || !exec(be, "CREATE TABLE " + TBL + " (c1 int)") ||
		!exec(be, "INSERT INTO " + TBL + " VALUES (1)") ||
		!exec(be, "GRANT ALL ON " + TBL + " TO " + std::string(cl.pgsql_username))) {
		BAIL_OUT("could not create the table");
	}
	auto add_column = [&]() {
		n++;
		exec(be, "ALTER TABLE " + TBL + " ADD COLUMN c" + std::to_string(n) + " int");
	};

	PGConnPtr c = proxyConn();
	if (PQstatus(c.get()) != CONNECTION_OK) {
		BAIL_OUT("could not connect through the proxy");
	}
	std::string r = unnamed(c.get());
	ok(r == cols(n), "%s: unnamed query before the change: '%s'", mode, r.c_str());

	// The first use may fail once: the client is told, and the statement is prepared again.
	add_column();
	stray_replies = 0;
	const std::string first = unnamed(c.get());
	const std::string second = unnamed(c.get());
	ok((first == cols(n) || first == "ERROR 0A000") && second == cols(n),
		"%s: after ADD COLUMN at most one error, then the new column: '%s', then '%s'", mode, first.c_str(), second.c_str());
	ok(stray_replies == 0 && execScalar(c.get(), "SELECT 1") == "1",
		"%s: nothing stray after it, and the next query works (%d stray replies)", mode, stray_replies);
	// The first client leaves first: with multiplexing off it would keep the one backend.
	c.reset();
	{
		PGConnPtr c2 = proxyConn();
		r = unnamed(c2.get());
		ok(r == cols(n), "%s: a new client gets the new column with no error: '%s'", mode, r.c_str());
	}
	c = proxyConn();

	// Inside a transaction PostgreSQL has already failed it, so the client gets the error. The
	// statement is prepared again for the next use.
	unnamed(c.get());   // the backend holds the statement again, whatever happened above
	add_column();
	exec(c.get(), "BEGIN");
	r = unnamed(c.get());
	ok(r == "ERROR 0A000" && PQtransactionStatus(c.get()) == PQTRANS_INERROR,
		"%s: inside a transaction the changed query fails it: '%s'", mode, r.c_str());
	exec(c.get(), "ROLLBACK");
	r = unnamed(c.get());
	ok(r == cols(n), "%s: after the ROLLBACK it works: '%s'", mode, r.c_str());

	// A named statement gets the error, as from PostgreSQL; prepared again, it works. ProxySQL already
	// holds the text on the backend, so preparing it again must not reuse the old backend statement.
	PGresult* p = PQprepare(c.get(), "s1", Q.c_str(), 0, nullptr);
	PQclear(p);
	r = named(c.get(), "s1");
	ok(r == cols(n), "%s: named statement before the change: '%s'", mode, r.c_str());
	add_column();
	r = named(c.get(), "s1");
	ok(r == "ERROR 0A000", "%s: named statement after ADD COLUMN gets PostgreSQL's error: '%s'", mode, r.c_str());
	exec(c.get(), "DEALLOCATE s1");
	p = PQprepare(c.get(), "s1", Q.c_str(), 0, nullptr);
	PQclear(p);
	r = named(c.get(), "s1");
	ok(r == cols(n), "%s: prepared again, it works: '%s'", mode, r.c_str());
}

// search_path reaches the backend in ways other than a plain SET. Whatever ProxySQL makes of them, a
// later client must still get its own table, with no error.
static void path_edge_cases(const char* mode) {
	const std::string q = "SELECT * FROM t";
	{
		PGConnPtr c = proxyConn();
		exec(c.get(), "SET search_path = \"sr_b\"");
		std::string r1 = unnamed(c.get(), q);
		exec(c.get(), "SET search_path =   sr_b ,  public");
		std::string r2 = unnamed(c.get(), q);
		exec(c.get(), "SET search_path TO sr_a, sr_b");
		std::string r3 = unnamed(c.get(), q);
		ok(r1 == cols(2) && r2 == cols(2) && r3 == cols(1),
			"%s: other spellings of a search_path find the right table: '%s', '%s', '%s'", mode, r1.c_str(), r2.c_str(), r3.c_str());
	}
	{
		std::stringstream ss;
		ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port << " user=" << cl.pgsql_username
			<< " password=" << cl.pgsql_password << " sslmode=disable options='-c search_path=sr_b'";
		PGConnPtr c(PQconnectdb(ss.str().c_str()), &PQfinish);
		const std::string r = unnamed(c.get(), q);
		PGConnPtr c2 = proxyConnWithPath("sr_a");
		const std::string r2 = unnamed(c2.get(), q);
		ok(r == cols(2) && r2 == cols(1), "%s: search_path from a startup option: '%s', then a sr_a client: '%s'",
			mode, r.c_str(), r2.c_str());
	}
	{
		PGConnPtr c = proxyConnWithPath("sr_a");
		const std::vector<std::string> p = pipeline(c.get(), { "SET search_path = sr_b", q });
		const std::string after = unnamed(c.get(), q);
		PGConnPtr c2 = proxyConnWithPath("sr_a");
		const std::string other = unnamed(c2.get(), q);
		ok(join(p) == "ok, " + cols(2) && after == cols(2) && other == cols(1),
			"%s: SET search_path and the query in one pipeline: '%s', then '%s'; a sr_a client: '%s'",
			mode, join(p).c_str(), after.c_str(), other.c_str());
	}
	{
		// ProxySQL does not parse SET LOCAL: it pins the session and keeps keying by the session's
		// search_path, so inside the transaction the kept sr_a statement can be refused.
		PGConnPtr c = proxyConnWithPath("sr_a");
		exec(c.get(), "BEGIN");
		exec(c.get(), "SET LOCAL search_path = sr_b");
		const std::string in = unnamed(c.get(), q);
		exec(c.get(), "COMMIT");
		const std::string out = unnamed(c.get(), q);
		c.reset();   // pinned: it holds the one backend connection
		PGConnPtr c2 = proxyConnWithPath("sr_a");
		const std::string other = unnamed(c2.get(), q);
		ok((in == cols(2) || in == "ERROR 0A000") && out == cols(1) && other == cols(1),
			"%s: SET LOCAL search_path: in the transaction '%s', after it '%s', a sr_a client '%s'",
			mode, in.c_str(), out.c_str(), other.c_str());
	}
	{
		PGConnPtr c = proxyConnWithPath("sr_a");
		exec(c.get(), "BEGIN");
		exec(c.get(), "SET search_path = sr_b");
		const std::string in = unnamed(c.get(), q);
		exec(c.get(), "ROLLBACK");
		const std::string out = unnamed(c.get(), q);
		PGConnPtr c2 = proxyConnWithPath("sr_a");
		const std::string other = unnamed(c2.get(), q);
		ok(in == cols(2) && out == cols(1) && other == cols(1),
			"%s: SET search_path rolled back: in the transaction '%s', after it '%s', a sr_a client '%s'",
			mode, in.c_str(), out.c_str(), other.c_str());
	}
}

// Tables of the same shape: one statement could serve both, but each client must get its own rows.
static void same_shape_cases(const char* mode) {
	const std::string q = "SELECT a FROM u";
	int wrong = 0;
	for (int i = 0; i < 6; i++) {
		const char* p = (i % 2) ? "sr_b" : "sr_a";
		PGConnPtr c = proxyConnWithPath(p);
		const std::string r = unnamed_value(c.get(), q);
		if (r != std::string((i % 2) ? "v=20" : "v=10")) { wrong++; diag("%s got '%s'", p, r.c_str()); }
	}
	ok(wrong == 0, "%s: same shaped tables, new clients alternating search_path get their own rows (%d wrong)", mode, wrong);

	// A named statement follows the search_path it runs under, as in PostgreSQL.
	PGConnPtr c = proxyConnWithPath("sr_a");
	PQclear(PQprepare(c.get(), "u1", q.c_str(), 0, nullptr));
	const std::string r1 = first_value(PQexecPrepared(c.get(), "u1", 0, nullptr, nullptr, nullptr, 0));
	exec(c.get(), "SET search_path = sr_b");
	const std::string r2 = first_value(PQexecPrepared(c.get(), "u1", 0, nullptr, nullptr, nullptr, 0));
	ok(r1 == "v=10" && r2 == "v=20", "%s: same shaped tables, a named statement run under sr_a then sr_b: '%s', '%s'",
		mode, r1.c_str(), r2.c_str());
}

// PostgreSQL fails a named statement run under another search_path that finds another shape, every
// time. ProxySQL must do the same, and must not let that client's statement break the clients still
// on the first path.
static void named_switch_cases(const char* mode, const std::function<void()>& new_backend) {
	const std::string q = "SELECT * FROM t";
	PGConnPtr c = proxyConnWithPath("sr_a");
	PQclear(PQprepare(c.get(), "sw", q.c_str(), 0, nullptr));
	const std::string r0 = named(c.get(), "sw");
	exec(c.get(), "SET search_path = sr_b");
	const std::string r1 = named(c.get(), "sw");
	const std::string r2 = named(c.get(), "sw");
	ok(r0 == cols(1) && r1 == "ERROR 0A000" && r2 == "ERROR 0A000",
		"%s: named statement prepared under sr_a, run under sr_b: '%s', then '%s' and '%s' (PostgreSQL: the error)",
		mode, r0.c_str(), r1.c_str(), r2.c_str());
	PGConnPtr c2 = proxyConnWithPath("sr_a");
	const std::string other = unnamed(c2.get(), q);
	const std::string again = named(c.get(), "sw");
	const std::string other2 = unnamed(c2.get(), q);
	ok(other == cols(1) && again == "ERROR 0A000" && other2 == cols(1),
		"%s: a sr_a client is not broken by it: '%s', and after it ran again ('%s'): '%s'",
		mode, other.c_str(), again.c_str(), other2.c_str());

	// On a backend connection that does not hold it, ProxySQL prepares it under the client's sr_b
	// (PostgreSQL would refuse it), keyed as sr_a. A sr_a client there gets the error once at most.
	c2.reset();
	new_backend();
	const std::string moved = named(c.get(), "sw");
	c.reset();
	c2 = proxyConnWithPath("sr_a");
	const std::string o1 = unnamed(c2.get(), q);
	const std::string o2 = unnamed(c2.get(), q);
	ok((o1 == cols(1) || o1 == "ERROR 0A000") && o2 == cols(1),
		"%s: run on a new backend connection: '%s'; a sr_a client there: '%s', then '%s'",
		mode, moved.c_str(), o1.c_str(), o2.c_str());
}

static void make_table(PGconn* be, const std::string& t, const std::string& def) {
	if (!exec(be, "DROP TABLE IF EXISTS " + t) || !exec(be, "CREATE TABLE " + t + " " + def) ||
		!exec(be, "GRANT ALL ON " + t + " TO " + std::string(cl.pgsql_username))) {
		BAIL_OUT("could not create %s", t.c_str());
	}
}

// Other schema changes, and other errors.
static void schema_edge_cases(const char* mode, PGconn* be) {
	PGConnPtr c = proxyConn();
	{
		const std::string t = "src_drop_t", q = "SELECT * FROM " + t;
		make_table(be, t, "(c1 int)");
		exec(be, "INSERT INTO " + t + " VALUES (1)");
		const std::string r0 = unnamed(c.get(), q);
		exec(be, "DROP TABLE " + t);
		const std::string r1 = unnamed(c.get(), q);
		make_table(be, t, "(x int, y int, z int)");
		const std::string r2 = unnamed(c.get(), q);
		const std::string r3 = unnamed(c.get(), q);
		ok(r0 == cols(1) && r1 == "ERROR 42P01" && (r2 == cols(3) || r2 == "ERROR 0A000") && r3 == cols(3),
			"%s: DROP then CREATE with other columns: '%s', '%s', '%s', '%s'", mode, r0.c_str(), r1.c_str(), r2.c_str(), r3.c_str());
	}
	{
		const std::string t = "src_type_t", q = "SELECT c1 FROM " + t;
		make_table(be, t, "(c1 int)");
		exec(be, "INSERT INTO " + t + " VALUES (1)");
		const std::string r0 = unnamed(c.get(), q);
		exec(be, "ALTER TABLE " + t + " ALTER COLUMN c1 TYPE text");
		const std::string r1 = unnamed(c.get(), q);
		PGresult* r = PQexecParams(c.get(), q.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0);
		const Oid type = PQresultStatus(r) == PGRES_TUPLES_OK ? PQftype(r, 0) : 0;
		PQclear(r);
		ok(r0 == cols(1) && (r1 == cols(1) || r1 == "ERROR 0A000") && type == 25,
			"%s: ALTER COLUMN TYPE int to text: '%s', '%s', then type oid %u (text is 25)", mode, r0.c_str(), r1.c_str(), type);
	}
	{
		// Describe of the statement revalidates it too.
		const std::string t = "src_desc_t", q = "SELECT * FROM " + t;
		make_table(be, t, "(c1 int)");
		PQclear(PQprepare(c.get(), "d1", q.c_str(), 0, nullptr));
		PGresult* r = PQdescribePrepared(c.get(), "d1");
		const int before = PQresultStatus(r) == PGRES_COMMAND_OK ? PQnfields(r) : -1;
		PQclear(r);
		exec(be, "ALTER TABLE " + t + " ADD COLUMN c2 int");
		r = PQdescribePrepared(c.get(), "d1");
		const char* st = PQresultErrorField(r, PG_DIAG_SQLSTATE);
		const std::string after = PQresultStatus(r) == PGRES_COMMAND_OK ? cols(PQnfields(r)) : std::string("ERROR ") + (st ? st : "?");
		PQclear(r);
		exec(c.get(), "DEALLOCATE d1");
		PQclear(PQprepare(c.get(), "d1", q.c_str(), 0, nullptr));
		r = PQdescribePrepared(c.get(), "d1");
		const int again = PQresultStatus(r) == PGRES_COMMAND_OK ? PQnfields(r) : -1;
		PQclear(r);
		ok(before == 1 && after == "ERROR 0A000" && again == 2,
			"%s: Describe after ADD COLUMN: %d columns, then '%s' (PostgreSQL: the error), prepared again %d", mode,
			before, after.c_str(), again);
	}
	{
		// A 0A000 raised while the query runs is not about the kept statement: it must stay kept, so
		// the backend holds no more statements after the errors than before.
		const std::string q = "SELECT src_raise_0a000($1::int)";
		const std::string r0 = unnamed_value(c.get(), q, "0");
		const int n0 = backend_stmts(c.get());
		std::string errs;
		for (int i = 0; i < 3; i++) errs += unnamed_value(c.get(), q, "1") + ";";
		const int n1 = backend_stmts(c.get());
		const std::string r1 = unnamed_value(c.get(), q, "0");
		ok(r0 == "v=0" && errs == "ERROR 0A000;ERROR 0A000;ERROR 0A000;" && n1 == n0 && r1 == "v=0",
			"%s: another 0A000 keeps the statement: '%s', '%s', backend statements %d then %d, then '%s'",
			mode, r0.c_str(), errs.c_str(), n0, n1, r1.c_str());
	}
	{
		// The stale statement in the middle of a pipeline: the rest of the pipeline is skipped, as in
		// PostgreSQL, and the next one works.
		const std::string t = "src_pipe_t", q = "SELECT * FROM " + t;
		make_table(be, t, "(c1 int)");
		const std::string r0 = unnamed(c.get(), q);
		exec(be, "ALTER TABLE " + t + " ADD COLUMN c2 int");
		const std::vector<std::string> p1 = pipeline(c.get(), { "SELECT 1", q, "SELECT 2" });
		const std::vector<std::string> p2 = pipeline(c.get(), { "SELECT 1", q, "SELECT 2" });
		const bool first_ok = join(p1) == "cols=1, ERROR 0A000, aborted" || join(p1) == "cols=1, cols=2, cols=1";
		ok(r0 == cols(1) && first_ok && join(p2) == "cols=1, cols=2, cols=1",
			"%s: stale statement mid-pipeline: '%s', next pipeline '%s'", mode, join(p1).c_str(), join(p2).c_str());
	}
}

// More statements than max_stmts_per_connection (20): every search_path is its own statement, so the
// connection is reset when it goes back to the pool. Every query must still work.
static void many_paths_cases(const char* mode) {
	const std::string q = "SELECT * FROM t";
	PGConnPtr c = proxyConn();
	int wrong = 0;
	for (int i = 1; i <= 25; i++) {
		exec(c.get(), "SET search_path = sr_a, x" + std::to_string(i));
		const std::string r = unnamed(c.get(), q);
		if (r != cols(1)) { wrong++; diag("path %d got '%s'", i, r.c_str()); }
	}
	c.reset();
	PGConnPtr c2 = proxyConnWithPath("sr_a, x1");
	const std::string r1 = unnamed(c2.get(), q);
	PGConnPtr c3 = proxyConnWithPath("sr_b");
	const std::string r2 = unnamed(c3.get(), q);
	ok(wrong == 0 && r1 == cols(1) && r2 == cols(2),
		"%s: 25 search_paths on one connection (%d wrong), then '%s' and '%s'", mode, wrong, r1.c_str(), r2.c_str());
}

// Clients of both search_paths take turns on the one backend connection, with unnamed and named
// statements.
static void interleave_cases(const char* mode) {
	const std::string q = "SELECT * FROM t";
	std::vector<PGConnPtr> cs;
	for (int i = 0; i < 6; i++) {
		cs.push_back(proxyConnWithPath((i % 2) ? "sr_b" : "sr_a"));
		PQclear(PQprepare(cs.back().get(), "n1", q.c_str(), 0, nullptr));
	}
	int wrong = 0;
	for (int round = 0; round < 10; round++) {
		for (int i = 0; i < 6; i++) {
			const std::string want = cols((i % 2) ? 2 : 1);
			const std::string r = (round % 2) ? named(cs[i].get(), "n1") : unnamed(cs[i].get(), q);
			if (r != want) { wrong++; diag("client %d round %d got '%s'", i, round, r.c_str()); }
		}
	}
	ok(wrong == 0, "%s: 6 clients of both search_paths, 10 rounds of unnamed and named, on one backend (%d wrong)",
		mode, wrong);
}

// A refused statement is forgotten but never closed, so it stays on the backend. It must still count
// toward max_stmts_per_connection. With the limit at 1, on a new backend connection: the first
// statement fits; refused and prepared again, the backend holds two, so the connection must be reset
// on its way back to the pool, which leaves it none.
static void leftover_cases(const char* mode, PGconn* admin, PGconn* be, const std::string& max_stmts) {
	const std::string t = "src_left_t", q = "SELECT * FROM " + t;
	make_table(be, t, "(c1 int)");
	exec(admin, "SET pgsql-max_stmts_per_connection=1");
	exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	PGConnPtr c = proxyConn();
	const std::string r0 = unnamed(c.get(), q);
	const int n0 = backend_stmts(c.get());
	exec(be, "ALTER TABLE " + t + " ADD COLUMN c2 int");
	const std::string r1 = unnamed(c.get(), q);
	const std::string r2 = unnamed(c.get(), q);
	const int n1 = backend_stmts(c.get());
	exec(admin, "SET pgsql-max_stmts_per_connection=" + max_stmts);
	exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	ok(r0 == cols(1) && n0 == 1 && (r1 == "ERROR 0A000" || r1 == cols(2)) && r2 == cols(2) && n1 == 0,
		"%s: a refused statement left on the backend counts toward max_stmts_per_connection: '%s', backend "
		"statements %d; after ADD COLUMN '%s', '%s', backend statements %d (want 0: reset)", mode,
		r0.c_str(), n0, r1.c_str(), r2.c_str(), n1);
}

int main(int argc, char** argv) {
	if (cl.getEnv())
		return exit_status();

	plan(2 * (8 + 9 + 5 + 2 + 3 + 5 + 1 + 1 + 1));

	PGConnPtr admin = openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, nullptr);
	PGConnPtr be = openConn(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_server_username,
		cl.pgsql_server_password, cl.pgsql_username);
	if (PQstatus(admin.get()) != CONNECTION_OK || PQstatus(be.get()) != CONNECTION_OK) {
		BAIL_OUT("could not connect to the admin interface or the backend");
	}
	const std::string max_conn = execScalar(admin.get(), "SELECT max_connections FROM pgsql_servers WHERE hostgroup_id=" +
		std::to_string(HG) + " LIMIT 1");
	const std::string native = execScalar(admin.get(),
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
	const std::string max_stmts = execScalar(admin.get(),
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-max_stmts_per_connection'");
	const std::string user(cl.pgsql_username);
	if (!exec(be.get(), "DROP SCHEMA IF EXISTS sr_a CASCADE") || !exec(be.get(), "DROP SCHEMA IF EXISTS sr_b CASCADE") ||
		!exec(be.get(), "CREATE SCHEMA sr_a") || !exec(be.get(), "CREATE SCHEMA sr_b") ||
		!exec(be.get(), "CREATE TABLE sr_a.t (a int)") || !exec(be.get(), "INSERT INTO sr_a.t VALUES (1)") ||
		!exec(be.get(), "CREATE TABLE sr_b.t (a int, b int)") || !exec(be.get(), "INSERT INTO sr_b.t VALUES (1, 2)") ||
		!exec(be.get(), "GRANT USAGE ON SCHEMA sr_a, sr_b TO " + user) ||
		!exec(be.get(), "CREATE TABLE sr_a.u (a int)") || !exec(be.get(), "INSERT INTO sr_a.u VALUES (10)") ||
		!exec(be.get(), "CREATE TABLE sr_b.u (a int)") || !exec(be.get(), "INSERT INTO sr_b.u VALUES (20)") ||
		!exec(be.get(), "GRANT SELECT ON sr_a.t, sr_b.t, sr_a.u, sr_b.u TO " + user) ||
		!exec(be.get(), "CREATE OR REPLACE FUNCTION src_raise_0a000(int) RETURNS int LANGUAGE plpgsql AS "
			"$$ BEGIN IF $1 = 1 THEN RAISE EXCEPTION 'not this one' USING ERRCODE = 'feature_not_supported'; END IF; "
			"RETURN $1; END $$")) {
		BAIL_OUT("could not create the schemas");
	}

	const char* modes[][2] = { { "false", "libpq" }, { "true", "native" } };
	for (const auto& m : modes) {
		if (max_conn.empty() || !one_backend(admin.get(), m[0], "1")) {
			BAIL_OUT("could not set up one %s backend connection", m[1]);
		}
		search_path_cases(m[1]);
		schema_change_cases(m[1], be.get());
		path_edge_cases(m[1]);
		same_shape_cases(m[1]);
		named_switch_cases(m[1], [&]() { one_backend(admin.get(), m[0], "1"); });
		schema_edge_cases(m[1], be.get());
		many_paths_cases(m[1]);
		interleave_cases(m[1]);
		one_backend(admin.get(), m[0], "1");
		leftover_cases(m[1], admin.get(), be.get(), max_stmts.empty() ? "20" : max_stmts);
	}

	exec(be.get(), "DROP TABLE IF EXISTS " + TBL);
	for (const char* t : { "src_drop_t", "src_type_t", "src_desc_t", "src_pipe_t", "src_left_t" }) {
		exec(be.get(), std::string("DROP TABLE IF EXISTS ") + t);
	}
	exec(be.get(), "DROP FUNCTION IF EXISTS src_raise_0a000(int)");
	exec(be.get(), "DROP SCHEMA IF EXISTS sr_a CASCADE");
	exec(be.get(), "DROP SCHEMA IF EXISTS sr_b CASCADE");
	if (native.empty() == false) {
		exec(admin.get(), "SET pgsql-use_native_backend_protocol='" + native + "'");
		exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	}
	exec(admin.get(), "UPDATE pgsql_servers SET max_connections=" + max_conn + " WHERE hostgroup_id=" + std::to_string(HG));
	exec(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME");
	return exit_status();
}
