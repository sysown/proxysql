/**
 * @file pgsql-native_extq_batch-t.cpp
 * @brief Native extended-query batching: from the first message of a unit bound for the backend,
 *        ProxySQL buffers the unit and sends it in one write at the Sync, matching the replies in
 *        order. Each scenario runs the same frame with libpq, whose one-message-at-a-time path is the
 *        reference, and with the native protocol, compares what the client receives, and checks
 *        what only the batch changes.
 *
 * Needs a hostgroup 0 with one PostgreSQL server and an admin user able to edit pgsql_query_rules.
 */

#include <chrono>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>
#include "libpq-fe.h"
#include "pg_lite_client.h"  // raw frontend messages (MUST precede utils.h: mysql.h clash)
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int HG = 0;
static std::string tag;   // per run, so statement texts are new to the global statement cache

static PGConnPtr openConn(const char* host, int port, const char* user, const char* pass, const char* db) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass;
	if (db && *db) ss << " dbname=" << db;
	ss << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
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
static long execLong(PGconn* c, const std::string& q) {
	const std::string v = execScalar(c, q);
	return v.empty() ? -1 : atol(v.c_str());
}

// Tables are made over the direct backend connection, as the server's superuser in Docker, and used
// through the proxy as the test user: without the grant every statement on them fails with 42501.
static void createTable(PGconn* be, const std::string& tbl) {
	exec(be, "CREATE TABLE " + tbl + " (a int)");
	exec(be, "GRANT ALL ON " + tbl + " TO " + std::string(cl.pgsql_username));
}

// Taking the servers down and back drops every pooled connection: a pooled one keeps the protocol it
// was opened with, so without this a scenario could run on the other mode's connection.
static void resetPool(PGconn* admin) {
	const std::string hg = std::to_string(HG);
	if (!exec(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" + hg)
	    || !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not take hostgroup %s down", hg.c_str());
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	while (std::chrono::steady_clock::now() < deadline) {
		if (execLong(admin, "SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + hg) == 0) break;
		usleep(100000);
	}
	if (!exec(admin, "UPDATE pgsql_servers SET status='ONLINE' WHERE hostgroup_id=" + hg)
	    || !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not bring hostgroup %s back", hg.c_str());
	usleep(200000);
}

static void setNativeMode(PGconn* admin, bool on, bool reset_pool = true) {
	const std::string want = on ? "true" : "false";
	if (!exec(admin, "SET pgsql-use_native_backend_protocol='" + want + "'")
	    || !exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME"))
		BAIL_OUT("could not set pgsql-use_native_backend_protocol");
	const std::string got = execScalar(admin,
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
	if (got != want)
		BAIL_OUT("pgsql-use_native_backend_protocol did not take: wanted '%s', runtime says '%s'", want.c_str(), got.c_str());
	if (reset_pool) resetPool(admin);
}

static long pooled(PGconn* admin) {
	return execLong(admin, "SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(HG));
}
// A connection goes back to the pool only after it is reset, a moment after its client leaves: wait
// for the count instead of guessing how long that takes.
static long pooledWithin(PGconn* admin, long want, int seconds) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	long last = -1;
	for (;;) {
		last = pooled(admin);
		if (last == want || std::chrono::steady_clock::now() >= deadline) return last;
		usleep(100000);
	}
}
static long connUsed(PGconn* admin) {
	return execLong(admin, "SELECT COALESCE(SUM(ConnUsed),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(HG));
}
static long connOK(PGconn* admin) {
	return execLong(admin, "SELECT COALESCE(SUM(ConnOK),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(HG));
}

static std::string errorSqlstate(const std::vector<uint8_t>& payload) {
	size_t i = 0;
	while (i < payload.size() && payload[i] != 0) {
		const char code = (char)payload[i++];
		const size_t start = i;
		while (i < payload.size() && payload[i] != 0) i++;
		if (code == 'C') return std::string((const char*)payload.data() + start, i - start);
		if (i < payload.size()) i++;
	}
	return "";
}

// What the client receives up to the ReadyForQuery, one token per message: "1 2 D=42 C Z(I)". A
// DataRow shows its first column, an error its SQLSTATE, a ReadyForQuery its status.
static std::string replies(PgConnection& c) {
	std::string out;
	for (;;) {
		char type = 0;
		std::vector<uint8_t> buf;
		c.readMessage(type, buf);
		if (type == 'N' || type == 'S') continue;   // notices and parameter changes answer nothing
		if (!out.empty()) out += ' ';
		out += type;
		if (type == 'D' && buf.size() >= 6) {
			const int32_t len = (int32_t)((buf[2] << 24) | (buf[3] << 16) | (buf[4] << 8) | buf[5]);
			out += "=" + (len < 0 ? std::string("NULL") : std::string((const char*)buf.data() + 6, len));
		} else if (type == 'E') {
			out += "(" + errorSqlstate(buf) + ")";
		} else if (type == 'Z' && buf.size() >= 1) {
			out += std::string("(") + (char)buf[0] + ")";
			break;
		}
	}
	return out;
}

static PgConnection::Param text(const std::string& v) { return PgConnection::Param{ v, 0 }; }

// Parse + Bind + Execute of one statement, no Sync.
static void pbe(PgConnection& c, const std::string& name, const std::string& sql, const std::vector<PgConnection::Param>& params = {}) {
	c.prepareStatement(name, sql, false);
	c.bindStatement(name, "", params, {}, false);
	c.executePortal("", 0, false);
}

static std::unique_ptr<PgConnection> client() {
	std::unique_ptr<PgConnection> c(new PgConnection(5000));
	c->connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
	return c;
}

// Runs a scenario and returns what it reports; an exception (a timeout, a closed connection) is
// reported instead of escaping.
template <typename F>
static std::string run(F f) {
	try {
		return f();
	} catch (const PgException& e) {
		return std::string("threw: ") + e.what();
	}
}

static long ruleHits(PGconn* admin, int rule_id) {
	return execLong(admin, "SELECT hits FROM stats_pgsql_query_rules WHERE rule_id=" + std::to_string(rule_id));
}
// Hits reach the stats table on the worker's housekeeping pass: wait until they stop moving.
static long settledHits(PGconn* admin, int rule_id, long before) {
	long last = ruleHits(admin, rule_id), stable_since = 0;
	for (int i = 0; i < 60; i++) {
		usleep(100000);
		const long now = ruleHits(admin, rule_id);
		if (now != last) { last = now; stable_since = 0; continue; }
		if (last > before && ++stable_since >= 10) break;
	}
	return last;
}

// A rule on the digest; column/value add one action, e.g. "multiplex", "0".
static bool addRule(PGconn* admin, int id, const std::string& digest, const std::string& column = "", const std::string& value = "") {
	const std::string extra_col = column.empty() ? "" : ", " + column;
	const std::string extra_val = column.empty() ? "" : ", " + value;
	return exec(admin, "INSERT INTO pgsql_query_rules (rule_id, active, match_digest, apply" + extra_col + ") VALUES ("
			+ std::to_string(id) + ", 1, '" + digest + "', 1" + extra_val + ")")
		&& exec(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
}
static void dropRules(PGconn* admin) {
	exec(admin, "DELETE FROM pgsql_query_rules WHERE rule_id BETWEEN 7700 AND 7799");
	exec(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
}

int main(int, char**) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}
	plan(45);
	tag = std::to_string(getpid()) + "_" + std::to_string(time(nullptr) % 100000);

	PGConnPtr admin = openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, nullptr);
	PGConnPtr be = openConn(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_server_username, cl.pgsql_server_password, cl.pgsql_username);
	if (PQstatus(admin.get()) != CONNECTION_OK || PQstatus(be.get()) != CONNECTION_OK)
		BAIL_OUT("cannot reach the admin interface or the backend");
	dropRules(admin.get());
	const char* mode_name[2] = { "libpq", "native" };
	std::string r[2];

	// --- A statement no backend has prepared goes out with its Bind and Execute; the next unit reuses it.
	for (int m = 0; m < 2; m++) {
		setNativeMode(admin.get(), m == 1);
		r[m] = run([&]() {
			auto c = client();
			pbe(*c, "s_new", "SELECT $1::int + 1 AS new_" + tag + "_" + mode_name[m], { text("41") });
			c->sendSync();
			std::string out = replies(*c);
			c->bindStatement("s_new", "", { text("1") }, {}, false);
			c->executePortal("", 0, false);
			c->sendSync();
			return out + " | " + replies(*c);
		});
	}
	ok(r[1] == "1 2 D=42 C Z(I) | 2 D=2 C Z(I)", "new statement: Parse, Bind and Execute in one unit, reused by the next [%s]", r[1].c_str());
	ok(r[0] == r[1], "new statement: same replies as libpq [libpq: %s]", r[0].c_str());

	// --- The same new text Parsed twice in a unit under two names: one Parse reaches the backend.
	for (int m = 0; m < 2; m++) {
		setNativeMode(admin.get(), m == 1);
		r[m] = run([&]() {
			auto c = client();
			const std::string sql = "SELECT $1::int AS dup_" + tag + "_" + mode_name[m];
			pbe(*c, "s_d1", sql, { text("5") });
			pbe(*c, "s_d2", sql, { text("6") });
			c->sendSync();
			std::string out = replies(*c);
			c->bindStatement("s_d2", "", { text("7") }, {}, false);
			c->executePortal("", 0, false);
			c->sendSync();
			return out + " | " + replies(*c);
		});
	}
	ok(r[1] == "1 2 D=5 C 1 2 D=6 C Z(I) | 2 D=7 C Z(I)", "same text Parsed twice: both names usable [%s]", r[1].c_str());
	ok(r[0] == r[1], "same text Parsed twice: same replies as libpq [libpq: %s]", r[0].c_str());

	// --- ProxySQL's own reply waits for the replies before it: P2 is known, so its ParseComplete is
	// answered locally, yet it must come after E1's rows.
	for (int m = 0; m < 2; m++) {
		setNativeMode(admin.get(), m == 1);
		r[m] = run([&]() {
			auto c = client();
			const std::string known = "SELECT 'b' || $1 AS known_" + tag;
			c->prepareStatement("s_warm", known, false); c->sendSync();   // makes the text known
			replies(*c);
			pbe(*c, "s_a", "SELECT 'a' || $1 AS order_" + tag + "_" + mode_name[m], { text("1") });
			pbe(*c, "s_b", known, { text("2") });
			c->sendSync();
			return replies(*c);
		});
	}
	ok(r[1] == "1 2 D=a1 C 1 2 D=b2 C Z(I)", "ordering: a local ParseComplete waits for the Execute before it [%s]", r[1].c_str());
	ok(r[0] == r[1], "ordering: same replies as libpq [libpq: %s]", r[0].c_str());

	// --- An error skips what follows, ProxySQL's own replies included, and commits none of it: the
	// skipped Parse's name is still free afterwards.
	for (int m = 0; m < 2; m++) {
		setNativeMode(admin.get(), m == 1);
		r[m] = run([&]() {
			auto c = client();
			const std::string known = "SELECT 2 AS late_" + tag;
			c->prepareStatement("s_warm2", known, false); c->sendSync();
			replies(*c);
			pbe(*c, "s_err", "SELECT 1 / $1::int AS div_" + tag + "_" + mode_name[m], { text("0") });
			pbe(*c, "s_late", known);
			c->sendSync();
			std::string out = replies(*c);
			c->prepareStatement("s_late", "SELECT 3", false); c->sendSync();
			return out + " | " + replies(*c);
		});
	}
	ok(r[1] == "1 2 E(22012) Z(I) | 1 Z(I)", "error: the rest of the unit is skipped and its Parse never took the name [%s]", r[1].c_str());
	ok(r[0] == r[1], "error: same replies as libpq [libpq: %s]", r[0].c_str());

	// --- A multiplex=0 rule pins the connection to the session after a batched unit.
	for (int m = 0; m < 2; m++) {
		setNativeMode(admin.get(), m == 1);
		addRule(admin.get(), 7701, "mux_" + tag, "multiplex", "0");
		long used = -2;
		r[m] = run([&]() {
			auto c = client();
			pbe(*c, "s_mux", "SELECT 1 AS mux_" + tag + "_" + mode_name[m]);
			c->sendSync();
			const std::string out = replies(*c);
			usleep(300000);
			used = connUsed(admin.get());   // the client is still connected
			return out;
		});
		r[m] += " used=" + std::to_string(used);
		dropRules(admin.get());
	}
	ok(r[1] == "1 2 D=1 C Z(I) used=1", "multiplex=0 rule: the connection stays with the session [%s]", r[1].c_str());
	ok(r[0] == r[1], "multiplex=0 rule: as with libpq [libpq: %s]", r[0].c_str());

	// --- Rule hits count each message once, and an OK rule answers its Execute in place.
	long hits[2] = { 0, 0 }, ok_hits[2] = { 0, 0 };
	for (int m = 0; m < 2; m++) {
		setNativeMode(admin.get(), m == 1);
		addRule(admin.get(), 7702, "hits_" + tag);
		const long before = ruleHits(admin.get(), 7702);
		r[m] = run([&]() {
			auto c = client();
			pbe(*c, "s_h1", "SELECT 1 AS hits_" + tag);
			pbe(*c, "s_h2", "SELECT 2 AS hits_" + tag + "_2");
			c->sendSync();
			return replies(*c);
		});
		hits[m] = settledHits(admin.get(), 7702, before) - before;
		dropRules(admin.get());
		addRule(admin.get(), 7703, "okrule_" + tag, "OK_msg", "'okay'");
		const long ok_before = ruleHits(admin.get(), 7703);
		r[m] += " | " + run([&]() {
			auto c = client();
			pbe(*c, "s_p", "SELECT 5 AS plain_" + tag + "_" + mode_name[m]);
			pbe(*c, "s_ok", "SELECT 6 AS okrule_" + tag);
			c->sendSync();
			return replies(*c);
		});
		ok_hits[m] = settledHits(admin.get(), 7703, ok_before) - ok_before;
		dropRules(admin.get());
	}
	ok(hits[1] > 0 && hits[1] == hits[0], "rule hits: each message counted once, as with libpq [native %ld, libpq %ld]", hits[1], hits[0]);
	ok(ok_hits[1] > 0 && ok_hits[1] == ok_hits[0], "OK rule hits: as with libpq [native %ld, libpq %ld]", ok_hits[1], ok_hits[0]);
	ok(r[1].find(" | 1 2 D=5 C 1 2 C") != std::string::npos, "OK rule: its Execute is answered in place, after the rows before it [%s]", r[1].c_str());

	// --- A SET in the unit: the statement before it runs under the old value, the next unit under the new.
	for (int m = 0; m < 2; m++) {
		setNativeMode(admin.get(), m == 1);
		r[m] = run([&]() {
			auto c = client();
			pbe(*c, "s_before", "SELECT current_setting('extra_float_digits') AS before_" + tag + "_" + mode_name[m]);
			pbe(*c, "s_set", "SET extra_float_digits TO 3");
			c->sendSync();
			std::string out = replies(*c);
			pbe(*c, "s_after", "SELECT current_setting('extra_float_digits') AS after_" + tag + "_" + mode_name[m]);
			c->sendSync();
			return out + " | " + replies(*c);
		});
	}
	ok(r[1].rfind("1 2 D=1 C", 0) == 0 && r[1].find(" | 1 2 D=3 C Z(I)") != std::string::npos,
		"SET in a unit: the statement before it sees the old value, the next unit the new [%s]", r[1].c_str());
	ok(r[0] == r[1], "SET in a unit: same replies as libpq [libpq: %s]", r[0].c_str());

	// --- An error rule after buffered work: the earlier rows, then the error, then ReadyForQuery.
	{
		setNativeMode(admin.get(), true);
		addRule(admin.get(), 7704, "errrule_" + tag, "error_msg", "'refused by rule'");
		const long ok_before = connOK(admin.get());
		r[1] = run([&]() {
			auto c = client();
			pbe(*c, "s_fine", "SELECT 7 AS fine_" + tag);
			pbe(*c, "s_refused", "SELECT 8 AS errrule_" + tag);
			c->sendSync();
			std::string out = replies(*c);
			c->sendQuery("SELECT 9");
			return out + " | " + replies(*c);
		});
		dropRules(admin.get());
		const long opened = connOK(admin.get()) - ok_before;
		ok(r[1] == "1 2 D=7 C E(42501) Z(I) | T D=9 C Z(I)", "error rule after buffered work: rows, error, ReadyForQuery, session usable [%s]", r[1].c_str());
		ok(opened == 1, "error rule after buffered work: the backend fails the work and the connection is kept [opened %ld]", opened);
	}

	// --- ProxySQL's own error after a BEGIN in the same unit: the BEGIN has not run when the error is
	// found, yet the transaction must fail as on PostgreSQL, so INSERT 2 is refused and COMMIT rolls
	// back. Again with a SET that cuts the unit short first, after which the connection's last status
	// still says idle.
	for (int cut = 0; cut < 2; cut++) {
		setNativeMode(admin.get(), true);
		const std::string tbl = "extq_begin_" + tag + "_" + std::to_string(cut);
		createTable(be.get(), tbl);
		r[1] = run([&]() {
			auto c = client();
			pbe(*c, "", "BEGIN");
			pbe(*c, "", "INSERT INTO " + tbl + " VALUES (1)");
			if (cut) pbe(*c, "", "SET application_name TO 'extq_begin_" + tag + "'");
			c->bindStatement("s_missing", "", {}, {}, false);
			c->executePortal("", 0, false);
			c->sendSync();
			std::string out = replies(*c);
			c->sendQuery("INSERT INTO " + tbl + " VALUES (2)");
			out += " | " + replies(*c);
			c->sendQuery("COMMIT");
			return out + " | " + replies(*c);
		});
		const std::string want = std::string(cut ? "1 2 C 1 2 C 1 2 C" : "1 2 C 1 2 C") + " E(26000) Z(E) | E(25P02) Z(E) | C Z(I)";
		ok(r[1] == want, "own error after a BEGIN in the unit%s: failed transaction, COMMIT rolls back [%s]",
			cut ? ", cut short by SET" : "", r[1].c_str());
		ok(execLong(be.get(), "SELECT count(*) FROM " + tbl) == 0, "own error after a BEGIN in the unit%s: nothing committed",
			cut ? ", cut short by SET" : "");
		exec(be.get(), "DROP TABLE IF EXISTS " + tbl);
	}

	// --- No transaction, a SET cuts the unit short, then ProxySQL's own error: the INSERT before it is
	// rolled back as on PostgreSQL, and the connection that held it is kept for the next statement.
	{
		setNativeMode(admin.get(), true);
		const std::string tbl = "extq_cutnotx_" + tag;
		createTable(be.get(), tbl);
		const long ok_before = connOK(admin.get());
		r[1] = run([&]() {
			auto c = client();
			pbe(*c, "", "INSERT INTO " + tbl + " VALUES (1)");
			pbe(*c, "", "SET application_name TO 'extq_cutnotx_" + tag + "'");
			c->bindStatement("s_missing", "", {}, {}, false);
			c->executePortal("", 0, false);
			c->sendSync();
			std::string out = replies(*c);
			c->sendQuery("SELECT 9");
			return out + " | " + replies(*c);
		});
		const long opened = connOK(admin.get()) - ok_before;
		const long rows = execLong(be.get(), "SELECT count(*) FROM " + tbl);
		ok(r[1] == "1 2 C 1 2 C E(26000) Z(I) | T D=9 C Z(I)" && rows == 0 && opened == 1,
			"own error after a SET cut, no transaction: the INSERT is rolled back and the connection kept [%s, rows %ld, opened %ld]",
			r[1].c_str(), rows, opened);
		exec(be.get(), "DROP TABLE IF EXISTS " + tbl);
	}

	// --- BEGIN, INSERT, SAVEPOINT, INSERT and then ProxySQL's own error, all in one unit, the way pgjdbc
	// sends autosave: ROLLBACK TO SAVEPOINT must keep the INSERT made before the savepoint.
	{
		setNativeMode(admin.get(), true);
		const std::string tbl = "extq_sp_" + tag;
		createTable(be.get(), tbl);
		r[1] = run([&]() {
			auto c = client();
			pbe(*c, "", "BEGIN");
			pbe(*c, "", "INSERT INTO " + tbl + " VALUES (1)");
			pbe(*c, "", "SAVEPOINT sp");
			pbe(*c, "", "INSERT INTO " + tbl + " VALUES (2)");
			c->bindStatement("s_missing", "", {}, {}, false);
			c->executePortal("", 0, false);
			c->sendSync();
			std::string out = replies(*c);
			c->sendQuery("ROLLBACK TO SAVEPOINT sp");
			out += " | " + replies(*c);
			c->sendQuery("INSERT INTO " + tbl + " VALUES (3)");
			out += " | " + replies(*c);
			c->sendQuery("COMMIT");
			return out + " | " + replies(*c);
		});
		const std::string kept = execScalar(be.get(), "SELECT string_agg(a::text, ',' ORDER BY a) FROM " + tbl);
		ok(r[1] == "1 2 C 1 2 C 1 2 C 1 2 C E(26000) Z(E) | C Z(T) | C Z(T) | C Z(I)" && kept == "1,3",
			"own error after a SAVEPOINT in the unit: ROLLBACK TO SAVEPOINT keeps the work before it [%s, rows %s]",
			r[1].c_str(), kept.c_str());
		exec(be.get(), "DROP TABLE IF EXISTS " + tbl);
	}

	// --- A SET ProxySQL cannot parse pins the session to its hostgroup, and from then on ProxySQL does not
	// track BEGIN and COMMIT itself. Its own error inside the transaction must still fail it.
	{
		setNativeMode(admin.get(), true);
		const std::string lock_on = execScalar(admin.get(),
			"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-set_query_lock_on_hostgroup'");
		const std::string tbl = "extq_lock_" + tag;
		createTable(be.get(), tbl);
		r[1] = run([&]() {
			auto c = client();
			c->sendQuery("SET extq_batch.flag = 'x'");
			std::string out = replies(*c);
			c->sendQuery("BEGIN");
			out += " | " + replies(*c);
			c->sendQuery("INSERT INTO " + tbl + " VALUES (1)");
			out += " | " + replies(*c);
			c->bindStatement("s_missing", "", {}, {}, false);
			c->executePortal("", 0, false);
			c->sendSync();
			out += " | " + replies(*c);
			c->sendQuery("INSERT INTO " + tbl + " VALUES (2)");
			out += " | " + replies(*c);
			c->sendQuery("COMMIT");
			return out + " | " + replies(*c);
		});
		const long rows = execLong(be.get(), "SELECT count(*) FROM " + tbl);
		ok(lock_on == "1" && r[1] == "C Z(I) | C Z(T) | C Z(T) | E(26000) Z(E) | E(25P02) Z(E) | C Z(I)" && rows == 0,
			"own error in a transaction on a hostgroup-locked session: the transaction fails, nothing committed [lock=%s, %s, rows %ld]",
			lock_on.c_str(), r[1].c_str(), rows);
		exec(be.get(), "DROP TABLE IF EXISTS " + tbl);
	}

	// --- ProxySQL's own error after buffered work inside a transaction block: the work is rolled
	// back with the connection, and the client is in a failed transaction until it rolls back.
	{
		setNativeMode(admin.get(), true);
		const std::string tbl = "extq_batch_" + tag;
		createTable(be.get(), tbl);
		r[1] = run([&]() {
			auto c = client();
			c->sendQuery("BEGIN");
			std::string out = replies(*c);
			pbe(*c, "s_ins", "INSERT INTO " + tbl + " VALUES (1)");
			c->bindStatement("s_missing", "", {}, {}, false);
			c->executePortal("", 0, false);
			c->sendSync();
			out += " | " + replies(*c);
			c->sendQuery("SELECT 1");
			out += " | " + replies(*c);
			c->sendQuery("ROLLBACK");
			out += " | " + replies(*c);
			return out;
		});
		ok(r[1].find(" | 1 2 C E(26000) Z(E) | ") != std::string::npos,
			"local error in a transaction: the error, then ReadyForQuery 'E' [%s]", r[1].c_str());
		ok(r[1].find(" | E(25P02) Z(E) | ") != std::string::npos && r[1].size() > 7 && r[1].substr(r[1].size() - 7) == " C Z(I)",
			"local error in a transaction: the next statement is refused until ROLLBACK, which ends it [%s]", r[1].c_str());
		ok(execLong(be.get(), "SELECT count(*) FROM " + tbl) == 0, "local error in a transaction: the buffered INSERT was rolled back");
		exec(be.get(), "DROP TABLE IF EXISTS " + tbl);
	}

	// --- A unit ProxySQL answers entirely by itself takes no connection.
	for (int m = 0; m < 2; m++) {
		setNativeMode(admin.get(), m == 1);
		const std::string known = "SELECT 1 AS cached_" + tag;
		r[m] = run([&]() { auto c = client(); c->prepareStatement("s_c", known, false); c->sendSync(); return replies(*c); });
		resetPool(admin.get());
		const long before = connOK(admin.get());
		r[m] += " | " + run([&]() { auto c = client(); c->prepareStatement("s_c2", known, false); c->sendSync(); return replies(*c); });
		r[m] += " opened=" + std::to_string(connOK(admin.get()) - before) + " pooled=" + std::to_string(pooled(admin.get()));
	}
	ok(r[1] == "1 Z(I) | 1 Z(I) opened=0 pooled=0", "cached Parse only: answered without a connection [%s]", r[1].c_str());
	ok(r[0] == r[1], "cached Parse only: as with libpq [libpq: %s]", r[0].c_str());

	// --- Two Executes of the unnamed portal: the same answer as the one-message path.
	for (int m = 0; m < 2; m++) {
		setNativeMode(admin.get(), m == 1);
		r[m] = run([&]() {
			auto c = client();
			c->prepareStatement("s_twice", "SELECT 4 AS twice_" + tag + "_" + mode_name[m], false);
			c->bindStatement("s_twice", "", {}, {}, false);
			c->executePortal("", 0, false);
			c->executePortal("", 0, false);
			c->sendSync();
			std::string out = replies(*c);
			c->sendQuery("SELECT 1");
			return out + " | " + replies(*c);
		});
	}
	ok(r[0] == r[1], "Bind Execute Execute: same replies as libpq [native: %s] [libpq: %s]", r[1].c_str(), r[0].c_str());

	// --- ProxySQL's own Parse fails (the table is gone): the error belongs to the client's Execute.
	for (int m = 0; m < 2; m++) {
		setNativeMode(admin.get(), m == 1);
		const std::string tbl = "extq_gone_" + tag + "_" + mode_name[m];
		createTable(be.get(), tbl);
		r[m] = run([&]() {
			auto c = client();
			c->prepareStatement("s_gone", "SELECT a FROM " + tbl, false);
			c->bindStatement("s_gone", "", {}, {}, false);
			c->executePortal("", 0, false);
			c->sendSync();
			std::string out = replies(*c);
			exec(be.get(), "DROP TABLE " + tbl);
			resetPool(admin.get());   // the next connection lacks the statement
			c->bindStatement("s_gone", "", {}, {}, false);
			c->executePortal("", 0, false);
			c->sendSync();
			return out + " | " + replies(*c);
		});
	}
	ok(r[1] == "1 2 C Z(I) | 2 E(42P01) Z(I)", "own Parse fails: the client's Execute gets the error [%s]", r[1].c_str());
	ok(r[0] == r[1], "own Parse fails: same replies as libpq [libpq: %s]", r[0].c_str());

	// --- A connection pooled before the native protocol was turned on is replaced, not used.
	{
		setNativeMode(admin.get(), false);
		const std::string pre = run([&]() { auto c = client(); c->sendQuery("SELECT 1"); return replies(*c); });
		const long pooled_before = pooledWithin(admin.get(), 1, 5);
		setNativeMode(admin.get(), true, false);   // the libpq connection stays pooled
		const long ok_before = connOK(admin.get());
		r[1] = run([&]() {
			auto c = client();
			pbe(*c, "s_stale", "SELECT 3 AS stale_" + tag);
			c->sendSync();
			return replies(*c);
		});
		const long opened = connOK(admin.get()) - ok_before;
		ok(pre == "T D=1 C Z(I)" && pooled_before == 1, "stale libpq connection: one is pooled before the switch [%s, pooled %ld]", pre.c_str(), pooled_before);
		ok(r[1] == "1 2 D=3 C Z(I)" && opened == 1,
			"stale libpq connection: the unit opens a native connection instead of using it [%s, opened %ld]", r[1].c_str(), opened);
	}

	// --- A client Flush: the same answer as before the batch path existed.
	for (int m = 0; m < 2; m++) {
		setNativeMode(admin.get(), m == 1);
		r[m] = run([&]() {
			auto c = client();
			pbe(*c, "s_flush", "SELECT 1 AS flush_" + tag + "_" + mode_name[m]);
			c->sendMessage('H', {});
			return replies(*c);
		});
	}
	ok(r[0] == r[1], "client Flush: same replies as libpq [native: %s] [libpq: %s]", r[1].c_str(), r[0].c_str());

	// --- A statement ProxySQL answers itself, reached after a Parse already went to the backend: the
	// batch is cut short there and the rest of the unit runs on the same connection. The session must
	// stay up and answer like libpq.
	for (int m = 0; m < 2; m++) {
		setNativeMode(admin.get(), m == 1);
		r[m] = run([&]() {
			auto c = client();
			pbe(*c, "s_kill", "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid = $1::int AND application_name = $2 /* kill_" + tag + "_" + mode_name[m] + " */",
				{ text("2147483647"), text("no_such_application_" + tag) });
			c->sendSync();
			std::string out = replies(*c);
			c->sendQuery("SELECT 1");
			return out + " | " + replies(*c);
		});
	}
	ok(r[1].size() > 0 && r[1].find("threw") == std::string::npos && r[1].substr(r[1].size() - 12) == "T D=1 C Z(I)",
		"special statement after a sent Parse: the session survives [%s]", r[1].c_str());
	ok(r[0] == r[1], "special statement after a sent Parse: same replies as libpq [native: %s] [libpq: %s]", r[1].c_str(), r[0].c_str());

	// --- A large unit: a thousand INSERTs, more than one batch holds, all applied in order.
	{
		setNativeMode(admin.get(), true);
		const std::string tbl = "extq_many_" + tag;
		createTable(be.get(), tbl);
		r[1] = run([&]() {
			auto c = client();
			c->prepareStatement("s_many", "INSERT INTO " + tbl + " VALUES ($1::int)", false);
			for (int i = 0; i < 1000; i++) {
				c->bindStatement("s_many", "", { text(std::to_string(i)) }, {}, false);
				c->executePortal("", 0, false);
			}
			c->sendSync();
			const std::string out = replies(*c);
			size_t completes = 0;
			for (size_t p = out.find('C'); p != std::string::npos; p = out.find('C', p + 1)) completes++;
			return std::to_string(completes) + " " + out.substr(out.size() - 4);
		});
		ok(r[1] == "1000 Z(I)", "large unit: every Execute answered [%s]", r[1].c_str());
		ok(execLong(be.get(), "SELECT count(*) FROM " + tbl) == 1000 && execLong(be.get(), "SELECT sum(a) FROM " + tbl) == 499500,
			"large unit: every row written");
		exec(be.get(), "DROP TABLE IF EXISTS " + tbl);
	}

	// --- A unit several batches long fails in its third: the batches before it end in a Flush, not a
	// Sync, so the whole unit is one transaction and none of it stays, as on PostgreSQL.
	{
		setNativeMode(admin.get(), true);
		const std::string tbl = "extq_chunkerr_" + tag;
		createTable(be.get(), tbl);
		exec(be.get(), "ALTER TABLE " + tbl + " ADD CHECK (a <> 1500)");
		r[1] = run([&]() {
			auto c = client();
			c->prepareStatement("s_chunk", "INSERT INTO " + tbl + " VALUES ($1::int)", false);
			for (int i = 0; i < 2500; i++) {
				c->bindStatement("s_chunk", "", { text(std::to_string(i)) }, {}, false);
				c->executePortal("", 0, false);
			}
			c->sendSync();
			const std::string out = replies(*c);
			size_t completes = 0;
			for (size_t p = out.find(" C"); p != std::string::npos; p = out.find(" C", p + 1)) completes++;
			const size_t err = out.find("E(");
			std::string tail = err == std::string::npos ? "no error" : out.substr(err);
			c->sendQuery("SELECT 9");
			return std::to_string(completes) + " " + tail + " | " + replies(*c);
		});
		const long rows = execLong(be.get(), "SELECT count(*) FROM " + tbl);
		ok(r[1] == "1500 E(23514) Z(I) | T D=9 C Z(I)" && rows == 0,
			"unit over several batches, error in the third: nothing after it answered, none of it kept [%s, rows %ld]",
			r[1].c_str(), rows);
		exec(be.get(), "DROP TABLE IF EXISTS " + tbl);
	}

	// --- A large result inside a unit is passed on as it arrives, and the unit after it is unaffected.
	{
		setNativeMode(admin.get(), true);
		r[1] = run([&]() {
			auto c = client();
			pbe(*c, "s_big", "SELECT repeat('x', 1000) FROM generate_series(1, 20000) AS big_" + tag);
			pbe(*c, "s_after_big", "SELECT 11 AS after_big_" + tag);
			c->sendSync();
			const std::string out = replies(*c);
			size_t rows = 0;
			for (size_t p = out.find("D="); p != std::string::npos; p = out.find("D=", p + 1)) rows++;
			const std::string tail = " C 1 2 D=11 C Z(I)";
			const bool tail_ok = out.size() > tail.size() && out.compare(out.size() - tail.size(), tail.size(), tail) == 0;
			return std::to_string(rows) + (tail_ok ? " tail ok" : " tail: " + out.substr(out.size() > 40 ? out.size() - 40 : 0));
		});
		ok(r[1] == "20001 tail ok", "large result: all rows, then the next statement's [%s]", r[1].c_str());
	}

	// --- Implicit Sync: a simple Query right after an extended unit without Sync.
	for (int m = 0; m < 2; m++) {
		setNativeMode(admin.get(), m == 1);
		r[m] = run([&]() {
			auto c = client();
			pbe(*c, "s_impl", "SELECT 12 AS implicit_" + tag + "_" + mode_name[m]);
			c->sendQuery("SELECT 13");
			return replies(*c);
		});
	}
	ok(r[1] == "1 2 D=12 C T D=13 C Z(I)", "implicit Sync: one ReadyForQuery, after the simple Query [%s]", r[1].c_str());
	ok(r[0] == r[1], "implicit Sync: same replies as libpq [libpq: %s]", r[0].c_str());

	// --- A Describe of the unnamed portal logs the statement it described, though a later Bind in the
	// unit replaces that portal before the Describe's reply arrives.
	{
		const std::string def_log = execScalar(admin.get(), "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-eventslog_default_log'");
		const std::string buf_size = execScalar(admin.get(), "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-eventslog_buffer_history_size'");
		exec(admin.get(), "SET pgsql-eventslog_default_log=1");
		exec(admin.get(), "SET pgsql-eventslog_buffer_history_size=100000");
		exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
		setNativeMode(admin.get(), true);
		const std::string sql = "SELECT 21 AS dsc_a_" + tag;
		r[1] = run([&]() {
			auto c = client();
			c->prepareStatement("s_dsc_a", sql, false);
			c->prepareStatement("s_dsc_b", "SELECT 22 AS dsc_b_" + tag, false);
			c->bindStatement("s_dsc_a", "", {}, {}, false);
			c->describePortal("", false);
			c->bindStatement("s_dsc_b", "", {}, {}, false);
			c->executePortal("", 0, false);
			c->sendSync();
			return replies(*c);
		});
		exec(admin.get(), "DUMP PGSQL EVENTSLOG FROM BUFFER TO MEMORY");
		// The Parse and the Describe of the first statement, both under its name.
		r[1] += " | " + execScalar(admin.get(), "SELECT group_concat(client_stmt_name, ' ') FROM (SELECT client_stmt_name "
			"FROM stats_pgsql_query_events WHERE query = '" + sql + "' ORDER BY event_type)");
		exec(admin.get(), "SET pgsql-eventslog_default_log=" + (def_log.empty() ? "0" : def_log));
		exec(admin.get(), "SET pgsql-eventslog_buffer_history_size=" + (buf_size.empty() ? "0" : buf_size));
		exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	}
	ok(r[1] == "1 1 2 T 2 D=22 C Z(I) | s_dsc_a s_dsc_a", "unnamed-portal Describe: logged under its own statement [%s]", r[1].c_str());

	// --- The backend dies mid-batch inside a transaction: the session is kept in a failed transaction
	// and the first statement not yet answered, a named Bind, is logged on the way out. A Bind has no
	// text of its own, so the record must carry its statement's, not what the Parse before it left
	// behind (freed by then). Command stats are off: with them on, that leftover is cleared first.
	{
		const auto var = [&](const char* n) {
			return execScalar(admin.get(), std::string("SELECT variable_value FROM global_variables WHERE variable_name='") + n + "'");
		};
		const std::string def_log = var("pgsql-eventslog_default_log");
		const std::string buf_size = var("pgsql-eventslog_buffer_history_size");
		const std::string cmd_stats = var("pgsql-commands_stats");
		exec(admin.get(), "SET pgsql-eventslog_default_log=1");
		exec(admin.get(), "SET pgsql-eventslog_buffer_history_size=100000");
		exec(admin.get(), "SET pgsql-commands_stats='false'");
		exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
		setNativeMode(admin.get(), true);
		const std::string known = "SELECT 4 AS failed_bind_" + tag;
		const std::string name = "s_fb_" + tag;
		r[1] = run([&]() {
			auto w = client();
			w->prepareStatement("s_fb_warm", known, false);   // the unit's Parse of this text is then answered locally
			w->sendSync();
			replies(*w);
			auto c = client();
			c->sendQuery("BEGIN");
			std::string out = replies(*c);
			pbe(*c, "", "SELECT pg_sleep(3) AS fb_sleep_" + tag);
			c->prepareStatement(name, known, false);
			c->bindStatement(name, "p_fb", {}, {}, false);
			c->sendSync();
			usleep(1000000);
			exec(be.get(), "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE query LIKE '%fb_sleep_" + tag
				+ "%' AND pid <> pg_backend_pid()");
			return out + " | " + replies(*c);
		});
		exec(admin.get(), "DUMP PGSQL EVENTSLOG FROM BUFFER TO MEMORY");
		const std::string failed = "FROM stats_pgsql_query_events WHERE client_stmt_name='" + name + "' AND event_type=0";
		const long records = execLong(admin.get(), "SELECT count(*) " + failed);
		const long with_text = execLong(admin.get(), "SELECT count(*) " + failed + " AND instr(query, 'failed_bind_" + tag + "') > 0");
		exec(admin.get(), "SET pgsql-eventslog_default_log=" + (def_log.empty() ? "0" : def_log));
		exec(admin.get(), "SET pgsql-eventslog_buffer_history_size=" + (buf_size.empty() ? "0" : buf_size));
		exec(admin.get(), "SET pgsql-commands_stats='" + (cmd_stats.empty() ? std::string("true") : cmd_stats) + "'");
		exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
		ok(r[1] == "C Z(T) | E(25P02) Z(E)" && records == 1 && with_text == 1,
			"backend dies mid-batch: the unanswered Bind is logged with its statement's text [%s, records %ld, with text %ld]",
			r[1].c_str(), records, with_text);
	}

	dropRules(admin.get());
	setNativeMode(admin.get(), false);
	return exit_status();
}
