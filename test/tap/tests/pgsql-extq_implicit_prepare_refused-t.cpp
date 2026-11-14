/**
 * @file pgsql-extq_implicit_prepare_refused-t.cpp
 * @brief A client runs a statement it prepared earlier on a backend connection that does not hold
 *        it, so ProxySQL prepares it there first. When the backend refuses that Parse, the client
 *        must get the error and keep its connection, as with PostgreSQL. ProxySQL used to close it.
 *
 * Only a backend connection other than the one that prepared the statement lacks it, so each case
 * empties the pool between the client's Parse and its Execute, Describe or Bind. Each case runs
 * through ProxySQL and straight against PostgreSQL, the replies are compared, and each ends with a
 * query that shows the connection still works.
 */

#include <chrono>
#include <cstring>
#include <ctime>
#include <functional>
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
static std::string tag;
static PGconn* admin = nullptr;
static PGconn* be = nullptr;   // straight to PostgreSQL, as its superuser
static bool through_proxy = false;

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
static long execLong(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	long v = -1;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0)) v = atol(PQgetvalue(r, 0, 0));
	PQclear(r);
	return v;
}

// Tables are made as the superuser: in Docker the test user cannot create them.
static void createTable(const std::string& t) {
	exec(be, "CREATE TABLE " + t + " (a int)");
	exec(be, "GRANT ALL ON " + t + " TO " + std::string(cl.pgsql_username));
}

// Closes every backend connection of the hostgroup, so the next statement runs on a new one.
static void emptyPool() {
	const std::string hg = std::to_string(HG);
	if (!exec(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" + hg)
	    || !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not take hostgroup %s offline", hg.c_str());
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	long left = -1;
	while (std::chrono::steady_clock::now() < deadline) {
		left = execLong(admin, "SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + hg);
		if (left == 0) break;
		usleep(100000);
	}
	if (left != 0) BAIL_OUT("the pool did not drain (%ld connections left)", left);
	if (!exec(admin, "UPDATE pgsql_servers SET status='ONLINE' WHERE hostgroup_id=" + hg)
	    || !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not bring hostgroup %s back", hg.c_str());
	usleep(200000);
}

// A pooled connection keeps the protocol it was opened with, so the pool is emptied too.
static void setMode(bool native) {
	if (!exec(admin, std::string("SET pgsql-use_native_backend_protocol='") + (native ? "true" : "false") + "'")
	    || !exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME"))
		BAIL_OUT("could not switch the backend protocol");
	emptyPool();
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

// What the client receives up to the ReadyForQuery, one token per message: "1 2 D=1 C Z(T)".
static std::string replies(PgConnection& c) {
	std::string out;
	for (;;) {
		char type = 0;
		std::vector<uint8_t> buf;
		c.readMessage(type, buf);
		if (type == 'S' || type == 'N') continue;
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

static std::string simple(PgConnection& c, const std::string& sql) {
	c.sendQuery(sql);
	return replies(c);
}

using Frame = std::function<std::string(PgConnection&)>;

// Straight to PostgreSQL the frames run as its superuser, unless 'direct_as_test_user' is set: a
// privilege only bites the test user.
static bool direct_as_test_user = false;

static void connectTo(PgConnection& c, bool proxy) {
	if (proxy) {
		c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
	} else if (direct_as_test_user) {
		c.connect(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
	} else {
		c.connect(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_username, cl.pgsql_server_username, cl.pgsql_server_password);
	}
}

static std::string run(Frame f, bool proxy) {
	through_proxy = proxy;
	try {
		PgConnection c(5000);
		connectTo(c, proxy);
		return f(c);
	} catch (const PgException& e) {
		return std::string("threw: ") + e.what();
	}
}

// ProxySQL holds the Bind of the unnamed portal until the Execute and answers it with BindComplete
// at once, so when the Execute fails its stream has a "2" before the error that PostgreSQL's has not.
static void check(const char* mode, const char* label, const std::string& expected, Frame f) {
	std::string proxy = run(f, true);
	const std::string direct = run(f, false);
	for (size_t at; (at = proxy.find("| 2 E(")) != std::string::npos; ) proxy.erase(at + 2, 2);
	ok(proxy == expected && proxy == direct, "%s: %s [proxy: %s] [PostgreSQL: %s] [expected: %s]",
	   mode, label, proxy.c_str(), direct.c_str(), expected.c_str());
}

// Ends the client's Parse with a Sync, and empties the pool when going through ProxySQL, so that no
// backend connection holds the statement any more.
static std::string prepareThenForget(PgConnection& c, const std::string& name, const std::string& sql,
	const std::vector<uint32_t>& types = {}) {
	c.prepareStatement(name, sql, false, types);
	c.sendSync();
	const std::string out = replies(c);
	if (through_proxy) emptyPool();
	return out;
}

// Terminates the test user's backends, as an idle timeout or a server restart would, and waits
// until they are gone. ProxySQL still holds them in its pool.
static void killBackends() {
	const std::string who = "usename='" + std::string(cl.pgsql_username) + "' AND backend_type='client backend' AND pid <> pg_backend_pid()";
	exec(be, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE " + who);
	for (int i = 0; i < 50 && execLong(be, "SELECT count(*) FROM pg_stat_activity WHERE " + who) != 0; i++) usleep(100000);
}

// Bind and Execute of statement 'name' on the unnamed portal, then Sync.
static std::string execStmt(PgConnection& c, const std::string& name, const std::vector<PgConnection::Param>& params = {}) {
	c.bindStatement(name, "", params, {}, false);
	c.executePortal("", 0, false);
	c.sendSync();
	return replies(c);
}

int main(int, char**) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}
	tag = std::to_string(getpid()) + "_" + std::to_string(time(nullptr) % 100000);

	plan(17 + 24);

	PGConnPtr admin_conn = openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, nullptr);
	if (PQstatus(admin_conn.get()) != CONNECTION_OK) BAIL_OUT("cannot reach the admin interface");
	admin = admin_conn.get();
	PGConnPtr be_conn = openConn(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_server_username,
		cl.pgsql_server_password, cl.pgsql_username);
	if (PQstatus(be_conn.get()) != CONNECTION_OK) BAIL_OUT("cannot reach PostgreSQL");
	be = be_conn.get();

	const std::string FAILED = "1 Z(I) | C Z(T) | E(22012) Z(E) | E(25P02) Z(E) | C Z(I) | ";
	const std::string user = cl.pgsql_username;
	const bool superuser = execLong(be, "SELECT rolsuper::int FROM pg_roles WHERE rolname='" + user + "'") == 1;
	const PgConnection::Param zero{ std::string("0"), 0 };

	for (int m = 0; m < 2; m++) {
		const bool native = (m == 1);
		const char* mode = native ? "native" : "libpq";
		const std::string sfx = tag + "_" + mode;
		setMode(native);

		// The statement's table is dropped after the Parse: the backend refuses the Parse with 42P01,
		// as PostgreSQL refuses the Bind. Twice in a row, then a new statement, which ProxySQL prepares
		// on the backend itself: a failure must leave nothing behind for that prepare to resume into.
		// Once the table is back the first statement works again, parameter type included.
		check(mode, "Execute after the table was dropped, twice, then a new statement, then the table back",
			"1 Z(I) | E(42P01) Z(I) | E(42P01) Z(I) | 1 Z(I) | 2 D=2 C Z(I) | 2 D=1 C Z(I)", [&](PgConnection& c) {
			const std::string t = "p53_" + sfx;
			createTable(t);
			exec(be, "INSERT INTO " + t + " VALUES (1)");
			std::string out = prepareThenForget(c, "s1", "SELECT a FROM " + t + " WHERE a > $1", { 23 });
			exec(be, "DROP TABLE " + t);
			out += " | " + execStmt(c, "s1", { zero });
			out += " | " + execStmt(c, "s1", { zero });
			c.prepareStatement("s2", "SELECT 2 AS p53n_" + sfx, false);
			c.sendSync();
			out += " | " + replies(c);
			out += " | " + execStmt(c, "s2");
			createTable(t);
			exec(be, "INSERT INTO " + t + " VALUES (1)");
			out += " | " + execStmt(c, "s1", { zero });
			exec(be, "DROP TABLE " + t);
			return out;
		});

		// In a failed transaction the backend refuses any Parse with 25P02, as PostgreSQL refuses the
		// Bind. After ROLLBACK the statement works. A SET is a statement the native batch cannot carry.
		const std::vector<std::pair<std::string, std::string>> in_failed_txn = {
			{ "SELECT 53 AS p53_" + sfx, "2 D=53 C Z(I)" },
			{ "SET DateStyle TO 'ISO, MDY'", "2 C Z(I)" },
		};
		for (const auto& q : in_failed_txn) {
			check(mode, ("Execute in a failed transaction, again after ROLLBACK: " + q.first).c_str(), FAILED + q.second,
				[&](PgConnection& c) {
				std::string out = prepareThenForget(c, "s1", q.first);
				out += " | " + simple(c, "BEGIN");
				out += " | " + simple(c, "SELECT 1/0");
				out += " | " + execStmt(c, "s1");
				out += " | " + simple(c, "ROLLBACK");
				return out + " | " + execStmt(c, "s1");
			});
		}

		check(mode, "Describe in a failed transaction, again after ROLLBACK", FAILED + "t T Z(I)", [&](PgConnection& c) {
			std::string out = prepareThenForget(c, "s1", "SELECT 54 AS p53_" + sfx);
			out += " | " + simple(c, "BEGIN");
			out += " | " + simple(c, "SELECT 1/0");
			c.describeStatement("s1", false);
			c.sendSync();
			out += " | " + replies(c);
			out += " | " + simple(c, "ROLLBACK");
			c.describeStatement("s1", false);
			c.sendSync();
			return out + " | " + replies(c);
		});

		// The refused Parse is what fails the transaction: later statements are refused until ROLLBACK.
		check(mode, "Execute after the table was dropped, inside a transaction",
			"1 Z(I) | C Z(T) | E(42P01) Z(E) | E(25P02) Z(E) | C Z(I) | T D=1 C Z(I)", [&](PgConnection& c) {
			const std::string t = "p53t_" + sfx;
			createTable(t);
			std::string out = prepareThenForget(c, "s1", "SELECT a FROM " + t);
			exec(be, "DROP TABLE " + t);
			out += " | " + simple(c, "BEGIN");
			out += " | " + execStmt(c, "s1");
			out += " | " + simple(c, "SELECT 1");
			out += " | " + simple(c, "ROLLBACK");
			return out + " | " + simple(c, "SELECT 1");
		});

		// A dropped column (42703). Another client then gets the backend connection the error was on,
		// and both a simple and an extended query work on it; then the first client goes on too.
		check(mode, "Execute after a column was dropped, then another client on the same backend",
			"1 Z(I) | E(42703) Z(I) | T D=1 C Z(I) | 1 2 D=2 C Z(I) | T D=1 C Z(I)", [&](PgConnection& c) {
			const std::string t = "p53c_" + sfx;
			exec(be, "CREATE TABLE " + t + " (a int, b int)");
			exec(be, "GRANT ALL ON " + t + " TO " + user);
			std::string out = prepareThenForget(c, "s1", "SELECT b FROM " + t);
			exec(be, "ALTER TABLE " + t + " DROP COLUMN b");
			out += " | " + execStmt(c, "s1");
			PgConnection other(5000);
			connectTo(other, through_proxy);
			out += " | " + simple(other, "SELECT 1");
			other.prepareStatement("", "SELECT 2", false);
			out += " | " + execStmt(other, "");
			exec(be, "DROP TABLE " + t);
			return out + " | " + simple(c, "SELECT 1");
		});

		// psycopg runs a prepared statement as Bind, Describe of the portal, Execute, Sync.
		check(mode, "Bind, Describe portal, Execute after a column was dropped",
			"1 Z(I) | E(42703) Z(I) | T D=1 C Z(I)", [&](PgConnection& c) {
			const std::string t = "p53d_" + sfx;
			exec(be, "CREATE TABLE " + t + " (a int, b int)");
			exec(be, "GRANT ALL ON " + t + " TO " + user);
			std::string out = prepareThenForget(c, "s1", "SELECT b FROM " + t);
			exec(be, "ALTER TABLE " + t + " DROP COLUMN b");
			c.bindStatement("s1", "", {}, {}, false);
			c.describePortal("", false);
			c.executePortal("", 0, false);
			c.sendSync();
			out += " | " + replies(c);
			exec(be, "DROP TABLE " + t);
			return out + " | " + simple(c, "SELECT 1");
		});

		check(mode, "Execute after the table was renamed, then renamed back",
			"1 Z(I) | E(42P01) Z(I) | 2 D=1 C Z(I)", [&](PgConnection& c) {
			const std::string t = "p53r_" + sfx;
			createTable(t);
			exec(be, "INSERT INTO " + t + " VALUES (1)");
			std::string out = prepareThenForget(c, "s1", "SELECT a FROM " + t);
			exec(be, "ALTER TABLE " + t + " RENAME TO " + t + "_x");
			out += " | " + execStmt(c, "s1");
			exec(be, "ALTER TABLE " + t + "_x RENAME TO " + t);
			out += " | " + execStmt(c, "s1");
			exec(be, "DROP TABLE " + t);
			return out;
		});

		// The column's type changed so the statement's declared parameter type no longer compares
		// with it (42883): ProxySQL's Parse must carry the client's parameter types.
		check(mode, "Execute after a column type change the parameter no longer fits, then changed back",
			"1 Z(I) | E(42883) Z(I) | 2 D=1 C Z(I)", [&](PgConnection& c) {
			const std::string t = "p53y_" + sfx;
			createTable(t);
			exec(be, "INSERT INTO " + t + " VALUES (1)");
			std::string out = prepareThenForget(c, "s1", "SELECT a FROM " + t + " WHERE a > $1", { 23 });
			exec(be, "ALTER TABLE " + t + " ALTER COLUMN a TYPE text");
			out += " | " + execStmt(c, "s1", { zero });
			exec(be, "ALTER TABLE " + t + " ALTER COLUMN a TYPE int USING a::int");
			out += " | " + execStmt(c, "s1", { zero });
			exec(be, "DROP TABLE " + t);
			return out;
		});

		check(mode, "Execute after a function was dropped, then created again",
			"1 Z(I) | E(42883) Z(I) | 2 D=7 C Z(I)", [&](PgConnection& c) {
			const std::string fn = "p53fn_" + sfx;
			const std::string create = "CREATE FUNCTION " + fn + "() RETURNS int LANGUAGE sql AS 'SELECT 7'";
			exec(be, create);
			std::string out = prepareThenForget(c, "s1", "SELECT " + fn + "()");
			exec(be, "DROP FUNCTION " + fn + "()");
			out += " | " + execStmt(c, "s1");
			exec(be, create);
			out += " | " + execStmt(c, "s1");
			exec(be, "DROP FUNCTION " + fn + "()");
			return out;
		});

		// A dropped type (42704). PostgreSQL cannot be compared here: its saved plan keeps the dropped
		// type's id and fails with XX000 "cache lookup failed for type", even once the type is created
		// again. ProxySQL's Parse is a fresh one, refused while the type is gone and fine after.
		{
			const std::string ty = "p53ty_" + sfx;
			const std::string create = "CREATE TYPE " + ty + " AS ENUM ('x')";
			const std::string expected = "1 Z(I) | E(42704) Z(I) | 2 D=x C Z(I)";
			const Frame f = [&](PgConnection& c) {
				exec(be, create);
				std::string out = prepareThenForget(c, "s1", "SELECT 'x'::" + ty + "::text");
				exec(be, "DROP TYPE " + ty);
				out += " | " + execStmt(c, "s1");
				exec(be, create);
				out += " | " + execStmt(c, "s1");
				exec(be, "DROP TYPE " + ty);
				return out;
			};
			std::string proxy = run(f, true);
			const std::string direct = run(f, false);
			for (size_t at; (at = proxy.find("| 2 E(")) != std::string::npos; ) proxy.erase(at + 2, 2);
			ok(proxy == expected, "%s: Execute after a type was dropped, then created again [proxy: %s] [expected: %s] [PostgreSQL, not compared: %s]",
			   mode, proxy.c_str(), expected.c_str(), direct.c_str());
		}

		// PostgreSQL parses the statement again under the client's new search_path, where the table
		// is not found; ProxySQL's Parse runs under it too. Back on the old path it works again.
		check(mode, "Execute after search_path moved off the table's schema, then back",
			"C Z(I) | 1 Z(I) | C Z(I) | E(42P01) Z(I) | C Z(I) | 2 D=1 C Z(I)", [&](PgConnection& c) {
			const std::string sa = "p53sa_" + sfx;
			const std::string sb = "p53sb_" + sfx;
			for (const std::string& sch : { sa, sb }) {
				exec(be, "CREATE SCHEMA " + sch);
				exec(be, "GRANT USAGE ON SCHEMA " + sch + " TO " + user);
			}
			createTable(sa + ".t");
			exec(be, "INSERT INTO " + sa + ".t VALUES (1)");
			std::string out = simple(c, "SET search_path TO " + sa);
			out += " | " + prepareThenForget(c, "s1", "SELECT a FROM t");
			out += " | " + simple(c, "SET search_path TO " + sb);
			out += " | " + execStmt(c, "s1");
			out += " | " + simple(c, "SET search_path TO " + sa);
			out += " | " + execStmt(c, "s1");
			exec(be, "DROP SCHEMA " + sa + " CASCADE");
			exec(be, "DROP SCHEMA " + sb);
			return out;
		});

		// The test user loses USAGE on the table's schema (42501). A superuser is never refused.
		if (superuser) {
			skip(1, "%s: the test user is a superuser, a revoked privilege does not apply to it", mode);
		} else {
			direct_as_test_user = true;
			check(mode, "Execute after USAGE on the schema was revoked, then granted again",
				"1 Z(I) | E(42501) Z(I) | 2 D=1 C Z(I)", [&](PgConnection& c) {
				const std::string sch = "p53sp_" + sfx;
				exec(be, "CREATE SCHEMA " + sch);
				exec(be, "GRANT USAGE ON SCHEMA " + sch + " TO " + user);
				createTable(sch + ".t");
				exec(be, "INSERT INTO " + sch + ".t VALUES (1)");
				std::string out = prepareThenForget(c, "s1", "SELECT a FROM " + sch + ".t");
				exec(be, "REVOKE USAGE ON SCHEMA " + sch + " FROM " + user);
				out += " | " + execStmt(c, "s1");
				exec(be, "GRANT USAGE ON SCHEMA " + sch + " TO " + user);
				out += " | " + execStmt(c, "s1");
				exec(be, "DROP SCHEMA " + sch + " CASCADE");
				return out;
			});
			direct_as_test_user = false;
		}

		// A Describe of the statement after its table was dropped. PostgreSQL sends the parameter
		// description before it finds the table gone; ProxySQL's Parse fails first, so the client gets
		// the error alone. That message is taken out of PostgreSQL's reply before comparing.
		{
			const std::string t = "p53e_" + sfx;
			const std::string expected = "1 Z(I) | E(42P01) Z(I) | t T Z(I)";
			const Frame f = [&](PgConnection& c) {
				createTable(t);
				std::string out = prepareThenForget(c, "s1", "SELECT a FROM " + t);
				exec(be, "DROP TABLE " + t);
				c.describeStatement("s1", false);
				c.sendSync();
				out += " | " + replies(c);
				createTable(t);
				c.describeStatement("s1", false);
				c.sendSync();
				out += " | " + replies(c);
				exec(be, "DROP TABLE " + t);
				return out;
			};
			const std::string proxy = run(f, true);
			std::string direct = run(f, false);
			const size_t at = direct.find("| t E(");
			if (at != std::string::npos) direct.erase(at + 2, 2);
			ok(proxy == expected && direct == expected,
			   "%s: Describe after the table was dropped, then the table back [proxy: %s] [PostgreSQL without its 't': %s] [expected: %s]",
			   mode, proxy.c_str(), direct.c_str(), expected.c_str());
		}

		// The pooled connection the next statement gets was killed, as an idle timeout or a server
		// restart does. The first step sent on it fails, and the statement runs again on a new
		// connection, which first gets the client's DateStyle: the date shows it. Each case first
		// leaves one connection in the pool with the client's DateStyle on it, then kills it.
		// Native only: libpq mode does not retry an extended-protocol step, because ProxySQL has put
		// the connection in pipeline mode for it (kept on purpose, see pgsql-reg_test_6375_offline_retry-t).
		if (native) {
			const std::string date = "SELECT DATE '2026-10-15'::text AS ";
			check(mode, "Execute that needs a prepare, on a pooled connection whose backend was killed",
				"C Z(I) | 1 Z(I) | T D=1 C Z(I) | 2 D=15/10/2026 C Z(I) | T D=1 C Z(I)", [&](PgConnection& c) {
				std::string out = simple(c, "SET DateStyle TO 'SQL, DMY'");
				out += " | " + prepareThenForget(c, "s1", date + "p53k_" + sfx);
				out += " | " + simple(c, "SELECT 1");
				if (through_proxy) killBackends();
				out += " | " + execStmt(c, "s1");
				return out + " | " + simple(c, "SELECT 1");
			});
			check(mode, "Execute of a statement the killed connection holds",
				"C Z(I) | 1 Z(I) | 2 D=15/10/2026 C Z(I) | T D=1 C Z(I)", [&](PgConnection& c) {
				std::string out = simple(c, "SET DateStyle TO 'SQL, DMY'");
				c.prepareStatement("s1", date + "p53h_" + sfx, false);
				c.sendSync();
				out += " | " + replies(c);
				if (through_proxy) killBackends();
				out += " | " + execStmt(c, "s1");
				return out + " | " + simple(c, "SELECT 1");
			});
			// A frame with its own Parse goes out as one batch. The killed backend's FATAL is the
			// first thing read back: it is not an answer to the batch, which runs again elsewhere.
			check(mode, "Parse, Bind and Execute of a new statement on a killed connection",
				"C Z(I) | T D=1 C Z(I) | 1 2 D=15/10/2026 C Z(I) | T D=1 C Z(I)", [&](PgConnection& c) {
				std::string out = simple(c, "SET DateStyle TO 'SQL, DMY'");
				out += " | " + simple(c, "SELECT 1");
				if (through_proxy) killBackends();
				c.prepareStatement("", date + "p53q_" + sfx, false);
				out += " | " + execStmt(c, "");
				return out + " | " + simple(c, "SELECT 1");
			});
			// The same with a Parse ProxySQL answers itself, the text being prepared already.
			check(mode, "Parse of a known statement, Bind and Execute on a killed connection",
				"C Z(I) | 1 Z(I) | 1 2 D=15/10/2026 C Z(I) | T D=1 C Z(I)", [&](PgConnection& c) {
				std::string out = simple(c, "SET DateStyle TO 'SQL, DMY'");
				c.prepareStatement("s1", date + "p53c_" + sfx, false);
				c.sendSync();
				out += " | " + replies(c);
				if (through_proxy) killBackends();
				c.prepareStatement("s2", date + "p53c_" + sfx, false);
				out += " | " + execStmt(c, "s2");
				return out + " | " + simple(c, "SELECT 1");
			});
			check(mode, "simple query on a killed connection",
				"C Z(I) | T D=1 C Z(I) | T D=15/10/2026 C Z(I)", [&](PgConnection& c) {
				std::string out = simple(c, "SET DateStyle TO 'SQL, DMY'");
				out += " | " + simple(c, "SELECT 1");
				if (through_proxy) killBackends();
				return out + " | " + simple(c, date + "p53s_" + sfx);
			});
		}

		// What follows the refused Execute in the same frame is skipped up to the Sync: the INSERT
		// never runs.
		check(mode, "the rest of the frame is skipped", "1 Z(I) | E(42P01) Z(I) | T D=0 C Z(I)", [&](PgConnection& c) {
			const std::string t = "p53f_" + sfx;
			const std::string l = "p53l_" + sfx;
			createTable(t);
			createTable(l);
			std::string out = prepareThenForget(c, "s1", "SELECT a FROM " + t);
			exec(be, "DROP TABLE " + t);
			c.bindStatement("s1", "", {}, {}, false);
			c.executePortal("", 0, false);
			c.prepareStatement("", "INSERT INTO " + l + " VALUES (1)", false);
			c.bindStatement("", "", {}, {}, false);
			c.executePortal("", 0, false);
			c.sendSync();
			out += " | " + replies(c);
			out += " | " + simple(c, "SELECT count(*) FROM " + l);
			exec(be, "DROP TABLE " + l);
			return out;
		});

		// The unnamed statement, run in a later frame than its Parse.
		check(mode, "unnamed statement after the table was dropped, then the table back",
			"1 Z(I) | E(42P01) Z(I) | 2 D=1 C Z(I)", [&](PgConnection& c) {
			const std::string t = "p53u_" + sfx;
			createTable(t);
			exec(be, "INSERT INTO " + t + " VALUES (1)");
			std::string out = prepareThenForget(c, "", "SELECT a FROM " + t);
			exec(be, "DROP TABLE " + t);
			out += " | " + execStmt(c, "");
			createTable(t);
			exec(be, "INSERT INTO " + t + " VALUES (1)");
			out += " | " + execStmt(c, "");
			exec(be, "DROP TABLE " + t);
			return out;
		});

		// Named portals exist on the native protocol only. A refused Bind leaves no portal behind.
		if (native) {
			check(mode, "Bind of a named portal in a failed transaction, again after ROLLBACK", FAILED + "2 D=55 C Z(I)",
				[&](PgConnection& c) {
				std::string out = prepareThenForget(c, "s1", "SELECT 55 AS p53_" + sfx);
				out += " | " + simple(c, "BEGIN");
				out += " | " + simple(c, "SELECT 1/0");
				c.bindStatement("s1", "p53", {}, {}, false);
				c.executePortal("p53", 0, false);
				c.sendSync();
				out += " | " + replies(c);
				out += " | " + simple(c, "ROLLBACK");
				c.bindStatement("s1", "p53", {}, {}, false);
				c.executePortal("p53", 0, false);
				c.sendSync();
				return out + " | " + replies(c);
			});
			check(mode, "Bind of a named portal after the table was dropped, then an Execute of that portal",
				"1 Z(I) | E(42P01) Z(I) | E(34000) Z(I) | T D=1 C Z(I)", [&](PgConnection& c) {
				const std::string t = "p53p_" + sfx;
				createTable(t);
				std::string out = prepareThenForget(c, "s1", "SELECT a FROM " + t);
				exec(be, "DROP TABLE " + t);
				c.bindStatement("s1", "p53", {}, {}, false);
				c.sendSync();
				out += " | " + replies(c);
				c.executePortal("p53", 0, false);
				c.sendSync();
				out += " | " + replies(c);
				return out + " | " + simple(c, "SELECT 1");
			});
		}

		// The same text parsed again under another name, in one frame with its Bind and Execute.
		// ProxySQL answers that Parse itself from its statement cache, so PostgreSQL's reply differs
		// from the error on: only the error and the connection afterwards are checked.
		{
			const std::string t = "p53b_" + sfx;
			const std::string tail = "E(42P01) Z(I) | T D=1 C Z(I)";
			const std::string proxy = run([&](PgConnection& c) {
				createTable(t);
				prepareThenForget(c, "s1", "SELECT a FROM " + t);
				exec(be, "DROP TABLE " + t);
				c.prepareStatement("s2", "SELECT a FROM " + t, false);
				c.bindStatement("s2", "", {}, {}, false);
				c.executePortal("", 0, false);
				c.sendSync();
				const std::string out = replies(c);
				return out + " | " + simple(c, "SELECT 1");
			}, true);
			ok(proxy.size() >= tail.size() && proxy.compare(proxy.size() - tail.size(), tail.size(), tail) == 0,
			   "%s: Parse, Bind and Execute in one frame after the table was dropped [proxy: %s] [expected to end with: %s]",
			   mode, proxy.c_str(), tail.c_str());
		}
	}

	exec(admin, "LOAD PGSQL VARIABLES FROM DISK");
	exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	return exit_status();
}
