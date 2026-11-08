/**
 * @file pgsql-extq_local_error_in_txn-t.cpp
 * @brief An extended-query error ProxySQL gives itself, inside a transaction block, must fail the
 *        transaction as PostgreSQL does: ReadyForQuery 'E', later statements refused until
 *        ROLLBACK, the work done so far never committed, and a savepoint still able to recover it.
 *
 * Each case runs through ProxySQL and straight against PostgreSQL, and the replies are compared. The
 * error is one ProxySQL answers without the backend: a Bind of a statement the client never
 * prepared, an Execute of a portal never bound. Inside a transaction this is checked with the
 * native backend protocol only: there the error is failed on the backend itself. With the libpq one
 * ProxySQL poisons the session instead (pgsql-local_error_txn_state-t).
 *
 * L13-L18 check what failing on the backend keeps that poisoning would lose: the backend connection,
 * a LISTEN and a WITH HOLD cursor pinned to it, PostgreSQL's own answer to COMMIT, the savepoint
 * patterns of real drivers, and PostgreSQL's answer to every kind of statement in the failed
 * transaction.
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

// Switches the backend protocol and empties the pool: a pooled connection keeps the protocol it
// was opened with.
static void setMode(PGconn* admin, bool native) {
	const std::string hg = std::to_string(HG);
	if (!exec(admin, std::string("SET pgsql-use_native_backend_protocol='") + (native ? "true" : "false") + "'")
	    || !exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME")
	    || !exec(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" + hg)
	    || !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not switch the backend protocol");
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
// 'full' also shows notices and command tags: "N(25P01) C(ROLLBACK) Z(I)".
static std::string replies(PgConnection& c, bool full = false) {
	std::string out;
	for (;;) {
		char type = 0;
		std::vector<uint8_t> buf;
		c.readMessage(type, buf);
		if (type == 'S' || (type == 'N' && !full)) continue;
		if (!out.empty()) out += ' ';
		out += type;
		if (type == 'D' && buf.size() >= 6) {
			const int32_t len = (int32_t)((buf[2] << 24) | (buf[3] << 16) | (buf[4] << 8) | buf[5]);
			out += "=" + (len < 0 ? std::string("NULL") : std::string((const char*)buf.data() + 6, len));
		} else if (type == 'C' && full) {
			out += "(" + std::string((const char*)buf.data(), strnlen((const char*)buf.data(), buf.size())) + ")";
		} else if (type == 'E' || type == 'N') {
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

static std::string run(Frame f, bool through_proxy) {
	try {
		PgConnection c(5000);
		if (through_proxy) {
			c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
		} else {
			c.connect(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_username, cl.pgsql_server_username, cl.pgsql_server_password);
		}
		return f(c);
	} catch (const PgException& e) {
		return std::string("threw: ") + e.what();
	}
}

static void check(const char* mode, const char* label, const std::string& expected, Frame f) {
	const std::string proxy = run(f, true);
	const std::string direct = run(f, false);
	ok(proxy == expected && proxy == direct, "%s: %s [proxy: %s] [PostgreSQL: %s] [expected: %s]",
	   mode, label, proxy.c_str(), direct.c_str(), expected.c_str());
}

// ProxySQL only, for what PostgreSQL has no counterpart of.
static void checkProxy(const char* mode, const char* label, const std::string& expected, Frame f) {
	const std::string proxy = run(f, true);
	ok(proxy == expected, "%s: %s [proxy: %s] [expected: %s]", mode, label, proxy.c_str(), expected.c_str());
}

// The value of the first DataRow in a reply string: "T D=42 C Z(T)" gives "42".
static std::string firstValue(const std::string& r) {
	const size_t at = r.find("D=");
	return at == std::string::npos ? std::string() : r.substr(at + 2, r.find(' ', at) - at - 2);
}

// BEGIN, a temporary table with one row, then 'unit', then a statement, COMMIT, and a look at the
// table. When the unit's error fails the transaction, the statement is refused, COMMIT rolls back
// and the table is gone with it.
static std::string inTxn(PgConnection& c, const std::string& table, const std::function<void(PgConnection&)>& unit) {
	std::string out = simple(c, "BEGIN");
	out += " | " + simple(c, "CREATE TEMP TABLE " + table + " (a int)");
	out += " | " + simple(c, "INSERT INTO " + table + " VALUES (1)");
	unit(c);
	out += " | " + replies(c);
	out += " | " + simple(c, "SELECT 1");
	out += " | " + simple(c, "COMMIT");
	return out + " | " + simple(c, "SELECT count(*) FROM " + table);
}

static const std::string FAILED_TAIL = "E(25P02) Z(E) | C Z(I) | E(42P01) Z(I)";

// The message ProxySQL refuses itself, followed by its Sync.
static void refuseAndSync(PgConnection& c) {
	c.bindStatement("none_" + tag, "", {}, {}, false);
	c.executePortal("", 0, false);
	c.sendSync();
}

// As check(), for a Bind and Execute of a statement prepared earlier. ProxySQL holds the Bind of the
// unnamed portal until the Execute and answers it with BindComplete at once, so when PostgreSQL
// refuses the Bind, ProxySQL's stream has a "2" before the error that PostgreSQL's has not.
static void checkBindAhead(const char* mode, const char* label, const std::string& expected, Frame f) {
	std::string proxy = run(f, true);
	const std::string direct = run(f, false);
	const size_t at = proxy.find("| 2 E(");
	if (at != std::string::npos) proxy.erase(at + 2, 2);
	ok(proxy == expected && proxy == direct, "%s: %s [proxy: %s] [PostgreSQL: %s] [expected: %s]",
	   mode, label, proxy.c_str(), direct.c_str(), expected.c_str());
}

// One statement over the extended protocol, unnamed, without a Sync.
static void extq(PgConnection& c, const std::string& sql) {
	c.prepareStatement("", sql, false);
	c.bindStatement("", "", {}, {}, false);
	c.executePortal("", 0, false);
}

// Whether backend 'pid' is still connected a second later. A destroyed backend leaves
// pg_stat_activity within milliseconds, so one look that misses it is enough.
static bool backendAlive(const std::string& pid) {
	if (pid.empty() || pid.find_first_not_of("0123456789") != std::string::npos) return false;
	PGConnPtr pg = openConn(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_server_username,
		cl.pgsql_server_password, cl.pgsql_username);
	for (int i = 0; i < 10; i++) {
		if (execLong(pg.get(), "SELECT count(*) FROM pg_stat_activity WHERE pid=" + pid) != 1) return false;
		usleep(100000);
	}
	return true;
}

// NOTIFY sent straight to PostgreSQL, so it reaches a listener whichever way it connected.
static void notifyDirect(const std::string& channel) {
	PGConnPtr pg = openConn(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_server_username,
		cl.pgsql_server_password, cl.pgsql_username);
	exec(pg.get(), "NOTIFY " + channel + ", 'x'");
}

// PostgreSQL's reply is the expected one: for statements whose answer varies between versions.
// 'start' is what the run must begin with, so two runs that broke the same way do not pass.
static void checkSame(const char* mode, const std::string& label, const std::string& start, Frame f) {
	const std::string proxy = run(f, true);
	const std::string direct = run(f, false);
	ok(proxy == direct && direct.compare(0, start.size(), start) == 0, "%s: %s [proxy: %s] [PostgreSQL: %s]",
	   mode, label.c_str(), proxy.c_str(), direct.c_str());
}

int main(int, char**) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}
	tag = std::to_string(getpid()) + "_" + std::to_string(time(nullptr) % 100000);

	// L18: what each kind of statement gets in the failed transaction. PostgreSQL refuses all but
	// the ones that end it; ProxySQL must neither refuse more nor answer any itself.
	using Send = std::function<void(PgConnection&)>;
	const auto simpleQ = [](const std::string& sql) -> Send { return [sql](PgConnection& c) { c.sendQuery(sql); }; };
	const auto extQ = [](const std::string& sql) -> Send { return [sql](PgConnection& c) { extq(c, sql); c.sendSync(); }; };
	const std::vector<std::pair<std::string, Send>> probes = {
		{ "SELECT 1", simpleQ("SELECT 1") },
		{ "SHOW DateStyle", simpleQ("SHOW DateStyle") },
		{ "SAVEPOINT", simpleQ("SAVEPOINT sp_new") },
		{ "RELEASE SAVEPOINT", simpleQ("RELEASE SAVEPOINT sp_none") },
		{ "ROLLBACK TO an unknown savepoint", simpleQ("ROLLBACK TO SAVEPOINT sp_none") },
		{ "SET of a tracked variable", simpleQ("SET DateStyle TO 'ISO, MDY'") },
		{ "RESET of a tracked variable", simpleQ("RESET DateStyle") },
		{ "DISCARD ALL", simpleQ("DISCARD ALL") },
		{ "DEALLOCATE ALL", simpleQ("DEALLOCATE ALL") },
		{ "ROLLBACK AND CHAIN", simpleQ("ROLLBACK AND CHAIN") },
		{ "COMMIT AND CHAIN", simpleQ("COMMIT AND CHAIN") },
		{ "ABORT", simpleQ("ABORT") },
		{ "END", simpleQ("END") },
		{ "extended SELECT", extQ("SELECT 1") },
		{ "extended SET of a tracked variable", extQ("SET DateStyle TO 'ISO, MDY'") },
		{ "extended named ROLLBACK", [](PgConnection& c) {
			c.prepareStatement("rb_" + tag, "ROLLBACK", false);
			c.bindStatement("rb_" + tag, "", {}, {}, false);
			c.executePortal("", 0, false);
			c.sendSync();
		} },
		{ "extended Close then Parse of ROLLBACK under that name", [](PgConnection& c) {
			c.closeStatement("cl_" + tag, false);
			c.prepareStatement("cl_" + tag, "ROLLBACK", false);
			c.bindStatement("cl_" + tag, "", {}, {}, false);
			c.executePortal("", 0, false);
			c.sendSync();
		} },
	};
	// L19: statements ProxySQL can answer itself, sent in a transaction a backend error has failed.
	const std::vector<std::string> local_answers = {
		"SET DateStyle TO 'ISO, MDY'", "RESET DateStyle", "DISCARD ALL", "DEALLOCATE ALL", "SELECT pg_backend_pid()",
	};
	plan(14 + 7 + probes.size() + 2 * local_answers.size() + 2 * 2 + 2 * 6);

	PGConnPtr admin = openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, nullptr);
	if (PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("cannot reach the admin interface");

	for (int m = 0; m < 2; m++) {
		const bool native = (m == 1);
		const char* mode = native ? "native" : "libpq";
		setMode(admin.get(), native);

		// L3: outside a transaction block the error leaves the session idle and usable.
		check(mode, "L3 Bind of an unknown statement outside a transaction", "E(26000) Z(I) | T D=1 C Z(I)",
			[&](PgConnection& c) {
			c.bindStatement("none_" + tag, "", {}, {}, false);
			c.executePortal("", 0, false);
			c.sendSync();
			const std::string out = replies(c);
			return out + " | " + simple(c, "SELECT 1");
		});

		// L19: in a transaction the backend failed, PostgreSQL refuses these too. ProxySQL must not
		// answer them itself with a success and ReadyForQuery 'T'. Both backend protocols.
		for (const std::string& q : local_answers) {
			check(mode, ("L19 after a backend error: " + q).c_str(), "C Z(T) | E(22012) Z(E) | E(25P02) Z(E) | C Z(I)",
				[&](PgConnection& c) {
				std::string out = simple(c, "BEGIN");
				out += " | " + simple(c, "SELECT 1/0");
				out += " | " + simple(c, q);
				return out + " | " + simple(c, "ROLLBACK");
			});
		}

		// L20: a Parse of a text ProxySQL already knows is answered by ProxySQL itself. In the failed
		// transaction it must reach the backend and be refused. Known from another session, then from
		// this one.
		{
			const std::string q = "SELECT 20 AS l20_" + tag + "_" + mode;
			run([&](PgConnection& c) { extq(c, q); c.sendSync(); return replies(c); }, true);
			check(mode, "L20 Parse of a statement another session prepared, after a backend error",
				"C Z(T) | E(22012) Z(E) | E(25P02) Z(E) | C Z(I)", [&](PgConnection& c) {
				std::string out = simple(c, "BEGIN");
				out += " | " + simple(c, "SELECT 1/0");
				extq(c, q);
				c.sendSync();
				out += " | " + replies(c);
				return out + " | " + simple(c, "ROLLBACK");
			});
			check(mode, "L20 Parse of a statement this session prepared, after a backend error",
				"1 2 D=20 C Z(I) | C Z(T) | E(22012) Z(E) | E(25P02) Z(E) | C Z(I)", [&](PgConnection& c) {
				extq(c, q);
				c.sendSync();
				std::string out = replies(c);
				out += " | " + simple(c, "BEGIN");
				out += " | " + simple(c, "SELECT 1/0");
				extq(c, q);
				c.sendSync();
				out += " | " + replies(c);
				return out + " | " + simple(c, "ROLLBACK");
			});
		}

		// L21: a query rule's OK_msg, the query cache and the pg_cancel_backend/pg_terminate_backend
		// interception answer without the backend. In the failed transaction PostgreSQL refuses the
		// statement, and so must ProxySQL: as a simple Query, and as the Execute of a statement
		// prepared before the error.
		{
			const std::string ok_q = std::string("SELECT 21 AS okmsg_l21_") + tag + "_" + mode;
			const std::string qc_q = std::string("SELECT 21 AS qc_l21_") + tag + "_" + mode;
			exec(admin.get(), "INSERT INTO pgsql_query_rules (rule_id, active, match_digest, OK_msg, apply) VALUES "
				"(7902, 1, 'okmsg_l21_" + tag + "', 'ok', 1)");
			exec(admin.get(), "INSERT INTO pgsql_query_rules (rule_id, active, match_digest, cache_ttl, apply) VALUES "
				"(7903, 1, 'qc_l21_" + tag + "', 60000, 1)");
			exec(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
			run([&](PgConnection& c) { return simple(c, qc_q); }, true);   // fills the cache

			const std::string failed = "C Z(T) | E(22012) Z(E) | E(25P02) Z(E) | C Z(I)";
			const std::vector<std::pair<std::string, std::string>> simple_cases = {
				{ "a query rule's OK_msg", ok_q },
				{ "a query cache hit", qc_q },
				{ "pg_cancel_backend()", "SELECT pg_cancel_backend(2147483647)" },
				{ "pg_terminate_backend()", "SELECT pg_terminate_backend(2147483647)" },
			};
			for (const auto& sc : simple_cases) {
				check(mode, ("L21 after a backend error: " + sc.first).c_str(), failed, [&](PgConnection& c) {
					std::string out = simple(c, "BEGIN");
					out += " | " + simple(c, "SELECT 1/0");
					out += " | " + simple(c, sc.second);
					return out + " | " + simple(c, "ROLLBACK");
				});
			}
			// Texts unique to the mode: one the libpq pass prepared would be answered from the statement
			// cache here, and the Execute would first have to prepare it on a backend that never had it.
			// The pid differs rather than the text around it, which would stop it being taken for a cancel.
			// Prepared after BEGIN, so on the backend the transaction holds: prepared before it, BEGIN
			// could take another pooled connection and the Execute would prepare it there.
			const std::vector<std::pair<std::string, std::string>> execute_cases = {
				{ "Execute under a query rule's OK_msg", ok_q },
				{ "Execute of pg_cancel_backend()", "SELECT pg_cancel_backend(" + std::to_string(2147483647 - m) + ")" },
			};
			for (const auto& ec : execute_cases) {
				checkBindAhead(mode, ("L21 after a backend error: " + ec.first).c_str(),
					"C Z(T) | 1 Z(T) | E(22012) Z(E) | E(25P02) Z(E) | C Z(I)", [&](PgConnection& c) {
					std::string out = simple(c, "BEGIN");
					c.prepareStatement("s_l21", ec.second, false);
					c.sendSync();
					out += " | " + replies(c);
					out += " | " + simple(c, "SELECT 1/0");
					c.bindStatement("s_l21", "", {}, {}, false);
					c.executePortal("", 0, false);
					c.sendSync();
					out += " | " + replies(c);
					return out + " | " + simple(c, "ROLLBACK");
				});
			}
			exec(admin.get(), "DELETE FROM pgsql_query_rules WHERE rule_id IN (7902, 7903)");
			exec(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
		}
		if (native == false) {
			continue;
		}

		// L1: the unit's first message is the one ProxySQL refuses.
		check(mode, "L1 Bind of an unknown statement in a transaction",
			"C Z(T) | C Z(T) | C Z(T) | E(26000) Z(E) | " + FAILED_TAIL, [&](PgConnection& c) {
			return inTxn(c, "l1_" + tag, [&](PgConnection& c) {
				c.bindStatement("none_" + tag, "", {}, {}, false);
				c.executePortal("", 0, false);
				c.sendSync();
			});
		});

		// L2: a statement the session handles itself runs first, then the refused message.
		check(mode, "L2 refused message after a SET in the same unit",
			"C Z(T) | C Z(T) | C Z(T) | 1 E(26000) Z(E) | " + FAILED_TAIL, [&](PgConnection& c) {
			return inTxn(c, "l2_" + tag, [&](PgConnection& c) {
				c.prepareStatement("s_set", "SET extra_float_digits TO 2", false);
				c.bindStatement("none_" + tag, "", {}, {}, false);
				c.executePortal("", 0, false);
				c.sendSync();
			});
		});

		// L4: Execute of a portal never bound.
		check(mode, "L4 Execute of an unknown portal in a transaction",
			"C Z(T) | C Z(T) | C Z(T) | E(34000) Z(E) | " + FAILED_TAIL, [&](PgConnection& c) {
			return inTxn(c, "l4_" + tag, [&](PgConnection& c) {
				c.executePortal("none_" + tag, 0, false);
				c.sendSync();
			});
		});

		// L5: ROLLBACK TO SAVEPOINT recovers the transaction, as drivers with autosave do; the row
		// inserted before the savepoint survives and is committed, and it is the same transaction, on
		// the same backend connection, before and after.
		check(mode, "L5 savepoint recovers after the refused message",
			"C Z(T) | C Z(T) | C Z(T) | C Z(T) | E(26000) Z(E) | C Z(T) | T D=1 C Z(T) | C Z(I) | T D=1 C Z(I) | same transaction",
			[&](PgConnection& c) {
			const std::string t = "l5_" + tag;
			std::string out = simple(c, "BEGIN");
			out += " | " + simple(c, "CREATE TEMP TABLE " + t + " (a int)");
			out += " | " + simple(c, "INSERT INTO " + t + " VALUES (1)");
			out += " | " + simple(c, "SAVEPOINT sp1");
			const std::string xid_before = firstValue(simple(c, "SELECT txid_current()"));
			c.bindStatement("none_" + tag, "", {}, {}, false);
			c.executePortal("", 0, false);
			c.sendSync();
			out += " | " + replies(c);
			out += " | " + simple(c, "ROLLBACK TO SAVEPOINT sp1");
			const std::string xid_after = firstValue(simple(c, "SELECT txid_current()"));
			out += " | " + simple(c, "SELECT count(*) FROM " + t);
			out += " | " + simple(c, "COMMIT");
			out += " | " + simple(c, "SELECT count(*) FROM " + t);
			return out + (xid_before.empty() == false && xid_before == xid_after ? " | same transaction" : " | other transaction");
		});

		// L6: the refused message comes after an INSERT in the same unit, past a savepoint. The
		// INSERT ran, the savepoint undoes it, and the transaction goes on.
		check(mode, "L6 refused message after buffered work, then savepoint",
			"C Z(T) | C Z(T) | C Z(T) | 1 2 C E(26000) Z(E) | C Z(T) | T D=0 C Z(T) | C Z(I)",
			[&](PgConnection& c) {
			const std::string t = "l6_" + tag;
			std::string out = simple(c, "BEGIN");
			out += " | " + simple(c, "CREATE TEMP TABLE " + t + " (a int)");
			out += " | " + simple(c, "SAVEPOINT sp1");
			c.prepareStatement("s_ins", "INSERT INTO " + t + " VALUES (5)", false);
			c.bindStatement("s_ins", "", {}, {}, false);
			c.executePortal("", 0, false);
			c.bindStatement("none_" + tag, "", {}, {}, false);
			c.executePortal("", 0, false);
			c.sendSync();
			out += " | " + replies(c);
			out += " | " + simple(c, "ROLLBACK TO SAVEPOINT sp1");
			out += " | " + simple(c, "SELECT count(*) FROM " + t);
			return out + " | " + simple(c, "COMMIT");
		});

		// L7: Describe of a portal never bound.
		check(mode, "L7 Describe of an unknown portal in a transaction",
			"C Z(T) | C Z(T) | C Z(T) | E(34000) Z(E) | " + FAILED_TAIL, [&](PgConnection& c) {
			return inTxn(c, "l7_" + tag, [&](PgConnection& c) {
				c.describePortal("none_" + tag, false);
				c.sendSync();
			});
		});

		// L8: what drivers with autosave meet. A statement prepared earlier is dropped by DEALLOCATE ALL,
		// its next Bind fails, and the driver rolls back to its savepoint, prepares again and goes on.
		check(mode, "L8 Bind after DEALLOCATE ALL, recovered with a savepoint",
			"1 Z(I) | C Z(T) | C Z(T) | C Z(T) | E(26000) Z(E) | C Z(T) | 1 2 D=7 C Z(T) | C Z(I)",
			[&](PgConnection& c) {
			const std::string q = "SELECT 7 AS l8_" + tag;
			c.prepareStatement("S_1", q, false);
			c.sendSync();
			std::string out = replies(c);
			out += " | " + simple(c, "BEGIN");
			out += " | " + simple(c, "SAVEPOINT sp1");
			out += " | " + simple(c, "DEALLOCATE ALL");
			c.bindStatement("S_1", "", {}, {}, false);
			c.executePortal("", 0, false);
			c.sendSync();
			out += " | " + replies(c);
			out += " | " + simple(c, "ROLLBACK TO SAVEPOINT sp1");
			c.prepareStatement("S_1", q, false);
			c.bindStatement("S_1", "", {}, {}, false);
			c.executePortal("", 0, false);
			c.sendSync();
			out += " | " + replies(c);
			return out + " | " + simple(c, "COMMIT");
		});

		// L9: the refused message follows an INSERT in the same unit, with no savepoint: COMMIT rolls
		// back, and the INSERT with it.
		check(mode, "L9 refused message after buffered work, then COMMIT",
			"C Z(T) | C Z(T) | C Z(T) | 1 2 C E(26000) Z(E) | " + FAILED_TAIL, [&](PgConnection& c) {
			const std::string t = "l9_" + tag;
			return inTxn(c, t, [&](PgConnection& c) {
				c.prepareStatement("s_ins", "INSERT INTO " + t + " VALUES (2)", false);
				c.bindStatement("s_ins", "", {}, {}, false);
				c.executePortal("", 0, false);
				c.bindStatement("none_" + tag, "", {}, {}, false);
				c.executePortal("", 0, false);
				c.sendSync();
			});
		});

		// L10: a simple Query after the refused message, then a Sync. As in PostgreSQL the Query is
		// ignored after the error, and the Sync gets the one ReadyForQuery.
		check(mode, "L10 refused message, then a simple Query and Sync",
			"C Z(T) | E(26000) Z(E) | C Z(I)", [&](PgConnection& c) {
			std::string out = simple(c, "BEGIN");
			c.bindStatement("none_" + tag, "", {}, {}, false);
			c.executePortal("", 0, false);
			c.sendQuery("SELECT 1");
			c.sendSync();
			out += " | " + replies(c);
			return out + " | " + simple(c, "ROLLBACK");
		});

		// L11: the transaction has already failed on the backend when ProxySQL refuses a message.
		check(mode, "L11 refused message in an already failed transaction",
			"C Z(T) | E(22012) Z(E) | E(26000) Z(E) | C Z(I)", [&](PgConnection& c) {
			std::string out = simple(c, "BEGIN");
			out += " | " + simple(c, "SELECT 1/0");
			c.bindStatement("none_" + tag, "", {}, {}, false);
			c.executePortal("", 0, false);
			c.sendSync();
			out += " | " + replies(c);
			return out + " | " + simple(c, "ROLLBACK");
		});

		// L12: a query rule refuses a statement after buffered work in the same unit. ProxySQL only:
		// PostgreSQL has no rules. The rows before it arrive, the transaction fails as for any error.
		{
			exec(admin.get(), "INSERT INTO pgsql_query_rules (rule_id, active, match_digest, error_msg, apply) VALUES "
				"(7901, 1, 'refused_l12_" + tag + "', 'refused by rule', 1)");
			exec(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
			checkProxy(mode, "L12 rule refusal after buffered work in a transaction",
				"C Z(T) | C Z(T) | C Z(T) | 1 2 D=7 C E(42501) Z(E) | " + FAILED_TAIL, [&](PgConnection& c) {
				return inTxn(c, "l12_" + tag, [&](PgConnection& c) {
					c.prepareStatement("s_ok", "SELECT 7 AS l12_" + tag, false);
					c.bindStatement("s_ok", "", {}, {}, false);
					c.executePortal("", 0, false);
					c.prepareStatement("s_no", "SELECT 8 AS refused_l12_" + tag, false);
					c.sendSync();
				});
			});
			exec(admin.get(), "DELETE FROM pgsql_query_rules WHERE rule_id=7901");
			exec(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
		}

		// The statement ProxySQL sends to fail on purpose is not a backend error to report.
		{
			const std::string q = "SELECT COALESCE(SUM(count_star),0) FROM stats_pgsql_errors WHERE sqlstate='42601'";
			const long before = execLong(admin.get(), q);
			const std::string got = run([&](PgConnection& c) {
				return inTxn(c, "lc_" + tag, [&](PgConnection& c) {
					c.bindStatement("none_" + tag, "", {}, {}, false);
					c.executePortal("", 0, false);
					c.sendSync();
				});
			}, true);
			const long after = execLong(admin.get(), q);
			ok(got.find("E(26000) Z(E)") != std::string::npos && before == after,
			   "%s: the failing statement is not counted as a backend error [42601 count %ld -> %ld] [%s]",
			   mode, before, after, got.c_str());
		}

		// L13: the backend connection that held the transaction is still there after ROLLBACK, as the
		// client's own connection is with PostgreSQL. Looked up in pg_stat_activity: ProxySQL answers a
		// bare pg_backend_pid() itself.
		check(mode, "L13 the backend connection is kept after ROLLBACK",
			"C Z(T) | E(26000) Z(E) | C Z(I) | T D=1 C Z(I) | backend kept", [&](PgConnection& c) {
			std::string out = simple(c, "BEGIN");
			const std::string pid = firstValue(simple(c, "SELECT pid FROM pg_stat_activity WHERE pid = pg_backend_pid()"));
			refuseAndSync(c);
			out += " | " + replies(c);
			out += " | " + simple(c, "ROLLBACK");
			out += " | " + simple(c, "SELECT 1");
			return out + (backendAlive(pid) ? " | backend kept" : " | backend replaced");
		});

		// L14: a LISTEN pins the session to its backend. After ROLLBACK the subscription is still there
		// and a NOTIFY reaches the client.
		check(mode, "L14 a LISTEN still delivers after ROLLBACK",
			"C Z(I) | C Z(T) | E(26000) Z(E) | C Z(I) | notified", [&](PgConnection& c) {
			const std::string ch = "l14_" + tag;
			std::string out = simple(c, "LISTEN " + ch);
			out += " | " + simple(c, "BEGIN");
			refuseAndSync(c);
			out += " | " + replies(c);
			out += " | " + simple(c, "ROLLBACK");
			notifyDirect(ch);
			usleep(300000);
			const std::string r = simple(c, "SELECT 1");
			out += (r.compare(0, 1, "A") == 0 || r.find(" A") != std::string::npos) ? " | notified" : " | not notified";
			simple(c, "UNLISTEN *");
			return out;
		});

		// L15: a WITH HOLD cursor from an earlier transaction pins the session too. After ROLLBACK it
		// can still be fetched from.
		check(mode, "L15 a WITH HOLD cursor is still there after ROLLBACK",
			"C Z(T) | C Z(T) | C Z(I) | C Z(T) | E(26000) Z(E) | C Z(I) | T D=1 C Z(I) | C Z(I)", [&](PgConnection& c) {
			const std::string cur = "l15_" + tag;
			std::string out = simple(c, "BEGIN");
			out += " | " + simple(c, "DECLARE " + cur + " CURSOR WITH HOLD FOR SELECT generate_series(1, 3)");
			out += " | " + simple(c, "COMMIT");
			out += " | " + simple(c, "BEGIN");
			refuseAndSync(c);
			out += " | " + replies(c);
			out += " | " + simple(c, "ROLLBACK");
			out += " | " + simple(c, "FETCH 1 FROM " + cur);
			return out + " | " + simple(c, "CLOSE " + cur);
		});

		// L16: COMMIT of the failed transaction gets exactly PostgreSQL's answer, notices and command
		// tag included: CommandComplete ROLLBACK, nothing else.
		check(mode, "L16 COMMIT after the refused message, notices included",
			"C Z(T) | E(26000) Z(E) | C(ROLLBACK) Z(I)", [&](PgConnection& c) {
			std::string out = simple(c, "BEGIN");
			refuseAndSync(c);
			out += " | " + replies(c);
			c.sendQuery("COMMIT");
			return out + " | " + replies(c, true);
		});
		check(mode, "L16 extended-protocol COMMIT after the refused message, notices included",
			"C Z(T) | E(26000) Z(E) | 1 2 C(ROLLBACK) Z(I)", [&](PgConnection& c) {
			std::string out = simple(c, "BEGIN");
			refuseAndSync(c);
			out += " | " + replies(c);
			extq(c, "COMMIT");
			c.sendSync();
			return out + " | " + replies(c, true);
		});

		// L17: pgjdbc with autosave sends a SAVEPOINT ahead of each statement in the same unit, and on
		// an error rolls back to it and goes on. Both inserts outside the failed one are committed.
		check(mode, "L17 pgjdbc autosave pattern recovers",
			"C Z(T) | C Z(T) | 1 2 C 1 2 C Z(T) | 1 2 C E(26000) Z(E) | 1 2 C Z(T) | 1 2 C 1 2 C Z(T) | C Z(I) | T D=2 C Z(I)",
			[&](PgConnection& c) {
			const std::string t = "l17_" + tag;
			std::string out = simple(c, "BEGIN");
			out += " | " + simple(c, "CREATE TEMP TABLE " + t + " (a int)");
			extq(c, "SAVEPOINT PGJDBC_AUTOSAVE");
			extq(c, "INSERT INTO " + t + " VALUES (1)");
			c.sendSync();
			out += " | " + replies(c);
			extq(c, "SAVEPOINT PGJDBC_AUTOSAVE");
			refuseAndSync(c);
			out += " | " + replies(c);
			extq(c, "ROLLBACK TO SAVEPOINT PGJDBC_AUTOSAVE");
			c.sendSync();
			out += " | " + replies(c);
			extq(c, "SAVEPOINT PGJDBC_AUTOSAVE");
			extq(c, "INSERT INTO " + t + " VALUES (2)");
			c.sendSync();
			out += " | " + replies(c);
			out += " | " + simple(c, "COMMIT");
			return out + " | " + simple(c, "SELECT count(*) FROM " + t);
		});

		// L17: an ORM's nested transactions: one savepoint per level, the inner one rolled back on the
		// error, both released, the outer work committed.
		check(mode, "L17 nested savepoints recover and commit the outer work",
			"C Z(T) | C Z(T) | C Z(T) | C Z(T) | C Z(T) | C Z(T) | E(26000) Z(E) | C Z(T) | C Z(T) | C Z(T) | C Z(I) | T D=2 C Z(I)",
			[&](PgConnection& c) {
			const std::string t = "l17n_" + tag;
			std::string out = simple(c, "BEGIN");
			out += " | " + simple(c, "CREATE TEMP TABLE " + t + " (a int)");
			out += " | " + simple(c, "INSERT INTO " + t + " VALUES (1)");
			out += " | " + simple(c, "SAVEPOINT s1");
			out += " | " + simple(c, "INSERT INTO " + t + " VALUES (2)");
			out += " | " + simple(c, "SAVEPOINT s2");
			refuseAndSync(c);
			out += " | " + replies(c);
			out += " | " + simple(c, "ROLLBACK TO SAVEPOINT s2");
			out += " | " + simple(c, "RELEASE SAVEPOINT s2");
			out += " | " + simple(c, "RELEASE SAVEPOINT s1");
			out += " | " + simple(c, "COMMIT");
			return out + " | " + simple(c, "SELECT count(*) FROM " + t);
		});

		// L18: each kind of statement in the failed transaction, then a ROLLBACK to end whatever is left.
		for (const auto& p : probes) {
			checkSame(mode, "L18 in the failed transaction: " + p.first, "C Z(T) | E(26000) Z(E) | ",
				[&](PgConnection& c) {
				std::string out = simple(c, "BEGIN");
				refuseAndSync(c);
				out += " | " + replies(c);
				p.second(c);
				out += " | " + replies(c);
				return out + " | " + simple(c, "ROLLBACK");
			});
		}
	}

	exec(admin.get(), "LOAD PGSQL VARIABLES FROM DISK");
	exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	return exit_status();
}
