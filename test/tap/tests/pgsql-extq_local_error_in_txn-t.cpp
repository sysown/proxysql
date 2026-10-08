/**
 * @file pgsql-extq_local_error_in_txn-t.cpp
 * @brief An extended-query error ProxySQL gives itself, inside a transaction block, must fail the
 *        transaction as PostgreSQL does: ReadyForQuery 'E', later statements refused until
 *        ROLLBACK, the work done so far never committed, and a savepoint still able to recover it.
 *
 * Each case runs through ProxySQL and straight against PostgreSQL, and the replies are compared. The
 * error is one ProxySQL answers without the backend: a Bind of a statement the client never
 * prepared, an Execute of a portal never bound. Inside a transaction this is checked with the
 * native backend protocol only; the libpq one still leaves the transaction open.
 */

#include <chrono>
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
static std::string replies(PgConnection& c) {
	std::string out;
	for (;;) {
		char type = 0;
		std::vector<uint8_t> buf;
		c.readMessage(type, buf);
		if (type == 'N' || type == 'S') continue;
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

int main(int, char**) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}
	plan(14);
	tag = std::to_string(getpid()) + "_" + std::to_string(time(nullptr) % 100000);

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

		// L10: the unit ends with a simple Query instead of a Sync. PostgreSQL itself ignores the Query
		// after the error and waits for a Sync, so this is ProxySQL only: the error ends the unit with
		// a ReadyForQuery, the Query then runs in the failed transaction, and ROLLBACK ends it.
		checkProxy(mode, "L10 refused message in a unit ended by a simple Query",
			"C Z(T) | E(26000) Z(E) | E(25P02) Z(E) | C Z(I)", [&](PgConnection& c) {
			std::string out = simple(c, "BEGIN");
			c.bindStatement("none_" + tag, "", {}, {}, false);
			c.executePortal("", 0, false);
			c.sendQuery("SELECT 1");
			out += " | " + replies(c);
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
	}

	exec(admin.get(), "LOAD PGSQL VARIABLES FROM DISK");
	exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	return exit_status();
}
