/**
 * @file pgsql-commit_prepared_forwarded-t.cpp
 * @brief Transaction-end statements that do real work outside a transaction block
 *        must reach PostgreSQL instead of being answered locally.
 *
 * WHY THIS EXISTS
 * ---------------
 * When a session holds no backend transaction, PgSQL_Session::handler_CommitRollback
 * answers COMMIT / END / ROLLBACK / ABORT itself with a CommandComplete, and sends
 * nothing to a backend: the statement is a no-op there anyway. It used to recognise
 * those statements by prefix only, so it also swallowed statements that merely START
 * with one of the verbs and are meaningful, or required, outside a transaction block:
 *
 *   - COMMIT PREPARED 'gid' / ROLLBACK PREPARED 'gid' (two-phase commit). The client
 *     was told the global transaction committed while it stayed in pg_prepared_xacts,
 *     holding its locks, with its writes never applied;
 *   - "COMMIT; <more SQL>": the statements after the COMMIT were silently dropped;
 *   - ROLLBACK TO SAVEPOINT and COMMIT AND CHAIN, which PostgreSQL rejects outside
 *     a transaction block (25P01), were reported as successful.
 *
 * Every case runs on a session that has never opened a transaction, so no backend
 * transaction exists and the local short-circuit is the path under test. The
 * expectations are PostgreSQL's own answers.
 *
 * A full PREPARE TRANSACTION / COMMIT PREPARED round trip needs the backend to have
 * max_prepared_transactions > 0 (default 0). It runs when the backend allows it and
 * is skipped otherwise; the nonexistent-gid cases already prove the statement is
 * forwarded, because only PostgreSQL can answer 42704 (undefined_object).
 *
 * The plain forms (COMMIT, END, ROLLBACK;, ABORT WORK) must still be answered
 * successfully, as before.
 *
 * INFRA: legacy-g4 (any group with a PostgreSQL backend behind ProxySQL works).
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const char* SQLSTATE_UNDEFINED_OBJECT = "42704";
static const char* SQLSTATE_NO_ACTIVE_SQL_TRANSACTION = "25P01";

static PGConnPtr createProxyConn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " sslmode=disable";
	PGConnPtr conn(PQconnectdb(ss.str().c_str()), &PQfinish);
	if (PQstatus(conn.get()) != CONNECTION_OK) {
		diag("Connection to ProxySQL failed: %s", PQerrorMessage(conn.get()));
		return PGConnPtr(nullptr, &PQfinish);
	}
	return conn;
}

static std::string sqlstate_of(const PGresult* res) {
	const char* s = PQresultErrorField(res, PG_DIAG_SQLSTATE);
	return s ? s : "";
}

// The statement must fail with the given SQLSTATE: proof that PostgreSQL saw it.
static void expect_error(PGconn* conn, const char* query, const char* sqlstate) {
	PGresult* res = PQexec(conn, query);
	const ExecStatusType st = PQresultStatus(res);
	const std::string got = sqlstate_of(res);
	ok(st == PGRES_FATAL_ERROR && got == sqlstate,
		"'%s' is forwarded: expected error %s, got status=%s sqlstate='%s' msg='%s'",
		query, sqlstate, PQresStatus(st), got.c_str(), PQresultErrorMessage(res));
	PQclear(res);
}

// "<txn end>; SELECT <n>": PQexec returns the last statement's result, so seeing
// <n> proves the statement after the transaction end was executed.
static void expect_trailing_select(PGconn* conn, const char* query, const char* value) {
	PGresult* res = PQexec(conn, query);
	const ExecStatusType st = PQresultStatus(res);
	const bool got_row = st == PGRES_TUPLES_OK && PQntuples(res) == 1 && PQnfields(res) == 1;
	const char* got = got_row ? PQgetvalue(res, 0, 0) : "";
	ok(got_row && strcmp(got, value) == 0,
		"'%s' runs the trailing SELECT: expected '%s', got status=%s value='%s' msg='%s'",
		query, value, PQresStatus(st), got, PQresultErrorMessage(res));
	PQclear(res);
}

static void expect_command_ok(PGconn* conn, const char* query) {
	PGresult* res = PQexec(conn, query);
	const ExecStatusType st = PQresultStatus(res);
	ok(st == PGRES_COMMAND_OK,
		"plain '%s' outside a transaction succeeds: status=%s msg='%s'",
		query, PQresStatus(st), PQresultErrorMessage(res));
	PQclear(res);
}

static bool exec_ok(PGconn* conn, const char* query) {
	PGresult* res = PQexec(conn, query);
	const ExecStatusType st = PQresultStatus(res);
	const bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) diag("'%s' failed: %s", query, PQresultErrorMessage(res));
	PQclear(res);
	return good;
}

static std::string scalar(PGconn* conn, const char* query) {
	PGresult* res = PQexec(conn, query);
	std::string v;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0))
		v = PQgetvalue(res, 0, 0);
	else
		diag("'%s' failed: %s", query, PQresultErrorMessage(res));
	PQclear(res);
	return v;
}

// Real two-phase commit through ProxySQL: the prepared transaction must be committed
// on the server and its row must become visible. 3 assertions.
static void test_two_phase_commit_round_trip(PGconn* conn) {
	const std::string mpt = scalar(conn, "SHOW max_prepared_transactions");
	if (mpt.empty() || atoi(mpt.c_str()) <= 0) {
		skip(3, "backend max_prepared_transactions=%s, two-phase commit unavailable",
			mpt.empty() ? "?" : mpt.c_str());
		return;
	}
	const char* gid = "proxysql_commit_prepared_forwarded_gid";
	char q[256];
	// A leftover from an interrupted earlier run would make PREPARE TRANSACTION fail.
	snprintf(q, sizeof(q), "ROLLBACK PREPARED '%s'", gid);
	PGresult* res = PQexec(conn, q);
	PQclear(res);

	bool setup = exec_ok(conn, "DROP TABLE IF EXISTS commit_prepared_forwarded_tbl") &&
		exec_ok(conn, "CREATE TABLE commit_prepared_forwarded_tbl (id int)") &&
		exec_ok(conn, "BEGIN") &&
		exec_ok(conn, "INSERT INTO commit_prepared_forwarded_tbl VALUES (1)");
	snprintf(q, sizeof(q), "PREPARE TRANSACTION '%s'", gid);
	setup = setup && exec_ok(conn, q);
	ok(setup, "two-phase commit: table created and transaction prepared");
	if (!setup) {
		skip(2, "two-phase commit setup failed");
		exec_ok(conn, "ROLLBACK");
		return;
	}

	// The session is now idle with no backend transaction: exactly the state in
	// which COMMIT PREPARED used to be answered locally.
	snprintf(q, sizeof(q), "COMMIT PREPARED '%s'", gid);
	res = PQexec(conn, q);
	const ExecStatusType st = PQresultStatus(res);
	ok(st == PGRES_COMMAND_OK, "'%s' succeeds: status=%s msg='%s'",
		q, PQresStatus(st), PQresultErrorMessage(res));
	PQclear(res);

	snprintf(q, sizeof(q),
		"SELECT (SELECT count(*) FROM commit_prepared_forwarded_tbl) || '/' || "
		"(SELECT count(*) FROM pg_prepared_xacts WHERE gid = '%s')", gid);
	const std::string counts = scalar(conn, q);
	ok(counts == "1/0",
		"two-phase commit applied on the server: rows/prepared = '%s' (expected '1/0')",
		counts.c_str());

	exec_ok(conn, "DROP TABLE IF EXISTS commit_prepared_forwarded_tbl");
}

int main(int argc, char** argv) {
	plan(1 + 2 + 3 + 2 + 4 + 3 + 1);

	if (cl.getEnv())
		return exit_status();

	PGConnPtr conn = createProxyConn();
	ok(conn != nullptr, "connected to ProxySQL");
	if (!conn)
		return exit_status();
	PGconn* c = conn.get();

	// Two-phase commit statements on a gid that does not exist: only PostgreSQL
	// can produce 42704. A local answer is a CommandComplete instead.
	expect_error(c, "COMMIT PREPARED 'proxysql_nonexistent_gid'", SQLSTATE_UNDEFINED_OBJECT);
	expect_error(c, "ROLLBACK PREPARED 'proxysql_nonexistent_gid'", SQLSTATE_UNDEFINED_OBJECT);

	// Multi-statement queries that start with a transaction end.
	expect_trailing_select(c, "COMMIT; SELECT 4242", "4242");
	expect_trailing_select(c, "END; SELECT 4243", "4243");
	expect_trailing_select(c, "ROLLBACK; SELECT 4244", "4244");

	// Forms PostgreSQL rejects outside a transaction block.
	expect_error(c, "ROLLBACK TO SAVEPOINT proxysql_no_such_sp", SQLSTATE_NO_ACTIVE_SQL_TRANSACTION);
	expect_error(c, "COMMIT AND CHAIN", SQLSTATE_NO_ACTIVE_SQL_TRANSACTION);

	// The plain forms keep being answered successfully.
	expect_command_ok(c, "COMMIT");
	expect_command_ok(c, "END");
	expect_command_ok(c, "ROLLBACK;");
	expect_command_ok(c, "ABORT WORK");

	test_two_phase_commit_round_trip(c);

	PGresult* res = PQexec(c, "SELECT 1");
	ok(PQresultStatus(res) == PGRES_TUPLES_OK && PQtransactionStatus(c) == PQTRANS_IDLE,
		"session still usable and idle: %s", PQerrorMessage(c));
	PQclear(res);

	return exit_status();
}
