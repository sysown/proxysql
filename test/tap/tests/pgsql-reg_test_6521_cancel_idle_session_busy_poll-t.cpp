/**
 * Regression #6521: a query cancel for a session that is not running a query
 * must not leave cancel_query set on its backend. While it was set, BeforePoll
 * gave poll() a 0 ms timeout and the worker thread busy-polled: until the next
 * query for a session idle in a transaction, for the life of a fast-forward
 * session. ProxySQL's CPU is read through the admin system_cpu stats.
 * Also: a cancel in fast forward (fast-forward users, and any user during
 * COPY ... FROM STDIN) never reached the backend, so the query ran to the end.
 */
#include "command_line.h"
#include "libpq-fe.h"
#include "tap.h"
#include "utils.h"
#include <chrono>
#include <cstdlib>
#include <string>
#include <unistd.h>

// A busy-polling worker thread shows as ~100% (one core); an idle ProxySQL stays far below.
static const int MAX_IDLE_CPU = 30;
// The cancelled statements run 5 s and are cancelled after 1 s.
static const double MAX_SECS = 3.0;

static CommandLine cl;

static PGconn *connect(const char *host, int port, const char *user, const char *pass, const char *db = nullptr) {
	std::string s = "host=" + std::string(host) + " port=" + std::to_string(port) + " user=" + user +
					" password=" + pass + " sslmode=disable connect_timeout=5";
	if (db)
		s += " dbname=" + std::string(db);
	PGconn *c = PQconnectdb(s.c_str());
	if (PQstatus(c) != CONNECTION_OK)
		BAIL_OUT("connect: %s", PQerrorMessage(c));
	return c;
}

static std::string value(PGconn *c, const std::string &q) {
	PGresult *r = PQexec(c, q.c_str());
	if (PQresultStatus(r) != PGRES_TUPLES_OK && PQresultStatus(r) != PGRES_COMMAND_OK)
		BAIL_OUT("query '%s': %s", q.c_str(), PQresultErrorMessage(r));
	std::string s = PQntuples(r) ? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return s;
}

// Sends a CancelRequest for the idle session behind c, then reads ProxySQL's CPU.
static void cancel_and_check_cpu(PGconn *c, const char *what) {
	PGcancel *cancel = PQgetCancel(c);
	char errbuf[256];
	ok(cancel && PQcancel(cancel, errbuf, sizeof(errbuf)) == 1, "PQcancel on %s succeeds", what);
	if (cancel)
		PQfreeCancel(cancel);
	double cpu = 0;
	if (get_proxysql_cpu_usage(cl, cpu, 5))
		BAIL_OUT("failed to read ProxySQL CPU usage");
	ok(cpu < MAX_IDLE_CPU, "ProxySQL CPU after cancelling %s stays below %d%%: %.1f%%", what, MAX_IDLE_CPU, cpu);
}

// Cancels the statement running on c after 1 s; returns its SQLSTATE ("" on success).
static std::string cancel_after_1s(PGconn *c, double &secs) {
	sleep(1);
	const auto t0 = std::chrono::steady_clock::now();
	PGcancel *cancel = PQgetCancel(c);
	char errbuf[256];
	if (!cancel || PQcancel(cancel, errbuf, sizeof(errbuf)) != 1)
		BAIL_OUT("PQcancel: %s", cancel ? errbuf : "no cancel object");
	PQfreeCancel(cancel);
	std::string state;
	while (PGresult *r = PQgetResult(c)) {
		if (PQresultStatus(r) == PGRES_FATAL_ERROR && state.empty())
			state = PQresultErrorField(r, PG_DIAG_SQLSTATE) ? PQresultErrorField(r, PG_DIAG_SQLSTATE) : "?";
		PQclear(r);
	}
	secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
	return state;
}

int main() {
	alarm(120);
	plan(10);
	if (cl.getEnv())
		return exit_status();
	PGconn *admin = connect(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password);
	const std::string user = cl.pgsql_username;
	double secs = 0;

	// Idle inside a transaction: the backend stays attached and polled.
	PGconn *c = connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, "postgres");
	value(c, "BEGIN");
	value(c, "SELECT 1");
	cancel_and_check_cpu(c, "a session idle in a transaction");
	PGresult *r = PQexec(c, "SELECT 1");
	ok(PQresultStatus(r) == PGRES_TUPLES_OK, "the transaction still runs its next query");
	PQclear(r);
	value(c, "COMMIT");

	// COPY FROM STDIN runs in fast forward; the trigger keeps the backend busy.
	value(c, "DROP TABLE IF EXISTS reg_6521_t");
	value(c, "DROP FUNCTION IF EXISTS reg_6521_sleep()");
	value(c, "CREATE TABLE reg_6521_t (i int)");
	value(c, "CREATE FUNCTION reg_6521_sleep() RETURNS trigger LANGUAGE plpgsql AS "
			 "$$ BEGIN PERFORM pg_sleep(5); RETURN NEW; END $$");
	value(c, "CREATE TRIGGER reg_6521_sleep BEFORE INSERT ON reg_6521_t FOR EACH ROW EXECUTE FUNCTION reg_6521_sleep()");
	r = PQexec(c, "COPY reg_6521_t FROM STDIN");
	if (PQresultStatus(r) != PGRES_COPY_IN)
		BAIL_OUT("COPY did not start: %s", PQresultErrorMessage(r));
	PQclear(r);
	if (PQputCopyData(c, "1\n", 2) != 1 || PQputCopyEnd(c, NULL) != 1)
		BAIL_OUT("COPY data: %s", PQerrorMessage(c));
	std::string state = cancel_after_1s(c, secs);
	ok(state == "57014" && secs < MAX_SECS, "COPY FROM STDIN is cancelled: SQLSTATE '%s' after %.1f s", state.c_str(), secs);
	ok(value(c, "SELECT count(*) FROM reg_6521_t") == "0", "the cancelled COPY inserted no row");

	// Fast forward: an idle session must not spin, and every cancel must reach the backend.
	value(admin, "UPDATE pgsql_users SET fast_forward=1 WHERE username='" + user + "'");
	value(admin, "LOAD PGSQL USERS TO RUNTIME");
	PGconn *f = connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, "postgres");
	value(f, "SELECT 1");
	cancel_and_check_cpu(f, "an idle fast-forward session");
	for (const char *which : { "first", "second" }) {
		if (PQsendQuery(f, "SELECT pg_sleep(5)") != 1)
			BAIL_OUT("send: %s", PQerrorMessage(f));
		state = cancel_after_1s(f, secs);
		ok(state == "57014" && secs < MAX_SECS, "fast forward: the %s pg_sleep(5) is cancelled: SQLSTATE '%s' after %.1f s",
			which, state.c_str(), secs);
	}
	ok(value(f, "SELECT 1") == "1", "fast forward: the session still runs a query");
	PQfinish(f);
	value(admin, "UPDATE pgsql_users SET fast_forward=0 WHERE username='" + user + "'");
	value(admin, "LOAD PGSQL USERS TO RUNTIME");

	value(c, "DROP TABLE reg_6521_t");
	value(c, "DROP FUNCTION reg_6521_sleep()");
	PQfinish(c);
	PQfinish(admin);
	return exit_status();
}
