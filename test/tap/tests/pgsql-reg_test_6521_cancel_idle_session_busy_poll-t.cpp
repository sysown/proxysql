/**
 * Regression #6521: a query cancel for a session that is not running a query
 * must not leave cancel_query set on its backend. While it was set, BeforePoll
 * gave poll() a 0 ms timeout and the worker thread busy-polled: until the next
 * query for a session idle in a transaction, for the life of a fast-forward
 * session. ProxySQL's CPU is read through the admin system_cpu stats.
 * Also: a cancel in fast forward (fast-forward users, and any user during
 * COPY ... FROM STDIN) never reached the backend, so the query ran to the end.
 * Also: a cancel for a statement still waiting for a backend connection was lost,
 * and the statement ran later anyway. It must end the wait with 57014. A wait that
 * ends on a timeout or a refused connection must not leave the rest of the unit
 * queued, and inside a transaction any of the three must fail the transaction.
 */
#include "command_line.h"
#include "libpq-fe.h"
#include "tap.h"
#include "utils.h"
#include <chrono>
#include <cstdlib>
#include <memory>
#include <sstream>
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

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

// A client connection through ProxySQL as the test user.
static PGConnPtr backend() {
	return PGConnPtr(connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password), &PQfinish);
}

// A cancel for a statement still waiting for a backend connection. The statement must
// fail with 57014 at once and never reach the backend, and the session must stay usable.
// Each backend mode gets its own hostgroup with one connection, reached through a query rule
// matching "conn_wait"; a holder session keeps that connection busy.
static const int WAIT_RULE_ID = 1729;
static const int WAIT_CHECKS_PER_MODE = 33;

static bool exec_ok(PGconn* conn, const std::string& q) {
	PGresult* res = PQexec(conn, q.c_str());
	bool good = PQresultStatus(res) == PGRES_COMMAND_OK || PQresultStatus(res) == PGRES_TUPLES_OK;
	if (!good) diag("'%s' failed: %s", q.c_str(), PQresultErrorMessage(res));
	PQclear(res);
	return good;
}

static std::string scalar(PGconn* conn, const std::string& q) {
	PGresult* res = PQexec(conn, q.c_str());
	std::string v = (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) ? PQgetvalue(res, 0, 0) : "";
	PQclear(res);
	return v;
}

// SQLSTATE of the statement's error, "" when it succeeded
static std::string drain(PGconn* conn) {
	std::string state = "?";
	while (PGresult* res = PQgetResult(conn)) {
		if (PQresultStatus(res) == PGRES_FATAL_ERROR) {
			const char* s = PQresultErrorField(res, PG_DIAG_SQLSTATE);
			if (state == "?" || state.empty()) state = s ? s : "";
		} else if (state == "?") {
			state = "";
		}
		PQclear(res);
	}
	return state;
}

static bool next_statement_works(PGconn* conn) {
	PGresult* res = PQexecParams(conn, "SELECT 2", 0, NULL, NULL, NULL, NULL, 0);
	bool good = PQresultStatus(res) == PGRES_TUPLES_OK && std::string(PQgetvalue(res, 0, 0)) == "2";
	PQclear(res);
	return good;
}

static bool pq_cancel(PGconn* conn) {
	PGcancel* cancel = PQgetCancel(conn);
	char errbuf[256];
	bool sent = cancel && PQcancel(cancel, errbuf, sizeof(errbuf)) == 1;
	if (cancel) PQfreeCancel(cancel);
	return sent;
}

// Straight to the backend, as its superuser: the test user may not be allowed to create tables.
static PGConnPtr backend_direct() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_server_host << " port=" << cl.pgsql_server_port << " user=" << cl.pgsql_server_username
	   << " password=" << cl.pgsql_server_password << " dbname=" << cl.pgsql_username << " sslmode=disable";
	PGconn* conn = PQconnectdb(ss.str().c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		diag("Error: backend connection failed: %s", PQerrorMessage(conn));
		PQfinish(conn);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(conn, &PQfinish);
}

// Keeps the wait hostgroup's only connection busy for 'secs'.
static PGConnPtr hold_connection(int secs) {
	auto holder = backend();
	if (holder) {
		PQsendQuery(holder.get(), ("SELECT pg_sleep(" + std::to_string(secs) + ") AS conn_wait_hold").c_str());
		usleep(300 * 1000);
	}
	return holder;
}

enum class WaitStmt { EXT_SLEEP, EXT_INSERT, SIMPLE_SLEEP, SIMPLE_INSERT };

// Sends the statement while the holder has the connection, cancels it after 1 s and returns its
// SQLSTATE; 'secs' is how long the answer took after the cancel.
static std::string cancel_while_waiting(PGconn* victim, WaitStmt what, bool by_pg_cancel_backend, double& secs) {
	switch (what) {
	case WaitStmt::EXT_SLEEP:
		PQsendQueryParams(victim, "SELECT pg_sleep(10) AS conn_wait", 0, NULL, NULL, NULL, NULL, 0); break;
	case WaitStmt::EXT_INSERT:
		PQsendQueryParams(victim, "INSERT INTO conn_wait_t VALUES (7)", 0, NULL, NULL, NULL, NULL, 0); break;
	case WaitStmt::SIMPLE_SLEEP:
		PQsendQuery(victim, "SELECT pg_sleep(10) AS conn_wait"); break;
	case WaitStmt::SIMPLE_INSERT:
		PQsendQuery(victim, "INSERT INTO conn_wait_t VALUES (7)"); break;
	}
	sleep(1);
	const auto t0 = std::chrono::steady_clock::now();
	if (by_pg_cancel_backend) {
		auto canceller = backend();
		if (canceller) {
			const std::string q = "SELECT pg_cancel_backend(" + std::to_string(PQbackendPID(victim)) + ")";
			PQclear(PQexec(canceller.get(), q.c_str()));
		}
	} else {
		pq_cancel(victim);
	}
	const std::string state = drain(victim);
	secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
	return state;
}

static void cancel_while_waiting_checks(PGconn* admin, bool native, int hg, int dead_hg) {
	const char* mode = native ? "native" : "libpq";
	exec_ok(admin, std::string("SET pgsql-use_native_backend_protocol='") + (native ? "true" : "false") + "'");
	exec_ok(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	exec_ok(admin, "UPDATE pgsql_query_rules SET destination_hostgroup=" + std::to_string(hg) + " WHERE rule_id=" + std::to_string(WAIT_RULE_ID));
	exec_ok(admin, "UPDATE pgsql_query_rules SET destination_hostgroup=" + std::to_string(dead_hg) + " WHERE rule_id=" + std::to_string(WAIT_RULE_ID + 1));
	exec_ok(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");

	// every case gets its own client connection, so one failing case cannot fail the next
	double secs = 0;

	{
		auto victim = backend();
		auto holder = hold_connection(4);
		std::string state = cancel_while_waiting(victim.get(), WaitStmt::EXT_SLEEP, false, secs);
		ok(state == "57014" && secs < 1.0, "[%s] extended statement waiting for a connection is cancelled at once: '%s' after %.1f s", mode, state.c_str(), secs);
		ok(next_statement_works(victim.get()), "[%s] the session runs its next statement", mode);
		ok(drain(holder.get()) == "", "[%s] the statement holding the connection is not cancelled", mode);
	}
	{
		auto victim = backend();
		PQclear(PQexec(victim.get(), "DELETE FROM conn_wait_t"));
		auto holder = hold_connection(4);
		std::string state = cancel_while_waiting(victim.get(), WaitStmt::EXT_INSERT, false, secs);
		drain(holder.get());
		ok(state == "57014" && secs < 1.0, "[%s] extended INSERT waiting for a connection is cancelled at once: '%s' after %.1f s", mode, state.c_str(), secs);
		ok(scalar(victim.get(), "SELECT count(*) FROM conn_wait_t") == "0", "[%s] the cancelled INSERT never ran", mode);
	}
	{
		auto victim = backend();
		auto holder = hold_connection(4);
		std::string state = cancel_while_waiting(victim.get(), WaitStmt::SIMPLE_SLEEP, true, secs);
		drain(holder.get());
		ok(state == "57014" && secs < 1.0, "[%s] simple statement waiting for a connection is cancelled by pg_cancel_backend() at once: '%s' after %.1f s", mode, state.c_str(), secs);
		ok(next_statement_works(victim.get()), "[%s] the session runs its next statement", mode);
	}
	{
		auto victim = backend();
		PQclear(PQexec(victim.get(), "DELETE FROM conn_wait_t"));
		auto holder = hold_connection(4);
		std::string state = cancel_while_waiting(victim.get(), WaitStmt::SIMPLE_INSERT, false, secs);
		drain(holder.get());
		ok(state == "57014", "[%s] simple INSERT waiting for a connection is cancelled: '%s'", mode, state.c_str());
		ok(scalar(victim.get(), "SELECT count(*) FROM conn_wait_t") == "0", "[%s] the cancelled INSERT never ran", mode);
	}
	{
		// Two units in one pipeline: the cancel ends the waiting first unit only.
		auto victim = backend();
		auto holder = hold_connection(4);
		PGconn* c = victim.get();
		PQenterPipelineMode(c);
		PQsendQueryParams(c, "SELECT pg_sleep(10) AS conn_wait", 0, NULL, NULL, NULL, NULL, 0);
		PQpipelineSync(c);
		PQsendQueryParams(c, "SELECT 2", 0, NULL, NULL, NULL, NULL, 0);
		PQpipelineSync(c);
		PQflush(c);
		sleep(1);
		pq_cancel(c);
		std::string first = drain(c);
		PGresult* sync1 = PQgetResult(c);
		bool synced1 = sync1 && PQresultStatus(sync1) == PGRES_PIPELINE_SYNC;
		PQclear(sync1);
		PGresult* second = PQgetResult(c);
		bool second_ok = second && PQresultStatus(second) == PGRES_TUPLES_OK && std::string(PQgetvalue(second, 0, 0)) == "2";
		PQclear(second);
		while (PGresult* res = PQgetResult(c)) {
			bool sync = PQresultStatus(res) == PGRES_PIPELINE_SYNC;
			PQclear(res);
			if (sync) break;
		}
		PQexitPipelineMode(c);
		drain(holder.get());
		ok(first == "57014" && synced1 && second_ok, "[%s] pipeline: the waiting unit is cancelled ('%s'), the next unit still runs", mode, first.c_str());
	}
	{
		// A wait that ends on pgsql-connect_timeout_server_max must not leave the rest of the
		// extended unit queued: the session's next statement would run behind it and fail.
		const std::string saved = scalar(admin, "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-connect_timeout_server_max'");
		exec_ok(admin, "SET pgsql-connect_timeout_server_max=1000");
		exec_ok(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
		auto victim = backend();
		auto holder = hold_connection(4);
		PGresult* res = PQexecParams(victim.get(), "SELECT 1 AS conn_wait", 0, NULL, NULL, NULL, NULL, 0);
		std::string msg = PQresultErrorMessage(res);
		PQclear(res);
		msg = msg.substr(0, msg.find('\n'));
		ok(msg.find("Max connect timeout") != std::string::npos, "[%s] extended statement times out waiting for a connection: '%s'", mode, msg.c_str());
		ok(next_statement_works(victim.get()), "[%s] the session runs its next statement after the timeout", mode);
		drain(holder.get());
		exec_ok(admin, "SET pgsql-connect_timeout_server_max=" + saved);
		exec_ok(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	}
	{
		// A backend that refuses connections ends the wait on the connect-failure exit, which must
		// not leave the rest of the unit queued either.
		auto victim = backend();
		PGresult* res = PQexecParams(victim.get(), "SELECT 1 AS conn_dead", 0, NULL, NULL, NULL, NULL, 0);
		const bool failed = PQresultStatus(res) == PGRES_FATAL_ERROR;
		PQclear(res);
		ok(failed, "[%s] extended statement to a backend that refuses connections fails", mode);
		ok(next_statement_works(victim.get()), "[%s] the session runs its next statement after the failure", mode);
	}
	{
		// Inside a transaction, a statement routed to another hostgroup fails there: cancelled or timed
		// out while it waits, or refused by a backend that does not accept connections. Like any error
		// in a transaction, that must fail it: the next statement is refused and COMMIT rolls back.
		const std::string user = cl.pgsql_username;
		std::string persistent = scalar(admin, "SELECT transaction_persistent FROM pgsql_users WHERE username='" + user + "' LIMIT 1");
		if (persistent.empty()) persistent = "1";
		const std::string saved = scalar(admin, "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-connect_timeout_server_max'");
		// a transaction keeps its statements on its own hostgroup unless transaction_persistent is off
		exec_ok(admin, "UPDATE pgsql_users SET transaction_persistent=0 WHERE username='" + user + "'");
		exec_ok(admin, "LOAD PGSQL USERS TO RUNTIME");
		enum class End { CANCEL, TIMEOUT, CONNECT_FAILURE };
		auto holder = hold_connection(6); // keeps the wait hostgroup busy for the cancel and timeout cases
		int next_dead_hg = dead_hg + 1;   // the case above already used dead_hg
		for (End how : { End::CANCEL, End::TIMEOUT, End::CONNECT_FAILURE }) {
			if (how == End::TIMEOUT) {
				exec_ok(admin, "SET pgsql-connect_timeout_server_max=1000");
				exec_ok(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
			} else if (how == End::CONNECT_FAILURE) {
				// the connect retries must run out before the connect timeout does
				exec_ok(admin, "SET pgsql-connect_timeout_server_max=" + saved);
				exec_ok(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
				drain(holder.get());
			}
			const char* what = how == End::CANCEL ? "cancelled" : how == End::TIMEOUT ? "timed out" : "refused a connection";
			for (bool simple : { false, true }) {
				const char* proto = simple ? "simple" : "extended";
				if (how == End::CONNECT_FAILURE) {
					exec_ok(admin, "UPDATE pgsql_query_rules SET destination_hostgroup=" + std::to_string(next_dead_hg++) +
						" WHERE rule_id=" + std::to_string(WAIT_RULE_ID + 1));
					exec_ok(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
				}
				auto victim = backend();
				PGconn* c = victim.get();
				// cancel_txn_t, not conn_wait_t: that name matches the routing rule, so the INSERT would wait too
				PQclear(PQexec(c, "DELETE FROM cancel_txn_t"));
				exec_ok(c, "BEGIN");
				exec_ok(c, "INSERT INTO cancel_txn_t VALUES (5)");
				const char* q = how == End::CONNECT_FAILURE ? "SELECT 1 AS conn_dead" : "SELECT pg_sleep(10) AS conn_wait";
				if (simple) {
					PQsendQuery(c, q);
				} else {
					PQsendQueryParams(c, q, 0, NULL, NULL, NULL, NULL, 0);
				}
				if (how == End::CANCEL) {
					usleep(300 * 1000);
					pq_cancel(c);
				}
				const std::string state = drain(c);
				const bool expected = how == End::CANCEL ? state == "57014" : how == End::TIMEOUT ? state == "08001" : !state.empty();
				ok(expected && PQtransactionStatus(c) == PQTRANS_INERROR, "[%s] %s statement %s inside a transaction ('%s'), which is then failed: status=%d",
					mode, proto, what, state.c_str(), PQtransactionStatus(c));
				PGresult* res = PQexec(c, "SELECT 1");
				const char* sqlstate = PQresultErrorField(res, PG_DIAG_SQLSTATE);
				const std::string next = sqlstate ? sqlstate : "";
				PQclear(res);
				ok(next == "25P02", "[%s] %s, %s: the next statement in the failed transaction is refused: '%s'", mode, proto, what, next.c_str());
				res = PQexec(c, "COMMIT");
				const std::string tag = PQcmdStatus(res);
				PQclear(res);
				ok(tag == "ROLLBACK" && scalar(c, "SELECT count(*) FROM cancel_txn_t") == "0",
					"[%s] %s, %s: COMMIT rolls back and the INSERT is not saved: '%s'", mode, proto, what, tag.c_str());
			}
		}
		exec_ok(admin, "UPDATE pgsql_users SET transaction_persistent=" + persistent + " WHERE username='" + user + "'");
		exec_ok(admin, "LOAD PGSQL USERS TO RUNTIME");
	}
	std::string used;
	for (int i = 0; i < 20; i++) {
		used = scalar(admin, "SELECT ConnUsed FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(hg));
		if (used == "0") break;
		usleep(100 * 1000);
	}
	ok(used == "0", "[%s] no connection of the wait hostgroup is left in use: ConnUsed='%s'", mode, used.c_str());
}

static void test_cancel_while_waiting_for_connection(PGconn* a) {
	diag("Cancel a statement waiting for a backend connection");

	const std::string user = cl.pgsql_username;
	const std::string def_hg = scalar(a, "SELECT default_hostgroup FROM runtime_pgsql_users WHERE username='" + user + "' LIMIT 1");
	PGresult* srv = PQexec(a, ("SELECT hostname, port, use_ssl FROM runtime_pgsql_servers WHERE hostgroup_id=" + def_hg + " LIMIT 1").c_str());
	if (PQresultStatus(srv) != PGRES_TUPLES_OK || PQntuples(srv) == 0) {
		diag("Error: no backend server for hostgroup '%s' in file %s, line %d", def_hg.c_str(), __FILE__, __LINE__);
		PQclear(srv);
		return;
	}
	const std::string host = PQgetvalue(srv, 0, 0), port = PQgetvalue(srv, 0, 1), ssl = PQgetvalue(srv, 0, 2);
	PQclear(srv);
	const std::string native_saved = scalar(a, "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");

	// one hostgroup per backend mode, so neither reuses a connection made in the other mode
	const int hgs[2] = { WAIT_RULE_ID, WAIT_RULE_ID + 1 };
	for (int hg : hgs) {
		exec_ok(a, "INSERT INTO pgsql_servers (hostgroup_id, hostname, port, max_connections, use_ssl) VALUES (" +
			std::to_string(hg) + ", '" + host + "', " + port + ", 1, " + ssl + ")");
	}
	// and three per mode whose server refuses connections (port 1), one per connect failure below:
	// each failure meets a fresh, unshunned server
	const int dead_hgs[2] = { WAIT_RULE_ID + 2, WAIT_RULE_ID + 5 };
	for (int hg : dead_hgs) {
		for (int k = 0; k < 3; k++) {
			exec_ok(a, "INSERT INTO pgsql_servers (hostgroup_id, hostname, port, max_connections, use_ssl) VALUES (" +
				std::to_string(hg + k) + ", '" + host + "', 1, 1, 0)");
		}
	}
	exec_ok(a, "LOAD PGSQL SERVERS TO RUNTIME");
	exec_ok(a, "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (" +
		std::to_string(WAIT_RULE_ID) + ", 1, 'conn_wait', " + std::to_string(hgs[0]) + ", 1)");
	exec_ok(a, "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (" +
		std::to_string(WAIT_RULE_ID + 1) + ", 1, 'conn_dead', " + std::to_string(dead_hgs[0]) + ", 1)");
	exec_ok(a, "LOAD PGSQL QUERY RULES TO RUNTIME");
	{
		auto be = backend_direct();
		if (be) {
			exec_ok(be.get(), "CREATE TABLE IF NOT EXISTS conn_wait_t (i int)");
			exec_ok(be.get(), "GRANT ALL ON conn_wait_t TO " + user);
			exec_ok(be.get(), "CREATE TABLE IF NOT EXISTS cancel_txn_t (i int)");
			exec_ok(be.get(), "GRANT ALL ON cancel_txn_t TO " + user);
		}
	}

	cancel_while_waiting_checks(a, false, hgs[0], dead_hgs[0]);
	cancel_while_waiting_checks(a, true, hgs[1], dead_hgs[1]);

	{
		auto be = backend_direct();
		if (be) {
			exec_ok(be.get(), "DROP TABLE IF EXISTS conn_wait_t");
			exec_ok(be.get(), "DROP TABLE IF EXISTS cancel_txn_t");
		}
	}
	exec_ok(a, "DELETE FROM pgsql_query_rules WHERE rule_id IN (" + std::to_string(WAIT_RULE_ID) + ", " + std::to_string(WAIT_RULE_ID + 1) + ")");
	exec_ok(a, "LOAD PGSQL QUERY RULES TO RUNTIME");
	exec_ok(a, "DELETE FROM pgsql_servers WHERE hostgroup_id BETWEEN " + std::to_string(WAIT_RULE_ID) + " AND " + std::to_string(WAIT_RULE_ID + 7));
	exec_ok(a, "LOAD PGSQL SERVERS TO RUNTIME");
	exec_ok(a, "SET pgsql-use_native_backend_protocol='" + native_saved + "'");
	exec_ok(a, "LOAD PGSQL VARIABLES TO RUNTIME");
}

int main() {
	alarm(300);
	plan(10 + 2 * WAIT_CHECKS_PER_MODE);
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

	test_cancel_while_waiting_for_connection(admin);

	PQfinish(admin);
	return exit_status();
}
