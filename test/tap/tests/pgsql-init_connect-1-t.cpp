/**
 * @file pgsql-init_connect-1-t.cpp
 * @brief Global 'pgsql-init_connect': PostgreSQL port of mysql-init_connect-1-t.
 *
 * init_connect runs once on every new backend connection, before ProxySQL syncs the
 * client's tracked parameters. The feature is v3.1+ (PROXYSQL31); the tier is read from
 * the server's 'admin-version', and v3.1 cases run in both native and libpq backend mode.
 *
 * Every marker query carries create_new_connection=1, because a pooled connection keeps
 * the init_connect it was opened with.
 *
 * State touched (restored on exit): 'pgsql-init_connect', 'pgsql-use_native_backend_protocol'.
 */

#include "pgsql_init_connect_common.h"

#include <fstream>
#include <string>

CommandLine cl;

static constexpr int kPerMode = 21;       // v3.1 cases run once per backend mode
static constexpr int kStableCases = 3;    // v3.0 cases

// Two statements and one Sync in libpq pipeline mode; the first opens a new connection.
static bool pipeline_sees(PGconn* c, const char* expected) {
	if (!PQenterPipelineMode(c) ||
		!PQsendQueryParams(c, IC_MARKER, 0, NULL, NULL, NULL, NULL, 0) ||
		!PQsendQueryParams(c, "SELECT current_setting('ic.marker', true)", 0, NULL, NULL, NULL, NULL, 0) ||
		!PQpipelineSync(c)) {
		diag("pipeline send failed: %s", PQerrorMessage(c));
		return false;
	}
	int matched = 0;
	const unsigned long long deadline = monotonic_time() + 10000000ULL;
	while (monotonic_time() < deadline) {
		if (PQisBusy(c)) {
			struct pollfd pfd = { PQsocket(c), POLLIN, 0 };
			poll(&pfd, 1, 100);
			if (!PQconsumeInput(c)) break;
			continue;
		}
		PGresult* r = PQgetResult(c);
		if (r == NULL) continue;   // end of one statement's results
		const ExecStatusType st = PQresultStatus(r);
		if (st == PGRES_TUPLES_OK && PQntuples(r) == 1 && strcmp(PQgetvalue(r, 0, 0), expected) == 0) {
			matched++;
		} else if (st != PGRES_PIPELINE_SYNC) {
			diag("pipeline result %s: %s", PQresStatus(st), PQresultErrorMessage(r));
		}
		PQclear(r);
		if (st == PGRES_PIPELINE_SYNC) {
			PQexitPipelineMode(c);
			return matched == 2;
		}
	}
	diag("pipeline timed out or lost its connection: %s", PQerrorMessage(c));
	return false;
}

static long long seq_value(PGconn* c) {
	const IcResult r = ic_query(c, "SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM ic_seq");
	return r.ok ? atoll(r.value.c_str()) : -1;
}

static long long conn_ok(PGconn* admin) {
	return atoll(ic_admin_value(admin, "SELECT SUM(ConnOK) FROM stats_pgsql_connection_pool").c_str());
}

// A fresh client per case: a timed-out query leaves its connection busy.
static void run_mode(PGconn* admin, bool native) {
	ic_set_global(admin, "SET ic.marker TO 'global'");
	PGConnPtr c1 = ic_connect_client(cl);
	IcResult r = ic_query(c1.get(), IC_MARKER);
	ok(!r.timed_out && r.ok && r.value == "global",
	   "[native=%d] global init_connect applied (got '%s')", native, r.value.c_str());

	ic_set_global(admin, "SET ic.marker TO 'it''s'");
	PGConnPtr c2 = ic_connect_client(cl);
	r = ic_query(c2.get(), IC_MARKER);
	ok(!r.timed_out && r.ok && r.value == "it's",
	   "[native=%d] quoted value survives admin storage (got '%s')", native, r.value.c_str());

	// PMC-10003: init_connect must not return rows; the session is closed.
	ic_set_global(admin, "SELECT 1");
	PGConnPtr c3 = ic_connect_client(cl);
	r = ic_query(c3.get(), IC_MARKER);
	ok(!r.timed_out && !r.ok, "[native=%d] SELECT 1 init_connect fails the query", native);
	ic_set_global(admin, "SET ic.marker TO 'global'");
	// With a valid init_connect again, a closed session still fails, and libpq saw it close (not a hang).
	r = ic_query(c3.get(), IC_MARKER);
	ok(!r.timed_out && !r.ok && PQstatus(c3.get()) == CONNECTION_BAD, "[native=%d] and closes the session", native);
	PGConnPtr c4 = ic_connect_client(cl);
	r = ic_query(c4.get(), IC_MARKER);
	ok(!ic_admin_value(admin, "SELECT 1").empty() && r.ok && r.value == "global",
	   "[native=%d] ProxySQL still serves admin and new clients after PMC-10003", native);

	ic_set_global(admin, "SELECT pg_sleep(3)");
	PGConnPtr c5 = ic_connect_client(cl);
	r = ic_query(c5.get(), IC_MARKER);
	ok(!r.timed_out && !r.ok, "[native=%d] pg_sleep init_connect fails the query", native);
	ok(r.elapsed_ms > 2900 && r.elapsed_ms < 5000,
	   "[native=%d] after ~3 s (got %llu ms)", native, r.elapsed_ms);

	// A backend error reaches the client, and its session stays open.
	ic_set_global(admin, "Syntax Error");
	PGConnPtr c6 = ic_connect_client(cl);
	r = ic_query(c6.get(), IC_MARKER);
	ok(!r.timed_out && r.sqlstate == "42601",
	   "[native=%d] syntax error reaches the client (sqlstate '%s')", native, r.sqlstate.c_str());
	ic_set_global(admin, "SET ic.marker TO 'global'");
	r = ic_query(c6.get(), IC_MARKER);
	ok(!r.timed_out && r.ok && r.value == "global",
	   "[native=%d] same session works once init_connect is valid (got '%s')", native, r.value.c_str());

	ic_set_global(admin, "Syntax Error");
	PGConnPtr c7 = ic_connect_client(cl);
	r = ic_query_extended(c7.get(), IC_MARKER);
	ok(!r.timed_out && r.sqlstate == "42601",
	   "[native=%d] extended query gets the syntax error (sqlstate '%s')", native, r.sqlstate.c_str());
	ic_set_global(admin, "SET ic.marker TO 'global'");
	r = ic_query_extended(c7.get(), IC_MARKER);
	ok(!r.timed_out && r.ok && r.value == "global",
	   "[native=%d] extended session survives (got '%s')", native, r.value.c_str());

	// The backend sends an error and then closes (FATAL 57P01). As in MySQL, a server error is not
	// retried: every new connection would end the same way. The client gets it, and keeps its session.
	ic_set_global(admin, "DO $$BEGIN PERFORM pg_terminate_backend(pg_backend_pid()); END$$");
	PGConnPtr ck = ic_connect_client(cl);
	const long long kill_conn0 = atoll(ic_admin_value(admin, "SELECT SUM(ConnOK) FROM stats_pgsql_connection_pool").c_str());
	r = ic_query(ck.get(), IC_MARKER);
	const long long kill_conns = atoll(ic_admin_value(admin, "SELECT SUM(ConnOK) FROM stats_pgsql_connection_pool").c_str()) - kill_conn0;
	ok(!r.timed_out && r.sqlstate == "57P01" && kill_conns == 1,
	   "[native=%d] a backend that ends its own session is reported, not retried (sqlstate '%s', %lld connections)",
	   native, r.sqlstate.c_str(), kill_conns);
	ic_set_global(admin, "SET ic.marker TO 'global'");
	r = ic_query(ck.get(), IC_MARKER);
	ok(!r.timed_out && r.ok && r.value == "global",
	   "[native=%d] and the client session is kept (got '%s')", native, r.value.c_str());

	// An init_connect that fails inside its own transaction leaves that backend in 'E'. That
	// transaction is ProxySQL's, not the client's: the client must not be left in a failed one.
	ic_set_global(admin, "BEGIN; SET statement_timeout TO 'bogus'; COMMIT");
	PGConnPtr ct = ic_connect_client(cl);
	r = ic_query(ct.get(), IC_MARKER);
	ic_set_global(admin, "SET ic.marker TO 'global'");
	const IcResult simple = ic_query(ct.get(), IC_MARKER);
	const IcResult ext = ic_query_extended(ct.get(), IC_MARKER);
	ok(!r.timed_out && r.sqlstate == "22023" && simple.value == "global" && ext.value == "global",
	   "[native=%d] an init_connect transaction does not leave the client in one (sqlstate '%s', then '%s'/'%s' %s/%s)",
	   native, r.sqlstate.c_str(), simple.value.c_str(), ext.value.c_str(), simple.sqlstate.c_str(), ext.sqlstate.c_str());

	// A later statement of a multi-statement init_connect counts like the first: its error
	// reaches the client (session kept), its rows close the session (PMC-10003).
	ic_set_global(admin, "SET ic.a TO '1'; SET statement_timeout TO 'bogus'");
	PGConnPtr m1 = ic_connect_client(cl);
	r = ic_query(m1.get(), IC_MARKER);
	ic_set_global(admin, "SET ic.marker TO 'global'");
	IcResult after = ic_query(m1.get(), IC_MARKER);
	ok(!r.timed_out && r.sqlstate == "22023" && after.value == "global",
	   "[native=%d] an error in a later statement reaches the client, session kept (sqlstate '%s', then '%s')",
	   native, r.sqlstate.c_str(), after.value.c_str());

	ic_set_global(admin, "SET ic.a TO '1'; SELECT 1");
	PGConnPtr m2 = ic_connect_client(cl);
	r = ic_query(m2.get(), IC_MARKER);
	ic_set_global(admin, "SET ic.marker TO 'global'");
	after = ic_query(m2.get(), IC_MARKER);
	ok(!r.timed_out && !r.ok && !after.ok && PQstatus(m2.get()) == CONNECTION_BAD,
	   "[native=%d] rows from a later statement close the session", native);

	ic_set_global(admin, "SET ic.a TO '1'; SET ic.b TO '2'");
	PGConnPtr c8 = ic_connect_client(cl);
	r = ic_query(c8.get(), "SELECT /* create_new_connection=1 */ "
		"current_setting('ic.a', true) || current_setting('ic.b', true)");
	ok(!r.timed_out && r.ok && r.value == "12",
	   "[native=%d] multi-statement init_connect runs every statement (got '%s')", native, r.value.c_str());

	// Values no pooled connection carries: only a new connection can return them.
	ic_set_global(admin, "SET ic.marker TO 'ext'");
	PGConnPtr c9 = ic_connect_client(cl);
	r = ic_query_extended(c9.get(), IC_MARKER);
	ok(!r.timed_out && r.ok && r.value == "ext",
	   "[native=%d] extended query sees init_connect (got '%s')", native, r.value.c_str());

	ic_set_global(admin, "SET ic.marker TO 'pipe'");
	PGConnPtr c10 = ic_connect_client(cl);
	ok(pipeline_sees(c10.get(), "pipe"),
	   "[native=%d] pipelined batch on a new connection sees init_connect", native);

	// Sent once per backend connection: nextval() is not rolled back, so the sequence counts
	// init_connect runs, and ConnOK counts backend connections opened meanwhile. Each pair is
	// read sequence first, so a connection opened by the read itself lands in both.
	// The DDL client may stay attached to its backend, so the counted queries use another.
	PGConnPtr c11 = ic_connect_client(cl);
	ic_query(c11.get(), "CREATE SEQUENCE IF NOT EXISTS ic_seq");
	ic_set_global(admin, "DO $$BEGIN PERFORM nextval('ic_seq'); END$$");
	const long long seq0 = seq_value(c11.get()), conn0 = conn_ok(admin);
	PGConnPtr work = ic_connect_client(cl);
	ic_query(work.get(), IC_MARKER);
	for (int i = 0; i < 4; i++) ic_query(work.get(), "SELECT 1");
	const long long seq1 = seq_value(c11.get()), conn1 = conn_ok(admin);
	ok(seq1 - seq0 == conn1 - conn0 && conn1 - conn0 >= 1 && conn1 - conn0 < 5,
	   "[native=%d] sent once per backend connection (runs %lld-%lld, connections %lld-%lld)",
	   native, seq1, seq0, conn1, conn0);
	ic_set_global(admin, "");
	ic_query(c11.get(), "DROP SEQUENCE IF EXISTS ic_seq");

	// A connection held by a transaction keeps the init_connect it was opened with.
	ic_set_global(admin, "SET ic.marker TO 'global'");
	PGConnPtr c12 = ic_connect_client(cl);
	ic_query(c12.get(), "/* create_new_connection=1 */ BEGIN");
	const std::string before = ic_query(c12.get(), "SELECT current_setting('ic.marker', true)").value;
	ic_set_global(admin, "SET ic.marker TO 'next'");
	const std::string held = ic_query(c12.get(), "SELECT current_setting('ic.marker', true)").value;
	ic_query(c12.get(), "COMMIT");
	const std::string fresh = ic_query(c12.get(), IC_MARKER).value;
	ok(before == "global" && held == "global" && fresh == "next",
	   "[native=%d] runtime change reaches only new connections (before '%s', held '%s', new '%s')",
	   native, before.c_str(), held.c_str(), fresh.c_str());
}

// v3.0 ignores init_connect instead of stalling every new connection, and warns when the
// value is loaded to runtime.
static void run_stable(PGconn* admin) {
	const std::string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
	std::fstream log;
	const bool log_open = open_file_and_seek_end(log_path, log) == EXIT_SUCCESS;
	ic_set_global(admin, "SET ic.marker TO 'global'");
	if (log_open) {
		ok(wait_for_log_match(log, "\\[WARNING\\] pgsql-init_connect is ignored"),
		   "v3.0: loading a non-empty pgsql-init_connect logs a warning");
	} else {
		skip(1, "cannot open ProxySQL log at %s", log_path.c_str());
	}

	PGConnPtr c = ic_connect_client(cl);
	const IcResult r = ic_query(c.get(), IC_MARKER);
	ok(!r.timed_out && r.ok, "v3.0: query is not blocked by init_connect");
	ok(r.value.empty(), "v3.0: init_connect is not applied (got '%s')", r.value.c_str());
}

int main(int, char**) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}
	PGConnPtr admin_conn = ic_connect_admin(cl);
	PGconn* admin = admin_conn.get();
	if (PQstatus(admin) != CONNECTION_OK) return exit_status();

	const bool v31 = ic_is_v31(admin);
	plan(2 * kPerMode + kStableCases);

	const std::string orig_ic = ic_admin_value(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-init_connect'");

	if (!v31) {
		skip(2 * kPerMode, "init_connect needs ProxySQL v3.1+");
		run_stable(admin);
	} else {
		skip(kStableCases, "v3.0 only");
		const std::string orig_native = ic_admin_value(admin,
			"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
		for (bool native : {true, false}) {
			ic_admin(admin, std::string("UPDATE global_variables SET variable_value='") +
				(native ? "true" : "false") + "' WHERE variable_name='pgsql-use_native_backend_protocol'");
			ic_admin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
			run_mode(admin, native);
		}
		ic_admin(admin, "UPDATE global_variables SET variable_value=" + ic_literal(orig_native) +
			" WHERE variable_name='pgsql-use_native_backend_protocol'");
	}

	ic_set_global(admin, orig_ic);
	return exit_status();
}
