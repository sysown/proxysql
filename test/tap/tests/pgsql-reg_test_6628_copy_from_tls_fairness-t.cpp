/**
 * @file pgsql-reg_test_6628_copy_from_tls_fairness-t.cpp
 * @brief Regression #6628: a client streaming COPY FROM STDIN over TLS must not hold its worker
 *        thread.
 *
 * ProxySQL decrypts client TLS from a memory BIO. It used to read the socket again after
 * every record it decrypted, and kept going for as long as the client kept sending. One
 * COPY over TLS then held its worker thread for the whole stream: the other sessions on
 * that thread got no answer, and the watchdog could abort ProxySQL. The socket is now read
 * once per poll pass, and only what is already buffered is decrypted after that.
 *
 * The test streams a COPY over TLS for a few seconds: one row per CopyData message, as
 * psycopg2 sends them, flushed in TLS records under 8 KB. Meanwhile, probe sessions run
 * SELECT 1 and time it. It checks that the probes keep getting answers, and that every row
 * reached the backend. Probes are not pinned to the streaming session's thread: with idle
 * threads an idle session can resume on another worker. There are more probes than worker
 * threads, so their queries keep landing on the streaming session's thread.
 *
 * A TLS client can also vanish right after a complete record, with no close_notify. ProxySQL then
 * read an EOF with nothing left to decrypt and looked at a stale errno: on EAGAIN it never closed the
 * session, and the worker thread spun at 100 % CPU. The test drops the socket of a TLS client in the
 * middle of a COPY and of an idle TLS client, and checks that both sessions go away and ProxySQL stays
 * idle. The errno left by an earlier call cannot be arranged from outside, so these cases cover the EOF
 * path but can pass without that fix. The COPY case also fails when the torn-down connection is pooled.
 * Everything runs with libpq and with the native protocol (where the build has it).
 */

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <functional>
#include <chrono>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql_native_tier.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
using Clock = std::chrono::steady_clock;

static const std::string TBL = "copy_tls_fair_" + std::to_string(getpid());
static const std::string SEQ = TBL + "_rows";
static const std::string FN = TBL + "_count";

static const int STREAM_SECONDS = 8;
// The writer blocks in libpq: past this, its connection is cut so the test fails instead of hanging.
static const int WRITER_MAX_S = STREAM_SECONDS + 60;
static const char ROW[] = "a\tb\tc\n";
// A one-row CopyData message is 11 bytes: 680 of them make one 7480-byte TLS record per flush.
static const int ROWS_PER_FLUSH = 680;
// Bounds what ProxySQL may still hold for the backend when the client stops sending.
static const long long MAX_ROWS = 4000000;
// A probe on the streaming session's thread waited for the whole stream before the fix.
static const long MAX_PROBE_MS = 1000;
static const int PROBES = 8;
// A session whose client vanished is gone within this.
static const int GONE_S = 5;
static const double MAX_IDLE_CPU = 30;

static PGConnPtr open_admin_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password
	   << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr open_client_conn(const char* sslmode) {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username << " sslmode=" << sslmode;
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool execSQL(PGconn* c, const std::string& q) {
	PGresult* res = PQexec(c, q.c_str());
	ExecStatusType st = PQresultStatus(res);
	bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) diag("query failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(res);
	return good;
}

static std::string queryOneValue(PGconn* c, const std::string& q) {
	PGresult* res = PQexec(c, q.c_str());
	std::string out;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0))
		out = PQgetvalue(res, 0, 0);
	PQclear(res);
	return out;
}

static long ms_since(Clock::time_point t) {
	return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t).count();
}

// Dropping the servers drops their pooled connections, so the next ones use the protocol set here. The
// harness loads the config from disk before every test, so the disk copy is the one to put back.
static bool use_protocol(PGconn* admin, const std::string& native) {
	const bool good = execSQL(admin, "SET pgsql-use_native_backend_protocol='" + native + "'")
		&& execSQL(admin, "LOAD PGSQL VARIABLES TO RUNTIME") && execSQL(admin, "DELETE FROM pgsql_servers")
		&& execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME") && execSQL(admin, "LOAD PGSQL SERVERS FROM DISK")
		&& execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	usleep(300000);
	return good;
}

static bool wait_for(const std::function<bool()>& cond, int seconds) {
	const auto stop = Clock::now() + std::chrono::seconds(seconds);
	while (Clock::now() < stop) {
		if (cond()) return true;
		usleep(100000);
	}
	return cond();
}

// ProxySQL's sessions for the client connection whose local port is that of fd.
static std::string sessions_of(PGconn* admin, int fd) {
	sockaddr_in a {};
	socklen_t len = sizeof(a);
	if (getsockname(fd, (sockaddr*)&a, &len) != 0) return "unknown port";
	return queryOneValue(admin, "SELECT count(*) FROM stats_pgsql_processlist WHERE cli_port=" + std::to_string(ntohs(a.sin_port)));
}

// Drops the socket under a TLS client after a complete record, with no close_notify. 3 checks.
static void vanish_case(const std::string& what, PGconn* admin, PGconn* setup) {
	// In the middle of a COPY: the backend must be let go of too.
	std::string pid = "not found";
	auto c = open_client_conn("require");
	PGresult* res = PQexec(c.get(), ("COPY " + TBL + " FROM STDIN").c_str());
	if (PQresultStatus(res) == PGRES_COPY_IN) {
		for (int i = 0; i < ROWS_PER_FLUSH; i++) PQputCopyData(c.get(), ROW, (int)sizeof(ROW) - 1);
		PQflush(c.get());
		usleep(300000);
		pid = queryOneValue(setup, "SELECT pid FROM pg_stat_activity WHERE query LIKE 'COPY " + TBL + "%' AND state='active' LIMIT 1");
		shutdown(PQsocket(c.get()), SHUT_RDWR);
	} else {
		diag("%s: COPY did not start: %s", what.c_str(), PQerrorMessage(c.get()));
	}
	PQclear(res);
	const bool copy_gone = !pid.empty() && pid != "not found" && wait_for([&]() {
		return queryOneValue(setup, "SELECT count(*) FROM pg_stat_activity WHERE pid=" + pid) == "0"; }, GONE_S);
	c.reset();
	ok(copy_gone, "%s: a TLS client that vanishes in the middle of a COPY: its backend is let go within %d s"
		" (backend pid %s)", what.c_str(), GONE_S, pid.c_str());

	// Idle, right after a query.
	auto i = open_client_conn("require");
	const bool answered = queryOneValue(i.get(), "SELECT 1") == "1";
	const int fd = PQsocket(i.get());
	const std::string before = sessions_of(admin, fd);
	shutdown(fd, SHUT_RDWR);
	std::string left;
	const bool idle_gone = answered && before == "1" && wait_for([&]() { left = sessions_of(admin, fd); return left == "0"; }, GONE_S);
	i.reset();
	ok(idle_gone, "%s: an idle TLS client that vanishes: its session goes within %d s (sessions for its port: %s before, %s after)",
		what.c_str(), GONE_S, before.c_str(), left.c_str());

	double cpu = -1;
	if (get_proxysql_cpu_usage(cl, cpu, 5) != EXIT_SUCCESS) cpu = -1;
	ok(cpu >= 0 && cpu < MAX_IDLE_CPU, "%s: ProxySQL stays idle afterwards (CPU %.1f%%, below %.0f%%)",
		what.c_str(), cpu, MAX_IDLE_CPU);
}

// Streams a COPY over TLS while probe sessions time SELECT 1. 6 checks.
static void stream_case(const std::string& what, PGconn* setup) {
	execSQL(setup, "SELECT setval('" + SEQ + "', 1, false)");
	auto streamer = open_client_conn("require");
	if (PQstatus(streamer.get()) != CONNECTION_OK)
		BAIL_OUT("TLS client connection failed: %s", PQerrorMessage(streamer.get()));
	ok(PQsslInUse(streamer.get()) == 1, "%s: the streaming connection uses TLS towards ProxySQL", what.c_str());

	std::vector<PGConnPtr> probes;
	for (int i = 0; i < PROBES; i++) {
		probes.push_back(open_client_conn("disable"));
		if (PQstatus(probes.back().get()) != CONNECTION_OK)
			BAIL_OUT("probe connection failed: %s", PQerrorMessage(probes.back().get()));
	}

	PGresult* res = PQexec(streamer.get(), ("COPY " + TBL + " FROM STDIN").c_str());
	const bool copy_started = (PQresultStatus(res) == PGRES_COPY_IN);
	if (!copy_started) diag("COPY did not start: %s", PQerrorMessage(streamer.get()));
	PQclear(res);
	if (!copy_started) BAIL_OUT("COPY FROM STDIN did not start");


	std::atomic<bool> streaming { true };
	long long rows_sent = 0;
	bool copy_ok = false;
	long end_to_result_ms = -1;
	const int streamer_fd = PQsocket(streamer.get());
	std::thread writer([&]() {
		PGconn* c = streamer.get();
		const auto stop = Clock::now() + std::chrono::seconds(STREAM_SECONDS);
		bool sent_all = true;
		while (sent_all && Clock::now() < stop && rows_sent < MAX_ROWS) {
			for (int i = 0; i < ROWS_PER_FLUSH && sent_all; i++)
				sent_all = (PQputCopyData(c, ROW, (int)sizeof(ROW) - 1) == 1);
			if (sent_all) sent_all = (PQflush(c) == 0);
			if (sent_all) rows_sent += ROWS_PER_FLUSH;
			else diag("sending COPY data failed: %s", PQerrorMessage(c));
		}
		const auto t_end = Clock::now();
		if (sent_all && PQputCopyEnd(c, nullptr) == 1) {
			PGresult* r = PQgetResult(c);
			copy_ok = (r != nullptr && PQresultStatus(r) == PGRES_COMMAND_OK);
			if (!copy_ok) diag("COPY did not complete: %s", PQerrorMessage(c));
			PQclear(r);
			while ((r = PQgetResult(c)) != nullptr) PQclear(r);
		}
		end_to_result_ms = ms_since(t_end);
		streaming = false;
	});

	long max_probe_ms = 0;
	int probe_queries = 0, probe_failures = 0;
	const auto writer_deadline = Clock::now() + std::chrono::seconds(WRITER_MAX_S);
	bool writer_cut = false;
	while (streaming) {
		if (!writer_cut && Clock::now() > writer_deadline) {
			diag("%s: the writer is still blocked after %d s; cutting its connection", what.c_str(), WRITER_MAX_S);
			shutdown(streamer_fd, SHUT_RDWR);
			writer_cut = true;
		}
		for (auto& p : probes) {
			const auto t0 = Clock::now();
			if (queryOneValue(p.get(), "SELECT 1") != "1") probe_failures++;
			max_probe_ms = std::max(max_probe_ms, ms_since(t0));
			probe_queries++;
		}
		usleep(50000);
	}
	writer.join();
	diag("streamed %lld rows in %d s; result %ld ms after CopyDone; %d probe queries, slowest %ld ms",
		rows_sent, STREAM_SECONDS, end_to_result_ms, probe_queries, max_probe_ms);

	ok(copy_ok, "%s: COPY FROM STDIN over TLS completed", what.c_str());
	const std::string counted = queryOneValue(setup,
		"SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM " + SEQ);
	ok(counted == std::to_string(rows_sent), "%s: the backend received every row: sent %lld, counted %s",
		what.c_str(), rows_sent, counted.c_str());
	ok(probe_queries > 0 && probe_failures == 0, "%s: probe sessions got an answer to all %d queries (%d failed)",
		what.c_str(), probe_queries, probe_failures);
	ok(max_probe_ms < MAX_PROBE_MS, "%s: no probe query waited %ld ms or more during the stream (slowest %ld ms)",
		what.c_str(), MAX_PROBE_MS, max_probe_ms);
	ok(queryOneValue(streamer.get(), "SELECT 42") == "42", "%s: the streaming session still works after the COPY", what.c_str());

}

int main(int argc, char** argv) {
	if (cl.getEnv())
		return exit_status();

	auto admin = open_admin_conn();
	if (PQstatus(admin.get()) != CONNECTION_OK) {
		plan(1);
		ok(false, "ADMIN connection created: %s", PQerrorMessage(admin.get()));
		return exit_status();
	}
	const bool native_supported = pgsql_native_supported(admin.get());
	const std::vector<std::string> protocols = native_supported
		? std::vector<std::string> { "libpq", "native" } : std::vector<std::string> { "libpq" };
	// 1 + per protocol: 6 (stream) + 3 (vanish)
	plan(1 + (int)protocols.size() * 9);
	const std::string saved_native = queryOneValue(admin.get(),
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");

	// The sink keeps nothing: a trigger counts each row in a sequence and drops it.
	auto setup = open_client_conn("disable");
	if (PQstatus(setup.get()) != CONNECTION_OK)
		BAIL_OUT("setup connection failed: %s", PQerrorMessage(setup.get()));
	const bool setup_ok = execSQL(setup.get(), "DROP TABLE IF EXISTS " + TBL)
		&& execSQL(setup.get(), "DROP SEQUENCE IF EXISTS " + SEQ)
		&& execSQL(setup.get(), "CREATE TABLE " + TBL + " (a text, b text, c text)")
		&& execSQL(setup.get(), "CREATE SEQUENCE " + SEQ)
		&& execSQL(setup.get(), "CREATE OR REPLACE FUNCTION " + FN + "() RETURNS trigger LANGUAGE plpgsql"
			" AS 'BEGIN PERFORM nextval(''" + SEQ + "''); RETURN NULL; END'")
		&& execSQL(setup.get(), "CREATE TRIGGER " + FN + " BEFORE INSERT ON " + TBL
			+ " FOR EACH ROW EXECUTE FUNCTION " + FN + "()");
	ok(setup_ok, "COPY sink created");
	if (!setup_ok) BAIL_OUT("could not create the COPY sink");

	for (const std::string& protocol : protocols) {
		if (native_supported && !use_protocol(admin.get(), protocol == "native" ? "true" : "false"))
			BAIL_OUT("could not switch the backend protocol to %s", protocol.c_str());
		stream_case(protocol, setup.get());
		vanish_case(protocol, admin.get(), setup.get());
	}

	if (native_supported && !saved_native.empty()) use_protocol(admin.get(), saved_native);
	execSQL(setup.get(), "DROP TABLE IF EXISTS " + TBL);
	execSQL(setup.get(), "DROP FUNCTION IF EXISTS " + FN + "()");
	execSQL(setup.get(), "DROP SEQUENCE IF EXISTS " + SEQ);

	return exit_status();
}
