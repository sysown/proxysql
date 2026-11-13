/**
 * @file pgsql-reg_test_6628_copy_to_fairness-t.cpp
 * @brief Regression #6628: a COPY TO STDOUT over a plain backend connection must not hold its
 *        worker thread.
 *
 * In fast forward, the worker read an unencrypted backend socket in a loop. After each
 * read it asked poll() whether more data was waiting, and read again if so. PostgreSQL can
 * refill the socket faster than the worker cuts it into messages, so a large COPY TO kept
 * the worker in that loop. The client got nothing, the other sessions on that thread got
 * no answer, and the watchdog could abort ProxySQL. The socket is now read once per poll
 * pass, as with a TLS backend.
 *
 * The test streams a 1 GB COPY (SELECT ...) TO over a plain backend leg while probe sessions run
 * SELECT 1 and time it, with libpq and with the native protocol (where the build has it). With the
 * native protocol it also streams a 300 MB COPY table TO: that form has no FROM, so it does not go
 * through fast forward but through the native drive, which must not hold the thread either. It checks:
 * - the first rows arrive quickly;
 * - the probes keep getting answers;
 * - every row arrives.
 *
 * Probes are not pinned to the streaming session's thread: with idle threads an idle
 * session can resume on another worker. There are more probes than worker threads, so
 * their queries keep landing on the streaming session's thread.
 */

#include <unistd.h>

#include <algorithm>
#include <atomic>
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

static const long long ROWS = 1000000;
static const long long TABLE_ROWS = 300000;
static const int ROW_WIDTH = 1000;
static const std::string TBL = "copyto_fair_" + std::to_string(getpid());
// Before the fix, the first rows came after the loop had read the whole stream.
static const long MAX_FIRST_DATA_MS = 2000;
// A probe on the streaming session's thread waited for the whole stream before the fix.
static const long MAX_PROBE_MS = 1000;
static const int PROBES = 8;

static PGConnPtr open_admin_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr open_client_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
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

static bool execSQL(PGconn* c, const std::string& q) {
	PGresult* res = PQexec(c, q.c_str());
	const bool good = (PQresultStatus(res) == PGRES_COMMAND_OK || PQresultStatus(res) == PGRES_TUPLES_OK);
	if (!good) diag("query failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(res);
	return good;
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

// Streams one COPY TO while probe sessions time SELECT 1. 6 checks.
static void stream_case(const std::string& what, const std::string& sql, long long rows_expected) {
	auto streamer = open_client_conn();
	if (PQstatus(streamer.get()) != CONNECTION_OK)
		BAIL_OUT("client connection failed: %s", PQerrorMessage(streamer.get()));
	std::vector<PGConnPtr> probes;
	for (int i = 0; i < PROBES; i++) {
		probes.push_back(open_client_conn());
		if (PQstatus(probes.back().get()) != CONNECTION_OK)
			BAIL_OUT("probe connection failed: %s", PQerrorMessage(probes.back().get()));
	}
	long long expected_bytes = 0;
	for (long long g = 1; g <= rows_expected; g++) expected_bytes += std::to_string(g).size() + 1 + ROW_WIDTH + 1;

	std::atomic<bool> streaming { true };
	long long rows = 0, bytes = 0;
	long first_data_ms = -1, total_ms = -1;
	bool copy_ok = false;
	std::thread reader([&]() {
		PGconn* c = streamer.get();
		const auto t0 = Clock::now();
		PGresult* res = PQexec(c, sql.c_str());
		const bool started = (PQresultStatus(res) == PGRES_COPY_OUT);
		if (!started) diag("COPY TO did not start: %s", PQerrorMessage(c));
		PQclear(res);
		if (started) {
			char* buf = nullptr;
			int n;
			while ((n = PQgetCopyData(c, &buf, 0)) > 0) {
				if (first_data_ms < 0) first_data_ms = ms_since(t0);
				rows++;
				bytes += n;
				PQfreemem(buf);
				buf = nullptr;
			}
			if (n == -2) diag("COPY TO failed mid-stream: %s", PQerrorMessage(c));
			res = PQgetResult(c);
			copy_ok = (n == -1 && res != nullptr && PQresultStatus(res) == PGRES_COMMAND_OK);
			if (!copy_ok) diag("COPY TO did not complete: %s", PQerrorMessage(c));
			PQclear(res);
			while ((res = PQgetResult(c)) != nullptr) PQclear(res);
		}
		total_ms = ms_since(t0);
		streaming = false;
	});

	long max_probe_ms = 0;
	int probe_queries = 0, probe_failures = 0;
	while (streaming) {
		for (auto& p : probes) {
			const auto t0 = Clock::now();
			if (queryOneValue(p.get(), "SELECT 1") != "1") probe_failures++;
			max_probe_ms = std::max(max_probe_ms, ms_since(t0));
			probe_queries++;
		}
		usleep(50000);
	}
	reader.join();
	diag("%s: received %lld rows, %lld bytes in %ld ms; first rows after %ld ms; %d probe queries, slowest %ld ms",
		what.c_str(), rows, bytes, total_ms, first_data_ms, probe_queries, max_probe_ms);

	ok(copy_ok, "%s: the COPY TO STDOUT over a plain backend completed", what.c_str());
	ok(rows == rows_expected && bytes == expected_bytes, "%s: every row arrived: %lld of %lld rows, %lld of %lld bytes",
		what.c_str(), rows, rows_expected, bytes, expected_bytes);
	ok(first_data_ms >= 0 && first_data_ms < MAX_FIRST_DATA_MS, "%s: the first rows arrived after %ld ms (limit %ld ms)",
		what.c_str(), first_data_ms, MAX_FIRST_DATA_MS);
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
	// 1 + per protocol: 1 + 6 per COPY form (two for native)
	plan(1 + (int)protocols.size() * 7 + (native_supported ? 6 : 0));
	const std::string saved_native = queryOneValue(admin.get(),
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");

	auto setup = open_client_conn();
	ok(PQstatus(setup.get()) == CONNECTION_OK && execSQL(setup.get(), "DROP TABLE IF EXISTS " + TBL)
		&& execSQL(setup.get(), "CREATE UNLOGGED TABLE " + TBL + " AS SELECT g, repeat('x', " + std::to_string(ROW_WIDTH)
			+ ") AS b FROM generate_series(1, " + std::to_string(TABLE_ROWS) + ") g"),
		"source table of %lld rows created", TABLE_ROWS);

	for (const std::string& protocol : protocols) {
		if (native_supported && !use_protocol(admin.get(), protocol == "native" ? "true" : "false"))
			BAIL_OUT("could not switch the backend protocol to %s", protocol.c_str());
		// The loop under test is the one for an unencrypted backend. The backend reports its own
		// view: the marker appears in this very query, so the row it matches is its own.
		auto c = open_client_conn();
		const std::string backend_ssl = queryOneValue(c.get(),
			"SELECT s.ssl FROM pg_stat_ssl s JOIN pg_stat_activity a ON s.pid = a.pid"
			" WHERE a.state = 'active' AND a.query LIKE '%copyto_fair_marker%' LIMIT 1");
		ok(backend_ssl == "f", "%s: the backend leg is not encrypted (pg_stat_ssl.ssl=%s)", protocol.c_str(), backend_ssl.c_str());
		stream_case(protocol + ", COPY (SELECT ...) TO", "COPY (SELECT g, repeat('x', " + std::to_string(ROW_WIDTH)
			+ ") FROM generate_series(1, " + std::to_string(ROWS) + ") g) TO STDOUT", ROWS);
		// shortcut: not with libpq. There this form runs through PgSQL_Connection::handle_copy_out(), which,
		// like a large SELECT, handles up to 8 x pgsql-threshold_resultset_size per event and holds the thread
		// for seconds on a debug build. Add it once that budget is per pass.
		if (protocol == "native")
			stream_case(protocol + ", COPY table TO", "COPY " + TBL + " TO STDOUT", TABLE_ROWS);
	}

	if (native_supported && !saved_native.empty()) use_protocol(admin.get(), saved_native);
	execSQL(setup.get(), "DROP TABLE IF EXISTS " + TBL);

	return exit_status();
}
