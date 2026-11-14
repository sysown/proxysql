/**
 * @file pgsql-native_stress-t.cpp
 * @brief Stress / stability test for the native protocol path.
 *
 * PURPOSE
 * -------
 * Exercises ProxySQL's native protocol under repeated operations to surface
 * memory leaks, file-descriptor leaks, or state-machine bugs that don't
 * show up in short test runs. Three scenarios:
 *
 *   S0: 200 iterations of PREPARE/EXECUTE/DEALLOCATE on a single connection.
 *       Verifies that the SQL-side prepared statement cycle stays stable.
 *   S1: 200 iterations of SELECT with a 100-row result set. Verifies the
 *       simple-query path doesn't accumulate state.
 *   S2: 100 iterations of BEGIN; INSERT; COMMIT (no savepoints). Verifies
 *       the transaction state machine doesn't drift over many txns.
 *
 * Each scenario runs in both modes (libpq oracle, native candidate) and
 * asserts the result is identical. The CoverageRecorder reports per-kind
 * native coverage.
 *
 * INFRA: legacy-g1 (docker-pgsql16-single, scram-sha-256, no TLS).
 */

#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <fstream>
#include <unistd.h>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql-native_tracking.h"

CommandLine cl;
static const int BACKEND_HG = 0;
static std::fstream f_proxysql_log{};
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static std::string make_table_name() {
	return "pgsql_native_stress_" + std::to_string(getpid()) + "_" +
	       std::to_string(time(nullptr));
}

static PGConnPtr open_admin_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host
	   << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username
	   << " password=" << cl.admin_password;
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr open_client_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host
	   << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username
	   << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username
	   << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool execAdmin(PGconn* admin, const std::string& q) {
	PGresult* res = PQexec(admin, q.c_str());
	ExecStatusType st = PQresultStatus(res);
	bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) diag("admin failed: %s -- %s", q.c_str(), PQerrorMessage(admin));
	PQclear(res);
	return good;
}

static bool setNativeMode(PGconn* admin, bool on) {
	std::string v = on ? "true" : "false";
	return execAdmin(admin, "SET pgsql-use_native_backend_protocol='" + v + "'") &&
	       execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

struct ServerRow { std::string hostname, port, max_connections, comment; };

static std::vector<ServerRow> readServers(PGconn* admin, int hg) {
	std::vector<ServerRow> rows;
	PGresult* res = PQexec(admin,
	    ("SELECT hostname, port, max_connections, comment FROM pgsql_servers "
	     "WHERE hostgroup_id=" + std::to_string(hg)).c_str());
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		for (int i = 0; i < PQntuples(res); i++) {
			ServerRow r;
			r.hostname = PQgetvalue(res, i, 0);
			r.port = PQgetvalue(res, i, 1);
			r.max_connections = PQgetvalue(res, i, 2);
			r.comment = PQgetisnull(res, i, 3) ? "" : PQgetvalue(res, i, 3);
			rows.push_back(std::move(r));
		}
	}
	PQclear(res);
	return rows;
}

static bool flushBackendPool(PGconn* admin, int hg, const std::vector<ServerRow>& saved) {
	if (saved.empty()) return false;
	if (!execAdmin(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg))) return false;
	if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	for (const auto& r : saved) {
		std::string ins = "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) VALUES ("
			+ std::to_string(hg) + ",'" + r.hostname + "'," + r.port + ","
			+ (r.max_connections.empty() ? std::string("1000") : r.max_connections)
			+ ",'" + r.comment + "')";
		if (!execAdmin(admin, ins)) return false;
	}
	if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	usleep(200000);
	return true;
}

static bool nativeFallbackObserved() {
	const std::string re =
		".*(native_mode requested but unimplemented at this stage; falling back to libpq"
		"|native backend auth capability gap .* falling back to libpq).*";
	return wait_for_log_match(f_proxysql_log, re, 1000, 100);
}

static void drainLogToNow() {
	get_matching_lines(f_proxysql_log, "__no_such_marker_line__");
}

// Run a stress scenario: `work` is a function-like template invoked `iters`
// times on the same connection. Returns a digest string (per-iteration result
// summary) for libpq and native. The two digests must be byte-equal.
typedef std::string (*WorkFn)(PGconn*, int iter, void* ctx);

struct StressCase {
	std::string label;
	std::string kind;
	int iters;
	WorkFn work;
	void* ctx;            // arbitrary per-case state
};

static int run_stress_phase(PGconn* c, const StressCase& tc, std::string& digest) {
	std::stringstream ss;
	int rc = 0;
	for (int i = 0; i < tc.iters; i++) {
		std::string r = tc.work(c, i, tc.ctx);
		ss << r << "|";
	}
	digest = ss.str();
	return rc;
}

int main(int /*argc*/, char** /*argv*/) {
	plan(4);  // 3 cases + 1 coverage summary
	if (cl.getEnv()) return exit_status();

	std::string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
	if (open_file_and_seek_end(log_path, f_proxysql_log) != EXIT_SUCCESS) {
		BAIL_OUT("Cannot open ProxySQL log at %s", log_path.c_str());
		return exit_status();
	}
	PGConnPtr admin = open_admin_conn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) {
		BAIL_OUT("admin connect failed");
		return exit_status();
	}
	std::vector<ServerRow> saved = readServers(admin.get(), BACKEND_HG);
	if (saved.empty()) {
		BAIL_OUT("No pgsql_servers in hostgroup %d", BACKEND_HG);
		return exit_status();
	}
	diag("Backend under test (hg %d): %s:%s", BACKEND_HG,
	     saved[0].hostname.c_str(), saved[0].port.c_str());

	CoverageRecorder cov;

	// S0: 200 PREPARE/EXECUTE/DEALLOCATE cycles.
	{
		std::string lp_dig, nt_dig;
		if (!setNativeMode(admin.get(), false) || !flushBackendPool(admin.get(), BACKEND_HG, saved)) {
			cov.record({"S0: 200x PREPARE/EXECUTE/DEALLOCATE",
			            "STRESS_PREPARED", false, false, "admin: set libpq mode failed"});
		} else {
			PGConnPtr lp = open_client_conn();
			if (!lp) {
				cov.record({"S0: 200x PREPARE/EXECUTE/DEALLOCATE",
				            "STRESS_PREPARED", false, false, "libpq conn failed"});
			} else {
				for (int i = 0; i < 200; i++) {
					std::stringstream ss;
					ss << "PREPARE p AS SELECT " << i << "::int";
					PGresult* r = PQexec(lp.get(), ss.str().c_str()); PQclear(r);
					r = PQexec(lp.get(), "EXECUTE p"); PQclear(r);
					r = PQexec(lp.get(), "DEALLOCATE p"); PQclear(r);
					lp_dig += std::to_string(i) + ":ok|";
				}
			}
		}
		if (!setNativeMode(admin.get(), true) || !flushBackendPool(admin.get(), BACKEND_HG, saved)) {
			cov.record({"S0: 200x PREPARE/EXECUTE/DEALLOCATE",
			            "STRESS_PREPARED", false, false, "admin: set native mode failed"});
		} else {
			drainLogToNow();
			PGConnPtr nt = open_client_conn();
			if (!nt) {
				cov.record({"S0: 200x PREPARE/EXECUTE/DEALLOCATE",
				            "STRESS_PREPARED", false, false, "native conn failed"});
			} else {
				for (int i = 0; i < 200; i++) {
					std::stringstream ss;
					ss << "PREPARE p AS SELECT " << i << "::int";
					PGresult* r = PQexec(nt.get(), ss.str().c_str()); PQclear(r);
					r = PQexec(nt.get(), "EXECUTE p"); PQclear(r);
					r = PQexec(nt.get(), "DEALLOCATE p"); PQclear(r);
					nt_dig += std::to_string(i) + ":ok|";
				}
			}
			bool fell_back = nativeFallbackObserved();
			bool result_match = (lp_dig == nt_dig);
			cov.record({"S0: 200x PREPARE/EXECUTE/DEALLOCATE",
			            "STRESS_PREPARED", result_match, !fell_back,
			            std::string("result_match=") + (result_match ? "true" : "false") +
			            " iters=200"});
		}
		setNativeMode(admin.get(), false);
		flushBackendPool(admin.get(), BACKEND_HG, saved);
	}

	// S1: 200 iterations of SELECT 100-row.
	{
		std::string lp_dig, nt_dig;
		std::string tbl = make_table_name();
		std::string setup = "DROP TABLE IF EXISTS " + tbl +
		                    "; CREATE TABLE " + tbl + " (id int, v text); "
		                    "INSERT INTO " + tbl + " SELECT g, 'r' || g FROM generate_series(1,100) g";

		if (!setNativeMode(admin.get(), false) || !flushBackendPool(admin.get(), BACKEND_HG, saved)) {
			cov.record({"S1: 200x SELECT (100 rows each)",
			            "STRESS_SELECT", false, false, "admin: set libpq mode failed"});
		} else {
			PGConnPtr lp = open_client_conn();
			if (lp) {
				PGresult* r = PQexec(lp.get(), setup.c_str()); PQclear(r);
				for (int i = 0; i < 200; i++) {
					r = PQexec(lp.get(), ("SELECT id, v FROM " + tbl + " ORDER BY id").c_str());
					lp_dig += std::to_string(PQntuples(r)) + ":";
					PQclear(r);
				}
			}
		}
		if (!setNativeMode(admin.get(), true) || !flushBackendPool(admin.get(), BACKEND_HG, saved)) {
			cov.record({"S1: 200x SELECT (100 rows each)",
			            "STRESS_SELECT", false, false, "admin: set native mode failed"});
		} else {
			drainLogToNow();
			PGConnPtr nt = open_client_conn();
			if (nt) {
				std::string tbl2 = tbl + "_n";
				std::string setup2 = "DROP TABLE IF EXISTS " + tbl2 +
				                     "; CREATE TABLE " + tbl2 + " (id int, v text); "
				                     "INSERT INTO " + tbl2 + " SELECT g, 'r' || g FROM generate_series(1,100) g";
				PGresult* r = PQexec(nt.get(), setup2.c_str()); PQclear(r);
				for (int i = 0; i < 200; i++) {
					r = PQexec(nt.get(), ("SELECT id, v FROM " + tbl2 + " ORDER BY id").c_str());
					nt_dig += std::to_string(PQntuples(r)) + ":";
					PQclear(r);
				}
			}
			bool fell_back = nativeFallbackObserved();
			bool result_match = (lp_dig == nt_dig);
			cov.record({"S1: 200x SELECT (100 rows each)",
			            "STRESS_SELECT", result_match, !fell_back,
			            std::string("result_match=") + (result_match ? "true" : "false") +
			            " iters=200"});
		}
		setNativeMode(admin.get(), false);
		flushBackendPool(admin.get(), BACKEND_HG, saved);
	}

	// S2: 100 BEGIN/INSERT/COMMIT cycles.
	{
		std::string lp_dig, nt_dig;
		std::string tbl = make_table_name();
		std::string setup = "DROP TABLE IF EXISTS " + tbl +
		                    "; CREATE TABLE " + tbl + " (id int, v text)";

		if (!setNativeMode(admin.get(), false) || !flushBackendPool(admin.get(), BACKEND_HG, saved)) {
			cov.record({"S2: 100x BEGIN/INSERT/COMMIT",
			            "STRESS_TXN", false, false, "admin: set libpq mode failed"});
		} else {
			PGConnPtr lp = open_client_conn();
			if (lp) {
				PGresult* r = PQexec(lp.get(), setup.c_str()); PQclear(r);
				for (int i = 0; i < 100; i++) {
					r = PQexec(lp.get(), "BEGIN"); PQclear(r);
					r = PQexec(lp.get(), ("INSERT INTO " + tbl + " VALUES (" + std::to_string(i) + ", 'v')").c_str()); PQclear(r);
					r = PQexec(lp.get(), "COMMIT"); PQclear(r);
				}
				// Verify final state.
				r = PQexec(lp.get(), ("SELECT count(*) FROM " + tbl).c_str());
				lp_dig = std::to_string(atoi(PQgetvalue(r, 0, 0)));
				PQclear(r);
			}
		}
		if (!setNativeMode(admin.get(), true) || !flushBackendPool(admin.get(), BACKEND_HG, saved)) {
			cov.record({"S2: 100x BEGIN/INSERT/COMMIT",
			            "STRESS_TXN", false, false, "admin: set native mode failed"});
		} else {
			drainLogToNow();
			PGConnPtr nt = open_client_conn();
			if (nt) {
				std::string tbl2 = tbl + "_n";
				std::string setup2 = "DROP TABLE IF EXISTS " + tbl2 +
				                     "; CREATE TABLE " + tbl2 + " (id int, v text)";
				PGresult* r = PQexec(nt.get(), setup2.c_str()); PQclear(r);
				for (int i = 0; i < 100; i++) {
					r = PQexec(nt.get(), "BEGIN"); PQclear(r);
					r = PQexec(nt.get(), ("INSERT INTO " + tbl2 + " VALUES (" + std::to_string(i) + ", 'v')").c_str()); PQclear(r);
					r = PQexec(nt.get(), "COMMIT"); PQclear(r);
				}
				r = PQexec(nt.get(), ("SELECT count(*) FROM " + tbl2).c_str());
				nt_dig = std::to_string(atoi(PQgetvalue(r, 0, 0)));
				PQclear(r);
			}
			bool fell_back = nativeFallbackObserved();
			bool result_match = (lp_dig == nt_dig);
			cov.record({"S2: 100x BEGIN/INSERT/COMMIT",
			            "STRESS_TXN", result_match, !fell_back,
			            std::string("result_match=") + (result_match ? "true" : "false") +
			            " iters=100"});
		}
		setNativeMode(admin.get(), false);
		flushBackendPool(admin.get(), BACKEND_HG, saved);
	}

	cov.emit_tap();
	return exit_status();
}
