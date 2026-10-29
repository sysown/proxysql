#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <utility>
#include <unistd.h>
#include "libpq-fe.h"
#include <mysql.h>          // admin interface is reached via the MySQL client
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static PGConnPtr mk() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static std::string scalar(PGconn* c, const char* q) {
	PGresult* r = PQexec(c, q);
	std::string v = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) ? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return v;
}

static MYSQL* admin_connect() {
	MYSQL* conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, cl.admin_host, cl.admin_username, cl.admin_password,
	                        NULL, cl.admin_port, NULL, 0)) {
		diag("admin connect failed: %s", mysql_error(conn));
		mysql_close(conn);
		return NULL;
	}
	return conn;
}

static bool admin_exec(MYSQL* a, const char* q) {
	if (mysql_query(a, q)) { diag("admin query failed: '%s' : %s", q, mysql_error(a)); return false; }
	MYSQL_RES* r = mysql_store_result(a);
	if (r) mysql_free_result(r);
	return true;
}

static std::string admin_scalar(MYSQL* a, const char* q) {
	std::string v;
	if (mysql_query(a, q)) { diag("admin query failed: '%s' : %s", q, mysql_error(a)); return v; }
	MYSQL_RES* r = mysql_store_result(a);
	if (r) {
		MYSQL_ROW row = mysql_fetch_row(r);
		if (row && row[0]) v = row[0];
		mysql_free_result(r);
	}
	return v;
}

// Fetch the first two columns of every row (used to snapshot per-hostgroup config).
static std::vector<std::pair<std::string, std::string>> admin_rows2(MYSQL* a, const char* q) {
	std::vector<std::pair<std::string, std::string>> out;
	if (mysql_query(a, q)) { diag("admin query failed: '%s' : %s", q, mysql_error(a)); return out; }
	MYSQL_RES* r = mysql_store_result(a);
	if (r) {
		MYSQL_ROW row;
		while ((row = mysql_fetch_row(r))) {
			out.emplace_back(row[0] ? row[0] : "", row[1] ? row[1] : "");
		}
		mysql_free_result(r);
	}
	return out;
}

int main(int argc, char** argv) {
	if (cl.getEnv()) return exit_status();
	plan(3);

	MYSQL* admin = admin_connect();
	if (!admin) { BAIL_OUT("cannot reach ProxySQL admin"); return exit_status(); }

	// ---------------------------------------------------------------------------
	// 1) Session-state isolation across a DETERMINISTICALLY reused backend.
	//
	// This block runs FIRST (before the connection storm) and caps the backend
	// pool to a single connection, so that connection B has no clean alternative
	// and is FORCED to reuse connection A's just-freed, session-dirtied backend.
	// That is what makes the isolation assertion a real test of ProxySQL's
	// backend session-reset path rather than a near-tautology:
	//   - ProxySQL's get_random_MyConn() PREFERS a clean/perfect-match backend
	//     over one that needs a session reset (lib/PgSQL_HostGroups_Manager.cpp).
	//     If a clean spare exists, B is handed it and the reset path never runs,
	//     so a real reset bug would go undetected.
	//   - Running the storm first would flood the free pool with clean backends;
	//     hence the storm runs AFTER this block, and we drain pre-existing idle
	//     backends to zero before starting.
	//   - With max_connections=1 and free_connections_pct=0 there is exactly one
	//     backend and zero clean spares, so B provably reuses A's dirtied backend
	//     (verified: after A closes, ConnFree=1 on the single hostgroup; B then
	//     reuses it). B seeing the default TimeZone proves the reset ran.
	//
	// TimeZone is used (not application_name): application_name is deliberately in
	// ProxySQL's ignore_vars (lib/PgSQL_Variables.cpp) and never round-trips, so
	// it cannot probe session state. TimeZone IS a tracked variable
	// (pgsql_tracked_variables[] in include/proxysql_structs.h) that is forwarded
	// to, and reset on, the backend. 'Antarctica/Troll' is a valid, distinctive,
	// non-default IANA zone (default is 'GMT').
	// ---------------------------------------------------------------------------

	// Snapshot originals so we can restore regardless of assertion outcome.
	// Snapshot max_connections PER-HOSTGROUP so the restore is correct regardless
	// of the infra seed: a blanket single-value restore would silently flatten
	// distinct per-hostgroup values and corrupt the shared CI infra for later
	// tests. free_connections_pct is a single global variable, so a scalar
	// snapshot/restore is correct for it.
	std::vector<std::pair<std::string, std::string>> orig_maxconn = admin_rows2(admin,
		"SELECT hostgroup_id, max_connections FROM pgsql_servers ORDER BY hostgroup_id");
	std::string orig_free_pct = admin_scalar(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-free_connections_pct'");
	if (orig_free_pct.empty()) orig_free_pct = "10"; // documented default

	// Cap the pool to a single backend and keep no clean spares.
	admin_exec(admin, "UPDATE pgsql_servers SET max_connections=1");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	admin_exec(admin, "SET pgsql-free_connections_pct=0");
	admin_exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");

	// Wait for the connection reaper to drain any pre-existing idle backends to 0,
	// so the only backend B can reach is the one A dirties below.
	bool drained = false;
	for (int i = 0; i < 100; ++i) { // up to ~10s
		std::string f = admin_scalar(admin, "SELECT IFNULL(SUM(ConnFree),0) FROM stats_pgsql_connection_pool");
		if (f == "0") { drained = true; break; }
		usleep(100 * 1000);
	}
	if (!drained) diag("WARNING: backend free connections did not drain to 0; reuse may be non-deterministic");

	{
		PGConnPtr a = mk();
		PQclear(PQexec(a.get(), "SET TimeZone = 'Antarctica/Troll'"));
		std::string a_val = scalar(a.get(), "SHOW TimeZone");
		ok(a_val == "Antarctica/Troll", "connection A sees its own SET TimeZone (got '%s')", a_val.c_str());

		a.reset(); // close A -> its single backend returns to the pool, session-dirtied

		PGConnPtr b = mk(); // cap=1 + no spares => B must reuse A's dirtied backend
		std::string b_val = scalar(b.get(), "SHOW TimeZone");
		ok(b_val != "Antarctica/Troll",
		   "connection B (forced to reuse A's backend) does NOT inherit A's session state (got '%s')", b_val.c_str());
	}

	// Restore pool config BEFORE the storm and before returning, so the infra is
	// left at its originals even if an assertion above failed. Restore EACH
	// hostgroup to its own snapshotted value (never a blanket single-value
	// UPDATE) so distinct per-hostgroup seeds are preserved.
	if (orig_maxconn.empty()) {
		// Snapshot failed for some reason: fall back to the infra default rather
		// than leaving the cap in place.
		admin_exec(admin, "UPDATE pgsql_servers SET max_connections=50");
	} else {
		for (const auto& row : orig_maxconn) {
			std::string q = "UPDATE pgsql_servers SET max_connections=" + row.second +
			                " WHERE hostgroup_id=" + row.first;
			admin_exec(admin, q.c_str());
		}
	}
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	admin_exec(admin, (std::string("SET pgsql-free_connections_pct=") + orig_free_pct).c_str());
	admin_exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	mysql_close(admin);

	// ---------------------------------------------------------------------------
	// 2) Connection storm (pool restored to normal): open many short-lived
	//    connections; none should error out (no pool leak/exhaustion). Count ALL
	//    failures rather than stopping at the first, for better diagnostics.
	// ---------------------------------------------------------------------------
	int failures = 0;
	for (int i = 0; i < 100; ++i) {
		PGConnPtr c = mk();
		if (!c || PQstatus(c.get()) != CONNECTION_OK) { failures++; continue; }
		if (scalar(c.get(), "SELECT 1") != "1") { failures++; }
	}
	ok(failures == 0, "100 sequential short connections all succeed (no pool leak/exhaustion); %d/100 failed", failures);

	return exit_status();
}
