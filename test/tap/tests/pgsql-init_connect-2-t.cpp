/**
 * @file pgsql-init_connect-2-t.cpp
 * @brief 'pgsql_hostgroup_attributes.init_connect': PostgreSQL port of mysql-init_connect-2-t.
 *
 * The hostgroup value overrides the global 'pgsql-init_connect'; an empty hostgroup value
 * falls back to the global one. The feature is v3.1+ (PROXYSQL31); the tier is read from
 * the server's 'admin-version'. Runs in the server's default backend mode: the hostgroup
 * lookup does not depend on it, and pgsql-init_connect-1-t covers both modes.
 *
 * Every hostgroup in pgsql_servers gets the value, so the test does not depend on routing.
 *
 * State touched (restored on exit): 'pgsql-init_connect', and the init_connect of
 * pgsql_hostgroup_attributes rows for those hostgroups (rows the test adds are removed).
 */

#include "pgsql_init_connect_common.h"

#include <string>
#include <utility>
#include <vector>

CommandLine cl;

static constexpr int kV31Cases = 10;
static constexpr int kStableCases = 2;    // v3.0 cases

static std::vector<std::pair<std::string, std::string>> existing_rows;   // hostgroup_id, init_connect
static std::vector<std::string> added_rows;                              // hostgroup_id

static std::vector<std::vector<std::string>> rows(PGconn* admin, const char* sql) {
	std::vector<std::vector<std::string>> out;
	PGresult* r = PQexec(admin, sql);
	if (PQresultStatus(r) == PGRES_TUPLES_OK) {
		for (int i = 0; i < PQntuples(r); i++) {
			std::vector<std::string> row;
			for (int j = 0; j < PQnfields(r); j++) row.push_back(PQgetvalue(r, i, j));
			out.push_back(row);
		}
	} else {
		diag("admin query failed: %s -- %s", sql, PQresultErrorMessage(r));
	}
	PQclear(r);
	return out;
}

static void snapshot_hostgroups(PGconn* admin) {
	for (const auto& row : rows(admin, "SELECT hostgroup_id, init_connect FROM pgsql_hostgroup_attributes"))
		existing_rows.emplace_back(row[0], row[1]);
	for (const auto& row : rows(admin, "SELECT DISTINCT hostgroup_id FROM pgsql_servers")) {
		bool exists = false;
		for (const auto& e : existing_rows) exists = exists || e.first == row[0];
		if (!exists) added_rows.push_back(row[0]);
	}
}

static bool ic_set_hostgroups(PGconn* admin, const std::string& value) {
	for (const auto& hg : added_rows)
		ic_admin(admin, "INSERT OR IGNORE INTO pgsql_hostgroup_attributes(hostgroup_id) VALUES(" + hg + ")");
	return ic_admin(admin, "UPDATE pgsql_hostgroup_attributes SET init_connect=" + ic_literal(value) +
		" WHERE hostgroup_id IN (SELECT DISTINCT hostgroup_id FROM pgsql_servers)") &&
		ic_admin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
}

static void restore_hostgroups(PGconn* admin) {
	for (const auto& hg : added_rows)
		ic_admin(admin, "DELETE FROM pgsql_hostgroup_attributes WHERE hostgroup_id=" + hg);
	for (const auto& e : existing_rows)
		ic_admin(admin, "UPDATE pgsql_hostgroup_attributes SET init_connect=" + ic_literal(e.second) +
			" WHERE hostgroup_id=" + e.first);
	ic_admin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
}

// A fresh client per case: a timed-out query leaves its connection busy.
static void run_v31(PGconn* admin) {
	ic_set_hostgroups(admin, "SET ic.marker TO 'hg'");
	PGConnPtr c1 = ic_connect_client(cl);
	IcResult r = ic_query(c1.get(), IC_MARKER);
	ok(!r.timed_out && r.ok && r.value == "hg", "hostgroup init_connect applied (got '%s')", r.value.c_str());

	ic_set_hostgroups(admin, "SELECT 1");
	PGConnPtr c2 = ic_connect_client(cl);
	r = ic_query(c2.get(), IC_MARKER);
	ok(!r.timed_out && !r.ok, "SELECT 1 hostgroup init_connect fails the query");
	ic_set_hostgroups(admin, "SET ic.marker TO 'hg'");
	r = ic_query(c2.get(), IC_MARKER);
	ok(!r.timed_out && !r.ok && PQstatus(c2.get()) == CONNECTION_BAD, "and closes the session (PMC-10003)");

	ic_set_hostgroups(admin, "SELECT pg_sleep(3)");
	PGConnPtr c3 = ic_connect_client(cl);
	r = ic_query(c3.get(), IC_MARKER);
	ok(!r.timed_out && !r.ok, "pg_sleep hostgroup init_connect fails the query");
	ok(r.elapsed_ms > 2900 && r.elapsed_ms < 5000, "after ~3 s (got %llu ms)", r.elapsed_ms);

	ic_set_hostgroups(admin, "Syntax Error");
	PGConnPtr c4 = ic_connect_client(cl);
	r = ic_query(c4.get(), IC_MARKER);
	ok(!r.timed_out && r.sqlstate == "42601", "syntax error reaches the client (sqlstate '%s')", r.sqlstate.c_str());
	ic_set_hostgroups(admin, "SET ic.marker TO 'hg'");
	r = ic_query(c4.get(), IC_MARKER);
	ok(!r.timed_out && r.ok && r.value == "hg",
	   "same session works once init_connect is valid (got '%s')", r.value.c_str());

	ic_set_global(admin, "SET ic.marker TO 'g'");
	PGConnPtr c5 = ic_connect_client(cl);
	r = ic_query(c5.get(), IC_MARKER);
	ok(!r.timed_out && r.ok && r.value == "hg", "hostgroup overrides global (got '%s')", r.value.c_str());

	ic_set_hostgroups(admin, "");
	r = ic_query(c5.get(), IC_MARKER);
	ok(!r.timed_out && r.ok && r.value == "g", "empty hostgroup value falls back to global (got '%s')", r.value.c_str());

	ic_set_global(admin, "");
	ic_set_hostgroups(admin, "SET ic.marker TO 'hg'");
	r = ic_query(c5.get(), IC_MARKER);
	ok(!r.timed_out && r.ok && r.value == "hg", "back to a valid hostgroup value (got '%s')", r.value.c_str());
}

// v3.0 ignores init_connect (with a warning) instead of stalling every new connection.
static void run_stable(PGconn* admin) {
	ic_set_hostgroups(admin, "SET ic.marker TO 'hg'");
	PGConnPtr c = ic_connect_client(cl);
	const IcResult r = ic_query(c.get(), IC_MARKER);
	ok(!r.timed_out && r.ok, "v3.0: query is not blocked by hostgroup init_connect");
	ok(r.value.empty(), "v3.0: hostgroup init_connect is not applied (got '%s')", r.value.c_str());
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
	plan(kV31Cases + kStableCases);

	const std::string orig_ic = ic_admin_value(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-init_connect'");
	snapshot_hostgroups(admin);
	ic_set_global(admin, "");

	if (!v31) {
		skip(kV31Cases, "init_connect needs ProxySQL v3.1+");
		run_stable(admin);
	} else {
		skip(kStableCases, "v3.0 only");
		run_v31(admin);
	}

	restore_hostgroups(admin);
	ic_set_global(admin, orig_ic);
	return exit_status();
}
