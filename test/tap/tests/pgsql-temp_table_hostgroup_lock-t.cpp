/**
 * @file pgsql-temp_table_hostgroup_lock-t.cpp
 * @brief A CREATE TEMP TABLE must lock the session to the hostgroup it ran
 *        on, so the temp table cannot be left behind by a later reroute.
 *
 * @details
 *   A temporary table lives on the backend connection that created it:
 *   ProxySQL only disabled multiplexing for it, but did not lock the session
 *   to the hostgroup, so a query rule that routed a later statement
 *   elsewhere answered it from a different backend connection where the
 *   table does not exist ('relation ... does not exist'). The fix locks the
 *   session to the current hostgroup when the CREATE TEMP TABLE digest is
 *   seen, exactly like the other hostgroup locks: while
 *   pgsql-set_query_lock_on_hostgroup=1, a query routed to another
 *   hostgroup is refused with 'connection is locked to hostgroup'.
 *
 *   The fixture builds two dedicated hostgroups (18130, 18131) that both
 *   point at the first ONLINE backend with max_connections=1, so each pool
 *   owns exactly one backend connection, and two reserved negative-ID query
 *   rules (they sort ahead of every infra-installed rule) that route by a
 *   comment tag:
 *     rule A: comment tag "temp_table_hg_a" -> hostgroup 18130 (the CREATE lands here)
 *     rule B: comment tag "temp_table_hg_b" -> hostgroup 18131 (the rerouted read)
 *
 *   Note on the routing: match_pattern is evaluated against the raw query,
 *   which keeps the comment, while the CREATE TEMP TABLE detection works on
 *   the digest, where the comment is stripped -- the same statement is both
 *   routed by its tag and recognized as a temp table creation.
 *
 *   One frontend session, every statement over the Simple Query protocol:
 *     1. the session starts unlocked (locked_on_hostgroup == -1);
 *     2. the tagged CREATE TEMP TABLE is accepted (forwarded to PG);
 *     3. 'PROXYSQL INTERNAL SESSION' reports the lock: locked_on_hostgroup
 *        == 18130 (the core of the fix; -1 without it);
 *     4. the tagged read from the rule's hostgroup still sees the temp
 *        table (multiplexing was already disabled for it);
 *     5. the same read tagged for the other hostgroup is refused with
 *        SQLSTATE P0001 'connection is locked to hostgroup': without the
 *        fix the statement reached the other backend connection and
 *        PostgreSQL answered 'relation ... does not exist' (42P01).
 *
 *   State touched by this test (and restored on exit):
 *     - pgsql_servers rows for hostgroups 18130/18131
 *     - pgsql_query_rules rows with the reserved negative rule IDs
 *     - the pgsql-set_query_lock_on_hostgroup variable (pinned to 1)
 *     - the pgsql-free_connections_pct variable (pinned to 100, so the
 *       single pooled fixture connection survives between two queries)
 */

#include "libpq-fe.h"

#include "command_line.h"
#include "json.hpp"
#include "tap.h"
#include "utils.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

using nlohmann::json;
using std::string;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static constexpr int HG_A = 18130;
static constexpr int HG_B = 18131;
static constexpr const char* TAG_A = "temp_table_hg_a";
static constexpr const char* TAG_B = "temp_table_hg_b";

static constexpr const char* SNAP_SERVERS = "temp_table_lock_snap_servers";
static constexpr const char* SNAP_RULES = "temp_table_lock_snap_rules";

// Reserved negative rule IDs (see mysql-user-variable-tracking-t.cpp for the
// precedent): they sort ahead of every infra-installed rule, so the comment
// tag alone decides the routing, and they cannot collide with foreign rules.
static long rule_id_a = 0;
static long rule_id_b = 0;
// A temp table lives on the backend connection that created it: a per-run
// name keeps pooled connections from other runs out of the picture.
static string table_name;

static PGConnPtr connect_admin(CommandLine& cl) {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password
	   << " sslmode=disable";
	PGconn* c = PQconnectdb(ss.str().c_str());
	if (PQstatus(c) != CONNECTION_OK) {
		diag("admin connect failed: %s", PQerrorMessage(c));
	}
	return PGConnPtr(c, &PQfinish);
}

// NOTE: this is the *ProxySQL frontend* endpoint, not a backend server: every
// workload query must go through the query rules under test. The root user is
// used because the reader fixtures only provision 'postgres' on every node
// (see pgsql-backup_weight_threshold-t.cpp for the same reason).
static PGConnPtr connect_frontend(CommandLine& cl) {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_root_host << " port=" << cl.pgsql_root_port
	   << " user=" << cl.pgsql_root_username << " password=" << cl.pgsql_root_password
	   << " sslmode=disable";
	PGconn* c = PQconnectdb(ss.str().c_str());
	if (PQstatus(c) != CONNECTION_OK) {
		diag("ProxySQL frontend connect failed: %s", PQerrorMessage(c));
	}
	return PGConnPtr(c, &PQfinish);
}

static bool admin_exec(PGconn* admin, const char* sql) {
	PGresult* r = PQexec(admin, sql);
	const ExecStatusType st = PQresultStatus(r);
	const bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) {
		diag("admin query failed: '%s' : %s", sql, PQerrorMessage(admin));
	}
	PQclear(r);
	return good;
}

// Quote a value for the pgsql admin interface. The admin interface is backed
// by SQLite, so string literals must not use PostgreSQL-only syntax like
// E'...'; a plain literal with every single quote doubled is portable across
// both backends. Backslashes carry no special meaning here, which keeps the
// regex escaping in match_pattern intact.
static string sql_quote(const string& s) {
	string out = "'";
	for (const char c : s) {
		out += c;
		if (c == '\'') {
			out += '\'';
		}
	}
	out += "'";
	return out;
}

static int session_locked_hostgroup(PGconn* frontend) {
	static constexpr int UNKNOWN = -999;
	PGresult* r = PQexec(frontend, "PROXYSQL INTERNAL SESSION");
	if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) != 1) {
		diag("PROXYSQL INTERNAL SESSION failed: %s", PQresultErrorMessage(r));
		PQclear(r);
		return UNKNOWN;
	}
	int locked = UNKNOWN;
	try {
		const json j = json::parse(PQgetvalue(r, 0, 0));
		if (j.contains("locked_on_hostgroup") && j["locked_on_hostgroup"].is_number_integer()) {
			locked = j["locked_on_hostgroup"].get<int>();
		} else {
			diag("session_info has no locked_on_hostgroup integer");
		}
	} catch (const std::exception& e) {
		diag("cannot parse session_info JSON: %s", e.what());
	}
	PQclear(r);
	return locked;
}

struct Fixture {
	PGconn* admin = nullptr;
	bool armed = false;
	int failures = 0;
	// (name, value) pairs read before the pins are applied and written back on
	// restore.
	std::vector<std::pair<string, string>> saved_vars;

	Fixture() = default;
	Fixture(const Fixture&) = delete;
	Fixture& operator=(const Fixture&) = delete;

	// Every statement is attempted, failures are aggregated, and the restorer
	// stays armed so a retry (or the destructor) can try again.
	bool restore() {
		if (!armed) {
			return true;
		}
		if (!admin) {
			diag("cannot restore the fixture: no admin connection");
			failures++;
			return false;
		}
		std::vector<string> statements {
			"DELETE FROM pgsql_servers WHERE hostgroup_id IN (" + std::to_string(HG_A) + "," + std::to_string(HG_B) + ")",
			string("INSERT INTO pgsql_servers SELECT * FROM ") + SNAP_SERVERS,
			"DELETE FROM pgsql_query_rules WHERE rule_id IN (" + std::to_string(rule_id_a) + "," + std::to_string(rule_id_b) + ")",
			string("INSERT INTO pgsql_query_rules SELECT * FROM ") + SNAP_RULES,
			"LOAD PGSQL SERVERS TO RUNTIME",
			"LOAD PGSQL QUERY RULES TO RUNTIME"
		};
		for (const auto& v : saved_vars) {
			statements.push_back("SET " + v.first + "=" + v.second);
		}
		statements.push_back("LOAD PGSQL VARIABLES TO RUNTIME");
		bool all_ok = true;
		for (const string& sql : statements) {
			if (!admin_exec(admin, sql.c_str())) {
				diag("restore statement failed: %s", sql.c_str());
				failures++;
				all_ok = false;
			}
		}
		if (all_ok) {
			const std::vector<string> drops {
				"DROP TABLE IF EXISTS " + string(SNAP_SERVERS),
				"DROP TABLE IF EXISTS " + string(SNAP_RULES)
			};
			for (const string& sql : drops) {
				if (!admin_exec(admin, sql.c_str())) {
					diag("snapshot cleanup failed: %s", sql.c_str());
					failures++;
					all_ok = false;
				}
			}
		}
		if (all_ok) {
			armed = false;
		}
		return all_ok;
	}

	// Last-resort retry: swallow exceptions so a failed cleanup degrades to a
	// logged failure instead of std::terminate.
	~Fixture() noexcept {
		if (armed) {
			diag("Fixture fallback: retrying the restore");
			try {
				restore();
			} catch (...) {
				diag("Fixture fallback: restore threw; giving up");
			}
		}
	}
};

static bool install_rules(PGconn* admin) {
	const string pattern_a = sql_quote(string("^/\\* ") + TAG_A + " \\*/");
	const string pattern_b = sql_quote(string("^/\\* ") + TAG_B + " \\*/");
	const std::vector<string> statements {
		"DELETE FROM pgsql_query_rules WHERE rule_id IN (" + std::to_string(rule_id_a) + "," + std::to_string(rule_id_b) + ")",
		"INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply, comment) VALUES ("
			+ std::to_string(rule_id_a) + ", 1, " + pattern_a + ", " + std::to_string(HG_A) + ", 1, 'temp_table_lock_test')",
		"INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply, comment) VALUES ("
			+ std::to_string(rule_id_b) + ", 1, " + pattern_b + ", " + std::to_string(HG_B) + ", 1, 'temp_table_lock_test')",
		"LOAD PGSQL QUERY RULES TO RUNTIME"
	};
	for (const string& sql : statements) {
		if (!admin_exec(admin, sql.c_str())) {
			return false;
		}
	}
	usleep(100 * 1000); // let the runtime rules settle, as sibling tests do
	return true;
}

static void run_scenario(CommandLine& cl) {
	// The lock state lives in the session: one connection tells the whole
	// story.
	PGConnPtr fe = connect_frontend(cl);
	if (!fe || PQstatus(fe.get()) != CONNECTION_OK) {
		skip(5, "frontend connection failed");
		return;
	}

	// 1. The session starts unlocked: the CREATE TEMP TABLE below is what
	//    must take the lock.
	int locked = session_locked_hostgroup(fe.get());
	if (locked != -1) {
		diag("session starts with locked_on_hostgroup=%d, expected -1", locked);
	}
	ok(locked == -1, "session starts unlocked (locked_on_hostgroup=%d)", locked);

	// 2. The tagged CREATE TEMP TABLE itself is forwarded and accepted by
	//    PostgreSQL, on the rule's hostgroup.
	const string create_sql = string("/* ") + TAG_A + " */ CREATE TEMP TABLE " + table_name + " (id int)";
	PGresult* r = PQexec(fe.get(), create_sql.c_str());
	const bool create_ok = (PQresultStatus(r) == PGRES_COMMAND_OK);
	if (!create_ok) {
		diag("CREATE TEMP TABLE failed: %s", PQresultErrorMessage(r));
	}
	PQclear(r);
	ok(create_ok, "CREATE TEMP TABLE is accepted on the rule hostgroup");

	// 3. The lock the CREATE TEMP TABLE must take: the core of the fix.
	locked = session_locked_hostgroup(fe.get());
	if (locked != HG_A) {
		diag("locked_on_hostgroup=%d after CREATE TEMP TABLE, expected %d", locked, HG_A);
	}
	ok(locked == HG_A, "session lock state after CREATE TEMP TABLE (locked_on_hostgroup=%d)", locked);

	// 4. The temp table is only on hostgroup A's single connection: a query
	//    routed there still sees it (multiplexing was already disabled for
	//    it, before the fix under test).
	const string same_sql = string("/* ") + TAG_A + " */ SELECT * FROM " + table_name;
	r = PQexec(fe.get(), same_sql.c_str());
	const bool same_ok = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 0);
	if (!same_ok) {
		diag("same-hostgroup read returned: %s", PQresultErrorMessage(r));
	}
	PQclear(r);
	ok(same_ok, "temp table is visible on the rule hostgroup");

	// 5. The same read routed to the other hostgroup: refused by the hostgroup
	//    lock (SQLSTATE P0001), so the statement never reaches a connection
	//    without the temp table. Without the fix it got there, and PostgreSQL
	//    answered 'relation ... does not exist' (42P01).
	const string cross_sql = string("/* ") + TAG_B + " */ SELECT * FROM " + table_name;
	r = PQexec(fe.get(), cross_sql.c_str());
	const ExecStatusType cross_st = PQresultStatus(r);
	const char* cross_sqlstate = PQresultErrorField(r, PG_DIAG_SQLSTATE);
	const string cross_err = (cross_st == PGRES_TUPLES_OK ? "" : PQresultErrorMessage(r));
	const bool cross_ok = (cross_st == PGRES_FATAL_ERROR
		&& cross_sqlstate && strcmp(cross_sqlstate, "P0001") == 0
		&& cross_err.find("connection is locked to hostgroup") != string::npos);
	if (!cross_ok) {
		diag("cross-hostgroup read status=%d sqlstate='%s', error: %s",
			(int)cross_st, (cross_sqlstate ? cross_sqlstate : ""), cross_err.c_str());
	}
	PQclear(r);
	ok(cross_ok, "cross-hostgroup read is refused by the hostgroup lock");
}

int main(int, char**) {
	CommandLine cl;
	plan(6);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	table_name = string("temp_table_lock_test_") + std::to_string(getpid());
	rule_id_a = -181300000L - (static_cast<long>(getpid()) % 100000L) * 2L;
	rule_id_b = rule_id_a + 1;

	PGConnPtr admin_holder = connect_admin(cl);
	PGconn* admin = admin_holder.get();
	if (PQstatus(admin) != CONNECTION_OK) {
		BAIL_OUT("cannot connect to the ProxySQL admin interface");
	}

	// Copy the first ONLINE backend's settings so the fixture hostgroups
	// reach the server exactly like the infra's own entries do.
	string backend_host;
	int backend_port = 0, backend_weight = 1, backend_compression = 0;
	int backend_max_replication_lag = 0;
	int backend_use_ssl = 0, backend_max_latency_ms = 0;
	{
		const char* q = "SELECT hostname, port, weight, compression, max_replication_lag, use_ssl, max_latency_ms "
			"FROM runtime_pgsql_servers WHERE status='ONLINE' ORDER BY hostgroup_id, hostname, port LIMIT 1";
		PGresult* r = PQexec(admin, q);
		if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) != 1 || PQgetisnull(r, 0, 0) || PQgetisnull(r, 0, 1)) {
			diag("no ONLINE pgsql backend: %s", PQresultErrorMessage(r));
			PQclear(r);
			BAIL_OUT("this test requires an ONLINE pgsql backend");
		}
		backend_host = PQgetvalue(r, 0, 0);
		backend_port = atoi(PQgetvalue(r, 0, 1));
		backend_weight = atoi(PQgetvalue(r, 0, 2));
		backend_compression = atoi(PQgetvalue(r, 0, 3));
		backend_max_replication_lag = atoi(PQgetvalue(r, 0, 4));
		backend_use_ssl = atoi(PQgetvalue(r, 0, 5));
		backend_max_latency_ms = atoi(PQgetvalue(r, 0, 6));
		PQclear(r);
	}

	Fixture fixture;
	{
		const char* q = "SELECT variable_name, variable_value FROM global_variables WHERE variable_name IN "
			"('pgsql-set_query_lock_on_hostgroup','pgsql-free_connections_pct')";
		PGresult* r = PQexec(admin, q);
		if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) != 2) {
			diag("cannot read the pgsql variables: %s", PQerrorMessage(admin));
			PQclear(r);
			BAIL_OUT("cannot snapshot the pgsql variables");
		}
		for (int i = 0; i < PQntuples(r); i++) {
			const string name = PQgetvalue(r, i, 0);
			const string value = PQgetvalue(r, i, 1);
			if (value.empty()) {
				PQclear(r);
				BAIL_OUT("variable %s is empty", name.c_str());
			}
			fixture.saved_vars.emplace_back(name, value);
		}
		PQclear(r);
	}

	// Snapshot whatever the fixture rows are now, so the restore returns the
	// exact original state (also after a crashed previous run).
	{
		const std::vector<string> snapshots {
			string("CREATE TEMPORARY TABLE ") + SNAP_SERVERS + " AS SELECT * FROM pgsql_servers WHERE hostgroup_id IN ("
				+ std::to_string(HG_A) + "," + std::to_string(HG_B) + ")",
			string("CREATE TEMPORARY TABLE ") + SNAP_RULES + " AS SELECT * FROM pgsql_query_rules WHERE rule_id IN ("
				+ std::to_string(rule_id_a) + "," + std::to_string(rule_id_b) + ")"
		};
		for (const string& sql : snapshots) {
			if (!admin_exec(admin, sql.c_str())) {
				diag("snapshot failed, nothing else was mutated: %s", sql.c_str());
				BAIL_OUT("cannot snapshot the fixture state");
			}
		}
		fixture.admin = admin;
		fixture.armed = true;
	}

	{
		const string host = sql_quote(backend_host);
		const string server_values = "(" + std::to_string(HG_A) + ", " + host + ", " + std::to_string(backend_port)
			+ ", 'ONLINE', " + std::to_string(backend_weight) + ", " + std::to_string(backend_compression)
			+ ", 1, " + std::to_string(backend_max_replication_lag) + ", " + std::to_string(backend_use_ssl)
			+ ", " + std::to_string(backend_max_latency_ms) + ", 'temp_table_lock_test'),("
			+ std::to_string(HG_B) + ", " + host + ", " + std::to_string(backend_port)
			+ ", 'ONLINE', " + std::to_string(backend_weight) + ", " + std::to_string(backend_compression)
			+ ", 1, " + std::to_string(backend_max_replication_lag) + ", " + std::to_string(backend_use_ssl)
			+ ", " + std::to_string(backend_max_latency_ms) + ", 'temp_table_lock_test')";
		const std::vector<string> statements {
			"DELETE FROM pgsql_servers WHERE hostgroup_id IN (" + std::to_string(HG_A) + "," + std::to_string(HG_B) + ")",
			"INSERT INTO pgsql_servers (hostgroup_id, hostname, port, status, weight, compression, max_connections, "
				"max_replication_lag, use_ssl, max_latency_ms, comment) VALUES " + server_values,
			"LOAD PGSQL SERVERS TO RUNTIME",
			// Pin the variables the assertions depend on:
			// - set_query_lock_on_hostgroup=1: the cross-hostgroup refusal is
			//   part of the assertions;
			// - free_connections_pct=100: the single pooled fixture connection
			//   must survive the gap between two queries.
			"SET pgsql-set_query_lock_on_hostgroup=1",
			"SET pgsql-free_connections_pct=100",
			"LOAD PGSQL VARIABLES TO RUNTIME"
		};
		for (const string& sql : statements) {
			if (!admin_exec(admin, sql.c_str())) {
				BAIL_OUT("cannot install the fixture hostgroups");
			}
		}
	}
	diag("fixture: backend %s:%d, hostgroups %d/%d, rules %ld/%ld, table %s",
		backend_host.c_str(), backend_port, HG_A, HG_B, rule_id_a, rule_id_b, table_name.c_str());

	if (!install_rules(admin)) {
		// The scenario's five assertions, all failing: nothing ran.
		ok(false, "session starts unlocked");
		ok(false, "CREATE TEMP TABLE is accepted on the rule hostgroup");
		ok(false, "session lock state after CREATE TEMP TABLE");
		ok(false, "temp table is visible on the rule hostgroup");
		ok(false, "cross-hostgroup read is refused by the hostgroup lock");
	} else {
		run_scenario(cl);
	}

	ok(fixture.restore(), "cleanup: fixture hostgroups %d/%d and rules restored (failures=%d)",
		HG_A, HG_B, fixture.failures);

	return exit_status();
}
