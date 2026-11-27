/**
 * @file pgsql-set_multiplex_hostgroup_lock-t.cpp
 * @brief An unparseable SET must pin the session when the matching query rule
 *        disables multiplexing, exactly as when the rule says nothing about it.
 *
 * @details
 *   ProxySQL cannot parse a SET of a custom (extension namespace) GUC, so it
 *   answers it by locking the session on the rule's hostgroup: the setting
 *   only exists on the backend connection that ran the SET, and the lock
 *   keeps every later query of that session on the same connection. The lock
 *   used to be taken only when the matching rule said nothing about multiplex
 *   (NULL, i.e. -1): a rule that disabled multiplexing outright (multiplex=0)
 *   left the session unpinned, and the setting silently leaked away from the
 *   queries that followed.
 *
 *   The fixture builds two dedicated hostgroups (18120, 18121) that both point
 *   at the first ONLINE backend with max_connections=1, so each pool owns
 *   exactly one backend connection, and two reserved negative-ID query rules
 *   (they sort ahead of every infra-installed rule) that route by a comment
 *   tag:
 *     rule A: comment tag "set_multiplex_hg_a" -> hostgroup 18120 (the SET lands here)
 *     rule B: comment tag "set_multiplex_hg_b" -> hostgroup 18121 (the follow-up read)
 *
 *   For every multiplex mode set on both rules:
 *     1. the tagged SET of a custom GUC is accepted (forwarded to PG);
 *     2. 'PROXYSQL INTERNAL SESSION' reports the lock state: locked for
 *        unset and 0 (0 is the fix under test), unlocked for 1 and 2;
 *     3. the custom GUC is still visible on hostgroup 18120 connection;
 *     4. the hostgroup 18121 read documents the contrast: refused by the
 *        hostgroup lock (unset/0) versus 'unrecognized configuration
 *        parameter' from a different backend connection (1/2).
 *
 *   State touched by this test (and restored on exit):
 *     - pgsql_servers rows for hostgroups 18120/18121
 *     - pgsql_query_rules rows with the reserved negative rule IDs
 *     - the pgsql-set_query_lock_on_hostgroup variable (pinned to 1)
 *     - the pgsql-free_connections_pct variable (pinned to 100, so the single
 *       pooled fixture connection survives between two queries)
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
using std::vector;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static constexpr int HG_A = 18120;
static constexpr int HG_B = 18121;
static constexpr const char* TAG_A = "set_multiplex_hg_a";
static constexpr const char* TAG_B = "set_multiplex_hg_b";
static constexpr const char* GUC_VALUE = "pinned";

static constexpr const char* SNAP_SERVERS = "set_multiplex_snap_servers";
static constexpr const char* SNAP_RULES = "set_multiplex_snap_rules";

// Reserved negative rule IDs (see mysql-user-variable-tracking-t.cpp for the
// precedent): they sort ahead of every infra-installed rule, so the comment
// tag alone decides the routing, and they cannot collide with foreign rules.
static long rule_id_a = 0;
static long rule_id_b = 0;
// Custom GUCs live on the backend connection that ran the SET: a per-run name
// keeps pooled connections from other tests out of the picture.
static string guc_name;

struct Mode {
	const char* label;
	int multiplex; // -1 leaves the column NULL: the rule says nothing about multiplex
	bool expect_lock;
};

static const Mode modes[] = {
	{"multiplex unset", -1, true},
	{"multiplex 0", 0, true}, // disabling multiplex pins the session too: the fix under test
	{"multiplex 1", 1, false},
	{"multiplex 2", 2, false},
};

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
	vector<std::pair<string, string>> saved_vars;

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
		vector<string> statements {
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
			const vector<string> drops {
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

static string insert_rule_sql(long rule_id, const string& pattern, int dest_hg, int multiplex) {
	// multiplex < 0 leaves the column NULL: the rule says nothing about it.
	if (multiplex < 0) {
		return "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply, comment) VALUES ("
			+ std::to_string(rule_id) + ", 1, " + pattern + ", " + std::to_string(dest_hg) + ", 1, 'set_multiplex')";
	}
	return "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, multiplex, apply, comment) VALUES ("
		+ std::to_string(rule_id) + ", 1, " + pattern + ", " + std::to_string(dest_hg) + ", "
		+ std::to_string(multiplex) + ", 1, 'set_multiplex')";
}

static bool install_rules(PGconn* admin, const Mode& m) {
	const string pattern_a = sql_quote(string("^/\\* ") + TAG_A + " \\*/");
	const string pattern_b = sql_quote(string("^/\\* ") + TAG_B + " \\*/");
	const vector<string> statements {
		"DELETE FROM pgsql_query_rules WHERE rule_id IN (" + std::to_string(rule_id_a) + "," + std::to_string(rule_id_b) + ")",
		insert_rule_sql(rule_id_a, pattern_a, HG_A, m.multiplex),
		insert_rule_sql(rule_id_b, pattern_b, HG_B, m.multiplex),
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

static void run_mode(CommandLine& cl, const Mode& m) {
	// The lock state lives in the session: every mode starts fresh.
	PGConnPtr fe = connect_frontend(cl);
	if (!fe || PQstatus(fe.get()) != CONNECTION_OK) {
		skip(4, "frontend connection failed");
		return;
	}

	// 1. The unknown SET itself is forwarded and accepted by PostgreSQL.
	const string set_sql = string("/* ") + TAG_A + " */ SET " + guc_name + " = '" + GUC_VALUE + "'";
	PGresult* r = PQexec(fe.get(), set_sql.c_str());
	const bool set_ok = (PQresultStatus(r) == PGRES_COMMAND_OK);
	if (!set_ok) {
		diag("%s: SET failed: %s", m.label, PQresultErrorMessage(r));
	}
	PQclear(r);
	ok(set_ok, "%s: unknown SET statement is accepted", m.label);

	// 2. The lock the SET must (not) take: the core of the fix.
	const int locked = session_locked_hostgroup(fe.get());
	const bool lock_ok = (m.expect_lock ? locked == HG_A : locked == -1);
	if (!lock_ok) {
		diag("%s: locked_on_hostgroup=%d, expected %d", m.label, locked, (m.expect_lock ? HG_A : -1));
	}
	ok(lock_ok, "%s: session lock state after unknown SET (locked_on_hostgroup=%d)", m.label, locked);

	// 3. The GUC is only on hostgroup A's single connection: a query routed
	//    there must see it whether the session is locked or multiplexed.
	const string same_sql = string("/* ") + TAG_A + " */ SELECT current_setting('" + guc_name + "') AS val";
	r = PQexec(fe.get(), same_sql.c_str());
	bool same_ok = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1);
	string same_val;
	if (same_ok) {
		same_val = PQgetvalue(r, 0, 0);
		same_ok = (same_val == GUC_VALUE);
	}
	if (!same_ok) {
		diag("%s: same-hostgroup read returned '%s': %s",
			m.label, same_val.c_str(), PQresultErrorMessage(r));
	}
	PQclear(r);
	ok(same_ok, "%s: custom GUC is visible on the rule hostgroup", m.label);

	// 4. A read routed to the other hostgroup:
	//    - locked: refused by the hostgroup lock, the session never leaves the
	//      connection carrying the GUC;
	//    - not locked: multiplexing answers from a different backend
	//      connection that never saw the SET.
	const string cross_sql = string("/* ") + TAG_B + " */ SELECT current_setting('" + guc_name + "') AS val";
	r = PQexec(fe.get(), cross_sql.c_str());
	const ExecStatusType cross_st = PQresultStatus(r);
	const string cross_err = (cross_st == PGRES_TUPLES_OK ? "" : PQresultErrorMessage(r));
	bool cross_ok;
	if (m.expect_lock) {
		cross_ok = (cross_st != PGRES_TUPLES_OK && cross_err.find("locked to hostgroup") != string::npos);
	} else {
		cross_ok = (cross_st != PGRES_TUPLES_OK && cross_err.find("unrecognized configuration parameter") != string::npos);
	}
	if (!cross_ok) {
		diag("%s: cross-hostgroup read status=%d, error: %s", m.label, (int)cross_st, cross_err.c_str());
	}
	PQclear(r);
	ok(cross_ok, "%s: cross-hostgroup read is %s",
		m.label, (m.expect_lock ? "refused by the hostgroup lock" : "answered from a connection without the GUC"));
}

int main(int, char**) {
	CommandLine cl;
	plan(4 * 4 + 1);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	guc_name = string("set_multiplex_test.var_") + std::to_string(getpid());
	rule_id_a = -181200000L - (static_cast<long>(getpid()) % 100000L) * 2L;
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
		const vector<string> snapshots {
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
			+ ", " + std::to_string(backend_max_latency_ms) + ", 'set_multiplex'),("
			+ std::to_string(HG_B) + ", " + host + ", " + std::to_string(backend_port)
			+ ", 'ONLINE', " + std::to_string(backend_weight) + ", " + std::to_string(backend_compression)
			+ ", 1, " + std::to_string(backend_max_replication_lag) + ", " + std::to_string(backend_use_ssl)
			+ ", " + std::to_string(backend_max_latency_ms) + ", 'set_multiplex')";
		const vector<string> statements {
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
	diag("fixture: backend %s:%d, hostgroups %d/%d, rules %ld/%ld, guc %s",
		backend_host.c_str(), backend_port, HG_A, HG_B, rule_id_a, rule_id_b, guc_name.c_str());

	for (const Mode& m : modes) {
		if (!install_rules(admin, m)) {
			ok(false, "%s: rule installation failed", m.label);
			ok(false, "%s: unknown SET statement is accepted", m.label);
			ok(false, "%s: session lock state after unknown SET", m.label);
			ok(false, "%s: custom GUC is visible on the rule hostgroup", m.label);
			continue;
		}
		run_mode(cl, m);
	}

	ok(fixture.restore(), "cleanup: fixture hostgroups %d/%d and rules restored (failures=%d)",
		HG_A, HG_B, fixture.failures);

	return exit_status();
}
