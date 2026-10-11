/**
 * Regression #6429: PostgreSQL monitor intervals >= 2,147,484 ms overflowed a
 * 32-bit microsecond value. Negative / zero results made the scheduler
 * busy-loop and flood every backend with checks; tiny positive results
 * (4294968 ms -> 704 us) ran a full check round every 0.7 ms.
 *
 * For each check type (connect, ping, read_only, replication_lag) and each
 * wrapping value, the test first runs that type on a 1 s interval, then sets
 * the wrapping value, waits for the already-due check to settle, and
 * requires that (almost) no further checks of that type run in a quiet
 * window. Before the fix the counters grew by thousands per second.
 */
#include "command_line.h"
#include "libpq-fe.h"
#include "tap.h"
#include <cstdlib>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

// Test hostgroups used to make read_only and replication_lag checks run.
static const int WRITER_HG = 64290;
static const int READER_HG = 64291;
// A long interval that never wrapped (< 2,147,484 ms); keeps other types quiet.
static const char SAFE_LONG_INTERVAL[] = "2000000";
// Checks allowed in the quiet window (a batch dispatched just before it).
static const long MAX_QUIET_CHECKS = 2;

static std::string query(PGconn *conn, const std::string &sql) {
	PGresult *res = PQexec(conn, sql.c_str());
	if (PQresultStatus(res) != PGRES_TUPLES_OK && PQresultStatus(res) != PGRES_COMMAND_OK)
		BAIL_OUT("admin query failed: '%s': %s", sql.c_str(), PQresultErrorMessage(res));
	std::string value = PQntuples(res) ? PQgetvalue(res, 0, 0) : "";
	PQclear(res);
	return value;
}

/** Total checks (OK + ERR) performed so far for one check type. */
static long checks(PGconn *admin, const std::string &type) {
	return std::stol(query(admin,
		"SELECT SUM(CAST(Variable_Value AS INTEGER)) FROM stats_pgsql_global WHERE Variable_Name IN "
		"('PgSQL_Monitor_" + type + "_check_OK','PgSQL_Monitor_" + type + "_check_ERR')"));
}

struct check_type_t {
	const char *var;   // pgsql-monitor_<var>
	const char *stat;  // PgSQL_Monitor_<stat>_check_{OK,ERR}
};

// Order matters only for the unfixed code: a connect flood opens a new backend
// connection per check, exhausts the backend's connection slots and gets the
// server shunned, which disables the read_only / replication_lag checks. So
// the connect case runs last to keep every case able to show its own flood.
static const std::vector<check_type_t> TYPES = {
	{"read_only_interval", "read_only"},
	{"replication_lag_interval", "replication_lag"},
	{"ping_interval", "ping"},
	{"connect_interval", "connect"},
};

static void set_all_intervals(PGconn *admin, const char *value) {
	for (const auto &t : TYPES)
		query(admin, std::string("SET pgsql-monitor_") + t.var + "=" + value);
}

/** Waits (up to 5 s) for at least one more check of 'type' to complete. */
static bool wait_active(PGconn *admin, const std::string &type) {
	const long base = checks(admin, type);
	for (int i = 0; i < 50; i++) {
		if (checks(admin, type) > base)
			return true;
		usleep(100000);
	}
	return false;
}

static bool wait_all_active(PGconn *admin) {
	std::vector<long> base;
	for (const auto &t : TYPES)
		base.push_back(checks(admin, t.stat));
	for (int i = 0; i < 150; i++) {
		bool all = true;
		for (size_t j = 0; j < TYPES.size(); j++)
			all = all && checks(admin, TYPES[j].stat) > base[j];
		if (all)
			return true;
		usleep(100000);
	}
	return false;
}

int main() {
	alarm(300);
	CommandLine cl;
	if (cl.getEnv())
		return EXIT_FAILURE;
	const std::string port = std::to_string(cl.pgsql_admin_port);
	const char *keys[] = {"host", "port", "user", "password", "sslmode", "connect_timeout", nullptr};
	const char *values[] = {cl.pgsql_admin_host, port.c_str(), cl.admin_username,
							cl.admin_password, "disable", "5", nullptr};
	PGconn *admin = PQconnectdbParams(keys, values, 0);
	if (PQstatus(admin) != CONNECTION_OK)
		BAIL_OUT("admin connect: %s", PQerrorMessage(admin));

	const std::vector<std::string> wrapping = {
		"3600000",   // 1 h: wrapped negative
		"4294968",   // wrapped to +704 us
		"536870912", // wrapped to exactly 0
	};
	plan(1 + TYPES.size() * wrapping.size());

	std::vector<std::pair<std::string, std::string>> saved;
	saved.emplace_back("monitor_enabled", "");
	for (const auto &t : TYPES)
		saved.emplace_back(std::string("monitor_") + t.var, "");
	for (auto &s : saved)
		s.second = query(admin, "SELECT variable_value FROM global_variables WHERE "
								"variable_name='pgsql-" + s.first + "'");

	// Put an existing backend in a replication hostgroup pair with
	// max_replication_lag > 0, so read_only and replication_lag checks run too.
	const std::string host = query(admin,
		"SELECT hostname FROM runtime_pgsql_servers ORDER BY hostgroup_id LIMIT 1");
	const std::string srv_port = query(admin,
		"SELECT port FROM runtime_pgsql_servers ORDER BY hostgroup_id LIMIT 1");
	if (host.empty())
		BAIL_OUT("no pgsql backend configured");
	query(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id IN (" + std::to_string(WRITER_HG) +
					 "," + std::to_string(READER_HG) + ")");
	query(admin, "DELETE FROM pgsql_replication_hostgroups WHERE writer_hostgroup=" +
					 std::to_string(WRITER_HG));
	query(admin, "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_replication_lag) VALUES (" +
					 std::to_string(WRITER_HG) + ",'" + host + "'," + srv_port + ",3600)");
	query(admin, "INSERT INTO pgsql_replication_hostgroups (writer_hostgroup,reader_hostgroup,comment) "
				 "VALUES (" + std::to_string(WRITER_HG) + "," + std::to_string(READER_HG) +
					 ",'reg_test_6429')");
	query(admin, "LOAD PGSQL SERVERS TO RUNTIME");

	set_all_intervals(admin, "1000");
	query(admin, "SET pgsql-monitor_enabled=true");
	query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	ok(wait_all_active(admin), "read_only, replication_lag, ping and connect checks are running");

	for (const auto &t : TYPES) {
		for (const auto &value : wrapping) {
			// Make this type's next check imminent (<= 1 s away), so the
			// wrapping value is applied when that check comes due. Before
			// the fix, the rescheduling then landed in the past (or never
			// moved), regardless of what the previous schedule was.
			// Require such a check to be observed, so a case can't pass just
			// because this type's checks are not running at all (e.g. the
			// server got shunned).
			set_all_intervals(admin, SAFE_LONG_INTERVAL);
			query(admin, std::string("SET pgsql-monitor_") + t.var + "=1000");
			query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
			const bool active = wait_active(admin, t.stat);
			query(admin, std::string("SET pgsql-monitor_") + t.var + "=" + value);
			query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
			// The check that was already due may still run once after LOAD.
			usleep(1500000);
			const long before = checks(admin, t.stat);
			usleep(3000000);
			const long delta = checks(admin, t.stat) - before;
			ok(active && delta <= MAX_QUIET_CHECKS,
			   "pgsql-monitor_%s=%s: %s checks active at 1s interval=%s, then %ld in 3s "
			   "(expected <= %ld)",
			   t.var, value.c_str(), t.stat, active ? "yes" : "no", delta, MAX_QUIET_CHECKS);
		}
	}

	query(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id IN (" + std::to_string(WRITER_HG) +
					 "," + std::to_string(READER_HG) + ")");
	query(admin, "DELETE FROM pgsql_replication_hostgroups WHERE writer_hostgroup=" +
					 std::to_string(WRITER_HG));
	query(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	for (const auto &s : saved)
		query(admin, "SET pgsql-" + s.first + "='" + s.second + "'");
	query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	PQfinish(admin);
	return exit_status();
}
