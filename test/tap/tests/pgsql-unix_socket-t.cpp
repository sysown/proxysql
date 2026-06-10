/**
 * @file pgsql-unix_socket-t.cpp
 * @brief Regression test for sysown/proxysql#5837.
 *
 * Validates that when pgsql_servers has port=0 (meaning "hostname is a
 * Unix-domain socket path"), ProxySQL's client-side connect path AND
 * the pgsql monitor both build a libpq conninfo string that omits
 * `port=`. libpq would otherwise reject "port=0" with the error
 *
 *     invalid port number: "0"
 *
 * seen in the original issue. The test runs in the dedicated
 * `pgsql-socket` TAP group, whose setup-infras.bash replaces the
 * default TCP pgsql_servers rows with socket-path rows, and whose
 * env.sh mounts the pgdb1 socket directory into the ProxySQL
 * container at /var/run/postgresql-shared.
 */

#include <unistd.h>
#include <memory>
#include <string>
#include <sstream>
#include <vector>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType { ADMIN, BACKEND };

static PGConnPtr createNewConnection(ConnType t, const std::string& extra = "") {
	const char* host = (t == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
	int port = (t == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
	const char* user = (t == BACKEND) ? cl.pgsql_username : cl.admin_username;
	const char* pass = (t == BACKEND) ? cl.pgsql_password : cl.admin_password;

	std::stringstream ss;
	ss << "host=" << host << " port=" << port
	   << " user=" << user << " password=" << pass
	   << " sslmode=disable";
	if (!extra.empty()) {
		ss << " " << extra;
	}

	PGconn* conn = PQconnectdb(ss.str().c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		fprintf(stderr, "Connection to %s:%d failed: %s\n",
			host, port, PQerrorMessage(conn));
		PQfinish(conn);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(conn, &PQfinish);
}

static long readMonitorCounter(PGConnPtr& admin, const char* var) {
	std::stringstream q;
	q << "SELECT Variable_Value FROM stats_pgsql_global "
	     "WHERE Variable_Name='" << var << "';";
	PGresult* res = PQexec(admin.get(), q.str().c_str());
	long v = -1;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
		v = atol(PQgetvalue(res, 0, 0));
	}
	PQclear(res);
	return v;
}

static long readGlobalVar(PGConnPtr& admin, const char* var, long fallback) {
	std::stringstream q;
	q << "SELECT Variable_Value FROM global_variables "
	     "WHERE Variable_Name='" << var << "';";
	PGresult* res = PQexec(admin.get(), q.str().c_str());
	long v = fallback;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
		v = atol(PQgetvalue(res, 0, 0));
	}
	PQclear(res);
	return v;
}

static bool execSql(PGConnPtr& admin, const std::string& sql) {
	PGresult* res = PQexec(admin.get(), sql.c_str());
	bool ok = PQresultStatus(res) == PGRES_COMMAND_OK;
	if (!ok) {
		fprintf(stderr, "SQL failed: %s | %s\n",
			sql.c_str(), PQerrorMessage(admin.get()));
	}
	PQclear(res);
	return ok;
}

int main(int argc, char** argv) {
	plan(6);

	if (cl.getEnv()) return exit_status();

	auto admin = createNewConnection(ADMIN);
	ok(admin != nullptr, "ADMIN connection created");

	if (admin == nullptr) {
		diag("Cannot continue without admin connection");
		return exit_status();
	}

	// Speed up monitor cycles so the test finishes quickly.
	long orig_interval = readGlobalVar(admin,
		"pgsql-monitor_connect_interval", 2000);
	if (!execSql(admin, "SET pgsql-monitor_connect_interval=1000; LOAD PGSQL VARIABLES TO RUNTIME;")) {
		diag("Failed to lower monitor interval, continuing with current value");
	}

	// -----------------------------------------------------------------
	// 1. Confirm pgsql_servers is set up the way the group expects:
	//    hostname='/var/run/postgresql-shared', port=0
	// -----------------------------------------------------------------
	{
		PGresult* res = PQexec(admin.get(),
			"SELECT hostname, port FROM pgsql_servers "
			"WHERE hostname='/var/run/postgresql-shared' AND port=0 "
			"ORDER BY hostgroup_id");
		bool found = (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) >= 1);
		ok(found,
			"pgsql_servers has at least one row with hostname=/var/run/postgresql-shared, port=0");
		if (!found) {
			diag("Run this test via TAP_GROUP=pgsql-socket so setup-infras.bash can configure the socket rows");
		}
		PQclear(res);
	}

	// -----------------------------------------------------------------
	// 2. Client-side path: a SELECT through the proxy must succeed.
	//    Before the fix this failed at PQconnectdb with
	//    "invalid port number: \"0\"".
	// -----------------------------------------------------------------
	auto backend = createNewConnection(BACKEND);
	ok(backend != nullptr, "Client connection through ProxySQL (via Unix-socket backend) succeeds");

	if (backend != nullptr) {
		PGresult* res = PQexec(backend.get(), "SELECT 1 AS one");
		bool ok_q = (PQresultStatus(res) == PGRES_TUPLES_OK
			&& PQntuples(res) == 1
			&& strcmp(PQgetvalue(res, 0, 0), "1") == 0);
		ok(ok_q, "SELECT 1 through the proxy returns the expected result");
		if (!ok_q) {
			diag("PQresultStatus=%d, ntuples=%d, value=%s, error=%s",
				PQresultStatus(res), PQntuples(res),
				PQntuples(res) > 0 ? PQgetvalue(res, 0, 0) : "(none)",
				PQerrorMessage(backend.get()));
		}
		PQclear(res);
	} else {
		ok(0, "SELECT 1 through the proxy returns the expected result");
	}

	// -----------------------------------------------------------------
	// 3. Monitor path: the pgsql monitor's "Connections_OK" counter
	//    must increase. Before the fix every monitor attempt logged
	//    "Monitor connect failed ... invalid port number: \"0\"" and
	//    "Connections_ERR" increased instead.
	// -----------------------------------------------------------------
	long before_ok = readMonitorCounter(admin, "PgSQL_Monitor_Connections_OK");
	long before_err = readMonitorCounter(admin, "PgSQL_Monitor_Connections_ERR");
	diag("Baseline: Connections_OK=%ld Connections_ERR=%ld", before_ok, before_err);

	// Wait for at least one full monitor cycle. With
	// pgsql-monitor_connect_interval=1000 this is ~2.5s.
	usleep(2500 * 1000);

	long after_ok = readMonitorCounter(admin, "PgSQL_Monitor_Connections_OK");
	long after_err = readMonitorCounter(admin, "PgSQL_Monitor_Connections_ERR");
	diag("After wait: Connections_OK=%ld Connections_ERR=%ld", after_ok, after_err);

	ok(after_ok > before_ok,
		"PgSQL_Monitor_Connections_OK increases when port=0 socket path is configured");
	ok(after_err == before_err,
		"PgSQL_Monitor_Connections_ERR stays at baseline (no 'invalid port number' errors)");

	// -----------------------------------------------------------------
	// 4. Restore monitor interval so the next test group in the same
	//    INFRA_ID starts from a sane state.
	// -----------------------------------------------------------------
	{
		std::stringstream q;
		q << "SET pgsql-monitor_connect_interval=" << orig_interval << ";";
		execSql(admin, q.str());
		execSql(admin, "LOAD PGSQL VARIABLES TO RUNTIME;");
	}

	return exit_status();
}
