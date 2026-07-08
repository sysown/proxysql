/**
 * @file pgsql-servers_ssl_params-t.cpp
 * @brief TAP integration tests for pgsql_servers_ssl_params.
 *
 * Part 1: Admin CRUD operations via PgSQL admin port (6132).
 * Part 2: End-to-end backend SSL connections verifying per-server
 *         SSL params are applied (valid cert succeeds, bogus cert fails,
 *         per-server overrides globals, fallback works, monitor SSL).
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include <vector>
#include <cstdlib>
#include "libpq-fe.h"
#include "mysql.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

// ============================================================================
// Helpers
// ============================================================================

enum ConnType { ADMIN, BACKEND };

PGConnPtr createNewConnection(ConnType conn_type, bool with_ssl = false) {
	const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
	int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
	const char* username = (conn_type == BACKEND) ? cl.pgsql_root_username : cl.admin_username;
	const char* password = (conn_type == BACKEND) ? cl.pgsql_root_password : cl.admin_password;

	std::stringstream ss;
	ss << "host=" << host << " port=" << port;
	ss << " user=" << username << " password=" << password;
	ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

	PGconn* conn = PQconnectdb(ss.str().c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		fprintf(stderr, "Connection failed to '%s': %s\n",
			(conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
		PQfinish(conn);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(conn, &PQfinish);
}

bool exec_ok(PGconn* conn, const char* query) {
	PGresult* res = PQexec(conn, query);
	bool ok_result = (PQresultStatus(res) == PGRES_COMMAND_OK ||
	                  PQresultStatus(res) == PGRES_TUPLES_OK);
	if (!ok_result) {
		fprintf(stderr, "Query failed: %s\nError: %s\n", query, PQerrorMessage(conn));
	}
	PQclear(res);
	return ok_result;
}

int exec_count(PGconn* conn, const char* query) {
	PGresult* res = PQexec(conn, query);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		PQclear(res);
		return -1;
	}
	int count = PQntuples(res);
	PQclear(res);
	return count;
}

std::string exec_scalar(PGconn* conn, const char* query) {
	PGresult* res = PQexec(conn, query);
	if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
		PQclear(res);
		return "";
	}
	std::string val = PQgetvalue(res, 0, 0);
	PQclear(res);
	return val;
}

bool exec_queries(PGconn* conn, const std::vector<const char*>& queries) {
	for (const auto& q : queries) {
		if (!exec_ok(conn, q)) return false;
	}
	return true;
}

void cleanup_ssl_params(PGconn* admin) {
	exec_queries(admin, {
		"DELETE FROM pgsql_servers_ssl_params",
		"LOAD PGSQL SERVERS TO RUNTIME",
		"SAVE PGSQL SERVERS TO DISK"
	});
}

/**
 * @brief Create a bogus cert file that exists but has invalid content.
 *
 * libpq will attempt to parse this file and fail with "no start line",
 * which proves that per-server SSL params are actually being applied.
 * A nonexistent file path is simply ignored by libpq when the backend
 * doesn't require client certificates.
 */
static const char* BOGUS_CERT_PATH = "/tmp/proxysql_test_bogus_cert.pem";

static void create_bogus_cert_file() {
	FILE* f = fopen(BOGUS_CERT_PATH, "w");
	if (f) {
		fprintf(f, "this is not a valid certificate\n");
		fclose(f);
	}
}

static void remove_bogus_cert_file() {
	unlink(BOGUS_CERT_PATH);
}

static long getMonitorValue(PGconn* admin, const char* varname) {
	std::stringstream q;
	q << "SELECT Variable_Value FROM stats_pgsql_global "
		"WHERE Variable_Name='" << varname << "';";
	PGresult* res = PQexec(admin, q.str().c_str());
	if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
		PQclear(res);
		return -1;
	}
	long v = atol(PQgetvalue(res, 0, 0));
	PQclear(res);
	return v;
}

static long getConnectInterval(PGconn* admin) {
	PGresult* res = PQexec(admin,
		"SELECT Variable_Value FROM global_variables WHERE Variable_Name='pgsql-monitor_connect_interval';"
	);
	if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
		PQclear(res);
		return 60000;
	}
	long v = atol(PQgetvalue(res, 0, 0));
	PQclear(res);
	return v;
}

static bool setConnectInterval(PGconn* admin, int value) {
	std::stringstream q;
	q << "SET pgsql-monitor_connect_interval=" << value << ";";
	bool ok1 = exec_ok(admin, q.str().c_str());
	bool ok2 = exec_ok(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	usleep(10000);
	return ok1 && ok2;
}

// ============================================================================
// Part 1: Admin CRUD Operations
// ============================================================================

static void test_table_exists(PGconn* admin) {
	ok(exec_ok(admin, "SELECT * FROM pgsql_servers_ssl_params"),
		"pgsql_servers_ssl_params table exists and is queryable");
	ok(exec_ok(admin, "SELECT * FROM runtime_pgsql_servers_ssl_params"),
		"runtime_pgsql_servers_ssl_params table exists and is queryable");
}

static void test_insert_and_select(PGconn* admin) {
	cleanup_ssl_params(admin);

	ok(exec_ok(admin,
		"INSERT INTO pgsql_servers_ssl_params "
		"(hostname, port, username, ssl_ca, ssl_cert, ssl_key, "
		"ssl_crl, ssl_crlpath, ssl_protocol_version_range, comment) "
		"VALUES ('testhost', 5432, 'testuser', '/ca.crt', '/cert.crt', '/key.pem', "
		"'/crl.pem', '/crlpath', 'TLSv1.2-TLSv1.3', 'test row')"),
		"INSERT into pgsql_servers_ssl_params succeeds");

	int count = exec_count(admin, "SELECT * FROM pgsql_servers_ssl_params");
	ok(count == 1, "SELECT returns 1 row after INSERT");

	std::string val = exec_scalar(admin,
		"SELECT ssl_ca FROM pgsql_servers_ssl_params WHERE hostname='testhost'");
	ok(val == "/ca.crt", "ssl_ca column round-trips correctly");

	val = exec_scalar(admin,
		"SELECT ssl_protocol_version_range FROM pgsql_servers_ssl_params WHERE hostname='testhost'");
	ok(val == "TLSv1.2-TLSv1.3", "ssl_protocol_version_range round-trips correctly");
}

static void test_primary_key_constraint(PGconn* admin) {
	PGresult* res = PQexec(admin,
		"INSERT INTO pgsql_servers_ssl_params "
		"(hostname, port, username, ssl_ca) "
		"VALUES ('testhost', 5432, 'testuser', '/other_ca.crt')");
	bool failed = (PQresultStatus(res) != PGRES_COMMAND_OK);
	PQclear(res);
	ok(failed, "Duplicate primary key INSERT is rejected");
}

static void test_load_to_runtime(PGconn* admin) {
	ok(exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME"),
		"LOAD PGSQL SERVERS TO RUNTIME succeeds");

	int count = exec_count(admin, "SELECT * FROM runtime_pgsql_servers_ssl_params");
	ok(count == 1, "runtime table has 1 row after LOAD TO RUNTIME");

	std::string val = exec_scalar(admin,
		"SELECT ssl_ca FROM runtime_pgsql_servers_ssl_params WHERE hostname='testhost'");
	ok(val == "/ca.crt", "runtime ssl_ca matches admin table");
}

static void test_multiple_rows(PGconn* admin) {
	exec_ok(admin,
		"INSERT INTO pgsql_servers_ssl_params "
		"(hostname, port, username, ssl_ca) VALUES ('host2', 5433, 'user2', '/ca2.crt')");
	exec_ok(admin,
		"INSERT INTO pgsql_servers_ssl_params "
		"(hostname, port, username, ssl_ca) VALUES ('host3', 5434, '', '/ca3.crt')");

	ok(exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME"),
		"LOAD with multiple rows succeeds");

	int count = exec_count(admin, "SELECT * FROM runtime_pgsql_servers_ssl_params");
	ok(count == 3, "runtime table has 3 rows");
}

static void test_save_and_load_disk(PGconn* admin) {
	ok(exec_ok(admin, "SAVE PGSQL SERVERS TO DISK"), "SAVE TO DISK succeeds");

	exec_ok(admin, "DELETE FROM pgsql_servers_ssl_params");
	int count = exec_count(admin, "SELECT * FROM pgsql_servers_ssl_params");
	ok(count == 0, "admin table empty after DELETE");

	ok(exec_ok(admin, "LOAD PGSQL SERVERS FROM DISK"), "LOAD FROM DISK succeeds");

	count = exec_count(admin, "SELECT * FROM pgsql_servers_ssl_params");
	ok(count == 3, "admin table has 3 rows after LOAD FROM DISK");
}

static void test_delete_and_reload(PGconn* admin) {
	exec_ok(admin, "DELETE FROM pgsql_servers_ssl_params");
	ok(exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME"),
		"LOAD TO RUNTIME after DELETE succeeds");

	int count = exec_count(admin, "SELECT * FROM runtime_pgsql_servers_ssl_params");
	ok(count == 0, "runtime table empty after DELETE + LOAD");
}

static void test_update_and_reload(PGconn* admin) {
	exec_ok(admin,
		"INSERT INTO pgsql_servers_ssl_params "
		"(hostname, port, username, ssl_ca) VALUES ('updatehost', 5432, '', '/old_ca.crt')");
	exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");

	exec_ok(admin,
		"UPDATE pgsql_servers_ssl_params SET ssl_ca='/new_ca.crt' WHERE hostname='updatehost'");
	exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");

	std::string val = exec_scalar(admin,
		"SELECT ssl_ca FROM runtime_pgsql_servers_ssl_params WHERE hostname='updatehost'");
	ok(val == "/new_ca.crt", "UPDATE reflected in runtime after LOAD");
}

static void test_default_port(PGconn* admin) {
	cleanup_ssl_params(admin);

	exec_ok(admin,
		"INSERT INTO pgsql_servers_ssl_params "
		"(hostname, username, ssl_ca) VALUES ('defaultport', '', '/ca.crt')");

	std::string val = exec_scalar(admin,
		"SELECT port FROM pgsql_servers_ssl_params WHERE hostname='defaultport'");
	ok(val == "5432", "Default port is 5432");
}

// ============================================================================
// Part 2: End-to-End Backend SSL Connections
// ============================================================================

static bool get_backend_server(PGconn* admin, std::string& hostname, int& port) {
	PGresult* res = PQexec(admin,
		"SELECT hostname, port FROM pgsql_servers LIMIT 1");
	if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
		PQclear(res);
		return false;
	}
	hostname = PQgetvalue(res, 0, 0);
	port = atoi(PQgetvalue(res, 0, 1));
	PQclear(res);
	return true;
}

static void test_backend_ssl_baseline(PGconn* admin) {
	cleanup_ssl_params(admin);

	exec_ok(admin, "UPDATE pgsql_servers SET use_ssl=1");
	exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	usleep(500000);

	auto backend = createNewConnection(BACKEND);
	ok(backend != nullptr, "Baseline: backend connection through ProxySQL succeeds with use_ssl=1");

	if (backend) {
		PGresult* res = PQexec(backend.get(), "SELECT 1");
		ok(PQresultStatus(res) == PGRES_TUPLES_OK, "Baseline: SELECT 1 succeeds");
		PQclear(res);
	} else {
		ok(0, "Baseline: SELECT 1 succeeds (connection failed)");
	}
}

static void test_per_server_params_promoted_to_runtime(PGconn* admin) {
	std::string hostname;
	int port;
	if (!get_backend_server(admin, hostname, port)) {
		ok(0, "Per-server runtime: no backend server found");
		return;
	}

	cleanup_ssl_params(admin);

	// Insert per-server SSL params for the actual backend
	std::stringstream q;
	q << "INSERT INTO pgsql_servers_ssl_params "
		"(hostname, port, username, ssl_ca, ssl_cert, ssl_key, ssl_protocol_version_range) VALUES ('"
		<< hostname << "', " << port << ", '', '/test/ca.crt', '/test/cert.crt', '/test/key.pem', 'TLSv1.2-TLSv1.3')";
	exec_ok(admin, q.str().c_str());

	exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");

	// Verify the params appear in the runtime table for the correct server
	std::stringstream verify;
	verify << "SELECT ssl_ca, ssl_cert, ssl_key, ssl_protocol_version_range "
		"FROM runtime_pgsql_servers_ssl_params WHERE hostname='" << hostname << "' AND port=" << port;
	PGresult* res = PQexec(admin, verify.str().c_str());
	ok(PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1,
		"Per-server params for actual backend appear in runtime");

	if (PQntuples(res) == 1) {
		ok(std::string(PQgetvalue(res, 0, 0)) == "/test/ca.crt",
			"Runtime ssl_ca matches inserted value");
		ok(std::string(PQgetvalue(res, 0, 3)) == "TLSv1.2-TLSv1.3",
			"Runtime ssl_protocol_version_range matches inserted value");
	} else {
		ok(0, "Runtime ssl_ca matches inserted value");
		ok(0, "Runtime ssl_protocol_version_range matches inserted value");
	}
	PQclear(res);
}

static void test_tls_version_pin_causes_failure(PGconn* admin) {
	std::string hostname;
	int port;
	if (!get_backend_server(admin, hostname, port)) {
		ok(0, "TLS pin: no backend server found");
		return;
	}

	cleanup_ssl_params(admin);

	// Pin to TLSv1 (disabled in modern PgSQL) — connection must fail
	std::stringstream q;
	q << "INSERT INTO pgsql_servers_ssl_params "
		"(hostname, port, username, ssl_protocol_version_range) VALUES ('"
		<< hostname << "', " << port << ", '', 'TLSv1')";
	exec_ok(admin, q.str().c_str());

	exec_ok(admin, "UPDATE pgsql_servers SET use_ssl=1");
	exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	usleep(500000);

	// Use create_new_connection=1 annotation to force a new backend connection
	// that will use the per-server SSL params with TLSv1 restriction
	auto backend = createNewConnection(BACKEND);
	ok(backend != nullptr, "TLS pin: client connection to ProxySQL established");

	bool query_failed = true;
	if (backend) {
		PGresult* res = PQexec(backend.get(), "/* create_new_connection=1 */ SELECT 1");
		query_failed = (PQresultStatus(res) != PGRES_TUPLES_OK);
		if (!query_failed) {
			diag("TLS pin: query unexpectedly succeeded");
		}
		PQclear(res);
	}

	ok(query_failed, "TLS pin: query fails when per-server ssl_protocol_version_range=TLSv1");
}

static void test_per_server_overrides_global(PGconn* admin) {
	std::string hostname;
	int port;
	if (!get_backend_server(admin, hostname, port)) {
		ok(0, "Override: no backend server found");
		return;
	}

	cleanup_ssl_params(admin);

	// Per-server TLSv1 restriction should override working global config
	std::stringstream q;
	q << "INSERT INTO pgsql_servers_ssl_params "
		"(hostname, port, username, ssl_protocol_version_range) VALUES ('"
		<< hostname << "', " << port << ", '', 'TLSv1')";
	exec_ok(admin, q.str().c_str());

	exec_ok(admin, "UPDATE pgsql_servers SET use_ssl=1");
	exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	usleep(500000);

	auto backend = createNewConnection(BACKEND);
	bool query_failed = true;
	if (backend) {
		PGresult* res = PQexec(backend.get(), "/* create_new_connection=1 */ SELECT 1");
		query_failed = (PQresultStatus(res) != PGRES_TUPLES_OK);
		PQclear(res);
	}

	ok(query_failed,
		"Override: per-server TLSv1 restriction causes failure despite no global TLS restriction");
}

static void test_remove_per_server_fallback_to_global(PGconn* admin) {
	cleanup_ssl_params(admin);

	exec_ok(admin, "UPDATE pgsql_servers SET use_ssl=1");
	exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	usleep(500000);

	auto backend = createNewConnection(BACKEND);
	ok(backend != nullptr,
		"Fallback to global: after removing per-server params, connection succeeds");

	if (backend) {
		PGresult* res = PQexec(backend.get(), "SELECT 1");
		ok(PQresultStatus(res) == PGRES_TUPLES_OK,
			"Fallback to global: SELECT 1 succeeds");
		PQclear(res);
	} else {
		ok(0, "Fallback to global: SELECT 1 succeeds (connection failed)");
	}
}

static void test_monitor_ssl_with_per_server_params(PGconn* admin) {
	cleanup_ssl_params(admin);

	exec_ok(admin, "UPDATE pgsql_servers SET use_ssl=1");
	exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");

	long initial_ssl = getMonitorValue(admin, "PgSQL_Monitor_ssl_connections_OK");
	diag("Initial PgSQL_Monitor_ssl_connections_OK: %ld", initial_ssl);

	// Wait for at least 2 monitor cycles (interval was set to 2000ms in main)
	usleep(5000000); // 5 seconds

	long after_ssl = getMonitorValue(admin, "PgSQL_Monitor_ssl_connections_OK");
	diag("After PgSQL_Monitor_ssl_connections_OK: %ld", after_ssl);

	ok(after_ssl > initial_ssl,
		"Monitor SSL counter increased with use_ssl=1 and no per-server row");
}

/**
 * @brief Verify the monitor path actually consults pgsql_servers_ssl_params.
 *
 * Inserts a per-server row matching the actual backend with username=''
 * (so the monitor's empty-username fallback in get_Server_SSL_Params hits
 * it) and an ssl_protocol_version_range pinned to TLSv1 — disabled in
 * modern PostgreSQL builds. If the monitor honors per-server params and
 * propagates tls_version into its libpq conninfo, monitor SSL connections
 * must fail and the OK counter must NOT advance over the wait window.
 * If the monitor were ignoring per-server params (or dropping tls_version),
 * the counter would keep climbing, which is the regression we want to catch.
 */
static void test_monitor_uses_per_server_row(PGconn* admin) {
	std::string hostname;
	int port;
	if (!get_backend_server(admin, hostname, port)) {
		ok(0, "Monitor per-server: no backend server found");
		ok(0, "Monitor per-server: cleanup restores monitor SSL OK");
		return;
	}

	cleanup_ssl_params(admin);
	exec_ok(admin, "UPDATE pgsql_servers SET use_ssl=1");
	exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");

	// Insert a per-server row matching the backend, with TLSv1 pin so the
	// monitor's connection attempt must fail if tls_version flows through.
	std::stringstream q;
	q << "INSERT INTO pgsql_servers_ssl_params "
		"(hostname, port, username, ssl_protocol_version_range) VALUES ('"
		<< hostname << "', " << port << ", '', 'TLSv1')";
	exec_ok(admin, q.str().c_str());
	exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");

	// Drain any monitor connect cycle scheduled with the pre-LOAD config.
	// Why: the monitor thread may already be mid-cycle when LOAD runs; that
	// in-flight connect was scheduled with the OLD SSL params (no TLSv1 pin)
	// and will succeed and bump the counter AFTER we sample ok_before. Wait
	// until two consecutive 1s samples are equal — meaning the new config
	// is in effect and the counter has plateaued.
	long ok_before = getMonitorValue(admin, "PgSQL_Monitor_ssl_connections_OK");
	for (int i = 0; i < 10; i++) {
		usleep(1000000); // 1s — longer than the test's monitor connect interval
		long sample = getMonitorValue(admin, "PgSQL_Monitor_ssl_connections_OK");
		if (sample == ok_before) break;
		ok_before = sample;
	}
	diag("With TLSv1 per-server pin, ssl OK before wait (post-drain): %ld", ok_before);

	usleep(5000000); // 5 seconds — multiple monitor cycles

	long ok_after = getMonitorValue(admin, "PgSQL_Monitor_ssl_connections_OK");
	diag("With TLSv1 per-server pin, ssl OK after wait:  %ld (delta=%ld)",
		ok_after, ok_after - ok_before);

	ok(ok_after == ok_before,
		"Monitor per-server: SSL OK counter does NOT advance when "
		"per-server row pins ssl_protocol_version_range to TLSv1");

	// Phase 2: remove the row and confirm the monitor recovers, proving
	// the previous failure was caused by the per-server row and not by
	// some unrelated breakage.
	cleanup_ssl_params(admin);
	exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");

	long recover_before = getMonitorValue(admin, "PgSQL_Monitor_ssl_connections_OK");
	usleep(5000000);
	long recover_after = getMonitorValue(admin, "PgSQL_Monitor_ssl_connections_OK");
	diag("After cleanup, ssl OK recovered from %ld to %ld",
		recover_before, recover_after);

	ok(recover_after > recover_before,
		"Monitor per-server: SSL OK counter resumes advancing after "
		"removing the per-server row");
}

// ============================================================================
// Part 3: Cluster Query Support
// ============================================================================

/**
 * @brief Test that the PROXY_SELECT cluster query for pgsql_servers_ssl_params
 *        returns correct data via the MySQL admin port.
 *
 * Cluster sync uses MySQL-protocol admin connections. The PROXY_SELECT query
 * is intercepted by Admin_Handler and returns data from
 * get_current_pgsql_table() or dump_table_pgsql().
 */
static void test_cluster_query_ssl_params(PGconn* pgsql_admin) {
	cleanup_ssl_params(pgsql_admin);

	// Insert test data via PgSQL admin and load to runtime
	exec_ok(pgsql_admin,
		"INSERT INTO pgsql_servers_ssl_params "
		"(hostname, port, username, ssl_ca, ssl_cert, ssl_key, ssl_protocol_version_range, comment) "
		"VALUES ('cluster-host', 5432, 'clusteruser', '/certs/ca.crt', '/certs/cert.crt', "
		"'/certs/key.pem', 'TLSv1.2-TLSv1.3', 'cluster test')");
	exec_ok(pgsql_admin, "LOAD PGSQL SERVERS TO RUNTIME");

	// Connect to MySQL admin port and execute the cluster query
	MYSQL* mysql_admin = mysql_init(NULL);
	if (!mysql_real_connect(mysql_admin, cl.admin_host, cl.admin_username,
			cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		ok(0, "Cluster query: MySQL admin connection failed: %s", mysql_error(mysql_admin));
		ok(0, "Cluster query: skipping result check");
		ok(0, "Cluster query: skipping field check");
		mysql_close(mysql_admin);
		cleanup_ssl_params(pgsql_admin);
		return;
	}

	ok(1, "Cluster query: MySQL admin connection established");

	// Execute the PROXY_SELECT cluster query
	const char* cluster_query =
		"PROXY_SELECT hostname, port, username, ssl_ca, ssl_cert, ssl_key, "
		"ssl_crl, ssl_crlpath, ssl_protocol_version_range, comment "
		"FROM runtime_pgsql_servers_ssl_params ORDER BY hostname, port, username";

	int rc = mysql_query(mysql_admin, cluster_query);
	if (rc != 0) {
		ok(0, "Cluster query: PROXY_SELECT failed: %s", mysql_error(mysql_admin));
		ok(0, "Cluster query: skipping field check");
		mysql_close(mysql_admin);
		cleanup_ssl_params(pgsql_admin);
		return;
	}

	MYSQL_RES* result = mysql_store_result(mysql_admin);
	ok(result != NULL && mysql_num_rows(result) == 1,
		"Cluster query: PROXY_SELECT returns 1 row");

	if (result && mysql_num_rows(result) == 1) {
		MYSQL_ROW row = mysql_fetch_row(result);
		bool hostname_ok = (row[0] && strcmp(row[0], "cluster-host") == 0);
		bool ssl_ca_ok = (row[3] && strcmp(row[3], "/certs/ca.crt") == 0);
		bool tls_range_ok = (row[8] && strcmp(row[8], "TLSv1.2-TLSv1.3") == 0);

		ok(hostname_ok && ssl_ca_ok && tls_range_ok,
			"Cluster query: returned row has correct hostname, ssl_ca, and ssl_protocol_version_range");
	} else {
		ok(0, "Cluster query: skipping field check (no rows)");
	}

	if (result) mysql_free_result(result);
	mysql_close(mysql_admin);

	cleanup_ssl_params(pgsql_admin);
}

// ============================================================================
// main
// ============================================================================

int main(int argc, char** argv) {
	plan(37);

	if (cl.getEnv()) {
		BAIL_OUT("Failed to get environment variables");
		return exit_status();
	}

	auto admin = createNewConnection(ADMIN);
	ok(admin != nullptr, "Admin connection created");

	if (!admin) {
		BAIL_OUT("Cannot proceed without admin connection");
		return exit_status();
	}

	PGconn* a = admin.get();

	// Part 1: Admin CRUD
	diag("---- Part 1: Admin CRUD Operations ----");
	test_table_exists(a);
	test_insert_and_select(a);
	test_primary_key_constraint(a);
	test_load_to_runtime(a);
	test_multiple_rows(a);
	test_save_and_load_disk(a);
	test_delete_and_reload(a);
	test_update_and_reload(a);
	test_default_port(a);

	// Part 2: End-to-End SSL
	diag("---- Part 2: End-to-End Backend SSL ----");
	test_backend_ssl_baseline(a);
	test_per_server_params_promoted_to_runtime(a);
	test_tls_version_pin_causes_failure(a);
	test_per_server_overrides_global(a);
	test_remove_per_server_fallback_to_global(a);

	// Configure monitor: use 'postgres' user which is accepted by the
	// backend, set a tight connect_interval so cycles run within the test
	// wait window. Restore original values afterwards.
	//
	// We deliberately do NOT change pgsql-monitor_username /
	// pgsql-monitor_password. An earlier version of this test set them
	// to 'postgres'/'postgres' on the assumption that the backend had a
	// postgres user with password 'postgres', but the actual CI infra
	// (docker-pgsql16-single) randomizes POSTGRES_PASSWORD per container
	// startup (e.g. "05e792e51d"), so the hardcoded credentials never
	// authenticated and every monitor connect failed with
	//   FATAL: password authentication failed for user "postgres"
	// The default monitor/monitor user works against the infra's
	// pg_hba.conf and is what the initial (pre-test) connect check
	// already uses successfully.
	long original_connect_interval = getConnectInterval(a);
	// Read current monitor username for diagnostic logging only.
	std::string monitor_username = exec_scalar(a,
		"SELECT Variable_Value FROM global_variables WHERE Variable_Name='pgsql-monitor_username'");
	diag("Current monitor: user=%s interval=%ld ms",
		monitor_username.c_str(), original_connect_interval);

	setConnectInterval(a, 2000);
	exec_ok(a, "UPDATE pgsql_servers SET use_ssl=1");
	exec_ok(a, "LOAD PGSQL SERVERS TO RUNTIME");
	usleep(3000000); // let the monitor pick up the new settings

	test_monitor_ssl_with_per_server_params(a);
	test_monitor_uses_per_server_row(a);

	// Restore original connect interval. Monitor username/password are
	// no longer touched by this test - see comment above - so there's
	// nothing to restore there.
	setConnectInterval(a, (int)original_connect_interval);

	// Part 3: Cluster query support
	diag("---- Part 3: Cluster Query Support ----");
	test_cluster_query_ssl_params(a);

	// Cleanup
	remove_bogus_cert_file();
	cleanup_ssl_params(a);
	exec_ok(a, "UPDATE pgsql_servers SET use_ssl=0");
	exec_ok(a, "LOAD PGSQL SERVERS TO RUNTIME");

	return exit_status();
}
