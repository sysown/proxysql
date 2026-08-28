/**
 * @file test_pgsql_replication_lag-t.cpp
 * @brief POC: Test for PostgreSQL replication lag monitoring and shunning.
 * @details This is a test POC for new infra for testing PostgreSQL monitoring and SHUNNING. Correctness can
 *   be improved in multiple points, but for now, this provides coverage and automated testing for the feature.
 */

#include <cstring>
#include <fstream>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "libpq-fe.h"
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

#define _TO_S(s) ( std::to_string(s) )

// PostgreSQL query execution with logging - similar to MYSQL_QUERY_T
#define PG_QUERY_T(conn, query) \
	do { \
		diag("%s:%d: Executing query: %s", __func__, __LINE__, query); \
		PGresult* res = PQexec(conn, query); \
		if (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
					__FILE__, __LINE__, PQerrorMessage(conn)); \
			PQclear(res); \
			return EXIT_FAILURE; \
		} \
		PQclear(res); \
	} while(0)

PGconn* create_new_conn(const CommandLine& cl, bool with_ssl) {
	std::stringstream ss;

	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port;
	ss << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password;
	ss << " sslmode=disable";
	ss << " dbname=sysbench";

	diag("Creating PostgreSQL connection   params=\"%s\"", ss.str().c_str());
	PGconn* conn { PQconnectdb(ss.str().c_str()) };
	const bool res = (conn && PQstatus(conn) == CONNECTION_OK);

	if (res) {
		return conn;
	} else {
		fprintf(stderr, "File %s, line %d, Error: Connection failed\n", __FILE__, __LINE__);
		PQfinish(conn);
		return nullptr;
	}
}

const char* REPL_PORT { get_env_str("TAP_REPLICA_PORT", "15433") };
const string TEST_DATADIR { get_env_str("TAP_WORKDIR", ".") + _S("/test_pgsql_replication_lag") };
const int32_t MAX_REPL_LAG { 3 };

int test_replication_lag(
	const CommandLine& cl, MYSQL* admin, PGconn* pgconn, int32_t max_repl_lag, int32_t max_count
) {
	diag("Testing PostgreSQL replication lag check   max_count=%d", max_count);

	MYSQL_QUERY_T(admin, ("SET pgsql-monitor_replication_lag_count=" + _TO_S(max_count)).c_str());
	MYSQL_QUERY_T(admin, "LOAD PGSQL VARIABLES TO RUNTIME");

	// Get ProxySQL log path
	const string PROXYSQL_LOG_PATH {
		get_env_str("REGULAR_INFRA_DATADIR", "/tmp") + _S("/proxysql.log")
	};

	// Get pgsql-monitor_replication_lag_interval
	diag("Retrieving pgsql-monitor_replication_lag_interval");
	const ext_val_t<int32_t> monitor_interval {
		mysql_query_ext_val(admin,
			"SELECT variable_value FROM runtime_global_variables WHERE"
				" variable_name='pgsql-monitor_replication_lag_interval'",
			int32_t(-1))
	};
	CHECK_EXT_VAL(admin, monitor_interval);
	diag("pgsql-monitor_replication_lag_interval = %d ms", monitor_interval.val);

	// Wait for servers to be ONLINE (in case of previous execution)
	diag("Waiting until target replica is ONLINE (catchup with replication)...");
	{
		const string q_st_check {
			"SELECT IF("
				"(SELECT status FROM runtime_pgsql_servers WHERE port=" + _S(REPL_PORT) + ")=\"ONLINE\","
				" TRUE,"
				" FALSE"
			")"
		};
		uint32_t timeout = 60;
		uint32_t j = 0;

		for (uint32_t i = 0; i < 5; i++) {
			diag("Issuing check query   query=\"%s\"", q_st_check.c_str());
			const ext_val_t<int> is_online { mysql_query_ext_val(admin, q_st_check, 0) };
			CHECK_EXT_VAL(admin, is_online);

			diag("Check finished with result   val=\"%d\"", is_online.val);
			if (!is_online.val) {
				i = 0;
			}

			if (j > timeout) {
				break;
			} else {
				j++;
			}

			sleep(1);
		}
	}

	// Open log file before waiting
	diag("Opening ProxySQL log file for SHUNNED detection   logfile=\"%s\"", PROXYSQL_LOG_PATH.c_str());
	std::fstream logfile_shunn;
	int of_err = open_file_and_seek_end(PROXYSQL_LOG_PATH, logfile_shunn);
	if (of_err != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	diag("Opening ProxySQL log file for NOT_SHUNNING detection");
	std::fstream logfile_not_shunn;
	of_err = open_file_and_seek_end(PROXYSQL_LOG_PATH, logfile_not_shunn);
	if (of_err != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	// Delete and insert data
	diag("Inserting test data to trigger replication lag");
	PG_QUERY_T(pgconn, "DELETE FROM sbtest1");
	PG_QUERY_T(pgconn, "INSERT INTO sbtest1 (k, c, pad) VALUES (1, 'x', 'y')");
	PG_QUERY_T(pgconn,
		"WITH RECURSIVE gen(n) AS ("
			" SELECT 1"
			" UNION ALL"
			" SELECT n + 1"
			" FROM gen"
			" WHERE n < 48000"
		")"
		"INSERT INTO sbtest1 (k, c, pad)"
			"SELECT"
			" (random() * 10000)::int,"
			" lpad(md5(random()::text), 120, 'x')::char(120),"
			" lpad(md5(random()::text), 60,  'y')::char(60)"
			"FROM gen"
	);

	// Wait for monitoring interval
	diag("Waiting for replication lag detection");
	vector<int32_t> repl_lags {};

	for (int32_t i = 0; i < 20; i++) {
		const ext_val_t<int32_t> repl_lag {
			mysql_query_ext_val(admin,
				"SELECT repl_lag FROM pgsql_server_replication_lag_log "
					"WHERE port=" + _S(REPL_PORT) + " ORDER BY time_start_us DESC LIMIT 1",
				0
			)
		};
		CHECK_EXT_VAL(admin, repl_lag);
		diag("Fetched current replication lag   repl_lag=%d", repl_lag.val);

		if (repl_lag.val > max_repl_lag) {
			repl_lags.push_back(repl_lag.val);
		} else {
			repl_lags.clear();
		}

		if (repl_lags.size() >= max_count && repl_lags.size() > 3) {
			diag(
				"Consistent replication lag detected; server should be SHUNNED   repl_lags=%ld",
				repl_lags.size()
			);
			break;
		} else {
			diag(
				"Found replication lag; waiting for more entries   repl_lags=%ld",
				repl_lags.size()
			);
		}
		sleep(1);
	}

	// Check server status via runtime_pgsql_servers
	diag("Checking server status in runtime_pgsql_servers");
	vector<int32_t> shunned {};
	for (uint32_t i = 0; i < 6; i++) {
		const ext_val_t<string> server_status {
			mysql_query_ext_val(admin,
				"SELECT status FROM runtime_pgsql_servers WHERE port=" + _S(REPL_PORT),
				string("UNKNOWN")
			)
		};
		CHECK_EXT_VAL(admin, server_status);
		diag("Fetched current runtime_server_status   status=\"%s\"", server_status.val.c_str());

		shunned.push_back(server_status.val == "SHUNNED");
		sleep(1);
	}

	const int32_t times { std::reduce(shunned.begin(), shunned.end()) };
	ok(times >= 1, "Server status should have been SHUNNED at least one check   times=%d", times);

	// Check logs for shunning message
	diag("Checking ProxySQL log for shunning message");
	const string shun_regex {
		".*\\[WARNING\\] Shunning server [^\\s]+:" + _S(REPL_PORT) + " from HG 1 with replication lag of.*"
	};
	const string not_shun_regex {
		".*\\[INFO\\] Not shunning server [^\\s]+:" + _S(REPL_PORT) + " from HG 1 with replication lag of.*"
	};

	const auto& [_0, not_shun_lines] = get_matching_lines(logfile_not_shunn, not_shun_regex);
	const auto& [_1, shun_lines] = get_matching_lines(logfile_shunn, shun_regex);

	ok(
		shun_lines.size() > 0,
		"ProxySQL should have SHUNNED the server   shunn_count=%ld",
		shun_lines.size()
	);
	for (const auto& [pos, line, match] : shun_lines) {
		diag("Found log line   line=`%s`", line.c_str());
	}

	if (max_count > 1) {
		ok(
			not_shun_lines.size() >= max_count - 1,
			"SHUNNING attempts should exceed 'monitor_replication_lag_count'   nshunn_count=%ld",
			not_shun_lines.size()
		);
		for (const auto& [pos, line, match] : not_shun_lines) {
			diag("Found log line   line=`%s`", line.c_str());
		}
	} else {
		ok(
			not_shun_lines.size() == 0,
			"SHUNNING attempts should be only one; no logging required   nshunn_count=%ld",
			not_shun_lines.size()
		);
	}

	// Cleanup
	logfile_shunn.close();
	logfile_not_shunn.close();

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(3 * 2);

	// Connect to ProxySQL admin interface
	MYSQL* admin = mysql_init(NULL);

	diag("Creating connection to Admin   host=\"%s\" port=%d", cl.host, cl.admin_port);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY_T(admin, "UPDATE mysql_servers SET max_replication_lag=0");
	MYSQL_QUERY_T(admin,
		("UPDATE pgsql_servers SET max_replication_lag=" + _TO_S(MAX_REPL_LAG) +
			" WHERE port=" + _S(REPL_PORT)).c_str()
	);
	MYSQL_QUERY_T(admin, "LOAD PGSQL SERVERS TO RUNTIME");

	// Create connection to PostgreSQL
	PGconn* pgconn = create_new_conn(cl, false);
	if (pgconn == nullptr) {
		return EXIT_FAILURE;
	}

	PG_QUERY_T(pgconn,
		"CREATE TABLE IF NOT EXISTS sbtest1 ("
		" id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,"
		" k integer DEFAULT 0 NOT NULL,"
		" c character(120) DEFAULT ''::bpchar NOT NULL,"
		" pad character(60) DEFAULT ''::bpchar NOT NULL"
		")"
	);

	MYSQL_QUERY_T(admin, "SET pgsql-monitor_replication_lag_interval=1000");
	MYSQL_QUERY_T(admin, "LOAD PGSQL VARIABLES TO RUNTIME");

	// Execute the setup script
	{
		const string setup_script_path { TEST_DATADIR + "/setup_primary_vintf_throttle.sh" };
		diag("Executing vintf throttling setup script   path=\"%s\"", setup_script_path.c_str());

		int exec_rc = system(setup_script_path.c_str());
		if (exec_rc != 0) {
			diag("ERROR: Script execution failed; Aborting further testing   err=%d", exec_rc);
			// Continue anyway - the script may have already been run
			return exit_status();
		}
	}

	test_replication_lag(cl, admin, pgconn, MAX_REPL_LAG, 1);
	test_replication_lag(cl, admin, pgconn, MAX_REPL_LAG, 3);

	// Execute the cleanup script
	{
		const string del_script_path { TEST_DATADIR + "/delete_primary_vintf_throttle.sh" };
		diag("Executing vintf throttling setup script   path=\"%s\"", del_script_path.c_str());

		int exec_rc = system(del_script_path.c_str());
		if (exec_rc != 0) {
			diag("ERROR: Script execution failed; This could compromise further tests!   err=%d", exec_rc);
			// Continue anyway - the script may have already been run
			return exit_status();
		}
	}

	PQfinish(pgconn);
	mysql_close(admin);

	return exit_status();
}
