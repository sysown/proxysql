/**
 * @file test_match_eof_conn_cap.cpp
 * @brief Checks that ProxySQL correctly matches capabilities when matching client and backend conns.
 * @details When a client session requires a backend connection, it requests it to the connection pool.
 *   A filtering (via `MySQL_Connection::match_tracked_options`) takes place for conn selection, if no
 *   suitable conn is found, it should be created with the requested session options. This test checks this
 *   logic correctness and exercises it for all possible combinations of client and backend conns capabilities
 *   (`CLIENT_DEPRECATE_EOF`). For doing this, the test:
 *       1. Configs ProxySQL as MySQL backend of itself, via the `SQLite3` interface. This way, support for
 *       all frontend-backend capabilities combinations can be tested with a single instance.
 *       2. Configs a client user with 'fast_forward'. Since fast-forward is relevant for conn-matching, the
 *       config for the user will be switched (on/off) for each test, to exercise different combinations.
 *   Then, the test performs the following checks for conn creation:
 *       1. Creates a conn to ProxySQL with one of the possible caps combination.
 *       1. Switches (or not) the capability support for client/backend conns.
 *       2. Attempts to perform a query, forcing the creation of a backend conn.
 *       3. Performs multiple checks over the query and ProxySQL error log metrics:
 *          - Checks if the query was expected to fail/succeed (conn creation).
 *          - Checks error log for conn creation failures (caps mismatch).
 *          - Checks audit log for number of conn received (SQLite3 backend ProxySQL-ProxySQL).
 *          - Checks stats on connection creation to be increased by the expected amount.
 *    A similar flow is exercised for conn matching, with the difference that the previous steps are performed
 *    against an already warm-up conn-pool.
 *
 *    For being able to test `CLIENT_DEPRECATE_EOF` disabled, and ensuring the correct handling of sessions by
 *    ProxySQL the test is compiled against both `libmaridb` and `libmysql`. Executing both binaries **is
 *    required** as right now it's the only way to exercise all the possibilities.
 *
 *    NOTE: The checks on this test are oriented for the capability `CLIENT_DEPRECATE_EOF`. Yet, the flow
 *    present in this test is more generic, as it should match the one for any other client capability that
 *    requires to be matched between frontend and backend conns. This is even more relevant if the match is
 *    required for an smooth transition between regular and `fast-forward` sessions, as it's the case for
 *    `CLIENT_DEPRECATE_EOF`.
 */

#include <algorithm>
#include <dirent.h>
#include <cstring>
#include <fstream>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <vector>
#include <algorithm>
#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::fstream;
using std::string;
using std::vector;

#define _S(s) ( std::string {s} )
#define _TO_S(s) ( std::to_string(s) )

#define CHECK_EXT_VAL(val)\
	do {\
		if (val.err) {\
			diag("%s:%d: Query failed   err=\"%s\"", __func__, __LINE__, val.str.c_str());\
			return EXIT_FAILURE;\
		}\
	} while(0)

MYSQL* create_mysql_conn(const conn_opts_t& opts) {
	const char* host { opts.host.c_str() };
	const char* user { opts.user.c_str() };
	const char* pass { opts.pass.c_str() };

	MYSQL* conn = mysql_init(NULL);

#ifndef LIBMYSQL_HELPER8
	conn->options.client_flag &= ~CLIENT_DEPRECATE_EOF;
#endif

#ifdef LIBMYSQL_HELPER8
		{
			enum mysql_ssl_mode ssl_mode = SSL_MODE_DISABLED;
			mysql_options(conn, MYSQL_OPT_SSL_MODE, &ssl_mode);
		}
#endif

	if (!mysql_real_connect(conn, host, user, pass, NULL, opts.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(conn));
		return NULL;
	}

	return conn;
}

#define SELECT_RUNTIME_VAR "SELECT variable_value FROM runtime_global_variables WHERE variable_name="
#define TAP_NAME "TAP_FAST_FORWARD_CONNS_MATCHING_FLAGS___"

// Test specific ENV variables
const int HG_ID = get_env_int(TAP_NAME"MYSQL_SERVER_HOSTGROUP", 0);
const int SQLITE3_HG = get_env_int(TAP_NAME"SQLITE3_HOSTGROUP", 1459);
const int SQLITE3_PORT = get_env_int(TAP_NAME"SQLITE3_HOSTGROUP", 6030);
const int CONN_POOL_WARNMUP = get_env_int(TAP_NAME"CONN_POOL_WARNMUP", 10);
const char* FF_USER = get_env_str(TAP_NAME"FF_USER", "sbtest2");
const char* FF_PASS = get_env_str(TAP_NAME"FF_PASS", "sbtest2");
const int RETRIES_DELAY = get_env_int(TAP_NAME"CONNECT_RETRIES_DELAY", 500);
const int TO_SERVER_MAX = get_env_int(TAP_NAME"CONNECT_TIMEOUT_SERVER_MAX", 2000);

// Not specific ENV variables
const string PROXYSQL_LOG_PATH { get_env_str("REGULAR_INFRA_DATADIR", "/tmp/") + _S("/proxysql.log") };
const string PROXYSQL_AUDIT_DIR { get_env_str("REGULAR_INFRA_DATADIR", "/tmp/datadir") };

void dump_as_table(MYSQL* conn, const string& msg, const std::string& query) {
	int rc = mysql_query_t(conn, query.c_str());
	if (rc) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(conn));
		exit(1);
	}

	MYSQL_RES* myres { mysql_store_result(conn) };
	diag("%s\n%s", msg.c_str(), dump_as_table(myres).c_str());
	mysql_free_result(myres);
}

void run_setup_query(MYSQL* conn, const string& query) {
	int rc = mysql_query_t(conn, query.c_str());
	if (rc) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(conn));
		exit(1);
	}
}

const vector<string>& mysql_variables_setup {
	"SET mysql-have_ssl='false'",
	"LOAD MYSQL VARIABLES TO RUNTIME",
};

const vector<string>& sqlite3_server_setup {
	"DELETE FROM mysql_servers WHERE hostgroup_id = " + _TO_S(SQLITE3_HG),
	"INSERT INTO mysql_servers (hostgroup_id, hostname, port, use_ssl)"
		" VALUES (" + _TO_S(SQLITE3_HG) + ", '127.0.0.1', " + _TO_S(SQLITE3_PORT) + ", 0)",
	"LOAD MYSQL SERVERS TO RUNTIME",

	"DELETE FROM mysql_users WHERE username = '" + _S(FF_USER) + "'",
	"INSERT INTO mysql_users (username,password,fast_forward,default_hostgroup)"
		" VALUES ('" + _S(FF_USER) + "','" + _S(FF_PASS) + "',1," + _TO_S(SQLITE3_HG) + ")",
	"LOAD MYSQL USERS TO RUNTIME",
};

int wait_for_conn_pool_st(MYSQL* admin, int32_t tg_hg, int32_t count) {
	int to = wait_for_cond(admin,
		"SELECT IIF("
			"(SELECT SUM(ConnUsed) + SUM(ConnFree)"
				" FROM stats_mysql_connection_pool"
				" WHERE hostgroup=" + _TO_S(tg_hg) + ")=" + _TO_S(count) + ","
			" TRUE, FALSE"
		")",
		10
	);

	if (to == EXIT_FAILURE) {
		diag("Waiting for conn_pool status failed   tg_hg=%d conn_count=%d", tg_hg, count);
		dump_as_table(admin, "'stats_mysql_connection_pool' status after wait:",
			"SELECT hostgroup, srv_host, srv_port, ConnFree, ConnUsed, ConnOK, ConnERR"
				" FROM stats_mysql_connection_pool"
		);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

const string SELECT_CONN_SUM {
	"SELECT SUM(ConnUsed) + SUM(ConnFree) FROM stats_mysql_connection_pool"
		" WHERE hostgroup='" + std::to_string(SQLITE3_HG) + "'"
};

const string CONN_POOL_HG_STATUS {
	"SELECT hostgroup, srv_host, srv_port, ConnFree, ConnUsed, ConnOK, ConnERR"
		" FROM stats_mysql_connection_pool WHERE hostgroup='" + std::to_string(SQLITE3_HG) + "'"
};

int conn_pool_cleanup(MYSQL* admin, int tg_hg, int count) {
	ext_val_t<int> hg_conn_sum { mysql_query_ext_val(admin, SELECT_CONN_SUM, -1) };

	if (hg_conn_sum.err != EXIT_SUCCESS) {
		const string err { get_ext_val_err(admin, hg_conn_sum) };
		diag("Fetching conn_pool status failed   err:`%s`", err.c_str());
		return EXIT_FAILURE;
	}

	diag("Checking conn_pool status   ConnUsed+ConnFree=%d tg=%d", hg_conn_sum.val, count);

	if (hg_conn_sum.val >= 1) {
		MYSQL_QUERY_T(admin,
			"UPDATE mysql_servers SET max_connections=" + _TO_S(count)
				+ " WHERE hostgroup_id=" + _TO_S(SQLITE3_HG)
		);
		MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

		int rc = wait_for_conn_pool_st(admin, tg_hg, count);

		if (rc == EXIT_SUCCESS) {
			MYSQL_QUERY_T(admin,
				"UPDATE mysql_servers SET max_connections=" + _TO_S(1000)
					+ " WHERE hostgroup_id=" + _TO_S(SQLITE3_HG)
			);
			MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");
		}

		return rc;
	}

	return EXIT_SUCCESS;
}

const vector<string> test_conn_creation___mysql_config {
	"SET mysql-connect_retries_delay=" + _TO_S(RETRIES_DELAY),
	"SET mysql-connect_timeout_server=" + _TO_S(100),
	"SET mysql-connect_timeout_server_max=" + _TO_S(TO_SERVER_MAX),
	"LOAD MYSQL VARIABLES TO RUNTIME"
};

const char* get_ext (const char *fspec) {
	const char* e { strrchr (fspec, '.') };

	if (e == NULL) {
		return "";
	} else {
		return e;
	}
}

string find_latest_split(const std::string &dir_path, const string& prefix) {
	DIR *dir = opendir(dir_path.c_str());
	if (!dir) {
		printf("Failed to open directory   path=\"%s\"", dir_path.c_str());
		return {};
	}

	struct dirent* entry { nullptr };
	string latest_split_fname {};
	uint64_t latest_split_ext { 0 };

	while ((entry = readdir(dir)) != nullptr) {
		const string fname { entry->d_name };

		if (fname == "." || fname == "..") {
			continue;
		}

		if (fname.rfind(prefix) == 0) {
			const string ext { get_ext(fname.c_str()) };
			const string e_ext { ext.size() > 1 ? ext.substr(1) : "" };

			errno = 0;
			char* p_end { nullptr };
			const uint64_t ext_val { std::strtoull(e_ext.c_str(), &p_end, 10) };

			if (ext.c_str() == p_end) {
				continue;
			} else if (latest_split_ext < ext_val) {
				latest_split_ext = ext_val;
				latest_split_fname = fname;
			}
		}
	}

	closedir(dir);

	return latest_split_fname;
}

struct pool_cnf_t {
	bool warmup { false };
	uint32_t conn_caps { 0 };
};

struct conn_conf_t {
	const CommandLine& cl;
	bool fast_forward { false };
	uint32_t conn_caps { 0 };
};

/**
 * @details
 *   Scenario 1 -> 0:
 *   Should be tested through simple config and dynamic (on-the-fly) switch. When demanding the scenario, no
 *   conn should be found for either case (backend doesn't support either ProxySQL supports the creation). We
 *   need to test conn creation and conn_pool warmup here.
 *
 *   Scenario 0 -> 1:
 *   ProxySQL won't allow a mismatch **for conn creation**, since the backend connection support is
 *   automatically disabled based on client requirements. This scenario can still be tested with a warmup
 *   connection pool. Dynamic switch shouldn't make a difference here as it's only relevant for connection
 *   creation.
 */
struct proxy_cnf_t {
	bool cli_depr_eof { false };
	bool srv_depr_eof { false };
	bool force_mismatch { false };
};

struct test_cnf_t {
	pool_cnf_t pool_status;
	conn_conf_t conn_conf;
	proxy_cnf_t proxy_conf;
};

vector<proxy_cnf_t> gen_all_proxy_cnfs() {
	vector<vector<bool>> all_bin_vec { get_all_bin_vec(4) };
	std::sort(all_bin_vec.begin(), all_bin_vec.end());

	vector<proxy_cnf_t> all_proxy_cnfs {};
	for (const vector<bool>& bin_vec : all_bin_vec) {
		all_proxy_cnfs.push_back({ bin_vec[3], bin_vec[2], bin_vec[1] });
	}

	return all_proxy_cnfs;
}

string to_string(const pool_cnf_t& st) {
	return "{"
		"\"is_warmup\": " + _TO_S(st.warmup) + ",\"conn_caps\":" + _TO_S(st.conn_caps) +
	"}";
}

string to_string(const conn_conf_t& cnf) {
	return "{"
		"\"fast_forward\": " + _TO_S(cnf.fast_forward) + ",\"conn_caps\":" + _TO_S(cnf.conn_caps) +
	"}";
}

string to_string(const proxy_cnf_t& cnf) {
	return "{"
		"\"client_deprecate_eof\": " + _TO_S(cnf.cli_depr_eof) +
		",\"server_deprecate_eof\":" + _TO_S(cnf.srv_depr_eof) +
		",\"force_mismatch\":" + _TO_S(cnf.force_mismatch) +
	"}";
}

int apply_proxy_conf(MYSQL* admin, const proxy_cnf_t& cnf) {
	MYSQL_QUERY_T(admin, "SET mysql-enable_client_deprecate_eof=" + _TO_S(cnf.cli_depr_eof));
	MYSQL_QUERY_T(admin, "SET mysql-enable_server_deprecate_eof=" + _TO_S(cnf.srv_depr_eof));
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	return EXIT_SUCCESS;
}

string to_string(const test_cnf_t& test_conf) {
	return "{"
		"\"pool_status\":" + to_string(test_conf.pool_status) +
		",\"conn_conf\":" + to_string(test_conf.conn_conf) +
		",\"proxy_conf\":" + to_string(test_conf.proxy_conf) +
	"}";
}

int test_conn_acquisition(MYSQL* admin, const test_cnf_t& test_conf) {
	const conn_conf_t& conn_cnf { test_conf.conn_conf };
	const pool_cnf_t& pool_st { test_conf.pool_status };
	const proxy_cnf_t& proxy_cnf { test_conf.proxy_conf };

	diag("Started '%s'   %s", __func__, to_string(test_conf).c_str());

	diag("Setting test global 'mysql-variables'   test='%s'", __func__);
	std::for_each(test_conn_creation___mysql_config.begin(), test_conn_creation___mysql_config.end(),
		[&admin] (const string& q) { return run_setup_query(admin, q); }
	);

	//                     UPDATE GENERIC TEST CONFIG
	///////////////////////////////////////////////////////////////////////////
	const ext_val_t<int32_t> retries_delay {
		mysql_query_ext_val(admin, SELECT_RUNTIME_VAR"'mysql-connect_retries_delay'", -1)
	};
	CHECK_EXT_VAL(retries_delay);
	const ext_val_t<int32_t> to_server_max {
		mysql_query_ext_val(admin, SELECT_RUNTIME_VAR"'mysql-connect_timeout_server_max'", -1)
	};
	CHECK_EXT_VAL(to_server_max);
	///////////////////////////////////////////////////////////////////////////

	diag(
		"Update 'fast-forward' for testing user   user=\"%s\" fast_forward=%d",
		FF_USER, conn_cnf.fast_forward
	);
	MYSQL_QUERY_T(admin,
		"UPDATE mysql_users SET fast_forward=" + _TO_S(conn_cnf.fast_forward) +
			" WHERE username='" + _S(FF_USER) + "'"
	);
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

	diag("Using %s 'mysql-enable_client/server_deprecate_eof'", proxy_cnf.force_mismatch ? "DYNAMIC" : "STATIC");
	int rc = apply_proxy_conf(admin, proxy_cnf);
	if (rc) { return EXIT_FAILURE; }

	diag("Create client MySQL conn   user=\"%s\" port=\"%d\"", FF_USER, conn_cnf.cl.port);
	MYSQL* proxy { create_mysql_conn({ conn_cnf.cl.host, FF_USER, FF_PASS, conn_cnf.cl.port }) };
	if (proxy == NULL) { return EXIT_FAILURE; }
	dump_as_table(admin, "'connection_pool' status after client conn:", CONN_POOL_HG_STATUS);

	if (proxy_cnf.force_mismatch) {
		diag("Revert 'client_deprecate_eof'   client_deprecate_eof=%d", !proxy_cnf.cli_depr_eof);
		MYSQL_QUERY_T(admin, "SET mysql-enable_client_deprecate_eof=" + _TO_S(!proxy_cnf.cli_depr_eof));
		MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
	}

	diag("Get pre-conn attempt stats from target hostgroup   tg=%d", SQLITE3_HG);
	const ext_val_t<hg_pool_st_t> pre_hg_st { get_conn_pool_hg_stats(admin, SQLITE3_HG) };
	CHECK_EXT_VAL(pre_hg_st);
	const ext_val_t<int64_t> pre_srv_conns { mysql_query_ext_val(admin,
		"SELECT variable_value FROM stats.stats_mysql_global WHERE variable_name='Server_Connections_created'",
		int64_t(-1)
	)};
	CHECK_EXT_VAL(pre_srv_conns);

	fstream logfile_fs {};

	{
		diag("Open General log to check for errors   path=\"%s\"", PROXYSQL_LOG_PATH.c_str());
		int of_err = open_file_and_seek_end(PROXYSQL_LOG_PATH, logfile_fs);
		if (of_err != EXIT_SUCCESS) { return of_err; }
	}

	diag("Open ProxySQL audit log to check the connections attempts   path=\"%s\"", PROXYSQL_LOG_PATH.c_str());
	const ext_val_t<string> audit_fname {
		mysql_query_ext_val(admin, SELECT_RUNTIME_VAR"'mysql-auditlog_filename'", _S("audit.log"))
	};
	CHECK_EXT_VAL(audit_fname);

	const string latest_split { find_latest_split(PROXYSQL_AUDIT_DIR, audit_fname.val) };
	const string audit_path { PROXYSQL_AUDIT_DIR + "/" + latest_split };
	fstream auditlog_fs {};

	{
		diag("Open Audit log to check for conns   path=\"%s\"", audit_path.c_str());
		int of_err = open_file_and_seek_end(audit_path, auditlog_fs);
		if (of_err != EXIT_SUCCESS) { return of_err; }
	}

	diag("Issuing query (trx) creating new backend conn");
	rc = mysql_query_t(proxy, "BEGIN");
	if (rc == 0) {
		diag("Previous query successful; closing trx is required");
		mysql_query_t(proxy, "COMMIT");
	}

	// Sanity check; query should **NEVER** fail if mismatch is allowed (no fast-forward).
	if (rc != 0 && !conn_cnf.fast_forward) {
		diag(
			"Config should allow capabilities mismatch, but query failed. Aborting test   error=\"%s\"",
			mysql_error(proxy)
		);
		return EXIT_FAILURE;
	}

	if (
		// * -> (* *) -> *:
		// No match required without fast-forward
		!conn_cnf.fast_forward
		||
		// * -> (* *) -> *:
		// ConnPool warmup scenarios:
		(
			// For pool to serve the query, warmup conns caps need to match config on client-side. Client
			// conn caps must be checked (not only config) as disabled always win negotiation.
			pool_st.warmup && !conn_cnf.fast_forward && (
				(bool(pool_st.conn_caps & CLIENT_DEPRECATE_EOF) ==
					(proxy_cnf.cli_depr_eof && (conn_cnf.conn_caps & CLIENT_DEPRECATE_EOF)))
			)
		)
		||
		(
			// 1 -> (1 *) -> 0
			conn_cnf.fast_forward && (
				!(
					bool(conn_cnf.conn_caps & CLIENT_DEPRECATE_EOF)
					&& proxy_cnf.cli_depr_eof == 1
					&& proxy_cnf.force_mismatch
				)
			)
		)
	) {
		ok(
			rc == 0,
			"Query should SUCCEED (backend-conn match)   conn_conf='%s' proxy_conf='%s' pool_st='%s'",
			to_string(conn_cnf).c_str(), to_string(proxy_cnf).c_str(), to_string(pool_st).c_str()
		);
	} else {
		ok(
			rc != 0,
			"Query should FAIL (no backend-conn match)   conn_conf='%s' proxy_conf='%s' pool_st='%s'",
			to_string(conn_cnf).c_str(), to_string(proxy_cnf).c_str(), to_string(pool_st).c_str()
		);
	}

	uint32_t exp_conns { 0 };

	// * -> (* *) -> *:
	// If conn_pool is warm-up coons matches 'proxy_cnf.cli_depr_eof', conns should be reused from the pool.
	if (
		// fast-forward avoids the connection pool
		pool_st.warmup && !conn_cnf.fast_forward
	) {
		exp_conns = 0;
	}
	// Conn creation is required; no warmup pool
	else {
		// A match is required between client and backend conns:
		if (
			// No fast-forward should always work (no match-enforced)
			!conn_cnf.fast_forward
			||
			// Match is enforced by fast-forward
			(
				conn_cnf.fast_forward
				&&
				(
					// 1 -> (0 *) -> 1:
					// Disabled by server (ProxySQL) (fast-forward propagation)
					(
						!proxy_cnf.cli_depr_eof || !(conn_cnf.conn_caps & CLIENT_DEPRECATE_EOF)
					)
					||
					// 0 -> (* *) -> *:
					// Disabled by client always wins (fast-forward propagation)
					(
						!(conn_cnf.conn_caps & CLIENT_DEPRECATE_EOF) && proxy_cnf.cli_depr_eof
					)
					||
					// 1 -> (1 1) -> 0:
					!(proxy_cnf.cli_depr_eof && proxy_cnf.force_mismatch)
				)
			)
			||
			// * -> (0 0) -> *: Client caps should always match backend
			(!proxy_cnf.cli_depr_eof && !proxy_cnf.srv_depr_eof)
		) {
			exp_conns = 1;
		} else {
			exp_conns = TO_SERVER_MAX / RETRIES_DELAY;
		}
	}

	const string conn_match_regex {
		"Failed to obtain suitable connection for fast-forward; server lacks the required capabilities"
			"   hostgroup=" + _TO_S(SQLITE3_HG) + " client_flags=\\d+ server_capabilities=\\d+"
	};

	diag("Check ProxySQL log for connection mismatches   regex=\"%s\"", conn_match_regex.c_str());
	const auto& [_a, match_lines] { get_matching_lines(logfile_fs, conn_match_regex)};
	diag("Found General log matching lines   count=%ld", match_lines.size());

	uint32_t exp_lines { exp_conns == 1 || exp_conns == 0 ? 0 : exp_conns };
	ok(
		match_lines.size() == exp_lines,
		"Error log should hold conn match failures   lines=%ld exp_lines=%d",
		match_lines.size(), exp_lines
	);

	diag("Check Audit log for connections attempts on SQLite3");
	const auto& [_b, audit_lines] { get_matching_lines(auditlog_fs,
		"SQLite3_Connect_OK.*" + _S(FF_USER)
	)};
	diag("Found Audit log matching lines   count=%ld", audit_lines.size());

	ok(
		audit_lines.size() == exp_conns,
		"Audit log should contain SQLite3 created conns   lines=%ld exp_conns=%d",
		audit_lines.size(), exp_conns
	);

	diag("Get post-conn attempt stats from target hostgroup   tg=%d", SQLITE3_HG);
	const ext_val_t<hg_pool_st_t> post_hg_st { get_conn_pool_hg_stats(admin, SQLITE3_HG) };
	CHECK_EXT_VAL(post_hg_st);

	ok(
		pre_hg_st.val.conn_ok + exp_conns == post_hg_st.val.conn_ok,
		"Conn created should have increased by query attempt   pre-ConnOK=%d post-ConnOK=%d",
		pre_hg_st.val.conn_ok, post_hg_st.val.conn_ok
	);

	const ext_val_t<int64_t> post_srv_conns {
		mysql_query_ext_val(
			admin,
			"SELECT variable_value FROM stats.stats_mysql_global"
				" WHERE variable_name='Server_Connections_created'",
			int64_t(-1)
		)
	};
	CHECK_EXT_VAL(post_srv_conns);

	ok(
		pre_srv_conns.val + exp_conns == post_srv_conns.val,
		"Conn created should have increased by query attempt"
			"   pre-Server_Connections_created=%ld post-Server_Connections_created=%ld",
		pre_srv_conns.val, post_srv_conns.val
	);

	dump_as_table(admin, "'connection_pool' status after client conn:", CONN_POOL_HG_STATUS);

	mysql_close(proxy);

	return EXIT_SUCCESS;
}

int test_conn_acquisition(
	MYSQL* admin, const CommandLine& cl, bool ff, bool client_eof, bool force_match, bool warmup_pool
) {
	diag("Started '%s'   ff=%d client_eof=%d force_match=%d", __func__, ff, client_eof, force_match);

	diag("Setting test global 'mysql-variables'   test='%s'", __func__);
	std::for_each(test_conn_creation___mysql_config.begin(), test_conn_creation___mysql_config.end(),
		[&admin] (const string& q) { return run_setup_query(admin, q); }
	);

	//////
	const ext_val_t<int32_t> retries_delay {
		mysql_query_ext_val(admin, SELECT_RUNTIME_VAR"'mysql-connect_retries_delay'", -1)
	};
	CHECK_EXT_VAL(retries_delay);
	const ext_val_t<int32_t> to_server_max {
		mysql_query_ext_val(admin, SELECT_RUNTIME_VAR"'mysql-connect_timeout_server_max'", -1)
	};
	CHECK_EXT_VAL(to_server_max);
	//////

	diag("Update 'fast-forward' for testing user   user=\"%s\" fast_forward=%d", FF_USER, ff);
	MYSQL_QUERY_T(admin,
		"UPDATE mysql_users SET fast_forward=" + _TO_S(ff) + " WHERE username='" + _S(FF_USER) + "'"
	);
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

	diag("Update 'mysql-enable_client_deprecate_eof'   enable_client_deprecate_eof=%d", client_eof);
	MYSQL_QUERY_T(admin, "SET mysql-enable_client_deprecate_eof=" + _TO_S(client_eof));
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	diag("Create client MySQL conn   user=\"%s\" port=\"%d\"", FF_USER, cl.port);
	MYSQL* proxy { create_mysql_conn({ cl.host, FF_USER, FF_PASS, cl.port }) };
	if (proxy == NULL) { return EXIT_FAILURE; }
	dump_as_table(admin, "'connection_pool' status after client conn:", CONN_POOL_HG_STATUS);

	diag("Revert support for 'enable_client_deprecate_eof'   client_eof=%d", client_eof);
	MYSQL_QUERY_T(admin, "SET mysql-enable_client_deprecate_eof=" + _TO_S(!client_eof));
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	diag("Get pre-conn attempt stats from target hostgroup   tg=%d", SQLITE3_HG);
	const ext_val_t<hg_pool_st_t> pre_hg_st { get_conn_pool_hg_stats(admin, SQLITE3_HG) };
	CHECK_EXT_VAL(pre_hg_st);
	const ext_val_t<int64_t> pre_srv_conns { mysql_query_ext_val(admin,
		"SELECT variable_value FROM stats.stats_mysql_global WHERE variable_name='Server_Connections_created'",
		int64_t(-1)
	)};
	CHECK_EXT_VAL(pre_srv_conns);

	fstream logfile_fs {};

	{
		diag("Open General log to check for errors   path=\"%s\"", PROXYSQL_LOG_PATH.c_str());
		int of_err = open_file_and_seek_end(PROXYSQL_LOG_PATH, logfile_fs);
		if (of_err != EXIT_SUCCESS) { return of_err; }
	}

	diag("Open ProxySQL audit log to check the connections attempts   path=\"%s\"", PROXYSQL_LOG_PATH.c_str());
	const ext_val_t<string> audit_fname {
		mysql_query_ext_val(admin, SELECT_RUNTIME_VAR"'mysql-auditlog_filename'", _S("audit.log"))
	};
	CHECK_EXT_VAL(audit_fname);

	const string latest_split { find_latest_split(PROXYSQL_AUDIT_DIR, audit_fname.val) };
	const string audit_path { PROXYSQL_AUDIT_DIR + "/" + latest_split };
	fstream auditlog_fs {};

	{
		diag("Open Audit log to check for conns   path=\"%s\"", audit_path.c_str());
		int of_err = open_file_and_seek_end(audit_path, auditlog_fs);
		if (of_err != EXIT_SUCCESS) { return of_err; }
	}

	diag("Issue query (start trx) to create new backend conn   query=\"%s\"", "BEGIN");
	int rc = mysql_query_t(proxy, "BEGIN");
	if (rc == 0) {
		diag("Previous query successful; closing trx is required");
		mysql_query_t(proxy, "COMMIT");
	} else if (rc != 0 && !(force_match || ff)) {
		diag("Query failed. Aborting test   error=\"%s\"", mysql_error(proxy));
		return EXIT_FAILURE;
	}

	if ((force_match || ff) && client_eof) {
		ok(
			rc != 0,
			"Query should FAIL (no backend-conn match)   ff=%d client_eof=%d force_match=%d",
			ff, client_eof, force_match
		);
	} else {
		ok(
			rc == 0,
			"Query should SUCCEED (backend-conn match)   ff=%d client_eof=%d force_match=%d",
			ff, client_eof, force_match
		);
	}

	const int32_t exp_conns {
		!(force_match || ff) && warmup_pool ? 0 :
			(force_match || ff || client_eof) ? TO_SERVER_MAX/RETRIES_DELAY : 1
	};
	const string conn_match_regex {
		"Failed to obtain suitable connection for fast-forward; server lacks the required capabilities"
			"   hostgroup=" + _TO_S(SQLITE3_HG) + " client_flags=\\d+ server_capabilities=\\d+"
	};

	diag("Check ProxySQL log for connection mismatches   regex=\"%s\"", conn_match_regex.c_str());
	const auto& [_a, match_lines] { get_matching_lines(logfile_fs, conn_match_regex)};
	diag("Found General log matching lines   count=%ld", match_lines.size());

	bool exp_lines  {};
	ok(
		force_match || ff ? match_lines.size() == exp_conns : match_lines.size() == 0,
		"Error log should hold conn match failures   lines=%ld exp_lines=%d",
		match_lines.size(), exp_conns
	);

	diag("Check Audit log for connections attempts on SQLite3");
	const auto& [_b, audit_lines] { get_matching_lines(auditlog_fs,
		"SQLite3_Connect_OK.*" + _S(FF_USER)
	)};
	diag("Found Audit log matching lines   count=%ld", audit_lines.size());

	ok(
		audit_lines.size() == exp_conns,
		"Audit log should contain SQLite3 created conns   lines=%ld exp_lines=%d",
		audit_lines.size(), exp_conns
	);

	diag("Get post-conn attempt stats from target hostgroup   tg=%d", SQLITE3_HG);
	const ext_val_t<hg_pool_st_t> post_hg_st { get_conn_pool_hg_stats(admin, SQLITE3_HG) };
	CHECK_EXT_VAL(post_hg_st);

	ok(
		pre_hg_st.val.conn_ok + exp_conns == post_hg_st.val.conn_ok,
		"Conn created should have increased by query attempt   pre-ConnOK=%d post-ConnOK=%d",
		pre_hg_st.val.conn_ok, post_hg_st.val.conn_ok
	);

	const ext_val_t<int64_t> post_srv_conns {
		mysql_query_ext_val(
			admin,
			"SELECT variable_value FROM stats.stats_mysql_global"
				" WHERE variable_name='Server_Connections_created'",
			int64_t(-1)
		)
	};
	CHECK_EXT_VAL(post_srv_conns);

	ok(
		pre_srv_conns.val + exp_conns == post_srv_conns.val,
		"Conn created should have increased by query attempt"
			"   pre-Server_Connections_created=%ld post-Server_Connections_created=%ld",
		pre_srv_conns.val, post_srv_conns.val
	);

	dump_as_table(admin, "'connection_pool' status after client conn:", CONN_POOL_HG_STATUS);

	mysql_close(proxy);

	return EXIT_SUCCESS;
}

int test_conn_creation(
	MYSQL* admin, const CommandLine& cl, bool ff, bool client_eof, bool force_match
) {
	diag("Started '%s'   ff=%d client_eof=%d force_match=%d", __func__, ff, client_eof, force_match);

	diag("Initial connpool cleanup on hg   hg=%d conn_tg=%d", SQLITE3_HG, 0);
	int rc = conn_pool_cleanup(admin, SQLITE3_HG, 0);
	if (rc) { return EXIT_FAILURE; }

	dump_as_table(admin, "'stats_mysql_connection_pool' status:", CONN_POOL_HG_STATUS);

	return test_conn_acquisition(admin, cl, ff, client_eof, force_match, false);
}

int test_conn_creation(MYSQL* admin, const conn_conf_t& conn_cnf, const proxy_cnf_t& proxy_cnf) {
	const test_cnf_t test_cnf { pool_cnf_t { false, 0 }, conn_cnf, proxy_cnf };
	diag("Started '%s'   %s", __func__, to_string(test_cnf).c_str());

	diag("Initial connpool cleanup on hg   hg=%d conn_tg=%d", SQLITE3_HG, 0);
	int rc = conn_pool_cleanup(admin, SQLITE3_HG, 0);
	if (rc) { return EXIT_FAILURE; }

	dump_as_table(admin, "'stats_mysql_connection_pool' status:", CONN_POOL_HG_STATUS);

	return test_conn_acquisition(admin, test_cnf);
}

// CONN_POOL_WARMUP: Check backend conns created... Support vs Not-Supported
int test_conn_matching(MYSQL* admin, const test_cnf_t& test_cnf) {
	const conn_conf_t& conn_cnf { test_cnf.conn_conf };
	const proxy_cnf_t& proxy_cnf { test_cnf.proxy_conf };

	diag("Started '%s'   %s", __func__, to_string(test_cnf).c_str());

	diag("Initial connpool cleanup on hg   hg=%d conn_tg=%d", SQLITE3_HG, 0);
	int rc = conn_pool_cleanup(admin, SQLITE3_HG, 0);
	if (rc) { return EXIT_FAILURE; }

	dump_as_table(admin, "'stats_mysql_connection_pool' status:", CONN_POOL_HG_STATUS);

	bool pool_depr_eof { bool(test_cnf.pool_status.conn_caps & CLIENT_DEPRECATE_EOF) };
	MYSQL_QUERY_T(admin, "SET mysql-enable_client_deprecate_eof=" + _TO_S(pool_depr_eof));
	MYSQL_QUERY_T(admin, "SET mysql-enable_server_deprecate_eof=" + _TO_S(pool_depr_eof));
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	diag(
		"Warming-up conn-pool with conns  conns=%d eof_support=%d",
		CONN_POOL_WARNMUP, !proxy_cnf.cli_depr_eof
	);

	{
		diag("Update 'fast-forward' for testing user   user=\"%s\" ff=%d", FF_USER, conn_cnf.fast_forward);
		MYSQL_QUERY_T(admin,
			"UPDATE mysql_users SET fast_forward=" + _TO_S(0) + " WHERE username='" + _S(FF_USER) + "'"
		);
		MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

		diag("Create client MySQL conn   user=\"%s\" port=\"%d\"", FF_USER, conn_cnf.cl.port);
		MYSQL* proxy_warmup { create_mysql_conn({ conn_cnf.cl.host, FF_USER, FF_PASS, conn_cnf.cl.port }) };
		// MYSQL* proxy_warmup { create_mysql_conn({ cl.host, cl.username, cl.password, cl.port }) };
		if (proxy_warmup == NULL) { return EXIT_FAILURE; }

		for (int i = 0; i < CONN_POOL_WARNMUP; i++) {
			MYSQL_QUERY_T(proxy_warmup,
				"/* create_new_connection=1 */ BEGIN"
				// "/* create_new_connection=1;hostgroup=" + std::to_string(SQLITE3_HG) + " */ BEGIN"
			);
			MYSQL_QUERY_T(proxy_warmup, "COMMIT");
		}

		mysql_close(proxy_warmup);

		diag("Update 'fast-forward' for testing user   user=\"%s\" ff=%d", FF_USER, conn_cnf.fast_forward);
		MYSQL_QUERY_T(admin,
			"UPDATE mysql_users SET fast_forward=" + _TO_S(1) + " WHERE username='" + _S(FF_USER) + "'"
		);
		MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");
	}

	dump_as_table(admin, "'stats_mysql_connection_pool' status:", CONN_POOL_HG_STATUS);

	return test_conn_acquisition(admin, test_cnf);
}

#ifdef LIBMYSQL_HELPER8

/**
 * @brief Checks that client is disconnected when a conn is trying converted to 'fast-forward' and the
 *   currently locked backend connection doesn't match the correct capabilities.
 * @param admin An already oppened MySQL connection to the admin interface.
 * @return EXIT_SUCCESS if test was able to be performed, EXIT_FAILURE otherwise.
 */
int test_conn_ff_conv(MYSQL* admin, const CommandLine& cl, bool client_eof) {
	diag("Started '%s'   client_eof=%d", __func__, client_eof);

	diag("Initial connpool cleanup on hg   hg=%d conn_tg=%d", SQLITE3_HG, 0);
	int rc = conn_pool_cleanup(admin, SQLITE3_HG, 0);
	if (rc) { return EXIT_FAILURE; }

	diag("Update 'mysql-enable_client_deprecate_eof'   enable_client_deprecate_eof=%d", client_eof);
	MYSQL_QUERY_T(admin, "SET mysql-enable_client_deprecate_eof=" + _TO_S(client_eof));
	diag("Allowing capabilities mismatch when selecting backend connections");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	diag("Pairing frontend conn with backend one with mismatching capabilities");
	diag("Create client MySQL conn   user=\"%s\" port=\"%d\"", cl.username, cl.port);
	MYSQL* proxy { create_mysql_conn({ cl.host, cl.username, cl.password, cl.port }) };
	if (proxy == NULL) { return EXIT_FAILURE; }
	dump_as_table(admin, "'connection_pool' status after client conn:", CONN_POOL_HG_STATUS);

	diag("Revert support for 'enable_client_deprecate_eof'   client_eof=%d", !client_eof);
	MYSQL_QUERY_T(admin, "SET mysql-enable_client_deprecate_eof=" + _TO_S(!client_eof));
	MYSQL_QUERY_T(admin, "SET mysql-enable_server_deprecate_eof=1");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	diag("Get pre-conn attempt stats from target hostgroup   tg=%d", SQLITE3_HG);
	const ext_val_t<hg_pool_st_t> pre_hg_st { get_conn_pool_hg_stats(admin, SQLITE3_HG) };
	CHECK_EXT_VAL(pre_hg_st);
	const ext_val_t<int64_t> pre_srv_conns { mysql_query_ext_val(admin,
		"SELECT variable_value FROM stats.stats_mysql_global WHERE variable_name='Server_Connections_created'",
		int64_t(-1)
	)};
	CHECK_EXT_VAL(pre_srv_conns);

	diag("Issue query (start trx) to create new backend conn   query=\"%s\"", "BEGIN");
	rc = mysql_query_t(proxy, "/* hostgroup=" + std::to_string(SQLITE3_HG) +  " */ BEGIN");
	if (rc) {
		diag("Query failed. Aborting test   error=\"%s\"", mysql_error(proxy));
		return EXIT_FAILURE;
	}

	diag("Get post-conn attempt stats from target hostgroup   tg=%d", SQLITE3_HG);
	const ext_val_t<hg_pool_st_t> post_hg_st { get_conn_pool_hg_stats(admin, SQLITE3_HG) };
	CHECK_EXT_VAL(post_hg_st);

	ok(
		pre_hg_st.val.conn_used + 1 == post_hg_st.val.conn_used,
		"Conn created should have increased by query attempt   pre-ConnUsed=%d post-ConnUsed=%d",
		pre_hg_st.val.conn_used, post_hg_st.val.conn_used
	);

	diag("Switching now the session to FAST-FORWARD (opening binlog); DISCONNECT should be enforced");
	MYSQL_RPL rpl {};
	rc = mysql_binlog_open(proxy, &rpl);

	diag(
		"Error after starting replication   rc=%d errno=%d error=\"%s\"",
		rc, mysql_errno(proxy), mysql_error(proxy)
	);

	rc = mysql_binlog_fetch(proxy, &rpl);

	diag(
		"Error when trying to fetch replication data   rc=%d errno=%d error=\"%s\"",
		rc, mysql_errno(proxy), mysql_error(proxy)
	);

	mysql_close(proxy);

	return EXIT_SUCCESS;
}

#endif

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(
		5 * gen_all_proxy_cnfs().size()
#ifdef LIBMYSQL_HELPER8
		* 4 + 2
#else
		* 2
#endif
	);

	MYSQL* admin { create_mysql_conn({ cl.admin_host, cl.admin_username, cl.admin_password, cl.admin_port }) };
	if (admin == NULL) { return EXIT_FAILURE; }

	diag("Setting up global 'mysql-variables' config for the all tests...");
	std::for_each(mysql_variables_setup.begin(), mysql_variables_setup.end(),
		[&admin] (const string& q) { return run_setup_query(admin, q); }
	);
	diag("Setting up global 'SQLite3 server' config for the test");
	std::for_each(sqlite3_server_setup.begin(), sqlite3_server_setup.end(),
		[&admin] (const string& q) { return run_setup_query(admin, q); }
	);

	int rc = 0;
	uint32_t conn_caps {
#ifdef LIBMYSQL_HELPER8
		CLIENT_DEPRECATE_EOF
#else
		0
#endif
	};

	for (const proxy_cnf_t& proxy_cnf : gen_all_proxy_cnfs()) {
		rc = test_conn_creation(admin, { cl, true, conn_caps }, proxy_cnf );
		if (rc) { goto cleanup; }
	}
	for (const proxy_cnf_t& proxy_cnf : gen_all_proxy_cnfs()) {
		rc = test_conn_creation(admin, { cl, false, conn_caps }, proxy_cnf );
		if (rc) { goto cleanup; }
	}

#ifdef LIBMYSQL_HELPER8

	for (const proxy_cnf_t& proxy_cnf : gen_all_proxy_cnfs()) {
		rc = test_conn_matching(admin, {
			{ true, CLIENT_DEPRECATE_EOF }, { cl, true, conn_caps }, proxy_cnf
		});
		if (rc) { goto cleanup; }
	}
	for (const proxy_cnf_t& proxy_cnf : gen_all_proxy_cnfs()) {
		rc = test_conn_matching(admin, {
			{ true, CLIENT_DEPRECATE_EOF }, { cl, false, conn_caps }, proxy_cnf
		});
		if (rc) { goto cleanup; }
	}

	rc = test_conn_ff_conv(admin, cl, true);
	if (rc) { goto cleanup; }

	rc = test_conn_ff_conv(admin, cl, false);
	if (rc) { goto cleanup; }

#endif

cleanup:

	diag("Recover DISK 'mysql_servers' config");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS FROM DISK");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	diag("Recover DISK 'mysql_variables' config");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES FROM DISK");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(admin);

	return exit_status();
}
