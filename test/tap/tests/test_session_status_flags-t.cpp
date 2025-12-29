/**
 * @file test_session_status_flags-t.cpp
 * @brief Test file for testing the different operations that modify the 'status_flags' in a MySQL_Session.
 * @details The test performs the queries for both TEXT and BINARY protocols (when supported). For this
 *  purpose, the test exposes a generic payload format for performing the queries and inspecting
 *  'PROXYSQL INTERNAL SESSION'.
 *
 *  NOTE-TODO: The test needs to deal with potential replication issues for several queries. Due to current
 *  limitations in how ProxySQL handles errors for prepared statements, replications checks are performed in
 *  freshly created connections using TEXT protocol, prior to the statements executions.
 */

#include <chrono>
#include <stdio.h>
#include <string.h>
#include <string>
#include <tuple>
#include <vector>
#include <utility>
#include <unistd.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "json.hpp"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

using std::pair;
using std::tuple;
using std::vector;
using std::string;
using std::function;

using nlohmann::json;

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

// This test was previously failing due to replication not catching up quickly enough when doing
// some table creation operations. This variable controls the waiting timeout after these
// create operations are performed. See #3282 for context.
constexpr const int replication_timeout = 10;

json get_nested_json_elem(const json& j, const std::vector<std::string>& path) {
	json cur_j = j;

	for (const auto& step : path) {
		if (cur_j.contains(step)) {
			cur_j = cur_j.at(step);

			if (&step == &path.back()) {
				return cur_j;
			}
		} else {
			cur_j = {};
			break;
		}
	}

	return cur_j;
}

int execute_queries(MYSQL* proxy_mysql, const vector<string>& queries, vector<json>& out_j_sts) {
	vector<json> j_sts {};

	for (const auto& query : queries) {
		MYSQL_QUERY(proxy_mysql, query.c_str());
		MYSQL_RES* tr_res = mysql_store_result(proxy_mysql);

		if (query == "PROXYSQL INTERNAL SESSION") {
			json j_st {};
			parse_result_json_column(tr_res, j_st);

			j_sts.push_back(j_st);
		}

		mysql_free_result(tr_res);
	}

	out_j_sts = j_sts;

	return EXIT_SUCCESS;
}

json get_backend_elem(const json& j_status, const vector<string>& elem_path) {
	json j_tg_elem {};

	if (elem_path.empty()) {
		if (j_status.contains("backends")) {
			return j_status["backends"];
		} else {
			return {};
		}
	}

	if (j_status.contains("backends")) {
		for (auto& backend : j_status["backends"]) {
			j_tg_elem = get_nested_json_elem(backend, elem_path);

			if (!j_tg_elem.empty()) {
				break;
			}
		}
	}

	return j_tg_elem;
}

using rep_errno_t = int;
using rep_timeout = int;

using rep_check_t = pair<rep_errno_t, rep_timeout>;
using sess_check_t = tuple<vector<string>, function<bool(const json&)>, string>;
using query_t = tuple<string, rep_check_t, vector<sess_check_t>>;
struct QUERY { enum idx { QUERY_STR, REP_CHECK, SESS_CHECKS }; };

int exec_with_retry(MYSQL* proxy, const query_t& query_def) {
	const string& query = std::get<QUERY::QUERY_STR>(query_def);
	const rep_check_t& rep_check = std::get<QUERY::REP_CHECK>(query_def);

	int timeout = 0;
	int query_err = 0;

	diag("Executing query '%s' with retrying due to replication lag.", query.c_str());
	while (timeout < replication_timeout) {
		query_err = mysql_query(proxy, query.c_str());
		if (query_err) {
			int query_errno = mysql_errno(proxy);
			if (query_errno != rep_check.first) {
				break;
			} else {
				sleep(1);
				diag("Retrying query '%s' due to replication lag.", query.c_str());
			}
		} else {
			mysql_free_result(mysql_store_result(proxy));
			break;
		}
		timeout++;
	}

	if (query_err) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	} else {
		diag("Replication lag took '%d.'", timeout);
		return EXIT_SUCCESS;
	}
}

function<bool(const json&)> capture_exception(const function<bool(const json&)> sess_check_t) {
	return [=](const json& j_tg_elem) -> bool {
		try {
			return sess_check_t(j_tg_elem);
		} catch (const std::exception& ex) {
			diag("Invalid target elem conversion:\n -Elem: %s\n -Except: %s", j_tg_elem.dump().c_str(), ex.what());
			return false;
		}
	};
}

int prepare_stmt_queries(const CommandLine& cl, const vector<query_t>& p_queries) {
	// 1. Prepare the stmt in a connection
	MYSQL* proxy_mysql = mysql_init(NULL);

	diag("Openning INITIAL connection...");
	if (!mysql_real_connect(proxy_mysql, cl.root_host, cl.root_username, cl.root_password, NULL, cl.root_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
		return EXIT_FAILURE;
	}

	vector<query_t> queries {};
	vector<string> str_queries {};
	std::accumulate(
		queries.begin(), queries.end(), vector<string> {},
		[] (vector<string>& elems, const query_t& query_def) {
			const string& query = std::get<QUERY::QUERY_STR>(query_def);
			elems.push_back(query);
			return elems;
		}
	);

	if (p_queries.empty() == false) {
		std::copy_if(
			p_queries.begin(), p_queries.end(), std::back_inserter(queries),
			[] (const query_t& query_def) {
				const string& query = std::get<QUERY::QUERY_STR>(query_def);
				return strcasecmp(query.c_str(), "PROXYSQL INTERNAL SESSION");
			}
		);
	}

	diag("PREPARING multiplexing disabling queries - `%s`", json(str_queries).dump().c_str());
	for (const query_t& query_def : queries) {
		const string& query = std::get<QUERY::QUERY_STR>(query_def);
		const rep_check_t& rep_check = std::get<QUERY::REP_CHECK>(query_def);

		if (rep_check.first == 0 || rep_check.second == 0) {
		}

		MYSQL_STMT* stmt = mysql_stmt_init(proxy_mysql);
		if (!stmt) {
			fprintf(stderr, " mysql_stmt_init(), out of memory\n");
			return EXIT_FAILURE;
		}

		diag("Issuing PREPARE for `%s` in INIT conn", query.c_str());
		int my_err = mysql_stmt_prepare(stmt, query.c_str(), strlen(query.c_str()));
		if (my_err) {
			diag(
				"'mysql_stmt_prepare' failed for query '%s' with error - Err: '%d', ErrMsg: '%s'",
				query.c_str(), mysql_stmt_errno(stmt), mysql_stmt_error(stmt)
			);
			return EXIT_FAILURE;
		}

		mysql_stmt_close(stmt);
	}

	diag("Closing PREPARING connection...");
	mysql_close(proxy_mysql);

	return EXIT_SUCCESS;
}

int store_and_discard_stmt_res(MYSQL_STMT* stmt) {
	/* Fetch result set meta information */
	MYSQL_RES* prepare_meta_result = mysql_stmt_result_metadata(stmt);
	if (!prepare_meta_result)
	{
		fprintf(stderr, " mysql_stmt_result_metadata(), returned no meta information\n");
		fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
		return EXIT_FAILURE;
	}

	/* Get total columns in the query */
	uint32_t column_count = mysql_num_fields(prepare_meta_result);
	MYSQL_FIELD* fields = mysql_fetch_fields(prepare_meta_result);

	vector<MYSQL_BIND> res_binds(column_count, MYSQL_BIND {});
	size_t res_idx = 0;

	vector<char> is_null(column_count);
	vector<unsigned long> length(column_count);
	vector<string> res_bin_data {};

	vector<vector<char>> data_buffs {};

	for (uint32_t column = 0; column < column_count; column++) {
		data_buffs.push_back(vector<char>(fields[column].length));
	}

	for (uint32_t column = 0; column < column_count; column++) {
		res_binds[column].buffer_type = fields[column].type;
		res_binds[column].buffer = static_cast<void*>(&data_buffs[column][0]);
		res_binds[column].buffer_length = sizeof(int);
		res_binds[column].is_null = &is_null[column];
		res_binds[column].length = &length[column];
	}

	if (mysql_stmt_bind_result(stmt, &res_binds[0])) {
		diag("'mysql_stmt_bind_result' at line %d failed: %s", __LINE__, mysql_stmt_error(stmt));
		return EXIT_FAILURE;
	}

	mysql_free_result(prepare_meta_result);

	while (!mysql_stmt_fetch(stmt)) {}

	return EXIT_SUCCESS;
}

int exec_stmt_queries(MYSQL* proxy_mysql, const vector<query_t>& test_queries) {
	for (const query_t& test_query : test_queries) {
		const string& query = std::get<QUERY::QUERY_STR>(test_query);
		const rep_check_t& rep_check = std::get<QUERY::REP_CHECK>(test_query);
		const vector<sess_check_t>& sess_checks = std::get<QUERY::SESS_CHECKS>(test_query);

		if (query == "PROXYSQL INTERNAL SESSION") {
			for (const sess_check_t sess_check : sess_checks) {
				if (std::get<0>(sess_check).empty() || static_cast<bool>(std::get<1>(sess_check)) == false) {
					diag("ABORT: Empty 'sess_check_t' defined for query '%s'", query.c_str());
					return EXIT_FAILURE;
				}
			}

			json j_st {};

			MYSQL_QUERY(proxy_mysql, query.c_str());
			MYSQL_RES* tr_res = mysql_store_result(proxy_mysql);
			parse_result_json_column(tr_res, j_st);
			mysql_free_result(tr_res);

			for (const sess_check_t sess_check : sess_checks) {
				const vector<string>& tg_elem_path = std::get<0>(sess_check);
				const function<bool(const json&)>& status_check = std::get<1>(sess_check);
				const string& check_msg = std::get<2>(sess_check);
				const function<bool(const json&)>& no_except_status_check = capture_exception(status_check);

				json j_tg_elem {};
				if (tg_elem_path.front() == "backends") {
					j_tg_elem = get_backend_elem(j_st, vector<string> {tg_elem_path.begin() + 1, tg_elem_path.end()});
				} else {
					j_tg_elem = get_nested_json_elem(j_st, tg_elem_path);
				}

				ok(
					j_tg_elem.empty() == false, "Backend 'conn' objects should be found holding sess info - `%s`",
					json { tg_elem_path }.dump().c_str()
				);

				ok(no_except_status_check(j_tg_elem), "Connection status should reflect - %s", check_msg.c_str());
			}
		} else {
			MYSQL_STMT* stmt = mysql_stmt_init(proxy_mysql);

			diag("Issuing PREPARE for `%s` in new conn", query.c_str());
			int my_err = mysql_stmt_prepare(stmt, query.c_str(), strlen(query.c_str()));
			if (my_err) {
				diag(
					"LINE %d: 'mysql_stmt_prepare' failed for query '%s' with error - Err: '%d', ErrMsg: '%s'",
					__LINE__, query.c_str(), mysql_stmt_errno(stmt), mysql_stmt_error(stmt)
				);
				return EXIT_FAILURE;
			}

			// TODO: Remember to DOC requiring to execute
			{
				if (rep_check.first == 0 || rep_check.second == 0) {
					diag("Issuing EXECUTE for `%s` in new conn", query.c_str());
					my_err = mysql_stmt_execute(stmt);
					if (my_err) {
						diag("'mysql_stmt_execute' at line %d failed: %s", __LINE__, mysql_stmt_error(stmt));
						return EXIT_FAILURE;
					}
				} else {
					int timeout = 0;
					int query_err = 0;

					diag("Executing query '%s' with retrying due to replication lag.", query.c_str());
					while (timeout < replication_timeout) {
						query_err = mysql_stmt_execute(stmt);
						if (query_err) {
							int query_errno = mysql_stmt_errno(stmt);
							if (query_errno != rep_check.first) {
								break;
							} else {
								sleep(1);
								diag("Retrying EXECUTE for '%s' due to replication lag. Errno: %d", query.c_str(), query_errno);
							}
						} else {
							break;
						}
						timeout++;
					}

					if (query_err) {
						fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_stmt_error(stmt));
						return EXIT_FAILURE;
					} else {
						diag("Replication lag took '%d.'", timeout);
					}
				}

				if (query.find("SELECT") != string::npos) {
					my_err = store_and_discard_stmt_res(stmt);
					if (my_err) {
						diag("'get_stmt_result' at line %d failed", __LINE__);
						return EXIT_FAILURE;
					}
				}
			}

			mysql_stmt_close(stmt);
		}
	}

	return EXIT_SUCCESS;
}

int exec_test_queries(MYSQL* proxy_mysql, const vector<query_t>& test_queries) {
	for (const query_t& test_query : test_queries) {
		const string& query = std::get<QUERY::QUERY_STR>(test_query);
		const rep_check_t& rep_check = std::get<QUERY::REP_CHECK>(test_query);
		const vector<sess_check_t>& sess_checks = std::get<QUERY::SESS_CHECKS>(test_query);

		if (query == "PROXYSQL INTERNAL SESSION") {
			for (const sess_check_t sess_check : sess_checks) {
				if (std::get<0>(sess_check).empty() || static_cast<bool>(std::get<1>(sess_check)) == false) {
					diag("ABORT: Empty 'sess_check_t' defined for query '%s'", query.c_str());
					return EXIT_FAILURE;
				}
			}
		}

		diag("Issuing test query - `%s`", query.c_str());
		MYSQL_RES* tr_res = nullptr;

		if (rep_check.first == 0 || rep_check.second == 0) {
			MYSQL_QUERY(proxy_mysql, query.c_str());
			tr_res = mysql_store_result(proxy_mysql);
		} else {
			int timeout = 0;
			int query_err = 0;

			diag("Executing query '%s' with retrying due to replication lag.", query.c_str());
			while (timeout < replication_timeout) {
				query_err = mysql_query(proxy_mysql, query.c_str());
				if (query_err) {
					int query_errno = mysql_errno(proxy_mysql);
					if (query_errno != rep_check.first) {
						break;
					} else {
						sleep(1);
						diag("Retrying query '%s' due to replication lag.", query.c_str());
					}
				} else {
					tr_res = mysql_store_result(proxy_mysql);
					break;
				}
				timeout++;
			}

			if (query_err) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
				return -1;
			} else {
				diag("Replication lag took '%d.'", timeout);
			}
		}

		// Perform the status checks for this query
		if (query == "PROXYSQL INTERNAL SESSION") {
			json j_st {};
			parse_result_json_column(tr_res, j_st);

			for (const sess_check_t sess_check : sess_checks) {
				const vector<string>& tg_elem_path = std::get<0>(sess_check);
				const function<bool(const json&)>& status_check = std::get<1>(sess_check);
				const string& check_msg = std::get<2>(sess_check);
				const function<bool(const json&)>& no_except_status_check = capture_exception(status_check);

				json j_tg_elem {};
				if (tg_elem_path.front() == "backends") {
					j_tg_elem = get_backend_elem(j_st, vector<string> {tg_elem_path.begin() + 1, tg_elem_path.end()});
				} else {
					j_tg_elem = get_nested_json_elem(j_st, tg_elem_path);
				}

				ok(
					j_tg_elem.empty() == false, "Backend 'conn' objects should be found holding sess info - `%s`",
					json { tg_elem_path }.dump().c_str()
				);

				ok(no_except_status_check(j_tg_elem), "Connection status should reflect - %s", check_msg.c_str());
			}
		}

		mysql_free_result(tr_res);
	}

	return EXIT_SUCCESS;
}

bool check_server_status_in_trx(const json& j_tg_elem) {
	int32_t server_status = 0;

	if (j_tg_elem.empty() == false) {
		server_status = j_tg_elem.get<int32_t>();
	}

	return server_status & 0x01;
}

using setup_teardown_t = pair<vector<string>,vector<string>>;
using test_def_t = tuple<string, setup_teardown_t, vector<query_t>>;
struct SCONN_TEST_DEF { enum idx { NAME, SETUP_TEARDOWN, TEST_QUERIES }; };

int exec_and_discard(MYSQL* proxy_mysql, const vector<string>& queries) {
	for (const auto& query : queries) {
		MYSQL_QUERY(proxy_mysql, query.c_str());
		mysql_free_result(mysql_store_result(proxy_mysql));
	}

	return EXIT_SUCCESS;
}

using queries_exec_t = function<int(MYSQL*, const vector<query_t>&)>;

int exec_simple_conn_tests(
	const CommandLine& cl, const vector<test_def_t>& tests_def, const queries_exec_t& queries_exec
) {
	for (const auto& test_def : tests_def) {
		const string& test_name { std::get<SCONN_TEST_DEF::NAME>(test_def) };
		const setup_teardown_t& setup_teardown = std::get<SCONN_TEST_DEF::SETUP_TEARDOWN>(test_def);
		const vector<query_t>& test_queries = std::get<SCONN_TEST_DEF::TEST_QUERIES>(test_def);

		diag("Starting test '%s'", test_name.c_str());

		MYSQL* proxy_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxy_mysql, cl.root_host, cl.root_username, cl.root_password, NULL, cl.root_port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
			return EXIT_FAILURE;
		}

		// TEST SETUP queries
		int setup_err = exec_and_discard(proxy_mysql, setup_teardown.first);
		if (setup_err) { return EXIT_FAILURE; }

		int test_err = queries_exec(proxy_mysql, test_queries);
		if (test_err) { return EXIT_FAILURE; }

		// TEST TEARDOWN queries
		int tear_err = exec_and_discard(proxy_mysql, setup_teardown.second);
		if (tear_err) { return EXIT_FAILURE; }

		mysql_close(proxy_mysql);
	}

	return EXIT_SUCCESS;
}
int text_exec_simple_conn_tests(const CommandLine& cl, const vector<test_def_t>& tests_def) {
	for (const auto& test_def : tests_def) {
		const string& test_name { std::get<SCONN_TEST_DEF::NAME>(test_def) };
		const setup_teardown_t& setup_teardown = std::get<SCONN_TEST_DEF::SETUP_TEARDOWN>(test_def);
		const vector<query_t>& test_queries = std::get<SCONN_TEST_DEF::TEST_QUERIES>(test_def);

		diag("Starting test '%s'", test_name.c_str());

		MYSQL* proxy_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxy_mysql, cl.root_host, cl.root_username, cl.root_password, NULL, cl.root_port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
			return EXIT_FAILURE;
		}

		// TEST SETUP queries
		int setup_err = exec_and_discard(proxy_mysql, setup_teardown.first);
		if (setup_err) { return EXIT_FAILURE; }

		exec_test_queries(proxy_mysql, test_queries);

		// TEST TEARDOWN queries
		int tear_err = exec_and_discard(proxy_mysql, setup_teardown.second);
		if (tear_err) { return EXIT_FAILURE; }

		mysql_close(proxy_mysql);
	}

	return EXIT_SUCCESS;
}

const double COLISSION_PROB = 1e-8;

int _wait_for_replication(
	const CommandLine& cl, MYSQL* proxy_admin, const std::string& check, uint32_t timeout, uint32_t read_hg
) {
	const std::string t_count_reader_hg_servers {
		"SELECT COUNT(*) FROM mysql_servers WHERE hostgroup_id=%d"
	};
	std::string count_reader_hg_servers {};
	size_t size =
		snprintf( nullptr, 0, t_count_reader_hg_servers.c_str(), read_hg) + 1;
	{
		std::unique_ptr<char[]> buf(new char[size]);
		snprintf(buf.get(), size, t_count_reader_hg_servers.c_str(), read_hg);
		count_reader_hg_servers = std::string(buf.get(), buf.get() + size - 1);
	}

	MYSQL_QUERY(proxy_admin, count_reader_hg_servers.c_str());
	MYSQL_RES* hg_count_res = mysql_store_result(proxy_admin);
	MYSQL_ROW row = mysql_fetch_row(hg_count_res);
	uint32_t srv_count = strtoul(row[0], NULL, 10);
	mysql_free_result(hg_count_res);

	if (srv_count > UINT_MAX) {
		return EXIT_FAILURE;
	}

	int waited = 0;
	int queries = 0;
	int result = EXIT_FAILURE;

	if (srv_count != 0) {
		int retries = ceil(log10(COLISSION_PROB) / log10(static_cast<long double>(1)/srv_count));
		auto start = std::chrono::system_clock::now();
		std::chrono::duration<double> elapsed {};

		while (elapsed.count() < timeout && queries < retries) {
			MYSQL* proxy = mysql_init(NULL);
			if (!mysql_real_connect(proxy, cl.root_host, cl.root_username, cl.root_password, NULL, cl.root_port, NULL, 0)) {
				fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
				return EXIT_FAILURE;
			}

			int rc = mysql_query(proxy, check.c_str());
			bool correct_result = false;

			if (rc == EXIT_SUCCESS) {
				MYSQL_RES* st_res = mysql_store_result(proxy);
				correct_result = true;
				queries += 1;
				mysql_free_result(st_res);
			} else {
				diag("Replication check failed with error: ('%d','%s')", mysql_errno(proxy), mysql_error(proxy));
			}

			if (correct_result == false) {
				diag("Replication check failed with error: ('%d','%s')", mysql_errno(proxy), mysql_error(proxy));
				queries = 0;
				waited += 1;
				sleep(1);
			} else {
				mysql_close(proxy);
				continue;
			}

			auto it_end = std::chrono::system_clock::now();
			elapsed = it_end - start;

			mysql_close(proxy);
		}

		if (queries == retries) {
			result = EXIT_SUCCESS;
		}
	} else {
		result = EXIT_SUCCESS;
	}

	return result;
}

int stmt_exec_simple_conn_tests(const CommandLine& cl, const vector<test_def_t>& tests_def) {
	for (const auto& test_def : tests_def) {
		const string& test_name { std::get<SCONN_TEST_DEF::NAME>(test_def) };
		const setup_teardown_t& setup_teardown = std::get<SCONN_TEST_DEF::SETUP_TEARDOWN>(test_def);
		const vector<query_t>& test_queries = std::get<SCONN_TEST_DEF::TEST_QUERIES>(test_def);

		diag("Starting test '%s'", test_name.c_str());

		MYSQL* proxy_mysql = mysql_init(NULL);

		if (!mysql_real_connect(proxy_mysql, cl.root_host, cl.root_username, cl.root_password, NULL, cl.root_port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_mysql));
			return EXIT_FAILURE;
		}

		// TEST SETUP queries
		int setup_err = exec_and_discard(proxy_mysql, setup_teardown.first);
		if (setup_err) { return EXIT_FAILURE; }

		// NOTE-TODO: Due to current limitations in prepared statements handling, replication check needs to
		// be handled by TEXT PROTOCOL queries. Once we are sure replication is OK, we proceed with 'prepared
		// statements' checks.
		for (const query_t& query_def : test_queries) {
			const string& query = std::get<QUERY::QUERY_STR>(query_def);

			if (strcasecmp(query.c_str(), "PROXYSQL INTERNAL SESSION")) {
				diag("Executing query '%s' with REPLICATION WAIT", query.c_str());

				MYSQL* admin = mysql_init(NULL);
				if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
					fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
					return EXIT_FAILURE;
				}

				int wait_res = _wait_for_replication(cl, admin, query, 10, 1);
				if (wait_res != EXIT_SUCCESS) {
					diag("Waiting for replication FAILED. EXITING");
					return EXIT_FAILURE;
				}

				mysql_close(admin);
			}
		}

		prepare_stmt_queries(cl, test_queries);

		exec_stmt_queries(proxy_mysql, test_queries);

		// TEST TEARDOWN queries
		int tear_err = exec_and_discard(proxy_mysql, setup_teardown.second);
		if (tear_err) { return EXIT_FAILURE; }

		mysql_close(proxy_mysql);
	}

	return EXIT_SUCCESS;
}

bool check_if_tg_elem_is_true(const json& j_tg_elem) {
	return j_tg_elem.get<bool>() == true;
}

bool check_if_tg_elem_is_false(const json& j_tg_elem) {
	return j_tg_elem.get<bool>() == false;
}

bool check_if_multiplex_enabled(const json& j_backends) {
	for (const json& j_backend : j_backends) {
		if (j_backend.contains("conn")) {
			return false;
		}
	}

	return true;
}

const vector<test_def_t> text_tests_defs {
	{
		"TRX_SERVER_STATUS",
		{},
		{
			{ "START TRANSACTION", {}, {} },
			{ "SELECT 1", {}, {} },
			{ "PROXYSQL INTERNAL SESSION", {}, { {{"backends","conn","mysql","server_status"}, check_server_status_in_trx, "IN_TRANSACTION"} } },
			{ "COMMIT", {}, {} }
		},
	},
	{
		"STATUS_MYSQL_CONNECTION_USER_VARIABLE",
		setup_teardown_t { {}, {} },
		vector<query_t> {
			{ "SET @test_variable = 44", rep_check_t {}, vector<sess_check_t> {} },
			{
				"PROXYSQL INTERNAL SESSION", {},
				{
					{ {"backends","conn","status","user_variable"}, check_if_tg_elem_is_true, "USER_VARIABLE" },
					{ {"backends","conn","MultiplexDisabled"}, check_if_tg_elem_is_true, "MultiplexDisabled due to 'USER_VARIABLE'" }
				}
			}
		}
	},
	{
		"TEXT_PROTOCOL_PREPARE_STMT",
		{},
		{
			{ "PREPARE stmt_test FROM 'SELECT 1'", {}, {} },
			{
				"PROXYSQL INTERNAL SESSION", {},
				{
					{ {"backends","conn","status","prepared_statement"}, check_if_tg_elem_is_true, "PREPARED_STATEMENT" },
					{ {"backends","conn","MultiplexDisabled"}, check_if_tg_elem_is_true, "MultiplexDisabled" }
				}
			}
		}
	},
	{
		"STATUS_MYSQL_CONNECTION_LOCK_TABLES",
		{
			{
				"CREATE TABLE IF NOT EXISTS test.sess_st_lock_tables ("
				"  c1 INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
				"  c2 VARCHAR(100),"
				"  c3 VARCHAR(100)"
				")"
			},
			{
				"DROP TABLE test.sess_st_lock_tables"
			}
		},
		{
			{ "LOCK TABLES test.sess_st_lock_tables READ", {ER_NO_SUCH_TABLE, 10}, {} },
			{
				"PROXYSQL INTERNAL SESSION", {},
				{
					{ {"backends","conn","status","lock_tables"}, check_if_tg_elem_is_true, "LOCK_TABLES" },
					{ {"backends","conn","MultiplexDisabled"}, check_if_tg_elem_is_true, "MultiplexDisabled" }
				}
			},
			{ "UNLOCK TABLES", {}, {} },
			{
				"PROXYSQL INTERNAL SESSION", {},
				{
					{ {"backends"}, check_if_multiplex_enabled, "UNLOCK_TABLES re-enable multiplex" },
				}
			},
			{ "LOCK TABLES test.sess_st_lock_tables READ", {}, {} },
			{ "SET @test_variable = 43", {}, {} },
			{ "UNLOCK TABLES", {}, {} },
			{
				"PROXYSQL INTERNAL SESSION", {},
				{
					{ {"backends","conn","status","lock_tables"}, check_if_tg_elem_is_false, "UNLOCK_TABLES unset 'LOCK_TABLES' in status_flags" },
				}
			}
		}
	},
	{
		"STATUS_MYSQL_CONNECTION_FOUND_ROWS",
		{
			{
				"CREATE TABLE IF NOT EXISTS test.sess_st_sql_cacl_rows ("
				"  c1 INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
				"  c2 VARCHAR(100),"
				"  c3 VARCHAR(100)"
				")"
			},
			{
				"DROP TABLE test.sess_st_sql_cacl_rows"
			}
		},
		{
			{ "SELECT SQL_CALC_FOUND_ROWS * FROM test.sess_st_sql_cacl_rows", {ER_NO_SUCH_TABLE, 10}, {} },
			{
				"PROXYSQL INTERNAL SESSION", {},
				{
					{ {"backends","conn","status","found_rows"}, check_if_tg_elem_is_true, "SQL_CALC_FOUND_ROWS" },
					{ {"backends","conn","MultiplexDisabled"}, check_if_tg_elem_is_true, "MultiplexDisabled" }
				}
			},
			{ "SELECT FOUND_ROWS()", {}, {} },
			{
				"PROXYSQL INTERNAL SESSION", {},
				{
					{ {"backends","conn","status","found_rows"}, check_if_tg_elem_is_true, "SQL_CALC_FOUND_ROWS" },
					{ {"backends","conn","MultiplexDisabled"}, check_if_tg_elem_is_true, "MultiplexDisabled" }
				}
			}
		}
	},
	{
		"STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE",
		{
			{
				"CREATE TEMPORARY TABLE IF NOT EXISTS test.conn_st_temp_table ("
				"  c1 INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
				"  c2 VARCHAR(100),"
				"  c3 VARCHAR(100)"
				")"
			},
			{
				"DROP TABLE test.conn_st_temp_table"
			}
		},
		{
			{
				"PROXYSQL INTERNAL SESSION", {},
				{
					{ {"backends","conn","status","temporary_table"}, check_if_tg_elem_is_true, "TEMPORARY_TABLE" },
					{ {"backends","conn","MultiplexDisabled"}, check_if_tg_elem_is_true, "MultiplexDisabled due to 'CREATE TEMPORARY TABLE'" }
				}
			}
		}
	},
	{
		// TODO: Check why when GET_LOCK is executed the first backend is "NULL", and not filled like in the rest
		"STATUS_MYSQL_CONNECTION_GET_LOCK",
		{ {}, {} },
		{
			{ "SELECT 1", {}, {} },
			{
				"PROXYSQL INTERNAL SESSION", {},
				{ { {"backends"}, check_if_multiplex_enabled, "MultiplexEnabled after simple 'SELECT'" } }
			},
			{ "SELECT GET_LOCK('test_session_vars_lock', 2)", {}, {} },
			{
				"PROXYSQL INTERNAL SESSION", {},
				{
					{ {"backends","conn","status","get_lock"}, check_if_tg_elem_is_true, "GET_LOCK" },
					{ {"backends","conn","MultiplexDisabled"}, check_if_tg_elem_is_true, "MultiplexDisabled due to 'CREATE TEMPORARY TABLE'" }
				}
			},
			{ "SELECT RELEASE_LOCK('test_session_vars_lock')", {}, {} },
			// NOTE: Enable when supported
			// {
			// 	"PROXYSQL INTERNAL SESSION", {},
			// 	{ { {"backends"}, check_if_multiplex_enabled, "MultiplexEnabled after 'RELEASE_LOCK()'" } }
			// },
		}
	},
	{
		// Transaction detection is done through server status, while the MULTIPLEXING will be disabled for the connection and
		// the connection wont be returned to the connection pool, both of the metrics 'MultiplexDisabled' and 'status.no_multiplex'
		// will report 'false'.
		"STATUS_MYSQL_CONNECTION_NO_MULTIPLEX - TRANSACTION",
		setup_teardown_t { {}, {} },
		vector<query_t> {
			{ "START TRANSACTION", rep_check_t {}, vector<sess_check_t> {} },
			{ "SELECT 1", rep_check_t {}, vector<sess_check_t> {} },
			{
				"PROXYSQL INTERNAL SESSION", {},
				{
					{ {"backends","conn","status","no_multiplex"}, check_if_tg_elem_is_false, "NO_MULTIPLEX status is 'False'" },
					{ {"backends","conn","MultiplexDisabled"}, check_if_tg_elem_is_false, "MultiplexDisabled reports 'false' during 'TRANSACTION'" }
				}
			},
			{ "COMMIT", rep_check_t {}, vector<sess_check_t> {} },
			{
				"PROXYSQL INTERNAL SESSION", {},
				{
					{ {"backends"}, check_if_multiplex_enabled, "COMMIT re-enables MULTIPLEXING" },
				}
			},
		}
	},
	{
		"STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0",
		setup_teardown_t { {}, {} },
		vector<query_t> {
			{ "SET SQL_LOG_BIN=0", rep_check_t {}, vector<sess_check_t> {} },
			{ "SELECT 1", rep_check_t {}, vector<sess_check_t> {} },
			{
				"PROXYSQL INTERNAL SESSION", {},
				{
					{ {"backends","conn","MultiplexDisabled"}, check_if_tg_elem_is_true, "MultiplexDisabled due to 'SET SQL_LOG_BIN'" }
				}
			}
		}
	},
	{
		"STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT",
		setup_teardown_t {
			{ "CREATE TABLE IF NOT EXISTS test.test_conn_has_savepoint(id INT NOT NULL AUTO_INCREMENT PRIMARY KEY) ENGINE=INNODB" }, {}
		},
		vector<query_t> {
			{ "SET AUTOCOMMIT=0", rep_check_t {}, vector<sess_check_t> {} },
			{ "SELECT * FROM test.test_conn_has_savepoint LIMIT 1 FOR UPDATE", rep_check_t {}, vector<sess_check_t> {} },
			{ "SAVEPOINT test_conn_has_savepoint", rep_check_t {}, vector<sess_check_t> {} },
			{
				"PROXYSQL INTERNAL SESSION", {},
				{
					{ {"backends","conn","status","has_savepoint"}, check_if_tg_elem_is_true, "HAS_SAVEPOINT status is 'True'" },
					{ {"backends","conn","MultiplexDisabled"}, check_if_tg_elem_is_true, "MultiplexDisabled reports 'True' due to 'SAVEPOINT'" }
				}
			},
			{ "COMMIT", rep_check_t {}, vector<sess_check_t> {} },
			{
				"PROXYSQL INTERNAL SESSION", {},
				{
					{ {"backends"}, check_if_multiplex_enabled, "COMMIT re-enables MULTIPLEXING" },
				}
			}
		}
	}
};

const vector<string> stmt_compatible_tests {
	"STATUS_MYSQL_CONNECTION_USER_VARIABLE",
	"STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE",
	"STATUS_MYSQL_CONNECTION_FOUND_ROWS",
	"STATUS_MYSQL_CONNECTION_GET_LOCK"
};

const vector<query_t> test_compression_queries {
	{ "PROXYSQL INTERNAL SESSION", {}, {{{"conn","status","compression"}, check_if_tg_elem_is_true, "COMPRESSED_CONNECTION"}} },
};

int test_client_conn_compression_st(const CommandLine& cl) {
	MYSQL* proxysql_mysql = mysql_init(NULL);

	if (!mysql_real_connect(proxysql_mysql, cl.root_host, cl.root_username, cl.root_password, NULL, cl.root_port, NULL, CLIENT_COMPRESS)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return EXIT_FAILURE;
	}

	exec_test_queries(proxysql_mysql, test_compression_queries);

	mysql_close(proxysql_mysql);

	return EXIT_SUCCESS;
}

uint32_t compute_planned_tests(const vector<test_def_t> text_tests_def, const vector<string>& stmt_compatible_tests) {
	size_t test_count = 0;

	for (const test_def_t& test_def : text_tests_defs) {
		const string& test_name = std::get<SCONN_TEST_DEF::NAME>(test_def);

		for (const query_t& test_query : std::get<SCONN_TEST_DEF::TEST_QUERIES>(test_def)) {
			uint32_t test_checks = 0;

			for (const sess_check_t& check : std::get<QUERY::SESS_CHECKS>(test_query)) {
				test_checks += 2;
			}

			const vector<string>& c_tests = stmt_compatible_tests;
			bool is_also_stmt_test = std::find(c_tests.begin(), c_tests.end(), test_name) != c_tests.end();

			if (is_also_stmt_test) {
				test_checks *= 2;
			}

			test_count += test_checks;
		}
	}

	return test_count;
}

int main(int argc, char *argv[]) {
	CommandLine cl;

	if(cl.getEnv()) {
		return exit_status();
	}

	uint32_t computed_exp_tests = compute_planned_tests(text_tests_defs, stmt_compatible_tests);
	uint32_t compression_exp_tests = 2;

	diag("Computed simple connection 'TEXT' and 'STMT' tests where: '%d'", computed_exp_tests);
	diag("Special connections tests where: '%d'", compression_exp_tests);

	plan(compression_exp_tests + computed_exp_tests);

	MYSQL* proxy_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxy_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_admin));
		return EXIT_FAILURE;
	}

	// Set a replication lag inferior to default one (60). This is to prevent reads
	// from a replica in which replication is currently disabled.
	MYSQL_QUERY(proxy_admin, "UPDATE mysql_servers SET max_replication_lag=20");
	MYSQL_QUERY(proxy_admin, "LOAD MYSQL SERVERS TO RUNTIME");

	const vector<string>& c_tests = stmt_compatible_tests;
	vector<test_def_t> stmt_supp_tests {
		std::accumulate(
			text_tests_defs.begin(), text_tests_defs.end(), vector<test_def_t> {},
			[](vector<test_def_t>& elems, const test_def_t& t_def) -> vector<test_def_t>& {
				const auto same_name = [&t_def] (const string& test_name) -> bool {
					return std::get<SCONN_TEST_DEF::NAME>(t_def) == test_name;
				};
				auto f_test = std::find_if(stmt_compatible_tests.begin(), stmt_compatible_tests.end(), same_name);

				if (f_test != stmt_compatible_tests.end()) {
					elems.push_back(t_def);
				}

				return elems;
			}
		)
	};

	diag("####### START SPECIAL CONNECTIONS TESTS #######");
	int t_res = test_client_conn_compression_st(cl);
	if (t_res) { goto cleanup; }
	diag("#######  END SPECIAL PROTOCOL TESTS  #######\n");

	diag("####### START TEXT PROTOCOL TESTS #######");
	t_res = text_exec_simple_conn_tests(cl, text_tests_defs);
	if (t_res) { goto cleanup; }
	diag("#######  END TEXT PROTOCOL TESTS  #######\n");

	diag("####### START STMT PROTOCOL TESTS #######");
	t_res = stmt_exec_simple_conn_tests(cl, stmt_supp_tests);
	if (t_res) { goto cleanup; }
	diag("#######  END STMT PROTOCOL TESTS  #######\n");

cleanup:

	mysql_close(proxy_admin);

	return exit_status();
}
