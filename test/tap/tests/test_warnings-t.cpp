/**
 * @file test-warnings-t.cpp
 * @brief This test will test warnings support in ProxySQL
 */

#include <stdio.h>
#include <unistd.h>
#include <string>
#include <list>
#include <tuple>
#include <map>
#include <thread>

#include "json.hpp"
#include <mysql.h>
#include <mysql/mysqld_error.h>
#include "tap.h"
#include "command_line.h"
#include "utils.h" 

using LEVEL = std::string;
using CODE = int;
using MESSAGE = std::string;

#define MYSQL_QUERY__(mysql, query) \
	do { \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s\n", \
					__FILE__, __LINE__, mysql_error(mysql)); \
			goto cleanup; \
		} \
	} while(0)

#define MYSQL_CLEAR_RESULT(mysql) do { MYSQL_RES* mysql_result = mysql_use_result(mysql); \
									 while (MYSQL_ROW row = mysql_fetch_row(mysql_result)) {} \
									 mysql_free_result(mysql_result); \
								  } while(0)


enum MultiplexStatus {
	kNotApplicable = 0,
	kMultiplexingDisabled = (1 << 0),
	kMultiplexingEnabled = (1 << 1),
	kHasWarnings = (1 << 2),
	kUserVariables = (1 << 3)
};

enum ConnectionType {
	kAdmin,
	kMySQL
};

enum class WarningCheckType {
	kNotApplicable = 0,
	kConnection = (1 << 0),
	kCountQuery = (1 << 1),
	kShowWarnings = (1 << 2),
	kAll = (kConnection | kCountQuery | kShowWarnings)
};

struct QueryInfo {
	const char* query;
	bool is_select;
};

struct WarningCheckInfo {
	WarningCheckType type;
	int warning_count;
	std::vector<int> warning_codes;
};

struct TestInfo {
	ConnectionType conn_type;
	QueryInfo query_info;
	WarningCheckInfo warning_check_info;
	int multiplex_status;
};


void parse_result_json_column(MYSQL_RES* result, nlohmann::json& j) {
	if (!result) return;
	while (MYSQL_ROW row = mysql_fetch_row(result)) {
		j = nlohmann::json::parse(row[0]);
	}
}

int execute_query(MYSQL* proxysql, const QueryInfo& query_info) {
	MYSQL_QUERY(proxysql, query_info.query);
	if (query_info.is_select) {
		MYSQL_CLEAR_RESULT(proxysql);
	}
	return EXIT_SUCCESS;
}

// get warning count from MySQL connection (MYSQL::warning_count)
int get_warnings_count_from_connection(MYSQL* mysql) {
	return mysql_warning_count(mysql);
}

// retrieve warning count through a query. This action does not clear the warning message list.
int get_warnings_count(MYSQL* mysql) {
	MYSQL_QUERY(mysql, "SHOW COUNT(*) WARNINGS");
	MYSQL_RES* mysql_result = mysql_use_result(mysql);
	if (!mysql_result) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return -1;
	}
	MYSQL_ROW row = mysql_fetch_row(mysql_result);
	const int warning_count = atoi(row[0]);
	if (mysql_result) {
		mysql_free_result(mysql_result);
		mysql_result = nullptr;
	}
	return warning_count;
}

// retrieve warning message list. This action does not clear the warning message list.
int get_warnings(MYSQL* mysql, std::list<std::tuple<LEVEL,CODE,MESSAGE>>& warning_list) {
	MYSQL_QUERY(mysql, "SHOW WARNINGS");
	MYSQL_RES* mysql_result = mysql_use_result(mysql);
	unsigned long fetched_row_count = 0;
	while (MYSQL_ROW row = mysql_fetch_row(mysql_result)) {
		fetched_row_count++;
		warning_list.emplace_back(std::make_tuple(std::string(row[0]),atoi(row[1]),std::string(row[2])));
	}
	if (mysql_result) {
		mysql_free_result(mysql_result);
		mysql_result = nullptr;
	}
	return fetched_row_count;
}

// check multiplexing status
int check_proxysql_internal_session(MYSQL* proxysql, int exp_status) {
	nlohmann::json j_status{};
	MYSQL_RES* res = nullptr;
	int status{};

	bool found_backend = false;

	MYSQL_QUERY(proxysql, "PROXYSQL INTERNAL SESSION");
	res = mysql_store_result(proxysql);
	parse_result_json_column(res, j_status);
	mysql_free_result(res);

	
	if (j_status.contains("backends")) {
		for (auto& backend : j_status["backends"]) {
			if (backend != nullptr && backend.contains("conn")) {
				found_backend = true;
	
				if (backend["conn"]["MultiplexDisabled"]) {
					status |= MultiplexStatus::kMultiplexingEnabled;
				}

				if (backend["conn"]["status"]["has_warnings"] && j_status["warning_in_hg"] != -1) {
					status |= MultiplexStatus::kHasWarnings;
				}

				if (backend["conn"]["status"]["user_variable"]) {
					status |= MultiplexStatus::kUserVariables;
				}
			}
		}
	} 

	if (found_backend == false) {
		status |= MultiplexStatus::kMultiplexingDisabled;
	}

	ok(status == exp_status, "Multiplex status matches. Expected status:'%d' Actual status:'%d'", exp_status, status);

	return EXIT_SUCCESS;
}

const std::vector<TestInfo> select_test = {
											  { ConnectionType::kMySQL, {"SELECT 1/0", true}, {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
											  { ConnectionType::kMySQL, {"SELECT 1"  , true}, {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) }
};

const std::vector<TestInfo> insert_test = {
											  { ConnectionType::kMySQL, {"SET sql_mode='ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
											  { ConnectionType::kMySQL, {"DROP DATABASE IF EXISTS testdb", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
											  { ConnectionType::kMySQL, {"CREATE DATABASE testdb", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
											  { ConnectionType::kMySQL, {"CREATE TABLE testdb.t1 (a TINYINT NOT NULL, b CHAR(4))", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kMultiplexingDisabled) },
											  { ConnectionType::kMySQL, {"INSERT INTO testdb.t1 VALUES(10, 'mysql'), (NULL, 'test'), (300, 'xyz')", false}, {WarningCheckType::kAll, 3, {1265,1048,1264}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
											  { ConnectionType::kMySQL, {"SELECT 1", true}, {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
											  { ConnectionType::kMySQL, {"DROP DATABASE IF EXISTS testdb", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kMultiplexingDisabled) }
};

const std::vector<TestInfo> query_cache_test = {
												   { ConnectionType::kAdmin, {"SET mysql-query_cache_with_warnings_support=0", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ConnectionType::kAdmin, {"LOAD MYSQL VARIABLES TO RUNTIME", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ConnectionType::kAdmin, {"INSERT INTO mysql_query_rules (rule_id,active,digest,cache_ttl,apply) VALUES (500,1,'0x1559bca5d536e403',60000,1)", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ConnectionType::kAdmin, {"LOAD MYSQL QUERY RULES TO RUNTIME", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ConnectionType::kAdmin, {"PROXYSQL FLUSH QUERY CACHE", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ConnectionType::kMySQL, {"SELECT 1/0", true}, {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												   // this entry should not be saved in cache
												   { ConnectionType::kMySQL, {"SELECT 1/0", true}, {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												   { ConnectionType::kMySQL, {"SELECT 1", true}, {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												   { ConnectionType::kAdmin, {"SET mysql-query_cache_with_warnings_support=1", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ConnectionType::kAdmin, {"LOAD MYSQL VARIABLES TO RUNTIME", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ConnectionType::kMySQL, {"SELECT 1/0", true}, {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												   // resultset will be retrived from cache, with warning count zero
												   { ConnectionType::kMySQL, {"SELECT 1/0", true}, {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												   { ConnectionType::kAdmin, {"DELETE FROM mysql_query_rules WHERE rule_id = 500 AND digest = '0x1559bca5d536e403'", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ConnectionType::kAdmin, {"LOAD MYSQL QUERY RULES TO RUNTIME", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ConnectionType::kAdmin, {"PROXYSQL FLUSH QUERY CACHE", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) }
};

const std::vector<TestInfo> query_digest_test = {
												    { ConnectionType::kAdmin, {"SET mysql-query_digests='false'", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
													{ ConnectionType::kAdmin, {"LOAD MYSQL VARIABLES TO RUNTIME", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												    { ConnectionType::kMySQL, {"SELECT 1/0", true}, {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												    { ConnectionType::kAdmin, {"SET mysql-query_digests='true'", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												    { ConnectionType::kAdmin, {"LOAD MYSQL VARIABLES TO RUNTIME", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) }
};

const std::vector<TestInfo> warning_log_test = {
												   { ConnectionType::kAdmin, {"SET mysql-log_mysql_warnings_enabled='true'", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ConnectionType::kAdmin, {"LOAD MYSQL VARIABLES TO RUNTIME", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ConnectionType::kMySQL, {"SELECT 1/0", true}, {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												   { ConnectionType::kMySQL, {"SELECT 1", true}, {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												   { ConnectionType::kAdmin, {"SET mysql-log_mysql_warnings_enabled='false'", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ConnectionType::kAdmin, {"LOAD MYSQL VARIABLES TO RUNTIME", false}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) }
};

const std::vector<TestInfo> multiplexing_test = {
													{ ConnectionType::kMySQL, {"SELECT @@sql_mode", true}, {WarningCheckType::kNotApplicable}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kUserVariables) },
													{ ConnectionType::kMySQL, {"SELECT 1/0", true}, {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kUserVariables | MultiplexStatus::kHasWarnings) },
													{ ConnectionType::kMySQL, {"SELECT 1", true}, {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kUserVariables) }
};



#define IS_BIT_MASK_SET(variable,flag) ((variable & static_cast<int>(flag)) == static_cast<int>(flag))

int main(int argc, char** argv) {

	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(9+13+4+23+9+10);

	// Initialize Admin connection
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	// Connnect to ProxySQL Admin
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return exit_status();
	}

	// Initialize ProxySQL connection
	MYSQL* proxysql = mysql_init(NULL);
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}

	// Connect to ProxySQL
	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}
	
	std::vector<std::pair<const char*, std::vector<TestInfo>>> all_tests(6);

	all_tests[0].first = "SELECT";
	all_tests[0].second.insert(all_tests[0].second.end(), select_test.begin(), select_test.end());

	all_tests[1].first = "INSERT";
	all_tests[1].second.insert(all_tests[1].second.end(), insert_test.begin(), insert_test.end());

	all_tests[2].first = "QUERY_DIGEST";
	all_tests[2].second.insert(all_tests[2].second.end(), query_digest_test.begin(), query_digest_test.end());

	all_tests[3].first = "QUERY_CACHE";
	all_tests[3].second.insert(all_tests[3].second.end(), query_cache_test.begin(), query_cache_test.end());

	all_tests[4].first = "WARNING_LOGS";
	all_tests[4].second.insert(all_tests[4].second.end(), warning_log_test.begin(), warning_log_test.end());

	all_tests[5].first = "MULTIPLEXING";
	all_tests[5].second.insert(all_tests[5].second.end(), multiplexing_test.begin(), multiplexing_test.end());

	for (const auto& test : all_tests) {
		diag("Executing [%s] test...", test.first);
		for (const auto& test_info : test.second) {
			MYSQL* mysql = (test_info.conn_type == ConnectionType::kMySQL ? proxysql : proxysql_admin);

			if (execute_query(mysql, test_info.query_info) == EXIT_FAILURE)
				goto __exit;

			const int check_type = static_cast<int>(test_info.warning_check_info.type);

			if (IS_BIT_MASK_SET(check_type, WarningCheckType::kConnection)) {
				const int count = get_warnings_count_from_connection(mysql);
				ok((count == test_info.warning_check_info.warning_count), "Connection warning count should match. Expected count:'%d' Actual count:'%d'", test_info.warning_check_info.warning_count, count);
			}
			if (IS_BIT_MASK_SET(check_type, WarningCheckType::kCountQuery)) {
				const int count = get_warnings_count(mysql);
				ok((count == test_info.warning_check_info.warning_count), "Warnings count via query should match. Expected count:'%d' Actual count:'%d'", test_info.warning_check_info.warning_count, count);
			}
			if (IS_BIT_MASK_SET(check_type, WarningCheckType::kShowWarnings)) {
				std::list<std::tuple<LEVEL, CODE, MESSAGE>> warnings_list;

				const int count = get_warnings(mysql, warnings_list);
				ok((count == test_info.warning_check_info.warning_count), "Fetched warning messages count should match. Expected count:'%d' Actual count:'%d'", test_info.warning_check_info.warning_count, count);

				if (test_info.warning_check_info.warning_codes.empty() == false) {
					for (const auto& warnings : warnings_list) {
						const int exp_code = std::get<1>(warnings);
						bool match_found = false;
						for (const int code : test_info.warning_check_info.warning_codes) {
							if (exp_code == code) {
								match_found = true;
								break;
							}
						}
						ok(match_found, "Warning code '%d' should match", exp_code);
					}
				}
			}

			if (test_info.multiplex_status != MultiplexStatus::kNotApplicable) {
				if (check_proxysql_internal_session(mysql, test_info.multiplex_status) != EXIT_SUCCESS)
					goto __exit;
			}
		}
	}

__exit:
	mysql_close(proxysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
