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
#include "mysql.h"
#include "mysql/mysqld_error.h"
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

#define MYSQL_CLEAR_RESULT(mysql)        mysql_free_result(mysql_store_result(mysql));
#define MYSQL_CLEAR_STMT_RESULT(stmt)    mysql_stmt_store_result(stmt); \
										 mysql_stmt_free_result(stmt);

#define INIT_QUERY_TEXT(QUERY, IS_SELECT) {QUERY, IS_SELECT, false}
#define INIT_QUERY_PREPARE_STMT(QUERY, IS_SELECT) {QUERY, IS_SELECT, true}

enum MultiplexStatus {
	kNotApplicable = 0,
	kMultiplexingDisabled = (1 << 0),
	kMultiplexingEnabled = (1 << 1),
	kHasWarnings = (1 << 2),
	kUserVariables = (1 << 3)
};

enum ConnectionType {
	kAdmin = 0,
	kMySQL = 1
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
	bool prepare_stmt;
};

struct WarningCheckInfo {
	WarningCheckType type;
	int warning_count;
	std::vector<int> warning_codes;
};

struct Connection {
	ConnectionType conn_type;
	size_t id;
};

struct TestInfo {
	Connection conn;
	QueryInfo query_info;
	WarningCheckInfo warning_check_info;
	int multiplex_status;
};

#define MYSQL_CONN_DEFAULT	{ConnectionType::kMySQL, 0}
#define ADMIN_CONN_DEFAULT	{ConnectionType::kAdmin, 0}
#define MYSQL_CONN(ID)		{ConnectionType::kMySQL, ID}
#define ADMIN_CONN(ID)		{ConnectionType::kAdmin, ID}

CommandLine cl;
std::array<std::map<size_t, MYSQL*>,2> conn_pool;

MYSQL* get_connection(const Connection& conn, bool enable_client_deprecate_eof) {
	auto& my_conn = conn_pool[conn.conn_type];
	const auto& itr = my_conn.find(conn.id);
	if (itr != my_conn.end()) {
		return itr->second;
	}
	// Initialize connection
	MYSQL* proxysql = mysql_init(NULL);
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return NULL;
	}

	if (enable_client_deprecate_eof) {
		// enable 'CLIENT_DEPRECATE_EOF' support
		proxysql->options.client_flag |= CLIENT_DEPRECATE_EOF;
	}

	if (conn.conn_type == kAdmin) {
		// Connnect to ProxySQL
		if (!mysql_real_connect(proxysql, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
			return NULL;
		}
	} else if (conn.conn_type == kMySQL) {
		// Connect to ProxySQL
		if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
			return NULL;
		}
	}
	my_conn[conn.id] = proxysql;
	return proxysql;
}

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
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	return EXIT_SUCCESS;
}

int prepare_and_execute_stmt(MYSQL* mysql, const QueryInfo& query_info, MYSQL_STMT** stmt_out) {
	assert(stmt_out);
	MYSQL_STMT* stmt = mysql_stmt_init(mysql);
	if (!stmt) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return EXIT_FAILURE;
	}
	if (mysql_stmt_prepare(stmt, query_info.query, strlen(query_info.query))) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return EXIT_FAILURE;
	}
	if (mysql_stmt_execute(stmt) != 0) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return EXIT_FAILURE;
	}
	if (query_info.is_select) {
		MYSQL_CLEAR_STMT_RESULT(stmt);
	}
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	*stmt_out = stmt;
	return EXIT_SUCCESS;
}

// get warning count from MySQL connection (MYSQL::warning_count)
int get_warnings_count_from_connection(MYSQL* mysql) {
	return mysql_warning_count(mysql);
}

// get warning count from statement (MYSQL_STMT::mysql_upsert_status::warning_count)
int get_warnings_count_from_statement(MYSQL_STMT* stmt) {
	return mysql_stmt_warning_count(stmt);
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
	
				if (backend["conn"]["MultiplexDisabled"] == true) {
					status |= MultiplexStatus::kMultiplexingEnabled;
				}

				if (backend["conn"]["status"]["has_warnings"] == true && 
					backend["conn"]["warning_count"] > 0 &&
					j_status["warning_in_hg"] != -1) {
					status |= MultiplexStatus::kHasWarnings;
				}

				if (backend["conn"]["status"]["user_variable"] == true) {
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

const std::vector<TestInfo> mysql_variable_test = {
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("DELETE FROM mysql_query_rules", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL QUERY RULES TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("DELETE FROM mysql_hostgroup_attributes", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL SERVERS TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("SET mysql-handle_warnings=0", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL VARIABLES TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1/0", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DO 1/0", false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1/0", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("DO 1/0", false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("SET mysql-handle_warnings=1", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL VARIABLES TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
											    { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1"  , true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DO 1/0", false), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DO 1", false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1"  , true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("DO 1/0", false), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("DO 1", false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) }
};

const std::vector<TestInfo> hostgroup_attributes_test = {
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("SET mysql-handle_warnings=1", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL VARIABLES TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("DELETE FROM mysql_hostgroup_attributes", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("INSERT INTO mysql_hostgroup_attributes (hostgroup_id, hostgroup_settings) VALUES (0, '{\"handle_warnings\":0}')", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL SERVERS TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												// Hostgroup attributes take precedence and should override the global variable value for the specified hostgroup.
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DO 1/0", false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled)},
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1/0", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled)},
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DO 1", false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("DO 1/0", false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled)},
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1/0", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled)},
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("DO 1", false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("SET mysql-handle_warnings=0", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL VARIABLES TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("DELETE FROM mysql_hostgroup_attributes", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("INSERT INTO mysql_hostgroup_attributes (hostgroup_id, hostgroup_settings) VALUES (0, '{\"handle_warnings\":1}')", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL SERVERS TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DO 1/0", false), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("DO 1/0", false), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) }
};

const std::vector<TestInfo> random_test = {
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1"  , true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DO 1/0", false), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DO 1"  , false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SET character_set_database='latin1'", false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1"  , true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1"  , true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("DO 1/0", false), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("DO 1"  , false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SET character_set_database='latin2'", false), {WarningCheckType::kAll, 1, {1681}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1"  , true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) }
};

const std::vector<TestInfo> insert_test = {
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SET sql_mode='ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DROP DATABASE IF EXISTS testdb", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("CREATE DATABASE testdb", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("CREATE TABLE testdb.t1 (a TINYINT NOT NULL, b CHAR(4))", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kMultiplexingDisabled) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("INSERT INTO testdb.t1 VALUES(10, 'mysql'), (NULL, 'test'), (300, 'xyz')", false), {WarningCheckType::kAll, 3, {1265,1048,1264}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("INSERT INTO testdb.t1 VALUES(10, 'mysql'), (NULL, 'test'), (300, 'xyz')", false), {WarningCheckType::kAll, 3, {1265,1048,1264}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
											  { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DROP DATABASE IF EXISTS testdb", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kMultiplexingDisabled) }
};

const std::vector<TestInfo> query_cache_test = {
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("SET mysql-query_cache_handle_warnings=0", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL VARIABLES TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("DELETE FROM mysql_query_rules", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("INSERT INTO mysql_query_rules (rule_id,active,match_digest,cache_ttl,apply) VALUES (1,1,'SELECT ?/?',60000,1)", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL QUERY RULES TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("PROXYSQL FLUSH QUERY CACHE", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												   // this entry should not be saved in cache
												   { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												   { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												   // to check if prepare statement conflicts with cache
												   { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												   // { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("SET mysql-query_cache_handle_warnings=1", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL VARIABLES TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												   // resultset will be retrived from cache, with warning count zero
												   { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1/0", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												   // to check if prepare statement conflicts with cache
												   { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("DELETE FROM mysql_query_rules", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL QUERY RULES TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("PROXYSQL FLUSH QUERY CACHE", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) }
};

const std::vector<TestInfo> query_digest_test = {
												    { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("SET mysql-query_digests='false'", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
													{ ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL VARIABLES TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												    { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1/0", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
													{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DO 1/0", false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
													{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1/0", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
													{ MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("DO 1/0", false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												    { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("SET mysql-query_digests='true'", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												    { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL VARIABLES TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
													{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												    { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												    { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DO 1/0", false), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												    { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DO 1", false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												    { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												    { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) }
};

const std::vector<TestInfo> warning_log_test = {
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("SET mysql-log_mysql_warnings_enabled='true'", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL VARIABLES TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												   { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												   { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DO 1/0", false), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												   { MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("DO 1", false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												   { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kHasWarnings) },
												   { MYSQL_CONN_DEFAULT, INIT_QUERY_PREPARE_STMT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingDisabled) },
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("SET mysql-log_mysql_warnings_enabled='false'", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) },
												   { ADMIN_CONN_DEFAULT, INIT_QUERY_TEXT("LOAD MYSQL VARIABLES TO RUNTIME", false), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kNotApplicable) }
};

const std::vector<TestInfo> multiplexing_test = {
													{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT @@sql_mode", true), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kUserVariables) },
													{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kUserVariables | MultiplexStatus::kHasWarnings) },
													{ MYSQL_CONN_DEFAULT, INIT_QUERY_TEXT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kUserVariables) },
													{ MYSQL_CONN(1), INIT_QUERY_TEXT("SELECT @@sql_mode", true), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kUserVariables)},
													{ MYSQL_CONN(1), INIT_QUERY_TEXT("DO 1/0", false), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kUserVariables | MultiplexStatus::kHasWarnings)},
													{ MYSQL_CONN(1), INIT_QUERY_TEXT("DO 1", false), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kUserVariables)},
													{ MYSQL_CONN(2), INIT_QUERY_PREPARE_STMT("SELECT @@sql_mode", true), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kUserVariables)},
													{ MYSQL_CONN(2), INIT_QUERY_PREPARE_STMT("SELECT 1/0", true), {WarningCheckType::kAll, 1, {1365}}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kUserVariables | MultiplexStatus::kHasWarnings)},
													{ MYSQL_CONN(2), INIT_QUERY_PREPARE_STMT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kUserVariables) },
													{ MYSQL_CONN(3), INIT_QUERY_PREPARE_STMT("SET @test_variable = 44", true), {WarningCheckType::kNotApplicable}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kUserVariables)},
													{ MYSQL_CONN(3), INIT_QUERY_PREPARE_STMT("SELECT 1", true), {WarningCheckType::kAll, 0}, (MultiplexStatus::kMultiplexingEnabled | MultiplexStatus::kUserVariables) }
};

#define IS_BIT_MASK_SET(variable,flag) ((variable & static_cast<int>(flag)) == static_cast<int>(flag))

// base case
size_t check_count() { return 0; }

template <class First, class... Rest>
size_t check_count(First&& first, Rest&&... rest) {

	size_t count = 0;
	
	for (const auto& val : first) {
		if (val.warning_check_info.type != WarningCheckType::kNotApplicable) {
			if (val.warning_check_info.type == WarningCheckType::kAll)
				count += 3;
			else 
				count += 1;
			count += val.warning_check_info.warning_codes.size();
		}
		if (val.multiplex_status != 0) 
			count += 1;
	}
	return (count + check_count(rest...));
}

template <class... Args>
constexpr size_t test_size(Args&&... args) {
	return sizeof...(args);
}

#define TESTS_COMBINED mysql_variable_test, hostgroup_attributes_test, random_test, insert_test, query_digest_test, \
 query_cache_test, warning_log_test, multiplexing_test

void execute_tests(const std::vector<std::pair<const char*, std::vector<TestInfo>>>& all_tests, bool enable_client_deprecate_eof) {
	for (const auto& test : all_tests) {
		diag("Executing [%s] test... [CLIENT_DEPRECATE_EOF=%s]", test.first, (enable_client_deprecate_eof ? "TRUE" : "FALSE"));
		for (const auto& test_info : test.second) {
			MYSQL_STMT* stmt = nullptr;
			MYSQL* mysql = get_connection(test_info.conn, enable_client_deprecate_eof);
			if (!mysql) {
				goto __exit;
			}
			if (test_info.query_info.prepare_stmt) {
				if (prepare_and_execute_stmt(mysql, test_info.query_info, &stmt) == EXIT_FAILURE)
					goto __exit;
			} else {
				if (execute_query(mysql, test_info.query_info) == EXIT_FAILURE)
					goto __exit;
			}

			const int check_type = static_cast<int>(test_info.warning_check_info.type);

			if (IS_BIT_MASK_SET(check_type, WarningCheckType::kConnection)) {
				int count = get_warnings_count_from_connection(mysql);
				if (test_info.query_info.prepare_stmt) {
					count &= get_warnings_count_from_statement(stmt);
				}
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
				if (check_proxysql_internal_session(mysql, test_info.multiplex_status) != EXIT_SUCCESS) {
					if (stmt)
						mysql_stmt_close(stmt);
					goto __exit;
				}
			}

			if (stmt)
				mysql_stmt_close(stmt);
		}
	}

__exit:
	for (const auto& mysql_conn : conn_pool[kAdmin]) {
		mysql_close(mysql_conn.second);
	}
	conn_pool[kAdmin].clear();
	for (const auto& mysql_conn : conn_pool[kMySQL]) {
		mysql_close(mysql_conn.second);
	}
	conn_pool[kMySQL].clear();
}

int main(int argc, char** argv) {

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(check_count(TESTS_COMBINED)*2); // also check with client_deprecate_eof flag

	/*plan((20 + 6) +  // mysql variable test: 20 warning checks, 6 multiplex status checks
		 (20 + 6) +  // hostgroup attributes test: 20 warning checks, 6 multiplex status checks
		 (14 + 4) +  // random test: 14 warning checks, 4 multiplex status checks
		 (9 + 4) +   // insert test: 9 warning checks, 4 multiplex status checks
		 (3 + 1) +   // query digest test: 3 warning checks, 1 multiplex status checks
		 (18 + 5) +  // query cache test: 18 warning checks, 5 multiplex status checks
		 (7 + 2) +   // warning log test: 7 warning checks, 2 multiplex status checks
		 (7 + 3));   // multiplexing test: 7 warning checks, 3 multiplex status checks
	*/

	std::vector<std::pair<const char*, std::vector<TestInfo>>> all_tests(test_size(TESTS_COMBINED));

	all_tests[0].first = "MYSQL VARIABLE (mysql-handle_warnings)";
	all_tests[0].second.insert(all_tests[0].second.end(), mysql_variable_test.begin(), mysql_variable_test.end());

	all_tests[1].first = "HOSTGROUP ATTRIBUTES (handle_warnings)";
	all_tests[1].second.insert(all_tests[1].second.end(), hostgroup_attributes_test.begin(), hostgroup_attributes_test.end());
	
	all_tests[2].first = "RANDOM";
	all_tests[2].second.insert(all_tests[2].second.end(), random_test.begin(), random_test.end());

	all_tests[3].first = "INSERT";
	all_tests[3].second.insert(all_tests[3].second.end(), insert_test.begin(), insert_test.end());

	all_tests[4].first = "QUERY_DIGEST";
	all_tests[4].second.insert(all_tests[4].second.end(), query_digest_test.begin(), query_digest_test.end());

	all_tests[5].first = "QUERY_CACHE";
	all_tests[5].second.insert(all_tests[5].second.end(), query_cache_test.begin(), query_cache_test.end());

	all_tests[6].first = "WARNING_LOGS";
	all_tests[6].second.insert(all_tests[6].second.end(), warning_log_test.begin(), warning_log_test.end());

	all_tests[7].first = "MULTIPLEXING";
	all_tests[7].second.insert(all_tests[7].second.end(), multiplexing_test.begin(), multiplexing_test.end());

	execute_tests(all_tests, false);
	execute_tests(all_tests, true);

	return exit_status();
}
