/**
 * @file test_prepare_statement_memory_usage-t.cpp
 * @brief Examines the memory consumption of the prepared statement cache.. 
 * @details This test assesses the memory utilization of prepared statement metadata/backend cache memory.
 */

#include <string>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "proxysql_utils.h"
#include "utils.h"

CommandLine cl;

enum ComparisonOperator {
	kEqual = 0x00000001,
	kGreaterThan = 0x00000002,
	kLessThan = 0x00000004
};

int get_prepare_stmt_mem_usage(MYSQL* admin, uint64_t& prep_stmt_metadata_mem, uint64_t& prep_stmt_backend_mem) {
	prep_stmt_metadata_mem = prep_stmt_backend_mem = 0;
	MYSQL_QUERY_T(admin, "SELECT variable_name, variable_value FROM stats_memory_metrics WHERE \
		variable_name IN ('prepare_statement_metadata_memory', 'prepare_statement_backend_memory')");
	MYSQL_RES* myres = mysql_store_result(admin);
	while (MYSQL_ROW myrow = mysql_fetch_row(myres)) {
		if (strncmp(myrow[0], "prepare_statement_metadata_memory", sizeof("prepare_statement_metadata_memory") - 1) == 0) {
			prep_stmt_metadata_mem = std::stoull(myrow[1], nullptr, 10);
		} else if (strncmp(myrow[0], "prepare_statement_backend_memory", sizeof("prepare_statement_backend_memory") - 1) == 0) {
			prep_stmt_backend_mem = std::stoull(myrow[1], nullptr, 10);
		} else {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "Invalid resultset");
			mysql_free_result(myres);
			return EXIT_FAILURE;
		}
	}
	mysql_free_result(myres);
	return EXIT_SUCCESS;
}

int check_prepare_statement_mem_usage(MYSQL* proxysql_admin, MYSQL* proxysql, const char* query, int prep_stmt_metadata_mem_comp,
	int prep_stmt_backend_mem_comp) {
	uint64_t old_prep_stmt_metadata_mem, old_prep_stmt_backend_mem;
	if (get_prepare_stmt_mem_usage(proxysql_admin, old_prep_stmt_metadata_mem, old_prep_stmt_backend_mem) == EXIT_FAILURE) {
		return EXIT_FAILURE;
	}
	MYSQL_STMT* stmt = mysql_stmt_init(proxysql);
	if (!stmt) {
		diag("mysql_stmt_init(), out of memory\n");
		return EXIT_FAILURE;
	}
	if (mysql_stmt_prepare(stmt, query, strlen(query))) {
		diag("query: %s", query);
		diag("mysql_stmt_prepare at line %d failed: %s", __LINE__, mysql_error(proxysql));
		mysql_stmt_close(stmt);
		return EXIT_FAILURE;
	} else {
		ok(true, "Prepare succeeded: %s", query);
	}
	uint64_t new_prep_stmt_metadata_mem, new_prep_stmt_backend_mem;
	if (get_prepare_stmt_mem_usage(proxysql_admin, new_prep_stmt_metadata_mem, new_prep_stmt_backend_mem) == EXIT_FAILURE) {
		mysql_stmt_close(stmt);
		return EXIT_FAILURE;
	}
	auto fnCompare = [](const uint64_t& val1, const uint64_t& val2, int co) -> bool {
		bool res = false;
		if ((co & kLessThan) == kLessThan) {
			if ((co & kEqual) == kEqual) {
				res = (val1 >= val2);
			} else {
				res = (val1 > val2);
			}
		} else if ((co & kGreaterThan) == kGreaterThan) {
			if ((co & kEqual) == kEqual) {
				res = (val1 <= val2);
			} else {
				res = (val1 < val2);
			}
		} else {
			res = (val1 == val2);
		}
		return res;
		};

	ok(fnCompare(old_prep_stmt_metadata_mem, new_prep_stmt_metadata_mem, prep_stmt_metadata_mem_comp),
		"Memory usage check [%d]. 'prepare_statement_metadata_memory':[%lu] [%lu]", prep_stmt_metadata_mem_comp,
		old_prep_stmt_metadata_mem, new_prep_stmt_metadata_mem);
	
	ok(fnCompare(old_prep_stmt_backend_mem, new_prep_stmt_backend_mem, prep_stmt_backend_mem_comp),
		"Memory usage check [%d]. 'prepare_statement_backend_memory':[%lu] [%lu]", prep_stmt_backend_mem_comp,
		old_prep_stmt_backend_mem, new_prep_stmt_backend_mem);

	mysql_stmt_close(stmt);
	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {

	plan(4 * // query
		 3 // checks
	);

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

	if (check_prepare_statement_mem_usage(proxysql_admin, proxysql, "SELECT 1", kGreaterThan, (kGreaterThan | kEqual)) == EXIT_FAILURE)
		goto __cleanup;

	if (check_prepare_statement_mem_usage(proxysql_admin, proxysql, "SELECT 2", kGreaterThan, (kGreaterThan | kEqual)) == EXIT_FAILURE)
		goto __cleanup;

	if (check_prepare_statement_mem_usage(proxysql_admin, proxysql, "SELECT 1", kGreaterThan, kEqual) == EXIT_FAILURE)
		goto __cleanup;

	if (check_prepare_statement_mem_usage(proxysql_admin, proxysql, "SELECT 2", kGreaterThan, kEqual) == EXIT_FAILURE)
		goto __cleanup;

__cleanup:
	mysql_close(proxysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
